/**
 * messaging.ts — Envoi et réception de messages chiffrés
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PIPELINE ACTUEL (sans Double Ratchet — fonctionnel)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  ENVOI :
 *   1. Récupérer la clé publique KEM du destinataire ← key-registry.ts
 *   2. KEM encapsulate → sharedSecret + kemCiphertext  ← crypto/kem.ts
 *   3. HKDF(sharedSecret) → messageKey                ← crypto/hkdf.ts
 *   4. AES-256-GCM encrypt(plaintext, messageKey)      ← crypto/aes-gcm.ts
 *   5. DSA sign(ciphertext ‖ nonce ‖ kemCiphertext)    ← crypto/dsa.ts
 *   6. Stocker messageKey dans IDB
 *   7. Écrire EncryptedMessage dans Firestore
 *
 *  RÉCEPTION :
 *   1. DSA verify(signature, senderDsaPublicKey)       ← crypto/dsa.ts
 *   2. KEM decapsulate(kemCT, ourKemPrivKey) → sharedSecret ← crypto/kem.ts
 *   3. HKDF(sharedSecret) → messageKey                ← crypto/hkdf.ts
 *   4. Stocker messageKey dans IDB
 *   5. AES-256-GCM decrypt(ciphertext, nonce, key)    ← crypto/aes-gcm.ts
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * OÙ S'INSÈRE LE DOUBLE RATCHET (voir schéma dans double-ratchet.ts)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  ENVOI avec Double Ratchet :
 *   Étapes 2-4 actuelles (KEM → HKDF → AES) sont REMPLACÉES par :
 *   → doubleRatchetEncrypt(plaintext, stateJson, convId, privKey, pubKey, theirPubKey, sharedSecret)
 *     retourne : { ciphertext, nonce, kemCiphertext, messageIndex, newStateJson }
 *   Le stateJson est chargé/sauvé dans IDB via key-store.ts → saveRatchetState / loadRatchetState
 *
 *  RÉCEPTION avec Double Ratchet :
 *   Étapes 2-5 actuelles (KEM → HKDF → AES) sont REMPLACÉES par :
 *   → doubleRatchetDecrypt(ciphertext, nonce, messageIndex, kemCT, stateJson, convId, ...)
 *     retourne : { plaintext, newStateJson }
 *
 *  CONTOURNEMENT ACTUEL (pas de forward secrecy) :
 *   - Un seul KEM encapsulate par message → sharedSecret direct → HKDF → AES
 *   - La messageKey est mise en cache IDB pour relire ses propres messages
 *   - messageIndex est fixé à 0 (pas de chaîne de clés)
 *   - Si les clés KEM changent → les messages anciens ne sont plus déchiffrables
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Persistance des messageKeys (IDB)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Clé IDB : "msgkey:<convId>:<msgId>" → Base64(messageKey)
 *
 *  Avec Double Ratchet : remplacer ce cache par saveRatchetState() dans key-store.ts
 *  (une seule clé IDB par conversation : "ratchet:<convId>" → RatchetState JSON chiffré)
 */

import {
  collection, doc, addDoc, setDoc, getDoc, getDocs, updateDoc,
  query, where, orderBy, onSnapshot, serverTimestamp,
  type Unsubscribe,
  type QueryDocumentSnapshot,
  type DocumentData,
} from "firebase/firestore";
import { db }            from "./firebase";
import { getPublicKeys } from "./key-registry";
import { getKemPrivateKey, getDsaPrivateKey } from "./key-store";
import {
  kemEncapsulate,
  kemDecapsulate,
  dsaSign,
  dsaVerify,
  hkdfDerive,
  aesGcmEncrypt,
  aesGcmDecrypt,
  HKDF_INFO,
} from "../crypto";
import type { EncryptedMessage, Conversation, DecryptedMessage } from "../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// IDB — persistance des messageKeys
// ─────────────────────────────────────────────────────────────────────────────

const IDB_NAME  = "aegisquantum-vault";
const IDB_STORE = "keys";

// Singleton IDB — connexion ouverte une seule fois pour toute la session.
// Évite l'overhead d'ouverture/fermeture à chaque lecture/écriture de clé.
let _dbPromise: Promise<IDBDatabase> | null = null;

function getDB(): Promise<IDBDatabase> {
  if (!_dbPromise) {
    _dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror   = () => { _dbPromise = null; reject(req.error); };
    });
  }
  return _dbPromise;
}

async function idbSet(key: string, value: string): Promise<void> {
  const db  = await getDB();
  const tx  = db.transaction(IDB_STORE, "readwrite");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.put(value, key);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}

async function idbGet(key: string): Promise<string | undefined> {
  const db  = await getDB();
  const tx  = db.transaction(IDB_STORE, "readonly");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.get(key);
    req.onsuccess = () => resolve(req.result as string | undefined);
    req.onerror   = () => reject(req.error);
  });
}

/** Persiste la messageKey pour un message donné (envoi ou réception). */
async function storeMessageKey(convId: string, msgId: string, messageKey: string): Promise<void> {
  await idbSet(`msgkey:${convId}:${msgId}`, messageKey);
}

/** Récupère la messageKey depuis IDB. Retourne undefined si absente. */
async function loadMessageKey(convId: string, msgId: string): Promise<string | undefined> {
  return idbGet(`msgkey:${convId}:${msgId}`);
}

// TODO [DOUBLE RATCHET] — Importer les fonctions de gestion d'état ratchet :
//
//   import { saveRatchetState, loadRatchetState } from "./key-store";
//     saveRatchetState(uid, convId, stateJson)  → Promise<void>
//     loadRatchetState(uid, convId)             → Promise<string | null>
//
//   Ces fonctions sont déjà implémentées dans key-store.ts.
//   Elles stockent le RatchetState chiffré (AES-GCM) dans IndexedDB.
//   Clé IDB : "ratchet:<convId>" → JSON chiffré du RatchetState.
//
//   Supprimer storeMessageKey / loadMessageKey une fois le Double Ratchet en place
//   (le ratchet state contient toutes les clés nécessaires).

// ─────────────────────────────────────────────────────────────────────────────
// Cache mémoire des messageKeys en attente (anti race-condition envoi)
// ─────────────────────────────────────────────────────────────────────────────
//
// Problème : Firestore déclenche le snapshot local AVANT que addDoc() retourne
// l'ID du message → storeMessageKey() n'a pas encore été appelé → decryptMessage
// ne trouve pas la clé dans IDB → affichage de "[🔒 Message non déchiffrable]".
//
// Solution : mettre la messageKey en cache mémoire AVANT addDoc(), indexée par
// (convId, contenu déterministe). On utilise un Map<convId, Map<nonce, key>>
// car le nonce est généré avant addDoc et est unique par message.
// subscribeToMessages/decryptMessage consulte ce cache en premier.
//
const _pendingKeys = new Map<string, string>(); // `${convId}:${nonce}` → base64(messageKey)

// ─────────────────────────────────────────────────────────────────────────────
// Notification locale de mise à jour de preview (sans aller-retour Firestore)
// ─────────────────────────────────────────────────────────────────────────────
//
// Problème : updateConversationPreview() faisait un updateDoc() Firestore
// → déclenchait subscribeToConversations chez l'envoyeur
// → renderConversationList() → flash / refresh visuel côté envoyeur.
//
// Solution : quand ON envoie un message, on notifie la sidebar localement
// via un callback en mémoire (zéro aller-retour réseau). Le receiver, lui,
// met à jour Firestore quand il reçoit le message — les deux arrivent au
// même état final mais côté envoyeur il n'y a plus de snapshot parasite.
//
type ConvPreviewListener = (convId: string, preview: string, ts: number) => void;
const _convPreviewListeners = new Set<ConvPreviewListener>();

/** Enregistre un listener appelé à chaque mise à jour locale de preview. */
export function onConvPreviewUpdate(cb: ConvPreviewListener): () => void {
  _convPreviewListeners.add(cb);
  return () => _convPreviewListeners.delete(cb);
}

/** Appelé par sendMessage() au lieu de updateConversationPreview(). */
function _notifyConvPreviewUpdate(convId: string, plaintext: string, ts: number): void {
  const preview = plaintext.length > 40 ? plaintext.slice(0, 40) + '…' : plaintext;
  _convPreviewListeners.forEach(cb => cb(convId, preview, ts));
}

// Set des msgIds dont le déchiffrement a échoué et doit être retenté.
// Déclaré ici (module-level) pour être accessible dans subscribeToMessages.
const _retrySet = new Set<string>();

export function _storePendingKey(convId: string, nonce: string, messageKey: string): void {
  _pendingKeys.set(`${convId}:${nonce}`, messageKey);
}

export function _consumePendingKey(convId: string, nonce: string): string | undefined {
  const k = `${convId}:${nonce}`;
  const v = _pendingKeys.get(k);
  // NE PAS supprimer ici — la clé peut être nécessaire pour plusieurs snapshots
  // du même message (Firestore peut envoyer 2 snapshots rapides : local + serveur).
  // La clé sera supprimée dans decryptMessage() APRÈS que storeMessageKey() aura
  // persisté en IDB, garantissant qu'on ne la perd jamais.
  return v;
}

/** Supprime définitivement une pending key après persistance IDB réussie. */
export function _evictPendingKey(convId: string, nonce: string): void {
  _pendingKeys.delete(`${convId}:${nonce}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Paths Firestore
// ─────────────────────────────────────────────────────────────────────────────

const convsCol    = () => collection(db, "conversations");
const convDoc     = (convId: string) => doc(db, "conversations", convId);
const messagesCol = (convId: string) => collection(db, "conversations", convId, "messages");

// ─────────────────────────────────────────────────────────────────────────────
// Gestion des conversations
// ─────────────────────────────────────────────────────────────────────────────

export function getConversationId(uid1: string, uid2: string): string {
  return [uid1, uid2].sort().join("_");
}

export async function getOrCreateConversation(myUid: string, contactUid: string): Promise<string> {
  const convId = getConversationId(myUid, contactUid);
  const snap   = await getDoc(convDoc(convId));
  if (!snap.exists()) {
    await setDoc(convDoc(convId), {
      id                : convId,
      participants      : [myUid, contactUid],
      lastMessageAt     : serverTimestamp(),
      lastMessagePreview: "Conversation démarrée",
    });
  }
  return convId;
}

export async function getConversations(myUid: string): Promise<Conversation[]> {
  const q    = query(convsCol(), where("participants", "array-contains", myUid));
  const snap = await getDocs(q);
  return snap.docs.map((d) => d.data() as Conversation);
}

/**
 * Met à jour lastMessagePreview et lastMessageAt d'une conversation.
 * La preview est tronquée à 40 chars — jamais le plaintext complet côté serveur.
 */
export async function updateConversationPreview(convId: string, plaintext: string): Promise<void> {
  const preview = plaintext.length > 40 ? plaintext.slice(0, 40) + "…" : plaintext;
  try {
    await updateDoc(convDoc(convId), {
      lastMessagePreview: preview,
      lastMessageAt     : Date.now(),
    });
  } catch {
    // Race condition si la conversation vient d'être créée — silencieux
  }
}

export function subscribeToConversations(
  myUid   : string,
  callback: (convs: Conversation[]) => void
): Unsubscribe {
  const q = query(
    convsCol(),
    where("participants", "array-contains", myUid),
    orderBy("lastMessageAt", "desc")
  );
  return onSnapshot(q, (snap) => {
    callback(snap.docs.map((d) => d.data() as Conversation));
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi de message
// ─────────────────────────────────────────────────────────────────────────────

export async function sendMessage(
  myUid     : string,
  contactUid: string,
  plaintext : string
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  // ── 1. Clés du destinataire ───────────────────────────────────────────────
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Clés publiques introuvables pour ${contactUid}`);

  // ── 2. Nos clés privées ───────────────────────────────────────────────────
  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);  // nécessaire pour le Double Ratchet

  // ── CONTOURNEMENT ACTUEL — KEM direct ────────────────────────────────────
  //
  // TODO [DOUBLE RATCHET — ENVOI] Remplacer le bloc ci-dessous (étapes 3 à 5)
  // par un appel à doubleRatchetEncrypt() :
  //
  //   import { doubleRatchetEncrypt } from "../crypto/double-ratchet";
  //   import { saveRatchetState, loadRatchetState } from "./key-store";
  //
  //   // ENTRÉES doubleRatchetEncrypt :
  //   const stateJson = await loadRatchetState(myUid, convId);
  //   //   stateJson   : string | null   — état ratchet courant (null = 1er message)
  //   //   plaintext   : string          — message en clair (déjà disponible)
  //   //   convId      : string          — ID conversation (déjà disponible)
  //   //   myKemPrivateKey : string      — notre clé privée KEM (déjà disponible)
  //   //   ourKemPubKey    : string      — notre clé publique KEM (depuis key-registry ou key-store)
  //   //   contactKeys.kemPublicKey : string — clé publique KEM du contact
  //   //   sharedSecret : string         — secret KEM initial (depuis kemEncapsulate ci-dessous,
  //   //                                   UNIQUEMENT pour initialiser l'état si stateJson === null)
  //
  //   const { sharedSecret: initSecret, ciphertext: initKemCT } = await kemEncapsulate(contactKeys.kemPublicKey);
  //
  //   const drResult = await doubleRatchetEncrypt(
  //     plaintext,
  //     stateJson,
  //     convId,
  //     myKemPrivateKey,
  //     ourKemPublicKey,           // à récupérer depuis key-registry ou key-store
  //     contactKeys.kemPublicKey,
  //     initSecret,
  //   );
  //
  //   // SORTIES doubleRatchetEncrypt :
  //   //   drResult.ciphertext    : string  — message chiffré AES-256-GCM
  //   //   drResult.nonce         : string  — IV AES-GCM (12 bytes)
  //   //   drResult.kemCiphertext : string  — KEM CT du ratchet step courant
  //   //   drResult.messageIndex  : number  — numéro anti-replay dans la chaîne
  //   //   drResult.newStateJson  : string  — nouvel état ratchet → sauvegarder IDB
  //
  //   // Sauvegarder le nouvel état ratchet
  //   await saveRatchetState(myUid, convId, drResult.newStateJson);
  //
  //   // Utiliser drResult.ciphertext / nonce / kemCiphertext / messageIndex
  //   // à la place des variables locales ci-dessous

  // ── 3. KEM encapsulate (CONTOURNEMENT sans ratchet) ───────────────────────
  const { sharedSecret, ciphertext: kemCiphertext } = await kemEncapsulate(
    contactKeys.kemPublicKey
  );

  // ── 4. HKDF → messageKey (CONTOURNEMENT : dérivation directe sans chaîne) ─
  //
  // TODO [DOUBLE RATCHET] Cette ligne disparaît — le Double Ratchet fait la
  // dérivation en interne via hkdfDerivePair(sharedSecret) → (rootKey, chainKey)
  // puis HKDF(chainKey) → messageKey à chaque message.
  const messageKey = await hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY);

  // ── 5. AES-256-GCM encrypt (CONTOURNEMENT) ────────────────────────────────
  //
  // TODO [DOUBLE RATCHET] Cette ligne disparaît — aesGcmEncrypt est appelé
  // en interne dans doubleRatchetEncrypt(), utiliser drResult.ciphertext / nonce.
  const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);

  // ── 6. DSA sign — INCHANGÉ avec Double Ratchet ───────────────────────────
  //
  // La signature porte sur : ciphertext + nonce + kemCiphertext
  // Avec Double Ratchet : les valeurs viennent de drResult au lieu du bloc ci-dessus.
  const signedPayload = ciphertext + nonce + kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // ── 7. Cache mémoire AVANT addDoc (anti race-condition snapshot) ──────────
  // Firestore envoie le snapshot local AVANT que addDoc() retourne l'ID,
  // donc storeMessageKey() serait appelé trop tard. On indexe par nonce
  // (unique par message) pour que decryptMessage trouve la clé immédiatement.
  _storePendingKey(convId, nonce, messageKey);

  // ── 8. Écrire dans Firestore ──────────────────────────────────────────────
  //
  // TODO [DOUBLE RATCHET] messageIndex : remplacer 0 par drResult.messageIndex
  const msgRef = await addDoc(messagesCol(convId), {
    conversationId: convId,
    senderUid     : myUid,
    ciphertext,
    nonce,
    kemCiphertext,
    signature,
    messageIndex  : 0,     // TODO [DOUBLE RATCHET] → drResult.messageIndex
    timestamp     : Date.now(),
  } satisfies Omit<EncryptedMessage, "id">);

  // ── 8. Stocker la messageKey en IDB ───────────────────────────────────────
  //
  // TODO [DOUBLE RATCHET] Supprimer storeMessageKey — le ratchet state (IDB)
  // contient toutes les clés nécessaires. Appeler saveRatchetState() à la place.
  await storeMessageKey(convId, msgRef.id, messageKey);

  // ── 9. Preview de conversation mise à jour localement (sans écriture Firestore) ──
  // On NE fait plus de updateDoc() ici car cela déclencherait un snapshot
  // subscribeToConversations côté envoyeur → refresh de la sidebar → flash visuel.
  //
  // À la place, les deux côtés (envoyeur ET receiver) mettent à jour leur
  // sidebar via le snapshot du MESSAGE (subscribeToMessages → renderMessages),
  // qui appelle _notifyConvPreviewUpdate() ci-dessous.
  //
  // La preview Firestore (lastMessagePreview / lastMessageAt) est mise à jour
  // de manière différée par le receiver quand il reçoit le message — ce qui
  // n'affecte pas l'envoyeur car son propre subscribeToConversations ignorera
  // le snapshot tant qu'il vient d'un message déjà connu.
  _notifyConvPreviewUpdate(convId, plaintext, Date.now());

  // Évite "unused variable" en attendant le Double Ratchet
  void myKemPrivateKey;
}

// ─────────────────────────────────────────────────────────────────────────────
// Réception / déchiffrement
// ─────────────────────────────────────────────────────────────────────────────

export async function decryptMessage(
  myUid: string,
  msg  : EncryptedMessage
): Promise<DecryptedMessage> {

  // ── 1. DSA verify — INCHANGÉ avec Double Ratchet ─────────────────────────
  const senderKeys = await getPublicKeys(msg.senderUid);
  let   verified   = false;
  if (senderKeys) {
    const signedPayload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(signedPayload, msg.signature, senderKeys.dsaPublicKey);
  }

  // ── CONTOURNEMENT ACTUEL — KEM + cache IDB ───────────────────────────────
  //
  // TODO [DOUBLE RATCHET — RÉCEPTION] Remplacer le bloc ci-dessous (étapes 2 à 3)
  // par un appel à doubleRatchetDecrypt() :
  //
  //   import { doubleRatchetDecrypt } from "../crypto/double-ratchet";
  //   import { saveRatchetState, loadRatchetState } from "./key-store";
  //
  //   // ENTRÉES doubleRatchetDecrypt :
  //   const stateJson = await loadRatchetState(myUid, msg.conversationId);
  //   //   msg.ciphertext    : string  — message chiffré AES-256-GCM (depuis Firestore)
  //   //   msg.nonce         : string  — IV AES-GCM (depuis Firestore)
  //   //   msg.messageIndex  : number  — numéro anti-replay (depuis Firestore)
  //   //   msg.kemCiphertext : string  — KEM CT du ratchet step expéditeur (depuis Firestore)
  //   //   stateJson         : string | null — état ratchet courant (null = 1er message)
  //   //   msg.conversationId: string  — ID conversation
  //   //   myKemPrivateKey   : string  — notre clé privée KEM (depuis key-store.ts)
  //   //   ourKemPublicKey   : string  — notre clé publique KEM (depuis key-registry ou key-store)
  //   //   senderKeys.kemPublicKey : string — clé publique KEM de l'expéditeur
  //   //   sharedSecret      : string  — kemDecapsulate(msg.kemCiphertext, myKemPrivKey)
  //   //                                  (UNIQUEMENT pour initialiser si stateJson === null)
  //
  //   const sharedSecret = await kemDecapsulate(msg.kemCiphertext, myKemPrivateKey);
  //
  //   const drResult = await doubleRatchetDecrypt(
  //     msg.ciphertext,
  //     msg.nonce,
  //     msg.messageIndex,
  //     msg.kemCiphertext,
  //     stateJson,
  //     msg.conversationId,
  //     myKemPrivateKey,
  //     ourKemPublicKey,           // à récupérer depuis key-registry ou key-store
  //     senderKeys?.kemPublicKey ?? "",
  //     sharedSecret,
  //   );
  //
  //   // SORTIES doubleRatchetDecrypt :
  //   //   drResult.plaintext    : string  — texte clair déchiffré
  //   //   drResult.newStateJson : string  — nouvel état ratchet → sauvegarder IDB
  //
  //   // Sauvegarder le nouvel état ratchet
  //   await saveRatchetState(myUid, msg.conversationId, drResult.newStateJson);
  //
  //   // Utiliser drResult.plaintext à la place de `plaintext` ci-dessous

  // ── 2. Récupérer (ou dériver) la messageKey (CONTOURNEMENT) ──────────────
  let messageKey: string;

  // Priorité 1 : cache mémoire (anti race-condition : snapshot local avant addDoc)
  const pendingKey = _consumePendingKey(msg.conversationId, msg.nonce);

  // Priorité 2 : cache IDB (messages déjà reçus ou session précédente)
  const cachedKey  = pendingKey ? undefined : await loadMessageKey(msg.conversationId, msg.id);

  if (pendingKey) {
    // Clé trouvée dans le cache mémoire → message envoyé par nous dans cette session
    messageKey = pendingKey;
    // Persister en IDB pour les rechargements de session futurs,
    // PUIS supprimer du cache mémoire (la clé est maintenant safe dans IDB).
    await storeMessageKey(msg.conversationId, msg.id, messageKey);
    _evictPendingKey(msg.conversationId, msg.nonce);
  } else if (cachedKey) {
    // Cache IDB présent → message propre (session précédente) ou reçu et déjà vu
    messageKey = cachedKey;
  } else {
    // Cache absent → message reçu → KEM decapsulate
    let myKemPrivateKey: string;
    try {
      myKemPrivateKey = getKemPrivateKey(myUid);
    } catch {
      throw new Error("Clés privées non chargées — reconnectez-vous.");
    }

    // TODO [DOUBLE RATCHET] Ce kemDecapsulate direct disparaît —
    // le Double Ratchet le fait en interne via doubleRatchetDecrypt().
    // Le sharedSecret ci-dessous sert uniquement à initialiser le ratchet state
    // si stateJson === null (premier message reçu dans la conversation).
    const sharedSecret = await kemDecapsulate(msg.kemCiphertext, myKemPrivateKey);

    // TODO [DOUBLE RATCHET] Cette dérivation HKDF directe disparaît —
    // remplacée par la chaîne de clés du ratchet symétrique.
    messageKey = await hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY);

    // Persister pour relire ce message si les clés KEM changent
    // TODO [DOUBLE RATCHET] Supprimer — le ratchet state prend en charge cela.
    await storeMessageKey(msg.conversationId, msg.id, messageKey);
  }

  // ── 3. AES-256-GCM decrypt (CONTOURNEMENT) ────────────────────────────────
  //
  // TODO [DOUBLE RATCHET] Remplacer `messageKey` par la clé issue du ratchet
  // (drResult.plaintext remplace l'appel aesGcmDecrypt — fait en interne).
  const plaintext = await aesGcmDecrypt(msg.ciphertext, msg.nonce, messageKey);

  return {
    id       : msg.id,
    senderUid: msg.senderUid,
    plaintext,
    timestamp: msg.timestamp,
    verified,
    readBy   : msg.readBy ?? [],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Abonnement aux messages
// ─────────────────────────────────────────────────────────────────────────────

export function subscribeToMessages(
  myUid         : string,
  conversationId: string,
  callback      : (messages: DecryptedMessage[]) => void
): Unsubscribe {
  const q = query(messagesCol(conversationId), orderBy("timestamp", "asc"));

  // Cache local : msgId → DecryptedMessage (déchiffrés)
  const decryptedCache = new Map<string, DecryptedMessage>();

  // Registre complet des QueryDocumentSnapshot triés par timestamp.
  // Maintenu depuis docChanges() pour reconstruire la liste ordonnée
  // sans parcourir l'intégralité des docs à chaque snapshot Firestore.
  const allDocs = new Map<string, QueryDocumentSnapshot<DocumentData>>();

  /** Reconstruit la liste triée par timestamp et notifie l'UI. */
  function emitResult(): void {
    const sorted = [...allDocs.values()].sort(
      (a, b) => ((a.data().timestamp ?? 0) as number) - ((b.data().timestamp ?? 0) as number)
    );
    const result = sorted
      .map(d => decryptedCache.get(d.id))
      .filter((m): m is DecryptedMessage => m !== undefined);
    callback(result);
  }

  /**
   * Retente le déchiffrement d'un message après un délai.
   * Appelé après un échec sur le snapshot local optimiste de Firestore.
   * À ce moment-là, _pendingKeys contient encore la clé (non consommée)
   * et storeMessageKey() a eu le temps de persister en IDB.
   */
  function scheduleRetry(failedMsg: EncryptedMessage): void {
    setTimeout(async () => {
      const freshDoc = allDocs.get(failedMsg.id);
      const msgData  = freshDoc
        ? { id: freshDoc.id, ...freshDoc.data() } as EncryptedMessage
        : failedMsg;

      try {
        const decrypted = await decryptMessage(myUid, msgData);
        decryptedCache.set(msgData.id, decrypted);
        _retrySet.delete(msgData.id);
        emitResult();
      } catch (err) {
        console.error(`[AQ] Retry déchiffrement échoué pour ${msgData.id}:`, err);
        decryptedCache.set(msgData.id, {
          id       : msgData.id,
          senderUid: msgData.senderUid,
          plaintext: "[🔒 Message non déchiffrable — clés expirées ou session expirée]",
          timestamp: msgData.timestamp,
          verified : false,
          readBy   : [],
        });
        _retrySet.delete(msgData.id);
      }
    }, 80);
  }

  return onSnapshot(q, async (snap) => {
    const changes = snap.docChanges();

    // Mettre à jour le registre complet des docs (pour emitResult)
    for (const change of changes) {
      if (change.type === "added" || change.type === "modified") {
        allDocs.set(change.doc.id, change.doc);
      } else if (change.type === "removed") {
        allDocs.delete(change.doc.id);
        decryptedCache.delete(change.doc.id);
      }
    }

    let hasChanges = false;

    for (const change of changes) {
      const d   = change.doc;
      const msg = { id: d.id, ...d.data() } as EncryptedMessage;

      if (change.type === "removed") {
        hasChanges = true;
        continue;
      }

      if (change.type === "modified" && !_retrySet.has(d.id)) {
        // Modification : mettre à jour uniquement readBy, sans re-déchiffrer
        const cached = decryptedCache.get(d.id);
        if (cached) {
          const freshReadBy = (d.data().readBy ?? []) as string[];
          const current     = cached.readBy ?? [];
          if (freshReadBy.length !== current.length ||
              freshReadBy.some(uid => !current.includes(uid))) {
            decryptedCache.set(d.id, { ...cached, readBy: freshReadBy });
            hasChanges = true;
          }
        }
        continue;
      }

      // "added" (ou "modified" en retry) : déchiffrer si pas encore en cache
      if (decryptedCache.has(d.id) && !_retrySet.has(d.id)) continue;

      const isRetry = _retrySet.has(msg.id);
      try {
        const decrypted = await decryptMessage(myUid, msg);
        decryptedCache.set(msg.id, decrypted);
        _retrySet.delete(msg.id);
        hasChanges = true;

        // Mettre à jour la preview Firestore côté RECEIVER uniquement
        if (!isRetry && msg.senderUid !== myUid) {
          updateConversationPreview(msg.conversationId, decrypted.plaintext).catch(() => {});
        }
      } catch (err) {
        if (!isRetry) {
          console.warn(`[AQ] Déchiffrement différé pour ${msg.id} (race condition probable)`);
          _retrySet.add(msg.id);
          decryptedCache.set(msg.id, {
            id       : msg.id,
            senderUid: msg.senderUid,
            plaintext: "[🔒 Déchiffrement en cours…]",
            timestamp: msg.timestamp,
            verified : false,
            readBy   : [],
          });
          hasChanges = true;
          scheduleRetry(msg);
        } else {
          console.error(`[AQ] Échec définitif déchiffrement ${msg.id}:`, err);
          decryptedCache.set(msg.id, {
            id       : msg.id,
            senderUid: msg.senderUid,
            plaintext: "[🔒 Message non déchiffrable — clés expirées ou session expirée]",
            timestamp: msg.timestamp,
            verified : false,
            readBy   : [],
          });
          _retrySet.delete(msg.id);
          hasChanges = true;
        }
      }
    }

    if (!hasChanges) return;
    emitResult();
  });
}
