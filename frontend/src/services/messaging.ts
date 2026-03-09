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

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function idbSet(key: string, value: string): Promise<void> {
  const db  = await openDB();
  const tx  = db.transaction(IDB_STORE, "readwrite");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.put(value, key);
    req.onsuccess = () => { db.close(); resolve(); };
    req.onerror   = () => { db.close(); reject(req.error); };
  });
}

async function idbGet(key: string): Promise<string | undefined> {
  const db  = await openDB();
  const tx  = db.transaction(IDB_STORE, "readonly");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.get(key);
    req.onsuccess = () => { db.close(); resolve(req.result as string | undefined); };
    req.onerror   = () => { db.close(); reject(req.error); };
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

  // ── 7. Écrire dans Firestore ──────────────────────────────────────────────
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

  // ── 9. Mettre à jour la preview Firestore ────────────────────────────────
  await updateConversationPreview(convId, plaintext);

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
  const cachedKey = await loadMessageKey(msg.conversationId, msg.id);

  if (cachedKey) {
    // Cache IDB présent → message propre ou déjà vu
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

  return onSnapshot(q, async (snap) => {
    const decrypted: DecryptedMessage[] = [];
    for (const d of snap.docs) {
      const msg = { id: d.id, ...d.data() } as EncryptedMessage;
      try {
        decrypted.push(await decryptMessage(myUid, msg));
      } catch (err) {
        console.error(`[AQ] Échec déchiffrement message ${msg.id}:`, err);
        decrypted.push({
          id       : msg.id,
          senderUid: msg.senderUid,
          plaintext: "[🔒 Message non déchiffrable — clés expirées ou session expirée]",
          timestamp: msg.timestamp,
          verified : false,
        });
      }
    }
    callback(decrypted);
  });
}
