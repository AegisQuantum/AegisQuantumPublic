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

import { doubleRatchetEncrypt, doubleRatchetDecrypt } from "../crypto/double-ratchet"; //
import { saveRatchetState, loadRatchetState } from "./key-store";

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

  const myKeys      = await getPublicKeys(myUid);  // déjà importé
  const myKemPubKey = myKeys?.kemPublicKey ?? "";

  // ── 1. Clés du destinataire ───────────────────────────────────────────────
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Clés publiques introuvables pour ${contactUid}`);

  // ── 2. Nos clés privées ───────────────────────────────────────────────────
  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);  // nécessaire pour le Double Ratchet

  //3 ) Charge Ratchet State from IDB (null si 1er message) → ENTRÉE pour doubleRatchetEncrypt()
  const stateJson = await loadRatchetState(myUid, convId);

  //4) KEM init 
  const { sharedSecret: initSecret } = await kemEncapsulate(contactKeys.kemPublicKey);

  const drResult = await doubleRatchetEncrypt(
    plaintext,
    stateJson,
    convId,
    myKemPrivateKey,
    myKemPubKey,           // my public key à récupérer depuis key-registry ou key-store
    contactKeys.kemPublicKey,
    initSecret,
  );

  await saveRatchetState(myUid, convId, drResult.newStateJson);

  // ── 6. DSA sign — INCHANGÉ avec Double Ratchet ───────────────────────────
  //
  // La signature porte sur : ciphertext + nonce + kemCiphertext
  // Avec Double Ratchet : les valeurs viennent de drResult au lieu du bloc ci-dessus.
  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // ── 8. Écrire dans Firestore ──────────────────────────────────────────────
  await addDoc(messagesCol(convId), {
    conversationId: convId,
    senderUid     : myUid,
    ciphertext    : drResult.ciphertext,
    nonce         : drResult.nonce,
    kemCiphertext : drResult.kemCiphertext,
    signature,
    messageIndex  : drResult.messageIndex,
    timestamp     : Date.now(),
  } satisfies Omit<EncryptedMessage, "id">);

  // ── 9. Mettre à jour la preview Firestore ────────────────────────────────
  await updateConversationPreview(convId, plaintext);
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

  // ── 2. Nos clés ───────────────────────────────────────────────────────────
  const myKeys      = await getPublicKeys(myUid);  // déjà importé
  const myKemPubKey = myKeys?.kemPublicKey ?? ""; 

  const myKemPrivKey = getKemPrivateKey(myUid);

  // ── 3. Charger le RatchetState depuis IDB ────────────────────────────────
  const stateJson = await loadRatchetState(myUid, msg.conversationId);

  // ── 4. KEM decapsulate initial ────────────────────────────────────────────
  // Produit le sharedSecret utilisé UNIQUEMENT pour bootstrapper le ratchet
  // si stateJson === null (premier message reçu dans la conversation).
  // Si l'état existe déjà, doubleRatchetDecrypt ignore ce paramètre.
  const initSecret = await kemDecapsulate(msg.kemCiphertext, myKemPrivKey);

  // ── 5. Double Ratchet decrypt ─────────────────────────────────────────────
  const drResult = await doubleRatchetDecrypt(
    msg.ciphertext,
    msg.nonce,
    msg.messageIndex,
    msg.kemCiphertext,
    stateJson,
    msg.conversationId,
    myKemPrivKey,
    myKemPubKey,
    senderKeys?.kemPublicKey ?? "",
    initSecret,
  );

  // ── 6. Sauvegarder le nouvel état ratchet ────────────────────────────────
  await saveRatchetState(myUid, msg.conversationId, drResult.newStateJson);

  return {
    id       : msg.id,
    senderUid: msg.senderUid,
    plaintext: drResult.plaintext,
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

  // Cache local : msgId → DecryptedMessage
  // Évite de re-déchiffrer des messages déjà traités à chaque snapshot Firestore.
  // Critique pour les messages propres (envoyés par nous) : la messageKey est
  // stockée dans IDB par sendMessage(), mais le snapshot peut arriver avant
  // que storeMessageKey() soit terminé → race condition → déchiffrement échoue.
  // En ne re-traitant que les nouveaux docs, on élimine ce problème.
  const decryptedCache = new Map<string, DecryptedMessage>();

  return onSnapshot(q, async (snap) => {
    // Identifier les docs vraiment nouveaux (pas encore dans le cache)
    const newDocs = snap.docs.filter(d => !decryptedCache.has(d.id));

    // Déchiffrer uniquement les nouveaux
    for (const d of newDocs) {
      const msg = { id: d.id, ...d.data() } as EncryptedMessage;
      try {
        decryptedCache.set(msg.id, await decryptMessage(myUid, msg));
      } catch (err) {
        console.error(`[AQ] Échec déchiffrement message ${msg.id}:`, err);
        decryptedCache.set(msg.id, {
          id       : msg.id,
          senderUid: msg.senderUid,
          plaintext: "[🔒 Message non déchiffrable — clés expirées ou session expirée]",
          timestamp: msg.timestamp,
          verified : false,
        });
      }
    }

    // Ne notifier le callback que si de nouveaux messages ont été déchiffrés
    if (newDocs.length === 0) return;

    // Retourner tous les messages dans l'ordre Firestore (timestamp asc)
    callback(snap.docs.map(d => decryptedCache.get(d.id)!));
  });
}
