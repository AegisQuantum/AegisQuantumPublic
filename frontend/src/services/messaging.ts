/**
 * messaging.ts — Envoi et réception de messages chiffrés
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PIPELINE ACTUEL (sans Double Ratchet — fonctionnel)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  ENVOI :
 *   1. Récupérer la clé publique KEM du destinataire ← key-registry.ts
 *   2. KEM encapsulate → sharedSecret + kemCiphertext ← crypto/kem.ts
 *   3. HKDF(sharedSecret) → messageKey ← crypto/hkdf.ts
 *   4. AES-256-GCM encrypt(plaintext, messageKey) → ciphertext + nonce ← crypto/aes-gcm.ts
 *   5. DSA sign(ciphertext || nonce || kemCiphertext) → signature ← crypto/dsa.ts
 *   6. Écrire EncryptedMessage dans Firestore
 *
 *  RÉCEPTION :
 *   1. DSA verify(signature, senderDsaPublicKey) ← crypto/dsa.ts
 *   2. KEM decapsulate(kemCiphertext, ourKemPrivateKey) → sharedSecret ← crypto/kem.ts
 *   3. HKDF(sharedSecret) → messageKey ← crypto/hkdf.ts
 *   4. AES-256-GCM decrypt(ciphertext, nonce, messageKey) → plaintext ← crypto/aes-gcm.ts
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * TODO — Double Ratchet (à implémenter dans crypto/double-ratchet.ts)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Quand doubleRatchetEncrypt / doubleRatchetDecrypt seront implémentés :
 *
 *  ENVOI — remplacer les étapes 3+4 par :
 *    const { ciphertext, nonce, kemCiphertext: ratchetKemCT, messageIndex, newStateJson }
 *      = await doubleRatchetEncrypt(plaintext, stateJson, convId, myPrivKey, myPubKey, theirPubKey, sharedSecret);
 *    await saveRatchetState(myUid, convId, newStateJson);
 *
 *  RÉCEPTION — remplacer les étapes 3+4 par :
 *    const { plaintext, newStateJson }
 *      = await doubleRatchetDecrypt(ciphertext, nonce, messageIndex, kemCiphertext,
 *          stateJson, convId, myPrivKey, myPubKey, theirPubKey, sharedSecret);
 *    await saveRatchetState(myUid, convId, newStateJson);
 *
 *  Supprimer ensuite les imports hkdfDerive + aesGcmEncrypt/Decrypt directs de ce fichier.
 */

import {
  collection, doc, addDoc, setDoc, getDoc, getDocs,
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
// Paths Firestore
// ─────────────────────────────────────────────────────────────────────────────

const convsCol    = () => collection(db, "conversations");
const convDoc     = (convId: string) => doc(db, "conversations", convId);
const messagesCol = (convId: string) => collection(db, "conversations", convId, "messages");

// ─────────────────────────────────────────────────────────────────────────────
// Gestion des conversations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Retourne l'ID de conversation déterministe entre deux utilisateurs.
 * sorted([uid1, uid2]).join("_") → même ID dans les deux sens.
 */
export function getConversationId(uid1: string, uid2: string): string {
  return [uid1, uid2].sort().join("_");
}

/** Crée une conversation dans Firestore si elle n'existe pas encore. */
export async function getOrCreateConversation(myUid: string, contactUid: string): Promise<string> {
  const convId = getConversationId(myUid, contactUid);
  const snap   = await getDoc(convDoc(convId));
  if (!snap.exists()) {
    // setDoc avec l'ID déterministe — addDoc génèrerait un ID aléatoire
    // ce qui casserait les règles Firestore et la récupération par ID
    await setDoc(convDoc(convId), {
      id                : convId,
      participants      : [myUid, contactUid],
      lastMessageAt     : serverTimestamp(),
      lastMessagePreview: "Conversation started",
    });
  }
  return convId;
}

/** Récupère toutes les conversations de l'utilisateur courant. */
export async function getConversations(myUid: string): Promise<Conversation[]> {
  const q    = query(convsCol(), where("participants", "array-contains", myUid));
  const snap = await getDocs(q);
  return snap.docs.map((d) => d.data() as Conversation);
}

/** S'abonne en temps réel aux conversations de l'utilisateur. */
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

/**
 * Chiffre et envoie un message à un contact.
 *
 * Pipeline : KEM encapsulate → HKDF → AES-256-GCM → DSA sign → Firestore
 *
 * TODO : remplacer HKDF+AES-GCM directs par doubleRatchetEncrypt()
 *        quand crypto/double-ratchet.ts sera implémenté (voir en-tête du fichier).
 *
 * @param myUid      — UID de l'expéditeur
 * @param contactUid — UID du destinataire
 * @param plaintext  — texte clair du message
 */
export async function sendMessage(
  myUid     : string,
  contactUid: string,
  plaintext : string
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  // 1. Récupérer les clés publiques du destinataire
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`No public keys for contact ${contactUid}`);

  // 2. Récupérer nos clés privées depuis la mémoire (key-store.ts)
  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid); // non-utilisé sans Double Ratchet mais référencé

  // 3. KEM encapsulate → sharedSecret + kemCiphertext
  const { sharedSecret, ciphertext: kemCiphertext } = await kemEncapsulate(
    contactKeys.kemPublicKey
  );

  // 4. HKDF(sharedSecret) → messageKey
  //    TODO — Double Ratchet : cette étape sera internalisée dans doubleRatchetEncrypt()
  const messageKey = await hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY);

  // 5. AES-256-GCM encrypt
  //    TODO — Double Ratchet : cette étape sera internalisée dans doubleRatchetEncrypt()
  const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);

  // 6. DSA sign(ciphertext || nonce || kemCiphertext)
  const signedPayload = ciphertext + nonce + kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // 7. Écrire dans Firestore
  //    messageIndex = 0 — sera géré par le Double Ratchet
  const msg: Omit<EncryptedMessage, "id"> = {
    conversationId: convId,
    senderUid     : myUid,
    ciphertext,
    nonce,
    kemCiphertext,
    signature,
    messageIndex  : 0, // TODO — Double Ratchet : ratchet.sendCount
    timestamp     : Date.now(),
  };
  await addDoc(messagesCol(convId), msg);

  void myKemPrivateKey; // référencé pour lint — sera utilisé par le Double Ratchet
}

// ─────────────────────────────────────────────────────────────────────────────
// Réception de messages
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Déchiffre un message reçu.
 *
 * Pipeline : DSA verify → KEM decapsulate → HKDF → AES-256-GCM decrypt
 *
 * TODO : remplacer HKDF+AES-GCM directs par doubleRatchetDecrypt()
 *        quand crypto/double-ratchet.ts sera implémenté (voir en-tête du fichier).
 *
 * @param myUid — UID du destinataire (utilisateur courant)
 * @param msg   — document EncryptedMessage depuis Firestore
 */
export async function decryptMessage(
  myUid: string,
  msg  : EncryptedMessage
): Promise<DecryptedMessage> {
  // 1. Vérifier la signature DSA du sender (authenticité + intégrité)
  const senderKeys = await getPublicKeys(msg.senderUid);
  let   verified   = false;
  if (senderKeys) {
    const signedPayload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(signedPayload, msg.signature, senderKeys.dsaPublicKey);
  }

  // 2. KEM decapsulate → sharedSecret
  let myKemPrivateKey: string;
  try {
    myKemPrivateKey = getKemPrivateKey(myUid);
  } catch {
    throw new Error(`Clés privées non chargées pour ${myUid} — reconnectez-vous pour déchiffrer le vault.`);
  }
  const sharedSecret = await kemDecapsulate(msg.kemCiphertext, myKemPrivateKey);

  // 3. HKDF(sharedSecret) → messageKey
  //    TODO — Double Ratchet : cette étape sera internalisée dans doubleRatchetDecrypt()
  const messageKey = await hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY);

  // 4. AES-256-GCM decrypt
  //    TODO — Double Ratchet : cette étape sera internalisée dans doubleRatchetDecrypt()
  const plaintext = await aesGcmDecrypt(msg.ciphertext, msg.nonce, messageKey);

  return {
    id       : msg.id,
    senderUid: msg.senderUid,
    plaintext,
    timestamp: msg.timestamp,
    verified,
  };
}

/**
 * S'abonne en temps réel aux messages d'une conversation.
 * Déchiffre chaque message à la réception.
 */
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
        const dec = await decryptMessage(myUid, msg);
        decrypted.push(dec);
      } catch (err) {
        console.error(`[AQ] Failed to decrypt message ${msg.id}:`, err);
        decrypted.push({
          id       : msg.id,
          senderUid: msg.senderUid,
          plaintext: "[Decryption failed]",
          timestamp: msg.timestamp,
          verified : false,
        });
      }
    }
    callback(decrypted);
  });
}
