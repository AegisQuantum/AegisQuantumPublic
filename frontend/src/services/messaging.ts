/**
 * messaging.ts — Envoi et réception de messages chiffrés
 *
 * Responsabilités :
 *  - Construire et envoyer un message chiffré (KEM + AES-GCM + DSA + Double Ratchet)
 *  - Recevoir et déchiffrer les messages entrants
 *  - S'abonner en temps réel aux nouvelles conversations et messages via Firestore
 *  - Gérer la liste de conversations de l'utilisateur connecté
 *
 * Pipeline d'envoi (specs §4.2) :
 *  1. Récupérer la clé publique KEM du destinataire ← key-registry.ts
 *  2. KEM encapsulate → sharedSecret + kemCiphertext ← crypto/kem.ts
 *  3. HKDF sur sharedSecret → messageKey (32 bytes) ← crypto/hkdf.ts
 *  4. Double Ratchet step → clé de message finale ← crypto/double-ratchet.ts
 *  5. AES-256-GCM encrypt(plaintext, messageKey) → ciphertext + nonce ← crypto/aes-gcm.ts
 *  6. DSA sign(ciphertext || nonce || kemCiphertext) → signature ← crypto/dsa.ts
 *  7. Écrire le document EncryptedMessage dans Firestore
 *
 * Pipeline de réception :
 *  1. Lire le document EncryptedMessage depuis Firestore
 *  2. DSA verify(signature, senderDsaPublicKey) ← crypto/dsa.ts
 *  3. KEM decapsulate(kemCiphertext, ourKemPrivateKey) → sharedSecret ← crypto/kem.ts
 *  4. HKDF sur sharedSecret → messageKey ← crypto/hkdf.ts
 *  5. Double Ratchet step ← crypto/double-ratchet.ts
 *  6. AES-256-GCM decrypt(ciphertext, nonce, messageKey) → plaintext ← crypto/aes-gcm.ts
 */

import {
  collection,
  doc,
  addDoc,
  getDoc,
  getDocs,
  query,
  where,
  orderBy,
  onSnapshot,
  serverTimestamp,
  type Unsubscribe,
} from "firebase/firestore";
import { db } from "./firebase";
import { getPublicKeys } from "./key-registry";
import { getKemPrivateKey, getDsaPrivateKey, saveRatchetState, loadRatchetState } from "./key-store";
import type { EncryptedMessage, Conversation, DecryptedMessage } from "../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// DÉPENDANCES CRYPTO — à brancher une fois les modules crypto implémentés
// ─────────────────────────────────────────────────────────────────────────────

/**
 * TODO: importer kemEncapsulate() et kemDecapsulate() depuis crypto/kem.ts
 *
 * kemEncapsulate(recipientPublicKeyB64: string): Promise<{ sharedSecret: string; ciphertext: string }>
 *   → sharedSecret : Base64 (32 bytes) — input pour HKDF
 *   → ciphertext   : Base64 (1088 bytes) — stocké dans le message Firestore
 *
 * kemDecapsulate(ciphertextB64: string, privateKeyB64: string): Promise<string>
 *   → retourne sharedSecret Base64 (32 bytes)
 */
async function _kemEncapsulate(_recipientPublicKey: string): Promise<{ sharedSecret: string; ciphertext: string }> {
  throw new Error("TODO: brancher kemEncapsulate() depuis crypto/kem.ts");
}
async function _kemDecapsulate(_ciphertext: string, _privateKey: string): Promise<string> {
  throw new Error("TODO: brancher kemDecapsulate() depuis crypto/kem.ts");
}

/**
 * TODO: importer hkdfDerive() depuis crypto/hkdf.ts
 *
 * hkdfDerive(secret: string, info: string, length?: number): Promise<string>
 *   → secret : Base64 — shared secret KEM (32 bytes)
 *   → info   : string UTF-8 — contexte de dérivation (ex: "AegisQuantum-message-key")
 *   → length : longueur de la clé dérivée en bytes (défaut 32)
 *   → retourne Base64 (32 bytes par défaut)
 *
 * Algorithme : HKDF-SHA256 (Web Crypto API)
 */
async function _hkdfDerive(_secret: string, _info: string): Promise<string> {
  throw new Error("TODO: brancher hkdfDerive() depuis crypto/hkdf.ts");
}

/**
 * TODO: importer aesGcmEncrypt() et aesGcmDecrypt() depuis crypto/aes-gcm.ts
 *
 * aesGcmEncrypt(plaintext: string, key: string): Promise<{ ciphertext: string; nonce: string }>
 *   → plaintext : string UTF-8
 *   → key       : Base64 (32 bytes) — clé dérivée via HKDF + Double Ratchet
 *   → ciphertext: Base64 (AES-256-GCM)
 *   → nonce     : Base64 (12 bytes random IV)
 *
 * aesGcmDecrypt(ciphertext: string, nonce: string, key: string): Promise<string>
 *   → retourne le plaintext UTF-8
 *   → lève une erreur si tag GCM invalide
 */
async function _aesGcmEncrypt(_plaintext: string, _key: string): Promise<{ ciphertext: string; nonce: string }> {
  throw new Error("TODO: brancher aesGcmEncrypt() depuis crypto/aes-gcm.ts");
}
async function _aesGcmDecrypt(_ciphertext: string, _nonce: string, _key: string): Promise<string> {
  throw new Error("TODO: brancher aesGcmDecrypt() depuis crypto/aes-gcm.ts");
}

/**
 * TODO: importer dsaSign() et dsaVerify() depuis crypto/dsa.ts
 *
 * dsaSign(message: string, privateKeyB64: string): Promise<string>
 *   → message       : string à signer (ici : ciphertext + nonce + kemCiphertext concaténés)
 *   → privateKeyB64 : Base64 — ML-DSA-65 private key (vient de getDsaPrivateKey() dans key-store.ts)
 *   → retourne signature Base64
 *
 * dsaVerify(message: string, signature: string, publicKeyB64: string): Promise<boolean>
 *   → publicKeyB64 : Base64 — ML-DSA-65 public key du sender (vient de getPublicKeys() dans key-registry.ts)
 *   → retourne true si la signature est valide, false sinon
 */
async function _dsaSign(_message: string, _privateKey: string): Promise<string> {
  throw new Error("TODO: brancher dsaSign() depuis crypto/dsa.ts");
}
async function _dsaVerify(_message: string, _signature: string, _publicKey: string): Promise<boolean> {
  throw new Error("TODO: brancher dsaVerify() depuis crypto/dsa.ts");
}

/**
 * TODO: importer doubleRatchetEncrypt() et doubleRatchetDecrypt() depuis crypto/double-ratchet.ts
 *
 * Ces fonctions wrappent le Double Ratchet complet.
 * Elles prennent/retournent le RatchetState sérialisé (JSON string) pour
 * permettre la persistance dans IndexedDB via key-store.ts.
 *
 * doubleRatchetEncrypt(
 *   plaintext     : string,
 *   stateJson     : string | null,   // null = première utilisation → init ratchet
 *   ourPrivKey    : string,           // Base64 — ML-KEM-768 private key courante
 *   ourPubKey     : string,           // Base64 — ML-KEM-768 public key courante
 *   theirPubKey   : string,           // Base64 — ML-KEM-768 public key du contact
 *   sharedSecret  : string,           // Base64 — shared secret KEM (input au root key)
 * ): Promise<{ ciphertext: string; nonce: string; messageIndex: number; newStateJson: string }>
 *
 * doubleRatchetDecrypt(
 *   ciphertext    : string,
 *   nonce         : string,
 *   messageIndex  : number,
 *   kemCiphertext : string,           // pour reconstruire le shared secret via kemDecapsulate
 *   stateJson     : string | null,
 *   ourPrivKey    : string,
 *   sharedSecret  : string,
 * ): Promise<{ plaintext: string; newStateJson: string }>
 *
 * Toutes les dérivations internes utilisent hkdfDerive() depuis crypto/hkdf.ts.
 */
async function _doubleRatchetEncrypt(
  _plaintext: string,
  _stateJson: string | null,
  _ourPrivKey: string,
  _ourPubKey: string,
  _theirPubKey: string,
  _sharedSecret: string
): Promise<{ ciphertext: string; nonce: string; messageIndex: number; newStateJson: string }> {
  throw new Error("TODO: brancher doubleRatchetEncrypt() depuis crypto/double-ratchet.ts");
}
async function _doubleRatchetDecrypt(
  _ciphertext: string,
  _nonce: string,
  _messageIndex: number,
  _kemCiphertext: string,
  _stateJson: string | null,
  _ourPrivKey: string,
  _sharedSecret: string
): Promise<{ plaintext: string; newStateJson: string }> {
  throw new Error("TODO: brancher doubleRatchetDecrypt() depuis crypto/double-ratchet.ts");
}

// ─────────────────────────────────────────────────────────────────────────────
// Paths Firestore
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Schéma Firestore :
 *  /conversations/{convId}
 *    participants : [uid1, uid2]
 *    lastMessageAt: timestamp
 *    lastMessagePreview: string  (toujours "Message chiffré")
 *
 *  /conversations/{convId}/messages/{msgId}
 *    → EncryptedMessage
 */
const convsCol   = () => collection(db, "conversations");
const convDoc    = (convId: string) => doc(db, "conversations", convId);
const messagesCol = (convId: string) => collection(db, "conversations", convId, "messages");

// ─────────────────────────────────────────────────────────────────────────────
// Gestion des conversations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Retourne l'ID de conversation entre deux utilisateurs.
 * L'ID est déterministe : sorted([uid1, uid2]).join("_")
 * → même ID quelle que soit la direction de l'appel.
 */
export function getConversationId(uid1: string, uid2: string): string {
  return [uid1, uid2].sort().join("_");
}

/**
 * Crée une conversation dans Firestore si elle n'existe pas encore.
 * Appelé par ui/chat.ts quand l'utilisateur démarre une nouvelle conversation.
 *
 * @param myUid       — UID de l'utilisateur courant
 * @param contactUid  — UID du contact
 * @returns convId
 */
export async function getOrCreateConversation(myUid: string, contactUid: string): Promise<string> {
  const convId = getConversationId(myUid, contactUid);
  const snap   = await getDoc(convDoc(convId));
  if (!snap.exists()) {
    await addDoc(convsCol(), {
      id           : convId,
      participants : [myUid, contactUid],
      lastMessageAt: serverTimestamp(),
      lastMessagePreview: "Conversation started",
    });
  }
  return convId;
}

/**
 * Récupère toutes les conversations de l'utilisateur courant.
 * Appelé par ui/chat.ts pour remplir la sidebar.
 *
 * @param myUid — UID de l'utilisateur connecté
 */
export async function getConversations(myUid: string): Promise<Conversation[]> {
  const q    = query(convsCol(), where("participants", "array-contains", myUid));
  const snap = await getDocs(q);
  return snap.docs.map((d) => d.data() as Conversation);
}

/**
 * S'abonne en temps réel aux conversations de l'utilisateur.
 * Appelé par ui/chat.ts au chargement du chat screen.
 *
 * @param myUid    — UID de l'utilisateur connecté
 * @param callback — appelé à chaque mise à jour
 * @returns unsubscribe function
 */
export function subscribeToConversations(
  myUid: string,
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
 * Pipeline complet (voir en-tête du fichier) — les étapes crypto sont en TODO
 * jusqu'à l'implémentation des modules correspondants.
 *
 * @param myUid        — UID de l'expéditeur
 * @param contactUid   — UID du destinataire
 * @param plaintext    — texte clair du message
 * @throws Error si le contact n'a pas de clés publiques enregistrées
 */
export async function sendMessage(
  myUid: string,
  contactUid: string,
  plaintext: string
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  // 1. Récupérer les clés publiques du destinataire depuis Firestore
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`No public keys found for contact ${contactUid}`);

  // 2. Récupérer nos clés privées depuis key-store.ts (en mémoire)
  const myKemPrivateKey = getKemPrivateKey(myUid);
  const myDsaPrivateKey = getDsaPrivateKey(myUid);

  // 3. Charger l'état Double Ratchet courant pour cette conversation
  const ratchetStateJson = await loadRatchetState(myUid, convId);

  // TODO: décommenter le pipeline complet quand les modules crypto seront implémentés
  //
  // // 4. KEM encapsulate avec la clé publique du destinataire
  // const { sharedSecret, ciphertext: kemCiphertext } = await _kemEncapsulate(contactKeys.kemPublicKey);
  //
  // // 5. Double Ratchet encrypt (intègre HKDF + AES-GCM en interne)
  // const myPublicKeys = await getPublicKeys(myUid);
  // const { ciphertext, nonce, messageIndex, newStateJson } = await _doubleRatchetEncrypt(
  //   plaintext,
  //   ratchetStateJson,
  //   myKemPrivateKey,
  //   myPublicKeys!.kemPublicKey,
  //   contactKeys.kemPublicKey,
  //   sharedSecret
  // );
  //
  // // 6. Signer le message (ciphertext || nonce || kemCiphertext)
  // const signedPayload = ciphertext + nonce + kemCiphertext;
  // const signature = await _dsaSign(signedPayload, myDsaPrivateKey);
  //
  // // 7. Persister le nouvel état Double Ratchet
  // await saveRatchetState(myUid, convId, newStateJson);
  //
  // // 8. Écrire dans Firestore
  // const msg: Omit<EncryptedMessage, "id"> = {
  //   conversationId : convId,
  //   senderUid      : myUid,
  //   ciphertext,
  //   nonce,
  //   kemCiphertext,
  //   signature,
  //   messageIndex,
  //   timestamp: Date.now(),
  // };
  // await addDoc(messagesCol(convId), msg);

  // ⚠️ PLACEHOLDER — supprimé une fois la crypto branchée
  void myKemPrivateKey; void myDsaPrivateKey; void ratchetStateJson;
  console.warn("sendMessage: crypto not yet implemented — storing plaintext (DEV ONLY)");
  await addDoc(messagesCol(convId), {
    conversationId : convId,
    senderUid      : myUid,
    ciphertext     : btoa(plaintext), // Base64 du plaintext, PAS du chiffrement
    nonce          : "",
    kemCiphertext  : "",
    signature      : "",
    messageIndex   : 0,
    timestamp      : Date.now(),
    _devUnencrypted: true,            // flag pour repérer les messages non chiffrés
  } satisfies Omit<EncryptedMessage, "id"> & { _devUnencrypted: boolean });
}

// ─────────────────────────────────────────────────────────────────────────────
// Réception de messages
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Déchiffre un message reçu.
 *
 * @param myUid   — UID du destinataire (utilisateur courant)
 * @param msg     — document EncryptedMessage lu depuis Firestore
 * @returns DecryptedMessage avec le plaintext et le statut de vérification DSA
 */
export async function decryptMessage(
  myUid: string,
  msg: EncryptedMessage
): Promise<DecryptedMessage> {
  // TODO: décommenter le pipeline complet quand les modules crypto seront implémentés
  //
  // // 1. Vérifier la signature DSA du sender
  // const senderKeys = await getPublicKeys(msg.senderUid);
  // let verified = false;
  // if (senderKeys) {
  //   const signedPayload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
  //   verified = await _dsaVerify(signedPayload, msg.signature, senderKeys.dsaPublicKey);
  // }
  //
  // // 2. KEM decapsulate pour récupérer le shared secret
  // const myKemPrivateKey = getKemPrivateKey(myUid);
  // const sharedSecret = await _kemDecapsulate(msg.kemCiphertext, myKemPrivateKey);
  //
  // // 3. Double Ratchet decrypt
  // const ratchetStateJson = await loadRatchetState(myUid, msg.conversationId);
  // const { plaintext, newStateJson } = await _doubleRatchetDecrypt(
  //   msg.ciphertext,
  //   msg.nonce,
  //   msg.messageIndex,
  //   msg.kemCiphertext,
  //   ratchetStateJson,
  //   myKemPrivateKey,
  //   sharedSecret
  // );
  //
  // // 4. Persister le nouvel état Double Ratchet
  // await saveRatchetState(myUid, msg.conversationId, newStateJson);
  //
  // return { id: msg.id, senderUid: msg.senderUid, plaintext, timestamp: msg.timestamp, verified };

  // ⚠️ PLACEHOLDER — supprimé une fois la crypto branchée
  void myUid;
  console.warn("decryptMessage: crypto not yet implemented — reading Base64 plaintext (DEV ONLY)");
  return {
    id        : msg.id,
    senderUid : msg.senderUid,
    plaintext : atob(msg.ciphertext),
    timestamp : msg.timestamp,
    verified  : false,
  };
}

/**
 * S'abonne en temps réel aux messages d'une conversation.
 * Déchiffre chaque message à la réception et appelle le callback.
 *
 * Appelé par ui/chat.ts quand l'utilisateur sélectionne une conversation.
 *
 * @param myUid          — UID de l'utilisateur connecté
 * @param conversationId — ID de la conversation
 * @param callback       — appelé avec la liste complète des messages déchiffrés
 * @returns unsubscribe function
 */
export function subscribeToMessages(
  myUid: string,
  conversationId: string,
  callback: (messages: DecryptedMessage[]) => void
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
        console.error(`Failed to decrypt message ${msg.id}:`, err);
        decrypted.push({
          id        : msg.id,
          senderUid : msg.senderUid,
          plaintext : "[Decryption failed]",
          timestamp : msg.timestamp,
          verified  : false,
        });
      }
    }
    callback(decrypted);
  });
}
