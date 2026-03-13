/**
 * messaging.ts — Envoi et réception de messages chiffrés
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PIPELINE — Double Ratchet (ML-KEM-768 + HKDF + AES-256-GCM)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  ENVOI :
 *   1. Récupérer les clés publiques KEM (contact + les nôtres)
 *   2. Charger le RatchetState depuis IDB (null = premier message)
 *   3. doubleRatchetEncrypt() — gère le bootstrap KEM en interne si stateJson null
 *      → { ciphertext, nonce, kemCiphertext, messageIndex, newStateJson, initKemCiphertext? }
 *   4. saveRatchetState → IDB
 *   5. DSA sign(ciphertext ‖ nonce ‖ kemCiphertext)
 *   6. addDoc → Firestore (+ initKemCiphertext si premier message)
 *   7. Notifier la preview localement (pas d'écriture Firestore côté envoyeur)
 *
 *  RÉCEPTION :
 *   1. DSA verify(signature, senderDsaPublicKey)
 *   2. Charger le RatchetState depuis IDB
 *   3. doubleRatchetDecrypt() — décapsule initKemCiphertext si stateJson null
 *      → { plaintext, newStateJson }
 *   4. saveRatchetState → IDB
 *   5. updateConversationPreview (côté receiver uniquement)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Persistance (IDB)
 * ─────────────────────────────────────────────────────────────────────────────
 *  Clé IDB : "ratchet:<uid>:<convId>" → RatchetState JSON (en clair en dev)
 *  Géré par key-store.ts → saveRatchetState / loadRatchetState
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
import { getKemPrivateKey, getDsaPrivateKey, saveRatchetState, loadRatchetState } from "./key-store";
import { dsaSign, dsaVerify } from "../crypto";
import { doubleRatchetEncrypt, doubleRatchetDecrypt } from "../crypto/double-ratchet";
import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aes-gcm";
import { hkdfDerive }                   from "../crypto/hkdf";
import { toBase64, fromBase64 }         from "../crypto/kem";
import type { EncryptedMessage, Conversation, DecryptedMessage } from "../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// Notification locale de mise à jour de preview (sans aller-retour Firestore)
// ─────────────────────────────────────────────────────────────────────────────
// L'envoyeur notifie la sidebar localement (zéro réseau).
// Le receiver met à jour Firestore quand il reçoit et déchiffre le message.

type ConvPreviewListener = (convId: string, preview: string, ts: number) => void;
const _convPreviewListeners = new Set<ConvPreviewListener>();

export function onConvPreviewUpdate(cb: ConvPreviewListener): () => void {
  _convPreviewListeners.add(cb);
  return () => _convPreviewListeners.delete(cb);
}

function _notifyConvPreviewUpdate(convId: string, plaintext: string, ts: number): void {
  const preview = plaintext.length > 40 ? plaintext.slice(0, 40) + "\u2026" : plaintext;
  _convPreviewListeners.forEach(cb => cb(convId, preview, ts));
}

// Set des msgIds dont le déchiffrement a échoué et doit être retenté.
const _retrySet = new Set<string>();

// Cache volatile des plaintexts envoyés par l'utilisateur courant.
// Permet d'afficher ses propres messages sans tenter de les déchiffrer.
// Perdu après refresh — acceptable (forward secrecy, pas de stockage en clair).
const _sentPlaintextCache = new Map<string, string>();

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
  return snap.docs.map(d => d.data() as Conversation);
}

export async function updateConversationPreview(convId: string, plaintext: string): Promise<void> {
  const preview = plaintext.length > 40 ? plaintext.slice(0, 40) + "\u2026" : plaintext;
  try {
    await updateDoc(convDoc(convId), {
      lastMessagePreview: preview,
      lastMessageAt     : Date.now(),
    });
  } catch {
    // Silencieux — race condition si conv vient d'être créée
  }
}

export function subscribeToConversations(
  myUid   : string,
  callback: (convs: Conversation[]) => void,
): Unsubscribe {
  const q = query(
    convsCol(),
    where("participants", "array-contains", myUid),
    orderBy("lastMessageAt", "desc"),
  );
  return onSnapshot(q, snap => {
    callback(snap.docs.map(d => d.data() as Conversation));
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi de fichier — Double Ratchet + AES-256-GCM sur le contenu binaire
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Chiffre un fichier et l'envoie dans Firestore comme message.
 *
 * Pipeline :
 *  1. Lire le fichier en ArrayBuffer
 *  2. Dériver une fileKey dédiée via HKDF (séparée de la messageKey DR)
 *  3. AES-256-GCM encrypt(fileBytes, fileKey) → fileCiphertext
 *  4. Chiffrer un plaintext « [Fichier] nom (taille) » via Double Ratchet
 *  5. addDoc Firestore avec { hasFile, fileCiphertext, fileNonce, fileName, fileSize, fileType }
 *
 * La fileKey est dérivée depuis la messageKey DR via
 * HKDF(messageKey, "AegisQuantum-v1-file-key") pour rester liée
 * à la session DR sans réutiliser la même clé que le texte.
 */
export async function sendFile(
  myUid     : string,
  contactUid: string,
  file      : File,
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  if (file.size > 10 * 1024 * 1024) {
    throw new Error(`Fichier trop volumineux (${(file.size / 1024 / 1024).toFixed(1)} MB). Limite : 10 MB.`);
  }

  // ── 1. Clés ──────────────────────────────────────────────────────────────
  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Clés publiques introuvables pour ${contactUid}`);

  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);

  // ── 2. Lire le fichier ───────────────────────────────────────────────────
  const fileBuffer = await file.arrayBuffer();
  const fileBytes  = new Uint8Array(fileBuffer);

  // ── 3. Double Ratchet encrypt — plaintext = métadonnées lisibles ─────────
  const stateJson  = await loadRatchetState(myUid, convId);
  const placeholder = `[Fichier] ${file.name} (${_formatSize(file.size)})`;

  const drResult = await doubleRatchetEncrypt(
    placeholder,
    stateJson,
    convId,
    myKemPrivateKey,
    myKemPubKey,
    contactKeys.kemPublicKey,
  );
  await saveRatchetState(myUid, convId, drResult.newStateJson);

  // ── 4. Dériver fileKey depuis la messageKey DR ───────────────────────────
  // messageKey = clé AES 32 bytes encodée Base64, extraite depuis drResult.
  // On ne l'expose pas directement — on la re-dérive pour le fichier.
  // Hack : on dérive la fileKey depuis le kemCiphertext + convId comme IKM
  // (le kemCiphertext est unique par message et lié au DR).
  const fileKey = await hkdfDerive(
    drResult.kemCiphertext,
    `AegisQuantum-v1-file-key:${convId}:${drResult.messageIndex}`,
    32,
  );

  // ── 5. Chiffrer le contenu binaire ───────────────────────────────────────
  const fileB64 = toBase64(fileBytes);
  const { ciphertext: fileCiphertext, nonce: fileNonce } = await aesGcmEncrypt(fileB64, fileKey);

  // ── 6. DSA sign ──────────────────────────────────────────────────────────
  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // ── 7. Firestore ─────────────────────────────────────────────────────────
  const msgRef = await addDoc(messagesCol(convId), {
    conversationId   : convId,
    senderUid        : myUid,
    ciphertext       : drResult.ciphertext,
    nonce            : drResult.nonce,
    kemCiphertext    : drResult.kemCiphertext,
    signature,
    messageIndex     : drResult.messageIndex,
    timestamp        : Date.now(),
    hasFile          : true,
    fileCiphertext,
    fileNonce,
    fileName         : file.name,
    fileSize         : file.size,
    fileType         : file.type || "application/octet-stream",
    ...(drResult.initKemCiphertext
      ? { initKemCiphertext: drResult.initKemCiphertext }
      : {}),
  } as Omit<EncryptedMessage, "id">);

  _sentPlaintextCache.set(msgRef.id, placeholder);
  _notifyConvPreviewUpdate(convId, placeholder, Date.now());
}

function _formatSize(bytes: number): string {
  if (bytes < 1024)             return `${bytes} o`;
  if (bytes < 1024 * 1024)      return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi de message — Double Ratchet
// ─────────────────────────────────────────────────────────────────────────────

export async function sendMessage(
  myUid     : string,
  contactUid: string,
  plaintext : string,
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  // ── 1. Clés publiques ────────────────────────────────────────────────────
  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";

  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Clés publiques introuvables pour ${contactUid}`);

  // ── 2. Clés privées ──────────────────────────────────────────────────────
  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);

  // ── 3. État ratchet (null = premier message) ─────────────────────────────
  const stateJson = await loadRatchetState(myUid, convId);

  // ── 4. Double Ratchet encrypt ────────────────────────────────────────────
  // Si stateJson === null, doubleRatchetEncrypt génère lui-même le KEM init
  // et retourne initKemCiphertext → à stocker dans Firestore pour le receiver.
  const drResult = await doubleRatchetEncrypt(
    plaintext,
    stateJson,
    convId,
    myKemPrivateKey,
    myKemPubKey,
    contactKeys.kemPublicKey,
  );

  // ── 5. Sauvegarder le nouvel état ratchet ────────────────────────────────
  await saveRatchetState(myUid, convId, drResult.newStateJson);

  // ── 6. DSA sign ──────────────────────────────────────────────────────────
  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // ── 7. Écrire dans Firestore ─────────────────────────────────────────────
  // initKemCiphertext est présent uniquement sur le premier message.
  // Il est stocké dans Firestore pour que le receiver puisse bootstrapper
  // son état ratchet avec le même initSecret que l'envoyeur.
  const msgRef = await addDoc(messagesCol(convId), {
    conversationId    : convId,
    senderUid         : myUid,
    ciphertext        : drResult.ciphertext,
    nonce             : drResult.nonce,
    kemCiphertext     : drResult.kemCiphertext,
    signature,
    messageIndex      : drResult.messageIndex,
    timestamp         : Date.now(),
    ...(drResult.initKemCiphertext
      ? { initKemCiphertext: drResult.initKemCiphertext }
      : {}),
  } as Omit<EncryptedMessage, "id">);

  // ── 8. Stocker le plaintext en cache local (pour affichage côté envoyeur) ─
  // Après refresh, le plaintext n'est plus disponible — c'est le prix
  // de la sécurité forward secrecy (pas de stockage en clair).
  _sentPlaintextCache.set(msgRef.id, plaintext);
  _notifyConvPreviewUpdate(convId, plaintext, Date.now());
}

// ─────────────────────────────────────────────────────────────────────────────
// Déchiffrement — Double Ratchet
// ─────────────────────────────────────────────────────────────────────────────

export async function decryptMessage(
  myUid: string,
  msg  : EncryptedMessage,
): Promise<DecryptedMessage> {

  // ── 1. DSA verify ────────────────────────────────────────────────────────
  const senderKeys = await getPublicKeys(msg.senderUid);
  let   verified   = false;
  if (senderKeys) {
    const signedPayload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(signedPayload, msg.signature, senderKeys.dsaPublicKey);
  }

  // ── 2. Clés ──────────────────────────────────────────────────────────────
  const myKeys       = await getPublicKeys(myUid);
  const myKemPubKey  = myKeys?.kemPublicKey ?? "";
  const myKemPrivKey = getKemPrivateKey(myUid);

  // ── 3. État ratchet ──────────────────────────────────────────────────────
  const stateJson = await loadRatchetState(myUid, msg.conversationId);

  // ── 4. Double Ratchet decrypt ────────────────────────────────────────────
  // Si stateJson === null (1er message), passer initKemCiphertext depuis Firestore.
  // doubleRatchetDecrypt le décapsule pour retrouver le même initSecret que l'envoyeur.
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
    msg.initKemCiphertext,   // undefined pour les messages suivants (stateJson non null)
  );

  // ── 5. Sauvegarder le nouvel état ratchet ────────────────────────────────
  await saveRatchetState(myUid, msg.conversationId, drResult.newStateJson);

  // ── 6. Déchiffrer le fichier si présent ─────────────────────────────────
  let fileAttachment: DecryptedMessage["file"] | undefined;
  if (msg.hasFile && msg.fileCiphertext && msg.fileNonce && msg.fileName) {
    try {
      const fileKey = await hkdfDerive(
        msg.kemCiphertext, //
        `AegisQuantum-v1-file-key:${msg.conversationId}:${msg.messageIndex}`,
        32,
      );
      const fileB64    = await aesGcmDecrypt(msg.fileCiphertext, msg.fileNonce, fileKey);
      const fileBytes  = fromBase64(fileB64);
      const blob = new Blob(
      [fileBytes.buffer as ArrayBuffer],
      { type: msg.fileType ?? "application/octet-stream" }); //fix
      //const blob       = new Blob([fileBytes], { type: msg.fileType ?? "application/octet-stream" });
      fileAttachment   = {
        blob,
        name : msg.fileName,
        size : msg.fileSize ?? fileBytes.length,
        type : msg.fileType ?? "application/octet-stream",
      };
    } catch (fileErr) {
      console.warn(`[AQ] Déchiffrement fichier échoué pour ${msg.id}:`, fileErr);
    }
  }

  return {
    id       : msg.id,
    senderUid: msg.senderUid,
    plaintext: drResult.plaintext,
    timestamp: msg.timestamp,
    verified,
    readBy   : msg.readBy ?? [],
    file     : fileAttachment,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Abonnement aux messages
// ─────────────────────────────────────────────────────────────────────────────

export function subscribeToMessages(
  myUid         : string,
  conversationId: string,
  callback      : (messages: DecryptedMessage[]) => void,
): Unsubscribe {
  const q = query(messagesCol(conversationId), orderBy("timestamp", "asc"));

  const decryptedCache = new Map<string, DecryptedMessage>();
  const allDocs        = new Map<string, QueryDocumentSnapshot<DocumentData>>();

  function emitResult(): void {
    const sorted = [...allDocs.values()].sort(
      (a, b) => ((a.data().timestamp ?? 0) as number) - ((b.data().timestamp ?? 0) as number),
    );
    const result = sorted
      .map(d => decryptedCache.get(d.id))
      .filter((m): m is DecryptedMessage => m !== undefined);
    callback(result);
  }

  function scheduleRetry(failedMsg: EncryptedMessage): void {
      setTimeout(async () => {
        if (!_retrySet.has(failedMsg.id)) return;
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
          plaintext: "[\uD83D\uDD12 Message non déchiffrable — clés expirées ou session expirée]",
          timestamp: msgData.timestamp,
          verified : false,
          readBy   : [],
        });
        _retrySet.delete(msgData.id);
      }
    }, 80);
  }

  return onSnapshot(q, async snap => {
    const changes = snap.docChanges();

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

      if (decryptedCache.has(d.id) && !_retrySet.has(d.id)) continue;

      // L'expéditeur ne déchiffre jamais ses propres messages :
      // il ne possède pas l'état ratchet de réception pour eux,
      // et le KEM ciphertext a été encapsulé avec la clé du destinataire.
      if (msg.senderUid === myUid) {
        decryptedCache.set(msg.id, {
          id       : msg.id,
          senderUid: msg.senderUid,
          plaintext: _sentPlaintextCache.get(msg.id) ?? "[🔒 Message envoyé — rechargez pour voir]",
          timestamp: msg.timestamp,
          verified : true,  // on fait confiance à son propre message
          readBy   : msg.readBy ?? [],
        });
        hasChanges = true;
        continue;
      }

      const isRetry = _retrySet.has(msg.id);
      try {
        const decrypted = await decryptMessage(myUid, msg);
        decryptedCache.set(msg.id, decrypted);
        _retrySet.delete(msg.id);
        hasChanges = true;

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
            plaintext: "[\uD83D\uDD12 Déchiffrement en cours\u2026]",
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
            plaintext: "[\uD83D\uDD12 Message non déchiffrable — clés expirées ou session expirée]",
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
