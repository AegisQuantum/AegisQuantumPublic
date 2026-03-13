/**
 * messaging.ts — Envoi et réception de messages chiffrés (Double Ratchet)
 *
 * STRATEGIE D'AFFICHAGE SANS FLASH :
 * ------------------------------------
 * L'emetteur et le recepteur sont tous deux de simples "spectateurs" du flux
 * onSnapshot Firestore. La difference est que l'emetteur pre-peuple le cache
 * decryptedCache avec son message APRES avoir obtenu le vrai ID Firestore
 * (addDoc), puis notifie les subscribers. Quand le snapshot arrive ensuite,
 * decryptedCache.has(realId) === true -> skip -> zero rerender.
 *
 * PIPELINE ENVOI :
 *  1. Cles publiques + Double Ratchet encrypt
 *  2. saveRatchetState IDB
 *  3. DSA sign
 *  4. addDoc -> Firestore -> realId connu
 *  5. _preloadSentMessage(convId, realMsg) -> injecte dans decryptedCache de tous les subscribers
 *  6. emitResult -> renderMessages voit le message avec realId -> bulle creee, _renderedMsgIds.add(realId)
 *  7. Snapshot Firestore arrive (realId, "added") -> decryptedCache.has(realId) == true -> SKIP
 *
 * PIPELINE RECEPTION :
 *  1. Snapshot arrive (change.type = "added")
 *  2. DSA verify + Double Ratchet decrypt
 *  3. saveRatchetState IDB
 *  4. decryptedCache.set(msgId, decrypted) -> emitResult -> renderMessages
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

// ---------------------------------------------------------------------------
// Preview sidebar locale (zero Firestore cote emetteur)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Retry — dechiffrement differe (race condition)
// ---------------------------------------------------------------------------
const _retrySet = new Set<string>();

// ---------------------------------------------------------------------------
// Pre-load envoye — injecte APRES addDoc (realId connu) dans decryptedCache
//
// Fonctionnement :
//  1. sendMessage() appelle addDoc -> obtient realId
//  2. Appelle _preloadSentMessage(convId, { id: realId, ... })
//  3. Chaque subscriber actif pour cette conv reçoit le message via preloadFn
//  4. Le subscriber l'insere dans decryptedCache + appelle emitResult
//  5. renderMessages cree la bulle avec realId, ajoute realId dans _renderedMsgIds
//  6. Snapshot Firestore arrive : decryptedCache.has(realId) == true -> SKIP
//     -> aucun rerender, aucun flash
// ---------------------------------------------------------------------------

type PreloadFn = (msg: DecryptedMessage) => void;
const _preloadListeners = new Map<string, Set<PreloadFn>>();

function _registerPreloadListener(convId: string, fn: PreloadFn): () => void {
  if (!_preloadListeners.has(convId)) _preloadListeners.set(convId, new Set());
  _preloadListeners.get(convId)!.add(fn);
  return () => _preloadListeners.get(convId)?.delete(fn);
}

function _preloadSentMessage(convId: string, msg: DecryptedMessage): void {
  _preloadListeners.get(convId)?.forEach(fn => fn(msg));
}

// ---------------------------------------------------------------------------
// Paths Firestore
// ---------------------------------------------------------------------------

const convsCol    = () => collection(db, "conversations");
const convDoc     = (convId: string) => doc(db, "conversations", convId);
const messagesCol = (convId: string) => collection(db, "conversations", convId, "messages");

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

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
      lastMessagePreview: "Conversation demarree",
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
    // Silencieux
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

// ---------------------------------------------------------------------------
// Envoi fichier
// ---------------------------------------------------------------------------

export async function sendFile(
  myUid     : string,
  contactUid: string,
  file      : File,
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  if (file.size > 10 * 1024 * 1024) {
    throw new Error(`Fichier trop volumineux (${(file.size / 1024 / 1024).toFixed(1)} MB). Limite : 10 MB.`);
  }

  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Cles publiques introuvables pour ${contactUid}`);

  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);

  const fileBuffer = await file.arrayBuffer();
  const fileBytes  = new Uint8Array(fileBuffer);

  const stateJson   = await loadRatchetState(myUid, convId);
  const placeholder = `[Fichier] ${file.name} (${_formatSize(file.size)})`;

  const drResult = await doubleRatchetEncrypt(
    placeholder, stateJson, convId, myKemPrivateKey, myKemPubKey, contactKeys.kemPublicKey,
  );
  await saveRatchetState(myUid, convId, drResult.newStateJson);

  const fileKey = await hkdfDerive(
    drResult.kemCiphertext,
    `AegisQuantum-v1-file-key:${convId}:${drResult.messageIndex}`,
    32,
  );
  const fileB64 = toBase64(fileBytes);
  const { ciphertext: fileCiphertext, nonce: fileNonce } = await aesGcmEncrypt(fileB64, fileKey);

  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);
  const ts            = Date.now();

  const msgRef = await addDoc(messagesCol(convId), {
    conversationId   : convId,
    senderUid        : myUid,
    ciphertext       : drResult.ciphertext,
    nonce            : drResult.nonce,
    kemCiphertext    : drResult.kemCiphertext,
    senderEphPub     : drResult.senderEphPub, // <-- ADD THIS
    signature,
    messageIndex     : drResult.messageIndex,
    timestamp        : ts,
    hasFile          : true,
    fileCiphertext,
    fileNonce,
    fileName         : file.name,
    fileSize         : file.size,
    fileType         : file.type || "application/octet-stream",
    ...(drResult.initKemCiphertext ? { initKemCiphertext: drResult.initKemCiphertext } : {}),
  } as Omit<EncryptedMessage, "id">);

  // Preload avec le VRAI ID — le snapshot ne fera rien de plus
  _preloadSentMessage(convId, {
    id: msgRef.id, senderUid: myUid, plaintext: placeholder,
    timestamp: ts, verified: true, readBy: [],
  });
  _notifyConvPreviewUpdate(convId, placeholder, ts);
}

function _formatSize(bytes: number): string {
  if (bytes < 1024)        return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

// ---------------------------------------------------------------------------
// Envoi message texte
// ---------------------------------------------------------------------------

export async function sendMessage(
  myUid     : string,
  contactUid: string,
  plaintext : string,
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Cles publiques introuvables pour ${contactUid}`);

  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);

  const stateJson = await loadRatchetState(myUid, convId);

  const drResult = await doubleRatchetEncrypt(
    plaintext, stateJson, convId, myKemPrivateKey, myKemPubKey, contactKeys.kemPublicKey,
  );

  await saveRatchetState(myUid, convId, drResult.newStateJson);

  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);
  const ts            = Date.now();

  // addDoc d'abord — on obtient le realId avant de notifier le cache
  const msgRef = await addDoc(messagesCol(convId), {
    conversationId    : convId,
    senderUid         : myUid,
    ciphertext        : drResult.ciphertext,
    nonce             : drResult.nonce,
    kemCiphertext     : drResult.kemCiphertext,
    senderEphPub      : drResult.senderEphPub, // <-- ADD THIS
    signature,
    messageIndex      : drResult.messageIndex,
    timestamp         : ts,
    ...(drResult.initKemCiphertext ? { initKemCiphertext: drResult.initKemCiphertext } : {}),
  } as Omit<EncryptedMessage, "id">);

  // Injecter dans decryptedCache de tous les subscribers AVEC LE VRAI ID
  // -> quand le snapshot Firestore arrive, decryptedCache.has(realId) == true -> SKIP -> zero flash
  _preloadSentMessage(convId, {
    id: msgRef.id, senderUid: myUid, plaintext,
    timestamp: ts, verified: true, readBy: [],
  });

  _notifyConvPreviewUpdate(convId, plaintext, ts);
}

// ---------------------------------------------------------------------------
// Dechiffrement
// ---------------------------------------------------------------------------

export async function decryptMessage(
  myUid: string,
  msg  : EncryptedMessage,
): Promise<DecryptedMessage> {
  // ── Anciens messages (pre-Double Ratchet) ──────────────────────────────────
  // Les messages envoyes avant l'implementation du Double Ratchet n'ont pas de
  // kemCiphertext ni de messageIndex. On les detecte et on renvoie un placeholder
  // informatif plutot que de crasher.
  const isLegacyMessage = !msg.kemCiphertext || msg.messageIndex === undefined || msg.messageIndex === null;
  if (isLegacyMessage) {
    return {
      id        : msg.id,
      senderUid : msg.senderUid,
      plaintext : "[\uD83D\uDD12 Message ancien — chiffrement pr\u00e9-ratchet, non d\u00e9chiffrable]",
      timestamp : msg.timestamp,
      verified  : false,
      readBy    : msg.readBy ?? [],
    };
  }

  const senderKeys = await getPublicKeys(msg.senderUid);
  let   verified   = false;
  if (senderKeys) {
    const payload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(payload, msg.signature, senderKeys.dsaPublicKey);
  }

  const myKeys       = await getPublicKeys(myUid);
  const myKemPubKey  = myKeys?.kemPublicKey ?? "";
  const myKemPrivKey = getKemPrivateKey(myUid);
  const stateJson    = await loadRatchetState(myUid, msg.conversationId);

  const drResult = await doubleRatchetDecrypt(
    msg.ciphertext, msg.nonce, msg.messageIndex, msg.kemCiphertext,
    msg.senderEphPub,    // <-- ADD THIS
    stateJson, msg.conversationId, myKemPrivKey, myKemPubKey,
    senderKeys?.kemPublicKey ?? "", msg.initKemCiphertext,
  );

  await saveRatchetState(myUid, msg.conversationId, drResult.newStateJson);

  let fileAttachment: DecryptedMessage["file"] | undefined;
  if (msg.hasFile && msg.fileCiphertext && msg.fileNonce && msg.fileName) {
    try {
      const fileKey  = await hkdfDerive(
        msg.kemCiphertext,
        `AegisQuantum-v1-file-key:${msg.conversationId}:${msg.messageIndex}`,
        32,
      );
      const fileB64  = await aesGcmDecrypt(msg.fileCiphertext, msg.fileNonce, fileKey);
      const fileBytes = fromBase64(fileB64);
      const blob     = new Blob([fileBytes.buffer as ArrayBuffer], {
        type: msg.fileType ?? "application/octet-stream",
      });
      fileAttachment = {
        blob, name: msg.fileName,
        size: msg.fileSize ?? fileBytes.length,
        type: msg.fileType ?? "application/octet-stream",
      };
    } catch (e) {
      console.warn(`[AQ] Dechiffrement fichier echoue pour ${msg.id}:`, e);
    }
  }

  return {
    id: msg.id, senderUid: msg.senderUid, plaintext: drResult.plaintext,
    timestamp: msg.timestamp, verified, readBy: msg.readBy ?? [],
    file: fileAttachment,
  };
}

// ---------------------------------------------------------------------------
// subscribeToMessages
// ---------------------------------------------------------------------------

export function subscribeToMessages(
  myUid         : string,
  conversationId: string,
  callback      : (messages: DecryptedMessage[]) => void,
): Unsubscribe {
  const q = query(messagesCol(conversationId), orderBy("timestamp", "asc"));

  const decryptedCache = new Map<string, DecryptedMessage>();
  const allDocs        = new Map<string, QueryDocumentSnapshot<DocumentData>>();

  function emitResult(): void {
    // Messages Firestore confirmes, tries par timestamp
    const result = [...allDocs.values()]
      .sort((a, b) => ((a.data().timestamp ?? 0) as number) - ((b.data().timestamp ?? 0) as number))
      .map(d => decryptedCache.get(d.id))
      .filter((m): m is DecryptedMessage => m !== undefined);

    // Ajouter les messages preloades pas encore dans allDocs
    // (entre _preloadSentMessage et le snapshot Firestore, peut-etre quelques ms)
    const preloaded = [...decryptedCache.values()]
      .filter(m => !allDocs.has(m.id))
      .sort((a, b) => a.timestamp - b.timestamp);

    callback([...result, ...preloaded]);
  }

  // Preload : injecte un message envoye (avec realId) avant le snapshot
  const unregisterPreload = _registerPreloadListener(conversationId, (msg) => {
    decryptedCache.set(msg.id, msg);
    // allDocs ne contient pas encore ce msg (snapshot pas encore arrive)
    // On emet avec la liste Firestore + preloaded
    emitResult();
  });

  function scheduleRetry(failedMsg: EncryptedMessage): void {
    setTimeout(async () => {
      if (!_retrySet.has(failedMsg.id)) return;
      const freshDoc = allDocs.get(failedMsg.id);
      const msgData  = freshDoc ? { id: freshDoc.id, ...freshDoc.data() } as EncryptedMessage : failedMsg;
      try {
        const decrypted = await decryptMessage(myUid, msgData);
        decryptedCache.set(msgData.id, decrypted);
        _retrySet.delete(msgData.id);
        emitResult();
      } catch (err) {
        console.error(`[AQ] Retry dechiffrement echoue pour ${msgData.id}:`, err);
        decryptedCache.set(msgData.id, {
          id: msgData.id, senderUid: msgData.senderUid,
          plaintext: "[\uD83D\uDD12 Message non dechiffrable]",
          timestamp: msgData.timestamp, verified: false, readBy: [],
        });
        _retrySet.delete(msgData.id);
        emitResult();
      }
    }, 80);
  }

  const unsubFirestore = onSnapshot(q, async snap => {
    const changes = snap.docChanges();

    // Capturer quels IDs sont nouveaux AVANT de mettre a jour allDocs.
    const newlyConfirmedPreloads = new Set<string>();
    for (const change of changes) {
      if (change.type === "added" && decryptedCache.has(change.doc.id) && !allDocs.has(change.doc.id)) {
        newlyConfirmedPreloads.add(change.doc.id);
      }
    }

    // Mettre a jour allDocs
    for (const change of changes) {
      if (change.type === "added" || change.type === "modified") {
        allDocs.set(change.doc.id, change.doc);
      } else if (change.type === "removed") {
        allDocs.delete(change.doc.id); decryptedCache.delete(change.doc.id);
      }
    }

    let hasNewWork = false;

    // ── Modifications (readBy uniquement) ─────────────────────────────────
    for (const change of changes) {
      if (change.type !== "modified" || _retrySet.has(change.doc.id)) continue;
      const cached = decryptedCache.get(change.doc.id);
      if (cached) {
        const freshReadBy = (change.doc.data().readBy ?? []) as string[];
        const current     = cached.readBy ?? [];
        if (freshReadBy.length !== current.length || freshReadBy.some(u => !current.includes(u))) {
          decryptedCache.set(change.doc.id, { ...cached, readBy: freshReadBy });
          hasNewWork = true;
        }
      }
    }

    // ── Suppressions ──────────────────────────────────────────────────────
    if (changes.some(c => c.type === "removed")) hasNewWork = true;

    // ── Confirmations de preload ──────────────────────────────────────────
    if (newlyConfirmedPreloads.size > 0) hasNewWork = true;

    // ── Nouveaux messages a dechiffrer — PARALLELE ────────────────────────
    // On collecte d'abord tous les messages necessitant un dechiffrement,
    // puis on les dechiffre tous en parallele (Promise.all).
    // Avant : boucle sequentielle -> N * ~5ms = lent au chargement initial.
    // Apres : dechiffrement simultane -> ~max(5ms) quelle que soit la quantite.
    const toDecrypt: Array<{ msg: EncryptedMessage; isRetry: boolean }> = [];

    for (const change of changes) {
      if (change.type === "removed" || change.type === "modified") continue;
      const d   = change.doc;
      const msg = { id: d.id, ...d.data() } as EncryptedMessage;

      // Deja dans le cache (preloade ou dechiffre) et pas en retry -> SKIP
      if (decryptedCache.has(d.id) && !_retrySet.has(d.id)) continue;

      toDecrypt.push({ msg, isRetry: _retrySet.has(msg.id) });
    }

    if (toDecrypt.length > 0) {
      // Inserer les placeholders immediatement pour un affichage rapide
      for (const { msg, isRetry } of toDecrypt) {
        if (!isRetry && !decryptedCache.has(msg.id)) {
          decryptedCache.set(msg.id, {
            id: msg.id, senderUid: msg.senderUid,
            plaintext: "[\uD83D\uDD12 Dechiffrement\u2026]",
            timestamp: msg.timestamp, verified: false, readBy: [],
          });
        }
      }
      // Emettre avec les placeholders pendant que le dechiffrement tourne
      emitResult();

      // Dechiffrer tous les messages en parallele
      const results = await Promise.allSettled(
        toDecrypt.map(({ msg }) => decryptMessage(myUid, msg).then(d => ({ msg, decrypted: d })))
      );

      for (const result of results) {
        if (result.status === "fulfilled") {
          const { msg, decrypted } = result.value;
          decryptedCache.set(msg.id, decrypted);
          _retrySet.delete(msg.id);
          const { isRetry } = toDecrypt.find(t => t.msg.id === msg.id)!;
          if (!isRetry) {
            updateConversationPreview(msg.conversationId, decrypted.plaintext).catch(() => {});
          }
        } else {
          // Trouver le message en echec
          const idx     = results.indexOf(result);
          const { msg, isRetry } = toDecrypt[idx];
          if (!isRetry) {
            console.warn(`[AQ] Dechiffrement differe pour ${msg.id}`);
            _retrySet.add(msg.id);
            decryptedCache.set(msg.id, {
              id: msg.id, senderUid: msg.senderUid,
              plaintext: "[\uD83D\uDD12 Dechiffrement en cours\u2026]",
              timestamp: msg.timestamp, verified: false, readBy: [],
            });
            scheduleRetry(msg);
          } else {
            console.error(`[AQ] Echec definitif dechiffrement ${msg.id}`);
            decryptedCache.set(msg.id, {
              id: msg.id, senderUid: msg.senderUid,
              plaintext: "[\uD83D\uDD12 Message non dechiffrable]",
              timestamp: msg.timestamp, verified: false, readBy: [],
            });
            _retrySet.delete(msg.id);
          }
        }
      }
      hasNewWork = true;
    }

    if (hasNewWork) emitResult();
  });

  return () => {
    unsubFirestore();
    unregisterPreload();
  };
}
