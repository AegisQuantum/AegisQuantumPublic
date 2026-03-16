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
import {
  emitCryptoEvent, previewB64, shortUid, shortConvId,
} from "./crypto-events";
import {
  loadCachedMessages, saveCachedMessages, getLastCachedMessageTs,
  saveCachedConversations, loadCachedConversations,
} from "./idb-cache";
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
      lastMessageAt     : serverTimestamp(), // serverTimestamp pour tri Firestore coherent
    });
  } catch {
    // Silencieux
  }
}

export function subscribeToConversations(
  myUid   : string,
  callback: (convs: Conversation[]) => void,
): Unsubscribe {
  // Servir le cache IDB immédiatement (avant la réponse Firestore)
  loadCachedConversations(myUid).then(cached => {
    if (cached && cached.length > 0) callback(cached);
  }).catch(() => {});

  const q = query(
    convsCol(),
    where("participants", "array-contains", myUid),
    orderBy("lastMessageAt", "desc"),
  );
  return onSnapshot(q, snap => {
    const convs = snap.docs.map(d => d.data() as Conversation);
    callback(convs);
    // Persister dans IDB pour la prochaine session
    saveCachedConversations(myUid, convs).catch(() => {});
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
  console.log('[AQ:send] 1/6 — getOrCreateConversation', { myUid, contactUid });
  // S'assurer que la conversation existe dans Firestore AVANT d'ecrire le message.
  const convId = await getOrCreateConversation(myUid, contactUid);
  console.log('[AQ:send] 2/6 — convId OK:', convId);

  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  console.log('[AQ:send] 3/6 — myKemPubKey:', myKemPubKey ? myKemPubKey.slice(0,20)+'...' : 'ABSENT');

  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Cles publiques introuvables pour ${contactUid}`);
  console.log('[AQ:send] 4/6 — contactKeys OK');

  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);
  console.log('[AQ:send] 5/6 — clés privées OK');

  const stateJson = await loadRatchetState(myUid, convId);
  emitCryptoEvent({ step: 'ratchet:load', convId: shortConvId(convId) });

  const drResult = await doubleRatchetEncrypt(
    plaintext, stateJson, convId, myKemPrivateKey, myKemPubKey, contactKeys.kemPublicKey,
  );
  emitCryptoEvent({
    step: 'kem:encapsulate',
    convId: shortConvId(convId),
    peerUid: shortUid(contactUid),
    kemCiphertextPreview: previewB64(drResult.kemCiphertext),
    messageIndex: drResult.messageIndex,
  });
  emitCryptoEvent({
    step: 'hkdf:derive',
    convId: shortConvId(convId),
    messageIndex: drResult.messageIndex,
  });
  emitCryptoEvent({
    step: 'aes:encrypt',
    convId: shortConvId(convId),
    ciphertextPreview: previewB64(drResult.ciphertext),
    nonce: drResult.nonce.slice(0, 24),
    ciphertextLen: Math.round(drResult.ciphertext.length * 3 / 4),
    messageIndex: drResult.messageIndex,
  });

  await saveRatchetState(myUid, convId, drResult.newStateJson);
  emitCryptoEvent({ step: 'ratchet:save', convId: shortConvId(convId), messageIndex: drResult.messageIndex });

  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);
  emitCryptoEvent({
    step: 'dsa:sign',
    convId: shortConvId(convId),
    signaturePreview: previewB64(signature),
    signatureLen: Math.round(signature.length * 3 / 4),
    messageIndex: drResult.messageIndex,
  });
  const ts            = Date.now();

  // addDoc d'abord — on obtient le realId avant de notifier le cache
  console.log('[AQ:send] 6/6 — addDoc vers', `conversations/${convId}/messages`);
  let msgRef;
  try {
    msgRef = await addDoc(messagesCol(convId), {
      conversationId    : convId,
      senderUid         : myUid,
      ciphertext        : drResult.ciphertext,
      nonce             : drResult.nonce,
      kemCiphertext     : drResult.kemCiphertext,
      signature,
      messageIndex      : drResult.messageIndex,
      timestamp         : ts,
      ...(drResult.initKemCiphertext ? { initKemCiphertext: drResult.initKemCiphertext } : {}),
    } as Omit<EncryptedMessage, "id">);
  } catch (firestoreErr: unknown) {
    const e = firestoreErr as { code?: string; message?: string };
    console.error('[AQ:send] addDoc FAILED — code:', e.code, '— message:', e.message, '— full:', firestoreErr);
    throw firestoreErr;
  }
  console.log('[AQ:send] addDoc OK — msgId:', msgRef.id);
  emitCryptoEvent({
    step: 'firestore:write',
    convId: shortConvId(convId),
    firestoreDocId: msgRef.id.slice(0, 12) + '…',
    firestoreCollection: `conversations/${shortConvId(convId)}/messages`,
    messageIndex: drResult.messageIndex,
  });

  // Injecter dans decryptedCache de tous les subscribers AVEC LE VRAI ID
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
  emitCryptoEvent({
    step: 'firestore:read-pubkey',
    peerUid: shortUid(msg.senderUid),
    convId: shortConvId(msg.conversationId),
  });
  let   verified   = false;
  if (senderKeys) {
    const payload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(payload, msg.signature, senderKeys.dsaPublicKey);
    emitCryptoEvent({
      step: 'dsa:verify',
      peerUid: shortUid(msg.senderUid),
      convId: shortConvId(msg.conversationId),
      signaturePreview: previewB64(msg.signature),
      signatureLen: Math.round(msg.signature.length * 3 / 4),
      verified,
      messageIndex: msg.messageIndex,
    });
  }

  const myKeys       = await getPublicKeys(myUid);
  const myKemPubKey  = myKeys?.kemPublicKey ?? "";
  const myKemPrivKey = getKemPrivateKey(myUid);
  const stateJson    = await loadRatchetState(myUid, msg.conversationId);
  emitCryptoEvent({ step: 'ratchet:load', convId: shortConvId(msg.conversationId), messageIndex: msg.messageIndex });

  const drResult = await doubleRatchetDecrypt(
    msg.ciphertext, msg.nonce, msg.messageIndex, msg.kemCiphertext,
    stateJson, msg.conversationId, myKemPrivKey, myKemPubKey,
    senderKeys?.kemPublicKey ?? "", msg.initKemCiphertext,
  );
  emitCryptoEvent({
    step: 'kem:decapsulate',
    peerUid: shortUid(msg.senderUid),
    convId: shortConvId(msg.conversationId),
    kemCiphertextPreview: previewB64(msg.kemCiphertext),
    messageIndex: msg.messageIndex,
  });
  emitCryptoEvent({
    step: 'hkdf:derive',
    convId: shortConvId(msg.conversationId),
    messageIndex: msg.messageIndex,
  });
  emitCryptoEvent({
    step: 'aes:decrypt',
    convId: shortConvId(msg.conversationId),
    ciphertextPreview: previewB64(msg.ciphertext),
    nonce: msg.nonce.slice(0, 24),
    ciphertextLen: Math.round(msg.ciphertext.length * 3 / 4),
    messageIndex: msg.messageIndex,
  });

  await saveRatchetState(myUid, msg.conversationId, drResult.newStateJson);
  emitCryptoEvent({ step: 'ratchet:save', convId: shortConvId(msg.conversationId), messageIndex: msg.messageIndex });

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
  const decryptedCache = new Map<string, DecryptedMessage>();
  const allDocs        = new Map<string, QueryDocumentSnapshot<DocumentData>>();

  // ── Charger le cache IDB immédiatement (affichage instantané) ──────────
  // On appelle callback avec les messages cachés AVANT même que Firestore
  // réponde. Le onSnapshot viendra ensuite patcher uniquement les deltas.
  let _idbLoaded = false;
  loadCachedMessages(conversationId).then((cached) => {
    if (cached && cached.msgs.length > 0 && !_idbLoaded) {
      _idbLoaded = true;
      // Pré-peupler le cache mémoire avec les messages IDB
      for (const m of cached.msgs) decryptedCache.set(m.id, m);
      callback([...cached.msgs].sort((a, b) => a.timestamp - b.timestamp));
    }
  }).catch(() => {});

  // Firestore : ne demander que les messages après le dernier timestamp caché
  // Cela réduit les reads à seulement les nouveaux messages.
  // On initialise la query d'abord avec tout (cas où le cache est vide),
  // et on raffinera via _lastCachedTs ci-dessous.
  let _queryStartTs = 0;
  getLastCachedMessageTs(conversationId).then(ts => { _queryStartTs = ts; }).catch(() => {});

  // On garde la query full pour l'instant (ratchet stateful = on a besoin
  // que les IDs Firestore correspondent au cache). Le gain principal est le
  // skip de déchiffrement via decryptedCache.has().
  const q = query(messagesCol(conversationId), orderBy("timestamp", "asc"));

  // File sequentielle — garantit qu'un seul decryptMessage() tourne a la fois
  // Le Double Ratchet est STATEFUL : chaque dechiffrement lit IDB, avance l'etat,
  // ecrit IDB. Deux dechiffrements concurrents lisent le meme etat -> replay.
  let _decryptQueue: Promise<void> = Promise.resolve();

  function enqueueDecrypt(task: () => Promise<void>): void {
    _decryptQueue = _decryptQueue.then(task).catch(() => {});
  }

  // Debounce pour la sauvegarde IDB (ne pas écrire à chaque message individuel)
  let _saveCacheTimer: ReturnType<typeof setTimeout> | null = null;
  function _scheduleCacheSave(msgs: DecryptedMessage[]): void {
    if (_saveCacheTimer) clearTimeout(_saveCacheTimer);
    _saveCacheTimer = setTimeout(() => {
      saveCachedMessages(conversationId, msgs).catch(() => {});
    }, 800);
  }

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

    const all = [...result, ...preloaded];
    callback(all);
    // Sauvegarder les messages déchiffrés dans IDB (debounced)
    _scheduleCacheSave(all);
  }

  // Preload : injecte un message envoye (avec realId) avant le snapshot
  const unregisterPreload = _registerPreloadListener(conversationId, (msg) => {
    decryptedCache.set(msg.id, msg);
    emitResult();
  });

  const unsubFirestore = onSnapshot(q, snap => {
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

    // ── Modifications (readBy uniquement) ─────────────────────────────────
    let hasImmediateWork = false;
    for (const change of changes) {
      if (change.type !== "modified") continue;
      const cached = decryptedCache.get(change.doc.id);
      if (cached) {
        const freshReadBy = (change.doc.data().readBy ?? []) as string[];
        const current     = cached.readBy ?? [];
        if (freshReadBy.length !== current.length || freshReadBy.some(u => !current.includes(u))) {
          decryptedCache.set(change.doc.id, { ...cached, readBy: freshReadBy });
          hasImmediateWork = true;
        }
      }
    }

    if (changes.some(c => c.type === "removed")) hasImmediateWork = true;
    if (newlyConfirmedPreloads.size > 0)          hasImmediateWork = true;
    if (hasImmediateWork) emitResult();

    // ── Nouveaux messages a dechiffrer ────────────────────────────────────
    // Collecter uniquement les messages pas encore dans le cache
    const toDecrypt: EncryptedMessage[] = [];
    for (const change of changes) {
      if (change.type === "removed" || change.type === "modified") continue;
      const d   = change.doc;
      // Deja dans le cache (preloade ou deja dechiffre) -> SKIP
      if (decryptedCache.has(d.id)) continue;
      const msg = { id: d.id, ...d.data() } as EncryptedMessage;
      toDecrypt.push(msg);
    }

    if (toDecrypt.length === 0) return;

    // Trier par messageIndex avant d'enqueuer — ordre du ratchet
    toDecrypt.sort((a, b) => (a.messageIndex ?? 0) - (b.messageIndex ?? 0));

    // Inserer les placeholders immediatement (avant que la queue tourne)
    for (const msg of toDecrypt) {
      decryptedCache.set(msg.id, {
        id: msg.id, senderUid: msg.senderUid,
        plaintext: "[\uD83D\uDD12 Dechiffrement\u2026]",
        timestamp: msg.timestamp, verified: false, readBy: [],
      });
    }
    emitResult();

    // Enqueuer UN PAR UN dans la file sequentielle
    // Chaque tache attend la precedente -> jamais deux decryptMessage() en meme temps
    for (const msg of toDecrypt) {
      enqueueDecrypt(async () => {
        try {
          const decrypted = await decryptMessage(myUid, msg);
          decryptedCache.set(msg.id, decrypted);
          updateConversationPreview(msg.conversationId, decrypted.plaintext).catch(() => {});
        } catch (err) {
          console.error(`[AQ] Dechiffrement echoue pour ${msg.id}:`, err);
          decryptedCache.set(msg.id, {
            id: msg.id, senderUid: msg.senderUid,
            plaintext: "[\uD83D\uDD12 Message non dechiffrable]",
            timestamp: msg.timestamp, verified: false, readBy: [],
          });
        }
        emitResult();
      });
    }
  });

  return () => {
    unsubFirestore();
    unregisterPreload();
    if (_saveCacheTimer) clearTimeout(_saveCacheTimer);
  };
}
