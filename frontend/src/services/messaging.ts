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
 *
 * IMPORTANT — SERIALISATION DU RATCHET :
 * Le Double Ratchet est un état séquentiel : chaque message avance la chaîne.
 * Les déchiffrements DOIVENT être effectués en séquence (par messageIndex croissant),
 * jamais en parallèle. Un traitement parallèle ferait lire le même état depuis IDB
 * par deux appels concurrents, produire deux états N+1 divergents, et l'un écraserait
 * l'autre → corruption silencieuse → OperationError sur tous les messages suivants.
 */

import {
  collection, doc, setDoc, getDoc, getDocs, updateDoc,
  query, where, orderBy, onSnapshot, serverTimestamp,
  type Unsubscribe,
  type QueryDocumentSnapshot,
  type DocumentData,
} from "firebase/firestore";
import { toBase64 as _toB64 } from "../crypto/kem";
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
// _retrySet  : messages en cours de retry (un seul retry actif par message)
// _retryFailed : messages definitivement non-dechiffrables (plus jamais retentes)
// ---------------------------------------------------------------------------
const _retrySet    = new Set<string>();
const _retryFailed = new Set<string>();

// ---------------------------------------------------------------------------
// Pre-load envoye — injecte APRES addDoc (realId connu) dans decryptedCache
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
// Mutex par conversation — garantit que le ratchet est avancé en séquence
//
// Le Double Ratchet est un état séquentiel stocké dans IndexedDB. Si deux
// messages sont déchiffrés en parallèle (ex: chargement initial avec N msgs),
// les deux appels font loadRatchetState → même état → saveRatchetState en
// dernier gagne → état corrompu → OperationError sur tous les msgs suivants.
//
// Solution : un verrou (mutex) par conversationId. Chaque opération ratchet
// (encrypt ou decrypt) acquiert le verrou, effectue load→avance→save, puis
// relâche. Les opérations concurrentes sont mises en file d'attente.
// ---------------------------------------------------------------------------

const _ratchetLocks = new Map<string, Promise<void>>();

// ---------------------------------------------------------------------------
// ID deterministe pour un message — SHA-256(convId + uid + messageIndex + nonce)
// tronque a 20 chars base64url. Rend addDoc/setDoc idempotent face aux retries
// reseau du SDK Firestore (webchannel replay -> already-exists ignoree).
// ---------------------------------------------------------------------------

async function _deterministicMsgId(
  convId      : string,
  uid         : string,
  messageIndex: number,
  nonce       : string,
): Promise<string> {
  const raw    = new TextEncoder().encode(`${convId}:${uid}:${messageIndex}:${nonce}`);
  const hash   = await crypto.subtle.digest('SHA-256', raw);
  const b64    = _toB64(new Uint8Array(hash));
  // Base64 -> base64url, tronque a 20 chars (suffisant pour l'unicite)
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '').slice(0, 20);
}

function _withRatchetLock<T>(convId: string, fn: () => Promise<T>): Promise<T> {
  const current = _ratchetLocks.get(convId) ?? Promise.resolve();
  let resolve!: () => void;
  const next = new Promise<void>(r => { resolve = r; });
  _ratchetLocks.set(convId, next);

  return current.then(fn).finally(resolve) as Promise<T>;
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
  // Meme raison que sendMessage : garantir l'existence du doc conversation.
  const convId = await getOrCreateConversation(myUid, contactUid);

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

  // Ratchet sous verrou — load→encrypt→save en séquence
  const { drResult, fileKey, placeholder, ts } = await _withRatchetLock(convId, async () => {
    const stateJson   = await loadRatchetState(myUid, convId);
    const _placeholder = `[Fichier] ${file.name} (${_formatSize(file.size)})`;

    const _drResult = await doubleRatchetEncrypt(
      _placeholder, stateJson, convId, myKemPrivateKey ?? "", myKemPubKey, contactKeys.kemPublicKey,
    );
    await saveRatchetState(myUid, convId, _drResult.newStateJson);

    const _fileKey = await hkdfDerive(
      _drResult.kemCiphertext,
      `AegisQuantum-v1-file-key:${convId}:${_drResult.messageIndex}`,
      32,
    );
    return { drResult: _drResult, fileKey: _fileKey, placeholder: _placeholder, ts: Date.now() };
  });

  const fileB64 = toBase64(fileBytes);
  const { ciphertext: fileCiphertext, nonce: fileNonce } = await aesGcmEncrypt(fileB64, fileKey);

  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // setDoc idempotent — meme logique que sendMessage
  const msgId  = await _deterministicMsgId(convId, myUid, drResult.messageIndex, drResult.nonce);
  const msgRef = doc(messagesCol(convId), msgId);

  try {
    await setDoc(msgRef, {
      conversationId   : convId,
      senderUid        : myUid,
      ciphertext       : drResult.ciphertext,
      nonce            : drResult.nonce,
      kemCiphertext    : drResult.kemCiphertext,
      senderEphPub     : drResult.senderEphPub,
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
  } catch (err: unknown) {
    const code = (err as { code?: string })?.code ?? '';
    if (code !== 'already-exists') throw err;
  }

  _preloadSentMessage(convId, {
    id: msgId, senderUid: myUid, plaintext: placeholder,
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
  // S'assurer que le doc conversation existe avant d'ecrire un message.
  // La regle Firestore messages/create fait un get() sur conversations/{convId}
  // — si le doc est absent la regle crashe -> permission-denied.
  const convId = await getOrCreateConversation(myUid, contactUid);

  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Cles publiques introuvables pour ${contactUid}`);

  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);

  // Ratchet sous verrou — load→encrypt→save en séquence
  const { drResult, ts } = await _withRatchetLock(convId, async () => {
    const stateJson  = await loadRatchetState(myUid, convId);
    const _drResult  = await doubleRatchetEncrypt(
      plaintext, stateJson, convId, myKemPrivateKey ?? "", myKemPubKey, contactKeys.kemPublicKey,
    );
    await saveRatchetState(myUid, convId, _drResult.newStateJson);
    return { drResult: _drResult, ts: Date.now() };
  });

  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

  // setDoc avec ID deterministe = idempotent.
  // Si le SDK Firestore rejoue la requete apres un timeout reseau (webchannel retry),
  // le document existe deja cote serveur avec le meme ID -> l'erreur already-exists
  // est interceptee et ignoree silencieusement : le message est deja envoye.
  //
  // ID = hash SHA-256 tronque de (convId + myUid + messageIndex + nonce)
  // Garantit l'unicite par conversation et par ratchet step.
  const msgId  = await _deterministicMsgId(convId, myUid, drResult.messageIndex, drResult.nonce);
  const msgRef = doc(messagesCol(convId), msgId);

  try {
    await setDoc(msgRef, {
      conversationId    : convId,
      senderUid         : myUid,
      ciphertext        : drResult.ciphertext,
      nonce             : drResult.nonce,
      kemCiphertext     : drResult.kemCiphertext,
      senderEphPub      : drResult.senderEphPub,
      signature,
      messageIndex      : drResult.messageIndex,
      timestamp         : ts,
      ...(drResult.initKemCiphertext ? { initKemCiphertext: drResult.initKemCiphertext } : {}),
    } as Omit<EncryptedMessage, "id">);
  } catch (err: unknown) {
    // already-exists = le SDK a rejoue apres un timeout, message deja arrive -> OK
    const code = (err as { code?: string })?.code ?? '';
    if (code !== 'already-exists') throw err;
    // Le message est deja dans Firestore — on continue pour preload/preview
  }

  _preloadSentMessage(convId, {
    id: msgId, senderUid: myUid, plaintext,
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
  // Un message est "legacy" si et seulement si messageIndex est absent.
  // Bootstrap messages ont kemCiphertext="" (vide, pas absent) et initKemCiphertext défini.
  // Les messages en epoch symétrique ont aussi kemCiphertext="" mais messageIndex défini.
  // Seuls les messages pré-ratchet n'ont pas messageIndex.
  const isLegacyMessage = msg.messageIndex === undefined || msg.messageIndex === null;
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

  // Ratchet sous verrou — load→decrypt→save en séquence
  const { drResult } = await _withRatchetLock(msg.conversationId, async () => {
    const stateJson = await loadRatchetState(myUid, msg.conversationId);

    const _drResult = await doubleRatchetDecrypt(
      msg.ciphertext, msg.nonce, msg.messageIndex, msg.kemCiphertext,
      msg.senderEphPub,
      stateJson, msg.conversationId, myKemPrivKey ?? "", myKemPubKey,
      senderKeys?.kemPublicKey ?? "", msg.initKemCiphertext,
    );

    await saveRatchetState(myUid, msg.conversationId, _drResult.newStateJson);
    return { drResult: _drResult };
  });

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
    const result = [...allDocs.values()]
      .sort((a, b) => ((a.data().timestamp ?? 0) as number) - ((b.data().timestamp ?? 0) as number))
      .map(d => decryptedCache.get(d.id))
      .filter((m): m is DecryptedMessage => m !== undefined);

    const preloaded = [...decryptedCache.values()]
      .filter(m => !allDocs.has(m.id))
      .sort((a, b) => a.timestamp - b.timestamp);

    callback([...result, ...preloaded]);
  }

  const unregisterPreload = _registerPreloadListener(conversationId, (msg) => {
    decryptedCache.set(msg.id, msg);
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
        _retryFailed.add(msgData.id); // blacklist : aucun retry supplementaire
        emitResult();
      }
    }, 80);
  }

  const unsubFirestore = onSnapshot(q, async snap => {
    const changes = snap.docChanges();

    const newlyConfirmedPreloads = new Set<string>();
    for (const change of changes) {
      if (change.type === "added" && decryptedCache.has(change.doc.id) && !allDocs.has(change.doc.id)) {
        newlyConfirmedPreloads.add(change.doc.id);
      }
    }

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

    // ── Nouveaux messages a dechiffrer — SÉQUENTIEL par messageIndex ──────
    //
    // CRITIQUE : le Double Ratchet est séquentiel. Les messages DOIVENT être
    // déchiffrés dans l'ordre croissant de messageIndex. Un traitement parallèle
    // corromprait l'état ratchet (deux lectures du même état → deux sauvegardes
    // divergentes → le dernier écrase le premier → OperationError).
    //
    // On filtre, trie par messageIndex, puis on déchiffre un par un.
    const toDecrypt: EncryptedMessage[] = [];

    for (const change of changes) {
      if (change.type === "removed" || change.type === "modified") continue;
      const d   = change.doc;
      const msg = { id: d.id, ...d.data() } as EncryptedMessage;

      // Deja dans le cache, en retry actif, ou definitvement echoue -> SKIP
      if (_retryFailed.has(d.id)) continue;
      if (decryptedCache.has(d.id) && !_retrySet.has(d.id)) continue;

      // Messages envoyés par soi-même — déjà dans le cache via _preloadSentMessage.
      // Tenter de les déchiffrer avec le ratchet (état N+1 après l'envoi) échoue
      // systématiquement. On les ignore ici ; le preload les affiche correctement.
      if (msg.senderUid === myUid) continue;

      toDecrypt.push(msg);
    }

    if (toDecrypt.length > 0) {
      // Trier par messageIndex croissant — ordre obligatoire pour le ratchet
      toDecrypt.sort((a, b) => (a.messageIndex ?? 0) - (b.messageIndex ?? 0));

      // Insérer les placeholders immédiatement pour un affichage rapide
      for (const msg of toDecrypt) {
        if (!decryptedCache.has(msg.id)) {
          decryptedCache.set(msg.id, {
            id: msg.id, senderUid: msg.senderUid,
            plaintext: "[\uD83D\uDD12 Dechiffrement\u2026]",
            timestamp: msg.timestamp, verified: false, readBy: [],
          });
        }
      }
      emitResult();

      // Déchiffrer SÉQUENTIELLEMENT (le mutex _withRatchetLock dans decryptMessage
      // garantit l'ordre même si d'autres appels arrivent entre-temps)
      //
      // updateConversationPreview : 1 seul write pour tout le batch (le dernier msg
      // par timestamp), pas 1 write par message. Economise N-1 writes au chargement.
      const lastMsgInBatch = toDecrypt.reduce((a, b) => b.timestamp > a.timestamp ? b : a);

      for (const msg of toDecrypt) {
        try {
          const decrypted = await decryptMessage(myUid, msg);
          decryptedCache.set(msg.id, decrypted);
          _retrySet.delete(msg.id);
          if (msg.id === lastMsgInBatch.id) {
            updateConversationPreview(msg.conversationId, decrypted.plaintext).catch(() => {});
          }
        } catch (err: any) {
    if (err.message === "RAT_EMPTY_CHAIN_KEY") {
        console.warn(`[AQ] Désynchronisation détectée sur le message ${msg.id}. L'état local est corrompu.`);
        // On affiche un message spécial à l'utilisateur au lieu de "Déchiffrement..."
        decryptedCache.set(msg.id, {
            ...msg,
            plaintext: "[⚠️ Erreur de synchronisation : Clé manquante]",
            verified: false
        });
    } else {
        // Autre erreur (réseau, signature, etc.)
        _retrySet.add(msg.id);
        scheduleRetry(msg);
    }
}
        // Émettre après chaque message pour un affichage progressif
        emitResult();
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
