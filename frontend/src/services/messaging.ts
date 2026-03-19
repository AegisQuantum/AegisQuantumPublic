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
  collection, doc, setDoc, getDoc, getDocs, updateDoc, deleteDoc,
  query, where, orderBy, onSnapshot, serverTimestamp,
  type Unsubscribe,
  type QueryDocumentSnapshot,
  type DocumentData,
} from "firebase/firestore";
import { toBase64 as _toB64 } from "../crypto/kem";
import { db }            from "./firebase";
import { getPublicKeys } from "./key-registry";
import { getKemPrivateKey, getDsaPrivateKey, saveRatchetState, loadRatchetState, deleteRatchetState, saveMsgCache, loadMsgCache, deleteMsgCache } from "./key-store";
import { hideMessageLocally } from "./idb-cache";
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
// _retrySet    : messages en cours de retry (un seul retry actif par message)
// _retryFailed : messages définitivement non-déchiffrables (plus jamais retentés)
//
// BORNAGE : _retryFailed est capé à MAX_RETRY_FAILED entrées (insertions order).
// Sur des sessions très longues avec beaucoup d'erreurs, sans bornage le Set
// grossirait indéfiniment. On retire les 50 plus anciennes quand on atteint la limite.
// ---------------------------------------------------------------------------
const MAX_RETRY_FAILED = 500;
const _retrySet    = new Set<string>();
const _retryFailed = new Set<string>();

function _retryFailedAdd(msgId: string): void {
  if (_retryFailed.size >= MAX_RETRY_FAILED) {
    const iter = _retryFailed.values();
    for (let i = 0; i < 50; i++) _retryFailed.delete(iter.next().value as string);
  }
  _retryFailed.add(msgId);
}

/**
 * Réinitialise tout l'état module-level de messaging.
 *
 * DOIT être appelé à chaque nouvelle connexion (signIn) ET déconnexion
 * (signOut), car ces sets/maps sont des singletons JS qui survivent à un
 * simple changement de compte sans rechargement de page.
 *
 * Sans ça :
 *  - _retryFailed contient les IDs d'une session précédente → messages
 *    invisibles lors de la reconnexion (ni cache IDB ni rendu [🔒])
 *  - _ratchetLocks peuvent pointer vers des promises obsolètes
 */
export function resetMessagingState(): void {
  _retrySet.clear();
  _retryFailed.clear();
  _ratchetLocks.clear();
  _preloadListeners.clear();
  // _convPreviewListeners intentionnellement préservé : les listeners UI
  // sont enregistrés une seule fois au montage du chat et ne doivent pas
  // être perdus. Ils sont nettoyés par leur propre unsubscribe().
}

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
      _placeholder, stateJson, convId, myKemPrivateKey, myKemPubKey, contactKeys.kemPublicKey,
    );
    await saveRatchetState(myUid, convId, _drResult.newStateJson);

    // Dérivation de la clé fichier — sélectionne le premier matériau non-vide :
    //  • kemCiphertext    : disponible en epoch KEM-ratchet
    //  • initKemCiphertext: disponible en epoch bootstrap (premier message)
    //  • nonce            : fallback pour epoch symétrique (ratchet avancé côté sym.)
    //                       le nonce AES-GCM est toujours unique par message → clé unique
    const _kemForFileKey = _drResult.kemCiphertext || _drResult.initKemCiphertext || _drResult.nonce;
    const _fileKey = await hkdfDerive(
      _kemForFileKey,
      `AegisQuantum-v1-file-key:${convId}:${_drResult.messageIndex}`,
      32,
    );
    return { drResult: _drResult, fileKey: _fileKey, placeholder: _placeholder, ts: Date.now() };
  });

  const fileB64 = toBase64(fileBytes);
  const { ciphertext: fileCiphertext, nonce: fileNonce } = await aesGcmEncrypt(fileB64, fileKey);

  const signedPayload = drResult.ciphertext + drResult.nonce + drResult.kemCiphertext;
  const signature     = await dsaSign(signedPayload, myDsaPrivateKey);

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
      messageType      : (file.type.startsWith('image/') ? 'image' : file.type.startsWith('audio/') ? 'audio' : 'file') as 'image' | 'audio' | 'file',
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

  const sentBlob = new Blob([fileBytes.buffer as ArrayBuffer], {
    type: file.type || "application/octet-stream",
  });
  _preloadSentMessage(convId, {
    id: msgId, senderUid: myUid, plaintext: placeholder,
    timestamp: ts, verified: true, readBy: [],
    messageType      : (file.type.startsWith('image/') ? 'image' : file.type.startsWith('audio/') ? 'audio' : 'file') as 'image'|'audio'|'file',
    kemCiphertext    : drResult.kemCiphertext,
    initKemCiphertext: drResult.initKemCiphertext,
    messageIndex     : drResult.messageIndex,
    file: { blob: sentBlob, name: file.name, size: file.size, type: file.type || "application/octet-stream" },
  });
  saveMsgCache(msgId, { plaintext: placeholder, verified: true, senderUid: myUid, timestamp: ts }).catch(() => {});
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
      plaintext, stateJson, convId, myKemPrivateKey, myKemPubKey, contactKeys.kemPublicKey,
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
      messageType       : 'text' as const,
      ...(drResult.initKemCiphertext ? { initKemCiphertext: drResult.initKemCiphertext } : {}),
    } as Omit<EncryptedMessage, "id">);
  } catch (err: unknown) {
    // already-exists = le SDK a rejoue apres un timeout, message deja arrive -> OK
    const code = (err as { code?: string })?.code ?? '';
    if (code !== 'already-exists') throw err;
  }

  _preloadSentMessage(convId, {
    id: msgId, senderUid: myUid, plaintext,
    timestamp: ts, verified: true, readBy: [],
    messageType      : 'text' as const,
    kemCiphertext    : drResult.kemCiphertext,
    initKemCiphertext: drResult.initKemCiphertext,
    messageIndex     : drResult.messageIndex,
  });

  // Persistance IDB — permet de ré-afficher ce message après rechargement de
  // la conversation sans passer par le ratchet (qui serait déjà à N+1).
  saveMsgCache(msgId, { plaintext, verified: true, senderUid: myUid, timestamp: ts }).catch(() => {});

  _notifyConvPreviewUpdate(convId, plaintext, ts);
}

// ---------------------------------------------------------------------------
// Dechiffrement
// ---------------------------------------------------------------------------

/** Re-déchiffre uniquement la pièce jointe d'un message (sans Double Ratchet).
 *  Utilisé pour les propres messages de l'envoyeur sur rechargement de page.
 */
async function _decryptFileOnly(msgId: string, msg: EncryptedMessage): Promise<DecryptedMessage | null> {
  if (!msg.hasFile || !msg.fileCiphertext || !msg.fileNonce || !msg.fileName) return null;
  const kemForFileKey = msg.kemCiphertext || msg.initKemCiphertext || msg.nonce;
  const fileKey  = await hkdfDerive(
    kemForFileKey,
    `AegisQuantum-v1-file-key:${msg.conversationId}:${msg.messageIndex}`,
    32,
  );
  const fileB64   = await aesGcmDecrypt(msg.fileCiphertext, msg.fileNonce, fileKey);
  const fileBytes = fromBase64(fileB64);
  const ftype     = msg.fileType ?? "application/octet-stream";
  const blob      = new Blob([fileBytes.buffer as ArrayBuffer], { type: ftype });
  return {
    id: msgId, senderUid: msg.senderUid,
    plaintext: `[Fichier] ${msg.fileName}`,
    timestamp: msg.timestamp, verified: false, readBy: msg.readBy ?? [],
    messageType: msg.messageType,
    kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext, messageIndex: msg.messageIndex,
    file: { blob, name: msg.fileName, size: msg.fileSize ?? fileBytes.length, type: ftype },
  };
}

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

  // ── Tombstone (message supprimé pour tous) ─────────────────────────────────
  // Le ciphertext contient AES-GCM("__DELETED__", editKey).
  // On déchiffre pour vérifier l'intégrité, puis on retourne le placeholder.
  if (msg.deleted) {
    try {
      const editKey = await deriveEditKey(msg.kemCiphertext, msg.initKemCiphertext, msg.conversationId, msg.messageIndex);
      const marker  = await aesGcmDecrypt(msg.ciphertext, msg.nonce, editKey);
      if (marker !== "__DELETED__") throw new Error("tombstone invalide");
    } catch {
      // tombstone corrompu ou forgé — on affiche quand même le placeholder
    }
    return {
      id: msg.id, senderUid: msg.senderUid,
      plaintext : "Ce message a \u00e9t\u00e9 supprim\u00e9",
      timestamp : msg.timestamp, verified: false,
      isDeleted : true, readBy: msg.readBy ?? [],
      kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext,
      messageIndex : msg.messageIndex,
    };
  }

  // ── Message modifié ────────────────────────────────────────────────────────
  // Le ciphertext contient AES-GCM(nouvellePlaintext, editKey).
  if (msg.edited) {
    try {
      const editKey      = await deriveEditKey(msg.kemCiphertext, msg.initKemCiphertext, msg.conversationId, msg.messageIndex);
      const newPlaintext = await aesGcmDecrypt(msg.ciphertext, msg.nonce, editKey);
      return {
        id: msg.id, senderUid: msg.senderUid,
        plaintext : newPlaintext,
        timestamp : msg.timestamp, verified: false,
        isEdited  : true, editedAt: msg.editedAt,
        readBy    : msg.readBy ?? [],
        kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext,
        messageIndex : msg.messageIndex,
      };
    } catch {
      return {
        id: msg.id, senderUid: msg.senderUid,
        plaintext : "[\uD83D\uDD12 Message modifi\u00e9 — d\u00e9chiffrement \u00e9chou\u00e9]",
        timestamp : msg.timestamp, verified: false,
        isEdited  : true, readBy: msg.readBy ?? [],
        kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext,
        messageIndex : msg.messageIndex,
      };
    }
  }

  const senderKeys = await getPublicKeys(msg.senderUid);
  let   verified   = false;
  if (senderKeys) {
    const payload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(payload, msg.signature, senderKeys.dsaPublicKey);
  }

  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  let   myKemPrivKey: string;
  try {
    myKemPrivKey = getKemPrivateKey(myUid);
  } catch {
    return {
      id: msg.id, senderUid: msg.senderUid,
      plaintext : "[\uD83D\uDD12 Message chiffr\u00e9 — cl\u00e9s non charg\u00e9es]",
      timestamp : msg.timestamp, verified: false, readBy: msg.readBy ?? [],
    };
  }

  // Ratchet sous verrou — load→decrypt→save en séquence
  let drResult: import("../crypto/double-ratchet").DoubleRatchetDecryptResult;
  try {
    ({ drResult } = await _withRatchetLock(msg.conversationId, async () => {
      const stateJson = await loadRatchetState(myUid, msg.conversationId);
      const _drResult = await doubleRatchetDecrypt(
        msg.ciphertext, msg.nonce, msg.messageIndex, msg.kemCiphertext,
        msg.senderEphPub,
        stateJson, msg.conversationId, myKemPrivKey, myKemPubKey,
        senderKeys?.kemPublicKey ?? "", msg.initKemCiphertext,
      );
      await saveRatchetState(myUid, msg.conversationId, _drResult.newStateJson);
      return { drResult: _drResult };
    }));
  } catch (ratchetErr: unknown) {
    const errMsg = ratchetErr instanceof Error ? ratchetErr.message : String(ratchetErr);
    // Erreurs ratchet permanentes → [🔒] direct, pas de retry utile
    // OperationError = échec AES-GCM (mauvaise clé ratchet) — permanent, retry inutile
    const isPermanent = /initKemCiphertext|replay detected|too far ahead|RAT_EMPTY_CHAIN_KEY|OperationError/i.test(errMsg);
    if (isPermanent) {
      // Diagnostic : aide à identifier les désynchronisations de clés
      const stateJson = await loadRatchetState(myUid, msg.conversationId).catch(() => null);
      const myPubKey  = await getPublicKeys(myUid).catch(() => null);
      const senderPub = await getPublicKeys(msg.senderUid).catch(() => null);
      console.error(
        `[AQ:decrypt] Échec permanent msg=${msg.id} index=${msg.messageIndex}`,
        `\n  erreur     : ${errMsg}`,
        `\n  ratchet    : ${stateJson ? 'présent' : 'NULL (bootstrap attendu)'}`,
        `\n  myKemPub   : ${myPubKey?.kemPublicKey?.slice(0, 20) ?? 'ABSENT'}…`,
        `\n  senderPub  : ${senderPub?.kemPublicKey?.slice(0, 20) ?? 'ABSENT'}…`,
        `\n  initKemCT  : ${msg.initKemCiphertext ? msg.initKemCiphertext.slice(0, 20) + '…' : 'absent'}`,
        `\n  kemCT      : ${msg.kemCiphertext ? msg.kemCiphertext.slice(0, 20) + '…' : 'vide (epoch sym)'}`,
      );
      return {
        id: msg.id, senderUid: msg.senderUid,
        plaintext : "[\uD83D\uDD12 Message non d\u00e9chiffrable]",
        timestamp : msg.timestamp, verified: false, readBy: msg.readBy ?? [],
      };
    }
    throw ratchetErr; // erreur transitoire (réseau, etc.) → retry via subscribeToMessages
  }

  let fileAttachment: DecryptedMessage["file"] | undefined;
  if (msg.hasFile && msg.fileCiphertext && msg.fileNonce && msg.fileName) {
    try {
      // Même priorité que sendFile : kemCiphertext > initKemCiphertext > nonce
      const kemForFileKey = msg.kemCiphertext || msg.initKemCiphertext || msg.nonce;
      const fileKey  = await hkdfDerive(
        kemForFileKey,
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
      console.error(`[AQ] Dechiffrement fichier echoue pour ${msg.id}:`, e,
        `\n  hasFile=${msg.hasFile} kemCT=${msg.kemCiphertext?.slice(0,16)}…`,
        `\n  convId=${msg.conversationId} index=${msg.messageIndex}`);
    }
  }

  return {
    id: msg.id, senderUid: msg.senderUid, plaintext: drResult.plaintext,
    timestamp: msg.timestamp, verified, readBy: msg.readBy ?? [],
    file: fileAttachment,
    messageType      : msg.messageType,
    // Métadonnées de clé — permettent delete/edit depuis l'UI sans re-lire Firestore
    kemCiphertext    : msg.kemCiphertext,
    initKemCiphertext: msg.initKemCiphertext,
    messageIndex     : msg.messageIndex,
  };
}

// ---------------------------------------------------------------------------
// Resynchronisation du Double Ratchet
// ---------------------------------------------------------------------------

/**
 * Envoie un signal de resynchronisation ratchet à l'autre participant.
 *
 * Étapes :
 *  1. Supprime l'état ratchet local de cette conversation dans IDB.
 *  2. Écrit un document Firestore de type "ratchet-reset" dans la collection
 *     messages de la conversation.
 *  3. Quand l'autre client reçoit ce signal via onSnapshot, il efface aussi
 *     son état ratchet local.
 *  4. Le prochain vrai message envoyé par n'importe quel côté repartira d'un
 *     bootstrap complet (stateJson === null → initKemCiphertext générée).
 *
 * À utiliser après une régénération de clés (generateFreshKeys) ou quand les
 * deux ratchets sont désynchronisés (erreur "replay detected" ou RAT_EMPTY_CHAIN_KEY).
 */
export async function sendRatchetResetSignal(
  myUid     : string,
  contactUid: string,
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  // 1. Effacer l'état ratchet local
  await deleteRatchetState(myUid, convId);

  // 2. Signer le signal avec notre clé privée ML-DSA-65
  //    Payload : "ratchet-reset:{convId}:{myUid}:{ts}"
  //    Cela empêche un tiers (MitM, participant malveillant) de forger un
  //    faux signal et de forcer une resync — seul le détenteur de la clé
  //    privée DSA peut émettre un reset valide pour son propre compte.
  const ts             = Date.now();
  const signedPayload  = `ratchet-reset:${convId}:${myUid}:${ts}`;
  const myDsaPrivKey   = getDsaPrivateKey(myUid);
  const signature      = await dsaSign(signedPayload, myDsaPrivKey);

  // 3. Écrire le signal dans Firestore (ID déterministe pour l'idempotence)
  const raw   = new TextEncoder().encode(signedPayload);
  const hash  = await crypto.subtle.digest('SHA-256', raw);
  const { toBase64: _b64 } = await import('../crypto/kem');
  const sigId = _b64(new Uint8Array(hash)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'').slice(0, 20);

  const msgRef = doc(messagesCol(convId), `rr_${sigId}`);
  await setDoc(msgRef, {
    conversationId: convId,
    senderUid     : myUid,
    type          : "ratchet-reset",
    timestamp     : ts,
    // Signature DSA du payload — vérifiée par le destinataire avant d'effacer son ratchet
    signature     : signature,
    // Champs crypto vides (pas de contenu chiffré dans un signal de resync)
    ciphertext    : "",
    nonce         : "",
    kemCiphertext : "",
    senderEphPub  : "",
    messageIndex  : -1,
  });
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
      .map(d => decryptedCache.get(d.id) ?? {
        // Fallback pour les messages présents dans Firestore mais pas encore
        // (ou jamais) dans le cache — garantit qu'ils sont toujours visibles,
        // même s'ils ont échoué au déchiffrement ou sont en attente.
        id       : d.id,
        senderUid: (d.data().senderUid as string) ?? '',
        plaintext: '[\uD83D\uDD12 Message chiffr\u00e9]',
        timestamp: (d.data().timestamp as number) ?? 0,
        verified : false,
        readBy   : [],
      });

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
        _retryFailedAdd(msgData.id);
        emitResult();
      }
    }, 80);
  }

  const unsubFirestore = onSnapshot(q, async snap => {
    const changes = snap.docChanges();

    // ── Signaux de resynchronisation ratchet ─────────────────────────────
    // Traités EN PREMIER, avant tout le reste, pour que l'état ratchet soit
    // effacé avant qu'on tente de déchiffrer d'éventuels nouveaux messages
    // qui arrivent dans le même snapshot.
    for (const change of changes) {
      if (change.type !== "added") continue;
      const data = change.doc.data();
      if ((data.type as string | undefined) !== "ratchet-reset") continue;

      const senderUid     = data.senderUid as string;
      const signedPayload = `ratchet-reset:${conversationId}:${senderUid}:${data.timestamp as number}`;

      // Vérifier la signature ML-DSA-65 AVANT d'effacer le ratchet.
      // Un attaquant (MitM, participant malveillant) ne peut pas forger
      // un faux signal : sans la clé privée DSA de l'expéditeur, la
      // signature ne passe pas → le ratchet local est préservé.
      const senderKeys = await getPublicKeys(senderUid);
      if (!senderKeys) {
        console.warn(`[AQ] Signal ratchet-reset ignoré : clés publiques introuvables pour ${senderUid}`);
        continue;
      }
      const sigValid = await dsaVerify(signedPayload, data.signature as string, senderKeys.dsaPublicKey);
      if (!sigValid) {
        console.warn(`[AQ] Signal ratchet-reset REJETÉ (signature invalide) depuis ${senderUid}`);
        continue;
      }

      console.log(`[AQ] Signal ratchet-reset vérifié ✓ depuis ${senderUid} — effacement de l'état local`);

      // Effacer notre propre état ratchet pour cette conversation
      await deleteRatchetState(myUid, conversationId);

      // Vider les files de retry et retenter tous les messages échoués de cette
      // conversation. Les messages qui avaient échoué avec l'ancien état ratchet
      // (OperationError, etc.) doivent être retentés avec le nouvel état null.
      // Cibler uniquement les messages de cette conversation (présents dans allDocs)
      const failedIds = new Set(
        [..._retrySet, ..._retryFailed].filter(id => allDocs.has(id))
      );
      for (const id of failedIds) { _retrySet.delete(id); _retryFailed.delete(id); }

      for (const id of failedIds) {
        const freshDoc = allDocs.get(id);
        if (!freshDoc) continue;
        const msgData = { id: freshDoc.id, ...freshDoc.data() } as EncryptedMessage;
        if (msgData.senderUid === myUid) continue;
        try {
          const decrypted = await decryptMessage(myUid, msgData);
          decryptedCache.set(id, decrypted);
        } catch {
          _retryFailedAdd(id);
        }
      }

      // Afficher une bulle système (signature vérifiée ✓ donc on peut afficher "vérifié")
      decryptedCache.set(change.doc.id, {
        id       : change.doc.id,
        senderUid: senderUid,
        plaintext: "\uD83D\uDD04 Resynchronisation ratchet sign\u00e9e \u2713 — les nouveaux messages seront d\u00e9chiffrables",
        timestamp: (data.timestamp as number) ?? Date.now(),
        verified : true,
        readBy   : [],
        type     : "system",
      });
      allDocs.set(change.doc.id, change.doc);
    }

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

    // ── Modifications ─────────────────────────────────────────────────────
    for (const change of changes) {
      if (change.type !== "modified" || _retrySet.has(change.doc.id)) continue;
      const data   = change.doc.data();
      const cached = decryptedCache.get(change.doc.id);

      // Tombstone (supprimé) ou édité → re-déchiffrer complètement
      if ((data.deleted || data.edited) && !cached?.isDeleted) {
        const msgData = { id: change.doc.id, ...data } as EncryptedMessage;
        try {
          const decrypted = await decryptMessage(myUid, msgData);
          decryptedCache.set(change.doc.id, decrypted);
          deleteMsgCache(change.doc.id).catch(() => {}); // invalider cache IDB
          hasNewWork = true;
        } catch (e) {
          console.warn(`[AQ] Re-decrypt deleted/edited msg ${change.doc.id}:`, e);
        }
        continue;
      }

      // Sinon : mise à jour readBy uniquement
      if (cached) {
        const freshReadBy = (data.readBy ?? []) as string[];
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

    // ── Pré-remplissage depuis cache IDB (re-ouverture conversation) ─────
    //
    // Charge les plaintexts déjà déchiffrés lors d'une session précédente.
    // Évite de relancer le Double Ratchet sur des messages anciens (ce qui
    // échouerait car le ratchet est déjà avancé au-delà de ces messages).
    for (const change of changes) {
      if (change.type !== "added") continue;
      const d = change.doc;
      if (decryptedCache.has(d.id)) continue;
      const cached = await loadMsgCache(d.id);
      if (cached) {
        // Inclure les métadonnées Firestore pour permettre delete/edit depuis l'UI
        const msgFirestore = { id: d.id, ...d.data() } as EncryptedMessage;
        // Skip IDB cache for file messages — blob must be re-decrypted each session
        if (msgFirestore.hasFile) continue;
        decryptedCache.set(d.id, {
          id       : d.id,
          senderUid: cached.senderUid,
          plaintext: cached.plaintext,
          timestamp: cached.timestamp,
          verified : cached.verified,
          readBy   : [],
          messageType      : msgFirestore.messageType,
          kemCiphertext    : msgFirestore.kemCiphertext,
          initKemCiphertext: msgFirestore.initKemCiphertext,
          messageIndex     : msgFirestore.messageIndex,
        });
        hasNewWork = true;
      }
    }

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

      // Signaux système (ratchet-reset, etc.) — déjà traités plus haut → SKIP
      if ((msg as unknown as { type?: string }).type === "ratchet-reset") continue;

      // Déjà déchiffré et pas en cours de retry → SKIP
      if (decryptedCache.has(d.id) && !_retrySet.has(d.id)) continue;

      // Définitivement échoué → placeholder immédiat (évite le fallback [🔒 Message chiffré]
      // quand la conversation est rouverte avec un nouveau decryptedCache vide)
      if (_retryFailed.has(d.id)) {
        if (!decryptedCache.has(d.id)) {
          decryptedCache.set(d.id, {
            id: d.id, senderUid: msg.senderUid,
            plaintext: "[\uD83D\uDD12 Message non d\u00e9chiffrable]",
            timestamp: msg.timestamp, verified: false, readBy: msg.readBy ?? [],
          });
          hasNewWork = true;
        }
        continue;
      }

      // Messages envoyés par soi-même — déjà dans le cache via _preloadSentMessage.
      // Tenter de les déchiffrer avec le ratchet (état N+1 après l'envoi) échoue
      // systématiquement. On les ignore ici ; le preload les affiche correctement.
      if (msg.senderUid === myUid) {
        if (!decryptedCache.has(d.id)) {
          if (msg.hasFile && msg.fileCiphertext && msg.fileNonce && msg.fileName) {
            // Fichier propre : re-dériver la clé sans le ratchet (IKM = kemCT dans Firestore)
            _decryptFileOnly(d.id, msg).then(result => {
              if (result) { decryptedCache.set(d.id, result); emitResult(); }
            }).catch(() => {
              decryptedCache.set(d.id, {
                id: d.id, senderUid: msg.senderUid,
                plaintext: `[Fichier] ${msg.fileName}`,
                timestamp: msg.timestamp, verified: false, readBy: msg.readBy ?? [],
                messageType: msg.messageType,
                kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext, messageIndex: msg.messageIndex,
              });
              emitResult();
            });
            // Placeholder immédiat pendant le déchiffrement
            decryptedCache.set(d.id, {
              id: d.id, senderUid: msg.senderUid,
              plaintext: `[Fichier] ${msg.fileName ?? ''}`,
              timestamp: msg.timestamp, verified: false, readBy: msg.readBy ?? [],
              messageType: msg.messageType,
              kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext, messageIndex: msg.messageIndex,
            });
          } else {
            decryptedCache.set(d.id, {
              id: d.id, senderUid: msg.senderUid,
              plaintext: "[\uD83D\uDD12 Message envoy\u00e9 — non disponible sur cet appareil]",
              timestamp: msg.timestamp, verified: false, readBy: msg.readBy ?? [],
              messageType: msg.messageType,
              kemCiphertext: msg.kemCiphertext, initKemCiphertext: msg.initKemCiphertext, messageIndex: msg.messageIndex,
            });
          }
          hasNewWork = true;
        }
        continue;
      }

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
          // Persistance IDB — ré-affichage sans ratchet lors des rechargements
          saveMsgCache(msg.id, {
            plaintext: decrypted.plaintext, verified: decrypted.verified,
            senderUid: decrypted.senderUid, timestamp: decrypted.timestamp,
          }).catch(() => {});
          if (msg.id === lastMsgInBatch.id) {
            updateConversationPreview(msg.conversationId, decrypted.plaintext).catch(() => {});
          }
        } catch (err: any) {
    if (err.message === "RAT_EMPTY_CHAIN_KEY") {
        console.warn(`[AQ] Désynchronisation détectée sur le message ${msg.id}. L'état local est corrompu.`);
        // On affiche un message spécial à l'utilisateur au lieu de "Déchiffrement..."
        decryptedCache.set(msg.id, {
            id: msg.id, senderUid: msg.senderUid,
            plaintext: "[\u26A0\uFE0F Erreur de synchronisation : Cl\u00e9 manquante]",
            timestamp: msg.timestamp, verified: false, readBy: [],
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

// ─────────────────────────────────────────────────────────────────────────────
// Suppression de messages
//
// SÉCURITÉ DOUBLE RATCHET :
// Supprimer un message de Firestore N'AFFECTE PAS l'état du ratchet stocké
// en IDB. Le ratchet a déjà avancé au moment de la réception ; supprimer le
// document Firestore ne compromet ni la forward secrecy ni les messages futurs.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Clé de modification de message — dérivée des métadonnées Firestore
//
// La même clé est dérivée côté envoyeur (deleteMessageForBoth / editMessage)
// ET côté récepteur (decryptMessage quand msg.deleted ou msg.edited).
//
// Sécurité : seuls les participants qui peuvent lire la conversation Firestore
// (règles Firestore) peuvent accéder à kemCiphertext / initKemCiphertext /
// messageIndex et donc dériver cette clé. Forward secrecy de l'original préservée.
// ─────────────────────────────────────────────────────────────────────────────

export async function deriveEditKey(
  kemCiphertext    : string,
  initKemCiphertext: string | undefined,
  convId           : string,
  messageIndex     : number,
): Promise<string> {
  // IKM : premier matériau non-vide disponible dans Firestore
  //   • kemCiphertext     : epoch KEM-ratchet (déjà base64)
  //   • initKemCiphertext : epoch bootstrap (déjà base64)
  //   • convId encodé b64 : fallback epoch symétrique (messageIndex dans l'info rend la clé unique)
  const ikm = kemCiphertext || initKemCiphertext || btoa(convId);
  return hkdfDerive(
    ikm,
    `AegisQuantum-v1-msg-modify-key:${convId}:${messageIndex}`,
    32,
  );
}

/**
 * Supprime un message pour les deux participants.
 *
 * Au lieu de deleteDoc (1 write → perte de contexte), on écrase le ciphertext
 * avec un tombstone chiffré "__DELETED__" via la editKey dérivée des métadonnées
 * Firestore. Le récepteur voit "*Ce message a été supprimé*" en italique.
 *
 * 1 updateDoc → économie de reads/writes Firebase.
 */
export async function deleteMessageForBoth(
  convId           : string,
  msgId            : string,
  kemCiphertext    : string,
  initKemCiphertext: string | undefined,
  messageIndex     : number,
): Promise<void> {
  const editKey = await deriveEditKey(kemCiphertext, initKemCiphertext, convId, messageIndex);
  const { ciphertext: tombstoneCt, nonce: tombstoneNonce } = await aesGcmEncrypt("__DELETED__", editKey);

  const msgRef = doc(messagesCol(convId), msgId);
  await updateDoc(msgRef, {
    ciphertext : tombstoneCt,
    nonce      : tombstoneNonce,
    deleted    : true,
    // Effacer les pièces jointes — pas de doc/blob d'un message supprimé
    hasFile        : false,
    fileCiphertext : "",
    fileNonce      : "",
    fileName       : "",
    signature      : "",
  } as Partial<EncryptedMessage>);

  await deleteMsgCache(msgId);
}

/**
 * Modifie un message (pour les deux participants).
 *
 * Le ciphertext est remplacé par AES-GCM(nouvellePlaintext, editKey).
 * Le flag `edited: true` et `editedAt` sont ajoutés.
 * 1 updateDoc — aucun read Firestore supplémentaire.
 */
export async function editMessage(
  convId           : string,
  msgId            : string,
  newPlaintext     : string,
  kemCiphertext    : string,
  initKemCiphertext: string | undefined,
  messageIndex     : number,
): Promise<void> {
  const editKey = await deriveEditKey(kemCiphertext, initKemCiphertext, convId, messageIndex);
  const { ciphertext: editCt, nonce: editNonce } = await aesGcmEncrypt(newPlaintext, editKey);

  const msgRef = doc(messagesCol(convId), msgId);
  await updateDoc(msgRef, {
    ciphertext : editCt,
    nonce      : editNonce,
    edited     : true,
    editedAt   : Date.now(),
  } as Partial<EncryptedMessage>);

  // Invalider le cache IDB — le prochain chargement re-déchiffrera
  await deleteMsgCache(msgId);
}

/**
 * Supprime un message uniquement localement (pour soi uniquement).
 * - Le message reste dans Firestore, visible par l'autre participant.
 * - Stocke le msgId dans la liste "hidden" IDB de l'utilisateur.
 */
export async function deleteMessageForMe(uid: string, msgId: string): Promise<void> {
  await hideMessageLocally(uid, msgId);
}
