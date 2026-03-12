/**
 * messaging.ts — Envoi et réception de messages chiffrés
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PIPELINE ACTUEL — Double Ratchet (ML-KEM-768 + HKDF + AES-256-GCM)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  ENVOI :
 *   1. Récupérer les clés publiques KEM du destinataire et les nôtres
 *   2. Charger le RatchetState depuis IDB (null = premier message)
 *   3. kemEncapsulate → initSecret pour bootstrapper si state null
 *   4. doubleRatchetEncrypt(plaintext, state, ...) → { ciphertext, nonce, kemCiphertext, messageIndex, newStateJson }
 *   5. saveRatchetState → IDB
 *   6. DSA sign(ciphertext ‖ nonce ‖ kemCiphertext)
 *   7. addDoc → Firestore
 *   8. Notifier la preview localement
 *
 *  RÉCEPTION :
 *   1. DSA verify(signature, senderDsaPublicKey)
 *   2. Charger le RatchetState depuis IDB
 *   3. kemDecapsulate(kemCiphertext, ourPrivKey) → initSecret
 *   4. doubleRatchetDecrypt(...) → { plaintext, newStateJson }
 *   5. saveRatchetState → IDB
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Persistance de l'état (IDB)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Clé IDB : "ratchet:<uid>:<convId>" → RatchetState JSON chiffré AES-GCM
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
import {
  kemEncapsulate,
  kemDecapsulate,
  dsaSign,
  dsaVerify,
} from "../crypto";
import { doubleRatchetEncrypt, doubleRatchetDecrypt } from "../crypto/double-ratchet";
import type { EncryptedMessage, Conversation, DecryptedMessage } from "../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// IDB — connexion singleton
// ─────────────────────────────────────────────────────────────────────────────
// Les messageKeys individuelles ne sont plus stockées directement (le RatchetState
// dans key-store.ts prend en charge toute la persistance des clés).
// On garde le singleton IDB ici uniquement pour un éventuel usage futur ou
// pour la compatibilité avec les fonctions idbSet/idbGet si nécessaire.

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

// Gardé pour compatibilité / usage futur
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

// Évite les warnings "unused" — ces fonctions restent pour la migration
void idbSet; void idbGet;

// ─────────────────────────────────────────────────────────────────────────────
// Notification locale de mise à jour de preview (sans aller-retour Firestore)
// ─────────────────────────────────────────────────────────────────────────────
//
// L'envoyeur notifie la sidebar localement via ce callback en mémoire
// (zéro aller-retour réseau). Le receiver met à jour Firestore quand il
// reçoit le message.
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
const _retrySet = new Set<string>();

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
// Envoi de message — Double Ratchet
// ─────────────────────────────────────────────────────────────────────────────

export async function sendMessage(
  myUid     : string,
  contactUid: string,
  plaintext : string
): Promise<void> {
  const convId = getConversationId(myUid, contactUid);

  // ── 1. Clés publiques (les nôtres + celles du contact) ───────────────────
  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";

  const contactKeys = await getPublicKeys(contactUid);
  if (!contactKeys) throw new Error(`Clés publiques introuvables pour ${contactUid}`);

  // ── 2. Nos clés privées ───────────────────────────────────────────────────
  const myDsaPrivateKey = getDsaPrivateKey(myUid);
  const myKemPrivateKey = getKemPrivateKey(myUid);

  // ── 3. Charger l'état ratchet depuis IDB (null = premier message) ─────────
  const stateJson = await loadRatchetState(myUid, convId);

  // ── 4. KEM init secret (bootstrapping uniquement si stateJson === null) ───
  const { sharedSecret: initSecret } = await kemEncapsulate(contactKeys.kemPublicKey);

  // ── 5. Double Ratchet encrypt ─────────────────────────────────────────────
  const drResult = await doubleRatchetEncrypt(
    plaintext,
    stateJson,
    convId,
    myKemPrivateKey,
    myKemPubKey,
    contactKeys.kemPublicKey,
    initSecret,
  );

  // ── 6. Sauvegarder le nouvel état ratchet en IDB ──────────────────────────
  await saveRatchetState(myUid, convId, drResult.newStateJson);

  // ── 7. DSA sign(ciphertext ‖ nonce ‖ kemCiphertext) ──────────────────────
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

  // ── 9. Preview locale (sans écriture Firestore côté envoyeur) ────────────
  // Évite un snapshot subscribeToConversations parasite → flash sidebar.
  // La preview Firestore est mise à jour par le receiver.
  _notifyConvPreviewUpdate(convId, plaintext, Date.now());
}

// ─────────────────────────────────────────────────────────────────────────────
// Réception / déchiffrement — Double Ratchet
// ─────────────────────────────────────────────────────────────────────────────

export async function decryptMessage(
  myUid: string,
  msg  : EncryptedMessage
): Promise<DecryptedMessage> {

  // ── 1. DSA verify ────────────────────────────────────────────────────────
  const senderKeys = await getPublicKeys(msg.senderUid);
  let   verified   = false;
  if (senderKeys) {
    const signedPayload = msg.ciphertext + msg.nonce + msg.kemCiphertext;
    verified = await dsaVerify(signedPayload, msg.signature, senderKeys.dsaPublicKey);
  }

  // ── 2. Nos clés ───────────────────────────────────────────────────────────
  const myKeys      = await getPublicKeys(myUid);
  const myKemPubKey = myKeys?.kemPublicKey ?? "";
  const myKemPrivKey = getKemPrivateKey(myUid);

  // ── 3. Charger l'état ratchet depuis IDB ─────────────────────────────────
  const stateJson = await loadRatchetState(myUid, msg.conversationId);

  // ── 4. KEM decapsulate → initSecret (bootstrapping si stateJson null) ────
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

  // ── 6. Sauvegarder le nouvel état ratchet en IDB ──────────────────────────
  await saveRatchetState(myUid, msg.conversationId, drResult.newStateJson);

  return {
    id       : msg.id,
    senderUid: msg.senderUid,
    plaintext: drResult.plaintext,
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
   * Utilisé pour absorber la race condition snapshot local Firestore.
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
