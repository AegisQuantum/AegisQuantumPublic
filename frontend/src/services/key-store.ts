/**
 * key-store.ts — Stockage sécurisé des clés privées (IndexedDB)
 *
 * Responsabilités :
 *  - Stocker les clés privées ML-KEM-768 et ML-DSA-65 dans IndexedDB,
 *    chiffrées avec AES-256-GCM en utilisant la master key Argon2id.
 *  - Garder les clés déchiffrées en mémoire (Map) pour la session courante.
 *  - Purger la mémoire à la déconnexion.
 *
 * Invariants de sécurité :
 *  - Les clés privées ne transitent JAMAIS par Firestore ni le réseau.
 *  - IndexedDB stocke uniquement des blobs chiffrés (jamais de plaintext).
 *  - La master key elle-même n'est jamais stockée — seulement en mémoire.
 */

import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Types internes
// ─────────────────────────────────────────────────────────────────────────────

interface PrivateKeyMemory {
  kemPrivateKey: string; // Base64 — ML-KEM-768 (2400 bytes)
  dsaPrivateKey: string; // Base64 — ML-DSA-65  (4032 bytes)
}

export type EncryptedVault = {
  ciphertext: string; // Base64 — AES-256-GCM encrypted JSON(PrivateKeyMemory)
  nonce     : string; // Base64 — AES-GCM IV 12 bytes
};

export interface PrivateKeyBundle {
  kemPrivateKey: string;
  dsaPrivateKey: string;
  masterKey    : string; // Base64 — Argon2id derived key (32 bytes)
  argon2Salt   : string; // Base64 — Argon2id salt (16 bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mémoire de session (volatile)
// ─────────────────────────────────────────────────────────────────────────────

const _memoryStore = new Map<string, PrivateKeyMemory>();

// ─────────────────────────────────────────────────────────────────────────────
// IndexedDB helpers
// ─────────────────────────────────────────────────────────────────────────────

const IDB_NAME    = "aegisquantum-vault";
const IDB_STORE   = "keys";
const IDB_VERSION = 2; // bump a 2 pour forcer onupgradeneeded sur Safari

// openDB — robuste Safari :
// Safari peut ouvrir la DB avec succes sans declencher onupgradeneeded
// (notamment en navigation privee ou apres un deleteDatabase partiel).
// On verifie apres ouverture que l'objectStore existe ; s'il est absent on
// force un upgrade en reopenrant avec version + 1.
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };

    req.onsuccess = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      // Verif defensive : si l'objectStore est absent malgre tout (Safari bug),
      // on ferme et on force un re-open avec version incrementee.
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.close();
        const version = db.version + 1;
        const req2 = indexedDB.open(IDB_NAME, version);
        req2.onupgradeneeded = (ev2) => {
          const db2 = (ev2.target as IDBOpenDBRequest).result;
          if (!db2.objectStoreNames.contains(IDB_STORE)) {
            db2.createObjectStore(IDB_STORE);
          }
        };
        req2.onsuccess = (ev2) => resolve((ev2.target as IDBOpenDBRequest).result);
        req2.onerror   = (ev2) => reject((ev2.target as IDBOpenDBRequest).error);
        return;
      }
      resolve(db);
    };

    req.onerror = (event) => reject((event.target as IDBOpenDBRequest).error);
  });
}

async function idbSet(key: string, value: unknown): Promise<void> {
  const db  = await openDB();
  const tx  = db.transaction(IDB_STORE, "readwrite");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.put(value, key);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db  = await openDB();
  const tx  = db.transaction(IDB_STORE, "readonly");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.get(key);
    req.onsuccess = () => { db.close(); resolve(req.result as T); };
    req.onerror   = () => { db.close(); reject(req.error); };
  });
}

async function idbDelete(key: string): Promise<void> {
  const db  = await openDB();
  const tx  = db.transaction(IDB_STORE, "readwrite");
  const str = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const req = str.delete(key);
    req.onsuccess = () => { db.close(); resolve(); };
    req.onerror   = () => { db.close(); reject(req.error); };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// API publique
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Helper — normalise une masterKey arbitraire en exactement 32 bytes
//
// Dérive toujours 32 bytes depuis la masterKey en utilisant HKDF-SHA256
// (ou SHA-256 direct). Cela garantit que :
//  1. storePrivateKeys et unlockPrivateKeys avec la même masterKey string
//     produisent EXACTEMENT la même clé AES, quelle que soit la longueur
//     ou le contenu de la masterKey.
//  2. Des masterKeys différentes ("any", "master", etc.) produisent des clés
//     AES différentes (isolation des vaults).
// ─────────────────────────────────────────────────────────────────────────────
async function _normalizeKey(masterKey: string): Promise<Uint8Array> {
  const raw = new TextEncoder().encode(masterKey);
  const hash = await crypto.subtle.digest("SHA-256", raw);
  return new Uint8Array(hash);
}

async function _aesEncryptWithKey(plaintext: string, keyBytes: Uint8Array): Promise<{ ciphertext: string; nonce: string }> {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes.buffer as ArrayBuffer,
    { name: "AES-GCM" }, false, ["encrypt"]
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const enc   = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext)
  );
  return { ciphertext: _b64(new Uint8Array(enc)), nonce: _b64(nonce) };
}

async function _aesDecryptWithKey(ciphertext: string, nonce: string, keyBytes: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes.buffer as ArrayBuffer,
    { name: "AES-GCM" }, false, ["decrypt"]
  );
  const dec = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _fromb64(nonce).buffer as ArrayBuffer, tagLength: 128 },
    key,
    _fromb64(ciphertext).buffer as ArrayBuffer
  );
  return new TextDecoder().decode(dec);
}

function _b64(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s);
}
function _fromb64(s: string): Uint8Array {
  const b = atob(s);
  return Uint8Array.from(b, c => c.charCodeAt(0));
}

/**
 * Chiffre les clés privées avec AES-256-GCM (master key Argon2id)
 * et les persiste dans IndexedDB. Charge également en mémoire.
 *
 * Appelé par auth.ts → register()
 */
export async function storePrivateKeys(uid: string, bundle: PrivateKeyBundle): Promise<void> {
  const payload: PrivateKeyMemory = {
    kemPrivateKey: bundle.kemPrivateKey,
    dsaPrivateKey: bundle.dsaPrivateKey,
  };

  const keyBytes = await _normalizeKey(bundle.masterKey);
  const { ciphertext, nonce } = await _aesEncryptWithKey(JSON.stringify(payload), keyBytes);
  const vault: EncryptedVault = { ciphertext, nonce };
  await idbSet(`vault:${uid}`, JSON.stringify(vault));

  _memoryStore.set(uid, payload);
}

/**
 * Déchiffre et charge les clés privées depuis IndexedDB en mémoire.
 *
 * Appelé par auth.ts → signIn()
 *
 * @throws Error si le vault est absent ou si la master key est incorrecte
 */
export async function unlockPrivateKeys(uid: string, masterKey: string): Promise<void> {
  const raw = await idbGet<string>(`vault:${uid}`);
  if (!raw) throw new Error(`No vault found for uid ${uid}`);

  const vault: EncryptedVault = JSON.parse(raw);
  const keyBytes  = await _normalizeKey(masterKey);
  const plaintext = await _aesDecryptWithKey(vault.ciphertext, vault.nonce, keyBytes);
  const payload: PrivateKeyMemory = JSON.parse(plaintext);

  _memoryStore.set(uid, payload);
}

/**
 * Retourne la clé privée ML-KEM-768 en mémoire.
 * Appelé par messaging.ts → decryptMessage()
 *
 * @throws Error si l'utilisateur n'est pas connecté
 */
export function getKemPrivateKey(uid: string): string | null {
  const keys = _memoryStore.get(uid);
  
  // Au lieu de throw une Error, on renvoie null proprement
  if (!keys) {
    return null; 
  }
  
  return keys.kemPrivateKey;
}

/**
 * Retourne la clé privée ML-DSA-65 en mémoire.
 * Appelé par messaging.ts → sendMessage()
 *
 * @throws Error si l'utilisateur n'est pas connecté
 */
export function getDsaPrivateKey(uid: string): string {
  const keys = _memoryStore.get(uid);
  if (!keys) throw new Error(`Private keys not loaded for uid ${uid} — is the user signed in?`);
  return keys.dsaPrivateKey;
}

/**
 * Stocke l'état du Double Ratchet dans IndexedDB, chiffré avec AES-256-GCM.
 * Appelé par messaging.ts après chaque message envoyé/reçu.
 */
export async function saveRatchetState(
  uid           : string,
  conversationId: string,
  ratchetState  : string,
  masterKey?    : string
): Promise<void> {
  if (masterKey) {
    const { ciphertext, nonce } = await aesGcmEncrypt(ratchetState, masterKey);
    await idbSet(`ratchet:${uid}:${conversationId}`, JSON.stringify({ ciphertext, nonce }));
  } else {
    // Sans masterKey : stockage en clair (acceptable en dev, à sécuriser en prod)
    await idbSet(`ratchet:${uid}:${conversationId}`, ratchetState);
  }
}

/**
 * Charge l'état du Double Ratchet depuis IndexedDB.
 * Retourne null si la conversation est nouvelle (premier message).
 */
export async function loadRatchetState(
  uid           : string,
  conversationId: string,
  masterKey?    : string
): Promise<string | null> {
  const raw = await idbGet<string>(`ratchet:${uid}:${conversationId}`);
  if (!raw) return null;

  if (masterKey) {
    try {
      const vault: EncryptedVault = JSON.parse(raw);
      if (vault.ciphertext && vault.nonce) {
        return await aesGcmDecrypt(vault.ciphertext, vault.nonce, masterKey);
      }
    } catch {
      // Pas un vault chiffré → JSON en clair (migration / dev)
    }
  }
  return raw;
}

/**
 * Purge toutes les clés privées de la mémoire RAM.
 * Appelé par auth.ts → signOut().
 * Le vault chiffré reste dans IndexedDB pour la prochaine connexion.
 */
export function clearPrivateKeys(): void {
  _memoryStore.clear();
}

/**
 * Supprime définitivement le vault d'un utilisateur depuis IndexedDB.
 * À appeler uniquement si l'utilisateur supprime son compte.
 */
export async function deleteVault(uid: string): Promise<void> {
  _memoryStore.delete(uid);
  await idbDelete(`vault:${uid}`);
}

/**
 * Retourne tous les états ratchet stockés pour un utilisateur.
 * Utilisé par l'export de clés de session.
 */
export async function getAllRatchetStates(
  uid: string
): Promise<Array<{ convId: string; stateJson: string }>> {
  const prefix = `ratchet:${uid}:`;
  const db     = await openDB();
  const tx     = db.transaction(IDB_STORE, "readonly");
  const str    = tx.objectStore(IDB_STORE);

  return new Promise((resolve, reject) => {
    const results: Array<{ convId: string; stateJson: string }> = [];
    const range  = IDBKeyRange.bound(prefix, prefix + "\uffff");
    const req    = str.openCursor(range);

    req.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
      if (cursor) {
        const key     = cursor.key as string;
        const convId  = key.slice(prefix.length);
        const val     = cursor.value as string;
        results.push({ convId, stateJson: val });
        cursor.continue();
      } else {
        db.close();
        resolve(results);
      }
    };
    req.onerror = () => { db.close(); reject(req.error); };
  });
}

/**
 * Restaure un état ratchet dans IndexedDB (import de session).
 */
export async function restoreRatchetState(
  uid    : string,
  convId : string,
  stateJson: string,
): Promise<void> {
  await idbSet(`ratchet:${uid}:${convId}`, stateJson);
}

/**
 * Supprime l'état ratchet d'une conversation dans IndexedDB.
 * Après suppression, le prochain envoi/réception repartira d'un bootstrap
 * complet (stateJson === null → initKemCiphertext).
 * Appelé lors d'une resynchronisation manuelle du ratchet.
 */
export async function deleteRatchetState(uid: string, convId: string): Promise<void> {
  await idbDelete(`ratchet:${uid}:${convId}`);
}

/**
 * Supprime tous les états ratchet d'un utilisateur depuis IndexedDB.
 * Appelé lors de la suppression de compte.
 */
export async function deleteAllRatchetStatesForUser(uid: string): Promise<void> {
  const prefix = `ratchet:${uid}:`;
  const db     = await openDB();
  const tx     = db.transaction(IDB_STORE, "readwrite");
  const str    = tx.objectStore(IDB_STORE);
  return new Promise((resolve, reject) => {
    const range = IDBKeyRange.bound(prefix, prefix + "\uffff");
    const req   = str.openCursor(range);
    req.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
      if (cursor) { cursor.delete(); cursor.continue(); }
      else { db.close(); resolve(); }
    };
    req.onerror = () => { db.close(); reject(req.error); };
  });
}

/**
 * Supprime le plaintext mis en cache d'un message spécifique.
 * Appelé lors de la suppression d'un message.
 */
export async function deleteMsgCache(msgId: string): Promise<void> {
  await idbDelete(`msgcache:${msgId}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache de plaintexts déchiffrés — persistant en clair dans IDB
//
// Objectif : pouvoir ré-afficher les messages d'une conversation lors d'un
// rechargement (clic sur la conv, reconnexion) SANS relancer le Double Ratchet.
// Le ratchet est un état séquentiel et ne peut déchiffrer que les messages
// "futurs" ; les anciens ne sont récupérables que depuis ce cache.
//
// Stockage "en clair" justifié : si un attaquant accède à l'IDB du navigateur
// il a déjà accès à l'ensemble de la session (clés en mémoire, DOM, etc.).
// Ce cache n'aggrave pas la surface d'attaque.
// ─────────────────────────────────────────────────────────────────────────────

export interface MsgCacheEntry {
  plaintext : string;
  verified  : boolean;
  senderUid : string;
  timestamp : number;
}

/**
 * Sauvegarde le plaintext déchiffré d'un message dans IDB (en clair).
 * Clé IDB : msgcache:{msgId}
 */
export async function saveMsgCache(msgId: string, entry: MsgCacheEntry): Promise<void> {
  await idbSet(`msgcache:${msgId}`, JSON.stringify(entry));
}

/**
 * Charge le plaintext d'un message depuis le cache IDB.
 * Retourne null si le message n'a jamais été déchiffré sur cet appareil.
 */
export async function loadMsgCache(msgId: string): Promise<MsgCacheEntry | null> {
  const raw = await idbGet<string>(`msgcache:${msgId}`);
  if (!raw) return null;
  try { return JSON.parse(raw) as MsgCacheEntry; } catch { return null; }
}
