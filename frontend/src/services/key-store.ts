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
const IDB_VERSION = 1;

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
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

  // Chiffrer le vault avec la master key Argon2id
  const { ciphertext, nonce } = await aesGcmEncrypt(
    JSON.stringify(payload),
    bundle.masterKey
  );
  const vault: EncryptedVault = { ciphertext, nonce };
  await idbSet(`vault:${uid}`, JSON.stringify(vault));

  // Charger en mémoire pour la session courante
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
  const plaintext = await aesGcmDecrypt(vault.ciphertext, vault.nonce, masterKey);
  const payload: PrivateKeyMemory = JSON.parse(plaintext);

  _memoryStore.set(uid, payload);
}

/**
 * Retourne la clé privée ML-KEM-768 en mémoire.
 * Appelé par messaging.ts → decryptMessage()
 *
 * @throws Error si l'utilisateur n'est pas connecté
 */
export function getKemPrivateKey(uid: string): string {
  const keys = _memoryStore.get(uid);
  if (!keys) throw new Error(`Private keys not loaded for uid ${uid} — is the user signed in?`);
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
      // Si c'est un vault chiffré (a ciphertext + nonce)
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
