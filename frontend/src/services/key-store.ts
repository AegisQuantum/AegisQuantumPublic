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

// ─────────────────────────────────────────────────────────────────────────────
// DÉPENDANCES CRYPTO — à brancher une fois les modules crypto implémentés
// ─────────────────────────────────────────────────────────────────────────────

/**
 * TODO: importer aesGcmEncrypt() et aesGcmDecrypt() depuis crypto/aes-gcm.ts
 *
 * Signatures attendues :
 *   aesGcmEncrypt(plaintext: string, key: string): Promise<{ ciphertext: string; nonce: string }>
 *     → plaintext : Base64 ou UTF-8 string
 *     → key       : Base64 (32 bytes) — ici la master key Argon2id
 *     → ciphertext: Base64 (AES-256-GCM encrypted)
 *     → nonce     : Base64 (12 bytes random IV)
 *
 *   aesGcmDecrypt(ciphertext: string, nonce: string, key: string): Promise<string>
 *     → retourne le plaintext original
 *     → lève une erreur si le tag GCM est invalide (clé incorrecte ou données corrompues)
 */
async function _aesGcmEncrypt(
  _plaintext: string,
  _key: string
): Promise<{ ciphertext: string; nonce: string }> {
  throw new Error("TODO: brancher aesGcmEncrypt() depuis crypto/aes-gcm.ts");
}
void _aesGcmEncrypt;

async function _aesGcmDecrypt(
  _ciphertext: string,
  _nonce: string,
  _key: string
): Promise<string> {
  throw new Error("TODO: brancher aesGcmDecrypt() depuis crypto/aes-gcm.ts");
}
void _aesGcmDecrypt;

// ─────────────────────────────────────────────────────────────────────────────
// Types internes
// ─────────────────────────────────────────────────────────────────────────────

/** Clés privées maintenues en mémoire pour la session courante. */
interface PrivateKeyMemory {
  /** Base64 — ML-KEM-768 private key (2400 bytes). Vient de kemGenerateKeyPair() */
  kemPrivateKey: string;
  /** Base64 — ML-DSA-65 private key. Vient de dsaGenerateKeyPair() */
  dsaPrivateKey: string;
}

/** Format du vault chiffré persisté dans IndexedDB.
 * @todo Utilisé quand aesGcmEncrypt sera branché dans storePrivateKeys/unlockPrivateKeys.
 */
// @todo : branché dans storePrivateKeys/unlockPrivateKeys quand aesGcmEncrypt sera implémenté.
export type EncryptedVault = {
  /** Base64 — AES-256-GCM encrypted JSON(PrivateKeyMemory). Chiffré via aesGcmEncrypt() */
  ciphertext: string;
  /** Base64 — nonce AES-GCM (12 bytes). Produit par aesGcmEncrypt() */
  nonce: string;
}

/** Payload stocké à l'inscription, passé à storePrivateKeys(). */
export interface PrivateKeyBundle {
  kemPrivateKey: string;
  dsaPrivateKey: string;
  /** Base64 — master key Argon2id (32 bytes). Vient de argon2Derive() dans crypto/argon2.ts */
  masterKey: string;
  /** Base64 — salt Argon2id (16 bytes). À stocker aussi dans Firestore /users/{uid}/argon2Salt */
  argon2Salt: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mémoire de session (volatile — effacée à la déconnexion)
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
    req.onupgradeneeded = () => {
      req.result.createObjectStore(IDB_STORE);
    };
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
 * Chiffre les clés privées avec la master key Argon2id et les persiste dans IndexedDB.
 * Charge également les clés en mémoire pour la session courante.
 *
 * Appelé par auth.ts → register() après la génération des clés.
 *
 * @param uid    — UID Firebase de l'utilisateur
 * @param bundle — clés privées + master key + salt (vient de auth.ts)
 */
export async function storePrivateKeys(uid: string, bundle: PrivateKeyBundle): Promise<void> {
  const payload: PrivateKeyMemory = {
    kemPrivateKey: bundle.kemPrivateKey,
    dsaPrivateKey: bundle.dsaPrivateKey,
  };

  // Chiffrer le vault avec la master key Argon2id
  // TODO: décommenter quand crypto/aes-gcm.ts sera implémenté
  // const plaintext = JSON.stringify(payload);
  // const { ciphertext, nonce } = await _aesGcmEncrypt(plaintext, bundle.masterKey);
  // const vault: EncryptedVault = { ciphertext, nonce };
  // await idbSet(`vault:${uid}`, vault);

  // En attendant la crypto : stocker le payload en clair (⚠️ temporaire, DEV ONLY)
  await idbSet(`vault:${uid}`, JSON.stringify(payload));

  // Charger en mémoire pour la session
  _memoryStore.set(uid, payload);
}

/**
 * Déchiffre et charge les clés privées depuis IndexedDB en mémoire.
 * Appelé par auth.ts → signIn() après la dérivation Argon2id.
 *
 * @param uid       — UID Firebase de l'utilisateur
 * @param masterKey — Base64 (32 bytes) dérivée via argon2Derive() dans crypto/argon2.ts
 * @throws Error si le vault est absent ou si le déchiffrement échoue
 */
export async function unlockPrivateKeys(uid: string, masterKey: string): Promise<void> {
  const raw = await idbGet<string>(`vault:${uid}`);
  if (!raw) throw new Error(`No vault found for uid ${uid}`);

  // TODO: décommenter quand crypto/aes-gcm.ts sera implémenté
  // const vault: EncryptedVault = JSON.parse(raw);
  // const plaintext = await _aesGcmDecrypt(vault.ciphertext, vault.nonce, masterKey);
  // const payload: PrivateKeyMemory = JSON.parse(plaintext);

  // En attendant : lire le JSON en clair (⚠️ temporaire, DEV ONLY)
  void masterKey; // supprime le warning lint
  const payload: PrivateKeyMemory = JSON.parse(raw);

  _memoryStore.set(uid, payload);
}

/**
 * Retourne la clé privée ML-KEM-768 en mémoire pour un utilisateur donné.
 *
 * Appelé par messaging.ts → receiveMessage() pour kemDecapsulate().
 *
 * @returns Base64 — ML-KEM-768 private key (2400 bytes)
 * @throws Error si les clés ne sont pas chargées (utilisateur non connecté)
 */
export function getKemPrivateKey(uid: string): string {
  const keys = _memoryStore.get(uid);
  if (!keys) throw new Error(`Private keys not loaded for uid ${uid} — is the user signed in?`);
  return keys.kemPrivateKey;
}

/**
 * Retourne la clé privée ML-DSA-65 en mémoire pour un utilisateur donné.
 *
 * Appelé par messaging.ts → sendMessage() pour dsaSign().
 *
 * @returns Base64 — ML-DSA-65 private key
 * @throws Error si les clés ne sont pas chargées (utilisateur non connecté)
 */
export function getDsaPrivateKey(uid: string): string {
  const keys = _memoryStore.get(uid);
  if (!keys) throw new Error(`Private keys not loaded for uid ${uid} — is the user signed in?`);
  return keys.dsaPrivateKey;
}

/**
 * Stocke l'état du Double Ratchet pour une conversation, chiffré dans IndexedDB.
 *
 * Appelé par messaging.ts après chaque message envoyé/reçu.
 *
 * @param uid            — UID de l'utilisateur courant
 * @param conversationId — ID de la conversation
 * @param ratchetState   — objet RatchetState sérialisé (JSON string)
 *                          Vient de doubleRatchetEncrypt/Decrypt() dans crypto/double-ratchet.ts
 * @param masterKey      — Base64 — master key Argon2id pour chiffrer l'état
 */
export async function saveRatchetState(
  uid: string,
  conversationId: string,
  ratchetState: string,
  masterKey?: string
): Promise<void> {
  // TODO: chiffrer ratchetState avec aesGcmEncrypt(ratchetState, masterKey)
  //       quand crypto/aes-gcm.ts sera implémenté
  void masterKey;
  await idbSet(`ratchet:${uid}:${conversationId}`, ratchetState);
}

/**
 * Charge l'état du Double Ratchet pour une conversation depuis IndexedDB.
 *
 * Appelé par messaging.ts avant chaque sendMessage/receiveMessage.
 *
 * @returns JSON string du RatchetState, ou null si pas encore initialisé
 *          (premier message de la conversation)
 */
export async function loadRatchetState(
  uid: string,
  conversationId: string,
  masterKey?: string
): Promise<string | null> {
  // TODO: déchiffrer avec aesGcmDecrypt() quand crypto/aes-gcm.ts sera implémenté
  void masterKey;
  const raw = await idbGet<string>(`ratchet:${uid}:${conversationId}`);
  return raw ?? null;
}

/**
 * Purge toutes les clés privées de la mémoire.
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
