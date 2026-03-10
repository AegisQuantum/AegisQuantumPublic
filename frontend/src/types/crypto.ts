/**
 * crypto.ts — Types partagés de la couche crypto AegisQuantum
 */

/**
 * Paire de clés ML-KEM-768.
 * Miroir du type KemKeyPair défini dans crypto/kem.ts — re-exporté ici
 * pour que les services puissent l'importer sans dépendre directement de kem.ts.
 */
export interface KemKeyPair {
  /** Base64 — ML-KEM-768 public key (1184 bytes). Safe to publish. */
  publicKey: string;
  /** Base64 — ML-KEM-768 private key (2400 bytes). NEVER leaves memory. */
  privateKey: string;
}

/**
 * Paire de clés ML-DSA-65.
 * Vient de dsaGenerateKeyPair() dans crypto/dsa.ts
 */
export interface DsaKeyPair {
  /** Base64 — ML-DSA-65 public key. Safe to publish. */
  publicKey: string;
  /** Base64 — ML-DSA-65 private key. NEVER leaves memory. */
  privateKey: string;
}

/**
 * Résultat de la dérivation Argon2id.
 * Vient de argon2Derive() dans crypto/argon2.ts
 */
export interface Argon2Result {
  /** Base64 — 32-byte derived key, utilisée pour chiffrer le vault IndexedDB. */
  key: string;
  /** Base64 — 16-byte random salt, stocké en clair dans Firestore aux côtés du vault. */
  salt: string;
}
