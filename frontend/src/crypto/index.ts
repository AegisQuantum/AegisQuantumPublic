/**
 * index.ts — Point d'entrée du module crypto AegisQuantum
 *
 * Re-exporte toutes les primitives cryptographiques pour que les services
 * (auth.ts, messaging.ts, key-store.ts) puissent importer depuis "crypto/"
 * sans connaître les fichiers internes.
 *
 * Architecture des dépendances :
 *
 *   services/auth.ts
 *     ← kemGenerateKeyPair()   (kem.ts)
 *     ← dsaGenerateKeyPair()   (dsa.ts)
 *     ← argon2Derive()         (argon2.ts)
 *
 *   services/key-store.ts
 *     ← aesGcmEncrypt/Decrypt() (aes-gcm.ts)
 *
 *   services/messaging.ts
 *     ← kemEncapsulate/Decapsulate() (kem.ts)
 *     ← dsaSign/Verify()             (dsa.ts)
 *     ← doubleRatchetEncrypt/Decrypt() (double-ratchet.ts)
 *       └─ hkdfDerive()              (hkdf.ts)   ← interne au double ratchet
 *       └─ aesGcmEncrypt/Decrypt()   (aes-gcm.ts) ← interne au double ratchet
 */

// ML-KEM-768 (FIPS 203)
export { kemGenerateKeyPair, kemEncapsulate, kemDecapsulate, toBase64, fromBase64 } from "./kem";
export type { KemKeyPair, KemEncapResult } from "./kem";

// ML-DSA-65 (FIPS 204 / Dilithium)
export { dsaGenerateKeyPair, dsaSign, dsaVerify } from "./dsa";
export type { DsaKeyPair } from "./dsa";

// HKDF-SHA256
export { hkdfDerive, hkdfDerivePair, HKDF_INFO } from "./hkdf";

// AES-256-GCM
export { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm";

// Argon2id
export { argon2Derive } from "./argon2";

// Double Ratchet
export { doubleRatchetEncrypt, doubleRatchetDecrypt } from "./double-ratchet";
export type { DoubleRatchetEncryptResult, DoubleRatchetDecryptResult } from "./double-ratchet";

// RatchetState helpers
export { serializeRatchetState, deserializeRatchetState } from "./ratchet-state";
