/**
 * argon2.ts — Argon2id via argon2-browser (chargé via CDN, pas bundlé)
 *
 * argon2-browser ne peut pas être bundlé par Vite/Rollup car :
 *  - Son .wasm utilise des imports internes non-standards
 *  - Sa version dist/ référence des modules Node (path, fs) pour le fallback SSR
 *
 * Solution : argon2-browser est chargé via <script> dans index.html depuis le CDN
 * officiel, ce qui expose window.argon2. Ce module accède à ce global.
 *
 * En test (Vitest/Node), argon2-browser est mocké dans setup.crypto.ts par une
 * implémentation PBKDF2 équivalente — ce code ne s'exécute pas dans les tests.
 *
 * Paramètres Argon2id (OWASP 2024) :
 *  - m = 65536 (64 MB) · t = 3 · p = 1 · hashLen = 32
 */

import { toBase64, fromBase64 } from "./kem";

// ─────────────────────────────────────────────────────────────────────────────
// Typage minimal du global window.argon2 (exposé par le CDN)
// ─────────────────────────────────────────────────────────────────────────────

interface Argon2Global {
  ArgonType: { Argon2d: number; Argon2i: number; Argon2id: number };
  hash(params: {
    pass       : string | Uint8Array;
    salt       : Uint8Array;
    time      ?: number;
    mem       ?: number;
    parallelism?: number;
    hashLen   ?: number;
    type      ?: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }>;
}

/** Récupère le global window.argon2 injecté par le CDN. */
function getArgon2(): Argon2Global {
  const w = globalThis as unknown as { argon2?: Argon2Global };
  if (!w.argon2) {
    throw new Error(
      "argon2-browser not loaded. Make sure the CDN <script> is present in index.html."
    );
  }
  return w.argon2;
}

// ─────────────────────────────────────────────────────────────────────────────
// Paramètres
// ─────────────────────────────────────────────────────────────────────────────

const ARGON2_TIME_COST   = 3;
const ARGON2_MEMORY_COST = 65536;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN    = 32;

// ─────────────────────────────────────────────────────────────────────────────
// Core
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Dérive une master key AES-256 depuis le mot de passe utilisateur.
 *
 * @param password — mot de passe en clair (UTF-8)
 * @param saltB64  — salt Base64 existant (reconnexion), ou undefined (1ère connexion)
 * @returns { key: Base64 32 bytes, salt: Base64 16 bytes }
 */
export async function argon2Derive(
  password: string,
  saltB64?: string
): Promise<{ key: string; salt: string }> {
  const argon2 = getArgon2();

  const saltBytes = saltB64
    ? fromBase64(saltB64)
    : crypto.getRandomValues(new Uint8Array(16));

  const result = await argon2.hash({
    pass       : password,
    salt       : saltBytes,
    time       : ARGON2_TIME_COST,
    mem        : ARGON2_MEMORY_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLen    : ARGON2_HASH_LEN,
    type       : argon2.ArgonType.Argon2id,
  });

  return {
    key : toBase64(result.hash),
    salt: toBase64(saltBytes),
  };
}
