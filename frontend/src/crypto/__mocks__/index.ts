/**
 * src/crypto/__mocks__/index.ts
 *
 * Mock automatique de src/crypto utilisé par Vitest quand un test appelle
 * vi.mock("../crypto") ou vi.mock("../../crypto").
 *
 * Remplace :
 *  - argon2Derive     → PBKDF2-SHA256 (pas de WASM argon2-browser)
 *  - kemGenerateKeyPair / dsaGenerateKeyPair → clés fictives Base64
 *  - aesGcmEncrypt / aesGcmDecrypt → SubtleCrypto fonctionnel (pour ratchet)
 *  - dsaSign / dsaVerify → pass-through léger
 */

import { vi } from "vitest";

// ── helpers Base64 internes ────────────────────────────────────────────────
function _b64(b: Uint8Array): string {
  let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s);
}
function _fromb64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// ── compteur de clés ───────────────────────────────────────────────────────
let _keyCounter = 0;

// ── argon2Derive → PBKDF2-SHA256 ──────────────────────────────────────────
export const argon2Derive = vi.fn(async (password: string, saltB64?: string) => {
  const saltBytes = saltB64 ? _fromb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const km = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 1 }, km, 256
  );
  return { key: _b64(new Uint8Array(bits)), salt: _b64(saltBytes) };
});

// ── KEM keypair ────────────────────────────────────────────────────────────
export const kemGenerateKeyPair = vi.fn(async () => {
  const id = ++_keyCounter;
  return {
    publicKey : btoa(`kem-pub-${id}-` + "x".repeat(20)),
    privateKey: btoa(`kem-priv-${id}-` + "y".repeat(20)),
  };
});

export const kemEncapsulate = vi.fn(async () => ({
  sharedSecret: _b64(new Uint8Array(32).fill(0xAB)),
  ciphertext  : btoa("mock-kem-ciphertext"),
}));

export const kemDecapsulate = vi.fn(async () => _b64(new Uint8Array(32).fill(0xAB)));

// ── DSA keypair ────────────────────────────────────────────────────────────
export const dsaGenerateKeyPair = vi.fn(async () => {
  const id = ++_keyCounter;
  return {
    publicKey : btoa(`dsa-pub-${id}-` + "a".repeat(20)),
    privateKey: btoa(`dsa-priv-${id}-` + "b".repeat(20)),
  };
});

export const dsaSign   = vi.fn(async () => btoa("mock-sig"));
export const dsaVerify = vi.fn(async () => true);

// ── AES-256-GCM (fonctionnel pour que les tests ratchet passent) ───────────
export const aesGcmEncrypt = vi.fn(async (plaintext: string, keyB64: string) => {
  const keyBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(keyB64))
  );
  const key   = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const enc   = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, key, new TextEncoder().encode(plaintext));
  return { ciphertext: _b64(new Uint8Array(enc)), nonce: _b64(nonce) };
});

export const aesGcmDecrypt = vi.fn(async (ciphertextB64: string, nonceB64: string, keyB64: string) => {
  const keyBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(keyB64))
  );
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const dec = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _fromb64(nonceB64), tagLength: 128 },
    key, _fromb64(ciphertextB64)
  );
  return new TextDecoder().decode(dec);
});

// ── HKDF ──────────────────────────────────────────────────────────────────
export const hkdfDerive     = vi.fn(async () => _b64(new Uint8Array(32).fill(0xCC)));
export const hkdfDerivePair = vi.fn(async () => ({ rootKey: _b64(new Uint8Array(32).fill(1)), sendingChainKey: _b64(new Uint8Array(32).fill(2)) }));
export const HKDF_INFO      = "aegisquantum-v1";

// ── Double Ratchet ─────────────────────────────────────────────────────────
export const doubleRatchetEncrypt = vi.fn(async () => ({
  ciphertext: btoa("mock-ct"), nonce: btoa("mock-nonce"),
  kemCiphertext: btoa("mock-kem"), messageIndex: 0, newStateJson: "{}",
}));
export const doubleRatchetDecrypt = vi.fn(async () => ({ plaintext: "mock-plaintext", newStateJson: "{}" }));

// ── Helpers Base64 re-exportés ─────────────────────────────────────────────
export const toBase64   = vi.fn(_b64);
export const fromBase64 = vi.fn(_fromb64);

// ── RatchetState helpers ───────────────────────────────────────────────────
export const serializeRatchetState   = vi.fn((s: unknown) => JSON.stringify(s));
export const deserializeRatchetState = vi.fn((s: string)  => JSON.parse(s));
