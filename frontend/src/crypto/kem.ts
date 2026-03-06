/**
 * kem.ts — ML-KEM-768 (FIPS 203) Key Encapsulation Mechanism
 *
 * Wraps @openforge-sh/liboqs createMLKEM768 for use in AegisQuantum.
 *
 * Security invariants (§4.1.1 + §4.2 of specs):
 *  - Private keys NEVER leave this module's return value — caller is
 *    responsible for keeping them in memory only (never sent to Firebase).
 *  - Only the public key is meant to be published to Firestore /publicKeys/.
 *  - The shared secret is used as root input to HKDF-SHA256 (see hkdf.ts).
 *
 * All keys and ciphertexts are returned as Base64 strings for
 * JSON-serialisable transport and Firestore storage.
 */

import { createMLKEM768 } from "@openforge-sh/liboqs";

// ── Types ──────────────────────────────────────────────────────────────────

/** A ML-KEM-768 key pair. The private key must never be sent over the network. */
export interface KemKeyPair {
  /** Base64-encoded ML-KEM-768 public key — safe to publish to Firestore. */
  publicKey: string;
  /** Base64-encoded ML-KEM-768 private key — MUST stay in browser memory only. */
  privateKey: string;
}

/** Result of a KEM encapsulation operation. */
export interface KemEncapResult {
  /** Base64-encoded shared secret — input to HKDF-SHA256. Never stored. */
  sharedSecret: string;
  /** Base64-encoded KEM ciphertext — stored in message doc alongside the message. */
  ciphertext: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Encode a Uint8Array to a Base64 string. */
export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCodePoint(...bytes));
}

/** Decode a Base64 string to a Uint8Array. */
export function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

// ── Core KEM operations ────────────────────────────────────────────────────

/**
 * Generate a fresh ML-KEM-768 key pair.
 * createMLKEM768() is async (WASM init), then operations are synchronous.
 *
 * @returns KemKeyPair with Base64-encoded public and private keys.
 */
export async function kemGenerateKeyPair(): Promise<KemKeyPair> {
  const kem = await createMLKEM768();
  try {
    const { publicKey, secretKey } = kem.generateKeyPair();
    return {
      publicKey: toBase64(publicKey),
      privateKey: toBase64(secretKey),
    };
  } finally {
    kem.destroy();
  }
}

/**
 * Encapsulate a shared secret using a recipient's ML-KEM-768 public key.
 *
 * Called by the *sender* (Alice) before encrypting a message.
 * Performance KPI: < 5 ms (specs §2.2).
 *
 * @param recipientPublicKeyB64 - Base64-encoded recipient public key (from Firestore).
 * @returns sharedSecret (input to HKDF) + ciphertext (stored in message doc).
 */
export async function kemEncapsulate(
  recipientPublicKeyB64: string
): Promise<KemEncapResult> {
  const kem = await createMLKEM768();
  try {
    const publicKeyBytes = fromBase64(recipientPublicKeyB64);
    const { ciphertext, sharedSecret } = kem.encapsulate(publicKeyBytes);
    return {
      sharedSecret: toBase64(sharedSecret),
      ciphertext: toBase64(ciphertext),
    };
  } finally {
    kem.destroy();
  }
}

/**
 * Decapsulate a shared secret using the recipient's ML-KEM-768 private key.
 *
 * Called by the *recipient* (Bob) when receiving a message.
 * Performance KPI: < 5 ms (specs §2.2).
 *
 * @param ciphertextB64  - Base64-encoded KEM ciphertext from the message doc.
 * @param privateKeyB64  - Base64-encoded private key (in-memory only, never from Firebase).
 * @returns Base64-encoded shared secret — must match the sender's shared secret.
 */
export async function kemDecapsulate(
  ciphertextB64: string,
  privateKeyB64: string
): Promise<string> {
  const kem = await createMLKEM768();
  try {
    const ciphertextBytes = fromBase64(ciphertextB64);
    const privateKeyBytes = fromBase64(privateKeyB64);
    const sharedSecret = kem.decapsulate(ciphertextBytes, privateKeyBytes);
    return toBase64(sharedSecret);
  } finally {
    kem.destroy();
  }
}
