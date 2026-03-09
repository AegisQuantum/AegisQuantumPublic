/**
 * aes-gcm.ts — AES-256-GCM (AEAD) via Web Crypto API
 *
 * Rôle dans le protocole :
 *  - Chiffre le texte clair du message avec une clé dérivée via HKDF.
 *  - Le tag GCM (128 bits) garantit l'intégrité et l'authenticité du chiffré.
 *  - Un nonce aléatoire de 12 bytes est généré pour chaque message.
 *
 * Sécurité :
 *  - AES-256-GCM est un AEAD (Authenticated Encryption with Associated Data).
 *  - La clé vient toujours de hkdfDerive() — jamais générée directement.
 *  - Un nonce ne doit JAMAIS être réutilisé avec la même clé → on génère
 *    un nonce aléatoire frais par message (12 bytes via crypto.getRandomValues).
 *  - Le tag GCM est vérifié automatiquement par SubtleCrypto.decrypt() —
 *    si invalide, il lève une erreur (DOMException: OperationError).
 */

import { toBase64, fromBase64 } from "./kem";

// ─────────────────────────────────────────────────────────────────────────────
// Core
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Chiffre une string UTF-8 avec AES-256-GCM.
 *
 * Appelé par :
 *  - messaging.ts    : chiffrement du message plaintext
 *  - key-store.ts    : chiffrement du vault de clés privées dans IndexedDB
 *  - double-ratchet.ts : chiffrement interne des étapes de ratchet
 *
 * @param plaintext — string UTF-8 à chiffrer
 * @param keyB64    — Base64 (32 bytes) — clé AES-256 dérivée via hkdfDerive()
 * @returns { ciphertext, nonce }
 *   - ciphertext : Base64 — AES-256-GCM encrypted + 16 bytes tag GCM appendé
 *   - nonce      : Base64 — IV aléatoire 12 bytes (à stocker avec le message)
 */
export async function aesGcmEncrypt(
  plaintext: string,
  keyB64: string
): Promise<{ ciphertext: string; nonce: string }> {
  // Valider la longueur de la clé — AES-256-GCM exige exactement 32 bytes.
  // Web Crypto accepte 16/24/32 bytes (AES-128/192/256), mais on impose 256 bits.
  const keyBytes = fromBase64(keyB64);
  if (keyBytes.length !== 32) {
    throw new Error(
      `aesGcmEncrypt: invalid key length ${keyBytes.length} bytes — expected 32 bytes (256 bits)`
    );
  }

  // Importer la clé AES-GCM
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes.buffer as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  // Générer un nonce aléatoire frais (12 bytes = 96 bits, recommandé pour GCM)
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Chiffrer
  const plaintextBytes  = new TextEncoder().encode(plaintext);
  const ciphertextBytes = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 },
    key,
    plaintextBytes
  );

  return {
    ciphertext: toBase64(new Uint8Array(ciphertextBytes)),
    nonce     : toBase64(nonce),
  };
}

/**
 * Déchiffre un ciphertext AES-256-GCM.
 *
 * Appelé par :
 *  - messaging.ts  : déchiffrement du message reçu
 *  - key-store.ts  : déchiffrement du vault depuis IndexedDB
 *
 * @param ciphertextB64 — Base64 — ciphertext + tag GCM (vient de Firestore ou IndexedDB)
 * @param nonceB64      — Base64 — IV 12 bytes (stocké avec le message)
 * @param keyB64        — Base64 (32 bytes) — clé AES-256 dérivée via hkdfDerive()
 * @returns string UTF-8 — plaintext déchiffré
 * @throws DOMException(OperationError) si la clé ou le tag GCM est invalide
 */
export async function aesGcmDecrypt(
  ciphertextB64: string,
  nonceB64: string,
  keyB64: string
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    fromBase64(keyB64).buffer as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const plaintextBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(nonceB64).buffer as ArrayBuffer, tagLength: 128 },
    key,
    fromBase64(ciphertextB64).buffer as ArrayBuffer
  );

  return new TextDecoder().decode(plaintextBytes);
}
