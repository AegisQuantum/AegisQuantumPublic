/**
 * dsa.ts — ML-DSA-65 (FIPS 204 / Dilithium) Digital Signature Algorithm
 *
 * Wraps @openforge-sh/liboqs createMLDSA65 pour AegisQuantum.
 *
 * Rôle dans le protocole (specs §4.2) :
 *  - L'expéditeur SIGNE (ciphertext + nonce + kemCiphertext) avec sa clé privée DSA.
 *  - Le destinataire VÉRIFIE la signature avec la clé publique DSA de l'expéditeur
 *    (publiée dans Firestore /publicKeys/{uid}).
 *  - Garantit l'authenticité et l'intégrité du message.
 *  - Protège contre les attaques de substitution et les messages forgés.
 *
 * Tailles FIPS 204 (ML-DSA-65) :
 *  - Clé publique  : 1952 bytes → ~2602 chars Base64
 *  - Clé privée    : 4032 bytes → ~5376 chars Base64
 *  - Signature     : 3309 bytes → ~4412 chars Base64
 *
 * Toutes les clés et signatures sont encodées en Base64 pour
 * la sérialisation JSON et le stockage Firestore.
 */

import { createMLDSA65 } from "@openforge-sh/liboqs";
import { toBase64, fromBase64 } from "./kem";

// ── Types ──────────────────────────────────────────────────────────────────

/** Paire de clés ML-DSA-65. La clé privée ne doit jamais quitter la mémoire. */
export interface DsaKeyPair {
  /** Base64 — ML-DSA-65 public key (1952 bytes). Safe to publish to Firestore. */
  publicKey: string;
  /** Base64 — ML-DSA-65 private key (4032 bytes). MUST stay in browser memory only. */
  privateKey: string;
}

// ── Core DSA operations ────────────────────────────────────────────────────

/**
 * Génère une paire de clés ML-DSA-65 fraîche.
 *
 * createMLDSA65() est async (init WASM), puis les opérations sont synchrones.
 *
 * Appelé par auth.ts → register() lors de l'inscription.
 *
 * @returns DsaKeyPair avec clés encodées en Base64.
 */
export async function dsaGenerateKeyPair(): Promise<DsaKeyPair> {
  const dsa = await createMLDSA65();
  try {
    const { publicKey, secretKey } = dsa.generateKeyPair();
    return {
      publicKey : toBase64(publicKey),
      privateKey: toBase64(secretKey),
    };
  } finally {
    dsa.destroy();
  }
}

/**
 * Signe un message avec la clé privée ML-DSA-65 de l'expéditeur.
 *
 * Appelé par messaging.ts → sendMessage() avant l'écriture dans Firestore.
 * Le message signé est : ciphertext + nonce + kemCiphertext (concaténation de strings Base64).
 *
 * Performance KPI : < 10 ms (specs §2.2).
 *
 * @param message        — string à signer (UTF-8 ou Base64 concaténé)
 * @param privateKeyB64  — Base64 — ML-DSA-65 private key (vient de getDsaPrivateKey() dans key-store.ts)
 * @returns Base64 — signature ML-DSA-65 (~3309 bytes)
 */
export async function dsaSign(message: string, privateKeyB64: string): Promise<string> {
  const dsa = await createMLDSA65();
  try {
    const msgBytes = new TextEncoder().encode(message);
    const keyBytes = fromBase64(privateKeyB64);
    const signature = dsa.sign(msgBytes, keyBytes);
    return toBase64(signature);
  } finally {
    dsa.destroy();
  }
}

/**
 * Vérifie une signature ML-DSA-65.
 *
 * Appelé par messaging.ts → decryptMessage() lors de la réception d'un message.
 * Valide que le message n'a pas été altéré et vient bien de l'expéditeur déclaré.
 *
 * Performance KPI : < 5 ms (specs §2.2).
 *
 * @param message         — string originale qui a été signée
 * @param signatureB64    — Base64 — signature ML-DSA-65 (vient du document Firestore)
 * @param publicKeyB64    — Base64 — ML-DSA-65 public key de l'expéditeur
 *                          (vient de getPublicKeys() dans key-registry.ts)
 * @returns true si la signature est valide, false sinon
 */
export async function dsaVerify(
  message: string,
  signatureB64: string,
  publicKeyB64: string
): Promise<boolean> {
  const dsa = await createMLDSA65();
  try {
    const msgBytes = new TextEncoder().encode(message);
    const sigBytes = fromBase64(signatureB64);
    const keyBytes = fromBase64(publicKeyB64);
    return dsa.verify(msgBytes, sigBytes, keyBytes);
  } catch {
    // Signature ou clé malformée → considéré invalide
    return false;
  } finally {
    dsa.destroy();
  }
}
