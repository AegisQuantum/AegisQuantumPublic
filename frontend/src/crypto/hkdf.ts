/**
 * hkdf.ts — HKDF-SHA256 (RFC 5869) via Web Crypto API
 *
 * Rôle dans le protocole :
 *  - Prend le shared secret brut de ML-KEM-768 (32 bytes) et en dérive
 *    une clé de message sécurisée (32 bytes) pour AES-256-GCM.
 *  - Utilisé aussi par le Double Ratchet pour faire avancer les chaînes
 *    de clés (root key → sending/receiving chain key → message key).
 *
 * Pourquoi HKDF sur le shared secret KEM ?
 *  Le shared secret KEM est un bon matériau aléatoire mais pas directement
 *  une clé cryptographique. HKDF l'étire et le lie à un contexte (info)
 *  pour produire des clés indépendantes et liées sémantiquement.
 *
 * Toutes les entrées/sorties sont en Base64 pour la cohérence du module crypto.
 */

import { toBase64, fromBase64 } from "./kem";

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de contexte (info strings)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Info strings utilisées dans AegisQuantum.
 * Chaque usage de HKDF doit avoir sa propre info pour que les clés dérivées
 * soient cryptographiquement indépendantes.
 */
export const HKDF_INFO = {
  /** Clé de message AES-256-GCM — sendMessage/receiveMessage */
  MESSAGE_KEY    : "AegisQuantum-v1-message-key",
  /** Root key → chain key dans le Double Ratchet */
  RATCHET_ROOT   : "AegisQuantum-v1-ratchet-root",
  /** Chain key → message key dans le Double Ratchet */
  RATCHET_CHAIN  : "AegisQuantum-v1-ratchet-chain",
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Core
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Dérive une clé de longueur `outputLength` bytes à partir d'un secret Base64
 * et d'un contexte (info string).
 *
 * Algorithme : HKDF-SHA256 (RFC 5869)
 *  - Extract : HMAC-SHA256(salt=0x00…, IKM=secret) → pseudorandom key (PRK)
 *  - Expand  : HMAC-SHA256(PRK, info || counter) → OKM tronqué à outputLength
 *
 * Appelé par :
 *  - messaging.ts     : hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY) → clé AES-GCM
 *  - double-ratchet.ts: hkdfDerive(rootKey, HKDF_INFO.RATCHET_ROOT) → nouvelle root key
 *  - double-ratchet.ts: hkdfDerive(chainKey, HKDF_INFO.RATCHET_CHAIN) → message key
 *
 * @param secretB64    — Base64 — matériau d'entrée (IKM) : shared secret KEM ou chain key
 * @param info         — string UTF-8 — contexte de dérivation (voir HKDF_INFO)
 * @param outputLength — longueur de la clé dérivée en bytes (défaut : 32 = 256 bits)
 * @returns Base64 — clé dérivée de `outputLength` bytes
 */
export async function hkdfDerive(
  secretB64: string,
  info: string,
  outputLength = 32
): Promise<string> {
  // Rejeter un secret vide — un IKM vide est cryptographiquement dangereux
  // (HMAC d'un message vide est déterministe et prédictible).
  if (!secretB64 || fromBase64(secretB64).length === 0) {
    throw new Error("hkdfDerive: secret must not be empty");
  }

  // Importer le secret comme matériau de clé brut (HKDF)
  const ikm = await crypto.subtle.importKey(
    "raw",
    fromBase64(secretB64).buffer as ArrayBuffer,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  // Dériver `outputLength * 8` bits via HKDF-SHA256.
  // On utilise deriveBits (pas deriveKey) pour éviter la restriction Web Crypto
  // qui limite deriveKey aux longueurs AES valides (128/192/256 bits uniquement).
  // Ainsi outputLength=64 (512 bits), outputLength=48, etc. fonctionnent.
  const rawBits = await crypto.subtle.deriveBits(
    {
      name : "HKDF",
      hash : "SHA-256",
      salt : new Uint8Array(32),   // sel nul — standard (RFC 5869 §3.1) quand l'IKM est déjà aléatoire
      info : new TextEncoder().encode(info),
    },
    ikm,
    outputLength * 8  // en bits
  );

  return toBase64(new Uint8Array(rawBits));
}

/**
 * Dérive deux clés simultanément depuis un même secret (split KDF).
 * Utilisé par le Double Ratchet pour dériver en une passe :
 *   rootKey → (newRootKey, newChainKey)
 *
 * @param secretB64 — Base64 — root key courante ou shared secret KEM
 * @returns { rootKey, chainKey } — deux clés Base64 de 32 bytes chacune
 */
export async function hkdfDerivePair(
  secretB64: string
): Promise<{ rootKey: string; chainKey: string }> {
  const rootKey  = await hkdfDerive(secretB64, HKDF_INFO.RATCHET_ROOT,  32);
  const chainKey = await hkdfDerive(secretB64, HKDF_INFO.RATCHET_CHAIN, 32);
  return { rootKey, chainKey };
}
