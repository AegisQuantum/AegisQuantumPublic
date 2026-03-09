/**
 * double-ratchet.ts — Double Ratchet Algorithm (à implémenter)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ARCHITECTURE PRÉVUE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Le Double Ratchet combine deux mécanismes :
 *
 *  1. KEM Ratchet (DH Ratchet adapté ML-KEM-768)
 *     - À chaque tour de parole, l'expéditeur encapsule avec la clé publique
 *       courante du contact → nouveau shared secret → HKDF fait avancer la root key.
 *     - Fournit la FORWARD SECRECY : compromettre les clés actuelles ne permet
 *       pas de déchiffrer les anciens messages.
 *
 *  2. Symmetric Ratchet (chain ratchet)
 *     - HKDF(chainKey) → (newChainKey, messageKey) à chaque message.
 *     - Fournit la BREAK-IN RECOVERY.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DÉPENDANCES DISPONIBLES (déjà implémentées)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  import { kemEncapsulate, kemDecapsulate, kemGenerateKeyPair } from "./kem";
 *    kemEncapsulate(recipientPublicKeyB64)   → { sharedSecret, ciphertext }
 *    kemDecapsulate(ciphertextB64, privKeyB64) → sharedSecret
 *    kemGenerateKeyPair()                    → { publicKey, privateKey }
 *
 *  import { hkdfDerive, hkdfDerivePair, HKDF_INFO } from "./hkdf";
 *    hkdfDerive(secretB64, info, length?)     → keyB64
 *    hkdfDerivePair(secretB64)                → { rootKey, chainKey }
 *    HKDF_INFO.MESSAGE_KEY                    — info string pour les clés de message
 *    HKDF_INFO.RATCHET_ROOT                   — info string pour le root key
 *    HKDF_INFO.RATCHET_CHAIN                  — info string pour les chain keys
 *
 *  import { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm";
 *    aesGcmEncrypt(plaintext, keyB64)         → { ciphertext, nonce }
 *    aesGcmDecrypt(ciphertextB64, nonceB64, keyB64) → plaintext
 *
 *  import { serializeRatchetState, deserializeRatchetState } from "./ratchet-state";
 *    serializeRatchetState(state)             → JSON string (pour IndexedDB)
 *    deserializeRatchetState(json)            → RatchetState
 *
 *  import type { RatchetState } from "../types/ratchet";
 *    Champs : conversationId, rootKey, sendingChainKey, receivingChainKey,
 *             ourPrivateKey, ourPublicKey, theirPublicKey,
 *             sendCount, receiveCount, updatedAt
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * INTERFACES PUBLIQUES (à respecter — utilisées par messaging.ts)
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ── Types exportés — NE PAS MODIFIER ──────────────────────────────────────────

/** Résultat de doubleRatchetEncrypt — tout ce qui va dans Firestore + state mis à jour. */
export interface DoubleRatchetEncryptResult {
  ciphertext   : string;  // Base64 — AES-256-GCM encrypted message
  nonce        : string;  // Base64 — AES-GCM IV (12 bytes)
  kemCiphertext: string;  // Base64 — ML-KEM-768 ciphertext (pour le ratchet côté réception)
  messageIndex : number;  // numéro de message dans la chaîne courante (anti-replay)
  newStateJson : string;  // RatchetState sérialisé → à passer à key-store.ts
}

/** Résultat de doubleRatchetDecrypt. */
export interface DoubleRatchetDecryptResult {
  plaintext   : string;  // texte clair déchiffré
  newStateJson: string;  // RatchetState mis à jour → à passer à key-store.ts
}

// ── Stubs à implémenter ────────────────────────────────────────────────────────

/**
 * Chiffre un message avec le Double Ratchet.
 *
 * Appelé par messaging.ts → sendMessage().
 *
 * Si stateJson === null : première utilisation → initialiser un nouvel état.
 *
 * @param plaintext      — texte clair UTF-8
 * @param stateJson      — RatchetState sérialisé (null = premier message)
 * @param conversationId — ID Firestore de la conversation
 * @param ourPrivKey     — Base64 — ML-KEM-768 private key (key-store.ts → getKemPrivateKey)
 * @param ourPubKey      — Base64 — ML-KEM-768 public key (key-registry.ts)
 * @param theirPubKey    — Base64 — ML-KEM-768 public key du contact (key-registry.ts)
 * @param sharedSecret   — Base64 — shared secret du KEM initial (kemEncapsulate)
 */
export async function doubleRatchetEncrypt(
  _plaintext    : string,
  _stateJson    : string | null,
  _conversationId: string,
  _ourPrivKey   : string,
  _ourPubKey    : string,
  _theirPubKey  : string,
  _sharedSecret : string
): Promise<DoubleRatchetEncryptResult> {
  throw new Error("TODO: implémenter doubleRatchetEncrypt()");
}

/**
 * Déchiffre un message avec le Double Ratchet.
 *
 * Appelé par messaging.ts → decryptMessage().
 *
 * @param ciphertext     — Base64 — message chiffré AES-256-GCM (depuis Firestore)
 * @param nonce          — Base64 — IV AES-GCM (depuis Firestore)
 * @param messageIndex   — numéro de message (depuis Firestore) — vérifier anti-replay
 * @param kemCiphertext  — Base64 — ML-KEM-768 CT pour reconstruire le shared secret
 * @param stateJson      — RatchetState sérialisé (null = premier message)
 * @param conversationId — ID Firestore de la conversation
 * @param ourPrivKey     — Base64 — ML-KEM-768 private key (key-store.ts)
 * @param ourPubKey      — Base64 — ML-KEM-768 public key
 * @param theirPubKey    — Base64 — ML-KEM-768 public key du sender (key-registry.ts)
 * @param sharedSecret   — Base64 — shared secret KEM reconstruit via kemDecapsulate
 */
export async function doubleRatchetDecrypt(
  _ciphertext    : string,
  _nonce         : string,
  _messageIndex  : number,
  _kemCiphertext : string,
  _stateJson     : string | null,
  _conversationId: string,
  _ourPrivKey    : string,
  _ourPubKey     : string,
  _theirPubKey   : string,
  _sharedSecret  : string
): Promise<DoubleRatchetDecryptResult> {
  throw new Error("TODO: implémenter doubleRatchetDecrypt()");
}
