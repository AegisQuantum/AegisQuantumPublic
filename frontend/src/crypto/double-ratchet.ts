/**
 * double-ratchet.ts — Double Ratchet Algorithm
 *
 * Implémente le Double Ratchet de Signal pour le chiffrement de bout en bout
 * des messages après l'établissement de la session via ML-KEM-768.
 *
 * Appelé par :
 *  - messaging.ts → sendMessage()    → doubleRatchetEncrypt()
 *  - messaging.ts → decryptMessage() → doubleRatchetDecrypt()
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * BOOTSTRAP (premier message, stateJson === null)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Envoyeur (Alice) :
 *   1. kemEncapsulate(bobPubKey) → { initSecret, initKemCT }
 *   2. hkdfDerivePair(initSecret) → { rootKey, sendingChainKey }
 *   3. KEM ratchet step + symmetric ratchet → messageKey
 *   4. AES-256-GCM encrypt(plaintext, messageKey)
 *   5. Stocke initKemCT dans Firestore (champ initKemCiphertext, 1er message only)
 *
 *  Receiver (Bob) :
 *   1. kemDecapsulate(initKemCT, bobPrivKey) → initSecret  ← même secret qu'Alice
 *   2. hkdfDerivePair(initSecret) → { rootKey, receivingChainKey }
 *   3. KEM ratchet step (reçoit kemCiphertext du message) + symmetric ratchet → messageKey
 *   4. AES-256-GCM decrypt(ciphertext, nonce, messageKey)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * MESSAGES SUIVANTS (stateJson !== null)
 * ─────────────────────────────────────────────────────────────────────────────
 *  État restauré depuis IDB → KEM ratchet step + symmetric ratchet → messageKey
 */

import { kemEncapsulate, kemDecapsulate, kemGenerateKeyPair, toBase64, fromBase64 } from "./kem";
import { hkdfDerivePair } from "./hkdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm";
import { serializeRatchetState, deserializeRatchetState } from "./ratchet-state";
import type { RatchetState } from "../types/ratchet";

// ─────────────────────────────────────────────────────────────────────────────
// Types exportés
// ─────────────────────────────────────────────────────────────────────────────

export interface DoubleRatchetEncryptResult {
  /** Base64 — ciphertext AES-256-GCM du message */
  ciphertext        : string;
  /** Base64 — nonce AES-GCM (12 bytes, frais par message) */
  nonce             : string;
  /** Base64 — ML-KEM-768 ciphertext du ratchet step courant */
  kemCiphertext     : string;
  /** Index du message dans la chaîne courante — anti-replay côté réception */
  messageIndex      : number;
  /** RatchetState sérialisé → passer à saveRatchetState() dans key-store.ts */
  newStateJson      : string;
  /**
   * Base64 — KEM ciphertext d'initialisation de session.
   * Présent UNIQUEMENT sur le premier message (stateJson === null).
   * Stocké dans Firestore (champ initKemCiphertext).
   * Le receiver le décapsule pour bootstrapper le même initSecret.
   */
  initKemCiphertext?: string;
}

export interface DoubleRatchetDecryptResult {
  /** Texte clair déchiffré */
  plaintext   : string;
  /** RatchetState mis à jour → passer à saveRatchetState() dans key-store.ts */
  newStateJson: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetEncrypt
// ─────────────────────────────────────────────────────────────────────────────

export async function doubleRatchetEncrypt(
  plaintext     : string,
  stateJson     : string | null,
  conversationId: string,
  ourPrivKey    : string,
  ourPubKey     : string,
  theirPubKey   : string,
): Promise<DoubleRatchetEncryptResult> {

  let state: RatchetState;
  let initKemCiphertext: string | undefined;

  if (stateJson === null) {
    // ── Bootstrap : premier message ──────────────────────────────────────────
    // On génère l'init KEM en interne. L'envoyeur encapsule avec la clé publique
    // du contact → initSecret + initKemCT. Le receiver décapsulera initKemCT avec
    // sa clé privée pour retrouver le même initSecret. Symétrie garantie.
    const { sharedSecret: initSecret, ciphertext: initKemCT } =
      await kemEncapsulate(theirPubKey);
    initKemCiphertext = initKemCT;

    const { rootKey, chainKey: sendingChainKey } = await hkdfDerivePair(initSecret);

    state = {
      conversationId,
      rootKey,
      sendingChainKey,
      receivingChainKey : "",
      ourPrivateKey     : ourPrivKey,
      ourPublicKey      : ourPubKey,
      theirPublicKey    : theirPubKey,
      sendCount         : 0,
      receiveCount      : 0,
      updatedAt         : Date.now(),
    };
  } else {
    state = deserializeRatchetState(stateJson);
  }

  // ── KEM ratchet step (forward secrecy) ───────────────────────────────────
  const {
    newRootKey,
    newSendingChainKey : chainKeyAfterKem,
    kemCiphertext,
    newOurPrivKey,
    newOurPubKey,
  } = await kemRatchetStepSend(state.rootKey, state.theirPublicKey);

  state.rootKey       = newRootKey;
  state.ourPrivateKey = newOurPrivKey;
  state.ourPublicKey  = newOurPubKey;

  // ── Symmetric ratchet step → messageKey ──────────────────────────────────
  const { nextChainKey, messageKey } = await symmetricRatchetStep(chainKeyAfterKem);

  state.sendingChainKey = nextChainKey;
  const messageIndex    = state.sendCount;
  state.sendCount++;

  // ── AES-256-GCM ───────────────────────────────────────────────────────────
  const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);

  state.updatedAt = Date.now();
  const newStateJson = serializeRatchetState(state);

  return { ciphertext, nonce, kemCiphertext, messageIndex, newStateJson, initKemCiphertext };
}

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetDecrypt
// ─────────────────────────────────────────────────────────────────────────────

export async function doubleRatchetDecrypt(
  ciphertext        : string,
  nonce             : string,
  messageIndex      : number,
  kemCiphertext     : string,
  stateJson         : string | null,
  conversationId    : string,
  ourPrivKey        : string,
  ourPubKey         : string,
  theirPubKey       : string,
  initKemCiphertext?: string,  // présent uniquement sur le 1er message (stateJson === null)
): Promise<DoubleRatchetDecryptResult> {

  let state: RatchetState;

  if (stateJson === null) {
    // ── Bootstrap : premier message reçu ─────────────────────────────────────
    // Décapsule initKemCiphertext pour retrouver le même initSecret que l'envoyeur.
    if (!initKemCiphertext) {
      throw new Error(
        "doubleRatchetDecrypt: stateJson est null (1er message) mais initKemCiphertext est absent. " +
        "Vérifiez que le champ initKemCiphertext est bien stocké dans Firestore pour le premier message."
      );
    }
    const initSecret = await kemDecapsulate(initKemCiphertext, ourPrivKey);
    const { rootKey, chainKey: receivingChainKey } = await hkdfDerivePair(initSecret);

    state = {
      conversationId,
      rootKey,
      sendingChainKey  : "",
      receivingChainKey,
      ourPrivateKey    : ourPrivKey,
      ourPublicKey     : ourPubKey,
      theirPublicKey   : theirPubKey,
      sendCount        : 0,
      receiveCount     : 0,
      updatedAt        : Date.now(),
    };
  } else {
    state = deserializeRatchetState(stateJson);
  }

  // ── KEM ratchet step — réception ─────────────────────────────────────────
  // Décapsule le kemCiphertext du message pour avancer rootKey + receivingChainKey.
  const { newRootKey, newReceivingChainKey: chainKeyAfterKem } =
    await kemRatchetStepReceive(state.rootKey, kemCiphertext, state.ourPrivateKey);

  state.rootKey        = newRootKey;
  state.theirPublicKey = theirPubKey;

  // ── Symmetric ratchet — avancer jusqu'à messageIndex ─────────────────────
  if (messageIndex < state.receiveCount) {
    throw new Error(
      `doubleRatchetDecrypt: replay détecté — ` +
      `messageIndex=${messageIndex} déjà consommé (receiveCount=${state.receiveCount})`
    );
  }

  const MAX_SKIPPED = 1_000;
  const steps = messageIndex - state.receiveCount + 1;

  if (steps > MAX_SKIPPED) {
    throw new Error(
      `doubleRatchetDecrypt: messageIndex trop élevé — ` +
      `${steps} steps requis, max autorisé : ${MAX_SKIPPED}`
    );
  }

  let chainKey   = chainKeyAfterKem;
  let messageKey = "";

  for (let i = 0; i < steps; i++) {
    const { nextChainKey, messageKey: mk } = await symmetricRatchetStep(chainKey);
    chainKey   = nextChainKey;
    messageKey = mk;
  }

  state.receivingChainKey = chainKey;
  state.receiveCount      = messageIndex + 1;

  // ── AES-256-GCM decrypt ───────────────────────────────────────────────────
  const plaintext = await aesGcmDecrypt(ciphertext, nonce, messageKey);

  state.updatedAt = Date.now();
  const newStateJson = serializeRatchetState(state);

  return { plaintext, newStateJson };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers privés
// ─────────────────────────────────────────────────────────────────────────────

/** Concatène deux secrets Base64 au niveau bytes → Base64. */
function concatSecrets(a: string, b: string): string {
  const bytesA = fromBase64(a);
  const bytesB = fromBase64(b);
  const combined = new Uint8Array(bytesA.length + bytesB.length);
  combined.set(bytesA, 0);
  combined.set(bytesB, bytesA.length);
  return toBase64(combined);
}

/**
 * KEM ratchet step — envoi.
 * 1. Génère une nouvelle keypair KEM éphémère
 * 2. kemEncapsulate(theirPubKey) → { kemSecret, kemCiphertext }
 * 3. IKM = rootKey || kemSecret
 * 4. hkdfDerivePair(IKM) → { newRootKey, newSendingChainKey }
 */
async function kemRatchetStepSend(
  currentRootKey: string,
  theirPubKey   : string,
): Promise<{
  newRootKey        : string;
  newSendingChainKey: string;
  kemCiphertext     : string;
  newOurPrivKey     : string;
  newOurPubKey      : string;
}> {
  const { publicKey: newOurPubKey, privateKey: newOurPrivKey } =
    await kemGenerateKeyPair();

  const { sharedSecret: kemSecret, ciphertext: kemCiphertext } =
    await kemEncapsulate(theirPubKey);

  const ikm = concatSecrets(currentRootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newSendingChainKey } =
    await hkdfDerivePair(ikm);

  return { newRootKey, newSendingChainKey, kemCiphertext, newOurPrivKey, newOurPubKey };
}

/**
 * KEM ratchet step — réception.
 * 1. kemDecapsulate(kemCiphertext, ourPrivKey) → kemSecret
 * 2. IKM = rootKey || kemSecret
 * 3. hkdfDerivePair(IKM) → { newRootKey, newReceivingChainKey }
 */
async function kemRatchetStepReceive(
  currentRootKey: string,
  kemCiphertext : string,
  ourPrivKey    : string,
): Promise<{
  newRootKey           : string;
  newReceivingChainKey : string;
}> {
  const kemSecret = await kemDecapsulate(kemCiphertext, ourPrivKey);
  const ikm = concatSecrets(currentRootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newReceivingChainKey } =
    await hkdfDerivePair(ikm);
  return { newRootKey, newReceivingChainKey };
}

/**
 * Symmetric ratchet step — avance la chaîne d'un cran.
 * hkdfDerivePair(chainKey) → { nextChainKey, messageKey }
 */
async function symmetricRatchetStep(chainKey: string): Promise<{
  nextChainKey: string;
  messageKey  : string;
}> {
  const { rootKey: nextChainKey, chainKey: messageKey } = await hkdfDerivePair(chainKey);
  return { nextChainKey, messageKey };
}
