/**
 * double-ratchet.ts — Double Ratchet Algorithm (ML-KEM-768 variant)
 *
 * Implements the Signal Double Ratchet with ML-KEM-768 replacing Diffie-Hellman.
 * Called by:
 *  - messaging.ts → sendMessage()    → doubleRatchetEncrypt()
 *  - messaging.ts → decryptMessage() → doubleRatchetDecrypt()
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * KEY INSIGHT — why KEM ratchets differ from DH ratchets
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * In Signal's DH ratchet, both sides passively derive the same secret because
 * DH is commutative: DH(a, B) = DH(b, A). With ML-KEM, encapsulation is
 * one-directional: only the holder of the private key matching the public key
 * used during encapsulation can recover the shared secret.
 *
 * The solution (following Signal's PQXDH / SPQR approach):
 *  - The SENDER encapsulates to the RECEIVER's current ephemeral public key.
 *  - The sender also generates a FRESH ephemeral keypair and sends the public
 *    part alongside the message (senderEphPub). This becomes the target for
 *    the receiver's next encapsulation when they reply.
 *  - This gives both forward secrecy (old keys discarded) and break-in recovery
 *    (new ephemeral key each message).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SKIPPED KEYS — messages received out of order
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Because ML-KEM is one-directional, each message carries its own kemCiphertext
 * encapsulated to state.ourPublicKey at the time of sending. If message N+1
 * arrives before N, we must KEM-decapsulate N+1 NOW (while we still hold the
 * matching ourPrivateKey), derive and cache its messageKey, then wait for N.
 *
 * Fix (Signal spec §2.6 adapted for KEM):
 *  - In _advanceReceivingChain(), for every skipped index i < messageIndex,
 *    store the derived messageKey in state.skippedMessageKeys[i].
 *  - In doubleRatchetDecrypt(), check skippedMessageKeys[messageIndex] first.
 *    If found → use cached key, skip KEM ratchet step entirely.
 *    If not   → normal KEM ratchet step (message arrived in order).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * BOOTSTRAP (stateJson === null — first message ever in this conversation)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Sender (Alice):
 *   1. kemEncapsulate(bobLongTermPub) → { initSecret, initKemCT }
 *      hkdfDerivePair(initSecret) → { rootKey, sendingChainKey }
 *   2. kemGenerateKeyPair() → { aliceEphPriv, aliceEphPub }
 *      aliceEphPub stored in Firestore as senderEphPub — Bob will encapsulate
 *      to it when he replies.
 *   3. symmetricRatchetStep(sendingChainKey) → messageKey
 *      [NO KEM ratchet step on bootstrap — root chain already set from initSecret]
 *   4. AES-256-GCM encrypt(plaintext, messageKey)
 *   Firestore: initKemCiphertext ✓  senderEphPub ✓  kemCiphertext = ""
 *
 *  Receiver (Bob):
 *   1. kemDecapsulate(initKemCT, bobLongTermPriv) → initSecret        ← same ✓
 *      hkdfDerivePair(initSecret) → { rootKey, receivingChainKey }    ← same ✓
 *   2. state.theirPublicKey = aliceEphPub  (for next encapsulation)
 *   3. symmetricRatchetStep(receivingChainKey) → messageKey           ← same ✓
 *   4. AES-256-GCM decrypt
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SUBSEQUENT MESSAGES — sender side (stateJson !== null)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Sender (Alice, message N > 0):
 *   1. kemEncapsulate(state.theirPublicKey) → { kemSecret, kemCT }
 *      IKM = rootKey ‖ kemSecret
 *      hkdfDerivePair(IKM) → { newRootKey, newSendingChainKey }
 *   2. kemGenerateKeyPair() → { newEphPriv, newEphPub }
 *      state.ourPrivateKey = newEphPriv  (for next receive step)
 *      senderEphPub = newEphPub          (stored in Firestore)
 *   3. symmetricRatchetStep(newSendingChainKey) → messageKey
 *   4. AES-256-GCM encrypt
 *   Firestore: kemCiphertext ✓  senderEphPub ✓
 *
 *  Receiver (Bob, message N > 0):
 *   1. kemDecapsulate(kemCT, state.ourPrivateKey) → kemSecret          ← same ✓
 *      IKM = rootKey ‖ kemSecret → same newRootKey                     ← same ✓
 *      hkdfDerivePair(IKM) → { newRootKey, newReceivingChainKey }
 *   2. state.theirPublicKey = senderEphPub
 *   3. symmetricRatchetStep → same messageKey                          ← same ✓
 *   4. AES-256-GCM decrypt
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * FILE SECRET (fix for issue #5)
 * ─────────────────────────────────────────────────────────────────────────────
 *  fileSecret is derived from messageKey (a true per-message secret) via HKDF,
 *  NOT from kemCiphertext (which is public data in Firestore).
 *  messaging.ts uses fileSecret to AES-encrypt/decrypt file attachments.
 *  It is returned in both DoubleRatchetEncryptResult and DoubleRatchetDecryptResult.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * FIRESTORE MESSAGE DOCUMENT — required fields
 * ─────────────────────────────────────────────────────────────────────────────
 *  Always present  : ciphertext, nonce, kemCiphertext ("" on bootstrap),
 *                    senderEphPub, messageIndex, signature
 *  Bootstrap only  : initKemCiphertext
 */

import { kemEncapsulate, kemDecapsulate, kemGenerateKeyPair, toBase64, fromBase64 } from "./kem";
import { hkdfDerive, hkdfDerivePair, HKDF_INFO } from "./hkdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm";
import { serializeRatchetState, deserializeRatchetState } from "./ratchet-state";
import type { RatchetState } from "../types/ratchet";

// ─────────────────────────────────────────────────────────────────────────────
// Exported types
// ─────────────────────────────────────────────────────────────────────────────

export interface DoubleRatchetEncryptResult {
  ciphertext        : string;
  nonce             : string;
  kemCiphertext     : string;
  senderEphPub      : string;
  messageIndex      : number;
  newStateJson      : string;
  initKemCiphertext?: string;
  fileSecret        : string;
}

export interface DoubleRatchetDecryptResult {
  plaintext   : string;
  newStateJson: string;
  fileSecret  : string;
}

// Maximum skipped keys stored — protection contre les DoS / fuites mémoire
const MAX_SKIPPED_STORED = 1_000;

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetEncrypt
// ─────────────────────────────────────────────────────────────────────────────

export async function doubleRatchetEncrypt(
  plaintext     : string,
  stateJson     : string | null,
  conversationId: string,
  _ourPrivKey   : string,
  _ourPubKey    : string,
  theirPubKey   : string,
): Promise<DoubleRatchetEncryptResult> {

  // ── Bootstrap : first message ─────────────────────────────────────────────
  if (stateJson === null) {
    const { sharedSecret: initSecret, ciphertext: initKemCiphertext } =
      await kemEncapsulate(theirPubKey);

    const { rootKey, chainKey: sendingChainKey } = await hkdfDerivePair(initSecret);

    const { publicKey: ourEphPub, privateKey: ourEphPriv } = await kemGenerateKeyPair();

    const state: RatchetState = {
      conversationId,
      rootKey,
      sendingChainKey,
      receivingChainKey  : "",
      ourPrivateKey      : ourEphPriv,
      ourPublicKey       : ourEphPub,
      theirPublicKey     : theirPubKey,
      sendCount          : 0,
      receiveCount       : 0,
      updatedAt          : Date.now(),
      skippedMessageKeys : {},   // ← nouveau champ
    };

    const { nextChainKey, messageKey } = await symmetricRatchetStep(state.sendingChainKey);
    state.sendingChainKey = nextChainKey;
    const messageIndex    = state.sendCount++;

    const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);
    const fileSecret = await hkdfDerive(messageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

    state.updatedAt = Date.now();

    return {
      ciphertext,
      nonce,
      kemCiphertext    : "",
      senderEphPub     : ourEphPub,
      messageIndex,
      newStateJson     : serializeRatchetState(state),
      initKemCiphertext,
      fileSecret,
    };
  }

  // ── Subsequent messages ───────────────────────────────────────────────────
  const state = deserializeRatchetState(stateJson);

  // Ensure skippedMessageKeys exists on states serialized before this fix
  if (!state.skippedMessageKeys) state.skippedMessageKeys = {};

  const { sharedSecret: kemSecret, ciphertext: kemCiphertext } =
    await kemEncapsulate(state.theirPublicKey);

  const ikm = concatSecrets(state.rootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newSendingChainKey } = await hkdfDerivePair(ikm);
  state.rootKey = newRootKey;

  const { publicKey: newEphPub, privateKey: newEphPriv } = await kemGenerateKeyPair();
  state.ourPrivateKey = newEphPriv;
  state.ourPublicKey  = newEphPub;

  const { nextChainKey, messageKey } = await symmetricRatchetStep(newSendingChainKey);
  state.sendingChainKey = nextChainKey;
  const messageIndex    = state.sendCount++;

  const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);
  const fileSecret = await hkdfDerive(messageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

  state.updatedAt = Date.now();

  return {
    ciphertext,
    nonce,
    kemCiphertext,
    senderEphPub : newEphPub,
    messageIndex,
    newStateJson : serializeRatchetState(state),
    fileSecret,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetDecrypt
// ─────────────────────────────────────────────────────────────────────────────

export async function doubleRatchetDecrypt(
  ciphertext        : string,
  nonce             : string,
  messageIndex      : number,
  kemCiphertext     : string,
  senderEphPub      : string,
  stateJson         : string | null,
  conversationId    : string,
  ourPrivKey        : string,
  ourPubKey         : string,
  _theirLongTermPub : string,
  initKemCiphertext?: string,
): Promise<DoubleRatchetDecryptResult> {

  // ── Bootstrap : first message received ───────────────────────────────────
  if (stateJson === null) {
    if (!initKemCiphertext) {
      throw new Error(
        "doubleRatchetDecrypt: first message (stateJson=null) but initKemCiphertext is missing. " +
        "Ensure initKemCiphertext is stored in Firestore on the first message."
      );
    }

    const initSecret = await kemDecapsulate(initKemCiphertext, ourPrivKey);
    const { rootKey, chainKey: receivingChainKey } = await hkdfDerivePair(initSecret);

    const state: RatchetState = {
      conversationId,
      rootKey,
      sendingChainKey    : "",
      receivingChainKey,
      ourPrivateKey      : ourPrivKey,
      ourPublicKey       : ourPubKey,
      theirPublicKey     : senderEphPub,
      sendCount          : 0,
      receiveCount       : 0,
      updatedAt          : Date.now(),
      skippedMessageKeys : {},   // ← nouveau champ
    };

    const { messageKey } = await _advanceReceivingChain(state, messageIndex);

    const plaintext  = await aesGcmDecrypt(ciphertext, nonce, messageKey);
    const fileSecret = await hkdfDerive(messageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

    state.updatedAt = Date.now();
    return { plaintext, newStateJson: serializeRatchetState(state), fileSecret };
  }

  // ── Subsequent messages ───────────────────────────────────────────────────
  const state = deserializeRatchetState(stateJson);

  // Ensure skippedMessageKeys exists on states serialized before this fix
  if (!state.skippedMessageKeys) state.skippedMessageKeys = {};

  // ── Skipped key path : message arrived out of order ──────────────────────
  //
  // If messageIndex is in the skippedMessageKeys buffer, we already derived
  // this messageKey when a later message arrived first. Use the cached key
  // directly — do NOT perform another KEM ratchet step (state.ourPrivateKey
  // has already advanced past this message).
  const cachedMessageKey = state.skippedMessageKeys[String(messageIndex)];

  if (cachedMessageKey !== undefined) {
    // Consume and purge the cached key
    delete state.skippedMessageKeys[String(messageIndex)];

    const plaintext  = await aesGcmDecrypt(ciphertext, nonce, cachedMessageKey);
    const fileSecret = await hkdfDerive(cachedMessageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

    state.updatedAt = Date.now();
    return { plaintext, newStateJson: serializeRatchetState(state), fileSecret };
  }

  // ── Normal path : message arrived in order ────────────────────────────────
  //
  // Perform KEM ratchet step: decapsulate with our current ephemeral private key.
  // The sender encapsulated to state.ourPublicKey, so ourPrivateKey matches.
  const kemSecret = await kemDecapsulate(kemCiphertext, state.ourPrivateKey);
  const ikm       = concatSecrets(state.rootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newReceivingChainKey } = await hkdfDerivePair(ikm);

  state.rootKey           = newRootKey;
  state.receivingChainKey = newReceivingChainKey;

  // Update theirPublicKey to sender's new ephemeral key for next send step.
  state.theirPublicKey = senderEphPub;

  // Advance the symmetric chain, caching any skipped messageKeys along the way.
  const { messageKey } = await _advanceReceivingChain(state, messageIndex);

  const plaintext  = await aesGcmDecrypt(ciphertext, nonce, messageKey);
  const fileSecret = await hkdfDerive(messageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

  state.updatedAt = Date.now();
  return { plaintext, newStateJson: serializeRatchetState(state), fileSecret };
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Advance the receiving chain to messageIndex.
 *
 * - Anti-replay  : messageIndex < receiveCount → throw
 * - DoS guard    : steps > MAX_SKIPPED_STORED  → throw
 * - Skipped keys : for every index i < messageIndex that we step over,
 *   store the intermediate messageKey in state.skippedMessageKeys[i].
 *   These will be used if those messages arrive later (out-of-order delivery).
 *
 * Mutates state.receivingChainKey, state.receiveCount, state.skippedMessageKeys.
 * Returns the messageKey at messageIndex.
 */
async function _advanceReceivingChain(
  state       : RatchetState,
  messageIndex: number,
): Promise<{ messageKey: string }> {
  if (messageIndex < state.receiveCount) {
    throw new Error(
      `doubleRatchetDecrypt: replay detected — ` +
      `messageIndex=${messageIndex} already consumed (receiveCount=${state.receiveCount})`
    );
  }

  const steps = messageIndex - state.receiveCount + 1;
  if (steps > MAX_SKIPPED_STORED) {
    throw new Error(
      `doubleRatchetDecrypt: messageIndex too far ahead — ` +
      `${steps} steps required, max allowed: ${MAX_SKIPPED_STORED}`
    );
  }

  let chainKey   = state.receivingChainKey;
  let messageKey = "";

  for (let i = 0; i < steps; i++) {
    const result = await symmetricRatchetStep(chainKey);
    chainKey   = result.nextChainKey;
    messageKey = result.messageKey;

    // Cache every key we skip over (all except the last one, which is the
    // target messageKey we return to the caller).
    if (i < steps - 1) {
      const skippedIndex = state.receiveCount + i;

      // Guard against unbounded growth
      if (Object.keys(state.skippedMessageKeys).length < MAX_SKIPPED_STORED) {
        state.skippedMessageKeys[String(skippedIndex)] = messageKey;
      }
    }
  }

  state.receivingChainKey = chainKey;
  state.receiveCount      = messageIndex + 1;

  return { messageKey };
}

/**
 * Symmetric ratchet step — advance chain by one.
 * hkdfDerivePair(chainKey) → { nextChainKey, messageKey }
 */
async function symmetricRatchetStep(chainKey: string): Promise<{
  nextChainKey: string;
  messageKey  : string;
}> {
  const { rootKey: nextChainKey, chainKey: messageKey } = await hkdfDerivePair(chainKey);
  return { nextChainKey, messageKey };
}

/**
 * Concatenate two Base64 secrets at the byte level → Base64.
 * Used to form IKM = rootKey ‖ kemSecret for the KEM ratchet step.
 */
function concatSecrets(a: string, b: string): string {
  const bytesA   = fromBase64(a);
  const bytesB   = fromBase64(b);
  const combined = new Uint8Array(bytesA.length + bytesB.length);
  combined.set(bytesA, 0);
  combined.set(bytesB, bytesA.length);
  return toBase64(combined);
}