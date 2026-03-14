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
  /** Base64 — AES-256-GCM ciphertext */
  ciphertext        : string;
  /** Base64 — AES-GCM nonce (12 fresh bytes per message) */
  nonce             : string;
  /**
   * Base64 — ML-KEM-768 ciphertext for this ratchet step.
   * Empty string ("") on the bootstrap message (messageIndex 0).
   * The receiver checks: if stateJson was null → skip KEM ratchet step.
   */
  kemCiphertext     : string;
  /**
   * Base64 — sender's fresh ephemeral public key.
   * Stored in Firestore as senderEphPub.
   * The receiver stores it as state.theirPublicKey for the next send step.
   * Always present.
   */
  senderEphPub      : string;
  /** 0-based index in the sending chain — anti-replay guard on receive side */
  messageIndex      : number;
  /** Serialised RatchetState → pass to saveRatchetState() in key-store.ts */
  newStateJson      : string;
  /**
   * Base64 — session bootstrap KEM ciphertext.
   * Present ONLY on the first message (stateJson === null).
   * Store in Firestore as initKemCiphertext.
   * The receiver decapsulates it to recover initSecret.
   */
  initKemCiphertext?: string;
  /**
   * Base64 — 32-byte file encryption secret.
   * Derived from messageKey (a true secret) via HKDF.
   * Use to AES-encrypt file attachments in messaging.ts.
   * Never stored in Firestore.
   */
  fileSecret        : string;
}

export interface DoubleRatchetDecryptResult {
  /** Decrypted plaintext */
  plaintext   : string;
  /** Updated RatchetState → pass to saveRatchetState() in key-store.ts */
  newStateJson: string;
  /**
   * Base64 — 32-byte file secret matching the sender's fileSecret.
   * Use to AES-decrypt file attachments in messaging.ts.
   */
  fileSecret  : string;
}

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetEncrypt
// ─────────────────────────────────────────────────────────────────────────────

export async function doubleRatchetEncrypt(
  plaintext     : string,
  stateJson     : string | null,
  conversationId: string,
  _ourPrivKey    : string,   // our long-term KEM private key (unused after bootstrap)
  _ourPubKey     : string,   // our long-term KEM public key
  theirPubKey   : string,   // recipient's long-term KEM public key
): Promise<DoubleRatchetEncryptResult> {

  // ── Bootstrap : first message ─────────────────────────────────────────────
  if (stateJson === null) {
    // 1. KEM encapsulate to recipient's long-term key.
    //    initKemCiphertext goes to Firestore; initSecret never leaves this scope.
    const { sharedSecret: initSecret, ciphertext: initKemCiphertext } =
      await kemEncapsulate(theirPubKey);

    // Derive root key + initial sending chain key from initSecret.
    const { rootKey, chainKey: sendingChainKey } = await hkdfDerivePair(initSecret);

    // 2. Generate first ephemeral keypair.
    //    ourEphPub is sent in senderEphPub so the receiver can encapsulate to us.
    const { publicKey: ourEphPub, privateKey: ourEphPriv } = await kemGenerateKeyPair();

    const state: RatchetState = {
      conversationId,
      rootKey,
      sendingChainKey,
      receivingChainKey : "",
      ourPrivateKey     : ourEphPriv,
      ourPublicKey      : ourEphPub,
      theirPublicKey    : theirPubKey,
      sendCount         : 0,
      receiveCount      : 0,
      updatedAt         : Date.now(),
    };

    // 3. Symmetric ratchet only — no KEM ratchet step on bootstrap.
    //    Both sides derive messageKey from the same chain key (from initSecret).
    const { nextChainKey, messageKey } = await symmetricRatchetStep(state.sendingChainKey);
    state.sendingChainKey = nextChainKey;
    const messageIndex    = state.sendCount++;

    // 4. Encrypt.
    const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);

    // File secret: derived from messageKey (secret), NOT from kemCiphertext (public).
    const fileSecret = await hkdfDerive(messageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

    state.updatedAt = Date.now();

    return {
      ciphertext,
      nonce,
      kemCiphertext    : "",    // no ratchet KEM CT on bootstrap
      senderEphPub     : ourEphPub,
      messageIndex,
      newStateJson     : serializeRatchetState(state),
      initKemCiphertext,
      fileSecret,
    };
  }

  // ── Subsequent messages ───────────────────────────────────────────────────
  const state = deserializeRatchetState(stateJson);

  // 1. KEM ratchet step: encapsulate to receiver's current ephemeral public key.
  //    state.theirPublicKey was set to their latest senderEphPub on last receive.
  const { sharedSecret: kemSecret, ciphertext: kemCiphertext } =
    await kemEncapsulate(state.theirPublicKey);

  // Mix kemSecret into root chain: IKM = rootKey ‖ kemSecret.
  const ikm = concatSecrets(state.rootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newSendingChainKey } = await hkdfDerivePair(ikm);
  state.rootKey = newRootKey;

  // 2. Generate fresh ephemeral keypair.
  //    newEphPriv stored in state — used to decapsulate on the NEXT receive step.
  //    newEphPub sent in senderEphPub so receiver encapsulates to it when replying.
  const { publicKey: newEphPub, privateKey: newEphPriv } = await kemGenerateKeyPair();
  state.ourPrivateKey = newEphPriv;
  state.ourPublicKey  = newEphPub;

  // 3. Symmetric ratchet step → per-message key.
  const { nextChainKey, messageKey } = await symmetricRatchetStep(newSendingChainKey);
  state.sendingChainKey = nextChainKey;
  const messageIndex    = state.sendCount++;

  // 4. Encrypt.
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
  kemCiphertext     : string,   // "" on bootstrap message
  senderEphPub      : string,   // sender's fresh ephemeral public key
  stateJson         : string | null,
  conversationId    : string,
  ourPrivKey        : string,   // our long-term KEM private key
  ourPubKey         : string,   // our long-term KEM public key
  _theirLongTermPub  : string,   // sender's long-term KEM public key (for reference)
  initKemCiphertext?: string,   // only on bootstrap message (stateJson === null)
): Promise<DoubleRatchetDecryptResult> {

  // ── Bootstrap : first message received ───────────────────────────────────
  if (stateJson === null) {
    if (!initKemCiphertext) {
      throw new Error(
        "doubleRatchetDecrypt: first message (stateJson=null) but initKemCiphertext is missing. " +
        "Ensure initKemCiphertext is stored in Firestore on the first message."
      );
    }

    // 1. Decapsulate initKemCiphertext with our long-term private key.
    //    Recovers the same initSecret the sender derived.
    const initSecret = await kemDecapsulate(initKemCiphertext, ourPrivKey);
    const { rootKey, chainKey: receivingChainKey } = await hkdfDerivePair(initSecret);

    // 2. Store sender's ephemeral pub key as theirPublicKey.
    //    We will encapsulate to it when we send our first reply.
    const state: RatchetState = {
      conversationId,
      rootKey,
      sendingChainKey  : "",
      receivingChainKey,
      ourPrivateKey    : ourPrivKey,   // long-term for now; updated when we send
      ourPublicKey     : ourPubKey,
      theirPublicKey   : senderEphPub, // ← encapsulate here on next send
      sendCount        : 0,
      receiveCount     : 0,
      updatedAt        : Date.now(),
    };

    // 3. Symmetric ratchet only — matches sender's bootstrap (no KEM ratchet step).
    const { messageKey } = await _advanceReceivingChain(state, messageIndex);

    const plaintext  = await aesGcmDecrypt(ciphertext, nonce, messageKey);
    const fileSecret = await hkdfDerive(messageKey, HKDF_INFO.RATCHET_CHAIN + ":file", 32);

    state.updatedAt = Date.now();
    return { plaintext, newStateJson: serializeRatchetState(state), fileSecret };
  }

  // ── Subsequent messages ───────────────────────────────────────────────────
  const state = deserializeRatchetState(stateJson);

  // 1. KEM ratchet step: decapsulate with our current ephemeral private key.
  //    The sender encapsulated to state.ourPublicKey (our last senderEphPub),
  //    so we decapsulate with state.ourPrivateKey (the matching private key).
  const kemSecret = await kemDecapsulate(kemCiphertext, state.ourPrivateKey);
  const ikm       = concatSecrets(state.rootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newReceivingChainKey } = await hkdfDerivePair(ikm);

  state.rootKey           = newRootKey;
  state.receivingChainKey = newReceivingChainKey;

  // 2. Update theirPublicKey to sender's new ephemeral key.
  //    We will encapsulate to it on our next send.
  state.theirPublicKey = senderEphPub;

  // 3. Symmetric ratchet — advance to messageIndex (with anti-replay + DoS guard).
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
 * Applies anti-replay check (messageIndex < receiveCount → throw) and
 * DoS guard (steps > 1000 → throw).
 * Mutates state.receivingChainKey and state.receiveCount.
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

  const MAX_SKIPPED = 1_000;
  const steps = messageIndex - state.receiveCount + 1;
  if (steps > MAX_SKIPPED) {
    throw new Error(
      `doubleRatchetDecrypt: messageIndex too far ahead — ` +
      `${steps} steps required, max allowed: ${MAX_SKIPPED}`
    );
  }

  let chainKey   = state.receivingChainKey;
  let messageKey = "";

  for (let i = 0; i < steps; i++) {
    const result = await symmetricRatchetStep(chainKey);
    chainKey   = result.nextChainKey;
    messageKey = result.messageKey;
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