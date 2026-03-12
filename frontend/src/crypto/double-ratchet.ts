/**
 * double-ratchet.ts — Double Ratchet Algorithm 
 *
 * Rôle :
 * - Implémente le Double Ratchet de Signal pour le chiffrement de bout en bout
 *    des messages après l'établissement de la session via ML-KEM-768.
 * - Remplace les étapes 3-5 (KEM encapsulate → HKDF → AES-GCM) du chiffrement
 *  dans messaging.ts → sendMessage() et decryptMessage().
 * - Gère l'état de ratchet (RatchetState) pour chaque conversation, stocké chiffré 
 *  dans IndexedDB via key-store.ts.
 * - Utilise HKDF pour faire avancer les chaînes de clés (root key → chain key → message key).
 * - Utilise AES-256-GCM pour le chiffrement symétrique des messages.
 *
 * Appelé par :
 *  - messaging.ts → sendMessage() → doubleRatchetEncrypt()
 *  - messaging.ts → decryptMessage() → doubleRatchetDecrypt()
 * */

import { kemEncapsulate, kemDecapsulate, kemGenerateKeyPair, toBase64, fromBase64 } from "./kem";
import { hkdfDerivePair } from "./hkdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm";
import { serializeRatchetState, deserializeRatchetState } from "./ratchet-state";
import type { RatchetState } from "../types/ratchet";
// saveRatchetState / loadRatchetState sont appelés depuis messaging.ts, pas ici.
// Cet import est retiré pour éviter la dépendance circulaire
// double-ratchet.ts → key-store.ts → (potentiellement) messaging.ts.


// ─────────────────────────────────────────────────────────────────────────────
// Types exportés — NE PAS MODIFIER (utilisés par messaging.ts)
// ─────────────────────────────────────────────────────────────────────────────
export interface DoubleRatchetEncryptResult {
  /** Base64 — ciphertext AES-256-GCM du message */
  ciphertext   : string;
  /** Base64 — nonce AES-GCM (12 bytes, frais par message) */
  nonce        : string;
  /** Base64 — ML-KEM-768 ciphertext du ratchet step courant (1088 bytes) */
  kemCiphertext: string;
  /** Index du message dans la chaîne courante — anti-replay côté réception */
  messageIndex : number;
  /** RatchetState sérialisé → passer à saveRatchetState() dans key-store.ts */
  newStateJson : string;
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

/**
 * Chiffre un message avec le Double Ratchet.
 *
 * @returns DoubleRatchetEncryptResult
 *   .ciphertext    — Base64 — message chiffré
 *   .nonce         — Base64 — IV AES-GCM
 *   .kemCiphertext — Base64 — KEM CT du ratchet step (à stocker Firestore)
 *   .messageIndex  — numéro dans la chaîne courante (à stocker Firestore)
 *   .newStateJson  — état mis à jour (à passer à saveRatchetState)
 */
export async function doubleRatchetEncrypt(
  plaintext      : string,      // IN  — texte clair
  stateJson      : string | null, // IN  — état ratchet courant (null = init)
  conversationId : string,      // IN  — ID conversation Firestore
  ourPrivKey     : string,      // IN  — notre clé privée KEM (getKemPrivateKey)
  ourPubKey      : string,      // IN  — notre clé publique KEM (key-registry)
  theirPubKey    : string,      // IN  — clé publique KEM du contact
  sharedSecret   : string,      // IN  — shared secret KEM initial (si stateJson null)
  ): Promise<DoubleRatchetEncryptResult> {
    // ── Étape 1/2 : init ou restauration de l'état ──────────────────
    let state: RatchetState;

    if (stateJson === null) { // Premier message : sharedSecret produit par kemEncapsulate() dans messaging.ts.
      const { rootKey, chainKey: sendingChainKey } = await hkdfDerivePair(sharedSecret); // on bootstrappe rootKey + sendingChainKey depuis ce secret initial.

      state = {
        conversationId,
        rootKey,
        sendingChainKey,
        receivingChainKey : "",   // inconnu jusqu'au premier message recu
        ourPrivateKey     : ourPrivKey,
        ourPublicKey      : ourPubKey,
        theirPublicKey    : theirPubKey,
        sendCount         : 0,
        receiveCount      : 0,
        updatedAt         : Date.now(),
      };
    } else {
      state = deserializeRatchetState(stateJson); // restauration depuis le JSON stocké (message précédent)
    }

    // ── Étape 3 : KEM ratchet step ────────────────────────────────────────────
    // Un ratchet KEM est effectué à chaque envoi forward secrecy
    // former KEM pair abandonnée, chaque message dérive d'un kemSecret distinct
    const {
      newRootKey,
      newSendingChainKey : chainKeyAfterKem,
      kemCiphertext,
      newOurPrivKey,
      newOurPubKey,
    } = await kemRatchetStepSend(state.rootKey, state.theirPublicKey); // on fait avancer le ratchet KEM → nouvelle root key + nouvelle chain key d'envoi (la chain de réception est inchangée)

    //maj 
    state.rootKey       = newRootKey;
    state.ourPrivateKey = newOurPrivKey;
    state.ourPublicKey  = newOurPubKey;

    // ── Étape 4 : Symmetric ratchet step (HKDF) ─────────────────────────
    const { nextChainKey, messageKey } =
      await symmetricRatchetStep(chainKeyAfterKem);

    //maj
    state.sendingChainKey = nextChainKey;
    const messageIndex    = state.sendCount;
    state.sendCount++;

    // ── Étape 5 : AES-256-GCM ─────────────────────────────────────
    const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, messageKey);

    // ── Étape 6 : Sérialisation ────────────────────────────────────────────────
    state.updatedAt = Date.now();
    const newStateJson = serializeRatchetState(state);

    return { ciphertext, nonce, kemCiphertext, messageIndex, newStateJson }; //DoubleRatchetEncryptResult
  }


// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetDecrypt
// ─────────────────────────────────────────────────────────────────────────────

export async function doubleRatchetDecrypt(
  ciphertext    : string,
  nonce         : string,
  messageIndex  : number,
  kemCiphertext : string,
  stateJson     : string | null,
  conversationId: string,
  ourPrivKey    : string,
  ourPubKey     : string,
  theirPubKey   : string,
  sharedSecret  : string,
): Promise<DoubleRatchetDecryptResult> {

  // ── Étape 1/2 : same as send ──────────────────
  let state: RatchetState;

  if (stateJson === null) {
    const { rootKey, chainKey: receivingChainKey } =
      await hkdfDerivePair(sharedSecret);

    state = {
      conversationId,
      rootKey,
      sendingChainKey  : "",   // inconnu jusqu'au premier envoi
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

  // ── Étape 3 : KEM ratchet step ────────────────────────────────────────────
  // Décapsule le kemCiphertext joint au message pour retrouver le kemSecret
  // et avancer rootKey + receivingChainKey de manière identique au sender.
  const { newRootKey, newReceivingChainKey: chainKeyAfterKem } =
    await kemRatchetStepReceive(
      state.rootKey,
      kemCiphertext,
      state.ourPrivateKey,
    );

  state.rootKey        = newRootKey;
  state.theirPublicKey = theirPubKey;

  // ── Étape 4 : Symmetric ratchet step → messageKey ─────────────────────────
  if (messageIndex < state.receiveCount) { // Anti-replay : messageIndex doit être >= receiveCount.
    throw new Error(
      `doubleRatchetDecrypt: replay détecté — ` +
      `messageIndex=${messageIndex} déjà consommé (receiveCount=${state.receiveCount})`,
    );
  }

  // Avance la chaîne jusqu'à l'index attendu.
  // Production : les messageKeys sautées (hors-ordre) devraient être cachées
  // dans une skipped-keys map pour un déchiffrement différé.

  const MAX_SKIPPED_MESSAGES = 1_000; //limit to avoid DoS via messageIndex très grand
  const stepsToAdvance = messageIndex - state.receiveCount + 1; // +1 car receiveCount est l'index du prochain message attendu, pas du dernier consommé
  let chainKey   = chainKeyAfterKem;
  let messageKey = "";

  if (stepsToAdvance > MAX_SKIPPED_MESSAGES) {
  throw new Error(
    `doubleRatchetDecrypt: messageIndex trop élevé — ` +
    `${stepsToAdvance} steps requis, max autorisé : ${MAX_SKIPPED_MESSAGES}`
    );
  }

  for (let i = 0; i < stepsToAdvance; i++) { // faire avancer la chaîne de clés jusqu'à messageIndex
    const { nextChainKey, messageKey: mk } = await symmetricRatchetStep(chainKey);
    chainKey   = nextChainKey;
    messageKey = mk;
  }

  state.receivingChainKey = chainKey;
  state.receiveCount      = messageIndex + 1;

  // ── Étape 5 : déchiffrement AES ───────────────────────────────────
  const plaintext = await aesGcmDecrypt(ciphertext, nonce, messageKey);

  // ── Étape 6 : Sérialisation ────────────────────────────────────────────────
  state.updatedAt = Date.now();
  const newStateJson = serializeRatchetState(state);

  return { plaintext, newStateJson };
}


/** 
 *------------------------------
 *  HELPERS 
 * -----------------------------
 */

/**
 * Concatène deux secrets Base64 au niveau des bytes → Base64.
 *
 * Utilisé pour former l'IKM du KEM ratchet step :
 *   IKM = rootKey || kemSharedSecret
 */
function concatSecrets(secretA: string, secretB: string): string {
  const a = fromBase64(secretA);
  const b = fromBase64(secretB);
  const combined = new Uint8Array(a.length + b.length);
  combined.set(a, 0);
  combined.set(b, a.length);
  return toBase64(combined);
}


//TODO : could be done in a kem-ratchet.ts to avoid ugly files but whatever 
/**
 * KEM ratchet step — envoi.
 *
 * 1. Génère une nouvelle paire KEM éphémère (forward secrecy)
 * 2. kemEncapsulate(theirPubKey) → { kemCiphertext, kemSecret }
 * 3. IKM = rootKey || kemSecret  (concaténation bytes)
 * 4. hkdfDerivePair(IKM) → { newRootKey, newChainKey }
 *
 * Le kemCiphertext est transmis avec le message (champ Firestore).
 */
async function kemRatchetStepSend(
  currentRootKey : string,
  theirPubKey    : string,
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

  // IKM = rootKey || kemSecret — les deux secrets contribuent à l'entropie
  const ikm = concatSecrets(currentRootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newSendingChainKey } =
    await hkdfDerivePair(ikm);

  return { newRootKey, newSendingChainKey, kemCiphertext, newOurPrivKey, newOurPubKey };
}


/**
 * KEM ratchet step —  réception.
 *
 * 1. kemDecapsulate(kemCiphertext, ourPrivKey) → kemSecret
 * 2. IKM = rootKey || kemSecret
 * 3. hkdfDerivePair(IKM) → { newRootKey, newChainKey }
 *
 * Produit exactement les mêmes clés que kemRatchetStepSend → convergence.
 */
async function kemRatchetStepReceive(
  currentRootKey : string,
  kemCiphertext  : string,
  ourPrivKey     : string,
): Promise<{
  newRootKey           : string;
  newReceivingChainKey : string;
}> {
  const kemSecret = await kemDecapsulate(kemCiphertext, ourPrivKey);

  const ikm = concatSecrets(currentRootKey, kemSecret);
  const { rootKey: newRootKey, chainKey: newReceivingChainKey } =
    await hkdfDerivePair(ikm); //check que ça produit les mêmes clés que le sender (convergence)

  return { newRootKey, newReceivingChainKey }; //on return la new root key pour update le state, et la chain key pour faire avancer la chaîne de message keys
}

/**
 * Symmetric ratchet step — avance la chaîne de clefs d'un cran
 *
 * hkdfDerivePair(chainKey)
 *   .rootKey  → nextChainKey  (remplace chainKey dans state)
 *   .chainKey → messageKey    (usage unique AES-GCM, jeté ensuite)
 */
async function symmetricRatchetStep(chainKey: string): Promise<{
  nextChainKey: string;
  messageKey  : string;
}> {
  const { rootKey: nextChainKey, chainKey: messageKey } =
    await hkdfDerivePair(chainKey);
  return { nextChainKey, messageKey };
}
