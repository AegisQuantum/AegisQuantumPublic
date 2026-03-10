/**
 * double-ratchet.ts — Double Ratchet Algorithm (stub — à implémenter)
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * SCHÉMA DU PROTOCOLE COMPLET (Alice → Bob, puis Bob → Alice)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │                        ALICE envoie à BOB                           │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │                                                                     │
 *  │  [1] Récupérer kemPublicKey_Bob ← Firestore /publicKeys/bob         │
 *  │                                                                     │
 *  │  [2] KEM Encapsulate (ML-KEM-768)                                   │
 *  │      kemEncapsulate(kemPublicKey_Bob)                               │
 *  │      → sharedSecret (32B)  +  kemCiphertext (1088B)                 │
 *  │                                                                     │
 *  │      ╔══════════════════════════════════════════════════════╗       │
 *  │      ║  TODO [DOUBLE RATCHET — KEM RATCHET]                ║       │
 *  │      ║  Actuellement : 1 KEM par message (pas de ratchet)  ║       │
 *  │      ║  Avec DR : KEM ratchet step → nouveau sharedSecret  ║       │
 *  │      ║  qui fait avancer la rootKey via HKDF               ║       │
 *  │      ║  → HKDF(rootKey, sharedSecret) → (newRootKey,       ║       │
 *  │      ║                                   sendingChainKey)  ║       │
 *  │      ╚══════════════════════════════════════════════════════╝       │
 *  │                                                                     │
 *  │  [3] HKDF Dérivation                                                │
 *  │      hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY)                │
 *  │      → messageKey (32B)                                             │
 *  │                                                                     │
 *  │      ╔══════════════════════════════════════════════════════╗       │
 *  │      ║  TODO [DOUBLE RATCHET — SYMMETRIC RATCHET]          ║       │
 *  │      ║  Actuellement : dérivation directe sans chaîne      ║       │
 *  │      ║  Avec DR : hkdfDerivePair(sendingChainKey)          ║       │
 *  │      ║  → (newSendingChainKey, messageKey)                 ║       │
 *  │      ║  sendCount++ à chaque message                       ║       │
 *  │      ╚══════════════════════════════════════════════════════╝       │
 *  │                                                                     │
 *  │  [4] AES-256-GCM Chiffrement                                        │
 *  │      aesGcmEncrypt(plaintext, messageKey)                           │
 *  │      → ciphertext + nonce (12B)                                     │
 *  │                                                                     │
 *  │  [5] DSA Sign (ML-DSA-65) — INCHANGÉ avec Double Ratchet           │
 *  │      dsaSign(ciphertext ‖ nonce ‖ kemCiphertext, dsaPrivKey_Alice)  │
 *  │      → signature (3309B)                                            │
 *  │                                                                     │
 *  │  [6] Firestore → /conversations/{convId}/messages/{msgId}          │
 *  │      { ciphertext, nonce, kemCiphertext, signature, messageIndex }  │
 *  │      messageIndex = 0 actuellement                                  │
 *  │      TODO [DOUBLE RATCHET] → sendCount du ratchet state             │
 *  │                                                                     │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │                        BOB reçoit d'Alice                           │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │                                                                     │
 *  │  [1] Firestore snapshot → EncryptedMessage                          │
 *  │                                                                     │
 *  │  [2] DSA Verify (ML-DSA-65) — INCHANGÉ avec Double Ratchet         │
 *  │      Récupérer dsaPublicKey_Alice ← Firestore /publicKeys/alice     │
 *  │      dsaVerify(ciphertext ‖ nonce ‖ kemCiphertext,                  │
 *  │                signature, dsaPublicKey_Alice)                       │
 *  │      → boolean (verified)                                           │
 *  │                                                                     │
 *  │  [3] KEM Decapsulate (ML-KEM-768)                                   │
 *  │      kemDecapsulate(kemCiphertext, kemPrivKey_Bob)                   │
 *  │      → sharedSecret (32B) — identique à celui d'Alice en [2]       │
 *  │                                                                     │
 *  │      ╔══════════════════════════════════════════════════════╗       │
 *  │      ║  TODO [DOUBLE RATCHET — KEM RATCHET CÔTÉ RÉCEPTION] ║       │
 *  │      ║  Actuellement : KEM decapsulate direct               ║       │
 *  │      ║  Avec DR : détecter le KEM ratchet step              ║       │
 *  │      ║  (kemCiphertext provient d'une nouvelle paire)       ║       │
 *  │      ║  → HKDF(rootKey, sharedSecret) → (newRootKey,        ║       │
 *  │      ║                                   receivingChainKey) ║       │
 *  │      ╚══════════════════════════════════════════════════════╝       │
 *  │                                                                     │
 *  │  [4] HKDF Dérivation                                                │
 *  │      hkdfDerive(sharedSecret, HKDF_INFO.MESSAGE_KEY)                │
 *  │      → messageKey (32B)                                             │
 *  │                                                                     │
 *  │      ╔══════════════════════════════════════════════════════╗       │
 *  │      ║  TODO [DOUBLE RATCHET — SYMMETRIC RATCHET RÉCEPTION]║       │
 *  │      ║  Avec DR : hkdfDerivePair(receivingChainKey)         ║       │
 *  │      ║  → (newReceivingChainKey, messageKey)                ║       │
 *  │      ║  Vérifier messageIndex contre receiveCount (anti-    ║       │
 *  │      ║  replay) et gérer les messages hors-ordre (skipped   ║       │
 *  │      ║  message keys)                                       ║       │
 *  │      ╚══════════════════════════════════════════════════════╝       │
 *  │                                                                     │
 *  │  [5] AES-256-GCM Déchiffrement                                      │
 *  │      aesGcmDecrypt(ciphertext, nonce, messageKey)                   │
 *  │      → plaintext                                                    │
 *  │                                                                     │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │  CONTOURNEMENT ACTUEL (sans forward secrecy)                        │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │  • 1 kemEncapsulate/kemDecapsulate par message — pas de ratchet     │
 *  │  • messageKey = HKDF(sharedSecret) directement                     │
 *  │  • messageKey mise en cache IDB (msgkey:<convId>:<msgId>)           │
 *  │  • messageIndex figé à 0                                            │
 *  │  • Pas de forward secrecy : si kemPrivKey_Bob leak → tous les       │
 *  │    messages passés sont déchiffrables                               │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 * ═══════════════════════════════════════════════════════════════════════
 * DÉPENDANCES DISPONIBLES (toutes implémentées — prêtes à l'emploi)
 * ═══════════════════════════════════════════════════════════════════════
 *
 *  import { kemEncapsulate, kemDecapsulate, kemGenerateKeyPair } from "./kem";
 *    kemEncapsulate(recipientPubKeyB64)         → { sharedSecret: string, ciphertext: string }
 *    kemDecapsulate(ciphertextB64, privKeyB64)  → sharedSecret: string
 *    kemGenerateKeyPair()                       → { publicKey: string, privateKey: string }
 *
 *  import { hkdfDerive, hkdfDerivePair, HKDF_INFO } from "./hkdf";
 *    hkdfDerive(secretB64, info, outputLength?) → keyB64: string
 *    hkdfDerivePair(secretB64)                  → { rootKey: string, chainKey: string }
 *    HKDF_INFO.MESSAGE_KEY   — context string pour les clés de message
 *    HKDF_INFO.RATCHET_ROOT  — context string pour la root key
 *    HKDF_INFO.RATCHET_CHAIN — context string pour les chain keys
 *
 *  import { aesGcmEncrypt, aesGcmDecrypt } from "./aes-gcm";
 *    aesGcmEncrypt(plaintext: string, keyB64: string)              → { ciphertext, nonce }
 *    aesGcmDecrypt(ciphertextB64, nonceB64, keyB64)                → plaintext: string
 *
 *  import { serializeRatchetState, deserializeRatchetState } from "./ratchet-state";
 *    serializeRatchetState(state: RatchetState)  → json: string
 *    deserializeRatchetState(json: string)       → RatchetState
 *
 *  import type { RatchetState } from "../types/ratchet";
 *    {
 *      conversationId  : string,  — ID Firestore de la conversation
 *      rootKey         : string,  — Base64 32B — mis à jour à chaque KEM ratchet step
 *      sendingChainKey : string,  — Base64 32B — avance à chaque message envoyé
 *      receivingChainKey:string,  — Base64 32B — avance à chaque message reçu
 *      ourPrivateKey   : string,  — Base64 — ML-KEM-768 current private key
 *      ourPublicKey    : string,  — Base64 — ML-KEM-768 current public key
 *      theirPublicKey  : string,  — Base64 — dernière pubkey KEM connue du contact
 *      sendCount       : number,  — messages envoyés dans la chaîne courante
 *      receiveCount    : number,  — messages reçus dans la chaîne courante
 *      updatedAt       : number,  — timestamp ms
 *    }
 *
 *  import { saveRatchetState, loadRatchetState } from "../services/key-store";
 *    saveRatchetState(uid, convId, stateJson)  → Promise<void>
 *    loadRatchetState(uid, convId)             → Promise<string | null>
 */

// ─────────────────────────────────────────────────────────────────────────────
// Types exportés — NE PAS MODIFIER (utilisés par messaging.ts)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Résultat de doubleRatchetEncrypt.
 * Toutes les valeurs vont directement dans le document Firestore EncryptedMessage.
 */
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

/**
 * Résultat de doubleRatchetDecrypt.
 */
export interface DoubleRatchetDecryptResult {
  /** Texte clair déchiffré */
  plaintext   : string;
  /** RatchetState mis à jour → passer à saveRatchetState() dans key-store.ts */
  newStateJson: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetEncrypt — STUB (logique à implémenter)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Chiffre un message avec le Double Ratchet.
 *
 * Appelé par messaging.ts → sendMessage() en remplacement des étapes 3-5
 * (KEM encapsulate → HKDF → AES-GCM).
 *
 * Comportement attendu :
 *  1. Si stateJson === null → initialiser un nouvel état RatchetState :
 *     - Générer une nouvelle paire KEM : kemGenerateKeyPair()
 *     - KEM ratchet step : kemEncapsulate(theirPubKey) → sharedSecret
 *     - HKDF(sharedSecret) → { rootKey, sendingChainKey }
 *     - Stocker ourPrivKey, ourPubKey, theirPubKey, rootKey, chainKey dans l'état
 *  2. Si stateJson !== null → désérialiser l'état existant
 *  3. Symmetric ratchet step (envoi) :
 *     - hkdfDerivePair(sendingChainKey) → { newSendingChainKey, messageKey }
 *     - sendCount++
 *  4. AES-256-GCM encrypt(plaintext, messageKey) → { ciphertext, nonce }
 *  5. Si KEM ratchet step nécessaire (changement de tour) :
 *     - kemGenerateKeyPair() → nouvelle paire éphémère
 *     - kemEncapsulate(theirPubKey) → nouveau kemCiphertext + sharedSecret
 *     - HKDF(rootKey, sharedSecret) → (newRootKey, newSendingChainKey)
 *  6. Mettre à jour l'état et le sérialiser → newStateJson
 *
 * @param plaintext       — texte clair UTF-8 à chiffrer
 * @param stateJson       — RatchetState sérialisé, ou null (premier message)
 * @param conversationId  — ID Firestore de la conversation
 * @param ourPrivKey      — Base64 — ML-KEM-768 private key (getKemPrivateKey)
 * @param ourPubKey       — Base64 — ML-KEM-768 public key (key-registry)
 * @param theirPubKey     — Base64 — ML-KEM-768 public key du contact (key-registry)
 * @param sharedSecret    — Base64 — secret KEM initial (kemEncapsulate, utilisé
 *                          UNIQUEMENT si stateJson === null pour init)
 *
 * @returns DoubleRatchetEncryptResult
 *   .ciphertext    — Base64 — message chiffré
 *   .nonce         — Base64 — IV AES-GCM
 *   .kemCiphertext — Base64 — KEM CT du ratchet step (à stocker Firestore)
 *   .messageIndex  — numéro dans la chaîne courante (à stocker Firestore)
 *   .newStateJson  — état mis à jour (à passer à saveRatchetState)
 */
export async function doubleRatchetEncrypt(
  _plaintext      : string,      // IN  — texte clair
  _stateJson      : string | null, // IN  — état ratchet courant (null = init)
  _conversationId : string,      // IN  — ID conversation Firestore
  _ourPrivKey     : string,      // IN  — notre clé privée KEM (getKemPrivateKey)
  _ourPubKey      : string,      // IN  — notre clé publique KEM (key-registry)
  _theirPubKey    : string,      // IN  — clé publique KEM du contact
  _sharedSecret   : string,      // IN  — shared secret KEM initial (si stateJson null)
): Promise<DoubleRatchetEncryptResult> {
  // OUT : DoubleRatchetEncryptResult
  //   .ciphertext    → stocker dans Firestore EncryptedMessage.ciphertext
  //   .nonce         → stocker dans Firestore EncryptedMessage.nonce
  //   .kemCiphertext → stocker dans Firestore EncryptedMessage.kemCiphertext
  //   .messageIndex  → stocker dans Firestore EncryptedMessage.messageIndex
  //   .newStateJson  → passer à saveRatchetState(myUid, convId, newStateJson)
  throw new Error("TODO: implémenter doubleRatchetEncrypt()");
}

// ─────────────────────────────────────────────────────────────────────────────
// doubleRatchetDecrypt — STUB (logique à implémenter)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Déchiffre un message avec le Double Ratchet.
 *
 * Appelé par messaging.ts → decryptMessage() en remplacement des étapes 3-5
 * (KEM decapsulate → HKDF → AES-GCM).
 *
 * Comportement attendu :
 *  1. Si stateJson === null → initialiser un état RatchetState réception :
 *     - kemDecapsulate(kemCiphertext, ourPrivKey) → sharedSecret
 *     - HKDF(sharedSecret) → { rootKey, receivingChainKey }
 *  2. Si stateJson !== null → désérialiser l'état
 *  3. Vérifier si KEM ratchet step nécessaire (theirPubKey a changé)
 *     - Si oui : kemDecapsulate(kemCiphertext, ourPrivKey) → nouveau sharedSecret
 *       HKDF(rootKey, sharedSecret) → (newRootKey, newReceivingChainKey)
 *  4. Symmetric ratchet step (réception) :
 *     - Avancer jusqu'au messageIndex si messages hors-ordre (skipped keys)
 *     - hkdfDerivePair(receivingChainKey) → { newReceivingChainKey, messageKey }
 *     - receiveCount++
 *  5. AES-256-GCM decrypt(ciphertext, nonce, messageKey) → plaintext
 *  6. Mettre à jour l'état et le sérialiser → newStateJson
 *
 * @param ciphertext      — Base64 — message chiffré AES-256-GCM (depuis Firestore)
 * @param nonce           — Base64 — IV AES-GCM (depuis Firestore)
 * @param messageIndex    — numéro de message (depuis Firestore) — anti-replay
 * @param kemCiphertext   — Base64 — KEM CT du ratchet step (depuis Firestore)
 * @param stateJson       — RatchetState sérialisé, ou null (premier message reçu)
 * @param conversationId  — ID Firestore de la conversation
 * @param ourPrivKey      — Base64 — ML-KEM-768 private key (getKemPrivateKey)
 * @param ourPubKey       — Base64 — ML-KEM-768 public key (key-registry)
 * @param theirPubKey     — Base64 — ML-KEM-768 public key de l'expéditeur
 * @param sharedSecret    — Base64 — kemDecapsulate(kemCiphertext, ourPrivKey)
 *                          (UNIQUEMENT si stateJson === null, pour l'init)
 *
 * @returns DoubleRatchetDecryptResult
 *   .plaintext    → texte clair à afficher dans l'UI
 *   .newStateJson → passer à saveRatchetState(myUid, convId, newStateJson)
 */
export async function doubleRatchetDecrypt(
  _ciphertext     : string,      // IN  — ciphertext AES-GCM (Firestore)
  _nonce          : string,      // IN  — nonce AES-GCM (Firestore)
  _messageIndex   : number,      // IN  — index anti-replay (Firestore)
  _kemCiphertext  : string,      // IN  — KEM CT ratchet step (Firestore)
  _stateJson      : string | null, // IN  — état ratchet courant (null = init)
  _conversationId : string,      // IN  — ID conversation Firestore
  _ourPrivKey     : string,      // IN  — notre clé privée KEM (getKemPrivateKey)
  _ourPubKey      : string,      // IN  — notre clé publique KEM
  _theirPubKey    : string,      // IN  — clé publique KEM de l'expéditeur
  _sharedSecret   : string,      // IN  — shared secret KEM initial (si stateJson null)
): Promise<DoubleRatchetDecryptResult> {
  // OUT : DoubleRatchetDecryptResult
  //   .plaintext    → afficher dans l'UI (messaging.ts → subscribeToMessages callback)
  //   .newStateJson → passer à saveRatchetState(myUid, convId, newStateJson)
  throw new Error("TODO: implémenter doubleRatchetDecrypt()");
}
