/**
 * ratchet.ts — État du Double Ratchet AegisQuantum
 */

/**
 * État complet du Double Ratchet pour une conversation donnée.
 * Sérialisé/désérialisé par ratchet-state.ts, stocké chiffré dans IndexedDB via key-store.ts.
 *
 * Vient de l'initialisation dans crypto/double-ratchet.ts (doubleRatchetInit())
 */
export interface RatchetState {
  conversationId: string;

  /**
   * Base64 — clé racine courante (32 bytes).
   * Mise à jour à chaque Diffie-Hellman ratchet step.
   * Dérivée via hkdfDerive() dans crypto/hkdf.ts
   */
  rootKey: string;

  /**
   * Base64 — clé de chaîne d'envoi courante (32 bytes).
   * Avance à chaque message envoyé via hkdfDerive() dans crypto/hkdf.ts
   */
  sendingChainKey: string;

  /**
   * Base64 — clé de chaîne de réception courante (32 bytes).
   * Avance à chaque message reçu via hkdfDerive() dans crypto/hkdf.ts
   */
  receivingChainKey: string;

  /**
   * Base64 — notre clé privée DH courante (ML-KEM-768, 2400 bytes).
   * Vient de kemGenerateKeyPair() dans crypto/kem.ts
   */
  ourPrivateKey: string;

  /**
   * Base64 — notre clé publique DH courante (ML-KEM-768, 1184 bytes).
   * Vient de kemGenerateKeyPair() dans crypto/kem.ts
   */
  ourPublicKey: string;

  /**
   * Base64 — dernière clé publique DH du contact (ML-KEM-768, 1184 bytes).
   * Récupérée depuis Firestore /publicKeys/{uid} via key-registry.ts
   */
  theirPublicKey: string;

  /** Nombre de messages envoyés dans la chaîne courante */
  sendCount: number;

  /** Nombre de messages reçus dans la chaîne courante */
  receiveCount: number;

  /** Timestamp de dernière mise à jour (ms) */
  updatedAt: number;
}
