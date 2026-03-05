/**
 * user.ts — Types utilisateur AegisQuantum
 */

/** Profil utilisateur stocké en mémoire après authentification. */
export interface AQUser {
  uid: string;
  email: string;
}

/**
 * Clés publiques d'un utilisateur, stockées dans Firestore sous /publicKeys/{uid}.
 * Ces données sont publiques — elles ne contiennent JAMAIS de clé privée.
 */
export interface PublicKeyBundle {
  uid: string;
  email: string;
  /** Base64 — ML-KEM-768 public key (1184 bytes). Vient de kemGenerateKeyPair() dans crypto/kem.ts */
  kemPublicKey: string;
  /** Base64 — ML-DSA-65 public key. Vient de dsaGenerateKeyPair() dans crypto/dsa.ts */
  dsaPublicKey: string;
  /** Timestamp de création (ms) */
  createdAt: number;
}
