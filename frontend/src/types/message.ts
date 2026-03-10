/**
 * message.ts — Types des messages AegisQuantum
 */

/**
 * Document Firestore stocké dans /conversations/{convId}/messages/{msgId}.
 * Tout est chiffré côté client — Firestore ne voit jamais le plaintext.
 */
export interface EncryptedMessage {
  id: string;
  conversationId: string;
  senderUid: string;

  /**
   * Base64 — ciphertext AES-256-GCM du message.
   * Produit par aesGcmEncrypt() dans crypto/aes-gcm.ts
   */
  ciphertext: string;

  /**
   * Base64 — nonce AES-GCM (12 bytes).
   * Produit par aesGcmEncrypt() dans crypto/aes-gcm.ts
   */
  nonce: string;

  /**
   * Base64 — KEM ciphertext ML-KEM-768 (1088 bytes).
   * Produit par kemEncapsulate() dans crypto/kem.ts
   * Permet au destinataire de reconstruire le shared secret via kemDecapsulate().
   */
  kemCiphertext: string;

  /**
   * Base64 — signature ML-DSA-65 du message (ciphertext + nonce + kemCiphertext).
   * Produit par dsaSign() dans crypto/dsa.ts
   * Vérifiée par le destinataire via dsaVerify() pour authentifier l'expéditeur.
   */
  signature: string;

  /**
   * Numéro de message dans le Double Ratchet — utilisé pour la dérivation des clés.
   * Géré par doubleRatchetEncrypt() dans crypto/double-ratchet.ts
   */
  messageIndex: number;

  timestamp: number;
}

/** Metadata d'une conversation (sans messages). */
export interface Conversation {
  id: string;
  /** UIDs des deux participants */
  participants: [string, string];
  /** Timestamp du dernier message */
  lastMessageAt: number;
  /** Preview du dernier message (non chiffré, juste "Message chiffré") */
  lastMessagePreview: string;
}

/** Message déchiffré, prêt à afficher dans l'UI. */
export interface DecryptedMessage {
  id: string;
  senderUid: string;
  plaintext: string;
  timestamp: number;
  /** true si la signature ML-DSA-65 a été vérifiée avec succès */
  verified: boolean;
}
