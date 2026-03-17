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

  senderEphPub: string; // <-- ADD THIS: Base64 — clé publique éphémère ML-KEM-768 utilisée pour ce message.

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

  /**
   * Base64 — KEM ciphertext d’initialisation de session.
   * Présent UNIQUEMENT sur le premier message d’une conversation (stateJson === null).
   * Généré par doubleRatchetEncrypt() et stocké dans Firestore.
   * Le receiver le décapsule pour bootstrapper son état ratchet avec le même initSecret.
   */
  initKemCiphertext?: string;

  timestamp: number;

  /**
   * UIDs des utilisateurs qui ont lu ce message.
   * Mis à jour via arrayUnion dans presence.ts → markMessageRead().
   * N'expose aucune donnée chiffrée — uniquement des UIDs.
   */
  readBy?: string[];

  // ── Pièce jointe chiffrée (optionnel) ───────────────────────────────────
  // Présent uniquement pour les messages de type fichier.
  // Le contenu binaire est chiffré AES-256-GCM côté client avant envoi.
  // Firestore ne stocke jamais le fichier en clair.

  /** true si ce message contient une pièce jointe chiffrée */
  hasFile?: boolean;
  /** Base64 — AES-256-GCM ciphertext du contenu binaire du fichier */
  fileCiphertext?: string;
  /** Base64 — nonce AES-GCM 12 bytes pour le déchiffrement du fichier */
  fileNonce?: string;
  /** Nom original du fichier (non chiffré — métadonnée acceptée) */
  fileName?: string;
  /** Taille originale en octets (non chiffrée — métadonnée acceptée) */
  fileSize?: number;
  /** MIME type du fichier (non chiffré — métadonnée acceptée) */
  fileType?: string;

  /**
   * Type spécial de message système.
   * "ratchet-reset" : signal de resynchronisation du Double Ratchet.
   * Pas de ciphertext — pas de déchiffrement. Les deux clients effacent
   * leur état ratchet local et repartent d'un bootstrap propre.
   */
  type?: "ratchet-reset";
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
  /** UIDs des utilisateurs qui ont lu ce message (depuis Firestore readBy). */
  readBy?: string[];
  /**
   * "system" : bulle système centrée (resync ratchet, etc.)
   * Absent pour les messages normaux.
   */
  type?: "system";
  /** Pièce jointe déchiffrée — présente uniquement pour les messages fichier */
  file?: {
    /** Blob déchiffré du fichier (jamais transmis, reconstruit en mémoire) */
    blob : Blob;
    name : string;
    size : number;
    type : string;
  };
}

/** Document Firestore dans /conversations/{convId}/typing/{uid}. */
export interface TypingStatus {
  uid      : string;
  updatedAt: number;
}
