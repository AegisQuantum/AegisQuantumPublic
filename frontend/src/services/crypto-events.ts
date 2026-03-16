/**
 * crypto-events.ts — Bus d'événements pour les opérations cryptographiques
 *
 * Permet à messaging.ts d'émettre des données réelles (IDs, tailles,
 * previews de ciphertext, résultats de vérification) sans jamais exposer
 * de clés privées. chat.ts s'y abonne pour afficher la "machine sous verre".
 *
 * SÉCURITÉ :
 *  - Jamais de clés privées, jamais de plaintext dans ces événements.
 *  - Les ciphertexts/signatures sont tronqués à 16 chars (preview uniquement).
 *  - Les UIDs peuvent être partiels (8 chars).
 */

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type CryptoEventName =
  | 'kem:encapsulate'
  | 'kem:decapsulate'
  | 'hkdf:derive'
  | 'aes:encrypt'
  | 'aes:decrypt'
  | 'dsa:sign'
  | 'dsa:verify'
  | 'ratchet:save'
  | 'ratchet:load'
  | 'firestore:write'
  | 'firestore:read-pubkey'
  | 'idb:cache-hit'
  | 'idb:cache-write';

export interface CryptoEventPayload {
  /** Nom de l'étape */
  step: CryptoEventName;
  /** ID court de la conversation (8 chars) */
  convId?: string;
  /** UID expéditeur/destinataire tronqué (8 chars) */
  peerUid?: string;
  /** Preview du kemCiphertext (16 chars + "…") */
  kemCiphertextPreview?: string;
  /** Preview du ciphertext AES (16 chars + "…") */
  ciphertextPreview?: string;
  /** Preview de la signature DSA (16 chars + "…") */
  signaturePreview?: string;
  /** Nonce AES (hex, 12 bytes = 24 chars) */
  nonce?: string;
  /** Index du message dans le ratchet */
  messageIndex?: number;
  /** Longueur du ciphertext en octets */
  ciphertextLen?: number;
  /** Longueur de la signature en octets */
  signatureLen?: number;
  /** Résultat de vérification DSA */
  verified?: boolean;
  /** ID Firestore du document écrit */
  firestoreDocId?: string;
  /** Collection Firestore concernée */
  firestoreCollection?: string;
  /** Source du cache IDB : 'messages' | 'conversations' | 'pubkeys' */
  cacheKey?: string;
  /** Nombre d'entrées dans le cache IDB */
  cacheCount?: number;
  /** Timestamp de l'événement */
  ts: number;
}

type CryptoEventListener = (payload: CryptoEventPayload) => void;

// ─────────────────────────────────────────────────────────────────────────────
// Bus interne
// ─────────────────────────────────────────────────────────────────────────────

const _listeners = new Set<CryptoEventListener>();

/** Émet un événement crypto vers tous les abonnés. */
export function emitCryptoEvent(payload: Omit<CryptoEventPayload, 'ts'>): void {
  const full: CryptoEventPayload = { ...payload, ts: Date.now() };
  _listeners.forEach(cb => {
    try { cb(full); } catch { /* silencieux */ }
  });
}

/** S'abonne aux événements crypto. Retourne une fonction de désabonnement. */
export function onCryptoEvent(cb: CryptoEventListener): () => void {
  _listeners.add(cb);
  return () => _listeners.delete(cb);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de troncature (sécurité)
// ─────────────────────────────────────────────────────────────────────────────

/** Tronque une chaîne base64 pour affichage : "3fa2b1c9…" */
export function previewB64(b64: string, chars = 16): string {
  if (!b64) return '—';
  return b64.length > chars ? b64.slice(0, chars) + '…' : b64;
}

/** Tronque un UID pour affichage (8 chars max). */
export function shortUid(uid: string): string {
  return uid.slice(0, 8);
}

/** Tronque un convId pour affichage. */
export function shortConvId(convId: string): string {
  // Format : uid1_uid2 — on garde 8+8
  return convId.length > 18 ? convId.slice(0, 8) + '…' + convId.slice(-8) : convId;
}
