/**
 * ratchet-state.ts — Sérialisation / désérialisation du RatchetState
 *
 * Rôle :
 *  - Fournit des helpers pour convertir le RatchetState en JSON string
 *    (pour le stockage IndexedDB via key-store.ts) et vice-versa.
 *  - Valide la cohérence du state à la désérialisation.
 *
 * Le RatchetState est stocké chiffré dans IndexedDB (AES-256-GCM, key-store.ts).
 * Il est chargé en mémoire uniquement pendant le traitement d'un message.
 */

import type { RatchetState } from "../types/ratchet";

/**
 * Sérialise un RatchetState en JSON string.
 * Appelé par messaging.ts après chaque envoi/réception de message.
 *
 * @param state — RatchetState courant
 * @returns JSON string à passer à key-store.ts → saveRatchetState()
 */
export function serializeRatchetState(state: RatchetState): string {
  return JSON.stringify(state);
}

/**
 * Désérialise un JSON string en RatchetState.
 * Appelé par messaging.ts avant chaque envoi/réception de message.
 *
 * @param json — JSON string venant de key-store.ts → loadRatchetState()
 * @returns RatchetState valide
 * @throws Error si le JSON est malformé ou incomplet
 */
export function deserializeRatchetState(json: string): RatchetState {
  let state: unknown;
  try {
    state = JSON.parse(json);
  } catch {
    throw new Error("RatchetState: invalid JSON");
  }

  const s = state as Record<string, unknown>;
  const required: (keyof RatchetState)[] = [
    "conversationId",
    "rootKey",
    "sendingChainKey",
    "receivingChainKey",
    "ourPrivateKey",
    "ourPublicKey",
    "theirPublicKey",
    "sendCount",
    "receiveCount",
    "updatedAt",
  ];
  for (const key of required) {
    if (s[key] === undefined || s[key] === null) {
      throw new Error(`RatchetState: missing field "${key}"`);
    }
  }

  return state as RatchetState;
}
