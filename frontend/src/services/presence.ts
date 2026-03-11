/**
 * presence.ts — Statuts de lecture et indicateur "en train d'écrire"
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ARCHITECTURE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  Typing indicator :
 *    Firestore : /conversations/{convId}/typing/{uid}
 *      { uid, updatedAt: number }
 *
 *    - setTyping(convId, uid, true)  → upsert du doc, TTL géré côté client
 *    - setTyping(convId, uid, false) → suppression du doc
 *    - subscribeToTyping(convId, myUid, cb) → onSnapshot filtre les autres UIDs
 *      Le callback reçoit la liste des UIDs en train d'écrire (hors myUid).
 *
 *    Invariant : si un utilisateur ferme l'onglet sans appeler setTyping(false),
 *    le doc reste en Firestore. Le client filtre donc les docs > TTL_MS = 5 s.
 *
 *  Read receipts :
 *    Firestore : champ `readBy: string[]` dans chaque message doc
 *      /conversations/{convId}/messages/{msgId}
 *
 *    - markMessageRead(convId, msgId, uid) → arrayUnion(uid) dans readBy
 *    - subscribeToReadReceipts(convId, msgId, cb) → onSnapshot sur le champ readBy
 *
 *    Stratégie :
 *      On ne marque "lu" QUE les messages reçus (senderUid !== myUid).
 *      On marque le dernier message visible dans la conversation.
 *      L'UI affiche : ✓ envoyé, ✓✓ lu (quand contactUid est dans readBy).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SÉCURITÉ
 * ─────────────────────────────────────────────────────────────────────────────
 *  - readBy ne contient que des UIDs — aucune donnée chiffrée n'est exposée.
 *  - typing ne contient que uid + timestamp — aucune donnée de message.
 *  - Les règles Firestore devront vérifier que uid === auth.uid pour toute
 *    écriture dans ces sous-collections.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  updateDoc,
  onSnapshot,
  arrayUnion,
  type Unsubscribe,
} from "firebase/firestore";
import { db } from "./firebase";

// ─────────────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Durée de vie côté client d'un statut "typing".
 * Si un doc typing est plus vieux que TTL_MS, il est ignoré dans le callback.
 * Protège contre les onglets fermés brutalement.
 */
export const TYPING_TTL_MS = 5_000;

/**
 * Délai d'inactivité avant d'arrêter automatiquement le typing.
 * Déclenché dans chat.ts via debounce sur l'input.
 */
export const TYPING_STOP_DELAY_MS = 3_000;

// ─────────────────────────────────────────────────────────────────────────────
// Paths Firestore
// ─────────────────────────────────────────────────────────────────────────────

const typingCol = (convId: string) =>
  collection(db, "conversations", convId, "typing");

const typingDoc = (convId: string, uid: string) =>
  doc(db, "conversations", convId, "typing", uid);

const messageDoc = (convId: string, msgId: string) =>
  doc(db, "conversations", convId, "messages", msgId);

// ─────────────────────────────────────────────────────────────────────────────
// Typing indicator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Signale que l'utilisateur est en train d'écrire (ou a arrêté).
 *
 * @param convId  — ID de la conversation
 * @param uid     — UID de l'utilisateur courant
 * @param isTyping — true = commence à écrire, false = arrête
 */
export async function setTyping(
  convId   : string,
  uid      : string,
  isTyping : boolean,
): Promise<void> {
  const ref = typingDoc(convId, uid);
  if (isTyping) {
    await setDoc(ref, { uid, updatedAt: Date.now() });
  } else {
    try {
      await deleteDoc(ref);
    } catch {
      // Le doc n'existe pas — silencieux
    }
  }
}

/**
 * S'abonne aux statuts typing d'une conversation.
 * Le callback reçoit la liste des UIDs (hors myUid) actuellement en train d'écrire.
 *
 * @param convId  — ID de la conversation
 * @param myUid   — UID de l'utilisateur courant (exclu du résultat)
 * @param callback — appelé avec la liste des UIDs qui écrivent
 * @returns Unsubscribe — à appeler pour se désabonner
 */
export function subscribeToTyping(
  convId  : string,
  myUid   : string,
  callback: (typingUids: string[]) => void,
): Unsubscribe {
  return onSnapshot(typingCol(convId), (snap) => {
    const now = Date.now();
    const typingUids = snap.docs
      .map(d => d.data() as { uid: string; updatedAt: number })
      .filter(d => d.uid !== myUid && now - d.updatedAt < TYPING_TTL_MS)
      .map(d => d.uid);
    callback(typingUids);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Read receipts
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Marque un message comme lu par l'utilisateur courant.
 * Utilise arrayUnion pour être idempotent (plusieurs appels = 1 seul UID dans readBy).
 *
 * À appeler uniquement pour les messages dont senderUid !== myUid.
 *
 * @param convId — ID de la conversation
 * @param msgId  — ID du message
 * @param uid    — UID de l'utilisateur qui a lu
 */
export async function markMessageRead(
  convId: string,
  msgId : string,
  uid   : string,
): Promise<void> {
  try {
    await updateDoc(messageDoc(convId, msgId), {
      readBy: arrayUnion(uid),
    });
  } catch (err) {
    // Silencieux — le doc peut ne pas exister encore (race condition)
    console.warn(`[AQ] markMessageRead: ${err}`);
  }
}

/**
 * Marque en masse les derniers messages non lus comme lus.
 * Optimisation : ne marque que les messages reçus (senderUid !== myUid)
 * qui ne sont pas encore dans readBy.
 *
 * @param convId   — ID de la conversation
 * @param messages — liste de messages (DecryptedMessage avec readBy)
 * @param myUid    — UID de l'utilisateur courant
 */
export async function markAllRead(
  convId  : string,
  messages: Array<{ id: string; senderUid: string; readBy?: string[] }>,
  myUid   : string,
): Promise<void> {
  const toMark = messages.filter(
    m => m.senderUid !== myUid && !(m.readBy ?? []).includes(myUid)
  );
  // Fire-and-forget en parallèle — on ne bloque pas l'UI
  await Promise.allSettled(toMark.map(m => markMessageRead(convId, m.id, myUid)));
}

/**
 * Crée un helper de debounce pour le typing indicator.
 * Retourne { onInput, onBlur, destroy }.
 *
 * Usage dans chat.ts :
 *   const typing = createTypingDebouncer(convId, myUid);
 *   input.addEventListener('input', typing.onInput);
 *   input.addEventListener('blur',  typing.onBlur);
 *   // À la fermeture de la conv : typing.destroy()
 *
 * @param convId  — ID de la conversation courante
 * @param myUid   — UID de l'utilisateur
 * @param stopDelay — ms d'inactivité avant d'appeler setTyping(false)
 */
export function createTypingDebouncer(
  convId   : string,
  myUid    : string,
  stopDelay: number = TYPING_STOP_DELAY_MS,
) {
  let _timer: ReturnType<typeof setTimeout> | null = null;
  let _isTyping = false;

  function _startTyping(): void {
    if (!_isTyping) {
      _isTyping = true;
      setTyping(convId, myUid, true).catch(() => {});
    }
    if (_timer) clearTimeout(_timer);
    _timer = setTimeout(_stopTyping, stopDelay);
  }

  function _stopTyping(): void {
    if (_timer) { clearTimeout(_timer); _timer = null; }
    if (_isTyping) {
      _isTyping = false;
      setTyping(convId, myUid, false).catch(() => {});
    }
  }

  return {
    /** À appeler à chaque frappe dans l'input. */
    onInput : _startTyping,
    /** À appeler quand l'input perd le focus ou qu'un message est envoyé. */
    onBlur  : _stopTyping,
    /** Stop immédiat + nettoyage. Appeler à la fermeture de la conversation. */
    destroy : _stopTyping,
  };
}
