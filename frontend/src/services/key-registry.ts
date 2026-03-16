/**
 * key-registry.ts — Registre des clés publiques dans Firestore
 *
 * Invariants de sécurité :
 *  - Ce module ne manipule QUE des clés publiques — jamais de clés privées.
 *  - Aucune donnée personnelle (email, nom) n'est stockée dans Firestore.
 *    L'identité est uniquement le uid Firebase.
 */

import {
  doc,
  setDoc,
  getDoc,
  collection,
  query,
  where,
  getDocs,
} from "firebase/firestore";
import { db } from "./firebase";
import { loadCachedPubKey, saveCachedPubKey } from "./idb-cache";
import { emitCryptoEvent, shortUid } from "./crypto-events";
import type { PublicKeyBundle } from "../types/user";

const publicKeysCol = () => collection(db, "publicKeys");
const publicKeyDoc  = (uid: string) => doc(db, "publicKeys", uid);

// Cache memoire de session — evite N reads Firestore par message dechiffre.
// Invalide uniquement a la deconnexion (clearPublicKeysCache).
const _publicKeysCache = new Map<string, PublicKeyBundle | null>();

export function clearPublicKeysCache(): void {
  _publicKeysCache.clear();
}

/**
 * Publie les clés publiques d'un utilisateur dans Firestore.
 */
export async function publishPublicKeys(uid: string, bundle: PublicKeyBundle): Promise<void> {
  await setDoc(publicKeyDoc(uid), bundle);
  _publicKeysCache.set(uid, bundle); // mettre en cache immediatement
}

/**
 * Récupère le bundle de clés publiques d'un utilisateur depuis Firestore.
 * Retourne null si l'utilisateur n'existe pas.
 * Cache memoire de session pour eviter les reads repetitifs.
 */
export async function getPublicKeys(uid: string): Promise<PublicKeyBundle | null> {
  // 1. Cache mémoire (le plus rapide)
  if (_publicKeysCache.has(uid)) return _publicKeysCache.get(uid)!;

  // 2. Cache IDB persisté (TTL 24h) — évite un read Firestore à chaque reconnexion
  const idbBundle = await loadCachedPubKey(uid);
  if (idbBundle) {
    _publicKeysCache.set(uid, idbBundle);
    return idbBundle;
  }

  // 3. Firestore (fallback)
  emitCryptoEvent({ step: 'firestore:read-pubkey', peerUid: shortUid(uid) });
  const snap = await getDoc(publicKeyDoc(uid));
  const bundle = snap.exists() ? snap.data() as PublicKeyBundle : null;
  _publicKeysCache.set(uid, bundle);
  if (bundle) saveCachedPubKey(uid, bundle).catch(() => {});
  return bundle;
}

/**
 * Récupère les bundles de clés publiques de plusieurs utilisateurs en une passe.
 * Les UIDs inconnus sont silencieusement ignorés (pas de throw).
 */
export async function getPublicKeysBatch(uids: string[]): Promise<Map<string, PublicKeyBundle>> {
  const result = new Map<string, PublicKeyBundle>();
  if (uids.length === 0) return result;

  // Firestore limite les clauses "in" à 30 éléments par requête
  const chunks: string[][] = [];
  for (let i = 0; i < uids.length; i += 30) {
    chunks.push(uids.slice(i, i + 30));
  }
  for (const chunk of chunks) {
    const q    = query(publicKeysCol(), where("uid", "in", chunk));
    const snap = await getDocs(q);
    snap.forEach((d) => {
      const bundle = d.data() as PublicKeyBundle;
      result.set(bundle.uid, bundle);
    });
  }
  return result;
}
