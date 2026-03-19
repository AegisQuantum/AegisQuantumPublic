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
import type { PublicKeyBundle } from "../types/user";

const publicKeysCol = () => collection(db, "publicKeys");
const publicKeyDoc  = (uid: string) => doc(db, "publicKeys", uid);

// Cache mémoire avec TTL de 5 minutes.
// Sans TTL, une régénération de clés (generateFreshKeys) ne serait jamais
// détectée par les contacts pendant toute la durée de la session.
const PUBKEY_TTL_MS = 5 * 60 * 1000; // 5 min

interface CachedEntry { bundle: PublicKeyBundle; cachedAt: number; }
const _publicKeysCache = new Map<string, CachedEntry>();

/**
 * Publie les clés publiques d'un utilisateur dans Firestore.
 */
export async function publishPublicKeys(uid: string, bundle: PublicKeyBundle): Promise<void> {
  await setDoc(publicKeyDoc(uid), bundle);
  _publicKeysCache.set(uid, { bundle, cachedAt: Date.now() });
}

/**
 * Invalide le cache mémoire d'un uid (ex. après generateFreshKeys).
 */
export function clearPublicKeysCache(uid?: string): void {
  if (uid) _publicKeysCache.delete(uid);
  else     _publicKeysCache.clear();
}

/**
 * Récupère le bundle de clés publiques d'un utilisateur depuis Firestore.
 * Retourne null si l'utilisateur n'existe pas.
 * Les clés sont mises en cache mémoire — 1 seul read Firestore par uid par session.
 */
export async function getPublicKeys(uid: string): Promise<PublicKeyBundle | null> {
  const entry = _publicKeysCache.get(uid);
  if (entry && Date.now() - entry.cachedAt < PUBKEY_TTL_MS) return entry.bundle;

  const snap = await getDoc(publicKeyDoc(uid));
  if (!snap.exists()) return null;
  const bundle = snap.data() as PublicKeyBundle;
  _publicKeysCache.set(uid, { bundle, cachedAt: Date.now() });
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
