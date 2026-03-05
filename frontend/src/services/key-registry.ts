/**
 * key-registry.ts — Registre des clés publiques dans Firestore
 *
 * Responsabilités :
 *  - Publier les clés publiques d'un utilisateur dans /publicKeys/{uid} à l'inscription
 *  - Lire les clés publiques d'un contact pour lui envoyer un message
 *  - Rechercher des utilisateurs par email pour démarrer une conversation
 *
 * Invariants de sécurité :
 *  - Ce module ne manipule QUE des clés publiques — jamais de clés privées.
 *  - Les données écrites dans Firestore sont lisibles par tout utilisateur connecté
 *    (selon les règles Firestore /publicKeys/{uid} — lecture publique, écriture owner only).
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

// ─────────────────────────────────────────────────────────────────────────────
// Paths Firestore
// ─────────────────────────────────────────────────────────────────────────────

/** /publicKeys/{uid} — bundle de clés publiques d'un utilisateur */
const publicKeysCol = () => collection(db, "publicKeys");
const publicKeyDoc  = (uid: string) => doc(db, "publicKeys", uid);

// ─────────────────────────────────────────────────────────────────────────────
// API publique
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Publie les clés publiques d'un utilisateur dans Firestore.
 * Appelé par auth.ts → register() après la génération des clés.
 *
 * @param uid    — UID Firebase
 * @param bundle — { uid, email, kemPublicKey, dsaPublicKey, createdAt }
 *   - kemPublicKey : Base64 (1184 bytes) — vient de kemGenerateKeyPair() dans crypto/kem.ts
 *   - dsaPublicKey : Base64 — vient de dsaGenerateKeyPair() dans crypto/dsa.ts
 *
 * @throws Error si l'écriture Firestore échoue
 */
export async function publishPublicKeys(uid: string, bundle: PublicKeyBundle): Promise<void> {
  await setDoc(publicKeyDoc(uid), bundle);
}

/**
 * Récupère le bundle de clés publiques d'un utilisateur depuis Firestore.
 *
 * Appelé par :
 *  - messaging.ts → sendMessage() pour récupérer kemPublicKey du destinataire
 *    et appeler kemEncapsulate() dans crypto/kem.ts
 *  - ui/fingerprint.ts pour afficher les Safety Numbers (hash SHA-256 de dsaPublicKey)
 *
 * @param uid — UID Firebase du contact
 * @returns PublicKeyBundle ou null si l'utilisateur n'existe pas / n'a pas de clés
 */
export async function getPublicKeys(uid: string): Promise<PublicKeyBundle | null> {
  const snap = await getDoc(publicKeyDoc(uid));
  if (!snap.exists()) return null;
  return snap.data() as PublicKeyBundle;
}

/**
 * Recherche un utilisateur par adresse email dans Firestore.
 *
 * Appelé par ui/chat.ts → "New conversation" pour trouver le destinataire.
 *
 * @param email — adresse email à rechercher
 * @returns PublicKeyBundle du premier résultat, ou null si introuvable
 */
export async function findUserByEmail(email: string): Promise<PublicKeyBundle | null> {
  const q    = query(publicKeysCol(), where("email", "==", email));
  const snap = await getDocs(q);
  if (snap.empty) return null;
  return snap.docs[0].data() as PublicKeyBundle;
}

/**
 * Récupère les bundles de clés publiques de plusieurs utilisateurs en une passe.
 *
 * Appelé par ui/chat.ts pour afficher la liste de contacts avec leurs infos.
 *
 * @param uids — liste d'UIDs Firebase
 * @returns Map uid → PublicKeyBundle (les UIDs introuvables sont absents de la Map)
 */
export async function getPublicKeysBatch(uids: string[]): Promise<Map<string, PublicKeyBundle>> {
  const result = new Map<string, PublicKeyBundle>();
  // Firestore ne supporte pas les `in` queries > 30 éléments — chunker si besoin
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
