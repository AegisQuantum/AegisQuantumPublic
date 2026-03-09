/**
 * auth.ts — Authentification AegisQuantum
 *
 * Stratégie : Firebase Auth exige un format email. L'utilisateur ne saisit
 * qu'un USERNAME + PASSWORD, jamais d'email. En interne on dérive un email
 * fictif non-exposé : username → <username>@aq.local
 *
 * Ce faux email n'est :
 *  - jamais affiché à l'utilisateur
 *  - jamais stocké dans Firestore
 *  - jamais retourné dans AQUser (qui ne contient que `uid`)
 *
 * Pipeline register() :
 *  1. Firebase createUser(fakeEmail, password) → uid
 *  2. kemGenerateKeyPair()  → kemKeyPair
 *  3. dsaGenerateKeyPair()  → dsaKeyPair
 *  4. argon2Derive(password) → { masterKey, salt }
 *  5. storePrivateKeys(uid, { kem, dsa, masterKey, salt }) → IDB chiffré
 *  6. publishPublicKeys(uid, { kemPublicKey, dsaPublicKey }) → Firestore
 *
 * Pipeline signIn() :
 *  1. Firebase signIn(fakeEmail, password) → uid
 *  2. fetchArgon2Salt(uid) ← Firestore /users/{uid}
 *  3. argon2Derive(password, salt) → masterKey
 *  4. unlockPrivateKeys(uid, masterKey) ← IDB → mémoire
 *
 * Prérequis Firebase console :
 *  Authentication → Sign-in method → Email/Password → ENABLED
 */

import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  type User,
} from "firebase/auth";
import { doc, setDoc, getDoc } from "firebase/firestore";
import { auth, db } from "./firebase";
import { storePrivateKeys, clearPrivateKeys, unlockPrivateKeys } from "./key-store";
import { publishPublicKeys } from "./key-registry";
import { kemGenerateKeyPair, dsaGenerateKeyPair, argon2Derive } from "../crypto";
import type { AQUser } from "../types/user";

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires internes
// ─────────────────────────────────────────────────────────────────────────────

/** Dérive un email fictif pour Firebase Auth — jamais affiché ni stocké. */
function toFakeEmail(username: string): string {
  const clean = username.toLowerCase().replace(/[^a-z0-9._-]/g, "");
  if (!clean) throw new Error("Invalid username");
  return `${clean}@aq.local`;
}

/** Valide un username (3–24 chars, alphanum + . _ -). Retourne null si OK. */
export function validateUsername(username: string): string | null {
  if (username.length < 3)  return "Username must be at least 3 characters.";
  if (username.length > 24) return "Username must be at most 24 characters.";
  if (!/^[a-zA-Z0-9._-]+$/.test(username))
    return "Only letters, numbers, . _ - are allowed.";
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// État local
// ─────────────────────────────────────────────────────────────────────────────

let _currentUser: AQUser | null = null;

export function getCurrentUser(): AQUser | null {
  return _currentUser;
}

// Synchroniser _currentUser avec Firebase Auth (rechargement de page)
onAuthStateChanged(auth, (firebaseUser: User | null) => {
  _currentUser = firebaseUser ? { uid: firebaseUser.uid } : null;
});

// ─────────────────────────────────────────────────────────────────────────────
// Inscription
// ─────────────────────────────────────────────────────────────────────────────

export async function register(username: string, password: string): Promise<AQUser> {
  const fakeEmail  = toFakeEmail(username);
  const credential = await createUserWithEmailAndPassword(auth, fakeEmail, password);
  const uid        = credential.user.uid;

  // Générer les paires de clés post-quantiques
  const kemKeyPair = await kemGenerateKeyPair();
  const dsaKeyPair = await dsaGenerateKeyPair();

  // Dériver la master key depuis le password (génère un salt aléatoire)
  const { key: masterKey, salt: argon2Salt } = await argon2Derive(password);

  // Chiffrer et persister les clés privées dans IndexedDB
  await storePrivateKeys(uid, {
    kemPrivateKey: kemKeyPair.privateKey,
    dsaPrivateKey: dsaKeyPair.privateKey,
    masterKey,
    argon2Salt,
  });

  // Stocker le salt Argon2 dans Firestore (nécessaire pour la reconnexion)
  // /users/{uid} → { argon2Salt }  — pas de clés privées ici, jamais
  await setDoc(doc(db, "users", uid), { argon2Salt });

  // Publier les clés publiques dans Firestore /publicKeys/{uid}
  await publishPublicKeys(uid, {
    uid,
    kemPublicKey: kemKeyPair.publicKey,
    dsaPublicKey: dsaKeyPair.publicKey,
    createdAt   : Date.now(),
  });

  _currentUser = { uid };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function signIn(username: string, password: string): Promise<AQUser> {
  const fakeEmail  = toFakeEmail(username);
  const credential = await signInWithEmailAndPassword(auth, fakeEmail, password);
  const uid        = credential.user.uid;

  // Récupérer le salt Argon2 depuis Firestore pour recalculer la master key
  const userDoc = await getDoc(doc(db, "users", uid));
  if (!userDoc.exists()) {
    throw new Error("User profile not found — account may be incomplete.");
  }
  const { argon2Salt } = userDoc.data() as { argon2Salt: string };

  // Recalculer la master key avec le même salt (même password → même key)
  const { key: masterKey } = await argon2Derive(password, argon2Salt);

  // Déchiffrer les clés privées depuis IndexedDB et les charger en mémoire
  await unlockPrivateKeys(uid, masterKey);

  _currentUser = { uid };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Déconnexion
// ─────────────────────────────────────────────────────────────────────────────

export async function signOut(): Promise<void> {
  clearPrivateKeys();         // purge RAM immédiatement
  await firebaseSignOut(auth);
  _currentUser = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Listener d'état d'authentification
// ─────────────────────────────────────────────────────────────────────────────

export function onAuthChange(callback: (user: AQUser | null) => void): () => void {
  return onAuthStateChanged(auth, (firebaseUser: User | null) => {
    callback(firebaseUser ? { uid: firebaseUser.uid } : null);
  });
}
