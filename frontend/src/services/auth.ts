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
 * Prérequis Firebase console :
 *  Authentication → Sign-in method → Email/Password → ENABLED
 *  (le second toggle "Email link / passwordless" doit rester OFF)
 */

import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  type User,
} from "firebase/auth";
import { auth } from "./firebase";
import { clearPrivateKeys } from "./key-store";
import type { AQUser } from "../types/user";
import type { KemKeyPair, DsaKeyPair, Argon2Result } from "../types/crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Stubs crypto (branchés quand crypto/ sera implémenté)
// ─────────────────────────────────────────────────────────────────────────────

async function _generateKemKeyPair(): Promise<KemKeyPair> {
  throw new Error("TODO: kemGenerateKeyPair()");
}
void _generateKemKeyPair;

async function _generateDsaKeyPair(): Promise<DsaKeyPair> {
  throw new Error("TODO: dsaGenerateKeyPair()");
}
void _generateDsaKeyPair;

async function _argon2Derive(_password: string, _salt?: string): Promise<Argon2Result> {
  throw new Error("TODO: argon2Derive()");
}
void _argon2Derive;

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaire interne : username → faux email Firebase
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Dérive un email fictif à partir d'un username.
 * Firebase Auth requiert un email valide — on utilise ce faux email uniquement
 * comme clé de connexion interne. Il n'est jamais visible ni stocké ailleurs.
 */
function toFakeEmail(username: string): string {
  const clean = username.toLowerCase().replace(/[^a-z0-9._-]/g, "");
  if (!clean) throw new Error("Invalid username");
  return `${clean}@aq.local`;
}

/**
 * Valide qu'un username est acceptable (3–24 chars, alphanum + . _ -)
 * Retourne un message d'erreur ou null si OK.
 */
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

// Synchroniser _currentUser avec Firebase Auth (ex : rechargement de page)
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

  // TODO: décommenter quand crypto/ sera implémenté
  // const kemKeyPair = await _generateKemKeyPair();
  // const dsaKeyPair = await _generateDsaKeyPair();
  // const { key: masterKey, salt: argon2Salt } = await _argon2Derive(password);
  // await storePrivateKeys(uid, {
  //   kemPrivateKey: kemKeyPair.privateKey,
  //   dsaPrivateKey: dsaKeyPair.privateKey,
  //   masterKey,
  //   argon2Salt,
  // });
  // await publishPublicKeys(uid, {
  //   uid,
  //   kemPublicKey: kemKeyPair.publicKey,
  //   dsaPublicKey: dsaKeyPair.publicKey,
  //   createdAt   : Date.now(),
  // });

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

  // TODO: décommenter quand crypto/ sera implémenté
  // const argon2Salt = await fetchArgon2Salt(uid);
  // const { key: masterKey } = await _argon2Derive(password, argon2Salt);
  // await unlockPrivateKeys(uid, masterKey);

  _currentUser = { uid };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Déconnexion
// ─────────────────────────────────────────────────────────────────────────────

export async function signOut(): Promise<void> {
  clearPrivateKeys();
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
