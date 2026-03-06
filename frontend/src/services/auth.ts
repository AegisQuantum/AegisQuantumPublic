/**
 * auth.ts — Authentification Firebase + dérivation cryptographique
 */

import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  type User,
} from "firebase/auth";
import { auth } from "./firebase";
import { storePrivateKeys, clearPrivateKeys } from "./key-store";
import { publishPublicKeys } from "./key-registry";
import type { AQUser } from "../types/user";
import type { KemKeyPair, DsaKeyPair, Argon2Result } from "../types/crypto";

// ─────────────────────────────────────────────────────────────────────────────
// DÉPENDANCES CRYPTO
// ─────────────────────────────────────────────────────────────────────────────

async function _generateKemKeyPair(): Promise<KemKeyPair> {
  throw new Error("TODO: brancher kemGenerateKeyPair() depuis crypto/kem.ts");
}

async function _generateDsaKeyPair(): Promise<DsaKeyPair> {
  throw new Error("TODO: brancher dsaGenerateKeyPair() depuis crypto/dsa.ts");
}

async function _argon2Derive(password: string, salt?: string): Promise<Argon2Result> {
  throw new Error("TODO: brancher argon2Derive() depuis crypto/argon2.ts");
}

// ─────────────────────────────────────────────────────────────────────────────
// État local
// ─────────────────────────────────────────────────────────────────────────────

let _currentUser: AQUser | null = null;

export function getCurrentUser(): AQUser | null {
  return _currentUser;
}

onAuthStateChanged(auth, (firebaseUser: User | null) => {
  if (firebaseUser) {
    _currentUser = { uid: firebaseUser.uid };
  } else {
    _currentUser = null;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Inscription
// ─────────────────────────────────────────────────────────────────────────────

export async function register(email: string, password: string): Promise<AQUser> {
  const credential = await createUserWithEmailAndPassword(auth, email, password);
  const uid = credential.user.uid;

  // TODO: décommenter quand les modules crypto seront implémentés
  // const kemKeyPair = await _generateKemKeyPair();
  // const dsaKeyPair = await _generateDsaKeyPair();
  // const { key: masterKey, salt: argon2Salt } = await _argon2Derive(password);
  // await storePrivateKeys(uid, { kemPrivateKey: kemKeyPair.privateKey, dsaPrivateKey: dsaKeyPair.privateKey, masterKey, argon2Salt });
  // await publishPublicKeys(uid, { uid, kemPublicKey: kemKeyPair.publicKey, dsaPublicKey: dsaKeyPair.publicKey, createdAt: Date.now() });

  _currentUser = { uid };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function signIn(email: string, password: string): Promise<AQUser> {
  const credential = await signInWithEmailAndPassword(auth, email, password);
  const uid = credential.user.uid;

  // TODO: unlock vault depuis IndexedDB
  // const userDoc = await getDoc(doc(db, "users", uid));
  // const argon2Salt: string = userDoc.data()?.argon2Salt;
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
// Listener d'état
// ─────────────────────────────────────────────────────────────────────────────

export function onAuthChange(callback: (user: AQUser | null) => void): () => void {
  return onAuthStateChanged(auth, (firebaseUser) => {
    if (firebaseUser) {
      callback({ uid: firebaseUser.uid });
    } else {
      callback(null);
    }
  });
}
