/**
 * auth.ts — Authentification Firebase + dérivation cryptographique
 *
 * Responsabilités :
 *  1. Créer/connecter un compte Firebase Auth (email + password)
 *  2. À l'inscription : générer les paires de clés post-quantiques et
 *     publier les clés publiques dans Firestore via key-registry.ts
 *  3. Dériver une master key depuis le mot de passe via Argon2id pour
 *     chiffrer le vault des clés privées dans IndexedDB via key-store.ts
 *  4. Exposer l'état d'authentification courant (utilisateur connecté)
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
// DÉPENDANCES CRYPTO — à brancher une fois les modules crypto implémentés
// ─────────────────────────────────────────────────────────────────────────────

/**
 * TODO: importer et appeler kemGenerateKeyPair() depuis crypto/kem.ts
 *
 * Signature attendue :
 *   kemGenerateKeyPair(): Promise<KemKeyPair>
 *     → { publicKey: string (Base64, 1184 bytes), privateKey: string (Base64, 2400 bytes) }
 */
async function _generateKemKeyPair(): Promise<KemKeyPair> {
  throw new Error("TODO: brancher kemGenerateKeyPair() depuis crypto/kem.ts");
}

/**
 * TODO: importer et appeler dsaGenerateKeyPair() depuis crypto/dsa.ts
 *
 * Signature attendue :
 *   dsaGenerateKeyPair(): Promise<DsaKeyPair>
 *     → { publicKey: string (Base64), privateKey: string (Base64) }
 *
 * Algorithme : ML-DSA-65 (FIPS 204)
 */
async function _generateDsaKeyPair(): Promise<DsaKeyPair> {
  throw new Error("TODO: brancher dsaGenerateKeyPair() depuis crypto/dsa.ts");
}

/**
 * TODO: importer et appeler argon2Derive() depuis crypto/argon2.ts
 *
 * Signature attendue :
 *   argon2Derive(password: string, salt?: string): Promise<Argon2Result>
 *     → { key: string (Base64, 32 bytes), salt: string (Base64, 16 bytes) }
 *
 * Paramètres Argon2id (specs §4.1.2) :
 *   - memory    : 65536 KiB (64 MiB)
 *   - iterations: 3
 *   - parallelism: 1
 *   - hashLength: 32
 *
 * À l'inscription : ne pas passer de salt (généré aléatoirement).
 * À la connexion  : récupérer le salt depuis Firestore /users/{uid}/argon2Salt
 *                   et le passer en second argument.
 */
async function _argon2Derive(password: string, salt?: string): Promise<Argon2Result> {
  throw new Error("TODO: brancher argon2Derive() depuis crypto/argon2.ts");
}

// ─────────────────────────────────────────────────────────────────────────────
// État local
// ─────────────────────────────────────────────────────────────────────────────

let _currentUser: AQUser | null = null;

/** Retourne l'utilisateur connecté, ou null. */
export function getCurrentUser(): AQUser | null {
  return _currentUser;
}

// Synchronise l'état local avec Firebase Auth
onAuthStateChanged(auth, (firebaseUser: User | null) => {
  if (firebaseUser) {
    _currentUser = { uid: firebaseUser.uid, email: firebaseUser.email ?? "" };
  } else {
    _currentUser = null;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Inscription
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Crée un compte Firebase et initialise toute la crypto post-quantique.
 *
 * Séquence :
 *  1. Firebase Auth createUserWithEmailAndPassword
 *  2. Générer une paire ML-KEM-768   ← _generateKemKeyPair()
 *  3. Générer une paire ML-DSA-65    ← _generateDsaKeyPair()
 *  4. Dériver la master key Argon2id ← _argon2Derive(password)
 *  5. Stocker les clés privées chiffrées dans IndexedDB ← storePrivateKeys()
 *  6. Publier les clés publiques dans Firestore ← publishPublicKeys()
 *
 * @throws Error si la création Firebase échoue ou si une étape crypto échoue
 */
export async function register(email: string, password: string): Promise<AQUser> {
  // 1. Créer le compte Firebase
  const credential = await createUserWithEmailAndPassword(auth, email, password);
  const uid = credential.user.uid;

  // 2 & 3. Générer les paires de clés post-quantiques
  // TODO: décommenter quand crypto/kem.ts et crypto/dsa.ts seront implémentés
  // const kemKeyPair = await _generateKemKeyPair();
  // const dsaKeyPair = await _generateDsaKeyPair();

  // 4. Dériver la master key depuis le mot de passe (Argon2id)
  // TODO: décommenter quand crypto/argon2.ts sera implémenté
  // const { key: masterKey, salt: argon2Salt } = await _argon2Derive(password);

  // 5. Stocker les clés privées chiffrées dans IndexedDB
  // TODO: décommenter après étapes 2-4
  // await storePrivateKeys(uid, {
  //   kemPrivateKey : kemKeyPair.privateKey,
  //   dsaPrivateKey : dsaKeyPair.privateKey,
  //   masterKey,       // utilisé pour chiffrer le vault (AES-GCM via crypto/aes-gcm.ts)
  //   argon2Salt,      // stocké aussi dans Firestore /users/{uid}/argon2Salt pour la reconnexion
  // });

  // 6. Publier les clés publiques dans Firestore
  // TODO: décommenter après étape 2-3
  // await publishPublicKeys(uid, {
  //   uid,
  //   email,
  //   kemPublicKey : kemKeyPair.publicKey,
  //   dsaPublicKey : dsaKeyPair.publicKey,
  //   createdAt    : Date.now(),
  // });

  _currentUser = { uid, email };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Connexion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Connecte un compte existant et déchiffre le vault de clés privées.
 *
 * Séquence :
 *  1. Firebase Auth signInWithEmailAndPassword
 *  2. Récupérer le salt Argon2id depuis Firestore /users/{uid}/argon2Salt
 *  3. Dériver la master key ← _argon2Derive(password, salt)
 *  4. Déchiffrer et charger les clés privées en mémoire ← storePrivateKeys (unlock)
 *
 * @throws Error si les credentials Firebase sont invalides ou si le vault est corrompu
 */
export async function signIn(email: string, password: string): Promise<AQUser> {
  // 1. Authentifier via Firebase
  const credential = await signInWithEmailAndPassword(auth, email, password);
  const uid = credential.user.uid;

  // 2. Récupérer le salt Argon2id depuis Firestore
  // TODO: décommenter quand Firestore schema est défini
  // const userDoc = await getDoc(doc(db, "users", uid));
  // const argon2Salt: string = userDoc.data()?.argon2Salt;
  // if (!argon2Salt) throw new Error("Argon2 salt not found — corrupted account?");

  // 3. Dériver la master key avec le salt récupéré
  // TODO: décommenter quand crypto/argon2.ts sera implémenté
  // const { key: masterKey } = await _argon2Derive(password, argon2Salt);

  // 4. Déchiffrer le vault IndexedDB et charger les clés privées en mémoire
  // TODO: décommenter quand key-store.ts sera complet
  // await unlockPrivateKeys(uid, masterKey);

  _currentUser = { uid, email };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Déconnexion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Déconnecte l'utilisateur et purge les clés privées de la mémoire.
 */
export async function signOut(): Promise<void> {
  clearPrivateKeys();
  await firebaseSignOut(auth);
  _currentUser = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Listener d'état
// ─────────────────────────────────────────────────────────────────────────────

/**
 * S'abonne aux changements d'état d'authentification Firebase.
 * Utilisé par main.ts pour router entre auth-screen et chat-screen.
 *
 * @param callback — appelé avec l'AQUser connecté, ou null si déconnecté
 * @returns unsubscribe function
 */
export function onAuthChange(callback: (user: AQUser | null) => void): () => void {
  return onAuthStateChanged(auth, (firebaseUser) => {
    if (firebaseUser) {
      callback({ uid: firebaseUser.uid, email: firebaseUser.email ?? "" });
    } else {
      callback(null);
    }
  });
}
