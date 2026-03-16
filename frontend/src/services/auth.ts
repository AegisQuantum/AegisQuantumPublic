/**
 * auth.ts — Authentification AegisQuantum
 */

import {
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  updatePassword,
  type User,
} from "firebase/auth";
import { doc, getDoc, setDoc } from "firebase/firestore";
import { auth, db } from "./firebase";
import { clearPrivateKeys, storePrivateKeys, unlockPrivateKeys, getKemPrivateKey, getDsaPrivateKey } from "./key-store";
import { publishPublicKeys, getPublicKeys } from "./key-registry";
import { kemGenerateKeyPair, dsaGenerateKeyPair, argon2Derive } from "../crypto";
import type { AQUser } from "../types/user";

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires
// ─────────────────────────────────────────────────────────────────────────────

function toFakeEmail(username: string): string {
  const clean = username.toLowerCase().replace(/[^a-z0-9._-]/g, "");
  if (!clean) throw new Error("Invalid username");
  return `${clean}@aq.local`;
}

export function validateUsername(username: string): string | null {
  if (username.length < 3)  return "Username must be at least 3 characters.";
  if (username.length > 24) return "Username must be at most 24 characters.";
  if (!/^[a-zA-Z0-9._-]+$/.test(username)) return "Only letters, numbers, . _ - are allowed.";
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// État local
// ─────────────────────────────────────────────────────────────────────────────

let _currentUser: AQUser | null = null;

export function getCurrentUser(): AQUser | null { return _currentUser; }

onAuthStateChanged(auth, (firebaseUser: User | null) => {
  _currentUser = firebaseUser ? { uid: firebaseUser.uid } : null;
});

// ─────────────────────────────────────────────────────────────────────────────
// Helper interne — génère + publie de nouvelles clés
// Appelé à la première connexion OU quand le vault IDB est absent/corrompu
// ─────────────────────────────────────────────────────────────────────────────

async function _generateAndPublishKeys(uid: string, password: string): Promise<void> {
  console.log("[AQ:crypto] Génération d'une nouvelle paire de clés…");

  const [kemKeyPair, dsaKeyPair] = await Promise.all([
    kemGenerateKeyPair(),
    dsaGenerateKeyPair(),
  ]);

  const { key: masterKey, salt: argon2Salt } = await argon2Derive(password);

  // Vault chiffré en IDB + clés en mémoire
  await storePrivateKeys(uid, {
    kemPrivateKey: kemKeyPair.privateKey,
    dsaPrivateKey: dsaKeyPair.privateKey,
    masterKey,
    argon2Salt,
  });

  // Clés publiques dans Firestore (écrase l'ancienne paire si elle existait)
  await publishPublicKeys(uid, {
    uid,
    kemPublicKey: kemKeyPair.publicKey,
    dsaPublicKey: dsaKeyPair.publicKey,
    createdAt: Date.now(),
  });

  // Salt Argon2 dans Firestore pour les reconnexions futures
  await setDoc(doc(db, "users", uid), { argon2Salt });

  console.log("[AQ:crypto] Clés générées et publiées ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline crypto principal
// ─────────────────────────────────────────────────────────────────────────────

export async function loadCryptoKeys(uid: string, password: string): Promise<void> {
  const existingPublicKeys = await getPublicKeys(uid);

  if (!existingPublicKeys) {
    // ── Première connexion ──────────────────────────────────────────────────
    console.log("[AQ:crypto] Première connexion…");
    await _generateAndPublishKeys(uid, password);
    return;
  }

  // ── Reconnexion : tenter de déchiffrer le vault IDB ─────────────────────
  console.log("[AQ:crypto] Reconnexion — déchiffrement du vault…");

  const userDoc = await getDoc(doc(db, "users", uid));
  if (!userDoc.exists()) {
    // /users/{uid} absent → vault impossible à déchiffrer → régénérer
    console.warn("[AQ:crypto] /users doc absent — régénération des clés…");
    await _generateAndPublishKeys(uid, password);
    return;
  }

  const { argon2Salt } = userDoc.data() as { argon2Salt: string };
  const { key: masterKey } = await argon2Derive(password, argon2Salt);

  try {
    await unlockPrivateKeys(uid, masterKey);
    console.log("[AQ:crypto] Vault déchiffré ✓");
  } catch (e) {
    // Vault IDB absent ou corrompu.
    //
    // CRITIQUE : des clés publiques existent déjà dans Firestore, ce qui signifie
    // que des messages ont été échangés avec ces clés. Régénérer ici écraserait
    // les clés publiques → tous les anciens messages deviendraient indéchiffrables
    // et la communication avec les contacts serait rompue silencieusement.
    //
    // On leve une erreur explicite pour que l'UI puisse avertir l'utilisateur
    // ("Vos clés locales sont introuvables. Effacez vos données et recréez un compte.").
    // Ne jamais régénérer silencieusement quand des clés publiques existent déjà.
    console.error("[AQ:crypto] Vault IDB introuvable alors que des clés publiques existent dans Firestore.");
    throw new Error(
      "VAULT_MISSING: Vos cl\u00e9s priv\u00e9es locales sont introuvables (IDB vid\u00e9 ?). " +
      "Impossible de se connecter sans elles — r\u00e9g\u00e9n\u00e9rer casserait toutes vos conversations. " +
      "Pour repartir de z\u00e9ro : supprimez votre compte et recr\u00e9ez-en un."
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function signIn(username: string, password: string): Promise<AQUser> {
  const fakeEmail  = toFakeEmail(username);
  const credential = await signInWithEmailAndPassword(auth, fakeEmail, password);
  const uid        = credential.user.uid;
  await loadCryptoKeys(uid, password);
  _currentUser = { uid };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Changement de mot de passe (première connexion obligatoire)
// ─────────────────────────────────────────────────────────────────────────────

export async function changePassword(uid: string, newPassword: string): Promise<void> {
  const firebaseUser = auth.currentUser;
  if (!firebaseUser) throw new Error("Not authenticated");

  // 1. Changer le mot de passe Firebase Auth
  await updatePassword(firebaseUser, newPassword);

  // 2. Récupérer les clés privées déjà en mémoire (chargées lors du signIn)
  const kemPrivateKey = getKemPrivateKey(uid);
  const dsaPrivateKey = getDsaPrivateKey(uid);

  // 3. Re-chiffrer le vault avec le nouveau mot de passe (nouveau salt Argon2)
  const { key: newMasterKey, salt: newArgon2Salt } = await argon2Derive(newPassword);

  await storePrivateKeys(uid, {
    kemPrivateKey,
    dsaPrivateKey,
    masterKey:  newMasterKey,
    argon2Salt: newArgon2Salt,
  });

  // 4. Mettre à jour le salt dans Firestore
  await setDoc(doc(db, "users", uid), { argon2Salt: newArgon2Salt });

  // 5. Marquer mustChangePassword = false
  const provSnap = await getDoc(doc(db, "provisioned", uid));
  if (provSnap.exists()) {
    await setDoc(doc(db, "provisioned", uid), { mustChangePassword: false }, { merge: true });
  }

  console.log("[AQ:auth] Mot de passe changé et vault re-chiffré ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// Vérification première connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function mustChangePassword(uid: string): Promise<boolean> {
  const snap = await getDoc(doc(db, "provisioned", uid));
  if (!snap.exists()) return false;
  return (snap.data() as { mustChangePassword?: boolean }).mustChangePassword === true;
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
// Listener
// ─────────────────────────────────────────────────────────────────────────────

export function onAuthChange(callback: (user: AQUser | null) => void): () => void {
  return onAuthStateChanged(auth, (firebaseUser: User | null) => {
    callback(firebaseUser ? { uid: firebaseUser.uid } : null);
  });
}
