/**
 * auth.ts — Authentification AegisQuantum
 */


import {
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  updatePassword,
  deleteUser,
  type User,
} from "firebase/auth";
import {
  doc, getDoc, setDoc, collection, getDocs, deleteDoc, writeBatch, query, where,
} from "firebase/firestore";
import { auth, db } from "./firebase";
import { clearPrivateKeys, storePrivateKeys, unlockPrivateKeys, getKemPrivateKey, getDsaPrivateKey, deleteVault, deleteAllRatchetStatesForUser } from "./key-store";
import { resetMessagingState } from "./messaging";
import { publishPublicKeys, getPublicKeys, clearPublicKeysCache } from "./key-registry";
import { kemGenerateKeyPair, dsaGenerateKeyPair, argon2Derive } from "../crypto";
import { clearAllCachesForAccount } from "./idb-cache";
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
// Erreur typée : vault IDB absent alors que des clés publiques existent
// ─────────────────────────────────────────────────────────────────────────────

/** Lancée par signIn() quand Firebase Auth réussit mais le vault IDB est vide.
 *  L'UI doit proposer l'import .aqsession (ou la régénération des clés).  */
export class VaultMissingError extends Error {
  constructor(public readonly uid: string) {
    super("VAULT_MISSING");
    this.name = "VaultMissingError";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline crypto principal
// ─────────────────────────────────────────────────────────────────────────────

export async function loadCryptoKeys(uid: string, password: string): Promise<void> {

  try { getKemPrivateKey(uid); return; } catch { /* not in memory, proceed */ }

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
    throw new VaultMissingError(uid);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function signIn(username: string, password: string): Promise<AQUser> {
  // Nettoie l'état de la session précédente (retry sets, ratchet locks…)
  // indispensable pour les changements de compte sans rechargement de page.
  resetMessagingState();
  clearPrivateKeys();
  clearPublicKeysCache();

  const fakeEmail  = toFakeEmail(username);
  const credential = await signInWithEmailAndPassword(auth, fakeEmail, password);
  const uid        = credential.user.uid;
  await loadCryptoKeys(uid, password); // peut lever VaultMissingError → propagée telle quelle
  _currentUser = { uid };
  return _currentUser;
}

// ─────────────────────────────────────────────────────────────────────────────
// Régénération des clés (utilisé par l'écran de récupération "repartir de zéro")
// ─────────────────────────────────────────────────────────────────────────────

/** Génère et publie une nouvelle paire de clés. DÉTRUIT l'accès aux conversations
 *  existantes (les contacts ont toujours l'ancienne clé publique en cache).
 *  À n'utiliser que si l'utilisateur accepte de tout perdre. */
export async function generateFreshKeys(uid: string, password: string): Promise<void> {
  await _generateAndPublishKeys(uid, password);
}

// ─────────────────────────────────────────────────────────────────────────────
// Changement de mot de passe (première connexion obligatoire)
// ─────────────────────────────────────────────────────────────────────────────

export async function changePassword(uid: string, newPassword: string): Promise<void> {
  const firebaseUser = auth.currentUser;
  if (!firebaseUser) throw new Error("Not authenticated");

  // 1. Changer le mot de passe Firebase Auth
  await updatePassword(firebaseUser, newPassword);

  // 2. Récupérer les clés privées déjà en mémoire
  const kemPrivateKey = getKemPrivateKey(uid);
  const dsaPrivateKey = getDsaPrivateKey(uid);

  // --- FIX TS: On vérifie que les clés sont présentes ---
  if (!kemPrivateKey || !dsaPrivateKey) {
    throw new Error("Clés privées introuvables en mémoire. Reconnexion requise.");
  }

  // 3. Re-chiffrer le vault avec le nouveau mot de passe
  const { key: newMasterKey, salt: newArgon2Salt } = await argon2Derive(newPassword);

  await storePrivateKeys(uid, {
    kemPrivateKey, // Maintenant garanti string
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
  resetMessagingState();
  await firebaseSignOut(auth);
  _currentUser = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppression de compte
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Supprime définitivement le compte de l'utilisateur.
 *
 * Séquence :
 *  1. Récupère toutes les conversations de l'utilisateur.
 *  2. Pour chaque conversation : si l'autre participant n'a plus de clés publiques
 *     (compte supprimé), supprime la conversation et tous ses messages.
 *  3. Supprime les documents Firestore personnels (users, publicKeys, provisioned).
 *  4. Purge le vault IDB, les états ratchet et tous les caches locaux.
 *  5. Nettoie le localStorage.
 *  6. Supprime le compte Firebase Auth (doit être en dernier — révoque le token).
 */
export async function deleteAccount(uid: string): Promise<void> {
  const firebaseUser = auth.currentUser;
  if (!firebaseUser) throw new Error("Not authenticated");

  const batch = writeBatch(db);

  // 1. Conversations — supprimer celles dont l'autre participant est aussi parti
  const convsSnap = await getDocs(
    query(collection(db, "conversations"), where("participants", "array-contains", uid))
  );

  for (const convDoc of convsSnap.docs) {
    const data = convDoc.data() as { participants: string[] };
    const otherUid = data.participants.find(p => p !== uid);

    if (otherUid) {
      const otherKeys = await getPublicKeys(otherUid);
      if (!otherKeys) {
        // Autre participant aussi supprimé → purger la conversation
        const msgsSnap = await getDocs(
          collection(db, "conversations", convDoc.id, "messages")
        );
        for (const msgDoc of msgsSnap.docs) batch.delete(msgDoc.ref);
        batch.delete(convDoc.ref);
      }
    }
  }

  // 2. Documents personnels Firestore
  batch.delete(doc(db, "users",      uid));
  batch.delete(doc(db, "publicKeys", uid));

  const provSnap = await getDoc(doc(db, "provisioned", uid));
  if (provSnap.exists()) batch.delete(doc(db, "provisioned", uid));

  await batch.commit();

  // 2b. Invalider le cache mémoire des clés publiques (key-registry garde un cache
  //     en mémoire pour éviter des reads Firestore répétés ; il faut le vider
  //     pour que getPublicKeys renvoie null après la suppression Firestore).
  clearPublicKeysCache(uid);

  // 3. Purge IDB
  await deleteVault(uid);
  await deleteAllRatchetStatesForUser(uid);
  await clearAllCachesForAccount(uid);

  // 4. Purge localStorage
  // localStorage.key(i) fonctionne dans tous les environnements (jsdom/happy-dom/browser).
  // Object.keys(localStorage) renvoie [] dans certains runtimes de test.
  const _lsKeys: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k?.startsWith("aq:")) _lsKeys.push(k);
  }
  _lsKeys.forEach(k => localStorage.removeItem(k));

  // 5. Suppression Firebase Auth (révoque le token — doit être en dernier)
  resetMessagingState();
  clearPrivateKeys();
  _currentUser = null;
  await deleteUser(firebaseUser);
}

// ─────────────────────────────────────────────────────────────────────────────
// Listener
// ─────────────────────────────────────────────────────────────────────────────

export function onAuthChange(callback: (user: AQUser | null) => void): () => void {
  return onAuthStateChanged(auth, (firebaseUser: User | null) => {
    callback(firebaseUser ? { uid: firebaseUser.uid } : null);
  });
}
