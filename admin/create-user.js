#!/usr/bin/env node
/**
 * AegisQuantum — Créer un compte utilisateur
 * Usage : node create-user.js <username> [--password <password>]
 */
import { initializeApp, cert } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { createRequire } from "module";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Initialisation Firebase Admin ──────────────────────────────────────────
const keyPath = resolve(__dirname, "serviceAccountKey.json");
try {
  readFileSync(keyPath);
} catch {
  console.error("✘  serviceAccountKey.json introuvable dans admin/");
  console.error("   Firebase Console → Project Settings → Service accounts → Generate new private key");
  process.exit(1);
}

initializeApp({ credential: cert(keyPath) });
const adminAuth = getAuth();
const db        = getFirestore();

// ── Parsing des arguments ──────────────────────────────────────────────────
const args     = process.argv.slice(2);
const username = args[0];
const pwIdx    = args.indexOf("--password");
const password = pwIdx !== -1 ? args[pwIdx + 1] : generatePassword();

if (!username) {
  console.error("Usage : node create-user.js <username> [--password <password>]");
  process.exit(1);
}

if (!/^[a-z0-9_-]{2,30}$/.test(username)) {
  console.error("✘  Username invalide. Utilisez uniquement : a-z, 0-9, _ - (2-30 caractères)");
  process.exit(1);
}

// ── Génération de mot de passe aléatoire ──────────────────────────────────
function generatePassword(length = 12) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#";
  let pw = "";
  const array = new Uint8Array(length);
  // Node.js crypto random
  const { randomFillSync } = await import("crypto").catch(() => ({ randomFillSync: null }));
  if (randomFillSync) {
    randomFillSync(array);
  } else {
    for (let i = 0; i < length; i++) array[i] = Math.floor(Math.random() * chars.length);
  }
  for (let i = 0; i < length; i++) pw += chars[array[i] % chars.length];
  return pw;
}

// ── Création du compte ─────────────────────────────────────────────────────
const email = `${username}@aq.local`;

try {
  const userRecord = await adminAuth.createUser({
    email,
    password,
    displayName: username,
  });

  const uid = userRecord.uid;

  // Créer le document /provisioned/{uid}
  await db.collection("provisioned").doc(uid).set({
    username,
    mustChangePassword: true,
    createdAt: Date.now(),
  });

  // Affichage
  const sep = "─".repeat(46);
  console.log(`\n✅  Compte créé avec succès !\n${sep}`);
  console.log(`  USERNAME  :  ${username}`);
  console.log(`  PASSWORD  :  ${password}`);
  console.log(`  UID       :  ${uid}`);
  console.log(`${sep}\n`);
  console.log("⚠️  Communiquez ces identifiants au client de façon sécurisée.");
  console.log("   Il devra changer son mot de passe à la première connexion.\n");

} catch (err) {
  if (err.code === "auth/email-already-exists") {
    console.error(`✘  Le nom d'utilisateur '${username}' existe déjà.`);
  } else {
    console.error("✘  Erreur lors de la création du compte :", err.message);
  }
  process.exit(1);
}
