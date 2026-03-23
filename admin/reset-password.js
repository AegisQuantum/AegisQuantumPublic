#!/usr/bin/env node
/**
 * AegisQuantum — Réinitialiser le mot de passe d'un utilisateur
 * Usage : node reset-password.js <username> [--password <new_password>]
 *
 * ⚠️ L'utilisateur devra aussi importer son .aqsession après le reset,
 *    car sa vaultKey dépend de l'ancien mot de passe.
 */
import { initializeApp, cert } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Initialisation Firebase Admin ──────────────────────────────────────────
const keyPath = resolve(__dirname, "serviceAccountKey.json");
try { readFileSync(keyPath); } catch {
  console.error("✘  serviceAccountKey.json introuvable dans admin/");
  process.exit(1);
}

initializeApp({ credential: cert(keyPath) });
const adminAuth = getAuth();
const db        = getFirestore();

// ── Parsing des arguments ──────────────────────────────────────────────────
const args     = process.argv.slice(2);
const username = args[0];
const pwIdx    = args.indexOf("--password");
const newPw    = pwIdx !== -1 ? args[pwIdx + 1] : generatePassword();

if (!username) {
  console.error("Usage : node reset-password.js <username> [--password <new_password>]");
  process.exit(1);
}

function generatePassword(length = 12) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#";
  let pw = "";
  for (let i = 0; i < length; i++) pw += chars[Math.floor(Math.random() * chars.length)];
  return pw;
}

// ── Trouver l'UID ──────────────────────────────────────────────────────────
const email = `${username}@aq.local`;
let uid;
try {
  const user = await adminAuth.getUserByEmail(email);
  uid = user.uid;
} catch {
  console.error(`✘  Utilisateur '${username}' introuvable.`);
  process.exit(1);
}

// ── Reset ──────────────────────────────────────────────────────────────────
await adminAuth.updateUser(uid, { password: newPw });

// Forcer le changement de mot de passe à la prochaine connexion
await db.collection("provisioned").doc(uid).set({
  username,
  mustChangePassword: true,
  resetAt: Date.now(),
}, { merge: true });

// Affichage
const sep = "─".repeat(42);
console.log(`\n✅  Mot de passe réinitialisé pour : ${username}\n${sep}`);
console.log(`  USERNAME    :  ${username}`);
console.log(`  NEW PASSWORD:  ${newPw}`);
console.log(`${sep}\n`);
console.log("⚠️  L'utilisateur devra aussi importer son .aqsession");
console.log("   pour retrouver ses clés privées (vault lié à l'ancien MDP).\n");
