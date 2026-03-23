#!/usr/bin/env node
/**
 * AegisQuantum — Lister les comptes utilisateurs
 * Usage : node list-users.js
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

// ── Chargement des utilisateurs ────────────────────────────────────────────
const listResult = await adminAuth.listUsers(1000);
const users      = listResult.users;

if (users.length === 0) {
  console.log("\n  Aucun utilisateur.\n");
  process.exit(0);
}

// Récupérer les docs /provisioned/ pour savoir si MDP changé
const provisionedDocs = await db.collection("provisioned").get();
const provisionedUids = new Set(provisionedDocs.docs.map(d => d.id));

// ── Affichage ──────────────────────────────────────────────────────────────
const sep = "─".repeat(72);
console.log(`\n${sep}`);
console.log(
  "  USERNAME".padEnd(22) +
  "UID".padEnd(30) +
  "MDP CHANGÉ ?".padEnd(16) +
  "CRÉÉ LE"
);
console.log(sep);

for (const u of users) {
  const username   = (u.displayName || u.email?.split("@")[0] || "?").padEnd(20);
  const uid        = u.uid.padEnd(28);
  const changed    = provisionedUids.has(u.uid) ? "⚠️  non  " : "✅  oui  ";
  const createdAt  = u.metadata.creationTime
    ? new Date(u.metadata.creationTime).toLocaleDateString("fr-FR")
    : "?";
  console.log(`  ${username}  ${uid}  ${changed}    ${createdAt}`);
}

console.log(sep);
console.log(`\n  Total : ${users.length} compte(s)\n`);
