#!/usr/bin/env node
/**
 * AegisQuantum — Supprimer un compte utilisateur
 * Usage : node delete-user.js <username>
 *
 * Supprime dans cet ordre :
 *   1. Messages dans toutes les conversations où l'user est participant
 *   2. Conversations où l'user est participant
 *   3. /publicKeys/{uid}
 *   4. /users/{uid}
 *   5. /provisioned/{uid}  (si présent)
 *   6. Compte Firebase Authentication
 */
import { initializeApp, cert } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { readFileSync, createInterface } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import readline from "readline";

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
const username = process.argv[2];
if (!username) {
  console.error("Usage : node delete-user.js <username>");
  process.exit(1);
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

// ── Confirmation ───────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const confirm = await new Promise(resolve => {
  rl.question(
    `\n⚠️  Vous êtes sur le point de supprimer le compte : ${username} (uid: ${uid})\n` +
    `   Cette action est irréversible.\n\n` +
    `Confirmer la suppression ? [tapez 'supprimer' pour confirmer] : `,
    resolve
  );
});
rl.close();

if (confirm.trim() !== "supprimer") {
  console.log("\n❌  Suppression annulée.\n");
  process.exit(0);
}

// ── Suppression des données Firestore ────────────────────────────────────
console.log("");

// 1. Conversations + messages
const convQuery = await db.collection("conversations")
  .where("participants", "array-contains", uid)
  .get();

if (!convQuery.empty) {
  process.stdout.write(`🗑️  Suppression des messages (${convQuery.size} conversation(s))...`);
  for (const convDoc of convQuery.docs) {
    const messagesSnap = await convDoc.ref.collection("messages").get();
    const typingSnap   = await convDoc.ref.collection("typing").get();
    const batch = db.batch();
    messagesSnap.forEach(m => batch.delete(m.ref));
    typingSnap.forEach(t => batch.delete(t.ref));
    batch.delete(convDoc.ref);
    await batch.commit();
  }
  console.log(" ✔");
} else {
  console.log("   (aucune conversation)");
}

// 2. Clés publiques
process.stdout.write("🗑️  Suppression des clés publiques...");
await db.collection("publicKeys").doc(uid).delete();
console.log(" ✔");

// 3. User document (salt Argon2)
process.stdout.write("🗑️  Suppression du profil utilisateur...");
await db.collection("users").doc(uid).delete();
console.log(" ✔");

// 4. Provisioned (si existant)
const provDoc = await db.collection("provisioned").doc(uid).get();
if (provDoc.exists) {
  await provDoc.ref.delete();
}

// 5. Firebase Authentication
process.stdout.write("🗑️  Suppression du compte Firebase Auth...");
await adminAuth.deleteUser(uid);
console.log(" ✔");

console.log(`\n✅  Compte '${username}' supprimé avec succès.\n`);
