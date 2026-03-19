/**
 * session-keys.ts — Export / Import des clés de session
 *
 * Permet d'exporter les clés privées (ML-KEM-768 + ML-DSA-65) et tous les états
 * ratchet dans un fichier chiffré .aqsession, déchiffrable grâce à une phrase
 * mnémotechnique de 10 mots.
 *
 * Format du fichier .aqsession :
 * {
 *   v        : 2,
 *   salt     : string,       // Base64 — salt Argon2id 16 bytes
 *   nonce    : string,       // Base64 — AES-GCM nonce 12 bytes
 *   ciphertext: string,      // Base64 — AES-256-GCM(JSON de SessionExportPayload)
 * }
 *
 * Sécurité :
 *  - Entropie phrase : 80 bits (10 mots × 8 bits)
 *  - Argon2id (64 MB, 3 it.) renforce la résistance au brute-force
 *  - AES-256-GCM garantit confidentialité + intégrité
 *  - Les clés privées ne transitent jamais via Firestore ni réseau
 */

import { argon2Derive }                                       from "../crypto/argon2";
import { aesGcmEncrypt, aesGcmDecrypt }                       from "../crypto/aes-gcm";
import { generateMnemonic }                                   from "../crypto/mnemonic";
import {
  getKemPrivateKey,
  getDsaPrivateKey,
  storePrivateKeys,
  getAllRatchetStates,
  restoreRatchetState,
  saveMsgCache,
}                                                             from "./key-store";
import { loadCachedMessages, saveCachedMessages }             from "./idb-cache";
import { db }                                                 from "./firebase";
import { doc, setDoc }                                        from "firebase/firestore";
import type { DecryptedMessage }                              from "../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface SessionExportPayload {
  v           : 2;
  uid         : string;
  exportedAt  : number;
  kemPrivateKey: string;  // Base64 — ML-KEM-768
  dsaPrivateKey: string;  // Base64 — ML-DSA-65
  ratchetStates  : Array<{ convId: string; stateJson: string }>;
  messageCaches ?: Array<{ convId: string; msgs: DecryptedMessage[]; lastTs: number }>;
}

export interface SessionFile {
  v         : 2;
  salt      : string;
  nonce     : string;
  ciphertext: string;
}

export interface SessionExportResult {
  fileJson: string;       // JSON du fichier .aqsession (à télécharger)
  mnemonic: string[];     // 10 mots à noter
}

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Exporte les clés de session (clés privées + états ratchet) chiffrées avec
 * une phrase mnémotechnique de 10 mots générée automatiquement.
 *
 * @param uid         — UID de l'utilisateur connecté
 * @param onProgress  — callback optionnel (phase en cours)
 * @returns { fileJson, mnemonic } — JSON du fichier et les 10 mots à noter
 */
export async function exportSessionKeys(
  uid        : string,
  onProgress?: (phase: "generating" | "collecting" | "deriving" | "encrypting" | "done") => void,
): Promise<SessionExportResult> {
  onProgress?.("generating");
  const mnemonic = generateMnemonic();
  const phrase   = mnemonic.join(" ");

  onProgress?.("collecting");
  const kemPrivateKey  = getKemPrivateKey(uid);
  const dsaPrivateKey  = getDsaPrivateKey(uid);
  const ratchetStates  = await getAllRatchetStates(uid);

  // Collecter les plaintexts mis en cache pour chaque conversation connue.
  // Indispensable pour lire les anciens messages sur un nouvel appareil :
  // le ratchet ne peut pas redéchiffrer le passé (forward secrecy).
  const messageCaches: Array<{ convId: string; msgs: DecryptedMessage[]; lastTs: number }> = [];
  for (const { convId } of ratchetStates) {
    const cached = await loadCachedMessages(convId);
    if (cached && cached.msgs.length > 0) {
      messageCaches.push({ convId, msgs: cached.msgs, lastTs: cached.lastTs });
    }
  }

  const payload: SessionExportPayload = {
    v           : 2,
    uid,
    exportedAt  : Date.now(),
    kemPrivateKey,
    dsaPrivateKey,
    ratchetStates,
    messageCaches,
  };

  onProgress?.("deriving");
  const { key, salt } = await argon2Derive(phrase);

  onProgress?.("encrypting");
  const { ciphertext, nonce } = await aesGcmEncrypt(JSON.stringify(payload), key);

  const file: SessionFile = { v: 2, salt, nonce, ciphertext };

  onProgress?.("done");
  return { fileJson: JSON.stringify(file), mnemonic };
}

/**
 * Déclenche le téléchargement du fichier .aqsession.
 */
export function downloadSessionFile(fileJson: string): void {
  const blob = new Blob([fileJson], { type: "application/octet-stream" });
  const url  = URL.createObjectURL(blob);
  const date = new Date().toISOString().slice(0, 10);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `aegisquantum-session-${date}.aqsession`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Import
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Importe les clés de session depuis un fichier .aqsession et une phrase mnémotechnique.
 *
 * Restaure les clés privées en mémoire et dans IndexedDB, ainsi que tous les états ratchet.
 *
 * @param fileContent  — contenu JSON du fichier .aqsession
 * @param mnemonic     — tableau de 10 mots (phrase mnémotechnique)
 * @param masterKey    — mot de passe actuel pour re-chiffrer les clés dans IndexedDB
 * @param onProgress   — callback optionnel
 * @returns uid de la session restaurée
 */
export async function importSessionKeys(
  fileContent: string,
  mnemonic   : string[],
  masterKey  : string,
  onProgress?: (phase: "parsing" | "deriving" | "decrypting" | "restoring" | "done") => void,
): Promise<string> {
  onProgress?.("parsing");
  let file: SessionFile;
  try {
    file = JSON.parse(fileContent);
  } catch {
    throw new Error("Fichier .aqsession invalide ou corrompu.");
  }

  if (file.v !== 2 || !file.salt || !file.nonce || !file.ciphertext) {
    throw new Error("Format .aqsession non reconnu (version incompatible ?).");
  }

  onProgress?.("deriving");
  const phrase         = mnemonic.join(" ");
  const { key }        = await argon2Derive(phrase, file.salt);

  onProgress?.("decrypting");
  let plaintext: string;
  try {
    plaintext = await aesGcmDecrypt(file.ciphertext, file.nonce, key);
  } catch {
    throw new Error("Phrase incorrecte ou fichier altéré.");
  }

  const payload: SessionExportPayload = JSON.parse(plaintext);
  if (payload.v !== 2 || !payload.uid || !payload.kemPrivateKey || !payload.dsaPrivateKey) {
    throw new Error("Contenu de session invalide.");
  }

  onProgress?.("restoring");

  // Reconstituer le salt Argon2id pour le vault (utiliser le même masterKey)
  const { key: vaultKey, salt: vaultSalt } = await argon2Derive(masterKey);

  // Stocker les clés privées dans IndexedDB + mémoire
  await storePrivateKeys(payload.uid, {
    kemPrivateKey: payload.kemPrivateKey,
    dsaPrivateKey: payload.dsaPrivateKey,
    masterKey    : vaultKey,
    argon2Salt   : vaultSalt,
  });

  // Restaurer tous les états ratchet
  for (const { convId, stateJson } of payload.ratchetStates) {
    await restoreRatchetState(payload.uid, convId, stateJson);
  }

  // Restaurer les caches de messages déchiffrés (optionnel selon version du fichier)
  if (payload.messageCaches) {
    for (const { convId, msgs, lastTs } of payload.messageCaches) {
      await saveCachedMessages(convId, msgs);
      void lastTs; // lastTs est recalculé par saveCachedMessages

      // Peupler aussi le cache per-message (key-store.ts → msgcache:{id})
      // utilisé par subscribeToMessages. Sans ça, loadMsgCache() retourne null
      // et tous les anciens messages restent affichés comme [🔒 Message chiffré]
      // même après un import réussi.
      for (const msg of msgs) {
        if (msg.isDeleted) continue; // les tombstones n'ont pas de plaintext utile
        await saveMsgCache(msg.id, {
          plaintext: msg.plaintext,
          verified:  msg.verified,
          senderUid: msg.senderUid,
          timestamp: msg.timestamp,
        });
      }
    }
  }

  // Mettre à jour le salt Argon2id dans Firestore avec le nouveau vaultSalt.
  // Sans cette mise à jour, la prochaine connexion sur ce navigateur lirait
  // l'ancien salt de Firestore → déchiffrement du vault IDB (nouveau salt) échoue.
  try {
    await setDoc(doc(db, "users", payload.uid), { argon2Salt: vaultSalt }, { merge: true });
  } catch (e) {
    // Non-bloquant : les clés sont en mémoire pour la session courante.
    // La prochaine connexion sur ce navigateur nécessitera un nouvel import.
    console.warn("[AQ:session] Impossible de mettre à jour argon2Salt dans Firestore:", e);
  }

  onProgress?.("done");
  return payload.uid;
}
