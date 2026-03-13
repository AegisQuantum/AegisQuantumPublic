/**
 * backup.ts — Export / Import chiffré de l'historique des messages
 *
 * Format .aqbackup :
 *   JSON chiffré AES-256-GCM, clé dérivée via Argon2id du mot de passe.
 *
 * Structure du plaintext (avant chiffrement) :
 * {
 *   version  : 1,
 *   exportedAt: number,          // timestamp Unix ms
 *   uid      : string,           // UID de l'exporteur
 *   conversations: [
 *     {
 *       convId      : string,
 *       localName   : string | null,
 *       participants: string[],
 *       messages    : DecryptedMessage[]
 *     }
 *   ]
 * }
 *
 * Structure du fichier .aqbackup (après chiffrement) :
 * {
 *   v        : 1,
 *   argon2Salt: string,   // Base64 — salt Argon2id
 *   nonce    : string,    // Base64 — AES-GCM nonce 12 bytes
 *   ciphertext: string,   // Base64 — AES-256-GCM(plaintext JSON)
 * }
 *
 * Sécurité :
 *  - Le mot de passe n'est jamais stocké ; la clé AES-256 est dérivée in-memory.
 *  - Argon2id (64 MB · 3 it.) : résistant aux attaques par dictionnaire sur le fichier.
 *  - AES-256-GCM garantit confidentialité + intégrité du backup.
 *  - Un nonce frais est généré à chaque export → deux exports du même contenu
 *    produisent des ciphertexts différents.
 */

import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aes-gcm";
import { argon2Derive }                  from "../crypto/argon2";
import type { DecryptedMessage }         from "../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface BackupConversation {
  convId      : string;
  localName   : string | null;
  participants: string[];
  messages    : DecryptedMessage[];
}

export interface BackupPayload {
  version      : 1;
  exportedAt   : number;
  uid          : string;
  conversations: BackupConversation[];
}

export interface AqBackupFile {
  v         : 1;
  argon2Salt: string;
  nonce     : string;
  ciphertext: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Chiffre le payload avec Argon2id + AES-256-GCM et déclenche le téléchargement.
 *
 * @param payload    — données à exporter (conversations déchiffrées en mémoire)
 * @param password   — mot de passe de l'utilisateur (pour dériver la clé AES)
 * @param onProgress — callback optionnel pour indiquer la phase en cours
 */
export async function exportBackup(
  payload    : BackupPayload,
  password   : string,
  onProgress?: (phase: "deriving" | "encrypting" | "downloading") => void,
): Promise<void> {
  onProgress?.("deriving");
  const { key, salt } = await argon2Derive(password);

  onProgress?.("encrypting");
  const plaintext = JSON.stringify(payload);
  const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, key);

  const backupFile: AqBackupFile = { v: 1, argon2Salt: salt, nonce, ciphertext };
  const blob = new Blob([JSON.stringify(backupFile)], { type: "application/octet-stream" });

  onProgress?.("downloading");
  const date = new Date().toISOString().slice(0, 10);
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `aegisquantum-backup-${date}.aqbackup`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Import (lecture + déchiffrement, validation)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lit un fichier .aqbackup, le déchiffre avec le mot de passe fourni,
 * et retourne le payload si la clé est correcte.
 *
 * @throws Error si le fichier est invalide ou le mot de passe incorrect
 */
export async function importBackup(
  file    : File,
  password: string,
): Promise<BackupPayload> {
  const raw  = await file.text();
  let parsed: AqBackupFile;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Fichier .aqbackup corrompu ou invalide.");
  }

  if (parsed.v !== 1 || !parsed.argon2Salt || !parsed.nonce || !parsed.ciphertext) {
    throw new Error("Format .aqbackup non reconnu (version incompatible ?).");
  }

  const { key } = await argon2Derive(password, parsed.argon2Salt);

  let plaintext: string;
  try {
    plaintext = await aesGcmDecrypt(parsed.ciphertext, parsed.nonce, key);
  } catch {
    throw new Error("Mot de passe incorrect ou fichier altéré.");
  }

  const payload: BackupPayload = JSON.parse(plaintext);
  if (payload.version !== 1) {
    throw new Error(`Version de backup inconnue : ${payload.version}`);
  }
  return payload;
}
