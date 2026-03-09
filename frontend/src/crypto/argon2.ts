/**
 * argon2.ts — Argon2id via argon2-browser
 *
 * Rôle dans le protocole :
 *  - Dérive une master key de 32 bytes depuis le mot de passe de l'utilisateur.
 *  - La master key chiffre le vault de clés privées dans IndexedDB (via AES-GCM).
 *  - Le salt est stocké en clair dans Firestore (/users/{uid}/argon2Salt) pour
 *    permettre la reconnexion depuis un autre appareil.
 *
 * Pourquoi Argon2id ?
 *  - Memory-hard : résiste aux attaques par GPU/FPGA/ASIC.
 *  - Paramètres choisis pour ~500ms sur un browser moderne (équilibre UX/sécu).
 *
 * Paramètres de dérivation (OWASP 2024 recommandations) :
 *  - m = 65536 (64 MB)  — memory cost
 *  - t = 3              — time cost (itérations)
 *  - p = 1              — parallelism
 *  - hashLen = 32       — output 256 bits
 *
 * ⚠️ Le salt doit être unique par utilisateur et généré aléatoirement.
 *    Ne jamais réutiliser un salt.
 */

import argon2 from "argon2-browser";
import { toBase64, fromBase64 } from "./kem";

// ─────────────────────────────────────────────────────────────────────────────
// Paramètres Argon2id
// ─────────────────────────────────────────────────────────────────────────────

const ARGON2_TIME_COST   = 3;
const ARGON2_MEMORY_COST = 65536; // 64 MB
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN    = 32;    // 256 bits = clé AES-256
const ARGON2_TYPE        = argon2.ArgonType.Argon2id;

// ─────────────────────────────────────────────────────────────────────────────
// Core
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Dérive une master key AES-256 depuis le mot de passe de l'utilisateur.
 *
 * Appelé par :
 *  - auth.ts → register() : `salt` passé à null → on génère un sel aléatoire
 *  - auth.ts → signIn()   : `saltB64` passé depuis Firestore → on réutilise le sel
 *
 * @param password — mot de passe en clair (UTF-8)
 * @param saltB64  — Base64 — salt 16 bytes.
 *                   Si null : génère un sel aléatoire (inscription).
 *                   Si fourni : réutilise le sel (connexion).
 * @returns { key, salt }
 *   - key  : Base64 — master key 32 bytes — utilisée pour chiffrer/déchiffrer le vault IDB
 *   - salt : Base64 — salt 16 bytes — à stocker dans Firestore /users/{uid}/argon2Salt
 */
export async function argon2Derive(
  password: string,
  saltB64?: string
): Promise<{ key: string; salt: string }> {
  // Générer ou réutiliser le salt
  const saltBytes = saltB64
    ? fromBase64(saltB64)
    : crypto.getRandomValues(new Uint8Array(16));

  const result = await argon2.hash({
    pass    : password,
    salt    : saltBytes,
    time    : ARGON2_TIME_COST,
    mem     : ARGON2_MEMORY_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLen : ARGON2_HASH_LEN,
    type    : ARGON2_TYPE,
  });

  return {
    key : toBase64(result.hash),
    salt: toBase64(saltBytes),
  };
}
