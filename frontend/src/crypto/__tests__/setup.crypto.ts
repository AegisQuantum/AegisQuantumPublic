/**
 * setup.crypto.ts — Setup Vitest pour les tests du module crypto/
 *
 * Problème : argon2-browser charge argon2.wasm via fetch() / fs.readFileSync()
 * avec un chemin relatif depuis node_modules/ — incompatible avec Vitest/Node.
 *
 * Solution : vi.mock() intercepte l'import avant résolution du module.
 * On substitue argon2-browser par une implémentation PBKDF2-SHA256
 * (Web Crypto natif dans Node 18+) qui a les mêmes propriétés testables :
 *   - Déterministe : même (password, salt) → même hash
 *   - Résistant : la sortie n'est pas trivialement liée à l'entrée
 *   - 32 bytes en sortie (configurable via hashLen)
 *
 * En production (browser), le vrai Argon2id WASM est utilisé — ce mock
 * n'est actif que dans l'environnement de test.
 */

import { vi } from "vitest";
import { webcrypto } from "node:crypto";

// Polyfill crypto.subtle pour Node (disponible nativement à partir de Node 19,
// mais nécessite le polyfill sur Node 18 dans certains contextes)
if (typeof globalThis.crypto === "undefined" || typeof globalThis.crypto.subtle === "undefined") {
  // @ts-expect-error — polyfill Node webcrypto
  globalThis.crypto = webcrypto;
}

/**
 * Mock de argon2-browser.
 *
 * argon2.ts fait : import argon2 from "argon2-browser"
 * puis utilise : argon2.ArgonType.Argon2id  et  argon2.hash({ pass, salt, time, mem, ... })
 *
 * Le mock doit exposer :
 *  - default.ArgonType.Argon2id
 *  - default.hash(params) → Promise<{ hash: Uint8Array }>
 */
vi.mock("argon2-browser", () => {
  const ArgonType = { Argon2d: 0, Argon2i: 1, Argon2id: 2 };

  const hash = async (params: {
    pass       : string | Uint8Array;
    salt       : Uint8Array;
    hashLen   ?: number;
    time      ?: number;
    mem       ?: number;
    parallelism?: number;
    type      ?: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }> => {
    const passBytes =
      typeof params.pass === "string"
        ? new TextEncoder().encode(params.pass)
        : params.pass;

    const keyMaterial = await globalThis.crypto.subtle.importKey(
      "raw",
      passBytes.buffer as ArrayBuffer,
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    const bits = await globalThis.crypto.subtle.deriveBits(
      {
        name      : "PBKDF2",
        hash      : "SHA-256",
        salt      : params.salt.buffer as ArrayBuffer,
        iterations: 1000,
      },
      keyMaterial,
      (params.hashLen ?? 32) * 8
    );

    const hashBytes = new Uint8Array(bits);
    const hashHex   = Array.from(hashBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return { hash: hashBytes, hashHex, encoded: hashHex };
  };

  // Vitest attend : { default: {...}, ArgonType: {...} }
  // car argon2.ts fait `import argon2 from "argon2-browser"` (default import)
  return {
    default  : { ArgonType, hash },
    ArgonType,          // aussi en named export au cas où
  };
});
