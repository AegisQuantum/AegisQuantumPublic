import { defineWorkspace } from "vitest/config";

/**
 * vitest.workspace.ts — Configuration multi-environnements pour AegisQuantum
 *
 * Deux projects séparés pour isoler les environnements :
 *
 *  [crypto]   — Node + mock argon2-browser (WASM non chargeable en Node)
 *               Tests : kem, dsa, hkdf, aes-gcm, argon2, ratchet-state
 *
 *  [services] — jsdom + fake-indexeddb + mocks Firebase
 *               Tests : auth, key-store, key-registry, messaging
 */
export default defineWorkspace([
  {
    test: {
      name       : "crypto",
      include    : ["src/crypto/__tests__/**/*.test.ts"],
      environment: "node",
      globals    : true,
      setupFiles : ["src/crypto/__tests__/setup.crypto.ts"],
    },
  },
  {
    test: {
      name       : "services",
      include    : ["src/services/__tests__/**/*.test.ts"],
      environment: "jsdom",
      globals    : true,
      setupFiles : ["src/services/__tests__/setup.ts"],
    },
  },
]);
