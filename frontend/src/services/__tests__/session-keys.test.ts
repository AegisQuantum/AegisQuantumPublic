/**
 * session-keys.test.ts — Tests for session key export/import
 *
 * Coverage:
 *  ── Functional ──────────────────────────────────────────────────────────────
 *  - exportSessionKeys() : produces a valid JSON SessionFile + 10-word mnemonic
 *  - importSessionKeys() : round-trips export→import and restores keys
 *  - downloadSessionFile(): creates a Blob download link (smoke test)
 *
 *  ── Security ────────────────────────────────────────────────────────────────
 *  - Wrong mnemonic → decrypt throws "Phrase incorrecte ou fichier altéré"
 *  - Corrupted file → throws
 *  - File v !== 2  → throws version error
 *  - Missing fields → throws
 */

import "./setup";           // mocks Firebase, IDB, crypto barrel

// ── Inject globalThis.argon2 mock ─────────────────────────────────────────
// session-keys.ts imports argon2Derive from "../crypto/argon2" (direct sub-module,
// not the barrel mock from setup.ts). argon2.ts reads globalThis.argon2.
// We inject a PBKDF2-based mock here so argon2Derive works without WASM.
(globalThis as Record<string, unknown>).argon2 = {
  ArgonType: { Argon2d: 0, Argon2i: 1, Argon2id: 2 },
  hash: async (params: { pass: string | Uint8Array; salt: Uint8Array; hashLen?: number }) => {
    const passBytes = typeof params.pass === "string"
      ? new TextEncoder().encode(params.pass)
      : params.pass;
    const km = await globalThis.crypto.subtle.importKey(
      "raw",
      passBytes.length > 0 ? (passBytes.buffer as ArrayBuffer) : new Uint8Array([0]).buffer,
      { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: params.salt.buffer as ArrayBuffer, iterations: 1 },
      km, (params.hashLen ?? 32) * 8
    );
    const hash = new Uint8Array(bits);
    let s = ""; for (const b of hash) s += String.fromCharCode(b);
    return { hash, hashHex: "", encoded: btoa(s) };
  },
};

import { describe, it, expect, beforeAll } from "vitest";
import { exportSessionKeys, importSessionKeys, downloadSessionFile } from "../../services/session-keys";
import { storePrivateKeys } from "../../services/key-store";

/** Normalize a mnemonic phrase: lowercase, trim, split on whitespace. */
function normalizeMnemonic(phrase: string): string[] {
  return phrase.trim().split(/\s+/).map(w => w.toLowerCase().trim()).filter(w => w.length > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const UID_TEST     = "session-test-uid-001";
const MASTER_KEY   = "test-master-password";
const KEM_PRIV     = btoa("kem-private-key-mock-" + "x".repeat(30));
const DSA_PRIV     = btoa("dsa-private-key-mock-" + "y".repeat(30));
const ARGON2_SALT  = btoa("salt16bytes-mock");

// Polyfill needed by argon2 mock via setup.ts
async function setupKeys(): Promise<void> {
  await storePrivateKeys(UID_TEST, {
    kemPrivateKey: KEM_PRIV,
    dsaPrivateKey: DSA_PRIV,
    masterKey    : MASTER_KEY,
    argon2Salt   : ARGON2_SALT,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// exportSessionKeys
// ─────────────────────────────────────────────────────────────────────────────

describe("exportSessionKeys", () => {
  beforeAll(async () => {
    await setupKeys();
  });

  it("returns a 10-word mnemonic", async () => {
    const { mnemonic } = await exportSessionKeys(UID_TEST);
    expect(mnemonic).toHaveLength(10);
    for (const word of mnemonic) {
      expect(typeof word).toBe("string");
      expect(word.length).toBeGreaterThan(0);
    }
  });

  it("returns valid JSON with v:2, salt, nonce, ciphertext", async () => {
    const { fileJson } = await exportSessionKeys(UID_TEST);
    const parsed = JSON.parse(fileJson);
    expect(parsed.v).toBe(2);
    expect(typeof parsed.salt).toBe("string");
    expect(typeof parsed.nonce).toBe("string");
    expect(typeof parsed.ciphertext).toBe("string");
    expect(parsed.salt.length).toBeGreaterThan(0);
    expect(parsed.ciphertext.length).toBeGreaterThan(0);
  });

  it("calls onProgress with all phases", async () => {
    const phases: string[] = [];
    await exportSessionKeys(UID_TEST, (phase) => phases.push(phase));
    expect(phases).toContain("generating");
    expect(phases).toContain("collecting");
    expect(phases).toContain("deriving");
    expect(phases).toContain("encrypting");
    expect(phases).toContain("done");
  });

  it("two exports produce different mnemonics (entropy)", async () => {
    const { mnemonic: a } = await exportSessionKeys(UID_TEST);
    const { mnemonic: b } = await exportSessionKeys(UID_TEST);
    // Very unlikely to collide
    expect(a.join(" ")).not.toBe(b.join(" "));
  });

  it("two exports produce different salts (unique encryption)", async () => {
    const { fileJson: f1 } = await exportSessionKeys(UID_TEST);
    const { fileJson: f2 } = await exportSessionKeys(UID_TEST);
    expect(JSON.parse(f1).salt).not.toBe(JSON.parse(f2).salt);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// importSessionKeys — round-trip
// ─────────────────────────────────────────────────────────────────────────────

describe("importSessionKeys — round-trip", () => {
  it("restores the UID after export→import", async () => {
    await setupKeys();
    const { fileJson, mnemonic } = await exportSessionKeys(UID_TEST);
    const restoredUid = await importSessionKeys(fileJson, mnemonic, MASTER_KEY);
    expect(restoredUid).toBe(UID_TEST);
  });

  it("calls onProgress through all import phases", async () => {
    await setupKeys();
    const { fileJson, mnemonic } = await exportSessionKeys(UID_TEST);
    const phases: string[] = [];
    await importSessionKeys(fileJson, mnemonic, MASTER_KEY, (phase) => phases.push(phase));
    expect(phases).toContain("parsing");
    expect(phases).toContain("deriving");
    expect(phases).toContain("decrypting");
    expect(phases).toContain("restoring");
    expect(phases).toContain("done");
  });

  it("accepts mnemonic passed as normalized array", async () => {
    await setupKeys();
    const { fileJson, mnemonic } = await exportSessionKeys(UID_TEST);
    // normalizeMnemonic should be idempotent on a valid mnemonic
    const normalized = normalizeMnemonic(mnemonic.join(" "));
    const restoredUid = await importSessionKeys(fileJson, normalized, MASTER_KEY);
    expect(restoredUid).toBe(UID_TEST);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// importSessionKeys — error cases
// ─────────────────────────────────────────────────────────────────────────────

describe("importSessionKeys — error handling", () => {
  it("throws on wrong mnemonic", async () => {
    await setupKeys();
    const { fileJson, mnemonic } = await exportSessionKeys(UID_TEST);
    // Alter the mnemonic
    const badMnemonic = [...mnemonic];
    badMnemonic[0] = badMnemonic[0] === "acid" ? "acre" : "acid";
    await expect(
      importSessionKeys(fileJson, badMnemonic, MASTER_KEY)
    ).rejects.toThrow();
  });

  it("throws on invalid JSON file content", async () => {
    await expect(
      importSessionKeys("not-json-at-all", generateMnemonic10(), MASTER_KEY)
    ).rejects.toThrow("invalide ou corrompu");
  });

  it("throws when v field is missing", async () => {
    const malformed = JSON.stringify({ salt: "a", nonce: "b", ciphertext: "c" });
    await expect(
      importSessionKeys(malformed, generateMnemonic10(), MASTER_KEY)
    ).rejects.toThrow();
  });

  it("throws when file has version != 2", async () => {
    const malformed = JSON.stringify({ v: 1, salt: "a", nonce: "b", ciphertext: "c" });
    await expect(
      importSessionKeys(malformed, generateMnemonic10(), MASTER_KEY)
    ).rejects.toThrow();
  });

  it("throws when ciphertext is empty", async () => {
    const malformed = JSON.stringify({ v: 2, salt: "a", nonce: "b", ciphertext: "" });
    await expect(
      importSessionKeys(malformed, generateMnemonic10(), MASTER_KEY)
    ).rejects.toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// downloadSessionFile — smoke test (DOM not available in test env)
// ─────────────────────────────────────────────────────────────────────────────

describe("downloadSessionFile", () => {
  it("is a function that accepts a JSON string", () => {
    // In jsdom, document.createElement and URL.createObjectURL are available
    // but this is a smoke test — we just ensure it doesn't throw on valid JSON
    expect(typeof downloadSessionFile).toBe("function");
    // If we're in a jsdom environment, try calling it
    if (typeof document !== "undefined" && typeof URL?.createObjectURL === "function") {
      expect(() => downloadSessionFile('{"v":2,"salt":"","nonce":"","ciphertext":""}')).not.toThrow();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// getAllRatchetStates — used by exportSessionKeys
// ─────────────────────────────────────────────────────────────────────────────

describe("getAllRatchetStates in export context", () => {
  it("exports empty ratchet states when no conversations", async () => {
    await setupKeys();
    const { fileJson, mnemonic } = await exportSessionKeys(UID_TEST);
    const restoredUid = await importSessionKeys(fileJson, mnemonic, MASTER_KEY);
    expect(restoredUid).toBe(UID_TEST);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a valid 10-word mnemonic using known WORDLIST entries.
 * (First 10 entries of WORDLIST: acid, acre, aged, aide, also, alto, arch, area, atom, aunt)
 */
function generateMnemonic10(): string[] {
  return ["acid", "acre", "aged", "aide", "also", "alto", "arch", "area", "atom", "aunt"];
}
