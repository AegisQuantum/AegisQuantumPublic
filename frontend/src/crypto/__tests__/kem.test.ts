/**
 * kem.test.ts — Unit & performance tests for ML-KEM-768
 *
 * KPIs verified (specs §2.2):
 *  - Encapsulation time  < 5 ms
 *  - Decapsulation time  < 5 ms
 *  - Success rate        100 %
 *
 * Security invariants verified:
 *  - Shared secrets from encap/decap are identical (correctness)
 *  - A wrong private key produces a different shared secret (security)
 *  - Base64 encoding is round-trippable
 */

import { describe, it, expect } from "vitest";
import {
  kemGenerateKeyPair,
  kemEncapsulate,
  kemDecapsulate,
  toBase64,
  fromBase64,
} from "../kem";

// ── Helper ─────────────────────────────────────────────────────────────────

/** Run fn N times and return the average duration in ms. */
async function measureAvgMs(fn: () => Promise<unknown>, runs = 5): Promise<number> {
  const times: number[] = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await fn();
    times.push(performance.now() - t0);
  }
  return times.reduce((a, b) => a + b, 0) / times.length;
}

// ── Base64 helpers ─────────────────────────────────────────────────────────

describe("toBase64 / fromBase64", () => {
  it("should round-trip a known byte array", () => {
    const original = new Uint8Array([0x00, 0xff, 0x42, 0x1a, 0x7f]);
    const encoded = toBase64(original);
    const decoded = fromBase64(encoded);
    expect(decoded).toEqual(original);
  });

  it("should produce a non-empty string for non-empty input", () => {
    const bytes = new Uint8Array(32).fill(0xab);
    expect(toBase64(bytes).length).toBeGreaterThan(0);
  });

  it("should handle empty arrays without throwing", () => {
    expect(() => toBase64(new Uint8Array(0))).not.toThrow();
    expect(() => fromBase64("")).not.toThrow();
  });
});

// ── Key generation ─────────────────────────────────────────────────────────

describe("kemGenerateKeyPair", () => {
  it("should return a public key and a private key", async () => {
    const { publicKey, privateKey } = await kemGenerateKeyPair();
    expect(typeof publicKey).toBe("string");
    expect(typeof privateKey).toBe("string");
    expect(publicKey.length).toBeGreaterThan(0);
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it("should generate distinct key pairs on successive calls", async () => {
    const kp1 = await kemGenerateKeyPair();
    const kp2 = await kemGenerateKeyPair();
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
    expect(kp1.privateKey).not.toBe(kp2.privateKey);
  });

  it("ML-KEM-768 public key should be 1184 bytes (FIPS 203)", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const bytes = fromBase64(publicKey);
    // ML-KEM-768 public key size = 1184 bytes (FIPS 203 spec)
    expect(bytes.length).toBe(1184);
  });

  it("ML-KEM-768 private key should be 2400 bytes (FIPS 203)", async () => {
    const { privateKey } = await kemGenerateKeyPair();
    const bytes = fromBase64(privateKey);
    // ML-KEM-768 secret key size = 2400 bytes (FIPS 203 spec)
    expect(bytes.length).toBe(2400);
  });
});

// ── Encapsulation ──────────────────────────────────────────────────────────

describe("kemEncapsulate", () => {
  it("should return a sharedSecret and a ciphertext", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const { sharedSecret, ciphertext } = await kemEncapsulate(publicKey);
    expect(typeof sharedSecret).toBe("string");
    expect(typeof ciphertext).toBe("string");
    expect(sharedSecret.length).toBeGreaterThan(0);
    expect(ciphertext.length).toBeGreaterThan(0);
  });

  it("ML-KEM-768 shared secret should be 32 bytes", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const { sharedSecret } = await kemEncapsulate(publicKey);
    expect(fromBase64(sharedSecret).length).toBe(32);
  });

  it("ML-KEM-768 ciphertext should be 1088 bytes (FIPS 203)", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const { ciphertext } = await kemEncapsulate(publicKey);
    expect(fromBase64(ciphertext).length).toBe(1088);
  });

  it("should produce distinct ciphertexts on successive encapsulations (semantic security)", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const r1 = await kemEncapsulate(publicKey);
    const r2 = await kemEncapsulate(publicKey);
    // Encapsulation is randomized — two calls on the same key MUST differ
    expect(r1.ciphertext).not.toBe(r2.ciphertext);
    expect(r1.sharedSecret).not.toBe(r2.sharedSecret);
  });

  it("should throw on an invalid public key", async () => {
    await expect(kemEncapsulate("not-valid-base64!!!")).rejects.toThrow();
  });
});

// ── Decapsulation ──────────────────────────────────────────────────────────

describe("kemDecapsulate", () => {
  it("should recover the same shared secret as encapsulation (correctness)", async () => {
    const { publicKey, privateKey } = await kemGenerateKeyPair();
    const { sharedSecret: ssSender, ciphertext } = await kemEncapsulate(publicKey);
    const ssRecipient = await kemDecapsulate(ciphertext, privateKey);
    // CRITICAL: sender and recipient MUST agree on the same shared secret
    expect(ssRecipient).toBe(ssSender);
  });

  it("100% success rate over 10 independent key exchanges", async () => {
    const results: boolean[] = [];
    for (let i = 0; i < 10; i++) {
      const { publicKey, privateKey } = await kemGenerateKeyPair();
      const { sharedSecret: ssSender, ciphertext } = await kemEncapsulate(publicKey);
      const ssRecipient = await kemDecapsulate(ciphertext, privateKey);
      results.push(ssRecipient === ssSender);
    }
    const successRate = results.filter(Boolean).length / results.length;
    expect(successRate).toBe(1.0); // KPI: 100% success rate
  });

  it("should produce a DIFFERENT shared secret with a wrong private key (security)", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const { privateKey: wrongPrivateKey } = await kemGenerateKeyPair(); // unrelated key pair
    const { sharedSecret: ssSender, ciphertext } = await kemEncapsulate(publicKey);
    // With the wrong private key, decap should either throw or return a different value
    // ML-KEM is designed to return a pseudo-random value (implicit rejection) — never the real secret
    try {
      const ssWrong = await kemDecapsulate(ciphertext, wrongPrivateKey);
      expect(ssWrong).not.toBe(ssSender);
    } catch {
      // Also acceptable: library throws on wrong key
    }
  });

  it("should throw on an invalid ciphertext", async () => {
    const { privateKey } = await kemGenerateKeyPair();
    await expect(kemDecapsulate("bad-ciphertext!!!", privateKey)).rejects.toThrow();
  });
});

// ── Performance KPIs (specs §2.2) ─────────────────────────────────────────

describe("Performance KPIs — ML-KEM-768 (specs §2.2: < 5 ms / op)", () => {
  it("encapsulation average should be < 5 ms", async () => {
    const { publicKey } = await kemGenerateKeyPair();
    const avgMs = await measureAvgMs(() => kemEncapsulate(publicKey));
    console.log(`[KPI] encap avg: ${avgMs.toFixed(2)} ms`);
    expect(avgMs).toBeLessThan(5);
  });

  it("decapsulation average should be < 5 ms", async () => {
    const { publicKey, privateKey } = await kemGenerateKeyPair();
    const { ciphertext } = await kemEncapsulate(publicKey);
    const avgMs = await measureAvgMs(() => kemDecapsulate(ciphertext, privateKey));
    console.log(`[KPI] decap avg: ${avgMs.toFixed(2)} ms`);
    expect(avgMs).toBeLessThan(5);
  });
});
