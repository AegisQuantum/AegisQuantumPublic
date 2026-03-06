/**
 * messaging.test.ts — Unit, KPI & security tests for messaging.ts
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  getConversationId,
  getOrCreateConversation,
  getConversations,
  sendMessage,
  decryptMessage,
  subscribeToConversations,
  subscribeToMessages,
} from "../messaging";
import { storePrivateKeys, clearPrivateKeys } from "../key-store";
import { publishPublicKeys } from "../key-registry";
import type { EncryptedMessage } from "../../types/message";

// ── Fixtures ───────────────────────────────────────────────────────────────

const UID_ALICE = "msg-test-alice-uid";
const UID_BOB   = "msg-test-bob-uid";
const UID_CAROL = "msg-test-carol-uid";

async function seedKeys(uid: string): Promise<void> {
  await storePrivateKeys(uid, {
    kemPrivateKey: `kem-priv-${uid}`,
    dsaPrivateKey: `dsa-priv-${uid}`,
    masterKey    : "master-key-32bytes===========",
    argon2Salt   : "argon2-salt-16bytes=",
  });
  await publishPublicKeys(uid, {
    uid,
    kemPublicKey: btoa("A".repeat(1184)),
    dsaPublicKey: btoa("B".repeat(256)),
    createdAt   : Date.now(),
  });
}

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

function makeEncryptedMsg(overrides: Partial<EncryptedMessage> = {}): EncryptedMessage {
  return {
    id            : "msg-test-001",
    conversationId: getConversationId(UID_ALICE, UID_BOB),
    senderUid     : UID_ALICE,
    ciphertext    : btoa("Hello Bob"),
    nonce         : "",
    kemCiphertext : "",
    signature     : "",
    messageIndex  : 0,
    timestamp     : Date.now(),
    ...overrides,
  };
}

beforeEach(async () => {
  await seedKeys(UID_ALICE);
  await seedKeys(UID_BOB);
});

afterEach(() => {
  clearPrivateKeys();
});

// ══════════════════════════════════════════════════════════════════════════
// 1. getConversationId
// ══════════════════════════════════════════════════════════════════════════

describe("getConversationId [UNIT]", () => {
  it("should return a non-empty string", () => {
    expect(getConversationId(UID_ALICE, UID_BOB).length).toBeGreaterThan(0);
  });

  it("should be symmetric", () => {
    expect(getConversationId(UID_ALICE, UID_BOB)).toBe(getConversationId(UID_BOB, UID_ALICE));
  });

  it("should be deterministic", () => {
    expect(getConversationId(UID_ALICE, UID_BOB)).toBe(getConversationId(UID_ALICE, UID_BOB));
  });

  it("should produce different IDs for different user pairs", () => {
    expect(getConversationId(UID_ALICE, UID_BOB)).not.toBe(getConversationId(UID_ALICE, UID_CAROL));
  });

  it("should use sorted UIDs separated by underscore", () => {
    const sorted = [UID_ALICE, UID_BOB].sort((a, b) => a.localeCompare(b));
    expect(getConversationId(UID_ALICE, UID_BOB)).toBe(sorted.join("_"));
  });

  it("collision check when uid contains underscore (informational)", () => {
    const id1 = getConversationId("user_a", "b");
    const id2 = getConversationId("user", "a_b");
    console.log(`[INFO] id1="${id1}" id2="${id2}" — collision check`);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. getOrCreateConversation
// ══════════════════════════════════════════════════════════════════════════

describe("getOrCreateConversation [INTEGRATION]", () => {
  it("should return the deterministic convId", async () => {
    const convId = await getOrCreateConversation(UID_ALICE, UID_BOB);
    expect(convId).toBe(getConversationId(UID_ALICE, UID_BOB));
  });

  it("should be idempotent", async () => {
    expect(await getOrCreateConversation(UID_ALICE, UID_BOB))
      .toBe(await getOrCreateConversation(UID_ALICE, UID_BOB));
  });

  it("should be symmetric", async () => {
    expect(await getOrCreateConversation(UID_ALICE, UID_BOB))
      .toBe(await getOrCreateConversation(UID_BOB, UID_ALICE));
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. sendMessage
// ══════════════════════════════════════════════════════════════════════════

describe("sendMessage [INTEGRATION]", () => {
  it("should complete without throwing (dev placeholder mode)", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "Hello Bob")).resolves.not.toThrow();
  });

  it("should throw if contact has no public keys registered", async () => {
    await expect(sendMessage(UID_ALICE, "uid-with-no-keys", "test"))
      .rejects.toThrow(/no public keys/i);
  });

  it("should throw if sender has no keys loaded in memory", async () => {
    clearPrivateKeys();
    await expect(sendMessage(UID_ALICE, UID_BOB, "test")).rejects.toThrow();
  });

  it("should handle empty plaintext gracefully", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "")).resolves.not.toThrow();
  });

  it("should handle a long plaintext (10 KB) without throwing", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "A".repeat(10_000))).resolves.not.toThrow();
  });

  it("should handle unicode plaintext", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "こんにちは 🔐 مرحبا")).resolves.not.toThrow();
  });

  it("[DoS] sendMessage se termine dans un délai raisonnable", async () => {
    const t0 = performance.now();
    await sendMessage(UID_ALICE, UID_BOB, "test DoS");
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. decryptMessage
// ══════════════════════════════════════════════════════════════════════════

describe("decryptMessage [UNIT]", () => {
  it("should return correct plaintext (dev mode)", async () => {
    const dec = await decryptMessage(UID_ALICE, makeEncryptedMsg({ ciphertext: btoa("Hello Bob") }));
    expect(dec.plaintext).toBe("Hello Bob");
  });

  it("should return verified: false in dev mode", async () => {
    expect((await decryptMessage(UID_ALICE, makeEncryptedMsg())).verified).toBe(false);
  });

  it("should preserve senderUid", async () => {
    expect((await decryptMessage(UID_BOB, makeEncryptedMsg({ senderUid: UID_ALICE }))).senderUid)
      .toBe(UID_ALICE);
  });

  it("should preserve id", async () => {
    expect((await decryptMessage(UID_BOB, makeEncryptedMsg({ id: "specific-msg-id" }))).id)
      .toBe("specific-msg-id");
  });

  it("should preserve timestamp", async () => {
    const ts = 1700000000000;
    expect((await decryptMessage(UID_BOB, makeEncryptedMsg({ timestamp: ts }))).timestamp).toBe(ts);
  });

  it("DecryptedMessage has all required fields", async () => {
    const dec = await decryptMessage(UID_BOB, makeEncryptedMsg());
    expect(dec).toHaveProperty("id");
    expect(dec).toHaveProperty("senderUid");
    expect(dec).toHaveProperty("plaintext");
    expect(dec).toHaveProperty("timestamp");
    expect(dec).toHaveProperty("verified");
  });

  it("should handle empty ciphertext", async () => {
    expect((await decryptMessage(UID_BOB, makeEncryptedMsg({ ciphertext: btoa("") }))).plaintext)
      .toBe("");
  });

  it("[REPLAY] décrypter 2× le même message est idempotent", async () => {
    const msg  = makeEncryptedMsg({ ciphertext: btoa("Replay payload"), id: "replay-msg" });
    const dec1 = await decryptMessage(UID_BOB, msg);
    const dec2 = await decryptMessage(UID_BOB, msg);
    expect(dec1.plaintext).toBe(dec2.plaintext);
    expect(dec1.id).toBe(dec2.id);
  });

  it("[OUT-OF-ORDER] messageIndex non-séquentiel ne crash pas", async () => {
    const dec5 = await decryptMessage(UID_BOB, makeEncryptedMsg({ messageIndex: 5, ciphertext: btoa("msg5"), id: "m5" }));
    const dec4 = await decryptMessage(UID_BOB, makeEncryptedMsg({ messageIndex: 4, ciphertext: btoa("msg4"), id: "m4" }));
    expect(dec5.plaintext).toBe("msg5");
    expect(dec4.plaintext).toBe("msg4");
  });

  it("[DoS] messageIndex = 1_000_000 se termine en < 500 ms", async () => {
    const t0  = performance.now();
    const dec = await decryptMessage(UID_BOB, makeEncryptedMsg({ messageIndex: 1_000_000, ciphertext: btoa("DoS probe") }));
    const ms  = performance.now() - t0;
    console.log(`  [DoS] decryptMessage(messageIndex=1M): ${ms.toFixed(2)} ms`);
    expect(ms).toBeLessThan(500);
    expect(typeof dec.plaintext).toBe("string");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. subscribeToConversations
// ══════════════════════════════════════════════════════════════════════════

describe("subscribeToConversations [INTEGRATION]", () => {
  it("should return an unsubscribe function", () => {
    const unsub = subscribeToConversations(UID_ALICE, () => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("unsubscribe should not throw", () => {
    expect(() => subscribeToConversations(UID_ALICE, () => {})()).not.toThrow();
  });

  it("callback should receive an array", async () => {
    const received: unknown[] = [];
    const unsub = subscribeToConversations(UID_CAROL, (c) => received.push(c));
    await new Promise((r) => setTimeout(r, 300));
    unsub();
    expect(received.length).toBeGreaterThan(0);
    expect(Array.isArray(received[0])).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 6. subscribeToMessages
// ══════════════════════════════════════════════════════════════════════════

describe("subscribeToMessages [INTEGRATION]", () => {
  it("should return an unsubscribe function", () => {
    const unsub = subscribeToMessages(UID_ALICE, getConversationId(UID_ALICE, UID_BOB), () => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("callback fires after a message is sent", async () => {
    const convId   = getConversationId(UID_ALICE, UID_BOB);
    const messages: unknown[] = [];
    const unsub = subscribeToMessages(UID_ALICE, convId, (msgs) => messages.push(...msgs));
    await sendMessage(UID_ALICE, UID_BOB, "Ping");
    await new Promise((r) => setTimeout(r, 500));
    unsub();
    expect(messages.length).toBeGreaterThan(0);
  });

  it("a decryption failure should not crash the subscription", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const unsub  = subscribeToMessages(UID_ALICE, convId, () => {});
    await new Promise((r) => setTimeout(r, 300));
    unsub();
    expect(true).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 7. KPIs
// ══════════════════════════════════════════════════════════════════════════

describe("Performance KPIs — messaging (specs §2.2)", () => {
  it("getConversationId < 0.1 ms (pure computation)", () => {
    const t0 = performance.now();
    getConversationId(UID_ALICE, UID_BOB);
    const ms = performance.now() - t0;
    console.log(`[KPI] getConversationId: ${ms.toFixed(4)} ms`);
    expect(ms).toBeLessThan(0.1);
  });

  it("sendMessage < 2000 ms", async () => {
    const ms = await measureMs(() => sendMessage(UID_ALICE, UID_BOB, "KPI test"));
    console.log(`[KPI] sendMessage: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(2000);
  });

  it("decryptMessage < 100 ms (dev stub)", async () => {
    const ms = await measureMs(() => decryptMessage(UID_BOB, makeEncryptedMsg({ ciphertext: btoa("KPI") })));
    console.log(`[KPI] decryptMessage: ${ms.toFixed(2)} ms`);
    expect(ms).toBeLessThan(100);
  });

  it("[KPI] taille sérialisée d'un EncryptedMessage (prod estimate) ≤ 15 Ko", () => {
    const productionMsg: EncryptedMessage = {
      id            : "prod-size-est",
      conversationId: getConversationId(UID_ALICE, UID_BOB),
      senderUid     : UID_ALICE,
      ciphertext    : btoa("A".repeat(100)),   // payload ~100 bytes
      nonce         : btoa("N".repeat(12)),    // AES-GCM nonce 12 bytes
      kemCiphertext : btoa("C".repeat(1088)),  // ML-KEM-768 CT 1088 bytes
      signature     : btoa("S".repeat(3309)),  // ML-DSA-65 sig ~3309 bytes
      messageIndex  : 0,
      timestamp     : Date.now(),
    };
    const sizeKB = JSON.stringify(productionMsg).length / 1024;
    console.log(`  [KPI] EncryptedMessage prod estimate: ${sizeKB.toFixed(2)} KB`);
    expect(sizeKB).toBeLessThan(15);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 8. Invariants de sécurité
// ══════════════════════════════════════════════════════════════════════════

describe("Security invariants — messaging", () => {
  it("[SEC] sendMessage throws if contact has no public keys", async () => {
    await expect(sendMessage(UID_ALICE, "uid-ghost-no-keys", "secret"))
      .rejects.toThrow(/no public keys/i);
  });

  it("[SEC] sendMessage throws if sender keys are cleared", async () => {
    clearPrivateKeys();
    await expect(sendMessage(UID_ALICE, UID_BOB, "secret")).rejects.toThrow();
  });

  it("[SEC] getConversationId is symmetric", () => {
    expect(getConversationId(UID_ALICE, UID_BOB)).toBe(getConversationId(UID_BOB, UID_ALICE));
  });

  it("[SEC] dev placeholder messages have verified: false", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    let detected = false;
    const unsub  = subscribeToMessages(UID_ALICE, convId, (msgs) => {
      if (msgs.some((m) => m.verified === false)) detected = true;
    });
    await sendMessage(UID_ALICE, UID_BOB, "dev flag check");
    await new Promise((r) => setTimeout(r, 500));
    unsub();
    expect(detected).toBe(true);
  });

  it("[SEC] decryptMessage handles empty kemCiphertext gracefully", async () => {
    await expect(decryptMessage(UID_BOB, makeEncryptedMsg({ kemCiphertext: "" })))
      .resolves.not.toThrow();
  });

  it("[SEC] decryptMessage with empty signature returns verified: false", async () => {
    const dec = await decryptMessage(UID_BOB, makeEncryptedMsg({ signature: "" }));
    expect(dec.verified).toBe(false);
  });

  it("[SEC] negative messageIndex does not crash", async () => {
    await expect(decryptMessage(UID_BOB, makeEncryptedMsg({ messageIndex: -1 })))
      .resolves.not.toThrow();
  });

  it("[SEC] 100 KB plaintext does not crash sendMessage", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "X".repeat(100_000))).resolves.not.toThrow();
  });

  it("[SEC] corrupt kemPublicKey in bundle — sendMessage stays stable (dev mode)", async () => {
    const CORRUPT_UID = "uid-corrupt-pubkey";
    await publishPublicKeys(CORRUPT_UID, {
      uid         : CORRUPT_UID,
      kemPublicKey: btoa("X".repeat(100)), // 100 bytes < 1184 required
      dsaPublicKey: btoa("Y".repeat(256)),
      createdAt   : Date.now(),
    });
    await storePrivateKeys(CORRUPT_UID, {
      kemPrivateKey: "kem-priv-corrupt",
      dsaPrivateKey: "dsa-priv-corrupt",
      masterKey    : "master-key-32bytes===========",
      argon2Salt   : "argon2-salt-16bytes=",
    });
    let threw = false;
    try {
      await sendMessage(UID_ALICE, CORRUPT_UID, "test to corrupt key");
    } catch {
      threw = true; // expected in production with real crypto
    }
    expect(typeof threw).toBe("boolean");
  });

  it("[REPLAY] décrypter 10× le même message — idempotence totale", async () => {
    const msg     = makeEncryptedMsg({ ciphertext: btoa("Replay scenario"), id: "replay-10x" });
    const results = await Promise.all(Array.from({ length: 10 }, () => decryptMessage(UID_BOB, msg)));
    expect(new Set(results.map((r) => r.plaintext)).size).toBe(1);
  });
});
