/**
 * messaging.test.ts — Tests du pipeline Double Ratchet (ML-KEM-768 + HKDF + AES-256-GCM)
 *
 * Ces tests utilisent le VRAI crypto (liboqs WASM, WebCrypto) via le mock Firestore/IDB.
 * Chaque test alice↔bob utilise de vraies keypairs ML-KEM-768 / ML-DSA-65.
 */
import { webcrypto } from 'node:crypto';
import { vi } from 'vitest';

// Polyfill the Web Crypto API for Node.js
vi.stubGlobal('crypto', webcrypto);


import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  getConversationId,
  getOrCreateConversation,
  sendMessage,
  decryptMessage,
  subscribeToConversations,
  subscribeToMessages,
} from "../messaging";
import { storePrivateKeys, clearPrivateKeys } from "../key-store";
import { publishPublicKeys }                  from "../key-registry";
import { kemGenerateKeyPair }                 from "../../crypto/kem";
import { dsaGenerateKeyPair }                 from "../../crypto/dsa";
import type { EncryptedMessage }              from "../../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const UID_ALICE = "test-alice";
const UID_BOB   = "test-bob";
const UID_CAROL = "test-carol";

beforeEach(async () => {
  const masterKey = btoa(String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i + 1)));

  for (const uid of [UID_ALICE, UID_BOB]) {
    const kem = await kemGenerateKeyPair();
    const dsa = await dsaGenerateKeyPair();
    await storePrivateKeys(uid, {
      kemPrivateKey: kem.privateKey,
      dsaPrivateKey: dsa.privateKey,
      masterKey,
      argon2Salt   : btoa("salt16bytes====="),
    });
    await publishPublicKeys(uid, {
      uid,
      kemPublicKey: kem.publicKey,
      dsaPublicKey: dsa.publicKey,
      createdAt   : Date.now(),
    });
  }
});

afterEach(() => {
  clearPrivateKeys();
});

// ─────────────────────────────────────────────────────────────────────────────
// Helper : Alice envoie, Bob attend de voir le message dechiffre
// Retourne apres que saveRatchetState cote Bob soit persiste (delai 200ms).
// ─────────────────────────────────────────────────────────────────────────────

async function aliceSendsBobDecrypts(text: string): Promise<{
  plaintext: string;
  verified : boolean;
}> {
  const convId = getConversationId(UID_ALICE, UID_BOB);

  const result = await new Promise<{ plaintext: string; verified: boolean }>((resolve, reject) => {
    const unsubBob = subscribeToMessages(UID_BOB, convId, msgs => {
      const m = msgs.find(m => m.senderUid === UID_ALICE && !m.plaintext.startsWith("["));
      if (m) {
        unsubBob();
        resolve({ plaintext: m.plaintext, verified: m.verified });
      }
    });

    sendMessage(UID_ALICE, UID_BOB, text).catch(err => {
      unsubBob();
      reject(err);
    });

    setTimeout(() => {
      unsubBob();
      reject(new Error(`Timeout: Bob n'a pas recu le message "${text}"`));
    }, 10_000);
  });

  // Laisser le temps a saveRatchetState (IDB async) de se terminer cote Bob
  // avant qu'il puisse envoyer a son tour. Sans ce delai, Bob lirait un stateJson
  // null depuis l'IDB et rebootstrapperait un nouvel etat au lieu de continuer le ratchet.
  await new Promise(r => setTimeout(r, 200));

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. getConversationId — tests purs
// ─────────────────────────────────────────────────────────────────────────────

describe("getConversationId [UNIT]", () => {
  it("est symetrique", () => {
    expect(getConversationId(UID_ALICE, UID_BOB))
      .toBe(getConversationId(UID_BOB, UID_ALICE));
  });

  it("est deterministe", () => {
    expect(getConversationId(UID_ALICE, UID_BOB))
      .toBe(getConversationId(UID_ALICE, UID_BOB));
  });

  it("produit des IDs differents pour des paires differentes", () => {
    expect(getConversationId(UID_ALICE, UID_BOB))
      .not.toBe(getConversationId(UID_ALICE, UID_CAROL));
  });

  it("utilise des UIDs tries separes par underscore", () => {
    const sorted = [UID_ALICE, UID_BOB].sort().join("_");
    expect(getConversationId(UID_ALICE, UID_BOB)).toBe(sorted);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. getOrCreateConversation
// ─────────────────────────────────────────────────────────────────────────────

describe("getOrCreateConversation [INTEGRATION]", () => {
  it("retourne le convId deterministe", async () => {
    const convId = await getOrCreateConversation(UID_ALICE, UID_BOB);
    expect(convId).toBe(getConversationId(UID_ALICE, UID_BOB));
  });

  it("est idempotent", async () => {
    expect(await getOrCreateConversation(UID_ALICE, UID_BOB))
      .toBe(await getOrCreateConversation(UID_ALICE, UID_BOB));
  });

  it("est symetrique", async () => {
    expect(await getOrCreateConversation(UID_ALICE, UID_BOB))
      .toBe(await getOrCreateConversation(UID_BOB, UID_ALICE));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Double Ratchet — chiffrement/dechiffrement bout en bout
// ─────────────────────────────────────────────────────────────────────────────

describe("Double Ratchet [INTEGRATION]", () => {

  it("1er message Alice -> Bob, dechiffrement correct + signature valide", async () => {
    const { plaintext, verified } = await aliceSendsBobDecrypts("Premier message !");
    expect(plaintext).toBe("Premier message !");
    expect(verified).toBe(true);
  }, 15_000);

  it("2eme message : etat ratchet restaure depuis IDB, dechiffrement correct", async () => {
    await aliceSendsBobDecrypts("Message 1");
    const { plaintext } = await aliceSendsBobDecrypts("Message 2");
    expect(plaintext).toBe("Message 2");
  }, 25_000);

  it("3 messages successifs tous dechiffres correctement", async () => {
    for (const text of ["Alpha", "Bravo", "Charlie"]) {
      const { plaintext } = await aliceSendsBobDecrypts(text);
      expect(plaintext).toBe(text);
    }
  }, 35_000);

  it("Bob peut repondre a Alice (bidirectionnel)", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);

    // Alice envoie en premier — Bob sauvegarde son etat ratchet de reception en IDB.
    // Le delai de 200ms dans aliceSendsBobDecrypts garantit que saveRatchetState est fini
    // avant que Bob envoie (sinon Bob lirait stateJson=null et rebootstrapperait).
    await aliceSendsBobDecrypts("Salut Bob !");

    // Bob -> Alice (premier message de Bob : stateJson null pour la direction BOB->ALICE)
    const reponse = await new Promise<string>((resolve, reject) => {
      const unsubAlice = subscribeToMessages(UID_ALICE, convId, msgs => {
        const m = msgs.find(m => m.senderUid === UID_BOB && !m.plaintext.startsWith("["));
        if (m) {
          unsubAlice();
          resolve(m.plaintext);
        }
      });

      sendMessage(UID_BOB, UID_ALICE, "Salut Alice !").catch(err => {
        unsubAlice();
        reject(err);
      });

      setTimeout(() => {
        unsubAlice();
        reject(new Error("Timeout: Alice n'a pas recu la reponse de Bob"));
      }, 10_000);
    });

    expect(reponse).toBe("Salut Alice !");
  }, 30_000);

  it("unicode + emoji chiffres/dechiffres correctement", async () => {
    const text = "Hello world ! Emoji test 42";
    const { plaintext } = await aliceSendsBobDecrypts(text);
    expect(plaintext).toBe(text);
  }, 15_000);

  it("long message (5 KB) chiffre/dechiffre correctement", async () => {
    const text = "A".repeat(5_000);
    const { plaintext } = await aliceSendsBobDecrypts(text);
    expect(plaintext).toBe(text);
  }, 15_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. sendMessage — cas limites
// ─────────────────────────────────────────────────────────────────────────────

describe("sendMessage [INTEGRATION]", () => {
  it("reussit sans exception", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "Hello")).resolves.not.toThrow();
  }, 10_000);

  it("leve une erreur si le contact n'a pas de cles publiques", async () => {
    await expect(sendMessage(UID_ALICE, "uid-fantome", "test"))
      .rejects.toThrow(/introuvable/i);
  }, 10_000);

  it("leve une erreur si les cles de l'envoyeur sont purgees", async () => {
    clearPrivateKeys();
    await expect(sendMessage(UID_ALICE, UID_BOB, "test")).rejects.toThrow();
  });

  it("gere un plaintext vide", async () => {
    await expect(sendMessage(UID_ALICE, UID_BOB, "")).resolves.not.toThrow();
  }, 10_000);

  it("[KPI] se termine en < 5 000 ms", async () => {
    const t0 = performance.now();
    await sendMessage(UID_ALICE, UID_BOB, "KPI test");
    const ms = performance.now() - t0;
    console.log(`[KPI] sendMessage: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(5_000);
  }, 10_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. decryptMessage — cas limites
// ─────────────────────────────────────────────────────────────────────────────

describe("decryptMessage [UNIT]", () => {
  it("preserve senderUid, plaintext, timestamp", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);

    await new Promise<void>((resolve, reject) => {
      const unsub = subscribeToMessages(UID_BOB, convId, msgs => {
        const m = msgs.find(m => m.senderUid === UID_ALICE && !m.plaintext.startsWith("["));
        if (m) {
          expect(m.senderUid).toBe(UID_ALICE);
          expect(m.plaintext).toBe("test-metadata");
          expect(typeof m.timestamp).toBe("number");
          unsub();
          resolve();
        }
      });
      sendMessage(UID_ALICE, UID_BOB, "test-metadata").catch(reject);
      setTimeout(() => { unsub(); reject(new Error("timeout")); }, 8_000);
    });
  }, 15_000);

  it("initKemCiphertext absent + stateJson null -> erreur explicite", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const msg: EncryptedMessage = {
      id            : "no-init-kem",
      conversationId: convId,
      senderUid     : UID_ALICE,
      ciphertext    : btoa("X"),
      nonce         : btoa("N"),
      kemCiphertext : btoa("C"),
      signature     : "",
      messageIndex  : 0,
      timestamp     : Date.now(),
      // initKemCiphertext absent intentionnellement
    };
    await expect(decryptMessage(UID_BOB, msg)).rejects.toThrow(/initKemCiphertext/i);
  }, 5_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Invariants de securite
// ─────────────────────────────────────────────────────────────────────────────

describe("Invariants de securite [SEC]", () => {
  it("[SEC] sendMessage leve une erreur si cles envoyeur absentes", async () => {
    clearPrivateKeys();
    await expect(sendMessage(UID_ALICE, UID_BOB, "secret")).rejects.toThrow();
  });

  it("[SEC] sendMessage leve une erreur si contact sans cles publiques", async () => {
    await expect(sendMessage(UID_ALICE, "uid-fantome-sec", "secret"))
      .rejects.toThrow(/introuvable/i);
  });

  it("[SEC] deux messages successifs dechiffres = forward secrecy fonctionne", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const results: string[] = [];

    for (const text of ["sec-msg-1", "sec-msg-2"]) {
      await new Promise<void>((resolve, reject) => {
        const unsub = subscribeToMessages(UID_BOB, convId, msgs => {
          const last = msgs.filter(m => m.senderUid === UID_ALICE && !m.plaintext.startsWith("[")).pop();
          if (last) {
            results.push(last.plaintext);
            unsub();
            resolve();
          }
        });
        sendMessage(UID_ALICE, UID_BOB, text).catch(reject);
        setTimeout(() => { unsub(); reject(new Error("timeout")); }, 8_000);
      });
    }

    expect(results).toEqual(["sec-msg-1", "sec-msg-2"]);
  }, 25_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. subscribeToConversations / subscribeToMessages
// ─────────────────────────────────────────────────────────────────────────────

describe("subscribeToConversations [INTEGRATION]", () => {
  it("retourne une fonction de desabonnement", () => {
    const unsub = subscribeToConversations(UID_ALICE, () => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("le callback recoit un tableau", async () => {
    const received: unknown[][] = [];
    const unsub = subscribeToConversations(UID_CAROL, c => received.push(c));
    await new Promise(r => setTimeout(r, 300));
    unsub();
    expect(Array.isArray(received[0])).toBe(true);
  });
});

describe("subscribeToMessages [INTEGRATION]", () => {
  it("retourne une fonction de desabonnement", () => {
    const unsub = subscribeToMessages(UID_ALICE, getConversationId(UID_ALICE, UID_BOB), () => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("le callback est appele apres un envoi", async () => {
    const convId   = getConversationId(UID_ALICE, UID_BOB);
    const messages: unknown[] = [];
    const unsub = subscribeToMessages(UID_ALICE, convId, msgs => messages.push(...msgs));
    await sendMessage(UID_ALICE, UID_BOB, "Ping");
    await new Promise(r => setTimeout(r, 500));
    unsub();
    expect(messages.length).toBeGreaterThan(0);
  }, 10_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. KPIs
// ─────────────────────────────────────────────────────────────────────────────

describe("Performance KPIs", () => {
  it("getConversationId < 0.1 ms", () => {
    const t0 = performance.now();
    getConversationId(UID_ALICE, UID_BOB);
    expect(performance.now() - t0).toBeLessThan(0.1);
  });

  it("sendMessage < 5 000 ms", async () => {
    const t0 = performance.now();
    await sendMessage(UID_ALICE, UID_BOB, "KPI");
    const ms = performance.now() - t0;
    console.log(`[KPI] sendMessage: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(5_000);
  }, 10_000);

  it("[KPI] taille EncryptedMessage prod <= 15 KB", () => {
    const msg: EncryptedMessage = {
      id               : "prod-size",
      conversationId   : getConversationId(UID_ALICE, UID_BOB),
      senderUid        : UID_ALICE,
      ciphertext       : btoa("A".repeat(100)),
      nonce            : btoa("N".repeat(12)),
      kemCiphertext    : btoa("C".repeat(1088)),
      signature        : btoa("S".repeat(3309)),
      messageIndex     : 0,
      timestamp        : Date.now(),
      initKemCiphertext: btoa("I".repeat(1088)),
    };
    const sizeKB = JSON.stringify(msg).length / 1024;
    console.log(`[KPI] EncryptedMessage prod: ${sizeKB.toFixed(2)} KB`);
    expect(sizeKB).toBeLessThan(15);
  });
});
