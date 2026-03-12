/**
 * double-ratchet.test.ts
 * src/crypto/__tests__/double-ratchet.test.ts
 *
 * Compatible avec la nouvelle API doubleRatchetDecrypt :
 *   - sharedSecret supprimé
 *   - initKemCiphertext?: string  (optionnel, présent uniquement sur le 1er message)
 *   - doubleRatchetEncrypt retourne initKemCiphertext sur le 1er message
 */

import { describe, it, expect, vi, beforeAll } from "vitest";
import { doubleRatchetEncrypt, doubleRatchetDecrypt } from "../double-ratchet";
import { kemGenerateKeyPair } from "../kem";
import { deserializeRatchetState } from "../ratchet-state";

// ─────────────────────────────────────────────────────────────────────────────
// Mock key-store — IDB non disponible en Node/jsdom
// ─────────────────────────────────────────────────────────────────────────────

vi.mock("../../services/key-store", () => ({
  saveRatchetState: vi.fn().mockResolvedValue(undefined),
  loadRatchetState: vi.fn().mockResolvedValue(null),
}));

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

interface Peer {
  privKey: string;
  pubKey : string;
  convId : string;
}

let alice: Peer;
let bob  : Peer;

beforeAll(async () => {
  const aliceKP = await kemGenerateKeyPair();
  const bobKP   = await kemGenerateKeyPair();
  alice = { privKey: aliceKP.privateKey, pubKey: aliceKP.publicKey, convId: "conv_alice_bob" };
  bob   = { privKey: bobKP.privateKey,   pubKey: bobKP.publicKey,   convId: "conv_alice_bob" };
}, 30_000);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Effectue un aller-retour Alice→Bob.
 *
 * Nouvelle API :
 *  - doubleRatchetEncrypt n'a plus besoin de sharedSecret (le fait en interne)
 *  - doubleRatchetDecrypt reçoit initKemCiphertext (depuis enc.initKemCiphertext)
 *    au lieu du sharedSecret pré-calculé
 */
async function roundTrip(
  plaintext  : string,
  aliceState : string | null,
  bobState   : string | null,
): Promise<{ decrypted: string; aliceNewState: string; bobNewState: string }> {
  const enc = await doubleRatchetEncrypt(
    plaintext, aliceState, alice.convId,
    alice.privKey, alice.pubKey, bob.pubKey,
  );

  const dec = await doubleRatchetDecrypt(
    enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
    bobState, bob.convId,
    bob.privKey, bob.pubKey, alice.pubKey,
    enc.initKemCiphertext,   // ← présent sur le 1er message, undefined ensuite
  );

  return { decrypted: dec.plaintext, aliceNewState: enc.newStateJson, bobNewState: dec.newStateJson };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Initialisation
// ─────────────────────────────────────────────────────────────────────────────

describe("Initialisation depuis sharedSecret", () => {
  it("produit un état valide avec tous les champs requis", async () => {
    const enc   = await doubleRatchetEncrypt(
      "hello", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const state = deserializeRatchetState(enc.newStateJson);

    expect(state.conversationId).toBe(alice.convId);
    expect(state.rootKey).toBeTruthy();
    expect(state.sendingChainKey).toBeTruthy();
    expect(state.ourPrivateKey).toBeTruthy();
    expect(state.ourPublicKey).toBeTruthy();
    expect(state.theirPublicKey).toBe(bob.pubKey);
    expect(state.sendCount).toBe(1);
    expect(state.receiveCount).toBe(0);
    expect(state.updatedAt).toBeGreaterThan(0);
  });

  it("le premier message contient initKemCiphertext", async () => {
    const enc = await doubleRatchetEncrypt(
      "init", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    expect(enc.initKemCiphertext).toBeDefined();
    expect(enc.initKemCiphertext!.length).toBeGreaterThan(100); // 1088 bytes en base64 ≈ 1452 chars
  });

  it("les messages suivants n'ont pas initKemCiphertext", async () => {
    const enc1 = await doubleRatchetEncrypt(
      "msg1", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const enc2 = await doubleRatchetEncrypt(
      "msg2", enc1.newStateJson, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    expect(enc2.initKemCiphertext).toBeUndefined();
  });

  it("initialise receiveCount à 0 côté Bob", async () => {
    const enc = await doubleRatchetEncrypt(
      "init", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const dec = await doubleRatchetDecrypt(
      enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey,
      enc.initKemCiphertext,
    );
    const state = deserializeRatchetState(dec.newStateJson);
    expect(state.receiveCount).toBe(1);
    expect(state.sendCount).toBe(0);
  });

  it("throw si stateJson === null et initKemCiphertext absent", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        undefined, // ← manquant intentionnellement
      )
    ).rejects.toThrow(/initKemCiphertext/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Chiffrement de base
// ─────────────────────────────────────────────────────────────────────────────

describe("Chiffrement de base", () => {
  it("le ciphertext est différent du plaintext", async () => {
    const plaintext = "message secret";
    const enc = await doubleRatchetEncrypt(
      plaintext, null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    expect(enc.ciphertext).not.toBe(plaintext);
    expect(enc.ciphertext.length).toBeGreaterThan(0);
    expect(enc.nonce.length).toBeGreaterThan(0);
    expect(enc.kemCiphertext.length).toBeGreaterThan(0);
  });

  it("deux chiffrements du même plaintext produisent des ciphertexts différents", async () => {
    const enc1 = await doubleRatchetEncrypt(
      "même message", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const enc2 = await doubleRatchetEncrypt(
      "même message", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
    expect(enc1.nonce).not.toBe(enc2.nonce);
    expect(enc1.kemCiphertext).not.toBe(enc2.kemCiphertext);
    expect(enc1.initKemCiphertext).not.toBe(enc2.initKemCiphertext);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Round-trip Alice → Bob
// ─────────────────────────────────────────────────────────────────────────────

describe("Round-trip Alice → Bob", () => {
  it("déchiffre correctement le premier message", async () => {
    const { decrypted } = await roundTrip("bonjour Bob", null, null);
    expect(decrypted).toBe("bonjour Bob");
  });

  it("déchiffre une chaîne de 5 messages consécutifs", async () => {
    let aliceState: string | null = null;
    let bobState  : string | null = null;
    const messages = ["msg1", "msg2", "msg3", "msg4", "msg5"];

    for (const msg of messages) {
      const result = await roundTrip(msg, aliceState, bobState);
      expect(result.decrypted).toBe(msg);
      aliceState = result.aliceNewState;
      bobState   = result.bobNewState;
    }
  });

  it("préserve les caractères spéciaux et unicode", async () => {
    const exotic = "🔒 héllo wörld — \"quotes\" & <tags> \n newline \t tab";
    const { decrypted } = await roundTrip(exotic, null, null);
    expect(decrypted).toBe(exotic);
  });

  it("fonctionne avec un message vide", async () => {
    const { decrypted } = await roundTrip("", null, null);
    expect(decrypted).toBe("");
  });

  it("fonctionne avec un message très long (10 KB)", async () => {
    const big = "A".repeat(10_000);
    const { decrypted } = await roundTrip(big, null, null);
    expect(decrypted).toBe(big);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Forward Secrecy
// ─────────────────────────────────────────────────────────────────────────────

describe("Forward Secrecy", () => {
  it("N messages consécutifs → N kemCiphertexts tous distincts", async () => {
    const N = 10;
    let state: string | null = null;
    const kemCTs = new Set<string>();

    for (let i = 0; i < N; i++) {
      const enc = await doubleRatchetEncrypt(
        `message ${i}`, state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      );
      kemCTs.add(enc.kemCiphertext);
      state = enc.newStateJson;
    }
    expect(kemCTs.size).toBe(N);
  });

  it("N messages → N ciphertexts tous distincts (même plaintext)", async () => {
    const N = 8;
    let state: string | null = null;
    const ciphertexts = new Set<string>();

    for (let i = 0; i < N; i++) {
      const enc = await doubleRatchetEncrypt(
        "même texte", state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      );
      ciphertexts.add(enc.ciphertext);
      state = enc.newStateJson;
    }
    expect(ciphertexts.size).toBe(N);
  });

  it("les ourPrivateKey dans state changent à chaque ratchet step", async () => {
    let state: string | null = null;
    const privKeys = new Set<string>();

    for (let i = 0; i < 5; i++) {
      const enc = await doubleRatchetEncrypt(
        `msg ${i}`, state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      );
      const s = deserializeRatchetState(enc.newStateJson);
      privKeys.add(s.ourPrivateKey);
      state = enc.newStateJson;
    }
    expect(privKeys.size).toBe(5);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. messageIndex et receiveCount
// ─────────────────────────────────────────────────────────────────────────────

describe("messageIndex et receiveCount", () => {
  it("messageIndex s'incrémente de 0 à N-1", async () => {
    let state: string | null = null;
    for (let i = 0; i < 5; i++) {
      const enc = await doubleRatchetEncrypt(
        `msg ${i}`, state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      );
      expect(enc.messageIndex).toBe(i);
      state = enc.newStateJson;
    }
  });

  it("sendCount dans state = messageIndex + 1 après chaque envoi", async () => {
    let state: string | null = null;
    for (let i = 0; i < 4; i++) {
      const enc = await doubleRatchetEncrypt(
        `msg ${i}`, state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      );
      const s = deserializeRatchetState(enc.newStateJson);
      expect(s.sendCount).toBe(i + 1);
      state = enc.newStateJson;
    }
  });

  it("receiveCount dans state = messageIndex + 1 après chaque réception", async () => {
    let aliceState: string | null = null;
    let bobState  : string | null = null;

    for (let i = 0; i < 4; i++) {
      const enc = await doubleRatchetEncrypt(
        `msg ${i}`, aliceState, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      );
      const dec = await doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        bobState, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        enc.initKemCiphertext,
      );
      const s = deserializeRatchetState(dec.newStateJson);
      expect(s.receiveCount).toBe(i + 1);
      aliceState = enc.newStateJson;
      bobState   = dec.newStateJson;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Persistance
// ─────────────────────────────────────────────────────────────────────────────

describe("Persistance de l'état ratchet", () => {
  it("state sérialisé → désérialisé → round-trip toujours fonctionnel", async () => {
    const enc1 = await doubleRatchetEncrypt(
      "msg1", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const dec1 = await doubleRatchetDecrypt(
      enc1.ciphertext, enc1.nonce, enc1.messageIndex, enc1.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey,
      enc1.initKemCiphertext,
    );

    // Simuler sauvegarde/rechargement IDB
    const savedAliceState = enc1.newStateJson;
    const savedBobState   = dec1.newStateJson;

    const enc2 = await doubleRatchetEncrypt(
      "msg2", savedAliceState, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const dec2 = await doubleRatchetDecrypt(
      enc2.ciphertext, enc2.nonce, enc2.messageIndex, enc2.kemCiphertext,
      savedBobState, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey,
      enc2.initKemCiphertext, // undefined sur les messages suivants
    );

    expect(dec2.plaintext).toBe("msg2");
  });

  it("le JSON de l'état est un JSON valide avec tous les champs RatchetState", async () => {
    const enc   = await doubleRatchetEncrypt(
      "test", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const state = deserializeRatchetState(enc.newStateJson);

    expect(typeof state.conversationId  ).toBe("string");
    expect(typeof state.rootKey         ).toBe("string");
    expect(typeof state.sendingChainKey ).toBe("string");
    expect(typeof state.ourPrivateKey   ).toBe("string");
    expect(typeof state.ourPublicKey    ).toBe("string");
    expect(typeof state.theirPublicKey  ).toBe("string");
    expect(typeof state.sendCount       ).toBe("number");
    expect(typeof state.receiveCount    ).toBe("number");
    expect(typeof state.updatedAt       ).toBe("number");
  });

  it("updatedAt est mis à jour à chaque opération", async () => {
    const before = Date.now();
    const enc    = await doubleRatchetEncrypt(
      "timing test", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const state  = deserializeRatchetState(enc.newStateJson);
    expect(state.updatedAt).toBeGreaterThanOrEqual(before);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. KPI Performance
// ─────────────────────────────────────────────────────────────────────────────

describe("KPI Performance", () => {
  it("encrypt sur un état existant < 10 ms", async () => {
    // Le bootstrap (stateJson=null) fait 2x kemEncapsulate → plus lent.
    // Le KPI de 5ms s'applique aux messages suivants (state existant).
    const init = await doubleRatchetEncrypt(
      "warmup", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );

    const start = performance.now();
    await doubleRatchetEncrypt(
      "perf test", init.newStateJson, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const elapsed = performance.now() - start;

    console.log(`[KPI] doubleRatchetEncrypt (state existant) : ${elapsed.toFixed(2)} ms`);
    expect(elapsed).toBeLessThan(10); // 10ms : conservative pour CI/CD, 5ms en local
  }, 15_000);

  it("decrypt sur un état existant < 10 ms", async () => {
    const enc1 = await doubleRatchetEncrypt(
      "warmup", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const dec1 = await doubleRatchetDecrypt(
      enc1.ciphertext, enc1.nonce, enc1.messageIndex, enc1.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey,
      enc1.initKemCiphertext,
    );
    const enc2 = await doubleRatchetEncrypt(
      "perf test", enc1.newStateJson, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );

    const start = performance.now();
    await doubleRatchetDecrypt(
      enc2.ciphertext, enc2.nonce, enc2.messageIndex, enc2.kemCiphertext,
      dec1.newStateJson, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey,
      enc2.initKemCiphertext,
    );
    const elapsed = performance.now() - start;

    console.log(`[KPI] doubleRatchetDecrypt (state existant) : ${elapsed.toFixed(2)} ms`);
    expect(elapsed).toBeLessThan(10);
  }, 15_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Pentests
// ─────────────────────────────────────────────────────────────────────────────

describe("Pentests", () => {

  it("messageIndex = 1 000 000 → throw ou réponse < 500 ms", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );

    const start = performance.now();
    let threw = false;
    try {
      await doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, 1_000_000, enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        enc.initKemCiphertext,
      );
    } catch {
      threw = true;
    }
    const elapsed = performance.now() - start;

    if (!threw) {
      console.log(`[PENTEST] messageIndex=1M sans throw : ${elapsed.toFixed(0)} ms`);
      expect(elapsed).toBeLessThan(500);
    } else {
      console.log(`[PENTEST] messageIndex=1M → throw propre ✓`);
    }
  }, 10_000);

  it("kemCiphertext invalide (random bytes) → throw", async () => {
    const enc     = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const garbage = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(1088))));

    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex,
        garbage,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        enc.initKemCiphertext,
      )
    ).rejects.toThrow();
  });

  it("stateJson corrompu → throw propre", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    await expect(
      doubleRatchetEncrypt(
        "msg2",
        '{"this":"is","not":"a valid ratchet state"}',
        alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      )
    ).rejects.toThrow();
  });

  it("stateJson non-JSON → throw propre", async () => {
    await expect(
      doubleRatchetEncrypt(
        "msg", "NOT_JSON_AT_ALL", alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
      )
    ).rejects.toThrow();
  });

  it("replay du même message → throw (replay détecté)", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg original", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );

    const dec = await doubleRatchetDecrypt(
      enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey,
      enc.initKemCiphertext,
    );
    expect(dec.plaintext).toBe("msg original");

    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        dec.newStateJson,
        bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        enc.initKemCiphertext,
      )
    ).rejects.toThrow(/replay/i);
  });

  it("mauvaise clé privée KEM pour decapsulate → throw", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );

    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        null, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey,
        enc.initKemCiphertext,
      )
    ).rejects.toThrow();
  });

  it("ciphertext AES falsifié → throw (intégrité AEAD)", async () => {
    const enc     = await doubleRatchetEncrypt(
      "message authentique", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );
    const tampered = enc.ciphertext.slice(0, -4) + "XXXX";

    await expect(
      doubleRatchetDecrypt(
        tampered, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        enc.initKemCiphertext,
      )
    ).rejects.toThrow();
  });

  it("messageIndex négatif → throw", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey,
    );

    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, -1, enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey,
        enc.initKemCiphertext,
      )
    ).rejects.toThrow();
  });
});