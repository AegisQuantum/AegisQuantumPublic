/**
 * double-ratchet.test.ts
 * src/crypto/_tests_/double-ratchet.test.ts
 *
 * Tests unitaires pour doubleRatchetEncrypt / doubleRatchetDecrypt.
 *
 * Prérequis : vitest + @openforge-sh/liboqs (WASM) disponible dans l'env de test.
 * Les mocks sur key-store sont nécessaires car IDB n'existe pas dans Node/jsdom.
 */

import { describe, it, expect, vi, beforeAll } from "vitest";
import { doubleRatchetEncrypt, doubleRatchetDecrypt } from "../double-ratchet";
import { kemGenerateKeyPair, kemEncapsulate, kemDecapsulate } from "../kem";
import { deserializeRatchetState } from "../ratchet-state";

// ─────────────────────────────────────────────────────────────────────────────
// Mock key-store — IDB non disponible en environnement Node/jsdom
// ─────────────────────────────────────────────────────────────────────────────

vi.mock("../../services/key-store", () => ({
  saveRatchetState: vi.fn().mockResolvedValue(undefined),
  loadRatchetState: vi.fn().mockResolvedValue(null),
}));

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures — générées une seule fois avant tous les tests (ML-KEM est lent)
// ─────────────────────────────────────────────────────────────────────────────

interface Peer {
  privKey    : string;
  pubKey     : string;
  convId     : string;
}

let alice : Peer;
let bob   : Peer;
let aliceInitSecret: string; // kemEncapsulate(bob.pubKey).sharedSecret
let bobInitSecret  : string; // kemDecapsulate(initKemCT, bob.privKey)
let initKemCT      : string;

beforeAll(async () => {
  const aliceKP = await kemGenerateKeyPair();
  const bobKP   = await kemGenerateKeyPair();

  alice = { privKey: aliceKP.privateKey, pubKey: aliceKP.publicKey, convId: "conv_alice_bob" };
  bob   = { privKey: bobKP.privateKey,   pubKey: bobKP.publicKey,   convId: "conv_alice_bob" };

  // Alice établit le secret initial (comme messaging.ts → sendMessage)
  const encap       = await kemEncapsulate(bob.pubKey);
  aliceInitSecret   = encap.sharedSecret;
  initKemCT         = encap.ciphertext;

  // Bob récupère le même secret (comme messaging.ts → decryptMessage)
  bobInitSecret     = await kemDecapsulate(initKemCT, bob.privKey);
}, 30_000); // timeout généreux pour l'init WASM ML-KEM

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Effectue un aller-retour complet Alice→Bob, retourne les deux états mis à jour. */
async function roundTrip(
  plaintext    : string,
  aliceState   : string | null,
  bobState     : string | null,
): Promise<{ decrypted: string; aliceNewState: string; bobNewState: string }> {
  const enc = await doubleRatchetEncrypt(
    plaintext, aliceState, alice.convId,
    alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
  );
  const dec = await doubleRatchetDecrypt(
    enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
    bobState, bob.convId,
    bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
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
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
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

  it("initialise receiveCount à 0 côté Bob", async () => {
    const enc   = await doubleRatchetEncrypt(
      "init", null, bob.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const dec   = await doubleRatchetDecrypt(
      enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
    );
    const state = deserializeRatchetState(dec.newStateJson);

    expect(state.receiveCount).toBe(1);
    expect(state.sendCount).toBe(0);
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
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    expect(enc.ciphertext).not.toBe(plaintext);
    expect(enc.ciphertext.length).toBeGreaterThan(0);
    expect(enc.nonce.length).toBeGreaterThan(0);
    expect(enc.kemCiphertext.length).toBeGreaterThan(0);
  });

  it("deux chiffrements du même plaintext produisent des ciphertexts différents", async () => {
    const enc1 = await doubleRatchetEncrypt(
      "même message", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const enc2 = await doubleRatchetEncrypt(
      "même message", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    // Deux ratchet steps KEM indépendants → ciphertexts distincts
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
    expect(enc1.nonce).not.toBe(enc2.nonce);
    expect(enc1.kemCiphertext).not.toBe(enc2.kemCiphertext);
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
// 4. Forward Secrecy — chaque messageKey est unique
// ─────────────────────────────────────────────────────────────────────────────

describe("Forward Secrecy", () => {
  it("N messages consécutifs → N kemCiphertexts tous distincts", async () => {
    const N = 10;
    let state: string | null = null;
    const kemCTs = new Set<string>();

    for (let i = 0; i < N; i++) {
      const enc = await doubleRatchetEncrypt(
        `message ${i}`, state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
      );
      kemCTs.add(enc.kemCiphertext);
      state = enc.newStateJson;
    }

    // Chaque message a effectué un ratchet KEM distinct
    expect(kemCTs.size).toBe(N);
  });

  it("N messages → N ciphertexts tous distincts (même plaintext)", async () => {
    const N = 8;
    let state: string | null = null;
    const ciphertexts = new Set<string>();

    for (let i = 0; i < N; i++) {
      const enc = await doubleRatchetEncrypt(
        "même texte", state, alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
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
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
      );
      const s = deserializeRatchetState(enc.newStateJson);
      privKeys.add(s.ourPrivateKey);
      state = enc.newStateJson;
    }

    // Chaque ratchet KEM génère une nouvelle paire → 5 clés privées distinctes
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
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
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
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
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
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
      );
      const dec = await doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        bobState, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
      );
      const s = deserializeRatchetState(dec.newStateJson);
      expect(s.receiveCount).toBe(i + 1);
      aliceState = enc.newStateJson;
      bobState   = dec.newStateJson;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Persistance — sérialisation / désérialisation du state
// ─────────────────────────────────────────────────────────────────────────────

describe("Persistance de l'état ratchet", () => {
  it("state sérialisé → désérialisé → round-trip toujours fonctionnel", async () => {
    // Envoi initial (state = null)
    const enc1 = await doubleRatchetEncrypt(
      "msg1", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const dec1 = await doubleRatchetDecrypt(
      enc1.ciphertext, enc1.nonce, enc1.messageIndex, enc1.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
    );

    // Simuler une déconnexion / reconnexion : sauvegarder et recharger le JSON
    const savedAliceState = enc1.newStateJson;
    const savedBobState   = dec1.newStateJson;

    // Deuxième message avec les états restaurés depuis "IDB"
    const enc2 = await doubleRatchetEncrypt(
      "msg2", savedAliceState, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const dec2 = await doubleRatchetDecrypt(
      enc2.ciphertext, enc2.nonce, enc2.messageIndex, enc2.kemCiphertext,
      savedBobState, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
    );

    expect(dec2.plaintext).toBe("msg2");
  });

  it("le JSON de l'état est un JSON valide avec tous les champs RatchetState", async () => {
    const enc   = await doubleRatchetEncrypt(
      "test", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const state = deserializeRatchetState(enc.newStateJson);

    // Tous les champs requis par RatchetState
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
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const state  = deserializeRatchetState(enc.newStateJson);
    expect(state.updatedAt).toBeGreaterThanOrEqual(before);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. KPI Performance — chaque step DR < 5 ms (hors init KEM WASM)
// ─────────────────────────────────────────────────────────────────────────────

describe("KPI Performance", () => {
  it("encrypt sur un état existant < 5 ms", async () => {
    // Préchauffer : premier message pour initialiser le state
    const init = await doubleRatchetEncrypt(
      "warmup", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    const start = performance.now();
    await doubleRatchetEncrypt(
      "perf test", init.newStateJson, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const elapsed = performance.now() - start;

    console.log(`[KPI] doubleRatchetEncrypt (state existant) : ${elapsed.toFixed(2)} ms`);
    expect(elapsed).toBeLessThan(5);
  }, 15_000);

  it("decrypt sur un état existant < 5 ms", async () => {
    // Préchauffer
    const enc1 = await doubleRatchetEncrypt(
      "warmup", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );
    const dec1 = await doubleRatchetDecrypt(
      enc1.ciphertext, enc1.nonce, enc1.messageIndex, enc1.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
    );
    const enc2 = await doubleRatchetEncrypt(
      "perf test", enc1.newStateJson, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    const start = performance.now();
    await doubleRatchetDecrypt(
      enc2.ciphertext, enc2.nonce, enc2.messageIndex, enc2.kemCiphertext,
      dec1.newStateJson, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
    );
    const elapsed = performance.now() - start;

    console.log(`[KPI] doubleRatchetDecrypt (state existant) : ${elapsed.toFixed(2)} ms`);
    expect(elapsed).toBeLessThan(5);
  }, 15_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Pentests / Cas adversariaux
// ─────────────────────────────────────────────────────────────────────────────

describe("Pentests", () => {

  // ── 8.1 messageIndex = 1 000 000 ────────────────────────────────────────
  it("messageIndex = 1 000 000 → throw ou réponse < 500 ms", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    // Forger un faux message avec messageIndex extrême
    const start = performance.now();
    let threw = false;
    try {
      await doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce,
        1_000_000,           // ← messageIndex forgé
        enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
      );
    } catch {
      threw = true;
    }
    const elapsed = performance.now() - start;

    if (!threw) {
      // Si ça ne throw pas, ça doit finir en < 500 ms
      console.log(`[PENTEST] messageIndex=1M sans throw : ${elapsed.toFixed(0)} ms`);
      expect(elapsed).toBeLessThan(500);
    } else {
      console.log(`[PENTEST] messageIndex=1M → throw propre ✓`);
    }
  }, 10_000);

  // ── 8.2 Mauvais kemCiphertext ────────────────────────────────────────────
  it("kemCiphertext invalide (random bytes) → throw", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    // Remplacer le kemCiphertext par du bruit aléatoire encodé en base64
    const garbage = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(1088))));

    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex,
        garbage,          // ← kemCiphertext corrompu
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
      )
    ).rejects.toThrow();
  });

  // ── 8.3 State JSON corrompu → throw propre ───────────────────────────────
  it("stateJson corrompu → throw propre (pas de crash silencieux)", async () => {
    await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    await expect(
      doubleRatchetEncrypt(
        "msg2",
        '{"this":"is","not":"a valid ratchet state"}', // JSON valide mais incomplet
        alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
      )
    ).rejects.toThrow();
  });

  it("stateJson non-JSON → throw propre", async () => {
    await expect(
      doubleRatchetEncrypt(
        "msg", "NOT_JSON_AT_ALL", alice.convId,
        alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
      )
    ).rejects.toThrow();
  });

  // ── 8.4 Replay — même message déchiffré deux fois ────────────────────────
  it("replay du même message → throw (replay détecté)", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg original", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    // Première réception — ok
    const dec = await doubleRatchetDecrypt(
      enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
      null, bob.convId,
      bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
    );
    expect(dec.plaintext).toBe("msg original");

    // Deuxième réception du même message avec l'état avancé → doit throw
    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        dec.newStateJson,   // ← état après la première réception
        bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
      )
    ).rejects.toThrow(/replay/i);
  });

  // ── 8.5 Mauvaise clé privée ──────────────────────────────────────────────
  it("mauvaise clé privée KEM pour decapsulate → throw", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    // Utiliser la clé privée d'Alice pour décapsuler un CT chiffré pour Bob
    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        null, alice.convId,
        alice.privKey,      // ← mauvaise clé privée (Alice au lieu de Bob)
        alice.pubKey, bob.pubKey, aliceInitSecret,
      )
    ).rejects.toThrow();
  });

  // ── 8.6 Ciphertext AES falsifié → throw (AEAD integrity) ────────────────
  it("ciphertext AES falsifié → throw (intégrité AEAD)", async () => {
    const enc = await doubleRatchetEncrypt(
      "message authentique", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    // Flipper un octet dans le ciphertext base64
    const tampered = enc.ciphertext.slice(0, -4) + "XXXX";

    await expect(
      doubleRatchetDecrypt(
        tampered, enc.nonce, enc.messageIndex, enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
      )
    ).rejects.toThrow();
  });

  // ── 8.7 messageIndex négatif → throw ────────────────────────────────────
  it("messageIndex négatif → throw", async () => {
    const enc = await doubleRatchetEncrypt(
      "msg", null, alice.convId,
      alice.privKey, alice.pubKey, bob.pubKey, aliceInitSecret,
    );

    await expect(
      doubleRatchetDecrypt(
        enc.ciphertext, enc.nonce,
        -1,               // ← messageIndex invalide
        enc.kemCiphertext,
        null, bob.convId,
        bob.privKey, bob.pubKey, alice.pubKey, bobInitSecret,
      )
    ).rejects.toThrow();
  });
});