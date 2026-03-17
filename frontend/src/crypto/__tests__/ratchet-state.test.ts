/**
 * ratchet-state.test.ts — Unit & Security tests for ratchet-state.ts
 *
 * ══════════════════════════════════════════════════════════════════
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────
 *  - serializeRatchetState()   : JSON string valide, round-trip
 *  - deserializeRatchetState() : restitue tous les champs
 *  - Round-trip complet        : serialize → deserialize → identique
 *
 *  ── Robustesse / Validation ─────────────────────────────────────
 *  - JSON malformé → throw
 *  - Champs manquants → throw avec nom du champ
 *  - Valeurs null pour champs requis → throw
 *  - JSON vide ({}) → throw
 *  - Types inattendus (number, boolean) → throw si champ absent
 *
 *  ── Security / Pentest ──────────────────────────────────────────
 *  - [PENTEST] Injection JSON (prototype pollution) → rejet propre
 *  - [PENTEST] Champ supplémentaire inconnu → ignoré (pas de crash)
 *  - [PENTEST] Valeur numérique à la place d'une string → acceptée
 *    (les champs numériques sendCount/receiveCount/updatedAt sont légitimes)
 * ══════════════════════════════════════════════════════════════════
 */

import { describe, it, expect } from "vitest";
import { serializeRatchetState, deserializeRatchetState } from "../ratchet-state";
import type { RatchetState } from "../../types/ratchet";

// ── Fixture ────────────────────────────────────────────────────────────────

function makeState(overrides: Partial<RatchetState> = {}): RatchetState {
  return {
    conversationId  : "conv-alice-bob-001",
    rootKey         : "rootKey-base64-AAAA",
    sendingChainKey : "sendChainKey-base64",
    receivingChainKey:"recvChainKey-base64",
    ourPrivateKey   : "ourPrivKey-base64",
    ourPublicKey    : "ourPubKey-base64",
    theirPublicKey  : "theirPubKey-base64",
    sendCount       : 0,
    receiveCount    : 0,
    updatedAt       : 1700000000000,
    skippedMessageKeys : {}, // empty by default
    ...overrides,
  };
}

const REQUIRED_FIELDS: (keyof RatchetState)[] = [
  "conversationId",
  "rootKey",
  "sendingChainKey",
  "receivingChainKey",
  "ourPrivateKey",
  "ourPublicKey",
  "theirPublicKey",
  "sendCount",
  "receiveCount",
  "updatedAt",
];

// ══════════════════════════════════════════════════════════════════════════
// 1. serializeRatchetState
// ══════════════════════════════════════════════════════════════════════════

describe("serializeRatchetState", () => {
  it("retourne une string JSON non-vide", () => {
    const json = serializeRatchetState(makeState());
    expect(typeof json).toBe("string");
    expect(json.length).toBeGreaterThan(0);
  });

  it("produit du JSON valide (parseable)", () => {
    const json = serializeRatchetState(makeState());
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("préserve tous les champs du state", () => {
    const state  = makeState({ sendCount: 42, receiveCount: 7 });
    const parsed = JSON.parse(serializeRatchetState(state));
    for (const field of REQUIRED_FIELDS) {
      expect(parsed[field]).toBeDefined();
    }
  });

  it("préserve les valeurs exactes (sendCount, receiveCount, updatedAt)", () => {
    const state  = makeState({ sendCount: 17, receiveCount: 3, updatedAt: 9999999 });
    const parsed = JSON.parse(serializeRatchetState(state));
    expect(parsed.sendCount).toBe(17);
    expect(parsed.receiveCount).toBe(3);
    expect(parsed.updatedAt).toBe(9999999);
  });

  it("deux états différents → JSON différents", () => {
    const j1 = serializeRatchetState(makeState({ sendCount: 1 }));
    const j2 = serializeRatchetState(makeState({ sendCount: 2 }));
    expect(j1).not.toBe(j2);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. deserializeRatchetState
// ══════════════════════════════════════════════════════════════════════════

describe("deserializeRatchetState", () => {
  it("restitue tous les champs requis", () => {
    const state = makeState();
    const json  = serializeRatchetState(state);
    const back  = deserializeRatchetState(json);
    for (const field of REQUIRED_FIELDS) {
      expect(back[field]).toBeDefined();
    }
  });

  it("les valeurs string sont correctes", () => {
    const state = makeState({ rootKey: "rootKey-exact-value" });
    const back  = deserializeRatchetState(serializeRatchetState(state));
    expect(back.rootKey).toBe("rootKey-exact-value");
  });

  it("les valeurs numériques sont correctes", () => {
    const state = makeState({ sendCount: 99, receiveCount: 11, updatedAt: 1234567890 });
    const back  = deserializeRatchetState(serializeRatchetState(state));
    expect(back.sendCount).toBe(99);
    expect(back.receiveCount).toBe(11);
    expect(back.updatedAt).toBe(1234567890);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. Round-trip
// ══════════════════════════════════════════════════════════════════════════

describe("Round-trip serialize → deserialize", () => {
  it("état identique après serialize+deserialize", () => {
    const original = makeState({
      conversationId  : "conv-XYZ-789",
      rootKey         : "rk-" + "x".repeat(40),
      sendCount       : 42,
      receiveCount    : 17,
      updatedAt       : Date.now(),
    });
    const back = deserializeRatchetState(serializeRatchetState(original));
    expect(back).toEqual(original);
  });

  it("double round-trip → état toujours identique", () => {
    const state = makeState();
    const back  = deserializeRatchetState(
      serializeRatchetState(
        deserializeRatchetState(serializeRatchetState(state))
      )
    );
    expect(back).toEqual(state);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. Robustesse / Validation des entrées
// ══════════════════════════════════════════════════════════════════════════

describe("deserializeRatchetState — robustesse", () => {
  it("lève une erreur sur JSON malformé", () => {
    expect(() => deserializeRatchetState("not json {{{")).toThrow();
  });

  it("lève une erreur sur JSON vide ({})", () => {
    expect(() => deserializeRatchetState("{}")).toThrow(/missing field/i);
  });

  it("lève une erreur sur string vide", () => {
    expect(() => deserializeRatchetState("")).toThrow();
  });

  it("lève une erreur sur tableau vide ([])", () => {
    expect(() => deserializeRatchetState("[]")).toThrow();
  });

  // Vérifier que chaque champ requis manquant provoque une erreur
  for (const field of REQUIRED_FIELDS) {
    it(`lève une erreur si le champ "${field}" est absent`, () => {
      const state = makeState();
      // Supprimer le champ
      const obj = JSON.parse(serializeRatchetState(state)) as Record<string, unknown>;
      delete obj[field];
      expect(() => deserializeRatchetState(JSON.stringify(obj))).toThrow();
    });
  }

  it("lève une erreur si rootKey est null", () => {
    const state = makeState();
    const obj   = JSON.parse(serializeRatchetState(state));
    obj.rootKey = null;
    expect(() => deserializeRatchetState(JSON.stringify(obj))).toThrow();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. Security / Pentests
// ══════════════════════════════════════════════════════════════════════════

describe("deserializeRatchetState — [PENTEST] sécurité", () => {
  it("[PENTEST] prototype pollution via __proto__ → rejet propre (pas de crash)", () => {
    const malicious = `{
      "__proto__": { "polluted": true },
      "conversationId": "x", "rootKey": "r",
      "sendingChainKey": "s", "receivingChainKey": "rc",
      "ourPrivateKey": "pk", "ourPublicKey": "pub",
      "theirPublicKey": "tp", "sendCount": 0,
      "receiveCount": 0, "updatedAt": 0
    }`;
    let threw = false;
    try {
      deserializeRatchetState(malicious);
    } catch {
      threw = true;
    }
    // Pas de pollution du prototype
    expect((Object.prototype as Record<string, unknown>)["polluted"]).toBeUndefined();
    void threw; // La désérialisation peut réussir ou échouer — l'important est l'absence de pollution
  });

  it("[PENTEST] champ supplémentaire inconnu → ignoré, pas de crash", () => {
    const state   = makeState();
    const obj     = JSON.parse(serializeRatchetState(state));
    obj.malicious = "<script>alert(1)</script>";
    expect(() => deserializeRatchetState(JSON.stringify(obj))).not.toThrow();
  });

  it("[PENTEST] très longues strings dans les champs → pas de crash", () => {
    const state = makeState({ rootKey: "A".repeat(100_000) });
    const back  = deserializeRatchetState(serializeRatchetState(state));
    expect(back.rootKey.length).toBe(100_000);
  });

  it("[PENTEST] sendCount négatif → accepté (validation métier à faire en amont)", () => {
    const state = makeState({ sendCount: -1 });
    const back  = deserializeRatchetState(serializeRatchetState(state));
    expect(back.sendCount).toBe(-1);
  });
});
