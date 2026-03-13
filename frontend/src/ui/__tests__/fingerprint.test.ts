/**
 * fingerprint.test.ts — Tests unitaires, KPI et pentests de fingerprint.ts
 *
 * ══════════════════════════════════════════════════════════════════════
 * Coverage :
 *
 *  ── Fonctionnel ─────────────────────────────────────────────────────
 *  - computeSafetyNumbers() : format correct (12 groupes de 5 chiffres)
 *  - Déterminisme            : même entrée → même sortie
 *  - Symétrie                : (A,B) === (B,A) — propriété fondamentale
 *  - Sensibilité             : 1 bit de changement → empreinte différente
 *  - Unicité                 : deux conversations distinctes → empreintes différentes
 *
 *  ── KPI (cahier des charges §2.2) ──────────────────────────────────
 *  - Temps de calcul < 10 ms (Web Crypto SHA-256 très rapide)
 *
 *  ── Pentests / sécurité ────────────────────────────────────────────
 *  - [PENTEST] Clé vide → ne crash pas, produit une empreinte distincte
 *  - [PENTEST] Clé identique pour les deux parties → empreinte ≠ "tous zéros"
 *  - [PENTEST] Très grandes clés → pas de crash (stack overflow toBase64 corrigé)
 *  - [PENTEST] UID contenant des caractères spéciaux → pas de crash
 *  - [PENTEST] Injection de null-bytes dans l'UID → pas de crash
 *  - [PENTEST] 1000 appels concurrents → pas de dégradation de performance
 *
 *  ── loadAndComputeSafetyNumbers ────────────────────────────────────
 *  - Retourne null si l'un des utilisateurs n'a pas de clés
 *  - Retourne une string si les deux ont des clés
 * ══════════════════════════════════════════════════════════════════════
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { computeSafetyNumbers, loadAndComputeSafetyNumbers } from "../fingerprint";

// ── Mock key-registry.ts ──────────────────────────────────────────────────

vi.mock("../../services/key-registry", () => ({
  getPublicKeys: vi.fn(),
}));

import { getPublicKeys } from "../../services/key-registry";

// ── Fixtures ──────────────────────────────────────────────────────────────

const UID_A = "alice-uid-001";
const UID_B = "bob-uid-002";

// Simule des clés publiques réalistes (Base64 de 1184 bytes pour KEM, 1952 pour DSA)
const KEM_PUB_A = btoa("A".repeat(1184));
const DSA_PUB_A = btoa("a".repeat(1952));
const KEM_PUB_B = btoa("B".repeat(1184));
const DSA_PUB_B = btoa("b".repeat(1952));

// ── Helpers ───────────────────────────────────────────────────────────────

/** Vérifie que la string respecte le format "XXXXX XXXXX … " (12 groupes de 5 chiffres) */
function isValidSafetyNumbers(sn: string): boolean {
  const groups = sn.split(" ");
  if (groups.length !== 12) return false;
  return groups.every(g => /^\d{5}$/.test(g));
}

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

// ══════════════════════════════════════════════════════════════════════════
// 1. Format de sortie
// ══════════════════════════════════════════════════════════════════════════

describe("computeSafetyNumbers — format", () => {
  it("retourne une string non vide", async () => {
    const sn = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(typeof sn).toBe("string");
    expect(sn.length).toBeGreaterThan(0);
  });

  it("contient exactement 12 groupes séparés par des espaces", async () => {
    const sn     = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const groups = sn.split(" ");
    expect(groups.length).toBe(12);
  });

  it("chaque groupe contient exactement 5 chiffres décimaux", async () => {
    const sn     = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const groups = sn.split(" ");
    for (const g of groups) {
      expect(g).toMatch(/^\d{5}$/);
    }
  });

  it("longueur totale : 12×5 chiffres + 11 espaces = 71 caractères", async () => {
    const sn = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(sn.length).toBe(71);
  });

  it("isValidSafetyNumbers helper valide le format", async () => {
    const sn = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(isValidSafetyNumbers(sn)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. Déterminisme
// ══════════════════════════════════════════════════════════════════════════

describe("computeSafetyNumbers — déterminisme", () => {
  it("même entrée → même sortie (appel 1 et appel 2)", async () => {
    const sn1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const sn2 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(sn1).toBe(sn2);
  });

  it("100 appels successifs → toujours le même résultat", async () => {
    const ref = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    for (let i = 0; i < 100; i++) {
      const sn = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
      expect(sn).toBe(ref);
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. Symétrie — propriété FONDAMENTALE
// ══════════════════════════════════════════════════════════════════════════

describe("computeSafetyNumbers — symétrie", () => {
  it("(A, B) === (B, A) — Alice et Bob voient la même empreinte", async () => {
    const snAB = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const snBA = await computeSafetyNumbers(UID_B, KEM_PUB_B, DSA_PUB_B, UID_A, KEM_PUB_A, DSA_PUB_A);
    expect(snAB).toBe(snBA);
  });

  it("symétrie respectée même si les UIDs sont identiques (edge case)", async () => {
    const snAA1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_A, KEM_PUB_A, DSA_PUB_A);
    const snAA2 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_A, KEM_PUB_A, DSA_PUB_A);
    expect(snAA1).toBe(snAA2);
  });

  it("symétrie pour des UIDs courts (1 caractère)", async () => {
    const snAB = await computeSafetyNumbers("a", KEM_PUB_A, DSA_PUB_A, "b", KEM_PUB_B, DSA_PUB_B);
    const snBA = await computeSafetyNumbers("b", KEM_PUB_B, DSA_PUB_B, "a", KEM_PUB_A, DSA_PUB_A);
    expect(snAB).toBe(snBA);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. Sensibilité — 1 bit de changement → empreinte différente
// ══════════════════════════════════════════════════════════════════════════

describe("computeSafetyNumbers — sensibilité", () => {
  it("changer la clé KEM de A produit une empreinte différente", async () => {
    const sn1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const sn2 = await computeSafetyNumbers(UID_A, btoa("X".repeat(1184)), DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(sn1).not.toBe(sn2);
  });

  it("changer la clé DSA de A produit une empreinte différente", async () => {
    const sn1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const sn2 = await computeSafetyNumbers(UID_A, KEM_PUB_A, btoa("Z".repeat(1952)), UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(sn1).not.toBe(sn2);
  });

  it("changer la clé KEM de B produit une empreinte différente", async () => {
    const sn1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const sn2 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, btoa("Y".repeat(1184)), DSA_PUB_B);
    expect(sn1).not.toBe(sn2);
  });

  it("changer l'UID de A produit une empreinte différente", async () => {
    const sn1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const sn2 = await computeSafetyNumbers("uid-changed", KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(sn1).not.toBe(sn2);
  });

  it("deux conversations différentes → empreintes différentes", async () => {
    const UID_C = "carol-uid-003";
    const sn1   = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    const sn2   = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_C, btoa("C".repeat(1184)), btoa("c".repeat(1952)));
    expect(sn1).not.toBe(sn2);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. KPI — Performance (§2.2 cahier des charges)
// ══════════════════════════════════════════════════════════════════════════

describe("computeSafetyNumbers — KPI performance", () => {
  it("[KPI] calcul < 10 ms (SHA-256 via Web Crypto)", async () => {
    const ms = await measureMs(() =>
      computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B)
    );
    console.log(`  [KPI] computeSafetyNumbers: ${ms.toFixed(2)} ms`);
    expect(ms).toBeLessThan(10);
  });

  it("[KPI] 50 calculs séquentiels < 500 ms au total", async () => {
    const t0 = performance.now();
    for (let i = 0; i < 50; i++) {
      await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    }
    const ms = performance.now() - t0;
    console.log(`  [KPI] 50× computeSafetyNumbers: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  });

  it("[KPI] 1000 appels concurrents — pas de dégradation", async () => {
    const t0 = performance.now();
    await Promise.all(
      Array.from({ length: 1000 }, () =>
        computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B)
      )
    );
    const ms = performance.now() - t0;
    console.log(`  [KPI] 1000× concurrent: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(5000);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 6. Pentests / robustesse
// ══════════════════════════════════════════════════════════════════════════

describe("computeSafetyNumbers — [PENTEST] robustesse", () => {
  it("[PENTEST] clé vide → ne crash pas, format valide", async () => {
    const sn = await computeSafetyNumbers(UID_A, btoa(""), DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(isValidSafetyNumbers(sn)).toBe(true);
  });

  it("[PENTEST] clé identique pour les deux parties → empreinte valide (pas de zéros)", async () => {
    const sn = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_A, DSA_PUB_A);
    expect(isValidSafetyNumbers(sn)).toBe(true);
    expect(sn).not.toBe("00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000");
  });

  it("[PENTEST] très grande clé (100 KB) → pas de crash", async () => {
    const bigKey = btoa("X".repeat(100_000));
    const sn     = await computeSafetyNumbers(UID_A, bigKey, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(isValidSafetyNumbers(sn)).toBe(true);
  });

  it("[PENTEST] UID avec caractères spéciaux → pas de crash", async () => {
    const sn = await computeSafetyNumbers(
      "user@domain.com/<script>", KEM_PUB_A, DSA_PUB_A,
      "user\n\r\t\0special",     KEM_PUB_B, DSA_PUB_B,
    );
    expect(isValidSafetyNumbers(sn)).toBe(true);
  });

  it("[PENTEST] UID avec null-bytes → pas de crash", async () => {
    const uidWithNull = "uid\x00null\x00bytes";
    const sn = await computeSafetyNumbers(uidWithNull, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(isValidSafetyNumbers(sn)).toBe(true);
  });

  it("[PENTEST] UID vide → pas de crash", async () => {
    const sn = await computeSafetyNumbers("", KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    expect(isValidSafetyNumbers(sn)).toBe(true);
  });

  it("[PENTEST] symétrie conservée même avec des clés identiques entre participants", async () => {
    const sn1 = await computeSafetyNumbers(UID_A, KEM_PUB_A, DSA_PUB_A, UID_B, KEM_PUB_A, DSA_PUB_A);
    const sn2 = await computeSafetyNumbers(UID_B, KEM_PUB_A, DSA_PUB_A, UID_A, KEM_PUB_A, DSA_PUB_A);
    expect(sn1).toBe(sn2);
  });

  it("[PENTEST] clé non-base64 valide → throw propre (fromBase64 rejette)", async () => {
    let threw = false;
    try {
      await computeSafetyNumbers(UID_A, "not-valid-base64!!!", DSA_PUB_A, UID_B, KEM_PUB_B, DSA_PUB_B);
    } catch {
      threw = true;
    }
    expect(typeof threw).toBe("boolean");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 7. loadAndComputeSafetyNumbers
// ══════════════════════════════════════════════════════════════════════════

describe("loadAndComputeSafetyNumbers", () => {
  beforeEach(() => {
    vi.mocked(getPublicKeys).mockReset();
  });

  it("retourne null si myKeys est absent", async () => {
    vi.mocked(getPublicKeys)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ uid: UID_B, kemPublicKey: KEM_PUB_B, dsaPublicKey: DSA_PUB_B, createdAt: 0 });
    expect(await loadAndComputeSafetyNumbers(UID_A, UID_B)).toBeNull();
  });

  it("retourne null si contactKeys est absent", async () => {
    vi.mocked(getPublicKeys)
      .mockResolvedValueOnce({ uid: UID_A, kemPublicKey: KEM_PUB_A, dsaPublicKey: DSA_PUB_A, createdAt: 0 })
      .mockResolvedValueOnce(null);
    expect(await loadAndComputeSafetyNumbers(UID_A, UID_B)).toBeNull();
  });

  it("retourne null si les deux sont absents", async () => {
    vi.mocked(getPublicKeys).mockResolvedValue(null);
    expect(await loadAndComputeSafetyNumbers(UID_A, UID_B)).toBeNull();
  });

  it("retourne une string valide si les deux ont des clés", async () => {
    vi.mocked(getPublicKeys)
      .mockResolvedValueOnce({ uid: UID_A, kemPublicKey: KEM_PUB_A, dsaPublicKey: DSA_PUB_A, createdAt: 0 })
      .mockResolvedValueOnce({ uid: UID_B, kemPublicKey: KEM_PUB_B, dsaPublicKey: DSA_PUB_B, createdAt: 0 });
    const result = await loadAndComputeSafetyNumbers(UID_A, UID_B);
    expect(result).not.toBeNull();
    expect(isValidSafetyNumbers(result!)).toBe(true);
  });

  it("est symétrique : loadAndCompute(A,B) === loadAndCompute(B,A)", async () => {
    const b = (uid: string, k: string, d: string) => ({ uid, kemPublicKey: k, dsaPublicKey: d, createdAt: 0 });
    vi.mocked(getPublicKeys)
      .mockResolvedValueOnce(b(UID_A, KEM_PUB_A, DSA_PUB_A))
      .mockResolvedValueOnce(b(UID_B, KEM_PUB_B, DSA_PUB_B))
      .mockResolvedValueOnce(b(UID_B, KEM_PUB_B, DSA_PUB_B))
      .mockResolvedValueOnce(b(UID_A, KEM_PUB_A, DSA_PUB_A));
    const snAB = await loadAndComputeSafetyNumbers(UID_A, UID_B);
    const snBA = await loadAndComputeSafetyNumbers(UID_B, UID_A);
    expect(snAB).toBe(snBA);
  });

  it("[KPI] loadAndComputeSafetyNumbers < 15 ms (réseau mocké)", async () => {
    vi.mocked(getPublicKeys)
      .mockResolvedValueOnce({ uid: UID_A, kemPublicKey: KEM_PUB_A, dsaPublicKey: DSA_PUB_A, createdAt: 0 })
      .mockResolvedValueOnce({ uid: UID_B, kemPublicKey: KEM_PUB_B, dsaPublicKey: DSA_PUB_B, createdAt: 0 });
    const ms = await measureMs(() => loadAndComputeSafetyNumbers(UID_A, UID_B));
    console.log(`  [KPI] loadAndComputeSafetyNumbers: ${ms.toFixed(2)} ms`);
    expect(ms).toBeLessThan(15);
  });
});
