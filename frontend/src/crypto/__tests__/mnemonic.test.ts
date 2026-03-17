/**
 * mnemonic.test.ts — Tests for mnemonic phrase generation and validation
 *
 * Coverage:
 *  ── Functional ──────────────────────────────────────────────────────────────
 *  - generateMnemonic()   : returns exactly 10 words from the wordlist
 *  - validateMnemonic()   : accepts valid phrases, rejects invalid ones
 *  - normalizeMnemonic()  : normalizes whitespace and casing
 *
 *  ── Security ────────────────────────────────────────────────────────────────
 *  - Entropy: two successive calls produce different phrases (probabilistic)
 *  - Wordlist: all 256 entries are distinct
 *  - Wrong word count: rejected by validateMnemonic
 *  - Unknown word: rejected by validateMnemonic
 */

import { describe, it, expect } from "vitest";
import { webcrypto } from "node:crypto";
import {
  generateMnemonic,
  validateMnemonic,
  normalizeMnemonic,
  WORDLIST,
  MNEMONIC_WORD_COUNT,
} from "../mnemonic";

// Polyfill crypto for Node
if (typeof globalThis.crypto === "undefined") {
  // @ts-expect-error — polyfill
  globalThis.crypto = webcrypto;
}

// ─────────────────────────────────────────────────────────────────────────────
// WORDLIST integrity
// ─────────────────────────────────────────────────────────────────────────────

describe("WORDLIST", () => {
  it("contains exactly 256 unique words", () => {
    expect(WORDLIST.length).toBe(256);
    const unique = new Set(WORDLIST);
    expect(unique.size).toBe(256);
  });

  it("all words are lowercase alpha only (no numbers or special chars)", () => {
    for (const word of WORDLIST) {
      expect(word).toMatch(/^[a-z]+$/);
    }
  });

  it("no word is empty", () => {
    for (const word of WORDLIST) {
      expect(word.length).toBeGreaterThan(0);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// generateMnemonic
// ─────────────────────────────────────────────────────────────────────────────

describe("generateMnemonic", () => {
  it(`returns exactly ${MNEMONIC_WORD_COUNT} words`, () => {
    const words = generateMnemonic();
    expect(words).toHaveLength(MNEMONIC_WORD_COUNT);
  });

  it("all words are from the wordlist", () => {
    const set   = new Set<string>(WORDLIST);
    const words = generateMnemonic();
    for (const word of words) {
      expect(set.has(word)).toBe(true);
    }
  });

  it("returns different phrases on successive calls (entropy check)", () => {
    const a = generateMnemonic().join(" ");
    const b = generateMnemonic().join(" ");
    // Very unlikely to collide: P(collision) < 1/256^10 ≈ 10^-24
    expect(a).not.toBe(b);
  });

  it("generated phrase validates correctly", () => {
    const words = generateMnemonic();
    expect(validateMnemonic(words)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// validateMnemonic
// ─────────────────────────────────────────────────────────────────────────────

describe("validateMnemonic", () => {
  it("accepts a valid 10-word phrase", () => {
    const words = generateMnemonic();
    expect(validateMnemonic(words)).toBe(true);
  });

  it("rejects phrase with fewer than 10 words", () => {
    const words = generateMnemonic().slice(0, 9);
    expect(validateMnemonic(words)).toBe(false);
  });

  it("rejects phrase with more than 10 words", () => {
    const words = [...generateMnemonic(), "acid"];
    expect(validateMnemonic(words)).toBe(false);
  });

  it("rejects phrase with an unknown word", () => {
    const words = generateMnemonic();
    words[3] = "notaword";
    expect(validateMnemonic(words)).toBe(false);
  });

  it("accepts words with leading/trailing whitespace after trim", () => {
    // validateMnemonic trims internally
    const words = generateMnemonic().map(w => `  ${w}  `);
    expect(validateMnemonic(words)).toBe(true);
  });

  it("accepts mixed-case words (normalized to lowercase)", () => {
    const words = generateMnemonic().map(w => w.toUpperCase());
    expect(validateMnemonic(words)).toBe(true);
  });

  it("rejects empty array", () => {
    expect(validateMnemonic([])).toBe(false);
  });

  it("rejects array of 10 empty strings", () => {
    const words = Array(10).fill("");
    expect(validateMnemonic(words)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// normalizeMnemonic
// ─────────────────────────────────────────────────────────────────────────────

describe("normalizeMnemonic", () => {
  it("splits space-separated phrase into 10 words", () => {
    const words = generateMnemonic();
    const phrase = words.join(" ");
    expect(normalizeMnemonic(phrase)).toEqual(words);
  });

  it("handles multiple spaces between words", () => {
    const words = generateMnemonic();
    const phrase = words.join("   ");
    expect(normalizeMnemonic(phrase)).toEqual(words);
  });

  it("strips leading and trailing whitespace", () => {
    const words = generateMnemonic();
    const phrase = "   " + words.join(" ") + "   ";
    expect(normalizeMnemonic(phrase)).toEqual(words);
  });

  it("normalizes uppercase to lowercase", () => {
    const words = generateMnemonic();
    const phrase = words.map(w => w.toUpperCase()).join(" ");
    expect(normalizeMnemonic(phrase)).toEqual(words);
  });

  it("handles newlines as separators", () => {
    const words = generateMnemonic();
    const phrase = words.join("\n");
    expect(normalizeMnemonic(phrase)).toEqual(words);
  });

  it("returns empty array for empty string", () => {
    expect(normalizeMnemonic("")).toEqual([]);
  });

  it("returns empty array for whitespace-only string", () => {
    expect(normalizeMnemonic("   \n\t  ")).toEqual([]);
  });

  it("normalized result passes validateMnemonic", () => {
    const words  = generateMnemonic();
    const phrase = "  " + words.map(w => w.toUpperCase()).join("  ") + "  ";
    const normalized = normalizeMnemonic(phrase);
    expect(validateMnemonic(normalized)).toBe(true);
  });
});
