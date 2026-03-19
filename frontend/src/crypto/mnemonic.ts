/**
 * mnemonic.ts — Génération et validation de phrases mnémotechniques
 *
 * Génère 10 mots aléatoires depuis une liste de 256 mots anglais simples.
 * Chaque mot = 8 bits → 10 mots = 80 bits d'entropie.
 * Combiné avec Argon2id, cela est plus que suffisant pour chiffrer une session.
 *
 * Usage :
 *  - generateMnemonic()  → string[] (10 mots)
 *  - mnemonicToKey(words) → key Base64 (via Argon2id)
 *  - validateMnemonic(words) → boolean
 */

// ─────────────────────────────────────────────────────────────────────────────
// Wordlist — 256 mots anglais simples, distincts, sans ambiguïté
// ─────────────────────────────────────────────────────────────────────────────

export const WORDLIST: readonly string[] = [
  "acid", "acre", "aged", "aide", "also", "alto", "arch", "area",
  "atom", "aunt", "axle", "baby", "back", "ball", "band", "bank",
  "barn", "base", "bath", "bead", "beam", "bear", "beat", "bell",
  "bend", "bike", "bird", "bite", "blow", "blue", "body", "bold",
  "bone", "book", "bore", "born", "boss", "bowl", "burn", "bush",
  "byte", "cage", "cake", "call", "camp", "card", "cart", "case",
  "cave", "cell", "chip", "cite", "city", "clan", "clay", "clip",
  "club", "coal", "coat", "code", "coil", "coin", "cold", "cord",
  "core", "corn", "cost", "crew", "crop", "crow", "cube", "curl",
  "dame", "dare", "dark", "data", "dawn", "debt", "deed", "deny",
  "desk", "dial", "diet", "disk", "dome", "door", "dove", "down",
  "drum", "duck", "dune", "dust", "duty", "earn", "edge", "even",
  "exam", "exit", "fact", "fail", "farm", "fate", "fill", "film",
  "find", "fire", "firm", "fish", "fist", "flag", "flat", "flaw",
  "flex", "flip", "flow", "foam", "fold", "fond", "food", "fork",
  "form", "fort", "fuel", "fund", "fury", "gain", "game", "gate",
  "gave", "gear", "glow", "glue", "goal", "gold", "golf", "grab",
  "gram", "grin", "grip", "grow", "gulf", "gust", "hand", "hard",
  "harm", "haze", "head", "heat", "heel", "help", "hide", "high",
  "hill", "hint", "hold", "hole", "home", "hoop", "hope", "horn",
  "host", "hunt", "inch", "iron", "isle", "item", "join", "jury",
  "just", "keep", "kick", "kill", "kind", "knee", "knit", "know",
  "lamp", "land", "lane", "lark", "lash", "late", "lava", "lead",
  "lean", "left", "lens", "lift", "lime", "line", "lion", "load",
  "lock", "loft", "long", "loop", "lore", "lost", "lump", "lure",
  "made", "main", "make", "mark", "mask", "math", "maze", "meal",
  "meet", "melt", "mesh", "mild", "milk", "mill", "mind", "mint",
  "miss", "mist", "mode", "more", "most", "mule", "myth", "navy",
  "need", "nest", "next", "node", "norm", "nose", "note", "oath",
  "obey", "open", "oven", "over", "page", "pain", "palm", "park",
  "part", "pass", "path", "pawn", "peak", "peel", "peer", "pick",
  "pine", "pipe", "plan", "play", "plow", "plug", "poem", "pole",
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────────────────────

export const MNEMONIC_WORD_COUNT = 10;

/**
 * Génère une phrase mnémotechnique de 10 mots aléatoires.
 * Entropie : 80 bits (10 × 8 bits par mot de la liste de 256).
 */
export function generateMnemonic(): string[] {
  const indices = crypto.getRandomValues(new Uint8Array(MNEMONIC_WORD_COUNT));
  return Array.from(indices, i => WORDLIST[i]);
}

/**
 * Vérifie que les mots donnés appartiennent tous à la wordlist et que
 * la longueur est correcte.
 */
export function validateMnemonic(words: string[]): boolean {
  if (words.length !== MNEMONIC_WORD_COUNT) return false;
  const set = new Set<string>(WORDLIST);
  return words.every(w => set.has(w.toLowerCase().trim()));
}

/**
 * Normalise les mots (minuscules, sans espaces parasites).
 */
export function normalizeMnemonic(phrase: string): string[] {
  return phrase
    .trim()
    .split(/\s+/)
    .map(w => w.toLowerCase().trim())
    .filter(w => w.length > 0);
}
