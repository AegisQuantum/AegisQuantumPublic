/**
 * argon2-browser.d.ts
 *
 * argon2-browser est chargé via CDN (script tag dans index.html), pas bundlé.
 * Il expose window.argon2 comme global. On déclare ce global ici pour TypeScript.
 *
 * Le module "argon2-browser" est conservé pour le mock Vitest (setup.crypto.ts)
 * qui utilise vi.mock("argon2-browser", ...) — ce chemin doit rester résolvable
 * dans le contexte de test Node, même si le vrai module n'est pas importé en prod.
 */

// Global exposé par le CDN dans le browser
declare const argon2: {
  ArgonType: { Argon2d: number; Argon2i: number; Argon2id: number };
  hash(params: {
    pass       : string | Uint8Array;
    salt       : Uint8Array;
    time      ?: number;
    mem       ?: number;
    parallelism?: number;
    hashLen   ?: number;
    type      ?: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }>;
};

// Module déclaré pour que vi.mock("argon2-browser") fonctionne dans Vitest
declare module "argon2-browser" {
  export enum ArgonType {
    Argon2d  = 0,
    Argon2i  = 1,
    Argon2id = 2,
  }
  export function hash(params: {
    pass       : string | Uint8Array;
    salt       : Uint8Array;
    time      ?: number;
    mem       ?: number;
    parallelism?: number;
    hashLen   ?: number;
    type      ?: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }>;
  const _default: { ArgonType: typeof ArgonType; hash: typeof hash };
  export default _default;
}
