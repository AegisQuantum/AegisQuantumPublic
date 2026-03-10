/**
 * fingerprint.ts — Safety Numbers
 *
 * Calcul et affichage des Safety Numbers (empreinte cryptographique des clés DSA).
 *
 * Algorithme (inspiré Signal) :
 *   1. SHA-256( dsaPublicKey_bytes + uid_bytes )  → 32 bytes
 *   5 itérations de SHA-256 supplémentaires pour durcir
 *   2. Découper en 8 groupes de 5 décimales (mod 100000 sur chaque uint32)
 *   3. Afficher les 8 groupes → facile à comparer vocalement
 *
 * Les deux participants génèrent leurs propres Safety Numbers avec les mêmes
 * clés publiques → si les chiffres correspondent, pas d'interception MITM.
 */

import { getPublicKeys } from '../services/key-registry';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function strToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total  = arrays.reduce((n, a) => n + a.length, 0);
  const result = new Uint8Array(total);
  let offset   = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

/**
 * Calcule le fingerprint d'une clé publique DSA pour un uid donné.
 * 5 tours de SHA-256 pour durcir (inspiré Signal).
 * Retourne 8 groupes de 5 chiffres décimaux (strings).
 */
async function computeFingerprint(dsaPublicKeyB64: string, uid: string): Promise<string[]> {
  let data = concatBytes(base64ToBytes(dsaPublicKeyB64), strToBytes(uid));

  // 5 tours de SHA-256
  for (let i = 0; i < 5; i++) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    data = new Uint8Array(hash);
  }

  // Extraire 8 groupes de 5 décimales
  // SHA-256 = 32 bytes = 8 × uint32
  const view   = new DataView(data.buffer);
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    const uint32 = view.getUint32(i * 4, false); // big-endian
    const mod    = uint32 % 100_000;
    groups.push(mod.toString().padStart(5, '0'));
  }
  return groups;
}

function renderGroups(containerId: string, groups: string[]): void {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = groups.map(g => `<div class="fp-block">${g}</div>`).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// Modale
// ─────────────────────────────────────────────────────────────────────────────

let _modalEl: HTMLElement | null = null;

async function loadModal(): Promise<HTMLElement> {
  if (_modalEl) return _modalEl;

  const res  = await fetch('/src/pages/fingerprint.html');
  if (!res.ok) {
    // fallback: construire directement si fetch échoue (prod)
    return buildModalInline();
  }
  const text  = await res.text();
  const wrap  = document.createElement('div');
  wrap.innerHTML = text;
  // extraire seulement le .modal-overlay
  const modal = wrap.querySelector<HTMLElement>('.modal-overlay');
  if (!modal) return buildModalInline();
  _modalEl = modal;
  document.body.appendChild(_modalEl);
  return _modalEl;
}

/** Construit la modale inline sans fetch (utilisé en prod si le HTML n'est pas accessible). */
function buildModalInline(): HTMLElement {
  const el = document.createElement('div');
  el.id        = 'fingerprint-modal';
  el.className = 'fp-modal-overlay';
  el.innerHTML = `
    <div class="fp-modal-card">
      <div class="fp-modal-header">
        <div class="fp-modal-title">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" width="13" height="13">
            <rect x="2" y="8" width="12" height="7" rx="1.5"/>
            <path d="M5 8V6a3 3 0 0 1 6 0v2"/>
            <circle cx="8" cy="11.5" r="1" fill="currentColor" stroke="none"/>
          </svg>
          Safety Numbers
        </div>
        <button class="fp-modal-close" id="modal-close-btn">×</button>
      </div>
      <p class="fp-modal-desc">
        Comparez ces numéros avec votre contact via un canal de confiance (vocal, en personne).
        S'ils correspondent, votre conversation est sécurisée et n'a pas été interceptée.
      </p>
      <div class="fp-section">
        <div class="fp-label">Votre empreinte — ML-DSA-65</div>
        <div class="fp-grid" id="fp-own"></div>
      </div>
      <div class="fp-section">
        <div class="fp-label">Empreinte du contact — ML-DSA-65</div>
        <div class="fp-grid" id="fp-contact"></div>
      </div>
      <div class="fp-status unverified" id="fp-status">
        <span class="fp-status-dot"></span>
        Non vérifié — comparez hors-bande
      </div>
    </div>`;
  document.body.appendChild(el);
  _modalEl = el;
  return el;
}

function closeModal(): void {
  if (_modalEl) {
    _modalEl.style.display = 'none';
  }
}

/** Point d'entrée appelé depuis chat.ts au clic sur btn-fingerprint. */
export async function showSafetyNumbers(myUid: string, contactUid: string): Promise<void> {
  const modal = await loadModal();
  modal.style.display = 'flex';

  // Spinner le temps de charger
  const ownEl     = modal.querySelector<HTMLElement>('#fp-own');
  const contactEl = modal.querySelector<HTMLElement>('#fp-contact');
  const statusEl  = modal.querySelector<HTMLElement>('#fp-status');
  if (ownEl)     ownEl.innerHTML     = '<div class="fp-loading">Calcul…</div>';
  if (contactEl) contactEl.innerHTML = '<div class="fp-loading">Chargement…</div>';

  // Bouton fermer
  modal.querySelector('#modal-close-btn')?.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });

  try {
    // Récupérer clés publiques DSA du contact depuis Firestore
    const contactKeys = await getPublicKeys(contactUid);
    if (!contactKeys) throw new Error(`Clés introuvables pour ${contactUid}`);

    // Récupérer nos propres clés publiques DSA
    const myKeys = await getPublicKeys(myUid);
    if (!myKeys) throw new Error(`Vos clés publiques sont introuvables`);

    // Calculer les deux fingerprints
    const [myGroups, contactGroups] = await Promise.all([
      computeFingerprint(myKeys.dsaPublicKey, myUid),
      computeFingerprint(contactKeys.dsaPublicKey, contactUid),
    ]);

    // Afficher
    const ownGrid     = modal.querySelector<HTMLElement>('#fp-own');
    const contactGrid = modal.querySelector<HTMLElement>('#fp-contact');
    if (ownGrid)     ownGrid.innerHTML     = myGroups.map(g => `<div class="fp-block">${g}</div>`).join('');
    if (contactGrid) contactGrid.innerHTML = contactGroups.map(g => `<div class="fp-block">${g}</div>`).join('');

    if (statusEl) {
      statusEl.className   = 'fp-status unverified';
      statusEl.innerHTML   = '<span class="fp-status-dot"></span> Non vérifié — comparez hors-bande avec votre contact';
    }
  } catch (err) {
    console.error('[AQ] Safety Numbers error:', err);
    if (ownEl)     ownEl.innerHTML     = '<div class="fp-error">Erreur de calcul</div>';
    if (contactEl) contactEl.innerHTML = '<div class="fp-error">Clés introuvables</div>';
    if (statusEl) {
      statusEl.className = 'fp-status error';
      statusEl.innerHTML = '<span class="fp-status-dot"></span> Impossible de calculer les Safety Numbers';
    }
  }
}
