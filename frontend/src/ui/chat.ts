/**
 * chat.ts — UI du chat branchée sur messaging.ts et auth.ts
 */

// Import du CSS chat — Vite le bundle en prod, l'injecte via <style> en dev
import '../styles/chat.css';

import { signOut }                          from '../services/auth';
import { openFingerprintModal, closeFingerprintModal } from './fingerprint';
import {
  subscribeToConversations,
  subscribeToMessages,
  sendMessage,
  getOrCreateConversation,
}                                           from '../services/messaging';
import type { Conversation, DecryptedMessage } from '../types/message';

let _unsubConvs:        (() => void) | null = null;
let _unsubMessages:     (() => void) | null = null;
let _currentConvId:     string | null       = null;
let _currentContactUid: string | null       = null;
let _myUid:             string              = '';

// ─────────────────────────────────────────────────────────────────────────────
// LocalStorage — noms locaux des conversations + avatar
// ─────────────────────────────────────────────────────────────────────────────

/** Retourne le nom local d'une conversation (renommage côté client uniquement). */
function getLocalConvName(convId: string): string | null {
  return localStorage.getItem(`aq:conv:name:${convId}`);
}

/** Sauvegarde un nom local pour une conversation. */
function setLocalConvName(convId: string, name: string): void {
  if (name.trim()) {
    localStorage.setItem(`aq:conv:name:${convId}`, name.trim());
  } else {
    localStorage.removeItem(`aq:conv:name:${convId}`);
  }
}

/** Retourne la couleur de fond de l'avatar. */
function getAvatarColor(): string {
  return localStorage.getItem(`aq:avatar:color:${_myUid}`) ?? '#6b8ff5';
}
function setAvatarColor(color: string): void {
  localStorage.setItem(`aq:avatar:color:${_myUid}`, color);
}

/** Initiales (max 2 chars). */
function getAvatarInitials(): string {
  return localStorage.getItem(`aq:avatar:initials:${_myUid}`) ?? _myUid.slice(0, 2).toUpperCase();
}
function setAvatarInitials(initials: string): void {
  const clean = initials.trim().slice(0, 2).toUpperCase();
  if (clean) localStorage.setItem(`aq:avatar:initials:${_myUid}`, clean);
}

/** Photo de profil — base64 DataURL ou null. */
function getAvatarPhoto(): string | null {
  return localStorage.getItem(`aq:avatar:photo:${_myUid}`);
}
function setAvatarPhoto(dataUrl: string | null): void {
  if (dataUrl) localStorage.setItem(`aq:avatar:photo:${_myUid}`, dataUrl);
  else         localStorage.removeItem(`aq:avatar:photo:${_myUid}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Point d'entrée — appelé par main.ts après connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function initChat(uid: string): Promise<void> {
  _myUid = uid;

  const container = document.getElementById('chat-screen')!;

  try {
    const res  = await fetch('/chat.html');
    if (!res.ok) throw new Error(`Failed to load chat.html: ${res.status}`);
    const html = await res.text();
    container.innerHTML = html;
  } catch (err) {
    console.error('[AQ] initChat: failed to load template', err);
    container.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:100%;flex-direction:column;gap:1rem;color:#fc8181;font-family:monospace;padding:2rem;text-align:center;background:#0e0f14">
        <strong>Erreur de chargement</strong>
        <code style="font-size:0.75rem;color:#8890c0;word-break:break-all">${(err as Error)?.message ?? String(err)}</code>
        <button onclick="location.reload()" style="margin-top:1rem;padding:0.5rem 1.5rem;background:#6b8ff5;color:#fff;border:none;border-radius:6px;cursor:pointer">Recharger</button>
      </div>`;
    throw err;
  }

  // ── Remplir identité ──
  refreshAvatar();
  const profileDropdownUid = document.getElementById('profile-dropdown-uid');
  const settingsUid        = document.getElementById('settings-uid');
  if (profileDropdownUid) profileDropdownUid.textContent = uid;
  if (settingsUid)        settingsUid.textContent = uid;

  // ── Déconnexion ──
  document.getElementById('btn-signout')?.addEventListener('click', handleSignOut);
  document.getElementById('btn-signout-settings')?.addEventListener('click', handleSignOut);

  // ── Envoi ──
  document.getElementById('btn-send')?.addEventListener('click', handleSendMessage);
  const msgInput = document.getElementById('message-input') as HTMLTextAreaElement | null;
  msgInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSendMessage(); }
  });

  // ── Navigation settings ──
  document.getElementById('rail-btn-settings')?.addEventListener('click', () => {
    const isSettings = document.getElementById('view-settings')?.style.display !== 'none';
    switchView(isSettings ? 'chat' : 'settings');
  });
  document.getElementById('btn-profile-settings')?.addEventListener('click', () => {
    closeProfileDropdown();
    // toggle aussi depuis le dropdown
    const isSettings = document.getElementById('view-settings')?.style.display !== 'none';
    switchView(isSettings ? 'chat' : 'settings');
  });
  document.getElementById('btn-settings-back')?.addEventListener('click', () => switchView('chat'));

  // ── Sidebar toggle ──
  document.getElementById('btn-toggle-sidebar')?.addEventListener('click', toggleSidebar);

  // ── Dropdown profil ──
  document.getElementById('topnav-avatar')?.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleProfileDropdown();
  });
  document.addEventListener('click', () => closeProfileDropdown());

  // ── Changer avatar ──
  document.getElementById('btn-change-avatar')?.addEventListener('click', openAvatarModal);
  document.getElementById('topnav-avatar')?.addEventListener('dblclick', (e) => { e.stopPropagation(); openAvatarModal(); });
  document.getElementById('avatar-modal-close')?.addEventListener('click', closeAvatarModal);
  document.getElementById('avatar-modal-cancel')?.addEventListener('click', () => { _pendingPhoto = undefined; closeAvatarModal(); });
  document.getElementById('avatar-modal-confirm')?.addEventListener('click', confirmAvatarChange);

  // Input file — photo
  document.getElementById('avatar-photo-input')?.addEventListener('change', (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const dataUrl = ev.target?.result as string;
      _pendingPhoto = dataUrl;
      const preview = document.getElementById('avatar-modal-preview') as HTMLElement | null;
      if (preview) {
        preview.textContent = '';
        preview.style.backgroundImage = `url('${dataUrl}')`;
        preview.style.backgroundSize = 'cover';
        preview.style.backgroundPosition = 'center';
      }
      const btnRemove = document.getElementById('btn-remove-photo');
      if (btnRemove) btnRemove.style.display = '';
    };
    reader.readAsDataURL(file);
  });

  // Supprimer photo
  document.getElementById('btn-remove-photo')?.addEventListener('click', () => {
    _pendingPhoto = null;
    const preview = document.getElementById('avatar-modal-preview') as HTMLElement | null;
    const input   = document.getElementById('avatar-initials-input') as HTMLInputElement | null;
    if (preview) {
      preview.style.backgroundImage = '';
      preview.style.background = getAvatarColor();
      preview.textContent = input?.value.trim().slice(0,2).toUpperCase() || getAvatarInitials();
    }
    const btnRemove = document.getElementById('btn-remove-photo');
    if (btnRemove) btnRemove.style.display = 'none';
  });

  // Sélecteur de couleurs
  document.querySelectorAll<HTMLElement>('.avatar-color-swatch').forEach((swatch) => {
    swatch.addEventListener('click', () => {
      document.querySelectorAll('.avatar-color-swatch').forEach(s => s.classList.remove('selected'));
      swatch.classList.add('selected');
      const preview = document.getElementById('avatar-modal-preview') as HTMLElement | null;
      // Ne changer la couleur du preview que s'il n'y a pas de photo en attente
      if (preview && !_pendingPhoto && !getAvatarPhoto()) {
        preview.style.background = swatch.dataset.color ?? '#6b8ff5';
      }
    });
  });

  // ── Safety Numbers ──
  document.getElementById('btn-fingerprint')?.addEventListener('click', () => {
    if (_currentContactUid) {
      openFingerprintModal(_myUid, _currentContactUid);
    } else {
      showToast('Ouvrez une conversation pour voir les Safety Numbers.');
    }
  });
  document.getElementById('modal-close-btn')?.addEventListener('click', closeFingerprintModal);
  document.getElementById('fingerprint-modal')?.addEventListener('click', (e) => {
    // Fermer si clic sur l'overlay (pas sur la carte)
    if ((e.target as HTMLElement).id === 'fingerprint-modal') closeFingerprintModal();
  });

  // ── Modal nouvelle conversation ──
  document.getElementById('btn-new-chat')?.addEventListener('click',    () => openNewConvModal());
  document.getElementById('modal-close')?.addEventListener('click',     () => closeNewConvModal());
  document.getElementById('modal-cancel')?.addEventListener('click',    () => closeNewConvModal());
  document.getElementById('modal-confirm')?.addEventListener('click',   () => confirmNewConv());
  document.getElementById('modal-uid-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')  confirmNewConv();
    if (e.key === 'Escape') closeNewConvModal();
  });

  // ── Renommer conversation (double-clic sur nom dans topbar) ──
  document.getElementById('chat-contact-name')?.addEventListener('dblclick', () => {
    if (_currentConvId) openRenameModal(_currentConvId);
  });
  document.getElementById('btn-rename-conv')?.addEventListener('click', () => {
    if (_currentConvId) openRenameModal(_currentConvId);
  });
  document.getElementById('rename-modal-close')?.addEventListener('click',   closeRenameModal);
  document.getElementById('rename-modal-cancel')?.addEventListener('click',  closeRenameModal);
  document.getElementById('rename-modal-confirm')?.addEventListener('click', confirmRename);
  document.getElementById('rename-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')  confirmRename();
    if (e.key === 'Escape') closeRenameModal();
  });

  // ── Copier UID ──
  const copyUid = () => navigator.clipboard.writeText(uid).then(() => showToast('UID copié !')).catch(() => {});
  document.getElementById('btn-copy-uid')?.addEventListener('click', copyUid);
  document.getElementById('btn-copy-uid-settings')?.addEventListener('click', copyUid);

  // ── Recherche ──
  document.getElementById('search-input')?.addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value.toLowerCase();
    document.querySelectorAll<HTMLElement>('.contact-item').forEach((el) => {
      const name = el.querySelector('.contact-name')?.textContent?.toLowerCase() ?? '';
      el.style.display = name.includes(q) ? '' : 'none';
    });
  });

  // ── S'abonner aux conversations ──
  _unsubConvs = subscribeToConversations(uid, renderConversationList);
}

// ─────────────────────────────────────────────────────────────────────────────
// Avatar
// ─────────────────────────────────────────────────────────────────────────────

function refreshAvatar(): void {
  const initials = getAvatarInitials();
  const color    = getAvatarColor();
  const photo    = getAvatarPhoto();

  // Topnav avatar
  const topnavAvatar = document.getElementById('topnav-avatar');
  if (topnavAvatar) {
    const textNode = Array.from(topnavAvatar.childNodes).find(n => n.nodeType === Node.TEXT_NODE);
    if (photo) {
      // Photo : cacher le texte, appliquer l'image en background
      if (textNode) (textNode as Text).textContent = '';
      (topnavAvatar as HTMLElement).style.cssText +=
        `;background-image:url('${photo}');background-size:cover;background-position:center;background-color:transparent`;
    } else {
      if (textNode) (textNode as Text).textContent = initials;
      (topnavAvatar as HTMLElement).style.backgroundImage = '';
      (topnavAvatar as HTMLElement).style.background = color;
    }
  }

  // Avatar dans les settings
  const settingsAvatar = document.getElementById('settings-avatar-preview');
  if (settingsAvatar) {
    if (photo) {
      settingsAvatar.textContent = '';
      (settingsAvatar as HTMLElement).style.cssText +=
        `;background-image:url('${photo}');background-size:cover;background-position:center`;
    } else {
      settingsAvatar.textContent = initials;
      (settingsAvatar as HTMLElement).style.backgroundImage = '';
      (settingsAvatar as HTMLElement).style.background = color;
    }
  }
}

function openAvatarModal(): void {
  const modal    = document.getElementById('avatar-modal');
  const preview  = document.getElementById('avatar-modal-preview') as HTMLElement | null;
  const input    = document.getElementById('avatar-initials-input') as HTMLInputElement | null;
  const curColor = getAvatarColor();
  const curPhoto = getAvatarPhoto();

  if (modal) modal.style.display = 'flex';

  // Preview : photo ou initiales
  if (preview) {
    if (curPhoto) {
      preview.textContent = '';
      preview.style.backgroundImage  = `url('${curPhoto}')`;
      preview.style.backgroundSize   = 'cover';
      preview.style.backgroundPosition = 'center';
      preview.style.backgroundColor = 'transparent';
    } else {
      preview.textContent = getAvatarInitials();
      preview.style.backgroundImage = '';
      preview.style.background = curColor;
    }
  }
  if (input) input.value = getAvatarInitials();

  // Marquer la couleur active
  document.querySelectorAll<HTMLElement>('.avatar-color-swatch').forEach((s) => {
    s.classList.toggle('selected', s.dataset.color === curColor);
  });

  // Mise à jour live du preview via l'input initiales
  input?.removeEventListener('input', _onInitialsInput);
  input?.addEventListener('input', _onInitialsInput);

  // Bouton supprimer photo (si photo existe)
  const btnRemovePhoto = document.getElementById('btn-remove-photo');
  if (btnRemovePhoto) btnRemovePhoto.style.display = curPhoto ? '' : 'none';

  setTimeout(() => input?.focus(), 50);
}

function _onInitialsInput(e: Event): void {
  const val     = (e.target as HTMLInputElement).value.trim().slice(0, 2).toUpperCase();
  const preview = document.getElementById('avatar-modal-preview');
  if (preview) preview.textContent = val || '?';
}

function closeAvatarModal(): void {
  const modal = document.getElementById('avatar-modal');
  if (modal) modal.style.display = 'none';
}

// Photo en attente de sauvegarde (chargée dans la modale)
let _pendingPhoto: string | null | undefined = undefined; // undefined = pas changé

function confirmAvatarChange(): void {
  const input    = document.getElementById('avatar-initials-input') as HTMLInputElement | null;
  const selected = document.querySelector<HTMLElement>('.avatar-color-swatch.selected');
  const color    = selected?.dataset.color ?? getAvatarColor();

  if (input?.value.trim()) setAvatarInitials(input.value);
  setAvatarColor(color);
  if (_pendingPhoto !== undefined) setAvatarPhoto(_pendingPhoto); // null = supprimer
  _pendingPhoto = undefined;
  refreshAvatar();
  closeAvatarModal();
  showToast('Avatar mis à jour !');
}

// ─────────────────────────────────────────────────────────────────────────────
// Modal renommer conversation
// ─────────────────────────────────────────────────────────────────────────────

function openRenameModal(convId: string): void {
  const modal = document.getElementById('rename-modal');
  const input = document.getElementById('rename-input') as HTMLInputElement | null;
  if (modal) modal.style.display = 'flex';
  if (input) {
    input.value = getLocalConvName(convId) ?? (_currentContactUid?.slice(0, 24) ?? '');
    input.select();
  }
  setTimeout(() => input?.focus(), 50);
}

function closeRenameModal(): void {
  const modal = document.getElementById('rename-modal');
  if (modal) modal.style.display = 'none';
}

function confirmRename(): void {
  if (!_currentConvId) return;
  const input = document.getElementById('rename-input') as HTMLInputElement | null;
  const name  = input?.value.trim() ?? '';
  setLocalConvName(_currentConvId, name);

  // Mettre à jour le nom dans la topbar
  const nameEl = document.getElementById('chat-contact-name');
  if (nameEl) nameEl.textContent = name || (_currentContactUid?.slice(0, 24) ?? '—');

  // Mettre à jour dans la sidebar sans reload complet
  const item = document.querySelector<HTMLElement>(`.contact-item[data-conv-id="${_currentConvId}"] .contact-name`);
  if (item) item.textContent = name || (_currentContactUid?.slice(0, 20) ?? '—');

  closeRenameModal();
  showToast('Conversation renommée.');
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar toggle
// ─────────────────────────────────────────────────────────────────────────────

function toggleSidebar(): void {
  const panel = document.getElementById('left-panel');
  const btn   = document.getElementById('btn-toggle-sidebar');
  if (!panel) return;
  panel.classList.toggle('collapsed');
  btn?.classList.toggle('active', panel.classList.contains('collapsed'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Dropdown profil
// ─────────────────────────────────────────────────────────────────────────────

function toggleProfileDropdown(): void {
  document.getElementById('topnav-avatar')?.classList.toggle('open');
}
function closeProfileDropdown(): void {
  document.getElementById('topnav-avatar')?.classList.remove('open');
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation chat / settings
// ─────────────────────────────────────────────────────────────────────────────

function switchView(view: 'chat' | 'settings'): void {
  const viewChat     = document.getElementById('view-chat');
  const viewSettings = document.getElementById('view-settings');
  const btnSettings  = document.getElementById('rail-btn-settings');
  if (view === 'chat') {
    if (viewChat)     viewChat.style.display     = '';
    if (viewSettings) viewSettings.style.display = 'none';
    btnSettings?.classList.remove('active');
  } else {
    if (viewChat)     viewChat.style.display     = 'none';
    if (viewSettings) viewSettings.style.display = '';
    btnSettings?.classList.add('active');
    refreshAvatar(); // synchroniser l'aperçu avatar dans settings
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto Box
// ─────────────────────────────────────────────────────────────────────────────

type CryptoStepType = 'send' | 'recv' | 'done' | 'warn' | 'active';

interface CryptoStepExplain {
  what: string;
  how: string;
  why: string;
  algo?: string;
}

interface CryptoStepDef {
  icon: string;
  type: CryptoStepType;
  label: string;
  detail?: string;
  delay: number;
  explain?: CryptoStepExplain;
}

const SEND_STEPS: CryptoStepDef[] = [
  {
    icon: '🔑', type: 'send', delay: 0,
    label: 'Génération des clés éphémères',
    detail: 'ML-KEM-768 keypair',
    explain: {
      what:  'Génération d\'une paire de clés ML-KEM-768 fraîche pour ce message uniquement.',
      how:   'ML-KEM (Module-LWE) génère une clé publique et une clé privée éphémères aléatoires. La clé publique permet au destinataire d\'encapsuler un secret partagé.',
      why:   'Les clés éphémères garantissent la forward secrecy : même si une clé long-terme est compromise, les anciens messages restent protégés.',
      algo:  'ML-KEM-768 (NIST FIPS 203) — Niveau 3, 192-bit post-quantique',
    },
  },
  {
    icon: '🔗', type: 'active', delay: 300,
    label: 'Encapsulation KEM',
    detail: 'kemEncapsulate(recipientPubKey) → sharedSecret + kemCiphertext',
    explain: {
      what:  'Encapsulation d\'un secret partagé avec la clé publique ML-KEM-768 du destinataire.',
      how:   'La clé publique du contact (Firestore) encapsule un secret aléatoire → kemCiphertext (transmis) + sharedSecret (jamais transmis).',
      why:   'Seul le destinataire avec sa clé privée peut décapsuler et retrouver le sharedSecret, même face à un ordinateur quantique.',
      algo:  'ML-KEM-768 encapsulate — IND-CCA2 sécurisé',
    },
  },
  {
    icon: '🧩', type: 'send', delay: 600,
    label: 'Dérivation de clé HKDF',
    detail: 'HKDF-SHA256(sharedSecret, info) → messageKey 256 bits',
    explain: {
      what:  'Dérivation d\'une clé AES-256 à partir du sharedSecret KEM.',
      how:   'HKDF (HMAC-based Extract-and-Expand KDF) avec SHA-256 transforme le sharedSecret brut en clé uniforme de 256 bits, avec un contexte (info) liant la clé à cet usage.',
      why:   'Le sharedSecret KEM brut n\'est pas utilisable directement comme clé AES. HKDF le distille et l\'isole de tout autre usage.',
      algo:  'HKDF-SHA256 (RFC 5869)',
    },
  },
  {
    icon: '🔒', type: 'send', delay: 900,
    label: 'Chiffrement AES-256-GCM',
    detail: 'aesGcmEncrypt(plaintext, messageKey, nonce) → ciphertext',
    explain: {
      what:  'Chiffrement authentifié du message avec AES-256-GCM.',
      how:   'Un nonce aléatoire de 96 bits est généré. AES-256-GCM chiffre le message et produit un ciphertext + tag d\'authentification GCM 128 bits. Le nonce est stocké avec le message.',
      why:   'AES-GCM garantit confidentialité et intégrité : toute modification du ciphertext invalide le tag et est détectée avant déchiffrement.',
      algo:  'AES-256-GCM (NIST SP 800-38D) — nonce 96 bits, tag 128 bits',
    },
  },
  {
    icon: '✍️', type: 'send', delay: 1200,
    label: 'Signature ML-DSA-65',
    detail: 'dsaSign(ciphertext ‖ nonce ‖ kemCiphertext, myPrivKey)',
    explain: {
      what:  'Signature numérique du message chiffré avec votre clé privée ML-DSA-65.',
      how:   'La concaténation (ciphertext + nonce + kemCiphertext) est signée avec Dilithium. La signature (~3 309 octets) est stockée dans Firestore avec le message.',
      why:   'Prouve que c\'est bien vous l\'expéditeur et que le message n\'a pas été altéré. Sans signature, un attaquant pourrait substituer le ciphertext.',
      algo:  'ML-DSA-65 (NIST FIPS 204 / Dilithium3) — résistant quantique',
    },
  },
  {
    icon: '📤', type: 'done', delay: 1500,
    label: 'Message envoyé dans Firestore',
    detail: '{ ciphertext, nonce, kemCiphertext, signature } → Firestore',
    explain: {
      what:  'Le paquet chiffré et signé est écrit dans Firestore.',
      how:   'Le document contient : kemCiphertext, ciphertext, nonce, signature. Le plaintext n\'est jamais transmis ni stocké.',
      why:   'Firebase ne voit que des blobs opaques. Même un accès complet à Firestore ne permet pas de lire les messages sans les clés privées locales.',
      algo:  'Firestore — stockage chiffré au repos (AES-256 Google)',
    },
  },
];

const RECV_STEPS: CryptoStepDef[] = [
  {
    icon: '📡', type: 'recv', delay: 0,
    label: 'Récupération clé publique DSA',
    detail: 'key-registry.getPublicKeys(senderUid) ← Firestore',
    explain: {
      what:  'Récupération de la clé publique ML-DSA-65 de l\'expéditeur depuis Firestore.',
      how:   'La clé publique DSA est publiée dans /publicKeys/{uid} lors de l\'inscription. Elle est lue depuis le cache mémoire ou Firestore si absente.',
      why:   'Vérifier la signature nécessite la clé publique de l\'expéditeur. Cette clé est publiée à l\'inscription et ne peut pas être falsifiée.',
      algo:  'key-registry.ts — cache mémoire + Firestore fallback',
    },
  },
  {
    icon: '🔍', type: 'active', delay: 350,
    label: 'Vérification signature ML-DSA-65',
    detail: 'dsaVerify(payload, signature, senderDsaPubKey)',
    explain: {
      what:  'Vérification cryptographique que la signature est valide et provient de l\'expéditeur déclaré.',
      how:   'ML-DSA-65 vérifie que la signature correspond au payload (ciphertext + nonce + kemCiphertext) et à la clé publique. Un seul octet modifié → échec.',
      why:   'Garantit authenticité et intégrité : impossible d\'injecter un message forgé ou d\'altérer un message existant sans être détecté.',
      algo:  'ML-DSA-65 verify (NIST FIPS 204) — retourne true/false',
    },
  },
  {
    icon: '🔓', type: 'recv', delay: 700,
    label: 'Décapsulation KEM',
    detail: 'kemDecapsulate(kemCiphertext, myPrivKey) → sharedSecret',
    explain: {
      what:  'Décapsulation du secret partagé avec votre clé privée ML-KEM-768.',
      how:   'Votre clé privée ML-KEM-768 (mémoire uniquement, jamais dans Firestore) décapsule le kemCiphertext pour retrouver le même sharedSecret que l\'expéditeur.',
      why:   'Seul le destinataire légitime a la clé privée. Sans elle, décapsuler le kemCiphertext est impossible même avec un ordinateur quantique.',
      algo:  'ML-KEM-768 decapsulate (NIST FIPS 203) — IND-CCA2',
    },
  },
  {
    icon: '🧩', type: 'recv', delay: 1050,
    label: 'Re-dérivation clé HKDF',
    detail: 'HKDF-SHA256(sharedSecret, info) → messageKey',
    explain: {
      what:  'Re-dérivation de la clé AES-256 à partir du sharedSecret décapsulé.',
      how:   'Même HKDF-SHA256 qu\'à l\'envoi. Le sharedSecret étant identique des deux côtés, la messageKey reconstruite est identique — sans jamais avoir transité.',
      why:   'La clé de déchiffrement n\'est jamais transmise. Elle est reconstruite indépendamment grâce au mécanisme KEM.',
      algo:  'HKDF-SHA256 (RFC 5869) — mêmes paramètres que l\'envoi',
    },
  },
  {
    icon: '✅', type: 'done', delay: 1400,
    label: 'Déchiffrement AES-256-GCM',
    detail: 'aesGcmDecrypt(ciphertext, nonce, messageKey) → plaintext',
    explain: {
      what:  'Déchiffrement authentifié et vérification d\'intégrité du message.',
      how:   'AES-256-GCM déchiffre le ciphertext avec la messageKey et le nonce. Le tag GCM est vérifié en premier — toute altération lève une exception avant d\'exposer des données.',
      why:   'GCM garantit un déchiffrement authentifié : impossible d\'obtenir un plaintext corrompu ou forgé sans que ce soit détecté.',
      algo:  'AES-256-GCM (NIST SP 800-38D) — authentification + confidentialité',
    },
  },
];

const ICONS_SVG: Record<CryptoStepType, string> = {
  send:   `<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" width="10" height="10"><path d="M1 6 11 1 6 11 5 8 1 6Z"/></svg>`,
  recv:   `<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" width="10" height="10"><path d="M6 1v8M2 6l4 4 4-4"/></svg>`,
  done:   `<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" width="10" height="10"><path d="M1.5 6.5 4.5 9.5 10.5 3"/></svg>`,
  warn:   `<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" width="10" height="10"><path d="M6 1 11 10H1L6 1Z"/><path d="M6 5v2.5M6 8.5v.5"/></svg>`,
  active: `<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" width="10" height="10"><circle cx="6" cy="6" r="4.5"/><path d="M6 3v3l2 1.5"/></svg>`,
};

function setCryptoStatus(state: 'idle' | 'sending' | 'active' | 'error'): void {
  const dot = document.getElementById('crypto-status-dot');
  if (!dot) return;
  dot.className = 'crypto-box-status';
  if (state !== 'idle') dot.classList.add(state === 'sending' ? 'sending' : state === 'active' ? 'active' : 'error');
}

function clearCryptoBox(): void {
  const steps = document.getElementById('crypto-steps');
  if (!steps) return;
  steps.innerHTML = '<div class="crypto-idle"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.2" width="22" height="22" opacity="0.3"><rect x="4" y="8" width="12" height="10" rx="2"/><path d="M7 8V6a3 3 0 0 1 6 0v2"/><circle cx="10" cy="13" r="1.2"/></svg><span>En attente d\'activité…</span></div>';
}

let _cryptoClearTimer: ReturnType<typeof setTimeout> | null = null;
let _cryptoStepTimers: ReturnType<typeof setTimeout>[]     = [];

function showCryptoSteps(stepsData: CryptoStepDef[], direction: 'ENVOI' | 'RÉCEPTION'): void {
  const container = document.getElementById('crypto-steps');
  if (!container) return;

  // Annuler tous les setTimeout pendants du run précédent
  _cryptoStepTimers.forEach(t => clearTimeout(t));
  _cryptoStepTimers = [];
  if (_cryptoClearTimer) { clearTimeout(_cryptoClearTimer); _cryptoClearTimer = null; }

  container.innerHTML = '';
  const sep = document.createElement('div');
  sep.className = 'crypto-sep';
  sep.innerHTML = `<span>── ${direction} ──</span>`;
  container.appendChild(sep);

  const stepEls: HTMLElement[] = [];
  stepsData.forEach((step, i) => {
    const t = setTimeout(() => {
      if (i > 0 && stepEls[i - 1]) {
        const prevIcon = stepEls[i - 1].querySelector('.crypto-step-icon');
        if (prevIcon && prevIcon.classList.contains('active')) {
          prevIcon.className = 'crypto-step-icon done';
          prevIcon.innerHTML = ICONS_SVG['done'];
        }
      }

      const ex = step.explain;
      const el = document.createElement('div');
      el.className = `crypto-step-wrap`;

      // Ligne principale (toujours visible)
      const row = document.createElement('div');
      row.className = `crypto-step${step.type === 'done' ? ' done-step' : ''}${ex ? ' clickable' : ''}`;
      row.innerHTML = `
        <div class="crypto-step-icon ${step.type}">${ICONS_SVG[step.type]}</div>
        <div class="crypto-step-body">
          <div class="crypto-step-label">${step.label}</div>
          ${step.detail ? `<div class="crypto-step-detail">${step.detail}</div>` : ''}
        </div>
        ${ex ? `<div class="crypto-step-chevron">
          <svg class="chevron-svg" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.8" width="9" height="9">
            <path d="M2 3.5l3 3 3-3"/>
          </svg>
        </div>` : ''}`;

      el.appendChild(row);

      // Panneau dépliable
      if (ex) {
        const panel = document.createElement('div');
        panel.className = 'crypto-step-panel';
        panel.innerHTML = `
          ${ex.algo ? `<div class="crypto-panel-algo">${ex.algo}</div>` : ''}
          <div class="crypto-panel-row">
            <span class="crypto-panel-key">Quoi</span>
            <span class="crypto-panel-val">${ex.what}</span>
          </div>
          <div class="crypto-panel-row">
            <span class="crypto-panel-key">Comment</span>
            <span class="crypto-panel-val">${ex.how}</span>
          </div>
          <div class="crypto-panel-row">
            <span class="crypto-panel-key">Pourquoi</span>
            <span class="crypto-panel-val">${ex.why}</span>
          </div>
          ${step.detail ? `<div class="crypto-panel-code">${step.detail}</div>` : ''}
        `;
        el.appendChild(panel);

        row.addEventListener('click', () => {
          const isOpen = el.classList.toggle('open');
          const chevron = row.querySelector('.chevron-svg') as SVGElement | null;
          if (chevron) chevron.style.transform = isOpen ? 'rotate(180deg)' : '';
          // Annuler le timer de nettoyage pendant qu'un panneau est ouvert
          if (isOpen && _cryptoClearTimer) {
            clearTimeout(_cryptoClearTimer);
            _cryptoClearTimer = null;
          }
          container.scrollTop = container.scrollHeight;
        });
      }

      container.appendChild(el);
      stepEls[i] = row; // garder ref sur la row pour l'icône active
      container.scrollTop = container.scrollHeight;
    }, step.delay);
    _cryptoStepTimers.push(t);
  });

  const lastDelay = stepsData[stepsData.length - 1].delay;
  setTimeout(() => setCryptoStatus('idle'), lastDelay + 600);

  _cryptoClearTimer = setTimeout(() => {
    if (container.querySelector('.crypto-step-wrap.open')) return; // panneau ouvert
    clearCryptoBox();
  }, lastDelay + 10_000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu de la liste des conversations
// ─────────────────────────────────────────────────────────────────────────────

function renderConversationList(convs: Conversation[]): void {
  const list = document.getElementById('contacts-list');
  if (!list) return;

  list.innerHTML = '<div class="contacts-section-label">Conversations</div>';

  if (convs.length === 0) {
    list.innerHTML += '<div class="contacts-empty">Aucune conversation.<br/>Appuyez sur <strong>+</strong> pour commencer.</div>';
    return;
  }

  for (const conv of convs) {
    const contactUid  = conv.participants.find((p) => p !== _myUid) ?? conv.participants[0];
    const isActive    = conv.id === _currentConvId;
    const displayName = getLocalConvName(conv.id) ?? contactUid.slice(0, 20);
    const preview     = conv.lastMessagePreview ?? '🔒 Chiffré';
    const timeStr     = conv.lastMessageAt
      ? new Date(conv.lastMessageAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : '';

    const item = document.createElement('div');
    item.className          = `contact-item${isActive ? ' active' : ''}`;
    item.dataset.convId     = conv.id;
    item.dataset.contactUid = contactUid;
    item.innerHTML = `
      <div class="contact-avatar">${displayName.slice(0, 2).toUpperCase()}</div>
      <div class="contact-body">
        <div class="contact-row">
          <span class="contact-name">${escapeHtml(displayName)}</span>
          <span class="contact-time">${timeStr}</span>
        </div>
        <div class="contact-preview">${escapeHtml(preview)}</div>
      </div>`;
    item.addEventListener('click', () => openConversation(conv.id, contactUid));
    list.appendChild(item);
  }

  // Après chaque re-render de la liste (ex: suite à un envoi Firestore),
  // réappliquer l'état actif si une conv est ouverte — sans toucher aux messages.
  if (_currentConvId) {
    const emptyState = document.getElementById('chat-empty');
    const convView   = document.getElementById('conversation-view');
    if (emptyState) { emptyState.style.display = 'none'; emptyState.classList.add('hidden'); }
    if (convView)   { convView.classList.remove('hidden'); convView.style.display = 'contents'; }
    // Re-marquer l'item actif dans la nouvelle liste
    document.querySelectorAll<HTMLElement>('.contact-item').forEach((el) => {
      el.classList.toggle('active', el.dataset.convId === _currentConvId);
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ouvrir une conversation
// ─────────────────────────────────────────────────────────────────────────────

function openConversation(convId: string, contactUid: string): void {
  if (_unsubMessages) { _unsubMessages(); _unsubMessages = null; }

  _currentConvId     = convId;
  _currentContactUid = contactUid;

  // Toujours revenir à la vue chat si on était dans les settings
  switchView('chat');

  const emptyState    = document.getElementById('chat-empty');
  const convView      = document.getElementById('conversation-view');
  const contactNameEl = document.getElementById('chat-contact-name');
  const topbarAvatar  = document.getElementById('topbar-avatar');

  emptyState?.classList.add('hidden');
  convView?.classList.remove('hidden');
  if (convView) convView.style.display = 'contents';

  const displayName = getLocalConvName(convId) ?? contactUid.slice(0, 24);
  if (contactNameEl) contactNameEl.textContent = displayName;
  if (topbarAvatar)  topbarAvatar.textContent  = displayName.slice(0, 2).toUpperCase();

  // Vider le DOM et l'état de rendu pour la nouvelle conversation
  const msgContainer = document.getElementById('messages-container');
  if (msgContainer) msgContainer.innerHTML = '';
  _renderedMsgIds = new Set();

  document.querySelectorAll('.contact-item').forEach((el) => {
    el.classList.toggle('active', (el as HTMLElement).dataset.convId === convId);
  });

  _unsubMessages = subscribeToMessages(_myUid, convId, renderMessages);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu des messages
// ─────────────────────────────────────────────────────────────────────────────

// Set des IDs de messages déjà rendus pour la conversation courante.
// Utiliser un Set d'IDs (plutôt qu'un compteur) rend le rendu idempotent :
// peu importe combien de fois Firestore re-déclenche le snapshot (envoi propre,
// mise à jour lastMessage, etc.), on n'affiche jamais deux fois le même message.
let _renderedMsgIds = new Set<string>();

function renderMessages(messages: DecryptedMessage[]): void {
  const container = document.getElementById('messages-container');
  if (!container) return;

  // Filtrer uniquement les messages pas encore dans le DOM
  const newMessages     = messages.filter(m => !_renderedMsgIds.has(m.id));
  const hasNewFromOther = newMessages.some(m => m.senderUid !== _myUid);

  if (newMessages.length === 0) return;

  for (const msg of newMessages) {
    const isMine = msg.senderUid === _myUid;
    const bubble = document.createElement('div');
    bubble.className     = `message-bubble ${isMine ? 'mine' : 'theirs'}`;
    bubble.dataset.msgId = msg.id;

    const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    bubble.innerHTML = `
      <div class="message-text-wrap">
        <p class="message-text">${escapeHtml(msg.plaintext)}</p>
      </div>
      <div class="message-meta">
        <span class="message-time">${time}</span>
        ${msg.verified ? '<span class="sig-ok">✓</span>' : '<span class="sig-pending">⦿</span>'}
      </div>`;
    container.appendChild(bubble);
    _renderedMsgIds.add(msg.id);
  }

  container.scrollTop = container.scrollHeight;

  if (hasNewFromOther) {
    setCryptoStatus('active');
    showCryptoSteps(RECV_STEPS, 'RÉCEPTION');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi d'un message — FIX : ne pas réinitialiser _currentConvId
// ─────────────────────────────────────────────────────────────────────────────

async function handleSendMessage(): Promise<void> {
  if (!_currentConvId || !_currentContactUid) return;

  const input = document.getElementById('message-input') as HTMLTextAreaElement | null;
  if (!input) return;

  const text = input.value.trim();
  if (!text) return;

  // Sauvegarder la conv courante AVANT l'await pour éviter tout reset
  const convId     = _currentConvId;
  const contactUid = _currentContactUid;

  input.value    = '';
  input.disabled = true;

  setCryptoStatus('sending');
  showCryptoSteps(SEND_STEPS, 'ENVOI');

  try {
    await sendMessage(_myUid, contactUid, text);
  } catch (err) {
    console.error('[AQ] sendMessage failed:', err);
    showToast('Envoi échoué. Vérifiez la console.');
    input.value = text;
    clearCryptoBox();
    setCryptoStatus('idle');
  } finally {
    input.disabled = false;
    input.focus();
    // Restaurer la conv courante si elle a changé pendant l'await (ne devrait pas arriver)
    if (_currentConvId !== convId) {
      _currentConvId     = convId;
      _currentContactUid = contactUid;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Modal nouvelle conversation
// ─────────────────────────────────────────────────────────────────────────────

function openNewConvModal(): void {
  const modal = document.getElementById('modal-new-conv');
  if (modal) modal.style.display = 'flex';
  setTimeout(() => document.getElementById('modal-uid-input')?.focus(), 50);
}
function closeNewConvModal(): void {
  const modal = document.getElementById('modal-new-conv');
  if (modal) modal.style.display = 'none';
  const input = document.getElementById('modal-uid-input') as HTMLInputElement | null;
  if (input) input.value = '';
}
async function confirmNewConv(): Promise<void> {
  const input      = document.getElementById('modal-uid-input') as HTMLInputElement | null;
  const contactUid = input?.value.trim();
  if (!contactUid || contactUid === _myUid) { showToast('UID invalide.'); return; }
  closeNewConvModal();
  try {
    const convId = await getOrCreateConversation(_myUid, contactUid);
    switchView('chat');
    openConversation(convId, contactUid);
  } catch (err) {
    showToast(`Erreur : ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Déconnexion — vider les IDs rendus
// ─────────────────────────────────────────────────────────────────────────────

async function handleSignOut(): Promise<void> {
  _unsubConvs?.();
  _unsubMessages?.();
  _currentConvId  = null;
  _renderedMsgIds  = new Set();
  await signOut();
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires
// ─────────────────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

function showToast(msg: string): void {
  const toast = document.createElement('div');
  toast.className   = 'toast';
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
