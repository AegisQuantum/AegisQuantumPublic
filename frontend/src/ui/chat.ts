/**
 * chat.ts — UI du chat branchée sur messaging.ts et auth.ts
 */

import { signOut }                          from '../services/auth';
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

/** Retourne la couleur de fond de l'avatar de l'utilisateur (stockée localement). */
function getAvatarColor(): string {
  return localStorage.getItem(`aq:avatar:color:${_myUid}`) ?? '#6b8ff5';
}

/** Sauvegarde la couleur d'avatar. */
function setAvatarColor(color: string): void {
  localStorage.setItem(`aq:avatar:color:${_myUid}`, color);
}

/** Retourne les initiales personnalisées de l'avatar (max 2 chars). */
function getAvatarInitials(): string {
  return localStorage.getItem(`aq:avatar:initials:${_myUid}`) ?? _myUid.slice(0, 2).toUpperCase();
}

/** Sauvegarde des initiales personnalisées. */
function setAvatarInitials(initials: string): void {
  const clean = initials.trim().slice(0, 2).toUpperCase();
  if (clean) localStorage.setItem(`aq:avatar:initials:${_myUid}`, clean);
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
  document.getElementById('rail-btn-settings')?.addEventListener('click', () => switchView('settings'));
  document.getElementById('btn-profile-settings')?.addEventListener('click', () => {
    closeProfileDropdown();
    switchView('settings');
  });

  // ── Sidebar toggle ──
  document.getElementById('btn-toggle-sidebar')?.addEventListener('click', toggleSidebar);

  // ── Dropdown profil ──
  document.getElementById('topnav-avatar')?.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleProfileDropdown();
  });
  document.addEventListener('click', () => closeProfileDropdown());

  // ── Changer avatar (click sur avatar dans settings) ──
  document.getElementById('btn-change-avatar')?.addEventListener('click', openAvatarModal);
  document.getElementById('avatar-modal-close')?.addEventListener('click', closeAvatarModal);
  document.getElementById('avatar-modal-cancel')?.addEventListener('click', closeAvatarModal);
  document.getElementById('avatar-modal-confirm')?.addEventListener('click', confirmAvatarChange);
  // Sélecteur de couleurs
  document.querySelectorAll<HTMLElement>('.avatar-color-swatch').forEach((swatch) => {
    swatch.addEventListener('click', () => {
      document.querySelectorAll('.avatar-color-swatch').forEach(s => s.classList.remove('selected'));
      swatch.classList.add('selected');
      const preview = document.getElementById('avatar-modal-preview');
      if (preview) preview.style.background = swatch.dataset.color ?? '#6b8ff5';
    });
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

  // Topnav avatar (texte seul — pas le dropdown)
  const topnavAvatar = document.getElementById('topnav-avatar');
  if (topnavAvatar) {
    const textNode = Array.from(topnavAvatar.childNodes).find(n => n.nodeType === Node.TEXT_NODE);
    if (textNode) textNode.textContent = initials;
    (topnavAvatar as HTMLElement).style.background = color;
  }

  // Avatar dans les settings
  const settingsAvatar = document.getElementById('settings-avatar-preview');
  if (settingsAvatar) {
    settingsAvatar.textContent  = initials;
    settingsAvatar.style.background = color;
  }
}

function openAvatarModal(): void {
  const modal    = document.getElementById('avatar-modal');
  const preview  = document.getElementById('avatar-modal-preview');
  const input    = document.getElementById('avatar-initials-input') as HTMLInputElement | null;
  const curColor = getAvatarColor();

  if (modal)   modal.style.display = 'flex';
  if (preview) { preview.textContent = getAvatarInitials(); preview.style.background = curColor; }
  if (input)   input.value = getAvatarInitials();

  // Marquer la couleur active
  document.querySelectorAll<HTMLElement>('.avatar-color-swatch').forEach((s) => {
    s.classList.toggle('selected', s.dataset.color === curColor);
  });

  // Mise à jour live du preview via l'input initiales
  input?.removeEventListener('input', _onInitialsInput);
  input?.addEventListener('input', _onInitialsInput);

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

function confirmAvatarChange(): void {
  const input    = document.getElementById('avatar-initials-input') as HTMLInputElement | null;
  const selected = document.querySelector<HTMLElement>('.avatar-color-swatch.selected');
  const color    = selected?.dataset.color ?? getAvatarColor();

  if (input?.value.trim()) setAvatarInitials(input.value);
  setAvatarColor(color);
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
interface CryptoStepDef { icon: string; type: CryptoStepType; label: string; detail?: string; delay: number; }

const SEND_STEPS: CryptoStepDef[] = [
  { icon: '🔑', type: 'send',   label: 'Génération des clés éphémères',        detail: 'ML-KEM-768 keypair',                             delay: 0    },
  { icon: '🔗', type: 'active', label: 'Établissement liaison Kyber',           detail: 'KEM encapsulate → sharedSecret + kemCiphertext', delay: 300  },
  { icon: '🔒', type: 'send',   label: 'Chiffrement AES-256-GCM',              detail: 'HKDF(sharedSecret) → messageKey + encrypt(msg)', delay: 600  },
  { icon: '📡', type: 'send',   label: 'Récupération clé publique du contact', detail: 'key-registry ← Firestore',                      delay: 900  },
  { icon: '✍️', type: 'send',   label: 'Signature ML-DSA-65',                  detail: 'sign(ciphertext ‖ nonce ‖ kemCiphertext)',       delay: 1100 },
  { icon: '📤', type: 'done',   label: 'Message envoyé',                       detail: 'EncryptedMessage → Firestore',                   delay: 1400 },
];
const RECV_STEPS: CryptoStepDef[] = [
  { icon: '📡', type: 'recv',   label: 'Récupération clé publique sender',     detail: 'key-registry ← Firestore',                      delay: 0   },
  { icon: '🔍', type: 'active', label: 'Vérification signature ML-DSA-65',     detail: 'dsaVerify(sig, dsaPubKey, payload)',             delay: 250 },
  { icon: '🔓', type: 'recv',   label: 'Décapsulation KEM',                    detail: 'kemDecapsulate(kemCT, privKey) → sharedSecret', delay: 500 },
  { icon: '🧩', type: 'recv',   label: 'Dérivation clé HKDF',                 detail: 'HKDF(sharedSecret, info) → messageKey',         delay: 750 },
  { icon: '✅', type: 'done',   label: 'Déchiffrement AES-256-GCM',            detail: 'aesGcmDecrypt(ct, nonce, key) → plaintext',     delay: 1000 },
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

function showCryptoSteps(stepsData: CryptoStepDef[], direction: 'ENVOI' | 'RÉCEPTION'): void {
  const container = document.getElementById('crypto-steps');
  if (!container) return;
  const idle = container.querySelector('.crypto-idle');
  if (idle) container.innerHTML = '';
  const sep = document.createElement('div');
  sep.className = 'crypto-sep';
  sep.innerHTML = `<span>── ${direction} ──</span>`;
  container.appendChild(sep);
  const stepEls: HTMLElement[] = [];
  stepsData.forEach((step, i) => {
    setTimeout(() => {
      if (i > 0 && stepEls[i - 1]) {
        const prevIcon = stepEls[i - 1].querySelector('.crypto-step-icon');
        if (prevIcon && prevIcon.classList.contains('active')) {
          prevIcon.className = 'crypto-step-icon done';
          prevIcon.innerHTML = ICONS_SVG['done'];
        }
      }
      const el = document.createElement('div');
      el.className = `crypto-step${step.type === 'done' ? ' done-step' : ''}`;
      el.innerHTML = `
        <div class="crypto-step-icon ${step.type}">${ICONS_SVG[step.type]}</div>
        <div class="crypto-step-body">
          <div class="crypto-step-label">${step.label}</div>
          ${step.detail ? `<div class="crypto-step-detail">${step.detail}</div>` : ''}
        </div>`;
      container.appendChild(el);
      stepEls[i] = el;
      container.scrollTop = container.scrollHeight;
    }, step.delay);
  });
  setTimeout(() => setCryptoStatus('idle'), stepsData[stepsData.length - 1].delay + 600);
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
    // Nom local (renommé) ou fallback UID
    const displayName = getLocalConvName(conv.id) ?? contactUid.slice(0, 20);
    // Aperçu du dernier message
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Ouvrir une conversation
// ─────────────────────────────────────────────────────────────────────────────

function openConversation(convId: string, contactUid: string): void {
  if (_unsubMessages) { _unsubMessages(); _unsubMessages = null; }

  _currentConvId     = convId;
  _currentContactUid = contactUid;

  const emptyState    = document.getElementById('chat-empty');
  const convView      = document.getElementById('conversation-view');
  const contactNameEl = document.getElementById('chat-contact-name');
  const topbarAvatar  = document.getElementById('topbar-avatar');

  emptyState?.classList.add('hidden');
  convView?.classList.remove('hidden');

  const displayName = getLocalConvName(convId) ?? contactUid.slice(0, 24);
  if (contactNameEl) contactNameEl.textContent = displayName;
  if (topbarAvatar)  topbarAvatar.textContent  = displayName.slice(0, 2).toUpperCase();

  // Vider le DOM et l'état de rendu pour la nouvelle conversation
  const msgContainer = document.getElementById('messages-container');
  if (msgContainer) msgContainer.innerHTML = '';
  _renderedCount = 0;

  document.querySelectorAll('.contact-item').forEach((el) => {
    el.classList.toggle('active', (el as HTMLElement).dataset.convId === convId);
  });

  _unsubMessages = subscribeToMessages(_myUid, convId, renderMessages);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu des messages
// ─────────────────────────────────────────────────────────────────────────────

// Nombre de messages déjà rendus pour la conversation courante.
// On compare uniquement la longueur : Firestore renvoie toujours la liste
// complète triée par timestamp, donc les nouveaux sont toujours en fin de liste.
let _renderedCount = 0;

function renderMessages(messages: DecryptedMessage[]): void {
  const container = document.getElementById('messages-container');
  if (!container) return;

  // Nouveaux messages = ceux après l'index _renderedCount
  const newMessages     = messages.slice(_renderedCount);
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
  }

  _renderedCount = messages.length;
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
  _currentConvId = null;
  _renderedCount  = 0;
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
