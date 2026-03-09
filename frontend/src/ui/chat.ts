/**
 * chat.ts — UI du chat branchée sur messaging.ts et auth.ts
 *
 * Responsabilités :
 *  - Charger le template chat.html dans #chat-screen
 *  - Afficher la liste des conversations en temps réel
 *  - Permettre d'ouvrir une conversation par UID de contact
 *  - Envoyer et recevoir des messages
 *  - Gérer la déconnexion
 *  - Afficher la crypto box avec les étapes de chiffrement/déchiffrement
 */

import { signOut }                          from '../services/auth';
import {
  subscribeToConversations,
  subscribeToMessages,
  sendMessage,
  getOrCreateConversation,
}                                           from '../services/messaging';
import type { Conversation, DecryptedMessage } from '../types/message';

let _unsubConvs:     (() => void) | null = null;
let _unsubMessages:  (() => void) | null = null;
let _currentConvId:  string | null       = null;
let _myUid:          string              = '';

// ─────────────────────────────────────────────────────────────────────────────
// Point d'entrée — appelé par main.ts après connexion
// ─────────────────────────────────────────────────────────────────────────────

export async function initChat(uid: string): Promise<void> {
  _myUid = uid;

  const container = document.getElementById('chat-screen')!;

  try {
    // Charger le template HTML du chat
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

  // Remplir identité
  const topnavAvatar       = document.getElementById('topnav-avatar');
  const profileDropdownUid = document.getElementById('profile-dropdown-uid');
  const settingsUid        = document.getElementById('settings-uid');
  // Le premier text node de l'avatar contient les initiales (avant le dropdown div)
  if (topnavAvatar) {
    const textNode = Array.from(topnavAvatar.childNodes).find(n => n.nodeType === Node.TEXT_NODE);
    if (textNode) textNode.textContent = uid.slice(0, 2).toUpperCase();
  }
  if (profileDropdownUid) profileDropdownUid.textContent = uid;
  if (settingsUid)        settingsUid.textContent = uid;

  // ── Déconnexion (dropdown + settings) ──
  document.getElementById('btn-signout')?.addEventListener('click', handleSignOut);
  document.getElementById('btn-signout-settings')?.addEventListener('click', handleSignOut);

  // ── Bouton envoi + input ──
  document.getElementById('btn-send')?.addEventListener('click', handleSendMessage);
  const msgInput = document.getElementById('message-input') as HTMLTextAreaElement | null;
  msgInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  });

  // ── Navigation settings via topnav + dropdown ──
  document.getElementById('rail-btn-settings')?.addEventListener('click', () => switchView('settings'));
  document.getElementById('btn-profile-settings')?.addEventListener('click', () => {
    closeProfileDropdown();
    switchView('settings');
  });

  // ── Toggle sidebar (1/3 gauche) ──
  document.getElementById('btn-toggle-sidebar')?.addEventListener('click', toggleSidebar);

  // ── Dropdown profil ──
  document.getElementById('topnav-avatar')?.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleProfileDropdown();
  });
  document.addEventListener('click', () => closeProfileDropdown());

  // ── Modal nouvelle conversation ──
  document.getElementById('btn-new-chat')?.addEventListener('click',    () => openModal());
  document.getElementById('modal-close')?.addEventListener('click',     () => closeModal());
  document.getElementById('modal-cancel')?.addEventListener('click',    () => closeModal());
  document.getElementById('modal-confirm')?.addEventListener('click',   () => confirmNewConv());
  document.getElementById('modal-uid-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')  confirmNewConv();
    if (e.key === 'Escape') closeModal();
  });

  // ── Copier UID (dropdown + settings) ──
  const copyUid = () => {
    navigator.clipboard.writeText(uid).then(() => showToast('UID copié !')).catch(() => {});
  };
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
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto Box — afficher les étapes
// ─────────────────────────────────────────────────────────────────────────────

type CryptoStepType = 'send' | 'recv' | 'done' | 'warn' | 'active';

interface CryptoStepDef {
  icon: string;
  type: CryptoStepType;
  label: string;
  detail?: string;
  delay: number;
}

const SEND_STEPS: CryptoStepDef[] = [
  { icon: '🔑', type: 'send',   label: 'Génération des clés éphémères',         detail: 'ML-KEM-768 keypair',                              delay: 0   },
  { icon: '🔗', type: 'active', label: 'Établissement liaison Kyber',            detail: 'KEM encapsulate → sharedSecret + kemCiphertext',  delay: 300 },
  { icon: '🔒', type: 'send',   label: 'Chiffrement AES-256-GCM',               detail: 'HKDF(sharedSecret) → messageKey + encrypt(msg)',  delay: 600 },
  { icon: '📡', type: 'send',   label: 'Récupération clé publique de Bob',       detail: 'key-registry ← Firestore',                       delay: 900 },
  { icon: '✍️', type: 'send',   label: 'Signature ML-DSA-65',                   detail: 'sign(ciphertext ‖ nonce ‖ kemCiphertext)',        delay: 1100 },
  { icon: '📤', type: 'done',   label: 'Message envoyé',                        detail: 'EncryptedMessage → Firestore',                    delay: 1400 },
];

const RECV_STEPS: CryptoStepDef[] = [
  { icon: '📡', type: 'recv',   label: 'Récupération clé publique d\'Alice',    detail: 'key-registry ← Firestore',                       delay: 0   },
  { icon: '🔍', type: 'active', label: 'Vérification signature ML-DSA-65',      detail: 'dsaVerify(sig, dsaPubKey, payload)',              delay: 250 },
  { icon: '🔓', type: 'recv',   label: 'Décapsulation KEM',                     detail: 'kemDecapsulate(kemCT, privKey) → sharedSecret',  delay: 500 },
  { icon: '🧩', type: 'recv',   label: 'Dérivation clé HKDF',                  detail: 'HKDF(sharedSecret, info) → messageKey',          delay: 750 },
  { icon: '✅', type: 'done',   label: 'Déchiffrement AES-256-GCM',             detail: 'aesGcmDecrypt(ct, nonce, key) → plaintext',      delay: 1000 },
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

  // Vider l'idle placeholder si présent, sinon garder l'historique
  const idle = container.querySelector('.crypto-idle');
  if (idle) container.innerHTML = '';

  // Ajouter un séparateur si ce n'est pas le tout premier bloc
  if (container.children.length > 0) {
    const sep = document.createElement('div');
    sep.className = 'crypto-sep';
    sep.innerHTML = `<span>${direction}</span>`;
    container.appendChild(sep);
  } else {
    const sep = document.createElement('div');
    sep.className = 'crypto-sep';
    sep.innerHTML = `<span>${direction}</span>`;
    container.appendChild(sep);
  }

  stepsData.forEach((step) => {
    setTimeout(() => {
      const el = document.createElement('div');
      el.className = `crypto-step${step.type === 'done' ? ' done-step' : ''}`;
      el.innerHTML = `
        <div class="crypto-step-icon ${step.type}">${ICONS_SVG[step.type]}</div>
        <div class="crypto-step-body">
          <div class="crypto-step-label">${step.label}</div>
          ${step.detail ? `<div class="crypto-step-detail">${step.detail}</div>` : ''}
        </div>
      `;
      container.appendChild(el);
      container.scrollTop = container.scrollHeight;
    }, step.delay);
  });

  // Reset dot status après la dernière étape
  const lastDelay = stepsData[stepsData.length - 1].delay + 600;
  setTimeout(() => setCryptoStatus('idle'), lastDelay);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu de la liste des conversations (sidebar)
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
    const contactUid = conv.participants.find((p) => p !== _myUid) ?? conv.participants[0];
    const isActive   = conv.id === _currentConvId;
    const preview    = conv.lastMessagePreview ?? '🔒 Message chiffré';
    const timeStr    = conv.lastMessageAt
      ? new Date(conv.lastMessageAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : '';

    const item = document.createElement('div');
    item.className          = `contact-item${isActive ? ' active' : ''}`;
    item.dataset.convId     = conv.id;
    item.dataset.contactUid = contactUid;
    item.innerHTML = `
      <div class="contact-avatar">${contactUid.slice(0, 2).toUpperCase()}</div>
      <div class="contact-body">
        <div class="contact-row">
          <span class="contact-name">${contactUid.slice(0, 20)}</span>
          <span class="contact-time">${timeStr}</span>
        </div>
        <div class="contact-preview">${escapeHtml(preview)}</div>
      </div>
    `;
    item.addEventListener('click', () => openConversation(conv.id, contactUid));
    list.appendChild(item);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ouvrir une conversation
// ─────────────────────────────────────────────────────────────────────────────

function openConversation(convId: string, contactUid: string): void {
  if (_unsubMessages) {
    _unsubMessages();
    _unsubMessages = null;
  }

  _currentConvId = convId;

  const emptyState    = document.getElementById('chat-empty');
  const convView      = document.getElementById('conversation-view');
  const contactNameEl = document.getElementById('chat-contact-name');
  const topbarAvatar  = document.getElementById('topbar-avatar');

  emptyState?.classList.add('hidden');
  convView?.classList.remove('hidden');
  if (contactNameEl) contactNameEl.textContent = contactUid.slice(0, 24);
  if (topbarAvatar)  topbarAvatar.textContent  = contactUid.slice(0, 2).toUpperCase();

  const msgContainer = document.getElementById('messages-container');
  if (msgContainer) msgContainer.innerHTML = '';

  document.querySelectorAll('.contact-item').forEach((el) => {
    el.classList.toggle('active', (el as HTMLElement).dataset.convId === convId);
  });

  _unsubMessages = subscribeToMessages(_myUid, convId, (messages) => {
    renderMessages(messages);
  });

  // Ensure chat view is shown
  switchView('chat');
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu des messages
// ─────────────────────────────────────────────────────────────────────────────

function renderMessages(messages: DecryptedMessage[]): void {
  const container = document.getElementById('messages-container');
  if (!container) return;

  const prevCount = container.querySelectorAll('.message-bubble').length;
  const hasNew    = messages.length > prevCount;

  container.innerHTML = '';

  for (const msg of messages) {
    const isMine = msg.senderUid === _myUid;
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${isMine ? 'mine' : 'theirs'}`;

    const time = new Date(msg.timestamp).toLocaleTimeString([], {
      hour: '2-digit', minute: '2-digit',
    });

    bubble.innerHTML = `
      <div class="message-text-wrap">
        <p class="message-text">${escapeHtml(msg.plaintext)}</p>
      </div>
      <div class="message-meta">
        <span class="message-time">${time}</span>
        ${msg.verified
          ? '<span class="sig-ok">✓</span>'
          : '<span class="sig-pending">⦿</span>'
        }
      </div>
    `;
    container.appendChild(bubble);
  }

  container.scrollTop = container.scrollHeight;

  // Si nouveau message reçu (pas envoyé par moi), afficher les étapes de réception
  if (hasNew && messages.length > 0) {
    const lastMsg = messages[messages.length - 1];
    if (lastMsg.senderUid !== _myUid) {
      setCryptoStatus('active');
      showCryptoSteps(RECV_STEPS, 'RÉCEPTION');
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi d'un message
// ─────────────────────────────────────────────────────────────────────────────

async function handleSendMessage(): Promise<void> {
  if (!_currentConvId) return;

  const input = document.getElementById('message-input') as HTMLTextAreaElement | null;
  if (!input) return;

  const text = input.value.trim();
  if (!text) return;

  const activeItem = document.querySelector('.contact-item.active') as HTMLElement | null;
  const contactUid = activeItem?.dataset.contactUid;
  if (!contactUid) return;

  input.value    = '';
  input.disabled = true;

  // Afficher les étapes de chiffrement
  setCryptoStatus('sending');
  showCryptoSteps(SEND_STEPS, 'ENVOI');

  try {
    await sendMessage(_myUid, contactUid, text);
  } catch (err) {
    console.error('sendMessage failed:', err);
    showToast('Failed to send message. Check the console.');
    input.value = text;
    clearCryptoBox();
    setCryptoStatus('idle');
  } finally {
    input.disabled = false;
    input.focus();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Modal nouvelle conversation
// ─────────────────────────────────────────────────────────────────────────────

function openModal(): void {
  const modal = document.getElementById('modal-new-conv');
  if (modal) modal.style.display = 'flex';
  setTimeout(() => document.getElementById('modal-uid-input')?.focus(), 50);
}

function closeModal(): void {
  const modal = document.getElementById('modal-new-conv');
  if (modal) modal.style.display = 'none';
  const input = document.getElementById('modal-uid-input') as HTMLInputElement | null;
  if (input) input.value = '';
}

async function confirmNewConv(): Promise<void> {
  const input = document.getElementById('modal-uid-input') as HTMLInputElement | null;
  const contactUid = input?.value.trim();
  if (!contactUid || contactUid === _myUid) {
    showToast('UID invalide.');
    return;
  }
  closeModal();
  switchView('chat');
  try {
    const convId = await getOrCreateConversation(_myUid, contactUid);
    openConversation(convId, contactUid);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('getOrCreateConversation failed:', err);
    showToast(`Erreur : ${msg}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Déconnexion
// ─────────────────────────────────────────────────────────────────────────────

async function handleSignOut(): Promise<void> {
  _unsubConvs?.();
  _unsubMessages?.();
  _currentConvId = null;
  await signOut();
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires
// ─────────────────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(msg: string): void {
  const toast = document.createElement('div');
  toast.className   = 'toast';
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
