/**
 * chat.ts — UI du chat branchée sur messaging.ts et auth.ts
 *
 * Responsabilités :
 *  - Charger le template chat.html dans #chat-screen
 *  - Afficher la liste des conversations en temps réel
 *  - Permettre d'ouvrir une conversation par UID de contact
 *  - Envoyer et recevoir des messages
 *  - Gérer la déconnexion
 */

import { signOut }                          from '../services/auth';
import {
  subscribeToConversations,
  subscribeToMessages,
  sendMessage,
  getOrCreateConversation,
  // getConversationId est utilisé via import() dynamique dans handleSendMessage
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

  // Charger le template HTML du chat
  const res      = await fetch('/src/pages/chat.html');
  const html     = await res.text();
  const container = document.getElementById('chat-screen')!;
  container.innerHTML = html;

  // Afficher l'uid courant dans la sidebar
  const userEmailEl = document.getElementById('current-user-email');
  if (userEmailEl) userEmailEl.textContent = `uid: ${uid.slice(0, 12)}…`;

  // Brancher les événements
  document.getElementById('btn-signout')?.addEventListener('click', handleSignOut);
  document.getElementById('btn-new-chat')?.addEventListener('click', handleNewChat);
  document.getElementById('btn-send')?.addEventListener('click', handleSendMessage);

  const msgInput = document.getElementById('message-input') as HTMLTextAreaElement | null;
  msgInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  });

  // S'abonner aux conversations en temps réel
  _unsubConvs = subscribeToConversations(uid, renderConversationList);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu de la liste des conversations (sidebar)
// ─────────────────────────────────────────────────────────────────────────────

function renderConversationList(convs: Conversation[]): void {
  const list = document.getElementById('contacts-list');
  if (!list) return;

  // Garder le label en tête
  list.innerHTML = '<div class="contacts-label">Conversations</div>';

  if (convs.length === 0) {
    list.innerHTML += '<div class="contacts-empty">No conversations yet.<br/>Press + to start one.</div>';
    return;
  }

  for (const conv of convs) {
    const contactUid = conv.participants.find((p) => p !== _myUid) ?? conv.participants[0];
    const isActive   = conv.id === _currentConvId;

    const item = document.createElement('div');
    item.className  = `contact-item${isActive ? ' active' : ''}`;
    item.dataset.convId     = conv.id;
    item.dataset.contactUid = contactUid;
    item.innerHTML = `
      <div class="contact-avatar">${contactUid.slice(0, 2).toUpperCase()}</div>
      <div class="contact-info">
        <div class="contact-name">${contactUid.slice(0, 16)}…</div>
        <div class="contact-preview">${conv.lastMessagePreview ?? 'Encrypted message'}</div>
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
  // Désabonner l'ancienne conversation
  if (_unsubMessages) {
    _unsubMessages();
    _unsubMessages = null;
  }

  _currentConvId = convId;

  // Mettre à jour l'UI
  const emptyState       = document.getElementById('chat-empty');
  const convView         = document.getElementById('conversation-view');
  const contactNameEl    = document.getElementById('chat-contact-name');

  emptyState?.classList.add('hidden');
  convView?.classList.remove('hidden');
  if (contactNameEl) contactNameEl.textContent = `${contactUid.slice(0, 20)}…`;

  // Vider le conteneur de messages
  const msgContainer = document.getElementById('messages-container');
  if (msgContainer) msgContainer.innerHTML = '';

  // Mettre en surbrillance dans la sidebar
  document.querySelectorAll('.contact-item').forEach((el) => {
    el.classList.toggle('active', (el as HTMLElement).dataset.convId === convId);
  });

  // S'abonner aux messages en temps réel
  _unsubMessages = subscribeToMessages(_myUid, convId, (messages) => {
    renderMessages(messages);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu des messages
// ─────────────────────────────────────────────────────────────────────────────

function renderMessages(messages: DecryptedMessage[]): void {
  const container = document.getElementById('messages-container');
  if (!container) return;

  container.innerHTML = '';

  for (const msg of messages) {
    const isMine = msg.senderUid === _myUid;
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${isMine ? 'mine' : 'theirs'}`;

    const time = new Date(msg.timestamp).toLocaleTimeString([], {
      hour: '2-digit', minute: '2-digit',
    });

    bubble.innerHTML = `
      <div class="message-text">${escapeHtml(msg.plaintext)}</div>
      <div class="message-meta">
        <span class="message-time">${time}</span>
        ${msg.verified
          ? '<span class="sig-ok" title="Signature verified">✓</span>'
          : '<span class="sig-pending" title="Signature not yet verified (crypto pending)">⚠</span>'
        }
      </div>
    `;
    container.appendChild(bubble);
  }

  // Scroll vers le bas
  container.scrollTop = container.scrollHeight;
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

  // Trouver le contactUid à partir de la conv active
  const activeItem  = document.querySelector('.contact-item.active') as HTMLElement | null;
  const contactUid  = activeItem?.dataset.contactUid;
  if (!contactUid) return;

  input.value    = '';
  input.disabled = true;

  try {
    await sendMessage(_myUid, contactUid, text);
  } catch (err) {
    console.error('sendMessage failed:', err);
    showToast('Failed to send message. Check the console.');
    input.value = text; // Remettre le texte si échec
  } finally {
    input.disabled = false;
    input.focus();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Nouvelle conversation
// ─────────────────────────────────────────────────────────────────────────────

async function handleNewChat(): Promise<void> {
  const contactUid = prompt('Enter the UID of the contact to message:')?.trim();
  if (!contactUid || contactUid === _myUid) return;

  try {
    const convId = await getOrCreateConversation(_myUid, contactUid);
    openConversation(convId, contactUid);
  } catch (err) {
    console.error('getOrCreateConversation failed:', err);
    showToast('Could not start conversation. Is the contact UID valid?');
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
  // main.ts / onAuthChange prend le relais pour revenir à l'écran d'auth
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
