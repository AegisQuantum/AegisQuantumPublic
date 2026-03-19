/**
 * chat.ts — UI du chat branchée sur messaging.ts et auth.ts
 */

// Import du CSS chat — Vite le bundle en prod, l'injecte via <style> en dev
import '../styles/chat.css';

import { signOut, deleteAccount }           from '../services/auth';
import { openFingerprintModal, closeFingerprintModal } from './fingerprint';
import {
  subscribeToConversations,
  subscribeToMessages,
  sendMessage,
  sendFile,
  getOrCreateConversation,
  onConvPreviewUpdate,
  sendRatchetResetSignal,
  deleteMessageForBoth,
  deleteMessageForMe,
  editMessage,
}                                           from '../services/messaging';
import { getHiddenMessages }               from '../services/idb-cache';
import {
  subscribeToTyping,
  markAllRead,
  createTypingDebouncer,
}                                           from '../services/presence';
import {
  exportBackup,
  type BackupConversation,
  type BackupPayload,
}                                           from '../services/backup';
import {
  exportSessionKeys,
  importSessionKeys,
  downloadSessionFile,
}                                           from '../services/session-keys';
import { validateMnemonic, normalizeMnemonic } from '../crypto/mnemonic';
import type { Conversation, DecryptedMessage } from '../types/message';

let _unsubConvs:        (() => void) | null = null;
let _unsubMessages:     (() => void) | null = null;
let _unsubTyping:       (() => void) | null = null;
let _unsubPreview:      (() => void) | null = null;
let _currentConvId:     string | null       = null;
let _currentContactUid: string | null       = null;
let _myUid:             string              = '';

// Cache local des conversations — mis à jour par subscribeToConversations ET
// par onConvPreviewUpdate (preview locale sans snapshot Firestore).
let _localConvs: import('../types/message').Conversation[] = [];

// Debouncer typing — créé à chaque ouverture de conversation, détruit à la fermeture
let _typingDebouncer: ReturnType<typeof createTypingDebouncer> | null = null;

// ─────────────────────────────────────────────────────────────────────────────
// Cache global des messages déchiffrés (pour la recherche + backup)
// Clé : convId  —  Valeur : derniers DecryptedMessage[] reçus du subscriber
// ─────────────────────────────────────────────────────────────────────────────
const _allDecryptedMessages = new Map<string, DecryptedMessage[]>();

// État de la recherche dans les messages
let _msgSearchQuery = '';

// Guard anti-double-submit — empêche deux envois simultanés (double-clic, Enter + clic)
let _sendInProgress = false;

// Context menu — message ciblé par le clic droit courant
let _ctxMsgId:             string | null = null;
let _ctxConvId:            string | null = null;
let _ctxIsMine:            boolean       = false;
let _ctxKemCiphertext:     string        = "";
let _ctxInitKemCiphertext: string | undefined;
let _ctxMessageIndex:      number        = 0;
let _ctxPlaintext:         string        = "";

// Messages cachés localement pour l'utilisateur courant
let _hiddenMessages = new Set<string>();

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

  // ── Envoi + typing ──
  document.getElementById('btn-send')?.addEventListener('click', handleSendMessage);
  const msgInput = document.getElementById('message-input') as HTMLTextAreaElement | null;
  msgInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); handleSendMessage(); }
  });
  msgInput?.addEventListener('input',  () => _typingDebouncer?.onInput());
  msgInput?.addEventListener('blur',   () => _typingDebouncer?.onBlur());

  // ── Envoi fichier ──
  const fileInput = document.getElementById('file-input') as HTMLInputElement | null;
  fileInput?.addEventListener('change', async (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file || !_currentContactUid) return;
    (e.target as HTMLInputElement).value = '';
    await handleSendFile(file);
  });

  // ── Envoi image ──
  const imageInput = document.getElementById('image-input') as HTMLInputElement | null;
  imageInput?.addEventListener('change', async (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file || !_currentContactUid) return;
    (e.target as HTMLInputElement).value = '';
    await handleSendFile(file);
  });

  // ── Navigation settings ──
  document.getElementById('rail-btn-settings')?.addEventListener('click', () => {
    const isSettings = document.getElementById('view-settings')?.style.display !== 'none';
    switchView(isSettings ? 'chat' : 'settings');
  });
  document.getElementById('btn-profile-settings')?.addEventListener('click', () => {
    closeProfileDropdown();
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

  document.querySelectorAll<HTMLElement>('.avatar-color-swatch').forEach((swatch) => {
    swatch.addEventListener('click', () => {
      document.querySelectorAll('.avatar-color-swatch').forEach(s => s.classList.remove('selected'));
      swatch.classList.add('selected');
      const preview = document.getElementById('avatar-modal-preview') as HTMLElement | null;
      if (preview && !_pendingPhoto && !getAvatarPhoto()) {
        preview.style.background = swatch.dataset.color ?? '#6b8ff5';
      }
    });
  });

  // ── Recherche dans les messages ──
  document.getElementById('btn-msg-search-toggle')?.addEventListener('click', toggleMsgSearch);
  document.getElementById('msg-search-input')?.addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value;
    const clearBtn = document.getElementById('msg-search-clear');
    if (clearBtn) clearBtn.style.display = q ? '' : 'none';
    applyMsgSearch(q);
  });
  document.getElementById('msg-search-clear')?.addEventListener('click', () => {
    const input = document.getElementById('msg-search-input') as HTMLInputElement | null;
    if (input) input.value = '';
    const clearBtn = document.getElementById('msg-search-clear');
    if (clearBtn) clearBtn.style.display = 'none';
    applyMsgSearch('');
    input?.focus();
  });
  document.getElementById('msg-search-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMsgSearch();
  });

  // ── Export Backup ──
  document.getElementById('btn-export-backup')?.addEventListener('click', openBackupExportModal);
  document.getElementById('backup-export-close')?.addEventListener('click', closeBackupExportModal);
  document.getElementById('backup-export-cancel')?.addEventListener('click', closeBackupExportModal);
  document.getElementById('backup-export-confirm')?.addEventListener('click', confirmBackupExport);
  document.getElementById('backup-export-password')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmBackupExport();
    if (e.key === 'Escape') closeBackupExportModal();
  });
  document.getElementById('backup-export-modal')?.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).id === 'backup-export-modal') closeBackupExportModal();
  });

  // ── Export clés de session ──
  document.getElementById('btn-export-session')?.addEventListener('click', openSessionExportModal);
  document.getElementById('session-export-close')?.addEventListener('click', closeSessionExportModal);
  document.getElementById('session-export-cancel')?.addEventListener('click', closeSessionExportModal);
  document.getElementById('session-export-confirm')?.addEventListener('click', confirmSessionExport);
  document.getElementById('session-export-modal')?.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).id === 'session-export-modal') closeSessionExportModal();
  });

  // ── Import clés de session ──
  document.getElementById('btn-import-session')?.addEventListener('click', openSessionImportModal);
  document.getElementById('session-import-close')?.addEventListener('click', closeSessionImportModal);
  document.getElementById('session-import-cancel')?.addEventListener('click', closeSessionImportModal);
  document.getElementById('session-import-confirm')?.addEventListener('click', confirmSessionImport);
  document.getElementById('session-import-modal')?.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).id === 'session-import-modal') closeSessionImportModal();
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

  // ── Resync ratchet ──
  document.getElementById('btn-resync-ratchet')?.addEventListener('click', async () => {
    if (!_currentConvId || !_currentContactUid) return;
    const confirmed = window.confirm(
      '↺ Resynchroniser le Double Ratchet ?\n\n' +
      'À utiliser si les messages ne s\'envoient plus ou restent [🔒] après une régénération de clés.\n\n' +
      'Les messages existants ne seront pas affectés. ' +
      'Les deux parties pourront s\'envoyer de nouveaux messages déchiffrables après la resync.'
    );
    if (!confirmed) return;

    const btn = document.getElementById('btn-resync-ratchet') as HTMLButtonElement | null;
    if (btn) { btn.disabled = true; btn.textContent = 'Resync…'; }

    try {
      await sendRatchetResetSignal(_myUid, _currentContactUid);
      showToast('Resynchronisation envoyée — le ratchet repart de zéro.');
    } catch (e) {
      showToast('Erreur lors de la resync : ' + ((e as Error).message ?? String(e)));
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="13" height="13"><path d="M13.5 8A5.5 5.5 0 1 1 8 2.5"/><path d="M10 2.5h3.5V6"/></svg> Resync`;
      }
    }
  });

  // ── Avertissement fermeture + bandeau export clés ──
  initCloseWarning();
  initExportWarningBanner();
  initLightbox();

  // ── Notifications push ──
  initPushNotifications();

  // ── Supprimer compte ──
  document.getElementById('btn-delete-account')?.addEventListener('click', openDeleteAccountModal);
  document.getElementById('modal-delete-account-close')?.addEventListener('click', closeDeleteAccountModal);
  document.getElementById('modal-delete-account-cancel')?.addEventListener('click', closeDeleteAccountModal);
  document.getElementById('modal-delete-account')?.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).id === 'modal-delete-account') closeDeleteAccountModal();
  });
  document.getElementById('modal-delete-account-confirm-input')?.addEventListener('input', (e) => {
    const val = (e.target as HTMLInputElement).value;
    const btn = document.getElementById('modal-delete-account-confirm') as HTMLButtonElement | null;
    if (btn) btn.disabled = val !== 'SUPPRIMER';
  });
  document.getElementById('modal-delete-account-confirm')?.addEventListener('click', confirmDeleteAccount);

  // ── Menu contextuel messages ──
  initMessageContextMenu();

  // Charger les messages cachés au démarrage
  getHiddenMessages(_myUid).then(s => { _hiddenMessages = s; });

  // ── Renommer conversation ──
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

  // ── Recherche sidebar (conversations) ──
  document.getElementById('search-input')?.addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value.toLowerCase();
    document.querySelectorAll<HTMLElement>('.contact-item').forEach((el) => {
      const name = el.querySelector('.contact-name')?.textContent?.toLowerCase() ?? '';
      el.style.display = name.includes(q) ? '' : 'none';
    });
  });

  // ── S'abonner aux conversations ──
  _unsubConvs = subscribeToConversations(uid, (convs) => {
    _localConvs = convs;
    renderConversationList(convs);
  });

  // ── Mise à jour locale de la preview quand ON envoie un message ──
  _unsubPreview?.();
  _unsubPreview = onConvPreviewUpdate((convId, preview, ts) => {
    _localConvs = _localConvs.map(c =>
      c.id === convId ? { ...c, lastMessagePreview: preview, lastMessageAt: ts } : c
    );
    _localConvs = [..._localConvs].sort((a, b) => (b.lastMessageAt ?? 0) - (a.lastMessageAt ?? 0));
    renderConversationList(_localConvs);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Avatar
// ─────────────────────────────────────────────────────────────────────────────

function refreshAvatar(): void {
  const initials = getAvatarInitials();
  const color    = getAvatarColor();
  const photo    = getAvatarPhoto();

  const topnavAvatar = document.getElementById('topnav-avatar');
  if (topnavAvatar) {
    const textNode = Array.from(topnavAvatar.childNodes).find(n => n.nodeType === Node.TEXT_NODE);
    if (photo) {
      if (textNode) (textNode as Text).textContent = '';
      (topnavAvatar as HTMLElement).style.cssText +=
        `;background-image:url('${photo}');background-size:cover;background-position:center;background-color:transparent`;
    } else {
      if (textNode) (textNode as Text).textContent = initials;
      (topnavAvatar as HTMLElement).style.backgroundImage = '';
      (topnavAvatar as HTMLElement).style.background = color;
    }
  }

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

  document.querySelectorAll<HTMLElement>('.avatar-color-swatch').forEach((s) => {
    s.classList.toggle('selected', s.dataset.color === curColor);
  });

  input?.removeEventListener('input', _onInitialsInput);
  input?.addEventListener('input', _onInitialsInput);

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

let _pendingPhoto: string | null | undefined = undefined;

function confirmAvatarChange(): void {
  const input    = document.getElementById('avatar-initials-input') as HTMLInputElement | null;
  const selected = document.querySelector<HTMLElement>('.avatar-color-swatch.selected');
  const color    = selected?.dataset.color ?? getAvatarColor();

  if (input?.value.trim()) setAvatarInitials(input.value);
  setAvatarColor(color);
  if (_pendingPhoto !== undefined) setAvatarPhoto(_pendingPhoto);
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

  const nameEl = document.getElementById('chat-contact-name');
  if (nameEl) nameEl.textContent = name || (_currentContactUid?.slice(0, 24) ?? '—');

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
    refreshAvatar();
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
    icon: '📡', type: 'send', delay: 0,
    label: 'Récupération clé publique KEM',
    detail: 'key-registry.getPublicKeys(contactUid) ← Firestore',
    explain: {
      what:  'Récupération de la clé publique ML-KEM-768 du destinataire depuis Firestore.',
      how:   'À l\'inscription, chaque utilisateur publie sa clé KEM publique dans /publicKeys/{uid}. Elle est lue depuis le cache mémoire ou Firestore si absente.',
      why:   'Sans cette clé publique, impossible d\'encapsuler un secret partagé. Premier message = initialisation du Double Ratchet avec cette clé.',
      algo:  'key-registry.ts — cache mémoire + Firestore fallback',
    },
  },
  {
    icon: '🔑', type: 'active', delay: 300,
    label: 'Double Ratchet — avancement KEM',
    detail: 'kemEncapsulate(theirKemPubKey) → sharedSecret éphémère; HKDF(rootKey ‖ sharedSecret) → rootKey + sendingChainKey',
    explain: {
      what:  'Chaque message fait tourner la "machine" du Double Ratchet via un échange KEM éphémère.',
      how:   'kemEncapsulate génère un secret partagé éphémère avec la clé publique KEM du contact. HKDF combine ce secret avec le rootKey courant pour produire un nouveau rootKey et une sendingChainKey. Le kemCiphertext est transmis avec le message.',
      why:   'C\'est le cœur du Double Ratchet : à chaque message, les clés changent (forward secrecy + break-in recovery). Un attaquant capturant un message ne peut ni lire les précédents ni forger les suivants.',
      algo:  'ML-KEM-768 encapsulate (FIPS 203) + HKDF-SHA256 (RFC 5869)',
    },
  },
  {
    icon: '🧩', type: 'send', delay: 600,
    label: 'Dérivation clé de message',
    detail: 'HKDF(sendingChainKey, "AQ-chain-v1") → messageKey 256 bits + nextChainKey',
    explain: {
      what:  'Dérivation d\'une clé AES-256 unique et jetable pour ce message.',
      how:   'La sendingChainKey est dérivée par HKDF en deux sorties : messageKey (pour AES-GCM) et nextChainKey (qui remplace sendingChainKey pour le prochain message). La chaîne avance sans jamais revenir en arrière.',
      why:   'Chaque message a une clé de chiffrement différente. Même si une messageKey est compromise, les autres messages restent protégés — c\'est le ratchet symétrique.',
      algo:  'HKDF-SHA256 (RFC 5869) — contexte "AQ-chain-v1"',
    },
  },
  {
    icon: '🔒', type: 'send', delay: 900,
    label: 'Chiffrement AES-256-GCM',
    detail: 'aesGcmEncrypt(plaintext, messageKey, nonce) → ciphertext',
    explain: {
      what:  'Chiffrement authentifié du message avec la clé jetable dérivée du ratchet.',
      how:   'Un nonce aléatoire 96 bits est généré. AES-256-GCM chiffre le message et produit un ciphertext + tag d\'authentification GCM 128 bits. La messageKey est détruite après usage.',
      why:   'AES-GCM garantit confidentialité et intégrité. Toute modification du ciphertext invalide le tag et est détectée avant de produire un quelconque plaintext.',
      algo:  'AES-256-GCM (NIST SP 800-38D) — nonce 96 bits, tag 128 bits',
    },
  },
  {
    icon: '✍️', type: 'send', delay: 1200,
    label: 'Signature ML-DSA-65',
    detail: 'dsaSign(ciphertext ‖ nonce ‖ kemCiphertext, myDsaPrivKey)',
    explain: {
      what:  'Signature numérique du payload chiffré avec votre clé privée ML-DSA-65 (Dilithium).',
      how:   'La concaténation (ciphertext + nonce + kemCiphertext) est signée avec votre clé DSA long-terme. La signature (~3 309 octets) est stockée avec le message dans Firestore.',
      why:   'Authentifie l\'expéditeur et garantit l\'intégrité. Sans signature, n\'importe qui pourrait injecter un faux message ou modifier le kemCiphertext pour détourner le ratchet.',
      algo:  'ML-DSA-65 (NIST FIPS 204 / Dilithium3) — résistant quantique',
    },
  },
  {
    icon: '📤', type: 'done', delay: 1500,
    label: 'Message envoyé dans Firestore',
    detail: '{ kemCiphertext, senderEphPub, ciphertext, nonce, signature, messageIndex }',
    explain: {
      what:  'Le paquet chiffré, signé et indexé est écrit dans Firestore.',
      how:   'Le document Firestore contient les blobs cryptographiques nécessaires à la réception (kemCiphertext, ciphertext, nonce, signature, senderEphPub). Le plaintext n\'y figure jamais.',
      why:   'Firebase ne voit que des blobs opaques. Même un accès root à Firestore ne permet pas de lire les messages sans les clés privées locales du destinataire.',
      algo:  'Firestore — stockage chiffré au repos (AES-256 Google) + règles de sécurité',
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
      why:   'La vérification de signature requiert la clé publique de l\'expéditeur. Sans elle, impossible d\'authentifier le message.',
      algo:  'key-registry.ts — cache mémoire + Firestore fallback',
    },
  },
  {
    icon: '🔍', type: 'active', delay: 350,
    label: 'Vérification signature ML-DSA-65',
    detail: 'dsaVerify(ciphertext ‖ nonce ‖ kemCiphertext, signature, senderDsaPubKey)',
    explain: {
      what:  'Vérification cryptographique que le message provient bien de l\'expéditeur déclaré et n\'a pas été altéré.',
      how:   'ML-DSA-65 (Dilithium) vérifie que la signature correspond au payload (ciphertext + nonce + kemCiphertext) et à la clé publique DSA. Un seul bit modifié → rejet immédiat.',
      why:   'Garantit authenticité et intégrité avant tout déchiffrement. Un attaquant ne peut ni forger un message ni modifier le kemCiphertext sans que la vérification échoue.',
      algo:  'ML-DSA-65 verify (NIST FIPS 204) — retourne true/false',
    },
  },
  {
    icon: '🔓', type: 'recv', delay: 700,
    label: 'Double Ratchet — avancement KEM',
    detail: 'kemDecapsulate(kemCiphertext, ourPrivKey) → sharedSecret; HKDF(rootKey ‖ sharedSecret) → rootKey + receivingChainKey',
    explain: {
      what:  'Décapsulation du secret éphémère et avancement de la machine Double Ratchet côté récepteur.',
      how:   'Votre clé privée KEM décapsule le kemCiphertext pour obtenir le même sharedSecret que l\'expéditeur. HKDF le combine avec le rootKey courant → nouveau rootKey + receivingChainKey. Même avancement de machine qu\'à l\'envoi.',
      why:   'Le ratchet avance de façon symétrique des deux côtés sans jamais transmettre la clé. Chaque message = nouvelle machine, même propriété de forward secrecy.',
      algo:  'ML-KEM-768 decapsulate (FIPS 203) + HKDF-SHA256 (RFC 5869)',
    },
  },
  {
    icon: '🧩', type: 'recv', delay: 1050,
    label: 'Dérivation clé de message',
    detail: 'HKDF(receivingChainKey, "AQ-chain-v1") → messageKey + nextChainKey',
    explain: {
      what:  'Re-dérivation de la clé AES-256 unique de ce message côté récepteur.',
      how:   'Même dérivation HKDF qu\'à l\'envoi depuis la receivingChainKey. Le sharedSecret KEM étant identique des deux côtés, la messageKey obtenue est exactement la même — sans jamais avoir transité sur le réseau.',
      why:   'La clé de déchiffrement n\'est jamais transmise. Elle est reconstruite indépendamment, preuve du fonctionnement du Double Ratchet.',
      algo:  'HKDF-SHA256 (RFC 5869) — contexte "AQ-chain-v1"',
    },
  },
  {
    icon: '✅', type: 'done', delay: 1400,
    label: 'Déchiffrement AES-256-GCM',
    detail: 'aesGcmDecrypt(ciphertext, nonce, messageKey) → plaintext',
    explain: {
      what:  'Déchiffrement authentifié et vérification d\'intégrité avec la clé jetable du ratchet.',
      how:   'AES-256-GCM déchiffre le ciphertext avec la messageKey dérivée et le nonce stocké. Le tag GCM 128 bits est vérifié avant tout — toute altération lève une exception sans exposer de données.',
      why:   'GCM garantit un déchiffrement authentifié : impossible d\'obtenir un plaintext corrompu ou forgé sans détection. La messageKey est détruite après usage.',
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

function showCryptoSteps(stepsData: CryptoStepDef[], direction: 'ENVOI' | 'RÉCEPTION' | 'ENVOI FICHIER'): void {
  const container = document.getElementById('crypto-steps');
  if (!container) return;

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
          if (isOpen && _cryptoClearTimer) {
            clearTimeout(_cryptoClearTimer);
            _cryptoClearTimer = null;
          }
          container.scrollTop = container.scrollHeight;
        });
      }

      container.appendChild(el);
      stepEls[i] = row;
      container.scrollTop = container.scrollHeight;
    }, step.delay);
    _cryptoStepTimers.push(t);
  });

  const lastDelay = stepsData[stepsData.length - 1].delay;
  setTimeout(() => setCryptoStatus('idle'), lastDelay + 600);

  _cryptoClearTimer = setTimeout(() => {
    if (container.querySelector('.crypto-step-wrap.open')) return;
    clearCryptoBox();
  }, lastDelay + 10_000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu de la liste des conversations
// ─────────────────────────────────────────────────────────────────────────────

function renderConversationList(convs: Conversation[]): void {
  const list = document.getElementById('contacts-list');
  if (!list) return;

  if (convs.length === 0) {
    list.innerHTML =
      '<div class="contacts-section-label">Conversations</div>' +
      '<div class="contacts-empty">Aucune conversation.<br/>Appuyez sur <strong>+</strong> pour commencer.</div>';
    return;
  }

  if (!list.querySelector('.contacts-section-label')) {
    const lbl = document.createElement('div');
    lbl.className   = 'contacts-section-label';
    lbl.textContent = 'Conversations';
    list.prepend(lbl);
  }

  const existingItems = new Map<string, HTMLElement>();
  list.querySelectorAll<HTMLElement>('.contact-item').forEach(el => {
    if (el.dataset.convId) existingItems.set(el.dataset.convId, el);
  });

  const newConvIds = new Set(convs.map(c => c.id));
  existingItems.forEach((el, convId) => {
    if (!newConvIds.has(convId)) el.remove();
  });

  const label = list.querySelector('.contacts-section-label')!;
  let insertAfter: Element = label;

  for (const conv of convs) {
    const contactUid  = conv.participants.find(p => p !== _myUid) ?? conv.participants[0];
    const displayName = getLocalConvName(conv.id) ?? contactUid.slice(0, 20);
    const preview     = conv.lastMessagePreview ?? '🔒 Chiffré';
    const timeStr     = conv.lastMessageAt
      ? new Date(conv.lastMessageAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : '';

    let item = existingItems.get(conv.id);

    if (!item) {
      item = document.createElement('div');
      item.className           = 'contact-item';
      item.dataset.convId      = conv.id;
      item.dataset.contactUid  = contactUid;

      const avatarEl  = document.createElement('div');
      avatarEl.className   = 'contact-avatar';
      avatarEl.textContent = displayName.slice(0, 2).toUpperCase();

      const bodyEl    = document.createElement('div');
      bodyEl.className = 'contact-body';

      const rowEl     = document.createElement('div');
      rowEl.className = 'contact-row';

      const nameEl    = document.createElement('span');
      nameEl.className   = 'contact-name';
      nameEl.textContent = displayName;

      const timeEl    = document.createElement('span');
      timeEl.className   = 'contact-time';
      timeEl.textContent = timeStr;

      const previewEl = document.createElement('div');
      previewEl.className   = 'contact-preview';
      previewEl.textContent = preview;

      rowEl.append(nameEl, timeEl);
      bodyEl.append(rowEl, previewEl);
      item.append(avatarEl, bodyEl);

      item.addEventListener('click', () => openConversation(conv.id, contactUid));
      existingItems.set(conv.id, item);
    } else {
      const nameEl    = item.querySelector<HTMLElement>('.contact-name');
      const timeEl    = item.querySelector<HTMLElement>('.contact-time');
      const previewEl = item.querySelector<HTMLElement>('.contact-preview');
      const avatarEl  = item.querySelector<HTMLElement>('.contact-avatar');

      if (nameEl    && nameEl.textContent    !== displayName)  nameEl.textContent    = displayName;
      if (timeEl    && timeEl.textContent    !== timeStr)      timeEl.textContent    = timeStr;
      if (previewEl && previewEl.textContent !== preview)      previewEl.textContent = preview;
      if (avatarEl) avatarEl.textContent = displayName.slice(0, 2).toUpperCase();
    }

    item.classList.toggle('active', conv.id === _currentConvId);

    if (insertAfter.nextSibling !== item) {
      insertAfter.insertAdjacentElement('afterend', item);
    }
    insertAfter = item;
  }

  if (_currentConvId) {
    document.getElementById('chat-empty')?.classList.add('hidden');
    document.getElementById('conversation-view')?.classList.remove('hidden');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ouvrir une conversation
// ─────────────────────────────────────────────────────────────────────────────

function openConversation(convId: string, contactUid: string): void {
  if (_unsubMessages) { _unsubMessages(); _unsubMessages = null; }
  if (_unsubTyping)   { _unsubTyping();   _unsubTyping   = null; }
  _typingDebouncer?.destroy();
  _typingDebouncer = null;

  _currentConvId     = convId;
  _currentContactUid = contactUid;

  switchView('chat');

  // Fermer la recherche si on change de conversation
  closeMsgSearch();

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

  const msgContainer = document.getElementById('messages-container');
  if (msgContainer) msgContainer.innerHTML = '';
  _renderedMsgIds = new Set();

  document.querySelectorAll('.contact-item').forEach((el) => {
    el.classList.toggle('active', (el as HTMLElement).dataset.convId === convId);
  });

  _typingDebouncer = createTypingDebouncer(convId, _myUid);
  _unsubTyping     = subscribeToTyping(convId, _myUid, renderTypingIndicator);
  _unsubMessages   = subscribeToMessages(_myUid, convId, renderMessages);
}

// ─────────────────────────────────────────────────────────────────────────────
// Typing indicator
// ─────────────────────────────────────────────────────────────────────────────

function renderTypingIndicator(typingUids: string[]): void {
  const el    = document.getElementById('typing-indicator');
  const label = document.getElementById('typing-label');
  if (!el || !label) return;
  if (typingUids.length === 0) {
    el.classList.remove('visible');
    label.textContent = '';
    return;
  }
  const name = typingUids[0].slice(0, 16);
  label.textContent = typingUids.length === 1
    ? `${name} écrit…`
    : `${typingUids.length} personnes écrivent…`;
  el.classList.add('visible');
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu des messages
// ─────────────────────────────────────────────────────────────────────────────

let _renderedMsgIds = new Set<string>();

function renderMessages(messages: DecryptedMessage[]): void {
  const container = document.getElementById('messages-container');
  if (!container) return;

  // Filtrer les messages cachés localement
  const visible = messages.filter(m => !_hiddenMessages.has(m.id));

  // Mettre à jour le cache global pour la recherche + backup
  if (_currentConvId) _allDecryptedMessages.set(_currentConvId, visible);
  messages = visible;

  const newMessages     = messages.filter(m => !_renderedMsgIds.has(m.id));
  const hasNewFromOther = newMessages.some(m => m.senderUid !== _myUid);

  for (const msg of messages) {
    if (!_renderedMsgIds.has(msg.id)) continue;
    if (msg.senderUid === _myUid) _updateReadReceipt(msg.id, msg.readBy ?? []);
    const bubble = container.querySelector<HTMLElement>(`.message-bubble[data-msg-id="${msg.id}"]`);
    if (bubble) {
      // ── Tombstone : message supprimé après coup ──────────────────────────
      if (msg.isDeleted && !bubble.classList.contains('msg-deleted-bubble')) {
        bubble.classList.add('msg-deleted-bubble');
        const wrap = bubble.querySelector('.message-text-wrap');
        if (wrap) wrap.innerHTML = `<p class="message-text msg-deleted-text"><em>Ce message a été supprimé</em></p>`;
        continue;
      }
      // ── Transition texte-placeholder → bulle image/fichier ──────────────
      // Quand le preload injecte msg.file après le rendu initial (texte placeholder)
      if (msg.file && !bubble.querySelector('.image-bubble, .file-bubble')) {
        const existingWrap = bubble.querySelector('.message-text-wrap');
        if (existingWrap) existingWrap.remove();
        const f       = msg.file;
        const sizeStr = _fmtSize(f.size);
        const isImage = f.type.startsWith('image/');
        if (isImage) {
          const imgWrap = document.createElement('div');
          imgWrap.className = 'image-bubble';
          imgWrap.title     = escapeHtml(f.name);
          const objectUrl = URL.createObjectURL(f.blob);
          const img       = document.createElement('img');
          img.src          = objectUrl;
          img.alt          = f.name;
          img.className    = 'image-bubble-img';
          img.style.cssText = 'max-width:260px;max-height:200px;border-radius:8px;display:block;cursor:pointer;object-fit:cover';
          img.addEventListener('load', () => URL.revokeObjectURL(objectUrl));
          img.addEventListener('error', () => { URL.revokeObjectURL(objectUrl); imgWrap.innerHTML = `<span style="font-size:11px;color:rgba(255,255,255,0.5)">[Image non affichable]</span>`; });
          img.addEventListener('click', () => _openLightbox(f.blob, f.name, f.size));
          const caption = document.createElement('div');
          caption.style.cssText = 'font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px';
          caption.textContent   = `${escapeHtml(f.name)} · ${sizeStr}`;
          imgWrap.appendChild(img);
          imgWrap.appendChild(caption);
          bubble.insertBefore(imgWrap, bubble.querySelector('.message-meta'));
        } else {
          const fileDiv = document.createElement('div');
          fileDiv.className = 'file-bubble';
          fileDiv.title     = `Télécharger ${f.name}`;
          fileDiv.innerHTML = `
            <div class="file-bubble-icon"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="16" height="16"><path d="M4 4h8l4 4v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z"/><path d="M12 4v4h4"/></svg></div>
            <div class="file-bubble-info"><span class="file-bubble-name">${escapeHtml(f.name)}</span><span class="file-bubble-meta">${sizeStr} · ${escapeHtml(f.type.split('/')[1] ?? f.type)}</span></div>
            <div class="file-bubble-dl"><svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.6" width="12" height="12"><path d="M7 2v7M4 7l3 3 3-3"/><path d="M2 12h10"/></svg></div>`;
          fileDiv.addEventListener('click', () => _downloadBlob(f.blob, f.name));
          bubble.insertBefore(fileDiv, bubble.querySelector('.message-meta'));
        }
        continue;
      }
      const textEl = bubble.querySelector<HTMLElement>('.message-text');
      if (textEl) {
        const current = textEl.textContent ?? '';
        const isPlaceholder = current.startsWith('[\uD83D\uDD12');
        if (isPlaceholder && msg.plaintext !== current) {
          textEl.textContent = msg.plaintext;
          // Réappliquer la recherche si active
          if (_msgSearchQuery) {
            textEl.dataset.plaintext = msg.plaintext;
            applyMsgSearch(_msgSearchQuery);
          }
          if (!msg.plaintext.startsWith('[\uD83D\uDD12')) {
            bubble.classList.remove('decryption-pending');
          }
        }
        // ── Mise à jour du label "message modifié" ─────────────────────
        if (msg.isEdited) {
          textEl.textContent = msg.plaintext;
          const wrap = textEl.closest('.message-text-wrap');
          if (wrap && !wrap.querySelector('.msg-edited-label')) {
            wrap.insertAdjacentHTML('beforeend', `<span class="msg-edited-label"><em>message modifié</em></span>`);
          }
        }
      }
    }
  }

  if (_currentConvId) {
    markAllRead(_currentConvId, messages, _myUid).catch(() => {});
  }

  if (newMessages.length === 0) return;

  for (const msg of newMessages) {
    // ── Bulle système (resync ratchet, etc.) ──────────────────────────────
    if (msg.type === 'system') {
      const sysBubble = document.createElement('div');
      sysBubble.className     = 'message-bubble system-msg';
      sysBubble.dataset.msgId = msg.id;
      sysBubble.innerHTML = `<span class="system-msg-text">${escapeHtml(msg.plaintext)}</span>`;
      container.appendChild(sysBubble);
      _renderedMsgIds.add(msg.id);
      continue;
    }

    const isMine = msg.senderUid === _myUid;
    const isRead = isMine && (msg.readBy ?? []).includes(_currentContactUid ?? '');
    const bubble = document.createElement('div');
    bubble.className     = `message-bubble ${isMine ? 'mine' : 'theirs'}`;
    bubble.dataset.msgId = msg.id;

    const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const metaHtml = `
      <div class="message-meta">
        <span class="message-time">${time}</span>
        ${isMine
          ? `<span class="msg-status" data-msg-id="${msg.id}">
               <span class="msg-check${isRead ? ' read' : ''}">✓</span>
               <span class="msg-check${isRead ? ' read' : ''}">✓</span>
             </span>`
          : (msg.verified
              ? '<span class="sig-ok" title="Signature vérifiée">✓</span>'
              : '<span class="sig-pending" title="Non vérifiée">⦿</span>')
        }
      </div>`;

    if (msg.isDeleted) {
      // ── Message supprimé (tombstone) ─────────────────────────────────────
      bubble.classList.add('msg-deleted-bubble');
      bubble.innerHTML = `
        <div class="message-text-wrap">
          <p class="message-text msg-deleted-text"><em>Ce message a été supprimé</em></p>
        </div>`;
    } else if (msg.file) {
      // ── Bulle fichier ou image ─────────────────────────────────────────
      const f       = msg.file;
      const sizeStr = _fmtSize(f.size);
      const isImage = f.type.startsWith('image/');

      if (isImage) {
        // ── Aperçu image inline ──────────────────────────────────────────
        const imgWrap = document.createElement('div');
        imgWrap.className = 'image-bubble';
        imgWrap.title     = escapeHtml(f.name);

        const objectUrl = URL.createObjectURL(f.blob);
        const img       = document.createElement('img');
        img.src          = objectUrl;
        img.alt          = f.name;
        img.className    = 'image-bubble-img';
        img.style.cssText = 'max-width:260px;max-height:200px;border-radius:8px;display:block;cursor:pointer;object-fit:cover';
        img.addEventListener('load', () => URL.revokeObjectURL(objectUrl));
        img.addEventListener('error', () => {
          URL.revokeObjectURL(objectUrl);
          imgWrap.innerHTML = `<span style="font-size:11px;color:rgba(255,255,255,0.5)">[Image non affichable]</span>`;
        });
        img.addEventListener('click', () => _openLightbox(f.blob, f.name, f.size));

        const caption = document.createElement('div');
        caption.style.cssText = 'font-size:10px;color:rgba(255,255,255,0.4);margin-top:4px';
        caption.textContent   = `${escapeHtml(f.name)} · ${sizeStr}`;

        imgWrap.appendChild(img);
        imgWrap.appendChild(caption);
        bubble.appendChild(imgWrap);
      } else {
        // ── Fichier générique ────────────────────────────────────────────
        const fileDiv = document.createElement('div');
        fileDiv.className = 'file-bubble';
        fileDiv.title     = `Télécharger ${f.name}`;
        fileDiv.innerHTML = `
          <div class="file-bubble-icon">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" width="16" height="16">
              <path d="M4 4h8l4 4v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z"/>
              <path d="M12 4v4h4"/>
            </svg>
          </div>
          <div class="file-bubble-info">
            <span class="file-bubble-name">${escapeHtml(f.name)}</span>
            <span class="file-bubble-meta">${sizeStr} · ${escapeHtml(f.type.split('/')[1] ?? f.type)}</span>
          </div>
          <div class="file-bubble-dl">
            <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.6" width="12" height="12">
              <path d="M7 2v7M4 7l3 3 3-3"/><path d="M2 12h10"/>
            </svg>
          </div>`;
        fileDiv.addEventListener('click', () => _downloadBlob(f.blob, f.name));
        bubble.appendChild(fileDiv);
      }
    } else {
      // ── Bulle texte normale (ou modifiée) ───────────────────────────────
      const editedLabel = msg.isEdited
        ? `<span class="msg-edited-label"><em>message modifié</em></span>`
        : '';
      bubble.innerHTML = `
        <div class="message-text-wrap">
          <p class="message-text">${escapeHtml(msg.plaintext)}</p>
          ${editedLabel}
        </div>`;
    }

    bubble.insertAdjacentHTML('beforeend', metaHtml);

    // Clic droit → menu contextuel
    bubble.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      showMessageContextMenu(e, msg.id, isMine, msg);
    });

    container.appendChild(bubble);
    _renderedMsgIds.add(msg.id);
  }

  const isAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
  if (isAtBottom || newMessages.some(m => m.senderUid === _myUid)) {
    container.scrollTop = container.scrollHeight;
  }

  if (_msgSearchQuery) applyMsgSearch(_msgSearchQuery);

  if (hasNewFromOther) {
    setCryptoStatus('active');
    showCryptoSteps(RECV_STEPS, 'RÉCEPTION');
    // Notification push si l'app est en arrière-plan
    _maybePushNotification(newMessages.filter(m => m.senderUid !== _myUid));
  }
}

function _updateReadReceipt(msgId: string, readBy: string[]): void {
  const isRead = readBy.includes(_currentContactUid ?? '');
  document
    .querySelectorAll<HTMLElement>(`[data-msg-id="${msgId}"] .msg-check`)
    .forEach(el => el.classList.toggle('read', isRead));
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi de fichier
// ─────────────────────────────────────────────────────────────────────────────

async function handleSendFile(file: File): Promise<void> {
  if (!_currentConvId || !_currentContactUid) return;
  const contactUid = _currentContactUid;

  const attachBtn = document.getElementById('btn-attach');
  attachBtn?.classList.add('uploading');
  setCryptoStatus('sending');
  showCryptoSteps(SEND_STEPS, 'ENVOI FICHIER');

  try {
    await sendFile(_myUid, contactUid, file);
    showToast(`Fichier chiffré envoyé : ${file.name}`);
  } catch (err) {
    console.error('[AQ] sendFile failed:', err);
    showToast(`Échec envoi : ${err instanceof Error ? err.message : String(err)}`);
    clearCryptoBox();
    setCryptoStatus('idle');
  } finally {
    attachBtn?.classList.remove('uploading');
  }
}

function _downloadBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ── Lightbox image ──────────────────────────────────────────────────────────
let _lightboxBlob: Blob | null = null;
let _lightboxName = '';

function _openLightbox(blob: Blob, name: string, size: number): void {
  _lightboxBlob = blob;
  _lightboxName = name;

  const overlay  = document.getElementById('lightbox-overlay')!;
  const img      = document.getElementById('lightbox-img') as HTMLImageElement;
  const fname    = document.getElementById('lightbox-filename')!;
  const footer   = document.getElementById('lightbox-footer')!;

  const url = URL.createObjectURL(blob);
  img.src = url;
  img.alt = name;
  img.addEventListener('load', () => URL.revokeObjectURL(url), { once: true });

  fname.textContent  = name;
  footer.textContent = _fmtSize(size);

  overlay.classList.add('active');
  overlay.style.display = 'flex';
  document.addEventListener('keydown', _lightboxKeyHandler);
}

function _closeLightbox(): void {
  const overlay = document.getElementById('lightbox-overlay')!;
  const img     = document.getElementById('lightbox-img') as HTMLImageElement;
  overlay.classList.remove('active');
  overlay.style.display = 'none';
  img.src = '';
  _lightboxBlob = null;
  document.removeEventListener('keydown', _lightboxKeyHandler);
}

function _lightboxKeyHandler(e: KeyboardEvent): void {
  if (e.key === 'Escape') _closeLightbox();
}

function initLightbox(): void {
  document.getElementById('lightbox-close')?.addEventListener('click', _closeLightbox);
  document.getElementById('lightbox-download')?.addEventListener('click', () => {
    if (_lightboxBlob) _downloadBlob(_lightboxBlob, _lightboxName);
  });
  // Clic sur le fond (hors container) ferme le lightbox
  document.getElementById('lightbox-overlay')?.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).id === 'lightbox-overlay') _closeLightbox();
  });
}

function _fmtSize(bytes: number): string {
  if (bytes < 1024)        return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Envoi d'un message
// ─────────────────────────────────────────────────────────────────────────────

async function handleSendMessage(): Promise<void> {
  if (_sendInProgress) return;
  if (!_currentConvId || !_currentContactUid) return;

  const input = document.getElementById('message-input') as HTMLTextAreaElement | null;
  if (!input) return;

  const text = input.value.trim();
  if (!text) return;

  const convId     = _currentConvId;
  const contactUid = _currentContactUid;

  _sendInProgress = true;
  const btn = document.getElementById('btn-send') as HTMLButtonElement | null;
  if (btn) btn.disabled = true;

  input.value    = '';
  input.disabled = true;

  _typingDebouncer?.onBlur();

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
    _sendInProgress = false;
    if (btn) btn.disabled = false;
    input.disabled = false;
    input.focus();
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
// Déconnexion
// ─────────────────────────────────────────────────────────────────────────────

async function handleSignOut(): Promise<void> {
  _typingDebouncer?.destroy();
  _typingDebouncer = null;
  _unsubConvs?.();
  _unsubMessages?.();
  _unsubTyping?.();
  _unsubPreview?.();
  _unsubTyping    = null;
  _unsubPreview   = null;
  _currentConvId  = null;
  _localConvs     = [];
  _renderedMsgIds  = new Set();
  _allDecryptedMessages.clear();
  closeMsgSearch();
  await signOut();
}

// ─────────────────────────────────────────────────────────────────────────────
// Recherche dans les messages (client-side, zéro Firestore)
// ─────────────────────────────────────────────────────────────────────────────

/** Ouvre / ferme la barre de recherche dans les messages. */
function toggleMsgSearch(): void {
  const wrap = document.getElementById('msg-search-wrap');
  if (!wrap) return;
  const isOpen = wrap.classList.contains('open');
  if (isOpen) {
    closeMsgSearch();
  } else {
    wrap.classList.add('open');
    wrap.style.display = 'flex';
    document.getElementById('btn-msg-search-toggle')?.classList.add('active');
    setTimeout(() => (document.getElementById('msg-search-input') as HTMLInputElement | null)?.focus(), 60);
  }
}

/** Ferme la barre de recherche et réinitialise l'affichage. */
function closeMsgSearch(): void {
  const wrap  = document.getElementById('msg-search-wrap');
  const input = document.getElementById('msg-search-input') as HTMLInputElement | null;
  if (wrap)  { wrap.classList.remove('open'); }
  if (input) { input.value = ''; }
  const clearBtn = document.getElementById('msg-search-clear');
  if (clearBtn) clearBtn.style.display = 'none';
  document.getElementById('btn-msg-search-toggle')?.classList.remove('active');
  applyMsgSearch('');
}

/**
 * Filtre les bulles dans le DOM selon la requête.
 * - Ajoute la classe .searching sur le container (atténue les non-résultats)
 * - Ajoute la classe .search-match sur les bulles correspondantes
 * - Injecte un <mark class="msg-highlight"> autour de chaque occurrence
 * - Affiche un compteur de résultats dans la barre de recherche
 * - Scrolle jusqu'au premier résultat
 */
function applyMsgSearch(query: string): void {
  _msgSearchQuery = query.trim();
  const container = document.getElementById('messages-container');
  if (!container) return;

  const countEl = document.getElementById('msg-search-count') as HTMLElement | null;

  if (!_msgSearchQuery) {
    container.classList.remove('searching');
    container.querySelectorAll<HTMLElement>('.message-bubble').forEach(bubble => {
      bubble.classList.remove('search-match');
      const textEl = bubble.querySelector<HTMLElement>('.message-text');
      if (textEl && textEl.dataset.plaintext) {
        textEl.textContent = textEl.dataset.plaintext;
      }
    });
    if (countEl) countEl.remove();
    return;
  }

  const q = _msgSearchQuery.toLowerCase();
  let matchCount = 0;
  let firstMatchEl: HTMLElement | null = null;

  container.classList.add('searching');
  container.querySelectorAll<HTMLElement>('.message-bubble').forEach(bubble => {
    const textEl = bubble.querySelector<HTMLElement>('.message-text');
    if (!textEl) return;

    // Conserver le texte brut au premier passage
    if (!textEl.dataset.plaintext) {
      textEl.dataset.plaintext = textEl.textContent ?? '';
    }
    const raw = textEl.dataset.plaintext;

    if (raw.toLowerCase().includes(q)) {
      bubble.classList.add('search-match');
      matchCount++;
      if (!firstMatchEl) firstMatchEl = bubble;

      // Injecter le highlight HTML — escaper le raw pour sécurité
      const escaped = escapeHtml(raw);
      const pattern = new RegExp(escapeRegex(escapeHtml(_msgSearchQuery)), 'gi');
      textEl.innerHTML = escaped.replace(pattern, m => `<mark class="msg-highlight">${m}</mark>`);
    } else {
      bubble.classList.remove('search-match');
      textEl.textContent = raw;
    }
  });

  let counter = document.getElementById('msg-search-count') as HTMLElement | null;
  const wrap  = document.getElementById('msg-search-wrap');
  if (!counter && wrap) {
    counter = document.createElement('span');
    counter.id        = 'msg-search-count';
    counter.className = 'msg-search-count';
    const clearBtn = document.getElementById('msg-search-clear');
    if (clearBtn) wrap.insertBefore(counter, clearBtn);
    else           wrap.appendChild(counter);
  }
  if (counter) {
    counter.textContent = matchCount === 0
      ? '0 résultat'
      : matchCount === 1 ? '1 résultat' : `${matchCount} résultats`;
    counter.style.color = matchCount === 0 ? 'var(--c-red)' : 'var(--c-muted)';
  }

  if (firstMatchEl) {
    (firstMatchEl as HTMLElement).scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

/** Escaper les caractères spéciaux d'une regex. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─────────────────────────────────────────────────────────────────────────────
// Export Backup
// ─────────────────────────────────────────────────────────────────────────────

function openBackupExportModal(): void {
  const modal = document.getElementById('backup-export-modal');
  const input = document.getElementById('backup-export-password') as HTMLInputElement | null;
  const prog  = document.getElementById('backup-progress');
  if (modal) modal.style.display = 'flex';
  if (prog)  prog.style.display  = 'none';
  if (input) { input.value = ''; }
  setTimeout(() => input?.focus(), 60);
}

function closeBackupExportModal(): void {
  const modal = document.getElementById('backup-export-modal');
  if (modal) modal.style.display = 'none';
  const confirm = document.getElementById('backup-export-confirm') as HTMLButtonElement | null;
  if (confirm) { confirm.disabled = false; }
}

async function confirmBackupExport(): Promise<void> {
  const input    = document.getElementById('backup-export-password') as HTMLInputElement | null;
  const password = input?.value.trim();
  if (!password) { showToast('Mot de passe requis.'); input?.focus(); return; }

  const confirmBtn = document.getElementById('backup-export-confirm') as HTMLButtonElement | null;
  const prog       = document.getElementById('backup-progress');
  const fill       = document.getElementById('backup-progress-fill') as HTMLElement | null;
  const label      = document.getElementById('backup-progress-label') as HTMLElement | null;

  if (confirmBtn) confirmBtn.disabled = true;
  if (prog)  prog.style.display  = 'flex';

  const setProgress = (pct: number, text: string) => {
    if (fill)  fill.style.width  = `${pct}%`;
    if (label) label.textContent = text;
  };

  try {
    const convs: BackupConversation[] = [];
    for (const [convId, msgs] of _allDecryptedMessages.entries()) {
      const conv = _localConvs.find(c => c.id === convId);
      convs.push({
        convId,
        localName   : getLocalConvName(convId),
        participants: conv?.participants ?? [],
        // Exclure les messages non déchiffrés (placeholders)
        messages    : msgs.filter(m => !m.plaintext.startsWith('[\uD83D\uDD12')),
      });
    }

    if (convs.length === 0 || convs.every(c => c.messages.length === 0)) {
      showToast("Aucun message déchiffré à exporter. Ouvrez vos conversations d'abord.");
      if (confirmBtn) confirmBtn.disabled = false;
      if (prog) prog.style.display = 'none';
      return;
    }

    const payload: BackupPayload = {
      version      : 1,
      exportedAt   : Date.now(),
      uid          : _myUid,
      conversations: convs,
    };

    const totalMessages = convs.reduce((n, c) => n + c.messages.length, 0);

    await exportBackup(payload, password, (phase) => {
      if (phase === 'deriving')    setProgress(20, 'Dérivation Argon2id… (quelques secondes)');
      if (phase === 'encrypting')  setProgress(70, `Chiffrement AES-256-GCM de ${totalMessages} messages…`);
      if (phase === 'downloading') setProgress(100, 'Téléchargement…');
    });

    closeBackupExportModal();
    showToast(`Sauvegarde exportée — ${totalMessages} messages, ${convs.length} conversation(s).`);
  } catch (err) {
    console.error('[AQ] Backup export failed:', err);
    showToast(`Export échoué : ${err instanceof Error ? err.message : String(err)}`);
    if (confirmBtn) { confirmBtn.disabled = false; }
    setProgress(0, '');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Export clés de session
// ─────────────────────────────────────────────────────────────────────────────

// Stocker le fileJson généré entre step1 et step2
let _sessionExportFileJson: string | null = null;

function openSessionExportModal(): void {
  _sessionExportFileJson = null;
  const modal = document.getElementById('session-export-modal');
  if (modal) modal.style.display = 'flex';
  const step1 = document.getElementById('session-export-step1');
  const step2 = document.getElementById('session-export-step2');
  if (step1) step1.style.display = 'flex';
  if (step2) step2.style.display = 'none';
  const confirmBtn = document.getElementById('session-export-confirm') as HTMLButtonElement | null;
  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.innerHTML = `<svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11" style="margin-right:4px"><path d="M7 2v7M4 7l3 3 3-3"/><path d="M2 11h10"/></svg>Générer &amp; Télécharger`;
    confirmBtn.onclick = null;
  }
  const prog = document.getElementById('session-export-progress');
  if (prog) prog.style.display = 'none';
}

function closeSessionExportModal(): void {
  const modal = document.getElementById('session-export-modal');
  if (modal) modal.style.display = 'none';
  _sessionExportFileJson = null;
}

async function confirmSessionExport(): Promise<void> {
  const confirmBtn = document.getElementById('session-export-confirm') as HTMLButtonElement | null;
  const prog  = document.getElementById('session-export-progress');
  const fill  = document.getElementById('session-export-progress-fill');
  const label = document.getElementById('session-export-progress-label');
  const step1 = document.getElementById('session-export-step1');
  const step2 = document.getElementById('session-export-step2');
  const grid  = document.getElementById('session-mnemonic-grid');

  if (confirmBtn) confirmBtn.disabled = true;
  if (prog) prog.style.display = '';

  const setProgress = (pct: number, text: string): void => {
    if (fill)  fill.style.width  = `${pct}%`;
    if (label) label.textContent = text;
  };

  try {
    const { fileJson, mnemonic } = await exportSessionKeys(_myUid, (phase) => {
      if (phase === 'generating') setProgress(10, 'Génération de la phrase mnémotechnique…');
      if (phase === 'collecting') setProgress(25, 'Collecte des clés et états ratchet…');
      if (phase === 'deriving')   setProgress(50, 'Dérivation Argon2id… (quelques secondes)');
      if (phase === 'encrypting') setProgress(85, 'Chiffrement AES-256-GCM…');
      if (phase === 'done')       setProgress(100, 'Terminé !');
    });

    _sessionExportFileJson = fileJson;

    if (grid) {
      grid.innerHTML = '';
      mnemonic.forEach((word, i) => {
        const cell = document.createElement('div');
        cell.style.cssText = 'background:rgba(107,143,245,0.1);border:1px solid rgba(107,143,245,0.2);border-radius:5px;padding:6px 8px;text-align:center;font-family:monospace;font-size:12px;color:#c4c9e8';
        cell.innerHTML = `<span style="color:#5a6080;font-size:9px;display:block">${i + 1}.</span>${escapeHtml(word)}`;
        grid.appendChild(cell);
      });
    }

    if (step1) step1.style.display = 'none';
    if (prog)  prog.style.display  = 'none';
    if (step2) step2.style.display = 'flex';

    // Le bouton "Confirmer" déclenche maintenant le téléchargement
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.innerHTML = `<svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11" style="margin-right:4px"><path d="M7 2v7M4 7l3 3 3-3"/><path d="M2 11h10"/></svg>Télécharger le fichier`;
      confirmBtn.onclick = () => {
        if (_sessionExportFileJson) downloadSessionFile(_sessionExportFileJson);
        closeSessionExportModal();
        markSessionExported();
        showToast('Clés exportées avec succès. Gardez vos 10 mots en sécurité !');
      };
    }
  } catch (err) {
    console.error('[AQ] Session export failed:', err);
    showToast(`Export échoué : ${err instanceof Error ? err.message : String(err)}`);
    if (confirmBtn) confirmBtn.disabled = false;
    if (prog) prog.style.display = 'none';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Import clés de session
// ─────────────────────────────────────────────────────────────────────────────

function openSessionImportModal(): void {
  const modal = document.getElementById('session-import-modal');
  if (modal) modal.style.display = 'flex';
  const fileInput  = document.getElementById('session-import-file') as HTMLInputElement | null;
  const passInput  = document.getElementById('session-import-password') as HTMLInputElement | null;
  const mnemoInput = document.getElementById('session-import-mnemonic') as HTMLTextAreaElement | null;
  if (fileInput)  fileInput.value  = '';
  if (passInput)  passInput.value  = '';
  if (mnemoInput) mnemoInput.value = '';
  const prog = document.getElementById('session-import-progress');
  if (prog) prog.style.display = 'none';
  const confirmBtn = document.getElementById('session-import-confirm') as HTMLButtonElement | null;
  if (confirmBtn) confirmBtn.disabled = false;
  setTimeout(() => fileInput?.focus(), 60);
}

function closeSessionImportModal(): void {
  const modal = document.getElementById('session-import-modal');
  if (modal) modal.style.display = 'none';
}

async function confirmSessionImport(): Promise<void> {
  const fileInput  = document.getElementById('session-import-file') as HTMLInputElement | null;
  const passInput  = document.getElementById('session-import-password') as HTMLInputElement | null;
  const mnemoInput = document.getElementById('session-import-mnemonic') as HTMLTextAreaElement | null;
  const confirmBtn = document.getElementById('session-import-confirm') as HTMLButtonElement | null;
  const prog  = document.getElementById('session-import-progress');
  const fill  = document.getElementById('session-import-progress-fill');
  const label = document.getElementById('session-import-progress-label');

  const file     = fileInput?.files?.[0];
  const password = passInput?.value ?? '';
  const phrase   = mnemoInput?.value ?? '';

  if (!file)     { showToast('Sélectionnez un fichier .aqsession.'); return; }
  if (!password) { showToast('Entrez votre mot de passe AegisQuantum actuel.'); return; }

  const words = normalizeMnemonic(phrase);
  if (!validateMnemonic(words)) {
    showToast('Phrase invalide — 10 mots de la liste requis, séparés par des espaces.');
    return;
  }

  if (confirmBtn) confirmBtn.disabled = true;
  if (prog) prog.style.display = '';

  const setProgress = (pct: number, text: string): void => {
    if (fill)  fill.style.width  = `${pct}%`;
    if (label) label.textContent = text;
  };

  try {
    const fileContent = await file.text();
    const importedUid = await importSessionKeys(fileContent, words, password, (phase) => {
      if (phase === 'parsing')    setProgress(10, 'Lecture du fichier…');
      if (phase === 'deriving')   setProgress(30, 'Dérivation Argon2id… (quelques secondes)');
      if (phase === 'decrypting') setProgress(65, 'Déchiffrement AES-256-GCM…');
      if (phase === 'restoring')  setProgress(85, 'Restauration des clés et états ratchet…');
      if (phase === 'done')       setProgress(100, 'Terminé !');
    });

    closeSessionImportModal();
    showToast(`Session restaurée (UID: ${importedUid.slice(0, 8)}…). Reconnectez-vous pour appliquer.`);
  } catch (err) {
    console.error('[AQ] Session import failed:', err);
    showToast(`Import échoué : ${err instanceof Error ? err.message : String(err)}`);
    if (confirmBtn) confirmBtn.disabled = false;
    if (prog) prog.style.display = 'none';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Avertissement fermeture d'onglet
//
// 1. `beforeunload` → dialog natif du navigateur (fermeture effective de l'onglet)
//    NB : les navigateurs modernes ignorent tout texte personnalisé — seul le
//    déclenchement du dialog est contrôlable.
// 2. Ctrl+W / Cmd+W → modal personnalisée ; non-fermable via Enter (seulement clic)
// 3. Bandeau persistant dans l'UI jusqu'à l'export des clés
// ─────────────────────────────────────────────────────────────────────────────

let _closeWarningActive = false;

// Flag in-memory (remis à zéro à chaque connexion) — évite les clés localStorage
// périmées qui masqueraient le bandeau même si l'utilisateur n'a pas exporté.
let _exportedThisSession = false;

function isSessionExported(): boolean {
  return _exportedThisSession;
}

function markSessionExported(): void {
  _exportedThisSession = true;
  const banner = document.getElementById('export-warning-banner');
  if (banner) banner.style.display = 'none';
}

function initExportWarningBanner(): void {
  if (isSessionExported()) return;
  const banner = document.getElementById('export-warning-banner');
  if (!banner) {
    console.warn('[AQ] export-warning-banner introuvable dans le DOM');
    return;
  }
  banner.style.display = 'flex';
  banner.addEventListener('click', () => openSessionExportModal());
}

function initCloseWarning(): void {
  // beforeunload — déclenché seulement si les clés ne sont pas encore exportées
  const onBeforeUnload = (e: BeforeUnloadEvent) => {
    if (isSessionExported()) return; // clés sauvegardées → pas d'avertissement
    e.preventDefault();
    e.returnValue = '';
  };
  window.addEventListener('beforeunload', onBeforeUnload);

  // Ctrl+W / Cmd+W — intercepte avant que le navigateur ferme l'onglet
  window.addEventListener('keydown', (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'w') {
      if (isSessionExported()) return; // clés sauvegardées → laisser fermer normalement
      e.preventDefault();
      showCloseWarningModal();
    }
  });

  // Boutons du modal
  document.getElementById('btn-close-cancel')?.addEventListener('click', hideCloseWarningModal);
  document.getElementById('modal-close-warning')?.addEventListener('click', (e) => {
    if ((e.target as HTMLElement).id === 'modal-close-warning') hideCloseWarningModal();
  });

  const btnCloseAnyway = document.getElementById('btn-close-anyway');
  if (btnCloseAnyway) {
    // Bloquer la fermeture via Enter — uniquement clic souris
    btnCloseAnyway.addEventListener('keydown', (e) => e.preventDefault());
    btnCloseAnyway.addEventListener('click', () => {
      window.removeEventListener('beforeunload', onBeforeUnload);
      hideCloseWarningModal();
      window.close();
    });
  }
}

function showCloseWarningModal(): void {
  if (_closeWarningActive) return;
  _closeWarningActive = true;
  const modal = document.getElementById('modal-close-warning');
  if (modal) modal.style.display = 'flex';
  // Focus sur "Rester" — pas sur "Fermer quand même" — pour éviter Enter accidentel
  setTimeout(() => document.getElementById('btn-close-cancel')?.focus(), 60);
}

function hideCloseWarningModal(): void {
  _closeWarningActive = false;
  const modal = document.getElementById('modal-close-warning');
  if (modal) modal.style.display = 'none';
}

// ─────────────────────────────────────────────────────────────────────────────
// Notifications push — affichées uniquement quand l'app est en arrière-plan
//
// Pas de notification si :
//  - La page est visible (document.visibilityState === 'visible')
//  - L'API Notification n'est pas disponible
//  - La permission a été refusée
// ─────────────────────────────────────────────────────────────────────────────

let _notificationPermission: NotificationPermission = 'default';

function initPushNotifications(): void {
  if (!('Notification' in window)) return;

  // Lire la permission actuelle (sans demander — certains navigateurs
  // bloquent requestPermission() sans geste utilisateur)
  _notificationPermission = Notification.permission;

  if (_notificationPermission === 'default') {
    // Demander dès que l'utilisateur interagit avec la page (premier clic)
    const askOnce = (): void => {
      Notification.requestPermission()
        .then(perm => { _notificationPermission = perm; })
        .catch(() => { /* bloqué */ });
      document.removeEventListener('click', askOnce);
    };
    document.addEventListener('click', askOnce, { once: true });
  }
}

function _maybePushNotification(newFromOther: import('../types/message').DecryptedMessage[]): void {
  if (!('Notification' in window)) return;
  if (_notificationPermission !== 'granted') return;
  if (newFromOther.length === 0) return;
  // Pas de notif si la conversation est déjà ouverte ET l'onglet a le focus
  if (document.visibilityState === 'visible' && document.hasFocus()) return;

  // Regrouper toutes les nouvelles bulles en une seule notification
  const msg = newFromOther[newFromOther.length - 1];
  const senderLabel = msg.senderUid.slice(0, 8) + '…';
  const preview = msg.file
    ? `📎 ${msg.file.name}`
    : msg.plaintext.startsWith('[\uD83D\uDD12')
      ? '🔒 Message chiffré'
      : msg.plaintext.slice(0, 60) + (msg.plaintext.length > 60 ? '…' : '');

  try {
    const n = new Notification(`AegisQuantum — ${senderLabel}`, {
      body: preview,
      icon: '/BIGLOGO.png',
      tag : 'aq-msg',          // remplace la notif précédente (anti-spam)
      silent: false,
    });
    // Clic sur la notification → focus l'onglet
    n.onclick = () => { window.focus(); n.close(); };
  } catch {
    /* ServiceWorker manquant ou contexte non-sécurisé */
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppression de compte
// ─────────────────────────────────────────────────────────────────────────────

function openDeleteAccountModal(): void {
  const modal = document.getElementById('modal-delete-account');
  const input = document.getElementById('modal-delete-account-confirm-input') as HTMLInputElement | null;
  const btn   = document.getElementById('modal-delete-account-confirm') as HTMLButtonElement | null;
  if (input) input.value = '';
  if (btn)   btn.disabled = true;
  if (modal) modal.style.display = 'flex';
  setTimeout(() => input?.focus(), 60);
}

function closeDeleteAccountModal(): void {
  const modal = document.getElementById('modal-delete-account');
  if (modal) modal.style.display = 'none';
}

async function confirmDeleteAccount(): Promise<void> {
  const btn = document.getElementById('modal-delete-account-confirm') as HTMLButtonElement | null;
  if (btn) { btn.disabled = true; btn.textContent = 'Suppression…'; }

  try {
    await deleteAccount(_myUid);
    // La suppression Firebase Auth déclenche onAuthStateChanged → retour login
  } catch (err) {
    console.error('[AQ] Delete account failed:', err);
    showToast('Erreur : ' + (err instanceof Error ? err.message : String(err)));
    if (btn) { btn.disabled = false; btn.textContent = 'Supprimer définitivement'; }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Menu contextuel — messages
// ─────────────────────────────────────────────────────────────────────────────

function initMessageContextMenu(): void {
  const menu = document.getElementById('msg-context-menu');
  if (!menu) return;

  document.addEventListener('click', () => hideContextMenu());
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideContextMenu(); });

  document.getElementById('ctx-delete-for-me')?.addEventListener('click', async () => {
    if (!_ctxMsgId) return;
    hideContextMenu();
    await deleteMessageForMe(_myUid, _ctxMsgId);
    _hiddenMessages.add(_ctxMsgId);
    removeBubbleFromDom(_ctxMsgId);
    _ctxMsgId = null;
  });

  document.getElementById('ctx-delete-for-both')?.addEventListener('click', async () => {
    if (!_ctxMsgId || !_ctxConvId) return;
    hideContextMenu();
    const msgId            = _ctxMsgId;
    const convId           = _ctxConvId;
    const kemCiphertext    = _ctxKemCiphertext;
    const initKemCiphertext = _ctxInitKemCiphertext;
    const messageIndex     = _ctxMessageIndex;
    _ctxMsgId = null;
    try {
      await deleteMessageForBoth(convId, msgId, kemCiphertext, initKemCiphertext, messageIndex);
      // Ne pas retirer du DOM — subscribeToMessages va pousser le tombstone
    } catch (err) {
      showToast('Suppression échouée : ' + (err instanceof Error ? err.message : String(err)));
    }
  });

  document.getElementById('ctx-edit-message')?.addEventListener('click', () => {
    if (!_ctxMsgId) return;
    hideContextMenu();
    const textarea = document.getElementById('edit-message-input') as HTMLTextAreaElement | null;
    if (textarea) textarea.value = _ctxPlaintext;
    const modal = document.getElementById('modal-edit-message');
    if (modal) modal.style.display = 'flex';
    setTimeout(() => textarea?.focus(), 60);
  });

  document.getElementById('btn-edit-cancel')?.addEventListener('click', () => {
    const modal = document.getElementById('modal-edit-message');
    if (modal) modal.style.display = 'none';
  });

  document.getElementById('btn-edit-confirm')?.addEventListener('click', async () => {
    const textarea = document.getElementById('edit-message-input') as HTMLTextAreaElement | null;
    const newText  = textarea?.value.trim() ?? '';
    if (!newText || !_ctxMsgId || !_ctxConvId) return;
    const modal = document.getElementById('modal-edit-message');
    if (modal) modal.style.display = 'none';
    const msgId            = _ctxMsgId;
    const convId           = _ctxConvId;
    const kemCiphertext    = _ctxKemCiphertext;
    const initKemCiphertext = _ctxInitKemCiphertext;
    const messageIndex     = _ctxMessageIndex;
    _ctxMsgId = null;
    try {
      await editMessage(convId, msgId, newText, kemCiphertext, initKemCiphertext, messageIndex);
    } catch (err) {
      showToast('Modification échouée : ' + (err instanceof Error ? err.message : String(err)));
    }
  });
}

function showMessageContextMenu(e: MouseEvent, msgId: string, isMine: boolean, msg: DecryptedMessage): void {
  const menu    = document.getElementById('msg-context-menu');
  const btnBoth = document.getElementById('ctx-delete-for-both') as HTMLElement | null;
  const btnEdit = document.getElementById('ctx-edit-message')    as HTMLElement | null;
  if (!menu) return;

  _ctxMsgId              = msgId;
  _ctxConvId             = _currentConvId;
  _ctxIsMine             = isMine;
  _ctxKemCiphertext      = msg.kemCiphertext      ?? "";
  _ctxInitKemCiphertext  = msg.initKemCiphertext;
  _ctxMessageIndex       = msg.messageIndex       ?? 0;
  _ctxPlaintext          = msg.plaintext;

  const showOwnerActions = isMine && !msg.isDeleted;
  if (btnBoth) btnBoth.style.display = showOwnerActions ? '' : 'none';
  if (btnEdit) btnEdit.style.display = showOwnerActions ? '' : 'none';

  const x = Math.min(e.clientX, window.innerWidth  - 190);
  const y = Math.min(e.clientY, window.innerHeight - 80);
  menu.style.left    = `${x}px`;
  menu.style.top     = `${y}px`;
  menu.style.display = '';
}

function hideContextMenu(): void {
  const menu = document.getElementById('msg-context-menu');
  if (menu) menu.style.display = 'none';
}

function removeBubbleFromDom(msgId: string): void {
  const bubble = document.querySelector<HTMLElement>(`.message-bubble[data-msg-id="${msgId}"]`);
  bubble?.remove();
  _renderedMsgIds.delete(msgId);
  if (_currentConvId) {
    const msgs = _allDecryptedMessages.get(_currentConvId) ?? [];
    _allDecryptedMessages.set(_currentConvId, msgs.filter(m => m.id !== msgId));
  }
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
