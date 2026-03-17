/**
 * login.ts — UI de connexion AegisQuantum
 *
 * Après un signIn() réussi, gère directement la navigation :
 *  - mustChangePassword → écran changement MDP
 *  - sinon → chat
 *
 * Les clés privées sont déjà en mémoire après signIn() (loadCryptoKeys() appelé dedans).
 */

import { signIn as aqSignIn, mustChangePassword, VaultMissingError, generateFreshKeys } from '../services/auth';
import { resetMessagingState } from '../services/messaging';
import { importSessionKeys }          from '../services/session-keys';
import { validateMnemonic, normalizeMnemonic } from '../crypto/mnemonic';
import { initChat }                   from './chat';
import { initChangePassword }         from './change-password';

// Stocke temporairement uid + password pour l'écran de récupération vault
let _vrUid      = '';
let _vrPassword = '';

export function initAuth(): void {
  const submitBtn     = document.getElementById('submit-btn')    as HTMLButtonElement;
  const btnLabel      = document.getElementById('btn-label')     as HTMLSpanElement;
  const statusMsg     = document.getElementById('status-msg')    as HTMLDivElement;
  const inputUsername = document.getElementById('input-username') as HTMLInputElement;
  const inputPassword = document.getElementById('input-password') as HTMLInputElement;
  const togglePw      = document.getElementById('toggle-pw')      as HTMLButtonElement;

  // ── Écran de récupération vault ──────────────────────────────────────────
  document.getElementById('vr-import-btn')  ?.addEventListener('click', handleVaultImport);
  document.getElementById('vr-fresh-btn')   ?.addEventListener('click', handleVaultFresh);
  document.getElementById('vr-readonly-btn')?.addEventListener('click', handleVaultReadOnly);

  // ── Toggle masquage phrase mnémotechnique ────────────────────────────────
  let _mnemonicMasked = true;
  document.getElementById('vr-mnemonic-toggle')?.addEventListener('click', () => {
    const ta      = document.getElementById('vr-mnemonic') as HTMLTextAreaElement | null;
    const eyeIcon = document.getElementById('vr-mnemonic-eye');
    if (!ta) return;

    _mnemonicMasked = !_mnemonicMasked;

    if (_mnemonicMasked) {
      ta.style.setProperty('-webkit-text-security', 'disc');
      ta.style.setProperty('text-security',         'disc');
      if (eyeIcon) eyeIcon.innerHTML =
        `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5Z"/>` +
        `<line x1="2" y1="2" x2="14" y2="14"/>`;
    } else {
      ta.style.setProperty('-webkit-text-security', 'none');
      ta.style.setProperty('text-security',         'none');
      if (eyeIcon) eyeIcon.innerHTML =
        `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5Z"/>` +
        `<circle cx="8" cy="8" r="2"/>`;
    }
  });

  // ── Toggle mot de passe ──────────────────────────────────────────────────
  togglePw?.addEventListener('click', () => {
    const isHidden = inputPassword.type === 'password';
    inputPassword.type = isHidden ? 'text' : 'password';
    const icon = document.getElementById('eye-icon');
    if (icon) {
      icon.innerHTML = isHidden
        ? `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5Z"/><line x1="2" y1="2" x2="14" y2="14"/>`
        : `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5Z"/><circle cx="8" cy="8" r="2"/>`;
    }
  });

  // ── Submit ───────────────────────────────────────────────────────────────
  submitBtn.addEventListener('click', handleSubmit);
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    // Ne déclencher le submit que si l'écran d'auth est visible
    const authScreen = document.getElementById('auth-screen');
    if (!authScreen || authScreen.classList.contains('hidden')) return;
    handleSubmit();
  });

  async function handleSubmit(): Promise<void> {
    const username = inputUsername.value.trim();
    const password = inputPassword.value;

    if (!username || !password) {
      setStatus('Please fill in all fields.', 'error');
      return;
    }

    submitBtn.disabled = true;
    if (btnLabel) btnLabel.textContent = 'Signing in…';
    setStatus('Connexion en cours…', 'loading');

    try {
      console.log('[AQ] signIn →', username);

      // signIn → Firebase Auth + loadCryptoKeys (génère ou déchiffre les clés)
      const user = await aqSignIn(username, password);
      console.log('[AQ] signIn OK, uid:', user.uid);

      // Vérifier si première connexion
      const needsPwChange = await mustChangePassword(user.uid);

      const authScreen = document.getElementById('auth-screen')!;
      const chatScreen = document.getElementById('chat-screen')!;
      const pwScreen   = document.getElementById('change-password-screen')!;

      authScreen.classList.add('hidden');
      authScreen.classList.remove('active');

      if (needsPwChange) {
        // Première connexion → écran changement MDP
        console.log('[AQ] Première connexion → changement MDP requis');
        setStatus('', '');
        pwScreen.classList.remove('hidden');
        pwScreen.classList.add('active');
        chatScreen.classList.add('hidden');
        chatScreen.classList.remove('active');
        initChangePassword(user.uid);
      } else {
        // Connexion normale → chat
        console.log('[AQ] Accès au chat');
        setStatus('', '');
        chatScreen.classList.remove('hidden');
        chatScreen.classList.add('active');
        pwScreen.classList.add('hidden');
        pwScreen.classList.remove('active');
        await initChat(user.uid);
      }

    } catch (err: unknown) {
      // ── Vault absent : proposer la récupération ──────────────────────────
      if (err instanceof VaultMissingError) {
        _vrUid      = err.uid;
        _vrPassword = password;  // password issu de la closure handleSubmit
        showVaultRecoveryScreen();
        return;
      }

      console.error('[AQ] Auth error:', err);
      const raw  = err instanceof Error ? err.message : String(err);
      const code = (err as { code?: string }).code ?? '';

      let msg: string;
      if (/invalid-credential|wrong-password|user-not-found|INVALID_LOGIN_CREDENTIALS/i.test(raw + code)) {
        msg = 'Invalid username or password.';
      } else if (/network-request-failed/i.test(raw + code)) {
        msg = 'Network error — check your connection.';
      } else if (/too-many-requests/i.test(raw + code)) {
        msg = 'Too many attempts. Please wait a moment.';
      } else if (/user-disabled/i.test(raw + code)) {
        msg = 'This account has been disabled.';
      } else {
        msg = raw || code || 'Authentication failed.';
      }
      setStatus(msg, 'error');

      // Remettre l'écran auth visible si on l'a caché
      const authScreen = document.getElementById('auth-screen')!;
      if (authScreen.classList.contains('hidden')) {
        authScreen.classList.remove('hidden');
        authScreen.classList.add('active');
      }

    } finally {
      submitBtn.disabled = false;
      if (btnLabel) btnLabel.textContent = 'Sign in';
    }
  }

  function setStatus(msg: string, type: string): void {
    if (!statusMsg) return;
    statusMsg.textContent = msg;
    statusMsg.className   = `status-msg ${type}`;
  }

  // ── Helpers écran de récupération vault ─────────────────────────────────

  function showVaultRecoveryScreen(): void {
    document.getElementById('auth-screen')!.classList.add('hidden');
    document.getElementById('auth-screen')!.classList.remove('active');
    const vr = document.getElementById('vault-recovery-screen')!;
    vr.classList.remove('hidden');
    vr.classList.add('active');
    setVrStatus('', '');
  }

  function setVrStatus(msg: string, type: string): void {
    const el = document.getElementById('vr-status');
    if (!el) return;
    el.textContent = msg;
    el.className   = `status-msg ${type}`;
  }

  async function handleVaultImport(): Promise<void> {
    const fileInput  = document.getElementById('vr-file')     as HTMLInputElement | null;
    const mnemoInput = document.getElementById('vr-mnemonic') as HTMLTextAreaElement | null;
    const importBtn  = document.getElementById('vr-import-btn') as HTMLButtonElement | null;
    const progressEl = document.getElementById('vr-progress');
    const fillEl     = document.getElementById('vr-progress-fill');
    const labelEl    = document.getElementById('vr-progress-label');

    const file = fileInput?.files?.[0];
    if (!file) { setVrStatus('Sélectionnez un fichier .aqsession.', 'error'); return; }

    const words = normalizeMnemonic(mnemoInput?.value ?? '');
    if (!validateMnemonic(words)) {
      setVrStatus(`Phrase invalide — 10 mots de la liste requis (${words.length} mot(s) saisi(s)).`, 'error');
      return;
    }

    if (importBtn) { importBtn.disabled = true; }
    if (progressEl) progressEl.style.display = 'flex';
    setVrStatus('', '');

    const phases: Record<string, { pct: number; label: string }> = {
      parsing   : { pct: 10, label: 'Lecture du fichier…'             },
      deriving  : { pct: 40, label: 'Dérivation de la clé (Argon2id)…' },
      decrypting: { pct: 70, label: 'Déchiffrement des clés…'          },
      restoring : { pct: 90, label: 'Restauration des états ratchet…'  },
      done      : { pct: 100, label: 'Import terminé ✓'                },
    };

    try {
      const fileContent = await file.text();
      await importSessionKeys(fileContent, words, _vrPassword, (phase) => {
        const p = phases[phase];
        if (p) {
          if (fillEl)  fillEl.style.width  = `${p.pct}%`;
          if (labelEl) labelEl.textContent = p.label;
        }
      });

      // Succès — aller au chat
      document.getElementById('vault-recovery-screen')!.classList.add('hidden');
      document.getElementById('vault-recovery-screen')!.classList.remove('active');
      const chatScreen = document.getElementById('chat-screen')!;
      chatScreen.classList.remove('hidden');
      chatScreen.classList.add('active');
      await initChat(_vrUid);

    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setVrStatus(msg, 'error');
      if (importBtn) importBtn.disabled = false;
      if (progressEl) progressEl.style.display = 'none';
    }
  }

  function handleVaultReadOnly(): void {
    // Nettoyer l'état messaging hérité d'une éventuelle session précédente
    // (évite que _retryFailed cache les messages de ce compte)
    resetMessagingState();
    // Accès sans clés : les messages resteront affichés comme [🔒] chiffrés,
    // mais l'utilisateur peut naviguer dans l'app et importer ses clés plus tard
    // via Paramètres → Clés de session.
    document.getElementById('vault-recovery-screen')!.classList.add('hidden');
    document.getElementById('vault-recovery-screen')!.classList.remove('active');
    const chatScreen = document.getElementById('chat-screen')!;
    chatScreen.classList.remove('hidden');
    chatScreen.classList.add('active');
    initChat(_vrUid);
  }

  async function handleVaultFresh(): Promise<void> {
    const confirmed = window.confirm(
      '⚠️ Démarrer de zéro ?\n\n' +
      'Cela régénère vos clés cryptographiques et supprime définitivement ' +
      'l\'accès à toutes vos conversations existantes.\n\n' +
      'Cette action est irréversible.'
    );
    if (!confirmed) return;

    const freshBtn = document.getElementById('vr-fresh-btn') as HTMLButtonElement | null;
    if (freshBtn) { freshBtn.disabled = true; freshBtn.textContent = 'Génération en cours…'; }
    setVrStatus('Génération des nouvelles clés…', 'loading');

    try {
      await generateFreshKeys(_vrUid, _vrPassword);

      document.getElementById('vault-recovery-screen')!.classList.add('hidden');
      document.getElementById('vault-recovery-screen')!.classList.remove('active');
      const chatScreen = document.getElementById('chat-screen')!;
      chatScreen.classList.remove('hidden');
      chatScreen.classList.add('active');
      await initChat(_vrUid);

    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setVrStatus('Erreur : ' + msg, 'error');
      if (freshBtn) { freshBtn.disabled = false; freshBtn.textContent = 'Démarrer de zéro — générer de nouvelles clés'; }
    }
  }

  inputUsername?.focus();
}
