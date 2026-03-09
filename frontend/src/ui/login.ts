/**
 * login.ts — UI de connexion AegisQuantum
 *
 * Après un signIn() réussi, gère directement la navigation :
 *  - mustChangePassword → écran changement MDP
 *  - sinon → chat
 *
 * Les clés privées sont déjà en mémoire après signIn() (loadCryptoKeys() appelé dedans).
 */

import { signIn as aqSignIn, mustChangePassword } from '../services/auth';
import { initChat }                               from './chat';
import { initChangePassword }                     from './change-password';

export function initAuth(): void {
  const submitBtn     = document.getElementById('submit-btn')    as HTMLButtonElement;
  const btnLabel      = document.getElementById('btn-label')     as HTMLSpanElement;
  const statusMsg     = document.getElementById('status-msg')    as HTMLDivElement;
  const inputUsername = document.getElementById('input-username') as HTMLInputElement;
  const inputPassword = document.getElementById('input-password') as HTMLInputElement;
  const togglePw      = document.getElementById('toggle-pw')      as HTMLButtonElement;

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
    if (e.key === 'Enter') handleSubmit();
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
        // Afficher l'erreur brute pour debug
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

  inputUsername?.focus();
}
