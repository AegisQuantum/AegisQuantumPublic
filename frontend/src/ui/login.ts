/**
 * login.ts — UI d'authentification (username + password, sans email)
 */

import { register as aqRegister, signIn as aqSignIn, validateUsername } from '../services/auth';

export function initAuth(): void {
  const tabLogin      = document.getElementById('tab-login')     as HTMLButtonElement;
  const tabRegister   = document.getElementById('tab-register')  as HTMLButtonElement;
  const submitBtn     = document.getElementById('submit-btn')    as HTMLButtonElement;
  const btnLabel      = document.getElementById('btn-label')     as HTMLSpanElement;
  const statusMsg     = document.getElementById('status-msg')    as HTMLDivElement;
  const fieldConfirm  = document.getElementById('field-confirm') as HTMLDivElement;
  const strengthWrap  = document.getElementById('strength-wrap') as HTMLDivElement;
  const strengthFill  = document.getElementById('strength-fill') as HTMLDivElement;
  const strengthLabel = document.getElementById('strength-label')as HTMLSpanElement;
  const inputUsername = document.getElementById('input-username')as HTMLInputElement;
  const inputPassword = document.getElementById('input-password')as HTMLInputElement;
  const inputConfirm  = document.getElementById('input-confirm') as HTMLInputElement;
  const togglePw      = document.getElementById('toggle-pw')     as HTMLButtonElement;
  const fieldHint     = inputUsername.closest('.field')?.querySelector('.field-hint') as HTMLElement;

  let currentTab: 'login' | 'register' = 'login';

  // ── Tab switching ──────────────────────────────────────────────────────
  tabLogin.addEventListener('click',    () => switchTab('login'));
  tabRegister.addEventListener('click', () => switchTab('register'));

  function switchTab(tab: 'login' | 'register'): void {
    currentTab = tab;
    tabLogin.classList.toggle('active',    tab === 'login');
    tabRegister.classList.toggle('active', tab === 'register');
    btnLabel.textContent = tab === 'login' ? 'Sign in' : 'Create account';
    fieldConfirm.classList.toggle('hidden', tab === 'login');
    strengthWrap.classList.toggle('hidden', tab === 'login');
    if (fieldHint) fieldHint.style.display = tab === 'register' ? '' : 'none';
    setStatus('', '');
    inputUsername.focus();
  }

  // Masquer le hint en mode login dès le départ
  if (fieldHint) fieldHint.style.display = 'none';

  // ── Toggle mot de passe ─────────────────────────────────────────────────
  togglePw?.addEventListener('click', () => {
    const isHidden = inputPassword.type === 'password';
    inputPassword.type = isHidden ? 'text' : 'password';
    // Changer l'icône
    const icon = document.getElementById('eye-icon');
    if (icon) {
      icon.innerHTML = isHidden
        ? `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5Z"/><line x1="2" y1="2" x2="14" y2="14"/>`
        : `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5Z"/><circle cx="8" cy="8" r="2"/>`;
    }
  });

  // ── Password strength ──────────────────────────────────────────────────
  inputPassword.addEventListener('input', () => {
    if (currentTab !== 'register') return;
    const val = inputPassword.value;
    let score = 0;
    if (val.length >= 8)            score++;
    if (val.length >= 12)           score++;
    if (/[A-Z]/.test(val))          score++;
    if (/[0-9]/.test(val))          score++;
    if (/[^A-Za-z0-9]/.test(val))   score++;

    const levels = [
      { label: 'Too short',   color: '#ef4444', width: '10%'  },
      { label: 'Weak',        color: '#ef4444', width: '25%'  },
      { label: 'Fair',        color: '#f59e0b', width: '50%'  },
      { label: 'Good',        color: '#3b82f6', width: '75%'  },
      { label: 'Strong',      color: '#22c55e', width: '90%'  },
      { label: 'Very strong', color: '#22c55e', width: '100%' },
    ];
    const lvl = levels[Math.min(score, 5)];
    strengthFill.style.width      = lvl.width;
    strengthFill.style.background = lvl.color;
    strengthLabel.textContent     = lvl.label;
    strengthLabel.style.color     = lvl.color;
  });

  // ── Submit ─────────────────────────────────────────────────────────────
  submitBtn.addEventListener('click', handleSubmit);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSubmit();
  });

  async function handleSubmit(): Promise<void> {
    const username = inputUsername.value.trim();
    const password = inputPassword.value;
    const confirm  = inputConfirm.value;

    if (!username || !password) {
      setStatus('Please fill in all fields.', 'error');
      return;
    }

    if (currentTab === 'register') {
      const usernameError = validateUsername(username);
      if (usernameError) {
        setStatus(usernameError, 'error');
        return;
      }
      if (password !== confirm) {
        setStatus('Passwords do not match.', 'error');
        return;
      }
      if (password.length < 8) {
        setStatus('Password must be at least 8 characters.', 'error');
        return;
      }
    }

    setStatus('', 'loading', true);
    btnLabel.textContent = currentTab === 'login' ? 'Signing in…' : 'Creating account…';

    try {
      if (currentTab === 'login') {
        await aqSignIn(username, password);
      } else {
        await aqRegister(username, password);
      }
      // La navigation est gérée par onAuthChange dans main.ts
    } catch (err: unknown) {
      // Log complet en console pour debugging
      console.error('[AQ] Auth error:', err);

      const raw  = err instanceof Error ? err.message : String(err);
      const code = (err as { code?: string }).code ?? '';

      let msg: string;
      switch (true) {
        case /invalid-credential|wrong-password|user-not-found|INVALID_LOGIN_CREDENTIALS/i.test(raw + code):
          msg = 'Invalid username or password.'; break;
        case /email-already-in-use/i.test(raw + code):
          msg = 'This username is already taken.'; break;
        case /weak-password/i.test(raw + code):
          msg = 'Password is too weak (min. 8 characters).'; break;
        case /network-request-failed/i.test(raw + code):
          msg = 'Network error — check your connection.'; break;
        case /too-many-requests/i.test(raw + code):
          msg = 'Too many attempts. Please wait a moment.'; break;
        case /operation-not-allowed|configuration-not-found/i.test(raw + code):
          msg = 'Sign-in is not enabled on this project. Enable Email/Password in Firebase Console → Authentication → Sign-in method.'; break;
        case /user-disabled/i.test(raw + code):
          msg = 'This account has been disabled.'; break;
        case /invalid-email/i.test(raw + code):
          msg = 'Invalid username format.'; break;
        default:
          // Afficher le code Firebase brut si on ne le reconnaît pas
          msg = code ? `Authentication failed (${code}).` : (raw || 'Authentication failed.');
      }
      setStatus(msg, 'error');
    } finally {
      submitBtn.disabled = false;
      btnLabel.textContent = currentTab === 'login' ? 'Sign in' : 'Create account';
    }
  }

  function setStatus(msg: string, type: string, disableBtn = false): void {
    statusMsg.textContent = msg;
    statusMsg.className   = `status-msg ${type}`;
    submitBtn.disabled    = disableBtn;
  }
}
