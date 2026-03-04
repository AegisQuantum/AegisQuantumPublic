export function initAuth(): void {
  const tabLogin    = document.getElementById('tab-login')    as HTMLButtonElement;
  const tabRegister = document.getElementById('tab-register') as HTMLButtonElement;
  const submitBtn   = document.getElementById('submit-btn')   as HTMLButtonElement;
  const statusMsg   = document.getElementById('status-msg')   as HTMLDivElement;
  const fieldConfirm  = document.getElementById('field-confirm')  as HTMLDivElement;
  const strengthWrap  = document.getElementById('strength-wrap')  as HTMLDivElement;
  const strengthFill  = document.getElementById('strength-fill')  as HTMLDivElement;
  const strengthLabel = document.getElementById('strength-label') as HTMLSpanElement;
  const inputPassword = document.getElementById('input-password') as HTMLInputElement;

  let currentTab: 'login' | 'register' = 'login';

  // ── Tab switching ──
  tabLogin.addEventListener('click', () => switchTab('login'));
  tabRegister.addEventListener('click', () => switchTab('register'));

  function switchTab(tab: 'login' | 'register'): void {
    currentTab = tab;
    tabLogin.classList.toggle('active',    tab === 'login');
    tabRegister.classList.toggle('active', tab === 'register');
    submitBtn.textContent = tab === 'login' ? 'Sign in' : 'Create account';
    fieldConfirm.classList.toggle('hidden', tab === 'login');
    strengthWrap.classList.toggle('hidden', tab === 'login');
    setStatus('', '');
  }

  // ── Password strength ──
  inputPassword.addEventListener('input', () => {
    if (currentTab !== 'register') return;
    const val = inputPassword.value;
    let score = 0;
    if (val.length >= 8)  score++;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    const levels = [
      { label: 'Too short',  color: '#ef4444', width: '10%' },
      { label: 'Weak',       color: '#ef4444', width: '25%' },
      { label: 'Fair',       color: '#f59e0b', width: '50%' },
      { label: 'Good',       color: '#3b82f6', width: '75%' },
      { label: 'Strong',     color: '#22c55e', width: '90%' },
      { label: 'Very strong',color: '#22c55e', width: '100%'},
    ];
    const lvl = levels[Math.min(score, 5)];
    strengthFill.style.width      = lvl.width;
    strengthFill.style.background = lvl.color;
    strengthLabel.textContent     = lvl.label;
    strengthLabel.style.color     = lvl.color;
  });

  // ── Submit ──
  submitBtn.addEventListener('click', () => handleSubmit());

  async function handleSubmit(): Promise<void> {
    const email    = (document.getElementById('input-email')    as HTMLInputElement).value.trim();
    const password = (document.getElementById('input-password') as HTMLInputElement).value;
    const confirm  = (document.getElementById('input-confirm')  as HTMLInputElement).value;

    if (!email || !password) {
      setStatus('Please fill in all fields.', 'error');
      return;
    }

    if (currentTab === 'register' && password !== confirm) {
      setStatus('Passwords do not match.', 'error');
      return;
    }

    if (currentTab === 'register' && password.length < 8) {
      setStatus('Password must be at least 8 characters.', 'error');
      return;
    }

    setStatus('', 'loading', true);

    try {
      if (currentTab === 'login') {
        await signIn(email, password);
      } else {
        await register(email, password);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'An error occurred.';
      setStatus(msg, 'error');
    } finally {
      submitBtn.disabled = false;
    }
  }

  async function signIn(email: string, password: string): Promise<void> {
    // TODO: implémenter avec Firebase Auth + Argon2id
    setStatus('Sign in coming soon…', 'loading');
    console.log('signIn', email, password);
  }

  async function register(email: string, password: string): Promise<void> {
    // TODO: implémenter avec Firebase Auth + Argon2id
    setStatus('Register coming soon…', 'loading');
    console.log('register', email, password);
  }

  function setStatus(msg: string, type: string, disableBtn = false): void {
    statusMsg.textContent  = msg;
    statusMsg.className    = `status-msg ${type}`;
    submitBtn.disabled     = disableBtn;
  }
}
