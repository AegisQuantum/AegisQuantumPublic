/**
 * change-password.ts — Écran de changement de mot de passe obligatoire
 * Affiché à la première connexion après provisioning par l'admin.
 */

import { changePassword } from '../services/auth';
import { initChat }       from './chat';

export function initChangePassword(uid: string): void {
  const input   = document.getElementById('cp-input')   as HTMLInputElement;
  const confirm = document.getElementById('cp-confirm') as HTMLInputElement;
  const btn     = document.getElementById('cp-btn')     as HTMLButtonElement;
  const status  = document.getElementById('cp-status')  as HTMLDivElement;

  // Reset des champs
  if (input)   input.value   = '';
  if (confirm) confirm.value = '';
  setStatus('', '');

  // Enlever les anciens listeners en remplaçant le bouton
  const newBtn = btn?.cloneNode(true) as HTMLButtonElement;
  btn?.parentNode?.replaceChild(newBtn, btn);

  newBtn?.addEventListener('click', handleSubmit);

  document.getElementById('cp-form')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSubmit();
  });

  input?.focus();

  async function handleSubmit(): Promise<void> {
    const newPw  = input?.value  ?? '';
    const confPw = confirm?.value ?? '';

    if (newPw.length < 8) {
      setStatus('Le mot de passe doit faire au moins 8 caractères.', 'error');
      return;
    }
    if (newPw !== confPw) {
      setStatus('Les mots de passe ne correspondent pas.', 'error');
      return;
    }

    newBtn.disabled = true;
    setStatus('Changement en cours…', 'loading');

    try {
      await changePassword(uid, newPw);
      setStatus('✓ Mot de passe défini ! Chargement du chat…', 'success');

      await new Promise(r => setTimeout(r, 800));

      const pwScreen   = document.getElementById('change-password-screen')!;
      const chatScreen = document.getElementById('chat-screen')!;

      pwScreen.classList.add('hidden');
      pwScreen.classList.remove('active');
      chatScreen.classList.remove('hidden');
      chatScreen.classList.add('active');

      await initChat(uid);

    } catch (err) {
      console.error('[AQ] changePassword failed:', err);
      const msg = err instanceof Error ? err.message : String(err);
      setStatus(`Erreur : ${msg}`, 'error');
      newBtn.disabled = false;
    }
  }

  function setStatus(msg: string, type: string): void {
    if (!status) return;
    status.textContent = msg;
    status.className   = `status-msg ${type}`;
  }
}
