/**
 * main.ts — Point d'entrée de l'application AegisQuantum
 *
 * Responsabilités :
 *  - Initialiser l'écran d'auth au chargement
 *  - Écouter les changements d'état Firebase Auth
 *  - Basculer entre l'écran d'auth et l'écran de chat
 */

import { onAuthChange } from './services/auth';
import { initAuth }     from './ui/login';
import { initChat }     from './ui/chat';

// ── Initialiser l'UI d'authentification ──────────────────────────────────
initAuth();

// ── Réagir aux changements d'état Auth ───────────────────────────────────
onAuthChange((user) => {
  const authScreen = document.getElementById('auth-screen')!;
  const chatScreen = document.getElementById('chat-screen')!;

  if (user) {
    authScreen.classList.add('hidden');
    authScreen.classList.remove('active');
    chatScreen.classList.remove('hidden');
    chatScreen.classList.add('active');
    initChat(user.uid);
  } else {
    chatScreen.classList.add('hidden');
    chatScreen.classList.remove('active');
    authScreen.classList.remove('hidden');
    authScreen.classList.add('active');
  }
});
