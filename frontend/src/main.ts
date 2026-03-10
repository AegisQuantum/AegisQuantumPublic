/**
 * main.ts — Point d'entrée de l'application AegisQuantum
 *
 * Architecture de navigation :
 *  - login.ts appelle navigateToChat(uid) ou navigateToChangePassword(uid) directement
 *    après un signIn() réussi → les clés sont déjà en mémoire.
 *  - onAuthChange gère UNIQUEMENT la déconnexion automatique (token expiré, signOut).
 *  - Au rechargement de page avec session Firebase persistée → on force le re-login
 *    car les clés privées ne sont plus en mémoire (volatile).
 */

import './utils/logger';
import { onAuthChange }   from './services/auth';
import { initAuth }       from './ui/login';

// Initialiser l'UI auth (login form)
initAuth();

// onAuthChange gère SEULEMENT la déconnexion
// (le login positif est géré directement dans login.ts via navigateToChat)
onAuthChange((user) => {
  if (!user) {
    // Déconnexion (signOut ou token expiré) → retour écran auth
    console.log('[AQ] Session terminée → retour auth');
    const chatScreen = document.getElementById('chat-screen')!;
    const pwScreen   = document.getElementById('change-password-screen')!;
    const authScreen = document.getElementById('auth-screen')!;

    chatScreen.classList.add('hidden');
    chatScreen.classList.remove('active');
    pwScreen.classList.add('hidden');
    pwScreen.classList.remove('active');
    authScreen.classList.remove('hidden');
    authScreen.classList.add('active');
  }
  // Si user != null au chargement (session persistée Firebase) :
  // on NE fait rien — l'écran auth est déjà visible et l'utilisateur
  // doit se reconnecter pour recharger ses clés privées en mémoire.
});
