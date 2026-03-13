/**
 * fingerprint.ts — Safety Numbers (vérification d'empreinte de clés)
 *
 * Principe :
 *  Chaque conversation possède une empreinte unique dérivée des clés publiques
 *  ML-KEM-768 et ML-DSA-65 des deux participants.
 *
 *  Si Alice et Bob voient la même empreinte en dehors de l'app (appel vocal,
 *  en personne), la conversation n'a pas été interceptée (pas de MITM).
 *
 * Algorithme :
 *  1. Concaténer (triés par UID pour la symétrie) :
 *       kemPub_A ‖ dsaPub_A ‖ kemPub_B ‖ dsaPub_B ‖ uid_A ‖ uid_B
 *  2. SHA-256 → 32 bytes
 *  3. Convertir chaque byte en nombre décimal sur 3 chiffres → 96 chiffres
 *  4. Découper en 12 groupes de 5 chiffres (format humain lisible)
 *
 * Propriétés garanties :
 *  - Déterministe : même entrée → même empreinte
 *  - Symétrique   : Alice et Bob voient le même résultat
 *  - Unique       : change si UNE des quatre clés change
 *  - Opaque       : aucun matériau secret exposé
 *
 * Ce module ne touche pas aux clés privées — uniquement aux clés publiques
 * récupérées depuis Firestore via key-registry.ts.
 */

import { getPublicKeys } from "../services/key-registry";
import { fromBase64 }    from "../crypto/kem";

// ─────────────────────────────────────────────────────────────────────────────
// Calcul de l'empreinte
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Calcule les Safety Numbers d'une paire d'utilisateurs.
 *
 * @param uid1        — UID du premier participant (myUid ou contactUid — l'ordre n'importe pas)
 * @param kemPub1     — Base64 — clé publique ML-KEM-768 du participant 1
 * @param dsaPub1     — Base64 — clé publique ML-DSA-65  du participant 1
 * @param uid2        — UID du second participant
 * @param kemPub2     — Base64 — clé publique ML-KEM-768 du participant 2
 * @param dsaPub2     — Base64 — clé publique ML-DSA-65  du participant 2
 *
 * @returns string — 12 groupes de 5 chiffres séparés par des espaces
 *   ex : "12345 67890 11223 34455 66778 89900 11234 56789 01122 33445 56677 88990"
 */
export async function computeSafetyNumbers(
  uid1    : string,
  kemPub1 : string,
  dsaPub1 : string,
  uid2    : string,
  kemPub2 : string,
  dsaPub2 : string,
): Promise<string> {
  // Trier les participants par UID pour garantir la symétrie :
  // computeSafetyNumbers(A, B) === computeSafetyNumbers(B, A)
  const [first, second] = uid1 < uid2
    ? [{ kemPub: kemPub1, dsaPub: dsaPub1, uid: uid1 }, { kemPub: kemPub2, dsaPub: dsaPub2, uid: uid2 }]
    : [{ kemPub: kemPub2, dsaPub: dsaPub2, uid: uid2 }, { kemPub: kemPub1, dsaPub: dsaPub1, uid: uid1 }];

  // Construire le matériau d'entrée : concaténation des bytes des clés + UIDs
  const uidBytes1  = new TextEncoder().encode(first.uid);
  const uidBytes2  = new TextEncoder().encode(second.uid);
  const kemBytes1  = fromBase64(first.kemPub);
  const dsaBytes1  = fromBase64(first.dsaPub);
  const kemBytes2  = fromBase64(second.kemPub);
  const dsaBytes2  = fromBase64(second.dsaPub);

  // Assemblage dans un seul ArrayBuffer
  const totalLen = kemBytes1.length + dsaBytes1.length + uidBytes1.length
                 + kemBytes2.length + dsaBytes2.length + uidBytes2.length;
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of [kemBytes1, dsaBytes1, uidBytes1, kemBytes2, dsaBytes2, uidBytes2]) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  // SHA-256 → 32 bytes
  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  const hashBytes  = new Uint8Array(hashBuffer);

  // Convertir en 12 groupes de 5 chiffres :
  //   32 bytes → 32 nombres 0-255 → concaténer les représentations 3 chiffres
  //   → 96 chiffres → découper en 12 groupes de 5 (+ garder les 36 premiers = 60 chiffres)
  //
  // On utilise les 20 premiers bytes (160 bits) → 20 × 3 = 60 chiffres → 12 groupes de 5.
  // Les 12 derniers bytes sont ignorés — 160 bits de sécurité suffisent pour un affichage humain.
  const digits = Array.from(hashBytes.slice(0, 20))
    .map(b => b.toString().padStart(3, "0"))
    .join("");                    // 60 chiffres

  // Découper en 12 groupes de 5
  const groups: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    groups.push(digits.slice(i, i + 5));
  }
  return groups.join(" ");
}

/**
 * Charge les clés publiques depuis Firestore et calcule les Safety Numbers.
 * Retourne null si l'un des utilisateurs n'a pas de clés enregistrées.
 *
 * @param myUid      — UID de l'utilisateur courant
 * @param contactUid — UID du contact
 * @returns Safety Numbers string | null en cas d'erreur
 */
export async function loadAndComputeSafetyNumbers(
  myUid      : string,
  contactUid : string,
): Promise<string | null> {
  const [myKeys, contactKeys] = await Promise.all([
    getPublicKeys(myUid),
    getPublicKeys(contactUid),
  ]);

  if (!myKeys || !contactKeys) return null;

  return computeSafetyNumbers(
    myUid,      myKeys.kemPublicKey,     myKeys.dsaPublicKey,
    contactUid, contactKeys.kemPublicKey, contactKeys.dsaPublicKey,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu de la modale
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Injecte les 12 blocs de chiffres dans un conteneur DOM.
 *
 * @param container — élément DOM #fp-own ou #fp-contact
 * @param numbers   — Safety Numbers string (12 groupes de 5 séparés par espaces)
 */
function renderFingerprintBlocks(container: HTMLElement, numbers: string): void {
  container.innerHTML = "";
  const groups = numbers.split(" ");
  for (const group of groups) {
    const block = document.createElement("div");
    block.className   = "fp-block";
    block.textContent = group;
    container.appendChild(block);
  }
}

/**
 * Affiche un état de chargement dans un conteneur de fingerprint.
 */
function renderFingerprintLoading(container: HTMLElement): void {
  container.innerHTML = `<div class="fp-loading">Calcul en cours…</div>`;
}

/**
 * Affiche une erreur dans un conteneur de fingerprint.
 */
function renderFingerprintError(container: HTMLElement, msg: string): void {
  container.innerHTML = `<div class="fp-error">${msg}</div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// API publique — ouvrir / fermer la modale
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Ouvre la modale Safety Numbers pour une conversation.
 *
 * Appelé par chat.ts → bouton #btn-fingerprint.
 *
 * @param myUid      — UID de l'utilisateur courant
 * @param contactUid — UID du contact
 */
export async function openFingerprintModal(
  myUid      : string,
  contactUid : string,
): Promise<void> {
  // Récupérer la modale depuis le DOM (injectée dans public/chat.html)
  const overlay = document.getElementById("fingerprint-modal");
  if (!overlay) {
    console.error("[AQ] fingerprint-modal introuvable dans le DOM");
    return;
  }

  // Afficher la modale
  overlay.style.display = "flex";
  overlay.setAttribute("aria-hidden", "false");

  // Conteneurs des empreintes
  const fpOwn     = document.getElementById("fp-own");
  const fpContact = document.getElementById("fp-contact");
  const fpStatus  = document.getElementById("fp-status");

  if (fpOwn)     renderFingerprintLoading(fpOwn);
  if (fpContact) renderFingerprintLoading(fpContact);

  try {
    // Charger les clés et calculer l'empreinte commune
    const [myKeys, contactKeys] = await Promise.all([
      getPublicKeys(myUid),
      getPublicKeys(contactUid),
    ]);

    if (!myKeys) {
      if (fpOwn)    renderFingerprintError(fpOwn, "Vos clés publiques sont introuvables.");
      if (fpStatus) setFpStatus(fpStatus, "error", "Erreur — clés manquantes");
      return;
    }

    if (!contactKeys) {
      if (fpContact) renderFingerprintError(fpContact, "Clés du contact introuvables.");
      if (fpStatus)  setFpStatus(fpStatus, "error", "Erreur — clés du contact manquantes");
      return;
    }

    // Calculer l'empreinte commune (même résultat pour les deux participants)
    const safetyNumbers = await computeSafetyNumbers(
      myUid,      myKeys.kemPublicKey,      myKeys.dsaPublicKey,
      contactUid, contactKeys.kemPublicKey, contactKeys.dsaPublicKey,
    );

    // Alice et Bob voient la MÊME empreinte — c'est le point clé du protocole.
    // On affiche la même valeur dans les deux sections pour que l'utilisateur
    // comprenne qu'il doit la comparer avec ce que son contact voit chez lui.
    if (fpOwn)     renderFingerprintBlocks(fpOwn,     safetyNumbers);
    if (fpContact) renderFingerprintBlocks(fpContact, safetyNumbers);

    if (fpStatus) {
      setFpStatus(fpStatus, "unverified", "Non vérifié — comparez hors de l'application");
    }

  } catch (err) {
    console.error("[AQ] Erreur calcul Safety Numbers :", err);
    if (fpOwn)     renderFingerprintError(fpOwn,     "Erreur de calcul");
    if (fpContact) renderFingerprintError(fpContact, "Erreur de calcul");
    if (fpStatus)  setFpStatus(fpStatus, "error", "Erreur interne");
  }
}

/**
 * Ferme la modale Safety Numbers.
 */
export function closeFingerprintModal(): void {
  const overlay = document.getElementById("fingerprint-modal");
  if (overlay) {
    overlay.style.display = "none";
    overlay.setAttribute("aria-hidden", "true");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers internes
// ─────────────────────────────────────────────────────────────────────────────

type FpStatusType = "unverified" | "error";

function setFpStatus(el: HTMLElement, type: FpStatusType, message: string): void {
  el.className = `fp-status ${type}`;
  el.innerHTML = `<span class="fp-status-dot"></span>${message}`;
}
