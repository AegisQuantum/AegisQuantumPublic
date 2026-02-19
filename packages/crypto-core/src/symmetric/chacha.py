"""
symmetric/chacha.py — Chiffrement symétrique ChaCha20-Poly1305

ChaCha20-Poly1305 est un AEAD conçu par Daniel J. Bernstein :
  - Résistant aux attaques par timing (constant-time par design)
  - Préféré à AES sur les appareils sans accélération matérielle AES
  - Utilisé par TLS 1.3, WireGuard, Signal Protocol

Dans AegisQuantum :
  - Utilisé par défaut pour le chiffrement des messages du Double Ratchet
  - Alternative à AES-GCM (les deux sont proposés selon le profil du device)

Dépendances :
  pip install cryptography
"""

from __future__ import annotations
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


KEY_SIZE = 32    # 256 bits
NONCE_SIZE = 12  # 96 bits


@dataclass
class ChaCiphertext:
    nonce: bytes       # 12 bytes — JAMAIS réutilisé avec la même clé
    ciphertext: bytes  # données chiffrées + tag Poly1305 (16 bytes)

    def to_bytes(self) -> bytes:
        """Sérialise : nonce || ciphertext."""
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "ChaCiphertext":
        """Désérialise depuis nonce || ciphertext."""
        if len(data) < NONCE_SIZE + 16:
            raise ValueError("Données trop courtes pour un ChaCiphertext valide")
        return cls(nonce=data[:NONCE_SIZE], ciphertext=data[NONCE_SIZE:])


def generate_key() -> bytes:
    """Génère une clé ChaCha20-Poly1305 aléatoire (32 bytes)."""
    return os.urandom(KEY_SIZE)


def encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> ChaCiphertext:
    """
    Chiffre des données avec ChaCha20-Poly1305.

    Args:
        plaintext       : données à chiffrer
        key             : clé ChaCha20 (32 bytes)
        associated_data : données authentifiées mais non chiffrées

    Returns:
        ChaCiphertext(nonce, ciphertext)

    Raises:
        ValueError si la clé n'est pas de 32 bytes
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Clé invalide : attendu {KEY_SIZE} bytes, reçu {len(key)}")

    nonce = os.urandom(NONCE_SIZE)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, associated_data)

    return ChaCiphertext(nonce=nonce, ciphertext=ciphertext)


def decrypt(
    cha_ct: ChaCiphertext,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """
    Déchiffre et vérifie l'authenticité avec ChaCha20-Poly1305.

    Args:
        cha_ct          : ChaCiphertext(nonce, ciphertext)
        key             : clé ChaCha20 (32 bytes)
        associated_data : mêmes données associées qu'au chiffrement

    Returns:
        plaintext décrypté

    Raises:
        cryptography.exceptions.InvalidTag si le message est altéré
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Clé invalide : attendu {KEY_SIZE} bytes, reçu {len(key)}")

    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(cha_ct.nonce, cha_ct.ciphertext, associated_data)


def decrypt_bytes(
    data: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Raccourci : déchiffre directement depuis bytes sérialisés (nonce || ciphertext)."""
    return decrypt(ChaCiphertext.from_bytes(data), key, associated_data)