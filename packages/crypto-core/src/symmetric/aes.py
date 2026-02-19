"""
symmetric/aes.py — Chiffrement symétrique AES-256-GCM

AES-256-GCM est un AEAD (Authenticated Encryption with Associated Data) :
  - Chiffrement 256 bits
  - Authentification intégrée (MAC via GHASH)
  - Données associées (AAD) pour authentifier des métadonnées sans les chiffrer

Usage typique dans AegisQuantum :
  - Chiffrement des messages (alternance avec ChaCha20 selon le profil)
  - Chiffrement du stockage local des clés

Dépendances :
  pip install cryptography
"""

from __future__ import annotations
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32    # 256 bits
NONCE_SIZE = 12  # 96 bits — recommandé pour GCM


@dataclass
class AESCiphertext:
    nonce: bytes       # 12 bytes — unique par chiffrement
    ciphertext: bytes  # données chiffrées + tag d'authentification (16 bytes)

    def to_bytes(self) -> bytes:
        """Sérialise : nonce || ciphertext (pour stockage/transport)."""
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "AESCiphertext":
        """Désérialise depuis nonce || ciphertext."""
        if len(data) < NONCE_SIZE + 16:
            raise ValueError("Données trop courtes pour un AESCiphertext valide")
        return cls(nonce=data[:NONCE_SIZE], ciphertext=data[NONCE_SIZE:])


def generate_key() -> bytes:
    """Génère une clé AES-256 aléatoire (32 bytes)."""
    return os.urandom(KEY_SIZE)


def encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> AESCiphertext:
    """
    Chiffre des données avec AES-256-GCM.

    Args:
        plaintext       : données à chiffrer
        key             : clé AES-256 (32 bytes)
        associated_data : données authentifiées mais non chiffrées (ex: headers)

    Returns:
        AESCiphertext(nonce, ciphertext)

    Raises:
        ValueError si la clé n'est pas de 32 bytes
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Clé AES invalide : attendu {KEY_SIZE} bytes, reçu {len(key)}")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return AESCiphertext(nonce=nonce, ciphertext=ciphertext)


def decrypt(
    aes_ct: AESCiphertext,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """
    Déchiffre et vérifie l'authenticité avec AES-256-GCM.

    Args:
        aes_ct          : AESCiphertext(nonce, ciphertext)
        key             : clé AES-256 (32 bytes)
        associated_data : mêmes données associées qu'au chiffrement

    Returns:
        plaintext décrypté

    Raises:
        cryptography.exceptions.InvalidTag si le message est altéré/corrompu
        ValueError si la clé est invalide
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Clé AES invalide : attendu {KEY_SIZE} bytes, reçu {len(key)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(aes_ct.nonce, aes_ct.ciphertext, associated_data)


def decrypt_bytes(
    data: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Raccourci : déchiffre directement depuis bytes sérialisés (nonce || ciphertext)."""
    return decrypt(AESCiphertext.from_bytes(data), key, associated_data)