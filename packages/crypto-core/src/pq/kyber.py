"""
pq/kyber.py — ML-KEM-1024 (FIPS 203 / Kyber-1024)
Recommandé ANSSI, standardisé NIST PQC.

Dépendance : liboqs-python
  pip install liboqs-python
  (nécessite liboqs compilé : https://github.com/open-quantum-safe/liboqs)

Rôle : Key Encapsulation Mechanism (KEM)
  - generate_keypair()  → (public_key, secret_key)
  - encapsulate(pk)     → (ciphertext, shared_secret)
  - decapsulate(ct, sk) → shared_secret
"""

from __future__ import annotations
from dataclasses import dataclass
import oqs  # liboqs-python


ALGORITHM = "Kyber1024"  # ML-KEM-1024, niveau de sécurité NIST 5


@dataclass
class KyberKeyPair:
    public_key: bytes
    secret_key: bytes


@dataclass
class KyberEncapsulation:
    ciphertext: bytes
    shared_secret: bytes


def generate_keypair() -> KyberKeyPair:
    """
    Génère une paire de clés ML-KEM-1024.

    Returns:
        KyberKeyPair(public_key, secret_key)
        - public_key : 1568 bytes  (à transmettre)
        - secret_key : 3168 bytes  (à garder secret)
    """
    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return KyberKeyPair(public_key=public_key, secret_key=secret_key)


def encapsulate(public_key: bytes) -> KyberEncapsulation:
    """
    Encapsule un secret partagé avec la clé publique du destinataire.

    Args:
        public_key: clé publique ML-KEM-1024 du destinataire (1568 bytes)

    Returns:
        KyberEncapsulation(ciphertext, shared_secret)
        - ciphertext     : 1568 bytes  (à envoyer au destinataire)
        - shared_secret  : 32 bytes    (secret partagé côté émetteur)
    """
    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return KyberEncapsulation(ciphertext=ciphertext, shared_secret=shared_secret)


def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Décapsule le secret partagé avec la clé secrète.

    Args:
        ciphertext : reçu de l'émetteur (1568 bytes)
        secret_key : clé secrète ML-KEM-1024 (3168 bytes)

    Returns:
        shared_secret : 32 bytes — doit être identique à celui de l'émetteur
    """
    with oqs.KeyEncapsulation(ALGORITHM, secret_key=secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret