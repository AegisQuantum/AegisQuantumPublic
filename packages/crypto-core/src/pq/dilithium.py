"""
pq/dilithium.py — ML-DSA (Dilithium3 / FIPS 204)
Recommandé ANSSI, standardisé NIST PQC.

Dépendance : liboqs-python
  pip install liboqs-python

Rôle : Signatures post-quantiques
  - generate_keypair()         → (public_key, secret_key)
  - sign(message, secret_key)  → signature
  - verify(message, signature, public_key) → bool
"""

from __future__ import annotations
from dataclasses import dataclass
import oqs  # liboqs-python


ALGORITHM = "ML-DSA-65"  # ML-DSA niveau 3 — équilibre sécurité/performance


@dataclass
class DilithiumKeyPair:
    public_key: bytes
    secret_key: bytes


def generate_keypair() -> DilithiumKeyPair:
    """
    Génère une paire de clés ML-DSA (Dilithium3).

    Returns:
        DilithiumKeyPair(public_key, secret_key)
        - public_key : 1952 bytes
        - secret_key : 4000 bytes
    """
    with oqs.Signature(ALGORITHM) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
    return DilithiumKeyPair(public_key=public_key, secret_key=secret_key)


def sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Signe un message avec la clé secrète ML-DSA.

    Args:
        message    : données à signer (bytes quelconques)
        secret_key : clé secrète Dilithium3

    Returns:
        signature : ~3293 bytes
    """
    with oqs.Signature(ALGORITHM, secret_key=secret_key) as sig:
        signature = sig.sign(message)
    return signature


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Vérifie une signature ML-DSA.

    Args:
        message    : données signées originales
        signature  : signature à vérifier
        public_key : clé publique ML-DSA du signataire

    Returns:
        True si la signature est valide, False sinon
    """
    with oqs.Signature(ALGORITHM) as sig:
        return sig.verify(message, signature, public_key)