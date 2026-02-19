"""
hybrid/kdf.py — Dérivation de clés via HKDF-SHA256

Utilisé pour :
  - Dériver un secret de session depuis l'échange hybride X25519+Kyber
  - Dériver les clés du Double Ratchet (chain key, message key)
  - Étirer des clés de longueur arbitraire depuis un IKM

Dépendances :
  pip install cryptography
"""

from __future__ import annotations
import os

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def hkdf_derive(
    input_key_material: bytes,
    length: int = 32,
    info: bytes = b"AegisQuantum-v1",
    salt: bytes | None = None,
) -> bytes:
    """
    Dérive une clé via HKDF-SHA256.

    Args:
        input_key_material : secret d'entrée (IKM) — ex: DH secret concatené
        length             : longueur de la clé dérivée en bytes (défaut 32)
        info               : contexte de binding (distinct par usage)
        salt               : sel optionnel (None → sel nul par défaut HKDF)

    Returns:
        Clé dérivée de `length` bytes

    Usage:
        # Dériver une clé de 32 bytes depuis un échange hybride
        key = hkdf_derive(dh_secret + kyber_secret, info=b"session-key")

        # Dériver clé de chiffrement + clé MAC en une fois
        key_material = hkdf_derive(root_key, length=64, info=b"chain-keys")
        enc_key, mac_key = key_material[:32], key_material[32:]
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)


def hkdf_expand(
    pseudo_random_key: bytes,
    length: int = 32,
    info: bytes = b"AegisQuantum-v1",
) -> bytes:
    """
    Expansion HKDF uniquement (sans extract) — utile quand le PRK est déjà disponible.

    Args:
        pseudo_random_key : clé pseudo-aléatoire (PRK) déjà extraite
        length            : longueur souhaitée
        info              : contexte de binding

    Returns:
        Clé expandée de `length` bytes
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    hkdf_exp = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return hkdf_exp.derive(pseudo_random_key)


def derive_message_keys(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Dérive les clés du Double Ratchet depuis une chain key.

    Retourne (next_chain_key, message_key) — deux clés de 32 bytes.
    Utilise des contextes info distincts pour les séparer.

    Args:
        chain_key : clé de chaîne courante (32 bytes)

    Returns:
        (next_chain_key, message_key) — chacune de 32 bytes
    """
    next_chain_key = hkdf_derive(
        chain_key,
        length=32,
        info=b"AegisQuantum-v1-chain-key",
    )
    message_key = hkdf_derive(
        chain_key,
        length=32,
        info=b"AegisQuantum-v1-message-key",
    )
    return next_chain_key, message_key