"""
ratchet/session.py — Gestion de session Double Ratchet

Couche de haut niveau au-dessus de double_ratchet.py.
Encapsule l'état, la sérialisation et les opérations de session.

Usage typique :
  # Alice initie
  session = Session.create_as_sender(shared_secret, bob_bundle)
  encrypted = session.encrypt(b"Hello Bob!")
  serialized = session.serialize()  # → stocker en base

  # Bob répond
  session = Session.create_as_receiver(shared_secret, bob_keys)
  plaintext = session.decrypt(encrypted_msg)
"""

from __future__ import annotations
from dataclasses import dataclass
import base64
import json

from ratchet.double_ratchet import (
    RatchetState,
    EncryptedMessage,
    RatchetHeader,
    initialize_sender,
    initialize_receiver,
    ratchet_encrypt,
    ratchet_decrypt,
)


@dataclass
class RecipientBundle:
    """Clés publiques du destinataire nécessaires pour initier une session."""
    dh_public: bytes      # clé X25519 publique
    kyber_public: bytes   # clé ML-KEM publique


class Session:
    """
    Session Double Ratchet entre deux parties.
    Thread-safe si l'état est rechargé depuis la DB avant chaque opération.
    """

    def __init__(self, state: RatchetState):
        self._state = state

    # ------------------------------------------------------------------ #
    #  Constructeurs                                                       #
    # ------------------------------------------------------------------ #

    @classmethod
    def create_as_sender(
        cls,
        shared_secret: bytes,
        recipient: RecipientBundle,
    ) -> "Session":
        """
        Crée une session côté émetteur (après X3DH).

        Args:
            shared_secret : secret partagé issu de X3DH (32 bytes)
            recipient     : bundle de clés publiques du destinataire
        """
        state = initialize_sender(
            shared_secret=shared_secret,
            recipient_dh_public=recipient.dh_public,
            recipient_kyber_public=recipient.kyber_public,
        )
        return cls(state)

    @classmethod
    def create_as_receiver(
        cls,
        shared_secret: bytes,
        dh_public: bytes,
        dh_private: bytes,
        kyber_public: bytes,
        kyber_secret: bytes,
    ) -> "Session":
        """
        Crée une session côté récepteur (après X3DH).

        Args:
            shared_secret : secret partagé issu de X3DH (32 bytes)
            dh_public     : clé X25519 publique locale (depuis le key bundle)
            dh_private    : clé X25519 privée locale
            kyber_public  : clé ML-KEM publique locale
            kyber_secret  : clé ML-KEM secrète locale
        """
        state = initialize_receiver(
            shared_secret=shared_secret,
            dh_self_public=dh_public,
            dh_self_private=dh_private,
            kyber_self_public=kyber_public,
            kyber_self_secret=kyber_secret,
        )
        return cls(state)

    @classmethod
    def from_json(cls, serialized: str) -> "Session":
        """Restaure une session depuis son état sérialisé (stockage DB)."""
        data = json.loads(serialized)
        state = RatchetState.from_dict(data)
        return cls(state)

    # ------------------------------------------------------------------ #
    #  Opérations de session                                               #
    # ------------------------------------------------------------------ #

    def encrypt(self, plaintext: bytes | str) -> dict:
        """
        Chiffre un message.

        Args:
            plaintext : message à chiffrer (str ou bytes)

        Returns:
            dict sérialisable JSON contenant header + ciphertext
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        encrypted, self._state = ratchet_encrypt(self._state, plaintext)
        return _serialize_message(encrypted)

    def decrypt(self, message: dict) -> bytes:
        """
        Déchiffre un message reçu.

        Args:
            message : dict retourné par encrypt() de l'autre côté

        Returns:
            plaintext en bytes

        Raises:
            InvalidTag si le message est corrompu ou altéré
        """
        encrypted = _deserialize_message(message)
        plaintext, self._state = ratchet_decrypt(self._state, encrypted)
        return plaintext

    def decrypt_text(self, message: dict) -> str:
        """Déchiffre et retourne le message en UTF-8."""
        return self.decrypt(message).decode("utf-8")

    # ------------------------------------------------------------------ #
    #  Sérialisation                                                       #
    # ------------------------------------------------------------------ #

    def serialize(self) -> str:
        """Sérialise l'état de la session en JSON (pour stockage Prisma)."""
        return self._state.to_json()

    def get_state_dict(self) -> dict:
        """Retourne l'état sous forme de dict."""
        return self._state.to_dict()


# ------------------------------------------------------------------ #
#  Helpers de sérialisation des messages                               #
# ------------------------------------------------------------------ #

def _serialize_message(msg: EncryptedMessage) -> dict:
    """Sérialise un EncryptedMessage en dict JSON-compatible."""
    h = msg.header
    return {
        "header": {
            "dh_ratchet_public": base64.b64encode(h.dh_ratchet_public).decode(),
            "kyber_ciphertext": base64.b64encode(h.kyber_ciphertext).decode() if h.kyber_ciphertext else None,
            "message_index": h.message_index,
            "prev_chain_length": h.prev_chain_length,
        },
        "ciphertext": base64.b64encode(msg.ciphertext).decode(),
    }


def _deserialize_message(data: dict) -> EncryptedMessage:
    """Désérialise un dict en EncryptedMessage."""
    h = data["header"]
    header = RatchetHeader(
        dh_ratchet_public=base64.b64decode(h["dh_ratchet_public"]),
        kyber_ciphertext=base64.b64decode(h["kyber_ciphertext"]) if h.get("kyber_ciphertext") else None,
        message_index=h["message_index"],
        prev_chain_length=h["prev_chain_length"],
    )
    return EncryptedMessage(
        header=header,
        ciphertext=base64.b64decode(data["ciphertext"]),
    )