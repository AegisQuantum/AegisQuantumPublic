"""
ratchet/chain.py — Gestion des chain keys et message keys du Double Ratchet

Le Symmetric-Key Ratchet (SKR) dérive des clés de message séquentielles
depuis une chain key. Chaque message consomme une message key et fait
avancer la chain key — les clés passées sont détruites (Perfect Forward Secrecy).

Structure :
  chain_key[n] → (chain_key[n+1], message_key[n])

La dérivation utilise HKDF avec des contextes distincts pour séparer
next_chain_key et message_key.

Dépendances :
  pip install cryptography
"""

from __future__ import annotations
from dataclasses import dataclass, field
import base64

from hybrid.kdf import hkdf_derive


MESSAGE_KEY_INFO = b"AegisQuantum-v1-msg-key"
CHAIN_KEY_INFO = b"AegisQuantum-v1-chain-key"


@dataclass
class MessageKey:
    """Clé de message dérivée — utilisée une seule fois puis détruite."""
    index: int    # numéro du message dans la chaîne
    key: bytes    # 32 bytes — clé de chiffrement du message


@dataclass
class ChainState:
    """
    État d'une chaîne de clés (sending ou receiving).

    Attributes:
        chain_key    : clé de chaîne courante (32 bytes)
        index        : nombre de messages déjà dérivés
        skipped_keys : clés sautées (messages reçus hors ordre) — index → key
    """
    chain_key: bytes
    index: int = 0
    skipped_keys: dict[int, bytes] = field(default_factory=dict)

    MAX_SKIP = 1000  # limite anti-DoS sur les clés sautées

    def advance(self) -> MessageKey:
        """
        Avance la chaîne : dérive message_key[n] et chain_key[n+1].

        Détruit chain_key[n] après la dérivation (PFS).

        Returns:
            MessageKey pour le message courant (index n)
        """
        # Dériver message_key depuis la chain_key courante
        msg_key_bytes = hkdf_derive(
            self.chain_key,
            length=32,
            info=MESSAGE_KEY_INFO,
        )
        # Dériver la prochaine chain_key
        next_chain_key = hkdf_derive(
            self.chain_key,
            length=32,
            info=CHAIN_KEY_INFO,
        )

        current_index = self.index

        # Écraser la chain_key courante (PFS)
        self.chain_key = next_chain_key
        self.index += 1

        return MessageKey(index=current_index, key=msg_key_bytes)

    def advance_to(self, target_index: int) -> MessageKey:
        """
        Avance jusqu'à target_index, stockant les clés intermédiaires
        (messages reçus hors ordre).

        Args:
            target_index : index du message à déchiffrer

        Returns:
            MessageKey pour target_index

        Raises:
            ValueError si target_index < index courant ou dépasse MAX_SKIP
        """
        if target_index < self.index:
            # Chercher dans les clés sautées
            if target_index in self.skipped_keys:
                key = self.skipped_keys.pop(target_index)
                return MessageKey(index=target_index, key=key)
            raise ValueError(f"Clé d'index {target_index} déjà consommée ou inconnue")

        if target_index - self.index > self.MAX_SKIP:
            raise ValueError(
                f"Trop de messages sautés : {target_index - self.index} > {self.MAX_SKIP}"
            )

        # Avancer en stockant les clés intermédiaires
        while self.index < target_index:
            msg_key = self.advance()
            self.skipped_keys[msg_key.index] = msg_key.key

        # Dériver la clé cible
        return self.advance()

    def to_dict(self) -> dict:
        """Sérialise l'état pour stockage (Prisma / IndexedDB)."""
        return {
            "chain_key": base64.b64encode(self.chain_key).decode(),
            "index": self.index,
            "skipped_keys": {
                str(k): base64.b64encode(v).decode()
                for k, v in self.skipped_keys.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChainState":
        """Restaure l'état depuis le stockage."""
        return cls(
            chain_key=base64.b64decode(data["chain_key"]),
            index=data["index"],
            skipped_keys={
                int(k): base64.b64decode(v)
                for k, v in data.get("skipped_keys", {}).items()
            },
        )