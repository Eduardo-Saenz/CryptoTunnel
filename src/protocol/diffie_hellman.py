"""Minimal Diffie-Hellman over RFC 3526 group 14 (2048-bit MODP)."""

from __future__ import annotations

import os


_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
""".replace(
    " ", ""
).replace(
    "\n", ""
)

P = int(_P_HEX, 16)
G = 2


def random_exponent() -> int:
    """Return a random private exponent for MODP group 14."""
    return int.from_bytes(os.urandom(32), "big")


def generate_keypair() -> tuple[int, int]:
    """Generate (private, public) Diffie-Hellman key pair."""
    priv = random_exponent()
    pub = pow(G, priv, P)
    return priv, pub


def derive_shared(peer_public: int, private: int) -> bytes:
    """Derive the shared secret resulting from combining both keys."""
    shared = pow(peer_public, private, P)
    return shared.to_bytes(256, "big")


def public_from_private(private: int) -> int:
    """Recompute the public component from a known private exponent."""
    return pow(G, private, P)
