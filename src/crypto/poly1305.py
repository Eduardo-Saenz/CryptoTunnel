"""Poly1305 one-time authenticator implementation."""

from __future__ import annotations


def _clamp(r: int) -> int:
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    return r


def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = _clamp(int.from_bytes(key[:16], "little"))
    s = int.from_bytes(key[16:], "little")

    accumulator = 0
    p = (1 << 130) - 5

    for offset in range(0, len(msg), 16):
        block = msg[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        accumulator = (accumulator + n) % p
        accumulator = (accumulator * r) % p

    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")
