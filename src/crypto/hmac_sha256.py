"""HMAC-SHA256 implementation built on the local SHA-256 primitive."""

from __future__ import annotations

from typing import Optional

from .sha256 import sha256

BLOCK_SIZE = 64


def _normalize_key(key: bytes) -> bytes:
    """Hash/zero-pad key so it fits the HMAC block size."""
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    return key.ljust(BLOCK_SIZE, b"\x00")


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC using the local SHA-256 implementation."""
    normalized = _normalize_key(key)
    o_key_pad = bytes((x ^ 0x5C) for x in normalized)
    i_key_pad = bytes((x ^ 0x36) for x in normalized)
    return sha256(o_key_pad + sha256(i_key_pad + data))


def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    """HKDF-Extract stage (RFC 5869)."""
    if salt is None:
        salt = b"\x00" * BLOCK_SIZE
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand stage (RFC 5869)."""
    blocks = []
    prev = b""
    counter = 1
    while len(b"".join(blocks)) < length:
        prev = hmac_sha256(prk, prev + info + bytes([counter]))
        blocks.append(prev)
        counter += 1
    return b"".join(blocks)[:length]
