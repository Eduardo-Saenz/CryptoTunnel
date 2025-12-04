"""ChaCha20-Poly1305 AEAD built from local primitives."""

from __future__ import annotations

from .chacha20 import chacha20_encrypt
from .poly1305 import poly1305_mac


def _poly_key(key: bytes, nonce: bytes) -> bytes:
    return chacha20_encrypt(key, nonce, 0, b"\x00" * 64)[:32]


def _encode_length(value: int) -> bytes:
    return value.to_bytes(8, "little")


def chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    poly_key = _poly_key(key, nonce)
    ciphertext = chacha20_encrypt(key, nonce, 1, plaintext)
    mac_data = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    mac_data += ciphertext + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    mac_data += _encode_length(len(aad))
    mac_data += _encode_length(len(ciphertext))
    tag = poly1305_mac(poly_key, mac_data)
    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
) -> bytes:
    poly_key = _poly_key(key, nonce)
    mac_data = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    mac_data += ciphertext + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    mac_data += _encode_length(len(aad))
    mac_data += _encode_length(len(ciphertext))
    expected_tag = poly1305_mac(poly_key, mac_data)
    if not _constant_time_eq(expected_tag, tag):
        raise ValueError("Invalid authentication tag")
    return chacha20_encrypt(key, nonce, 1, ciphertext)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
