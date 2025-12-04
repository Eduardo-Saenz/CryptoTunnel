"""ChaCha20 stream cipher implementation."""

from __future__ import annotations

from typing import Iterable


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    constants = b"expand 32-byte k"
    state = [
        int.from_bytes(constants[i : i + 4], "little") for i in range(0, 16, 4)
    ]
    state += [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    state.append(counter)
    state += [int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)]

    working_state = state[:]
    for _ in range(10):
        _quarter_round(working_state, 0, 4, 8, 12)
        _quarter_round(working_state, 1, 5, 9, 13)
        _quarter_round(working_state, 2, 6, 10, 14)
        _quarter_round(working_state, 3, 7, 11, 15)
        _quarter_round(working_state, 0, 5, 10, 15)
        _quarter_round(working_state, 1, 6, 11, 12)
        _quarter_round(working_state, 2, 7, 8, 13)
        _quarter_round(working_state, 3, 4, 9, 14)

    output = [
        (working_state[i] + state[i]) & 0xFFFFFFFF for i in range(16)
    ]
    return b"".join(word.to_bytes(4, "little") for word in output)


def chacha20_encrypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """Encrypt or decrypt data with ChaCha20."""
    keystream = bytearray()
    block_counter = counter
    for offset in range(0, len(data), 64):
        keystream.extend(_chacha_block(key, block_counter, nonce))
        block_counter += 1
    return bytes(a ^ b for a, b in zip(data, keystream))
