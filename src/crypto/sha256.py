"""Minimal SHA-256 implementation without external dependencies."""

from __future__ import annotations

from typing import Iterable, List


_INITIAL_STATE = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


def _right_rotate(value: int, shift: int) -> int:
    """Return value rotated right by the requested number of bits."""
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def _chunks(data: bytes, size: int) -> Iterable[bytes]:
    """Yield successive blocks of the desired size from data."""
    for idx in range(0, len(data), size):
        yield data[idx : idx + size]


def _pad_message(message: bytes) -> bytes:
    """Apply SHA-256 padding so the message length is congruent to 448 mod 512."""
    length = len(message) * 8
    padded = message + b"\x80"
    while (len(padded) % 64) != 56:
        padded += b"\x00"
    padded += length.to_bytes(8, "big")
    return padded


def _compress(chunk: bytes, state: List[int]) -> None:
    """Process one 512-bit block and update the running hash state."""
    w = [int.from_bytes(chunk[i : i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = (
            _right_rotate(w[i - 15], 7)
            ^ _right_rotate(w[i - 15], 18)
            ^ (w[i - 15] >> 3)
        )
        s1 = (
            _right_rotate(w[i - 2], 17)
            ^ _right_rotate(w[i - 2], 19)
            ^ (w[i - 2] >> 10)
        )
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        s1 = (
            _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
        )
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + s1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
        s0 = (
            _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
        )
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    state[0] = (state[0] + a) & 0xFFFFFFFF
    state[1] = (state[1] + b) & 0xFFFFFFFF
    state[2] = (state[2] + c) & 0xFFFFFFFF
    state[3] = (state[3] + d) & 0xFFFFFFFF
    state[4] = (state[4] + e) & 0xFFFFFFFF
    state[5] = (state[5] + f) & 0xFFFFFFFF
    state[6] = (state[6] + g) & 0xFFFFFFFF
    state[7] = (state[7] + h) & 0xFFFFFFFF


def sha256(data: bytes) -> bytes:
    """Return SHA-256 digest for the given input."""
    state = list(_INITIAL_STATE)
    for chunk in _chunks(_pad_message(data), 64):
        _compress(chunk, state)
    return b"".join(word.to_bytes(4, "big") for word in state)
