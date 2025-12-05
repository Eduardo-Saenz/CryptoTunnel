"""Skeleton for encrypted UDP tunnel using ChaCha20-Poly1305."""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

from ..crypto.chacha20_poly1305 import (
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)


@dataclass
class SessionKeys:
    enc_key: bytes
    mac_key: bytes
    base_nonce: bytes


class SecureTunnel:
    def __init__(self, sock: socket.socket, keys: SessionKeys):
        """Wrap a socket-like object with encryption/authentication."""
        self.sock = sock
        self.keys = keys
        self.send_seq = 0
        self.recv_seq = 0

    def _derive_nonce(self, seq: int) -> bytes:
        """Mix the base nonce with the sequence to obtain a unique nonce."""
        seq_bytes = seq.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.keys.base_nonce, seq_bytes))

    def send_packet(self, payload: bytes, aad: bytes = b"") -> None:
        """Encrypt payload, append tag, and push it through the socket."""
        nonce = self._derive_nonce(self.send_seq)
        ciphertext, tag = chacha20_poly1305_encrypt(
            self.keys.enc_key, nonce, payload, aad
        )
        header = struct.pack("!Q", self.send_seq)
        self.sock.sendall(header + ciphertext + tag)
        self.send_seq += 1

    def receive_packet(self, expected_aad: bytes = b"") -> bytes:
        """Read one encrypted packet and return the verified plaintext."""
        data = self.sock.recv(4096)
        if len(data) < 8 + 16:
            raise ValueError("Packet too small")
        seq = struct.unpack("!Q", data[:8])[0]
        if seq < self.recv_seq:
            raise ValueError("Replay detected")
        nonce = self._derive_nonce(seq)
        ciphertext = data[8:-16]
        tag = data[-16:]
        plaintext = chacha20_poly1305_decrypt(
            self.keys.enc_key, nonce, ciphertext, expected_aad, tag
        )
        self.recv_seq = seq + 1
        return plaintext
