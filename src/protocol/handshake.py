"""Authenticated Diffie-Hellman handshake with HKDF-derived keys."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..crypto.hmac_sha256 import hmac_sha256, hkdf_expand, hkdf_extract
from ..crypto.sha256 import sha256
from .diffie_hellman import (
    derive_shared,
    generate_keypair,
    public_from_private,
)


@dataclass
class HandshakeKeys:
    client_enc: bytes
    server_enc: bytes
    client_mac: bytes
    server_mac: bytes
    base_nonce: bytes


class HandshakeParticipant:
    """Shared logic for client and server handshake roles."""

    def __init__(
        self,
        psk: bytes,
        *,
        private_key: int | None = None,
        nonce: bytes | None = None,
    ):
        """Prepare deterministic or random key/nonce pairs for a role."""
        self.psk = psk
        if private_key is None:
            self.priv, self.pub = generate_keypair()
        else:
            self.priv = private_key
            self.pub = public_from_private(private_key)
        self.nonce = nonce if nonce is not None else os.urandom(12)

    def _transcript_hash(self, parts: list[bytes]) -> bytes:
        return sha256(b"".join(parts))

    def _derive_keys(self, shared_secret: bytes, nonces: bytes) -> HandshakeKeys:
        """Expand the Diffie-Hellman secret and nonces into tunnel keys."""
        prk = hkdf_extract(self.psk, shared_secret)
        okm = hkdf_expand(prk, nonces, 128)
        return HandshakeKeys(
            client_enc=okm[0:32],
            server_enc=okm[32:64],
            client_mac=okm[64:96],
            server_mac=okm[96:128],
            base_nonce=sha256(nonces)[:12],
        )


class HandshakeClient(HandshakeParticipant):
    def build_hello(self) -> dict:
        """Return the first handshake message (ClientHello + MAC)."""
        payload = {
            "role": "client",
            "pub": self.pub,
            "nonce": self.nonce,
        }
        mac = hmac_sha256(self.psk, self._serialize(payload))
        return {"payload": payload, "mac": mac}

    def process_server_hello(self, server_msg: dict) -> HandshakeKeys:
        """Validate the server response and derive session keys."""
        payload = server_msg["payload"]
        mac = server_msg["mac"]
        expected = hmac_sha256(self.psk, self._serialize(payload))
        if expected != mac:
            raise ValueError("Server authentication failed")
        shared = derive_shared(payload["pub"], self.priv)
        nonces = self.nonce + payload["nonce"]
        return self._derive_keys(shared, nonces)

    def _serialize(self, payload: dict) -> bytes:
        """Serialize the role/public key/nonce tuple for HMAC coverage."""
        return (
            payload["role"].encode()
            + payload["pub"].to_bytes(256, "big")
            + payload["nonce"]
        )


class HandshakeServer(HandshakeParticipant):
    def process_client_hello(self, client_msg: dict) -> tuple[dict, HandshakeKeys]:
        """Validate ClientHello, derive keys, and craft ServerHello reply."""
        payload = client_msg["payload"]
        mac = client_msg["mac"]
        expected = hmac_sha256(self.psk, self._serialize(payload))
        if expected != mac:
            raise ValueError("Client authentication failed")

        shared = derive_shared(payload["pub"], self.priv)
        nonces = payload["nonce"] + self.nonce
        keys = self._derive_keys(shared, nonces)

        response_payload = {
            "role": "server",
            "pub": self.pub,
            "nonce": self.nonce,
        }
        response_mac = hmac_sha256(self.psk, self._serialize(response_payload))
        return {"payload": response_payload, "mac": response_mac}, keys

    def _serialize(self, payload: dict) -> bytes:
        """Serialize payload to keep MAC inputs consistent."""
        return (
            payload["role"].encode()
            + payload["pub"].to_bytes(256, "big")
            + payload["nonce"]
        )
