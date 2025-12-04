"""Helper utilities to serialize handshake messages over the network."""

from __future__ import annotations

import json


def encode_handshake_message(msg: dict) -> bytes:
    payload = msg["payload"]
    data = {
        "role": payload["role"],
        "pub": payload["pub"].to_bytes(256, "big").hex(),
        "nonce": payload["nonce"].hex(),
        "mac": msg["mac"].hex(),
    }
    return json.dumps(data).encode("utf-8")


def decode_handshake_message(blob: bytes) -> dict:
    data = json.loads(blob.decode("utf-8"))
    payload = {
        "role": data["role"],
        "pub": int(data["pub"], 16),
        "nonce": bytes.fromhex(data["nonce"]),
    }
    mac = bytes.fromhex(data["mac"])
    return {"payload": payload, "mac": mac}
