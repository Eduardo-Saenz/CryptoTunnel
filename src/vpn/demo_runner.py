"""Local integration harness for handshake + secure tunnel."""

from __future__ import annotations

import os
import threading

from ..protocol.handshake import HandshakeClient, HandshakeServer
from .tunnel import SecureTunnel, SessionKeys
from .memory_transport import memory_socketpair


def _derive_session_keys(keys, role: str) -> SessionKeys:
    if role == "client":
        return SessionKeys(
            enc_key=keys.client_enc,
            mac_key=keys.client_mac,
            base_nonce=keys.base_nonce,
        )
    return SessionKeys(
        enc_key=keys.server_enc,
        mac_key=keys.server_mac,
        base_nonce=keys.base_nonce,
    )


def _recv_loop(tunnel: SecureTunnel, output: list[bytes], ready: threading.Event):
    try:
        ready.set()
        while True:
            data = tunnel.receive_packet()
            output.append(data)
            if data == b"END":
                break
    except Exception as exc:  # pragma: no cover - diagnostic only
        output.append(f"error:{exc}".encode())


def demo_transfer(psk: bytes) -> list[bytes]:
    sock_a, sock_b = memory_socketpair()

    # Handshake
    client = HandshakeClient(psk)
    server = HandshakeServer(psk)

    client_hello = client.build_hello()
    server_hello, server_keys = server.process_client_hello(client_hello)
    client_keys = client.process_server_hello(server_hello)

    # Derive tunnel keys
    client_session = SessionKeys(
        enc_key=client_keys.client_enc,
        mac_key=client_keys.client_mac,
        base_nonce=client_keys.base_nonce,
    )
    server_session = SessionKeys(
        enc_key=server_keys.client_enc,
        mac_key=server_keys.client_mac,
        base_nonce=server_keys.base_nonce,
    )

    client_tunnel = SecureTunnel(sock_a, client_session)
    server_tunnel = SecureTunnel(sock_b, server_session)

    results: list[bytes] = []
    ready = threading.Event()
    thread = threading.Thread(
        target=_recv_loop, args=(server_tunnel, results, ready), daemon=True
    )
    thread.start()
    ready.wait()

    for chunk in [b"hello", b"world", os.urandom(1024), b"END"]:
        client_tunnel.send_packet(chunk)

    thread.join(timeout=1)
    return results


if __name__ == "__main__":
    outputs = demo_transfer(b"psk-demo")
    for idx, item in enumerate(outputs):
        print(idx, item)
