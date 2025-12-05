"""Command-line client for file transfer over the secure tunnel."""

from __future__ import annotations

import argparse
import socket

from ..protocol.handshake import HandshakeClient
from ..protocol.serialization import (
    decode_handshake_message,
    encode_handshake_message,
)
from .tunnel import SecureTunnel, SessionKeys


CHUNK_SIZE = 2048


def load_psk(path: str) -> bytes:
    """Read the pre-shared key from disk."""
    with open(path, "rb") as handle:
        return handle.read()


def perform_handshake(sock: socket.socket, psk: bytes) -> SessionKeys:
    """Execute client-side handshake over the given socket."""
    client = HandshakeClient(psk)
    message = encode_handshake_message(client.build_hello())
    sock.sendall(message)
    response = sock.recv(4096)
    server_msg = decode_handshake_message(response)
    keys = client.process_server_hello(server_msg)
    return SessionKeys(
        enc_key=keys.client_enc,
        mac_key=keys.client_mac,
        base_nonce=keys.base_nonce,
    )


def send_file(tunnel: SecureTunnel, path: str) -> None:
    """Read a file and stream its contents through the encrypted tunnel."""
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            tunnel.send_packet(chunk)
    tunnel.send_packet(b"END")


def main() -> None:
    """CLI entry point for the secure tunnel client."""
    parser = argparse.ArgumentParser(description="Secure tunnel client")
    parser.add_argument("--server-host", required=True)
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--psk-file", required=True)
    parser.add_argument("--input-file", required=True)
    args = parser.parse_args()

    psk = load_psk(args.psk_file)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((args.server_host, args.server_port))

    session_keys = perform_handshake(sock, psk)
    tunnel = SecureTunnel(sock, session_keys)
    send_file(tunnel, args.input_file)
    sock.close()


if __name__ == "__main__":
    main()
