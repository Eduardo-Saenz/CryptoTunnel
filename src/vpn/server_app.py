"""Command-line server for receiving files over the secure tunnel."""

from __future__ import annotations

import argparse
import socket

from ..protocol.handshake import HandshakeServer
from ..protocol.serialization import (
    decode_handshake_message,
    encode_handshake_message,
)
from .tunnel import SecureTunnel, SessionKeys


def load_psk(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def receive_handshake(sock: socket.socket, psk: bytes) -> tuple[SessionKeys, tuple[str, int]]:
    server = HandshakeServer(psk)
    data, addr = sock.recvfrom(4096)
    client_msg = decode_handshake_message(data)
    response, keys = server.process_client_hello(client_msg)
    sock.sendto(encode_handshake_message(response), addr)
    session = SessionKeys(
        enc_key=keys.client_enc,
        mac_key=keys.client_mac,
        base_nonce=keys.base_nonce,
    )
    return session, addr


def receive_file(tunnel: SecureTunnel, output_path: str) -> None:
    with open(output_path, "wb") as handle:
        while True:
            chunk = tunnel.receive_packet()
            if chunk == b"END":
                break
            handle.write(chunk)


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure tunnel server")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--psk-file", required=True)
    parser.add_argument("--output-file", required=True)
    args = parser.parse_args()

    psk = load_psk(args.psk_file)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_host, args.listen_port))

    session_keys, client_addr = receive_handshake(sock, psk)
    sock.connect(client_addr)
    tunnel = SecureTunnel(sock, session_keys)
    receive_file(tunnel, args.output_file)
    sock.close()


if __name__ == "__main__":
    main()
