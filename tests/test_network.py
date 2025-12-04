import os
import socket
import tempfile
import threading
import unittest

from src.vpn.client_app import perform_handshake, send_file, load_psk
from src.vpn.server_app import receive_file, receive_handshake
from src.vpn.tunnel import SecureTunnel, SessionKeys


class TestUDPTransfer(unittest.TestCase):
    def test_client_server_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            psk_path = os.path.join(tmpdir, "psk.bin")
            input_path = os.path.join(tmpdir, "input.bin")
            output_path = os.path.join(tmpdir, "output.bin")

            with open(psk_path, "wb") as handle:
                handle.write(os.urandom(32))
            with open(input_path, "wb") as handle:
                handle.write(b"A" * 4096 + b"B" * 1024)

            psk = load_psk(psk_path)
            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except PermissionError:
                self.skipTest("Socket operations not permitted in this environment")
            server_sock.bind(("127.0.0.1", 0))
            port = server_sock.getsockname()[1]

            def server_thread():
                session_keys, client_addr = receive_handshake(server_sock, psk)
                server_sock.connect(client_addr)
                tunnel = SecureTunnel(server_sock, session_keys)
                receive_file(tunnel, output_path)
                server_sock.close()

            thread = threading.Thread(target=server_thread, daemon=True)
            thread.start()

            try:
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except PermissionError:
                server_sock.close()
                self.skipTest("Socket operations not permitted in this environment")
            client_sock.connect(("127.0.0.1", port))
            session_keys = perform_handshake(client_sock, psk)
            tunnel = SecureTunnel(client_sock, session_keys)
            send_file(tunnel, input_path)
            client_sock.close()

            thread.join(timeout=2)
            with open(output_path, "rb") as handle:
                received = handle.read()
            with open(input_path, "rb") as handle:
                original = handle.read()
            self.assertEqual(received, original)


if __name__ == "__main__":
    unittest.main()
