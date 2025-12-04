import unittest

from src.protocol.handshake import HandshakeClient, HandshakeServer


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.psk = b"unit-test-pre-shared-key"

    def test_successful_handshake_produces_matching_keys(self):
        client = HandshakeClient(
            self.psk, private_key=0x12345, nonce=b"\x01" * 12
        )
        server = HandshakeServer(
            self.psk, private_key=0xabcdef, nonce=b"\x02" * 12
        )

        client_hello = client.build_hello()
        server_hello, server_keys = server.process_client_hello(client_hello)
        client_keys = client.process_server_hello(server_hello)

        self.assertEqual(client_keys.client_enc, server_keys.client_enc)
        self.assertEqual(client_keys.server_enc, server_keys.server_enc)
        self.assertEqual(client_keys.client_mac, server_keys.client_mac)
        self.assertEqual(client_keys.server_mac, server_keys.server_mac)
        self.assertEqual(client_keys.base_nonce, server_keys.base_nonce)

    def test_rejects_invalid_client_mac(self):
        client = HandshakeClient(
            self.psk, private_key=0x1111, nonce=b"\x03" * 12
        )
        server = HandshakeServer(
            self.psk, private_key=0x2222, nonce=b"\x04" * 12
        )

        client_hello = client.build_hello()
        client_hello["mac"] = b"\x00" * len(client_hello["mac"])

        with self.assertRaises(ValueError):
            server.process_client_hello(client_hello)

    def test_rejects_invalid_server_mac(self):
        client = HandshakeClient(
            self.psk, private_key=0x3333, nonce=b"\x05" * 12
        )
        server = HandshakeServer(
            self.psk, private_key=0x4444, nonce=b"\x06" * 12
        )

        client_hello = client.build_hello()
        server_hello, _ = server.process_client_hello(client_hello)
        server_hello["mac"] = b"\xFF" * len(server_hello["mac"])

        with self.assertRaises(ValueError):
            client.process_server_hello(server_hello)


if __name__ == "__main__":
    unittest.main()
