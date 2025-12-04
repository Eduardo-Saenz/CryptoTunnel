import unittest

from src.crypto.chacha20 import chacha20_encrypt
from src.crypto.chacha20_poly1305 import (
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)
from src.crypto.hmac_sha256 import hmac_sha256, hkdf_expand, hkdf_extract
from src.crypto.poly1305 import poly1305_mac
from src.crypto.sha256 import sha256


class TestSHA256(unittest.TestCase):
    def test_sha256_vectors(self):
        self.assertEqual(
            sha256(b""),
            bytes.fromhex(
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
        )
        self.assertEqual(
            sha256(b"abc"),
            bytes.fromhex(
                "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad"
            ),
        )


class TestHMACandHKDF(unittest.TestCase):
    def test_hmac_sha256_rfc4231(self):
        key = b"\x0b" * 20
        data = b"Hi There"
        expected = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7"
        )
        self.assertEqual(hmac_sha256(key, data), expected)

    def test_hkdf_rfc5869_case1(self):
        ikm = b"\x0b" * 22
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk_expected = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        okm_expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(prk, prk_expected)
        okm = hkdf_expand(prk, info, 42)
        self.assertEqual(okm, okm_expected)


class TestChaCha20(unittest.TestCase):
    def test_chacha20_block_against_rfc8439(self):
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        keystream = chacha20_encrypt(key, nonce, 1, b"\x00" * 64)
        expected = bytes.fromhex(
            "10f1e7e4d13b5915500fdd1fa32071c4"
            "c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e"
        )
        self.assertEqual(keystream, expected)


class TestPoly1305(unittest.TestCase):
    def test_poly1305_rfc8439(self):
        key = bytes.fromhex(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        )
        msg = b"Cryptographic Forum Research Group"
        expected = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
        self.assertEqual(poly1305_mac(key, msg), expected)


class TestAEADChaCha20Poly1305(unittest.TestCase):
    def test_rfc8439_aead_vector(self):
        key = bytes.fromhex(
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0"
        )
        nonce = bytes.fromhex("000000000102030405060708")
        aad = bytes.fromhex("f33388860000000000004e91")
        plaintext = bytes.fromhex(
            "496e7465726e65742d44726166747320"
            "61726520647261667420646f63756d65"
            "6e74732076616c696420666f72206120"
            "6d6178696d756d206f6620736978206d"
            "6f6e74687320616e64206d6179206265"
            "20757064617465642c207265706c6163"
            "65642c206f72206f62736f6c65746564"
            "206279206f7468657220646f63756d65"
            "6e747320617420616e792074696d652e"
            "20497420697320696e617070726f7072"
            "6961746520746f2075736520496e7465"
            "726e65742d4472616674732061732072"
            "65666572656e6365206d617465726961"
            "6c206f7220746f206369746520746865"
            "6d206f74686572207468616e20617320"
            "2fe2809c776f726b20696e2070726f67"
            "726573732e2fe2809d"
        )
        expected_ciphertext = bytes.fromhex(
            "64a0861575861af460f062c79be643bd"
            "5e805cfd345cf389f108670ac76c8cb2"
            "4c6cfc18755d43eea09ee94e382d26b0"
            "bdb7b73c321b0100d4f03b7f355894cf"
            "332f830e710b97ce98c8a84abd0b9481"
            "14ad176e008d33bd60f982b1ff37c855"
            "9797a06ef4f0ef61c186324e2b350638"
            "3606907b6a7c02b0f9f6157b53c867e4"
            "b9166c767b804d46a59b5216cde7a4e9"
            "9040c5a40433225ee282a1b0a06c523e"
            "af4534d7f83fa1155b0047718cbc546a"
            "0d072b04b3564eea1b422273f548271a"
            "0bb2316053fa76991955ebd63159434e"
            "cebb4e466dae5a1073a6727627097a10"
            "49e617d91d361094fa68f0ff77987130"
            "305beaba2eda04df997b714d6c6f2c29"
            "a6ad5cb4022b02709b"
        )
        expected_tag = bytes.fromhex(
            "eead9d67890cbb22392336fea1851f38"
        )
        ciphertext, tag = chacha20_poly1305_encrypt(
            key, nonce, plaintext, aad
        )
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(tag, expected_tag)
        decrypted = chacha20_poly1305_decrypt(
            key, nonce, ciphertext, aad, tag
        )
        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()
