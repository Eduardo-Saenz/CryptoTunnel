import unittest

from src.vpn.demo_runner import demo_transfer


class TestIntegration(unittest.TestCase):
    def test_demo_transfer_roundtrip(self):
        outputs = demo_transfer(b"integration-psk")
        self.assertGreaterEqual(len(outputs), 4)
        self.assertEqual(outputs[0], b"hello")
        self.assertEqual(outputs[1], b"world")
        self.assertEqual(outputs[-1], b"END")
        self.assertEqual(sum(len(x) for x in outputs), len(b"hello") + len(b"world") + 1024 + len(b"END"))


if __name__ == "__main__":
    unittest.main()
