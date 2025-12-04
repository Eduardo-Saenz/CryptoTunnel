## Secure Encrypted VPN Channel

This repository contains my final project for the university Cryptography class: a fully custom, authenticated VPN-style tunnel that implements every cryptographic primitive from scratch (SHA-256, HMAC/HKDF, ChaCha20, Poly1305, DH key exchange, AEAD) and uses them to transfer files securely between Linux hosts (tested with Kali Linux ↔ Ubuntu Server). The work is intentionally self-contained and avoids high-level crypto libraries to satisfy course constraints.

### Features

- Pure-Python implementations of the required primitives (no `hashlib`, `cryptography`, etc.).
- Authenticated Diffie-Hellman handshake using a pre-shared key (PSK) to derive per-session keys.
- ChaCha20-Poly1305 encrypted tunnel with replay protection via sequence numbers and derived nonces.
- UDP client/server reference applications for file transfer (ready to be attached to a TUN interface).
- Extensive automated tests: primitives, handshake, in-memory tunnel demo, and UDP round trip.
- Documentation in `docs/` covering design rationale and testing strategy.

### Repository Layout

```
docs/                  ├─ overview and assignment instructions
src/crypto/            ├─ SHA-256, HMAC/HKDF, ChaCha20, Poly1305, AEAD
src/protocol/          ├─ Diffie-Hellman logic + handshake helpers
src/vpn/               ├─ Secure tunnel, demo runner, UDP client/server apps
tests/                 └─ Unit and integration tests
```

### Requirements

- Python 3.10+ (developed with CPython 3.12).
- Linux hosts (Kali/Ubuntu) with basic networking tools (`ip`, `tun` module) for final deployment.
- Ability to copy a shared secret (`psk.bin`) securely to both hosts.

### Quick Start

1. **Install dependencies**: the project only relies on the Python standard library, but you may optionally create a virtual environment.
2. **Generate a PSK** (32 random bytes) using the provided Make target:
   ```sh
   make psk               # writes ./psk.bin by default
   ```
   or specify a custom path: `make psk PSK_FILE=/secure/path/psk.bin`.
3. **Run tests** to ensure everything works locally:
   ```sh
   make test              # executes crypto, protocol, demo, and UDP tests
   ```
   The UDP test is skipped automatically if the environment disallows socket creation (e.g., CI sandboxes).
4. **Try the in-memory demo** (handshake + encrypted pipeline without network):
   ```sh
   make demo
   ```

### File Transfer over UDP

Once the PSK exists on both machines, you can transfer a file securely:

1. **Server (Ubuntu/Kali receiving host)**:
   ```sh
   python3 -m src.vpn.server_app \
     --listen-host 0.0.0.0 \
     --listen-port 9000 \
     --psk-file /path/to/psk.bin \
     --output-file received.bin
   ```
2. **Client (sending host)**:
   ```sh
   python3 -m src.vpn.client_app \
     --server-host <server-ip> \
     --server-port 9000 \
     --psk-file /path/to/psk.bin \
     --input-file secret_file.bin
   ```

The handshake authenticates both ends using the PSK, derives fresh session keys with HKDF, and then `SecureTunnel` encrypts every chunk using ChaCha20-Poly1305 with per-packet nonces. For the final VPN deliverable you only need to swap the file read/write logic with a TUN interface reader/writer so that arbitrary IP packets flow through the tunnel.

### Testing and Validation

- `tests/test_crypto.py`: RFC vectors for SHA-256, HMAC, HKDF, ChaCha20, Poly1305, and AEAD.
- `tests/test_protocol.py`: deterministically seeded handshake simulation checking mutual authentication and MAC failures.
- `tests/test_integration.py`: in-memory socketpair demo (`memory_transport`) verifying encrypted messaging.
- `tests/test_network.py`: localhost UDP client/server that encrypts/decrypts ~5 KB and compares the result (auto-skips when sockets are unavailable).

Run individual suites with `python3 -m unittest tests.test_crypto`, etc., or just `make test`.

### Next Steps (for class deliverable)

- Attach `SecureTunnel` to a TUN interface (`/dev/net/tun`) on Kali/Ubuntu to carry IP traffic instead of file chunks.
- Capture traffic via Wireshark/tcpdump demonstrating encrypted handshakes/data, and document replay/MITM protections.
- Prepare the final report (≥25 pages) detailing design, algorithms, performance, and attacks, as required by the assignment.

Feel free to open issues or suggestions if you're reviewing this for academic purposes. Otherwise, this repo stands as a reference implementation for the course project.
