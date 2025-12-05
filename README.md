## Secure Encrypted VPN Channel

This repository contains my final project for the university Cryptography class: a fully custom, authenticated VPN-style tunnel that implements every cryptographic primitive from scratch (SHA-256, HMAC/HKDF, ChaCha20, Poly1305, DH key exchange, AEAD) and uses them to transfer files securely between Linux hosts (tested with Kali Linux ↔ Ubuntu Server). The work is intentionally self-contained and avoids high-level crypto libraries to satisfy course constraints.

### Features

-   Pure-Python implementations of the required primitives.
-   Authenticated Diffie-Hellman handshake using a pre-shared key (PSK) to derive per-session keys.
-   ChaCha20-Poly1305 encrypted tunnel with replay protection via sequence numbers and derived nonces.
-   UDP client/server reference applications for file transfer (ready to be attached to a TUN interface).
-   Extensive automated tests: primitives, handshake, in-memory tunnel demo, and UDP round trip.

### Repository Layout

```
docs/                  ├─ overview and assignment instructions
src/crypto/            ├─ SHA-256, HMAC/HKDF, ChaCha20, Poly1305, AEAD
src/protocol/          ├─ Diffie-Hellman logic + handshake helpers
src/vpn/               ├─ Secure tunnel, demo runner, UDP client/server apps
tests/                 └─ Unit and integration tests
```

### Requirements

-   Python 3.10+ (developed with CPython 3.12).
-   Linux hosts (Kali/Ubuntu) with basic networking tools (`ip`, `tun` module) for final deployment.
-   Ability to copy a shared secret (`psk.bin`) securely to both hosts.

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

-   `tests/test_crypto.py`: RFC vectors for SHA-256, HMAC, HKDF, ChaCha20, Poly1305, and AEAD.
-   `tests/test_protocol.py`: deterministically seeded handshake simulation checking mutual authentication and MAC failures.
-   `tests/test_integration.py`: in-memory socketpair demo (`memory_transport`) verifying encrypted messaging.
-   `tests/test_network.py`: localhost UDP client/server that encrypts/decrypts ~5 KB and compares the result (auto-skips when sockets are unavailable).

Run individual suites with `python3 -m unittest tests.test_crypto`, etc., or just `make test`.

# 🔐 Encrypted File Transfer Test (Server ↔ Client)

This guide explains how to test the secure encrypted channel implemented in this project.
Follow these steps on two machines within the same local network.

---

# 🖥️ **1. Server Setup (Receiver)**

### **1.1. Ensure the PSK file is present**

The server must have a copy of the shared key:

```
psk.bin
```

Example location:

```
/home/<user>/psk.bin
```

Copy it from the client if needed:

```bash
scp psk.bin <user>@<SERVER_IP>:/path/to/psk.bin
```

---

### **1.2. Start the server**

Run the server application:

```bash
python3 -m src.vpn.server_app \
  --listen-host 0.0.0.0 \
  --listen-port 9000 \
  --psk-file /path/to/psk.bin \
  --output-file received.bin
```

**What it does:**

-   Listens for incoming connections on port `9000`
-   Performs authenticated, encrypted handshake using the PSK
-   Receives encrypted data from the client
-   Decrypts and saves the output as:

```
received.bin
```

---

# 💻 **2. Client Setup (Sender)**

### **2.1. Generate a 10 MB test file**

Create a file with random content:

```bash
dd if=/dev/urandom of=test10mb.bin bs=1M count=10
```

---

### **2.2. Generate the PSK (if not already created)**

```bash
make psk
```

This creates:

```
psk.bin
```

Copy the PSK to the server:

```bash
scp psk.bin <user>@<SERVER_IP>:/path/to/psk.bin
```

---

### **2.3. Run the client**

Execute the client and send the test file:

```bash
python3 -m src.vpn.client_app \
  --server-host <SERVER_IP> \
  --server-port 9000 \
  --psk-file psk.bin \
  --input-file test10mb.bin
```

**What it does:**

-   Connects to the server
-   Performs secure handshake with mutual authentication
-   Encrypts `test10mb.bin`
-   Sends encrypted data to the server in secure records

---

# ✔️ **3. Verify File Integrity**

On the **client**:

```bash
sha256sum test10mb.bin
```

On the **server**:

```bash
sha256sum received.bin
```

If the SHA-256 hashes match:

-   The transfer succeeded
-   The encrypted tunnel worked correctly
-   No tampering or corruption occurred

---

# 📡 **Flow Summary**

1. Both machines share the same `psk.bin`.
2. Server listens on `<SERVER_IP>:9000`.
3. Client initiates handshake and authentication.
4. Both derive session keys (encryption + integrity).
5. Client encrypts and transmits file.
6. Server decrypts and writes `received.bin`.
7. Hash verification confirms end-to-end integrity.
