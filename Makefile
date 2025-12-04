PYTHON ?= python3
PSK_FILE ?= psk.bin

.PHONY: help test demo psk clean

help:
	@echo "Targets:"
	@echo "  make test       - Run all unit/integration tests"
	@echo "  make demo       - Execute the in-memory demo transfer"
	@echo "  make psk        - Generate a 32-byte pre-shared key (psk.bin by default)"
	@echo "  make clean      - Remove __pycache__ and temporary artifacts"

test:
	$(PYTHON) -m unittest tests.test_crypto tests.test_protocol tests.test_integration tests.test_network

demo:
	$(PYTHON) -m src.vpn.demo_runner

psk:
	$(PYTHON) - <<'PY'
import os
path = r"$(PSK_FILE)"
with open(path, "wb") as handle:
    handle.write(os.urandom(32))
print(f"PSK written to {path}")
PY

clean:
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
