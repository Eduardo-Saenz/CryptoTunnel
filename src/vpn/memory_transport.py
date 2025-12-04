"""In-memory duplex channel emulating socket send/recv APIs."""

from __future__ import annotations

import queue
from typing import Tuple


class _Endpoint:
    def __init__(self):
        self._queue = queue.Queue()
        self._buffer = bytearray()
        self.peer: _Endpoint | None = None

    def connect(self, other: "._Endpoint") -> None:
        self.peer = other

    def sendall(self, data: bytes) -> None:
        if not self.peer:
            raise RuntimeError("Peer not connected")
        self.peer._queue.put(bytes(data))

    def recv(self, bufsize: int) -> bytes:
        while not self._buffer:
            chunk = self._queue.get()
            if chunk:
                self._buffer.extend(chunk)
            else:
                return b""
        if len(self._buffer) <= bufsize:
            data = bytes(self._buffer)
            self._buffer.clear()
            return data
        data = bytes(self._buffer[:bufsize])
        del self._buffer[:bufsize]
        return data

    def close(self) -> None:
        pass


def memory_socketpair() -> Tuple[_Endpoint, _Endpoint]:
    a = _Endpoint()
    b = _Endpoint()
    a.connect(b)
    b.connect(a)
    return a, b
