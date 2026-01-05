from __future__ import annotations

import os
import sys


class ConsoleDevice:
    def __init__(self) -> None:
        self._tty_fd: int | None = None
        try:
            self._tty_fd = os.open("/dev/tty", os.O_RDONLY)
        except Exception:
            self._tty_fd = None

    def read(self, count: int) -> bytes:
        if count <= 0:
            return b""
        if self._tty_fd is not None:
            try:
                return os.read(self._tty_fd, int(count))
            except Exception:
                pass
        try:
            return os.read(sys.stdin.fileno(), int(count))
        except Exception:
            return sys.stdin.buffer.read(int(count))

    def write(self, data: bytes) -> int:
        if not data:
            return 0
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return len(data)
