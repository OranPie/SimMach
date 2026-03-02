from __future__ import annotations

import unittest

from constants import PAGE_SIZE, Errno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simos.shell_bins import _install_base_bins
from simos.shell_env import ShellEnv
from simos.shell_runtime import _run_program


class _FakeConsole:
    def __init__(self, data: bytes = b"") -> None:
        self._in = bytearray(data)
        self.out = bytearray()

    def read(self, count: int) -> bytes:
        if count <= 0 or not self._in:
            return b""
        n = min(int(count), len(self._in))
        out = bytes(self._in[:n])
        del self._in[:n]
        return out

    def write(self, data: bytes) -> int:
        self.out += bytes(data)
        return len(data)


def _make_env() -> ShellEnv:
    physmem = PhysMem(size_bytes=2048 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=4096)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()
    _install_base_bins(fs)

    k = Kernel(kas)
    k.set_fs(fs)
    return ShellEnv(k=k, fs=fs, kas=kas)


class ShellRuntimeIntegration(unittest.TestCase):
    def test_run_program_echo_success(self) -> None:
        env = _make_env()
        fake = _FakeConsole()
        env.k.console = fake

        rc = _run_program(env, "/bin/echo", ["/bin/echo", "hello"], use_cbreak=False, max_steps=2_000_000)
        self.assertEqual(0, rc)
        self.assertIn(b"hello\n", bytes(fake.out))
        self.assertEqual({}, env.k.processes)

    def test_run_program_missing_binary_returns_errno(self) -> None:
        env = _make_env()
        fake = _FakeConsole()
        env.k.console = fake

        rc = _run_program(env, "/bin/definitely-missing", ["/bin/definitely-missing"], use_cbreak=False)
        self.assertEqual(int(Errno.ENOENT), rc)
        self.assertEqual({}, env.k.processes)


if __name__ == "__main__":
    unittest.main()
