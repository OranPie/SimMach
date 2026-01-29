from __future__ import annotations

import struct
import sys
import termios
from typing import Sequence

from constants import PAGE_SIZE, Sysno
from simmach.mem import AddressSpace, PageFlags
from simmach.syscall import TrapFrame

from simos.shell_env import ShellEnv

def _map_user_range(aspace: AddressSpace, base: int, size: int) -> None:
    n_pages = (int(size) + PAGE_SIZE - 1) // PAGE_SIZE
    for i in range(n_pages):
        aspace.map_page(int(base + i * PAGE_SIZE), PageFlags.USER | PageFlags.R | PageFlags.W)

def _write_cstring(aspace: AddressSpace, addr: int, s: str) -> int:
    b = s.encode("utf-8") + b"\x00"
    aspace.write(int(addr), b, user=True)
    return int(addr + len(b))

def _write_ptr_array(aspace: AddressSpace, addr: int, ptrs: Sequence[int]) -> None:
    raw = b"".join(struct.pack("<Q", int(p)) for p in ptrs)
    aspace.write(int(addr), raw, user=True)

def _prepare_exec_args(aspace: AddressSpace, *, base: int, path: str, argv: Sequence[str]) -> tuple[int, int, int, int]:
    cursor = int(base)
    path_ptr = cursor
    cursor = _write_cstring(aspace, cursor, path)

    arg_ptrs: list[int] = []
    for a in argv:
        arg_ptrs.append(cursor)
        cursor = _write_cstring(aspace, cursor, a)

    argv_arr = (cursor + 7) & ~7
    _write_ptr_array(aspace, argv_arr, [*arg_ptrs, 0])

    envp_arr = argv_arr + 8 * (len(arg_ptrs) + 1)
    _write_ptr_array(aspace, envp_arr, [0])

    end = envp_arr + 8
    return int(path_ptr), int(argv_arr), int(envp_arr), int(end)

class _CbreakTerminal:
    def __init__(self) -> None:
        self._fd = -1
        self._old: list[int] | None = None
        try:
            self._fd = open("/dev/tty", "rb", buffering=0).fileno()
        except Exception:
            try:
                if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                    self._fd = sys.stdin.fileno()
            except Exception:
                self._fd = -1

    def __enter__(self) -> "_CbreakTerminal":
        if self._fd < 0:
            return self
        try:
            self._old = termios.tcgetattr(self._fd)
            new = termios.tcgetattr(self._fd)
            new[3] = new[3] & ~(termios.ICANON | termios.ECHO)
            new[3] = new[3] | termios.ISIG
            new[6][termios.VMIN] = 1
            new[6][termios.VTIME] = 0
            termios.tcsetattr(self._fd, termios.TCSADRAIN, new)
        except Exception:
            self._old = None
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if self._fd < 0:
            return
        if self._old is None:
            return
        try:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        except Exception:
            pass

def _run_program(env: ShellEnv, path: str, argv: Sequence[str]) -> int:
    pid = env.k.create_process()
    aspace = env.k.processes[pid].aspace

    user_base = 0x2000_0000

    max_str_bytes = 4096
    max_ptr_bytes = 4096
    _map_user_range(aspace, user_base, max_str_bytes + max_ptr_bytes)

    path_ptr, argv_ptr, envp_ptr, _ = _prepare_exec_args(aspace, base=user_base, path=path, argv=argv)

    entry_ret = int(
        env.k.syscalls.dispatch(
            env.k,
            pid,
            TrapFrame(rax=int(Sysno.EXECVE), rdi=path_ptr, rsi=argv_ptr, rdx=envp_ptr),
        )
    )
    if entry_ret < 0:
        try:
            env.k._reap_process(pid)
        except Exception:
            pass
        return int(entry_ret)

    try:
        with _CbreakTerminal():
            env.k.run_user_rv64(pid, entry_ret, max_steps=200_000_000)
    except KeyboardInterrupt:
        print("\nInterrupted (Ctrl-C).")
    finally:
        try:
            env.k._reap_process(pid)
        except Exception:
            pass

    return 0
