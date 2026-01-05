from __future__ import annotations

import sys
import termios
import tty

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.mem import PageFlags
from simmach.rvprog import Program
from simmach import rvlib
from simmach import rvasm
from simmach.syscall import TrapFrame


class _RawTerminal:
    def __init__(self) -> None:
        self._tty = None
        try:
            self._tty = open("/dev/tty", "rb", buffering=0)
            self._fd = self._tty.fileno()
        except Exception:
            if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                self._fd = sys.stdin.fileno()
            else:
                self._fd = -1
        self._old: list[int] | None = None

    def __enter__(self) -> "_RawTerminal":
        if self._fd < 0:
            raise RuntimeError(
                "Arrow-key input requires a real TTY. Run this demo from a terminal (not the IDE run panel)."
            )
        self._old = termios.tcgetattr(self._fd)
        tty.setraw(self._fd)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if self._old is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        if self._tty is not None:
            try:
                self._tty.close()
            except Exception:
                pass


def main() -> None:
    physmem = PhysMem(size_bytes=1024 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=2048)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    entry = 0x1000_0000
    p = Program(entry=entry, text_vaddr=entry, data_vaddr=0x1000_4000)

    s_banner = p.db(b"Arrow keys demo (press q to quit)\n")
    s_up = p.db(b"UP\n")
    s_down = p.db(b"DOWN\n")
    s_left = p.db(b"LEFT\n")
    s_right = p.db(b"RIGHT\n")
    s_unknown = p.db(b"?\n")

    p.align_data(8)
    buf = p.db(b"\x00" * 8)

    p.label("start")

    rvlib.sys_write(p, fd=1, buf=s_banner, count=len(b"Arrow keys demo (press q to quit)\n"))

    # S0 = state (0: normal, 1: after ESC, 2: after ESC '[')
    p.li(rvlib.S0, 0)
    p.li(rvlib.S1, buf)

    p.label("loop")

    # Clear buf[0..7] to keep ld result stable.
    p.emit(rvasm.sd(0, rvlib.S1, 0))

    rvlib.sys_read(p, fd=0, buf=buf, count=1)

    # T0 = byte
    p.emit(rvasm.ld(rvlib.T0, rvlib.S1, 0))

    # if byte == 'q' -> exit
    p.li(rvlib.T1, ord("q"))
    p.beq(rvlib.T0, rvlib.T1, "quit")

    # state machine
    p.li(rvlib.T1, 0)
    p.beq(rvlib.S0, rvlib.T1, "st0")
    p.li(rvlib.T1, 1)
    p.beq(rvlib.S0, rvlib.T1, "st1")
    p.jal(0, "st2")

    p.label("st0")
    p.li(rvlib.T1, 0x1B)
    p.beq(rvlib.T0, rvlib.T1, "saw_esc")
    p.jal(0, "loop")

    p.label("saw_esc")
    p.li(rvlib.S0, 1)
    p.jal(0, "loop")

    p.label("st1")
    p.li(rvlib.T1, ord("["))
    p.beq(rvlib.T0, rvlib.T1, "saw_lb")
    p.li(rvlib.S0, 0)
    p.jal(0, "loop")

    p.label("saw_lb")
    p.li(rvlib.S0, 2)
    p.jal(0, "loop")

    p.label("st2")
    # Reset state no matter what.
    p.li(rvlib.S0, 0)

    p.li(rvlib.T1, ord("A"))
    p.beq(rvlib.T0, rvlib.T1, "print_up")
    p.li(rvlib.T1, ord("B"))
    p.beq(rvlib.T0, rvlib.T1, "print_down")
    p.li(rvlib.T1, ord("C"))
    p.beq(rvlib.T0, rvlib.T1, "print_right")
    p.li(rvlib.T1, ord("D"))
    p.beq(rvlib.T0, rvlib.T1, "print_left")
    p.jal(0, "print_unknown")

    p.label("print_up")
    rvlib.sys_write(p, fd=1, buf=s_up, count=len(b"UP\n"))
    p.jal(0, "loop")

    p.label("print_down")
    rvlib.sys_write(p, fd=1, buf=s_down, count=len(b"DOWN\n"))
    p.jal(0, "loop")

    p.label("print_left")
    rvlib.sys_write(p, fd=1, buf=s_left, count=len(b"LEFT\n"))
    p.jal(0, "loop")

    p.label("print_right")
    rvlib.sys_write(p, fd=1, buf=s_right, count=len(b"RIGHT\n"))
    p.jal(0, "loop")

    p.label("print_unknown")
    rvlib.sys_write(p, fd=1, buf=s_unknown, count=len(b"?\n"))
    p.jal(0, "loop")

    p.label("quit")
    rvlib.sys_exit(p, 0)

    rvx = p.build_rvx()
    inode = fs.create_file("/bin/arrowkeys")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/arrowkeys\x00", user=True)

    with _RawTerminal():
        entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
        assert entry_ret == entry
        k.run_user_rv64(pid, entry_ret, max_steps=2_000_000)


if __name__ == "__main__":
    main()
