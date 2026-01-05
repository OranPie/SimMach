from __future__ import annotations

import sys
import termios

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.mem import PageFlags
from simmach.rvprog import Program
from simmach import rvlib
from simmach.syscall import TrapFrame


class _CbreakTerminal:
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

    def __enter__(self) -> "_CbreakTerminal":
        if self._fd < 0:
            raise RuntimeError("This demo requires a real TTY. Run from iTerm/Terminal.")
        self._old = termios.tcgetattr(self._fd)

        new = termios.tcgetattr(self._fd)
        # cbreak-like: immediate key bytes, no echo; keep ISIG so Ctrl-C works
        new[3] = new[3] & ~(termios.ICANON | termios.ECHO)
        new[3] = new[3] | termios.ISIG
        new[6][termios.VMIN] = 1
        new[6][termios.VTIME] = 0
        termios.tcsetattr(self._fd, termios.TCSADRAIN, new)
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

    s_banner = p.db(b"READKEY debug demo: arrows + r + q. Ctrl-C to abort.\n")
    s_up = p.db(b"UP\n")
    s_down = p.db(b"DOWN\n")
    s_left = p.db(b"LEFT\n")
    s_right = p.db(b"RIGHT\n")
    s_r = p.db(b"R(restart)\n")
    s_q = p.db(b"Q(quit)\n")

    p.label("start")
    rvlib.sys_write(p, fd=1, buf=s_banner, count=len(b"READKEY debug demo: arrows + r + q. Ctrl-C to abort.\n"))

    p.label("loop")
    rvlib.sys_readkey(p)  # returns code in A0

    # codes: 1 up,2 down,3 left,4 right,5 r,6 q
    p.li(rvlib.T0, 1)
    p.beq(rvlib.A0, rvlib.T0, "print_up")
    p.li(rvlib.T0, 2)
    p.beq(rvlib.A0, rvlib.T0, "print_down")
    p.li(rvlib.T0, 3)
    p.beq(rvlib.A0, rvlib.T0, "print_left")
    p.li(rvlib.T0, 4)
    p.beq(rvlib.A0, rvlib.T0, "print_right")
    p.li(rvlib.T0, 5)
    p.beq(rvlib.A0, rvlib.T0, "print_r")
    p.li(rvlib.T0, 6)
    p.beq(rvlib.A0, rvlib.T0, "print_q")
    p.jal(0, "loop")

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

    p.label("print_r")
    rvlib.sys_write(p, fd=1, buf=s_r, count=len(b"R(restart)\n"))
    p.jal(0, "loop")

    p.label("print_q")
    rvlib.sys_write(p, fd=1, buf=s_q, count=len(b"Q(quit)\n"))
    rvlib.sys_exit(p, 0)

    rvx = p.build_rvx()
    inode = fs.create_file("/bin/readkey_dbg")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/readkey_dbg\x00", user=True)

    with _CbreakTerminal():
        try:
            entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
            assert entry_ret == entry
            k.run_user_rv64(pid, entry_ret, max_steps=500_000_000)
        except KeyboardInterrupt:
            print("\nInterrupted (Ctrl-C).")


if __name__ == "__main__":
    main()
