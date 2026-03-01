"""
Demo m19 — SimScript: recursive Fibonacci

Tests:
  - User-defined function calls (recursive)
  - if / elif / else chain
  - Return values
  - Constant folding at compile time
"""
from __future__ import annotations

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem, PageFlags
from simmach.syscall import TrapFrame
from simmach.simscript import compile as simscript_compile


_SRC = """\
def fib(n):
    if n == 0:
        return 0
    elif n == 1:
        return 1
    else:
        a = fib(n - 1)
        b = fib(n - 2)
        return a + b

def main():
    result = fib(10)
    if result == 55:
        write(1, "fib(10) = 55 OK\\n")
    else:
        write(1, "fib(10) WRONG\\n")
    exit(0)
"""


def main() -> None:
    physmem = PhysMem(size_bytes=1024 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=2048)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    rvx = simscript_compile(_SRC)

    inode = fs.create_file("/bin/fib")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/fib\x00", user=True)

    entry = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    k.run_user_rv64(pid, entry)

    print("\nM19 SimScript fib demo ok")


if __name__ == "__main__":
    main()
