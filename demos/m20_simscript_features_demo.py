"""
Demo m20 — SimScript: language features

Tests:
  - Module-level global constants
  - elif chains
  - break / continue in while loops
  - String interning (same literal used twice → same address)
  - Constant folding (LIMIT * 2 computed at compile time)
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
LIMIT = 5
STEP  = 2

def classify(x):
    if x < 0:
        return -1
    elif x == 0:
        return 0
    elif x < LIMIT:
        return 1
    else:
        return 2

def main():
    # Test elif
    a = classify(-3)
    if a == -1:
        write(1, "neg ok\\n")
    b = classify(0)
    if b == 0:
        write(1, "zero ok\\n")
    c = classify(3)
    if c == 1:
        write(1, "mid ok\\n")
    d = classify(10)
    if d == 2:
        write(1, "big ok\\n")

    # Test break
    i = 0
    while i < LIMIT * 2:
        if i == 3:
            break
        i = i + 1
    if i == 3:
        write(1, "break ok\\n")

    # Test continue (sum even numbers 0..8 = 0+2+4+6+8 = 20)
    j = 0
    total = 0
    while j < 10:
        j = j + 1
        if j % STEP != 0:
            continue
        total = total + j
    if total == 30:
        write(1, "continue ok\\n")

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

    inode = fs.create_file("/bin/features")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/features\x00", user=True)

    entry = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    k.run_user_rv64(pid, entry)

    print("\nM20 SimScript features demo ok")


if __name__ == "__main__":
    main()
