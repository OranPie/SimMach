"""
demos/m17_simscript_demo.py

Smoke test: compile a minimal SimScript program and run it via the kernel.
Shows that the full pipeline (lex → parse → codegen → RVX1 → execve → run) works.
"""
from __future__ import annotations

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem, PageFlags
from simmach.syscall import TrapFrame
from simmach.simscript import compile as simscript_compile


SRC = """\
def main():
    write(1, "hello from SimScript!\\n")
    x = 6 * 7
    if x == 42:
        write(1, "math works\\n")
    else:
        write(1, "math broken\\n")
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

    # Compile SimScript source to RVX1 bytes
    rvx = simscript_compile(SRC)

    # Store the executable in the filesystem
    inode = fs.create_file("/bin/hello")
    fs.write_inode(inode, 0, rvx, truncate=True)

    # Boot kernel and execve the binary
    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/hello\x00", user=True)

    entry = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    k.run_user_rv64(pid, entry)

    print("\nM17 SimScript smoke test ok")


if __name__ == "__main__":
    main()
