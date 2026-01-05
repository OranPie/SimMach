from __future__ import annotations

import struct

from constants import MAP_FILE, MAP_SHARED, PAGE_SIZE, PROT_READ, PROT_WRITE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.syscall import TrapFrame


def main() -> None:
    physmem = PhysMem(size_bytes=512 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=512)
    bfs = BetterFS(dev)
    bfs.format_and_mount(create_default_dirs=True)
    bfs.mount()

    # seed file
    inode = bfs.create_file("/tmp/mm.txt")
    bfs.write_inode(inode, 0, b"hello\n", truncate=True)

    k = Kernel(kas)
    k.set_fs(bfs)
    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x1000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/tmp/mm.txt\x00", user=True)

    fd = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=user_base, rsi=0, rdx=0))
    assert fd >= 3

    tf_mmap = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=0,
        rsi=4096,
        rdx=PROT_READ | PROT_WRITE,
        r10=MAP_FILE | MAP_SHARED,
        r8=int(fd),
        r9=0,
    )
    addr = k.syscalls.dispatch(k, pid, tf_mmap)
    assert addr > 0

    # modify mapping
    aspace.write(addr, b"WORLD", user=False)

    # munmap triggers writeback
    assert k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.MUNMAP), rdi=int(addr), rsi=4096)) == 0

    raw = bfs.read_inode(bfs.lookup("/tmp/mm.txt"), 0, 16)
    assert raw.startswith(b"WORLD")

    print("M10 mmap shared demo ok")


if __name__ == "__main__":
    main()
