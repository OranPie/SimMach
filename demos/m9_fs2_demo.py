from __future__ import annotations

from constants import PAGE_SIZE, Errno, Sysno
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

    k = Kernel(kas)
    k.set_fs(bfs)
    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x1000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)

    path = b"/tmp/a.txt\x00"
    path_ptr = user_base
    aspace.write(path_ptr, path, user=True)

    fd = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=path_ptr, rsi=1, rdx=0))
    assert fd >= 3

    payload = b"hello fs2\n"
    buf_ptr = user_base + 0x100
    aspace.write(buf_ptr, payload, user=True)

    nw = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.WRITE), rdi=int(fd), rsi=buf_ptr, rdx=len(payload)))
    assert nw == len(payload)

    assert k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(fd))) == 0

    fd2 = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=path_ptr, rsi=0, rdx=0))
    assert fd2 >= 3

    out_ptr = user_base + 0x200
    nr = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.READ), rdi=int(fd2), rsi=out_ptr, rdx=4096))
    assert nr == len(payload)
    got = aspace.read(out_ptr, nr, user=True)
    assert got == payload

    assert k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(fd2))) == 0

    fd3 = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=path_ptr, rsi=2, rdx=0))
    buf2_ptr = user_base + 0x300
    aspace.write(buf2_ptr, b"X", user=True)
    r = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.WRITE), rdi=int(fd3), rsi=buf2_ptr, rdx=1))
    assert r == 1

    assert k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(fd3))) == 0

    inode = bfs.lookup("/tmp/a.txt")
    assert inode is not None
    raw = bfs.read_inode(inode, 0, 4096)
    assert raw == payload + b"X"

    no = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=user_base + 0x5000, rsi=0, rdx=0))
    assert no == int(Errno.EFAULT)

    print("M9 fs2 demo ok")


if __name__ == "__main__":
    main()
