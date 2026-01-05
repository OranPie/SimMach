from __future__ import annotations

from constants import MAP_ANON, PAGE_SIZE, PROT_READ, PROT_WRITE, Sysno
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.kernel import Kernel
from simmach.syscall import TrapFrame


def main() -> None:
    physmem = PhysMem(size_bytes=256 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    k = Kernel(aspace)
    pid = k.create_process()

    pas = k.processes[pid].aspace
    # A user page for holding a small string too (so we can compare behavior).
    user_base = 0x1000_0000
    pas.map_page(user_base, PageFlags.R | PageFlags.W | PageFlags.USER)

    # mmap anonymous region
    tf_mmap = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=0,
        rsi=4096,
        rdx=PROT_READ | PROT_WRITE,
        r10=MAP_ANON,
        r8=-1,
        r9=0,
    )
    addr = k.syscalls.dispatch(k, pid, tf_mmap)
    assert addr > 0

    msg = b"mmap works\n"
    pas.write(addr, msg, user=True)

    tf_write = TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=addr, rdx=len(msg))
    n = k.syscalls.dispatch(k, pid, tf_write)
    assert n == len(msg)

    tf_munmap = TrapFrame(rax=int(Sysno.MUNMAP), rdi=addr, rsi=4096)
    assert k.syscalls.dispatch(k, pid, tf_munmap) == 0

    # after munmap: should be EFAULT on write (copy_from_user will fail)
    tf_write2 = TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=addr, rdx=len(msg))
    r = k.syscalls.dispatch(k, pid, tf_write2)
    assert r < 0

    print("M5 demo ok")


if __name__ == "__main__":
    main()
