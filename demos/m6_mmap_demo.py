from __future__ import annotations

from constants import MAP_ANON, PAGE_SIZE, PROT_READ, PROT_WRITE, Sysno
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.syscall import TrapFrame


def main() -> None:
    physmem = PhysMem(size_bytes=256 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    k = Kernel(aspace)
    pid = k.create_process()
    pas = k.processes[pid].aspace

    # 1) mmap with hint
    hint = 0x2200_0000
    tf1 = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=hint,
        rsi=8192,
        rdx=PROT_READ | PROT_WRITE,
        r10=MAP_ANON,
        r8=-1,
        r9=0,
    )
    addr = k.syscalls.dispatch(k, pid, tf1)
    assert addr == hint

    # 2) partial munmap: unmap first page only
    tfu = TrapFrame(rax=int(Sysno.MUNMAP), rdi=addr, rsi=4096)
    assert k.syscalls.dispatch(k, pid, tfu) == 0

    # remaining second page should still be mappable for user write
    pas.write(addr + 4096, b"ok\n", user=True)

    # unmap rest
    tfu2 = TrapFrame(rax=int(Sysno.MUNMAP), rdi=addr + 4096, rsi=4096)
    assert k.syscalls.dispatch(k, pid, tfu2) == 0

    print("M6 mmap demo ok")


if __name__ == "__main__":
    main()
