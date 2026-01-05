from __future__ import annotations

from constants import PAGE_SIZE, Sysno
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.kernel import Kernel


def main() -> None:
    physmem = PhysMem(size_bytes=64 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    k = Kernel(aspace)
    pid = k.create_process()

    # Map one user page and place two strings in it (in the process AddressSpace).
    pas = k.processes[pid].aspace
    user_base = 0x1000_0000
    pas.map_page(user_base, PageFlags.R | PageFlags.W | PageFlags.USER)

    s1 = b"t1: hello\n"
    s2 = b"t2: world\n"
    pas.write(user_base + 0x00, s1, user=True)
    pas.write(user_base + 0x80, s2, user=True)

    # Script op tuple: (sysno, arg1, arg2, arg3)
    t1 = [
        (int(Sysno.WRITE), 1, user_base + 0x00, len(s1)),
        (int(Sysno.YIELD), 0, 0, 0),
        (int(Sysno.WRITE), 1, user_base + 0x00, len(s1)),
        (int(Sysno.EXIT), 0, 0, 0),
    ]
    t2 = [
        (int(Sysno.WRITE), 1, user_base + 0x80, len(s2)),
        (int(Sysno.YIELD), 0, 0, 0),
        (int(Sysno.WRITE), 1, user_base + 0x80, len(s2)),
        (int(Sysno.EXIT), 0, 0, 0),
    ]

    k.create_thread(pid, t1)
    k.create_thread(pid, t2)

    k.run(max_steps=100)

    assert k.processes[pid].exit_status == 0
    print("M2 demo ok")


if __name__ == "__main__":
    main()
