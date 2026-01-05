from __future__ import annotations

from constants import PAGE_SIZE, Sysno
from simmach.exe import build_script_exe
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.kernel import Kernel


def main() -> None:
    physmem = PhysMem(size_bytes=256 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    k = Kernel(aspace)
    pid = k.create_process()

    # Put the user string into user memory at a fixed vaddr (process AddressSpace).
    pas = k.processes[pid].aspace
    user_data_base = 0x1000_0000
    pas.map_page(user_data_base, PageFlags.R | PageFlags.W | PageFlags.USER)
    msg = b"hello from exe\n"
    pas.write(user_data_base, msg, user=True)

    entry = 0x0040_0000
    exe = build_script_exe(
        entry_vaddr=entry,
        script_ops=[
            (int(Sysno.WRITE), 1, user_data_base, len(msg)),
            (int(Sysno.EXIT), 0, 0, 0),
        ],
    )

    rip = k.load_executable(pid, exe)
    assert rip == entry

    k.run_user_script(pid, rip)

    assert k.processes[pid].exit_status == 0
    print("M4 demo ok")


if __name__ == "__main__":
    main()
