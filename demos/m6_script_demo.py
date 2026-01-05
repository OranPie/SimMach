from __future__ import annotations

from constants import MAP_ANON, PAGE_SIZE, PROT_READ, PROT_WRITE, Sysno
from simmach.block import BlockDevice
from simmach.exe import build_script_exe, reg_ref
from simmach.fs import TinyFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem


def main() -> None:
    physmem = PhysMem(size_bytes=512 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=128)
    fs = TinyFS(dev)
    fs.format_and_mount({"/etc/demo.conf": b"from-script\n"})

    k = Kernel(aspace)
    k.set_fs(fs)
    pid = k.create_process()

    # user page with path and buffer (process AddressSpace)
    pas = k.processes[pid].aspace
    user_base = 0x1000_0000
    pas.map_page(user_base, PageFlags.R | PageFlags.W | PageFlags.USER)
    pas.write(user_base + 0x00, b"/etc/demo.conf\x00", user=True)

    # Script:
    # r0 = open(path_ptr)
    # r0 = read(fd=r0, buf=user_base+0x80, 32)   (r0 becomes nbytes)
    # write(1, buf, nbytes=r0)
    # movi r1, MAP_ANON      (r10=regs[1])
    # r0 = mmap(addr=0, len=4096, prot=PROT_READ|PROT_WRITE)
    # munmap(r0, 4096)
    # exit(0)
    buf = user_base + 0x80

    entry = 0x0040_0000
    exe = build_script_exe(
        entry_vaddr=entry,
        script_ops=[
            (int(Sysno.OPEN), user_base + 0x00, 0, 0),
            (int(Sysno.READ), reg_ref(0), buf, 32),
            (int(Sysno.WRITE), 1, buf, reg_ref(0)),
            (0, 1, MAP_ANON, 0),
            (int(Sysno.MMAP), 0, 4096, PROT_READ | PROT_WRITE),
            (int(Sysno.MUNMAP), reg_ref(0), 4096, 0),
            (int(Sysno.EXIT), 0, 0, 0),
        ],
    )

    rip = k.load_executable(pid, exe)
    k.run_user_script(pid, rip)

    assert k.processes[pid].exit_status == 0
    print("M6 script demo ok")


if __name__ == "__main__":
    main()
