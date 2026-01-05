from __future__ import annotations

import struct

from constants import MAP_ANON, MAP_FILE, MAP_FIXED, PAGE_SIZE, PROT_READ, PROT_WRITE, Errno, Sysno
from simmach.block import BlockDevice
from simmach.fs import TinyFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.syscall import TrapFrame

_I64 = struct.Struct("<q")


def main() -> None:
    physmem = PhysMem(size_bytes=512 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=256)
    fs = TinyFS(dev)
    content = b"file-mmap\n"
    fs.format_and_mount({"/etc/file.txt": content})

    k = Kernel(aspace)
    k.set_fs(fs)
    pid = k.create_process()
    pas = k.processes[pid].aspace

    user_base = 0x1000_0000
    pas.map_page(user_base, PageFlags.R | PageFlags.W | PageFlags.USER)
    pas.write(user_base, b"/etc/file.txt\x00", user=True)

    tf_open = TrapFrame(rax=int(Sysno.OPEN), rdi=user_base, rsi=0, rdx=0)
    fd = k.syscalls.dispatch(k, pid, tf_open)
    assert fd >= 3

    tf_mmap_file = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=0,
        rsi=4096,
        rdx=PROT_READ,
        r10=MAP_FILE,
        r8=fd,
        r9=0,
    )
    addr = k.syscalls.dispatch(k, pid, tf_mmap_file)
    assert addr > 0

    tf_write = TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=addr, rdx=len(content))
    assert k.syscalls.dispatch(k, pid, tf_write) == len(content)

    tf_mmap_none = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=0,
        rsi=4096,
        rdx=0,
        r10=MAP_FILE,
        r8=fd,
        r9=0,
    )
    addr_none = k.syscalls.dispatch(k, pid, tf_mmap_none)
    assert addr_none > 0
    tf_write2 = TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=addr_none, rdx=1)
    assert k.syscalls.dispatch(k, pid, tf_write2) == int(Errno.EFAULT)

    hint = 0x2200_0000
    tf_anon = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=hint,
        rsi=4096,
        rdx=PROT_READ | PROT_WRITE,
        r10=MAP_ANON,
        r8=-1,
        r9=0,
    )
    a1 = k.syscalls.dispatch(k, pid, tf_anon)
    assert a1 == hint
    pas.write(hint, b"xxxx", user=True)

    tf_file_fixed = TrapFrame(
        rax=int(Sysno.MMAP),
        rdi=hint,
        rsi=4096,
        rdx=PROT_READ,
        r10=MAP_FILE | MAP_FIXED,
        r8=fd,
        r9=0,
    )
    a2 = k.syscalls.dispatch(k, pid, tf_file_fixed)
    assert a2 == hint
    assert pas.read(hint, len(content), user=True) == content

    page2 = user_base + 0x1000
    pas.map_page(page2, PageFlags.R | PageFlags.W | PageFlags.USER)
    pas.write(page2, b"parent", user=True)

    child_pid = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.FORK)))
    assert child_pid > 0

    child_as = k.processes[child_pid].aspace
    assert child_as.read(page2, 6, user=True) == b"parent"
    child_as.write(page2, b"child!", user=True)
    assert pas.read(page2, 6, user=True) == b"parent"

    k.syscalls.dispatch(k, child_pid, TrapFrame(rax=int(Sysno.EXIT), rdi=7))

    status_ptr = user_base + 0x200
    got = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.WAITPID), rdi=child_pid, rsi=status_ptr))
    assert got == child_pid
    assert _I64.unpack(pas.read(status_ptr, 8, user=True))[0] == 7

    got2 = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.WAITPID), rdi=child_pid, rsi=status_ptr))
    assert got2 == int(Errno.ECHILD)

    print("M7 pp demo ok")


if __name__ == "__main__":
    main()
