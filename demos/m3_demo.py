from __future__ import annotations

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import TinyFS
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.kernel import Kernel
from simmach.syscall import TrapFrame


def main() -> None:
    physmem = PhysMem(size_bytes=128 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    # create a tiny block-backed FS
    dev = BlockDevice(block_size=512, num_blocks=128)
    fs = TinyFS(dev)
    fs.format_and_mount({"/etc/demo.conf": b"key=value\n"})

    k = Kernel(aspace)
    k.set_fs(fs)

    pid = k.create_process()
    pas = k.processes[pid].aspace

    # user memory
    user_base = 0x1000_0000
    pas.map_page(user_base, PageFlags.R | PageFlags.W | PageFlags.USER)

    path = b"/etc/demo.conf\x00"
    pas.write(user_base + 0x00, path, user=True)

    # open
    tf_open = TrapFrame(rax=int(Sysno.OPEN), rdi=user_base + 0x00, rsi=0, rdx=0)
    fd = k.syscalls.dispatch(k, pid, tf_open)
    assert fd >= 3

    # read -> user buf
    buf_ptr = user_base + 0x80
    tf_read = TrapFrame(rax=int(Sysno.READ), rdi=fd, rsi=buf_ptr, rdx=64)
    n = k.syscalls.dispatch(k, pid, tf_read)
    assert n > 0

    # write back to console
    tf_write = TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=buf_ptr, rdx=n)
    w = k.syscalls.dispatch(k, pid, tf_write)
    assert w == n

    # close
    tf_close = TrapFrame(rax=int(Sysno.CLOSE), rdi=fd)
    assert k.syscalls.dispatch(k, pid, tf_close) == 0

    # ENOENT
    pas.write(user_base + 0x00, b"/no/such\x00", user=True)
    tf_open2 = TrapFrame(rax=int(Sysno.OPEN), rdi=user_base + 0x00, rsi=0, rdx=0)
    enoent = k.syscalls.dispatch(k, pid, tf_open2)
    assert enoent < 0

    # EBADF
    tf_read2 = TrapFrame(rax=int(Sysno.READ), rdi=999, rsi=buf_ptr, rdx=1)
    ebadf = k.syscalls.dispatch(k, pid, tf_read2)
    assert ebadf < 0

    print("M3 demo ok")


if __name__ == "__main__":
    main()
