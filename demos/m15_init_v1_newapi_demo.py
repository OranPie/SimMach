from __future__ import annotations

from constants import MAP_FILE, MAP_SHARED, PAGE_SIZE, PROT_READ, PROT_WRITE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.mem import PageFlags
from simmach.rvprog import Program
from simmach import rvlib
from simmach import rvasm
from simmach.syscall import TrapFrame


def main() -> None:
    physmem = PhysMem(size_bytes=1024 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=2048)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    entry = 0x1000_0000
    p = Program(entry=entry, text_vaddr=entry, data_vaddr=0x1000_4000)

    s_parent = p.db(b"parent: hi\n")
    s_child = p.db(b"child: hi\n")
    s_done = p.db(b"parent: waited\n")
    s_log = p.db(b"init log\n")
    path_log = p.db(b"/tmp/init.log\x00")
    path_mm = p.db(b"/tmp/mm.txt\x00")
    seed = p.db(b"hello\n")
    p.align_data(8)
    world8 = p.db(b"WORLD\x00\x00\x00")
    p.align_data(8)
    status_slot = p.db(b"\x00" * 8)

    p.label("start")

    rvlib.sys_write(p, fd=1, buf=s_parent, count=len(b"parent: hi\n"))

    rvlib.sys_fork(p)
    p.beq(rvlib.A0, 0, "child")

    p.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))

    p.label("wait_loop")
    p.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p.li(rvlib.A1, status_slot)
    p.li(rvlib.A7, int(Sysno.WAITPID))
    rvlib.ecall(p)
    p.li(rvlib.T1, -11)
    p.beq(rvlib.A0, rvlib.T1, "wait_loop")

    rvlib.sys_write(p, fd=1, buf=s_done, count=len(b"parent: waited\n"))

    rvlib.sys_open(p, path_addr=path_log, flags=3)
    p.emit(rvasm.addi(rvlib.S1, rvlib.A0, 0))

    p.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p.li(rvlib.A1, s_log)
    p.li(rvlib.A2, len(b"init log\n"))
    p.li(rvlib.A7, int(Sysno.WRITE))
    rvlib.ecall(p)

    p.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p.li(rvlib.A7, int(Sysno.CLOSE))
    rvlib.ecall(p)

    rvlib.sys_open(p, path_addr=path_mm, flags=1)
    p.emit(rvasm.addi(rvlib.S1, rvlib.A0, 0))

    p.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p.li(rvlib.A1, seed)
    p.li(rvlib.A2, len(b"hello\n"))
    p.li(rvlib.A7, int(Sysno.WRITE))
    rvlib.ecall(p)

    # mmap shared
    p.li(rvlib.A0, 0)
    p.li(rvlib.A1, 4096)
    p.li(rvlib.A2, int(PROT_READ | PROT_WRITE))
    p.li(rvlib.A3, int(MAP_FILE | MAP_SHARED))
    p.emit(rvasm.addi(rvlib.A4, rvlib.S1, 0))
    p.li(rvlib.A5, 0)
    p.li(rvlib.A7, int(Sysno.MMAP))
    rvlib.ecall(p)
    p.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))

    # *(map) = *(world8)
    p.li(rvlib.T1, world8)
    p.emit(rvasm.ld(rvlib.T2, rvlib.T1, 0))
    p.emit(rvasm.sd(rvlib.T2, rvlib.T0, 0))

    # munmap
    p.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p.li(rvlib.A1, 4096)
    p.li(rvlib.A7, int(Sysno.MUNMAP))
    rvlib.ecall(p)

    # close
    p.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p.li(rvlib.A7, int(Sysno.CLOSE))
    rvlib.ecall(p)

    rvlib.sys_exit(p, 0)

    p.label("child")
    rvlib.sys_write(p, fd=1, buf=s_child, count=len(b"child: hi\n"))
    rvlib.sys_exit(p, 42)

    rvx = p.build_rvx()
    inode = fs.create_file("/bin/initv1_new")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/initv1_new\x00", user=True)

    entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    assert entry_ret == entry
    k.run_user_rv64(pid, entry_ret)

    log_inode = fs.lookup("/tmp/init.log")
    assert log_inode is not None
    raw = fs.read_inode(log_inode, 0, 64)
    assert b"init log" in raw

    mm_inode = fs.lookup("/tmp/mm.txt")
    assert mm_inode is not None
    raw2 = fs.read_inode(mm_inode, 0, 16)
    assert raw2.startswith(b"WORLD")

    print("\nM15 init v1 newapi demo ok")


if __name__ == "__main__":
    main()
