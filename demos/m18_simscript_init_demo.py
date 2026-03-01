"""
demos/m18_simscript_init_demo.py

Rewrite of m15_init_v1_demo in SimScript.

Before (m15_init_v1_demo.py): ~300 lines of raw RISC-V assembly helpers.
After (this file):             ~20 lines of SimScript source.

Verifies the same filesystem side effects:
  - /tmp/init.log contains "init log"
  - /tmp/mm.txt starts with "WORLD"
"""
from __future__ import annotations

from constants import PAGE_SIZE, Sysno, MAP_FILE, MAP_SHARED, PROT_READ, PROT_WRITE, O_CREAT, O_APPEND
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem, PageFlags
from simmach.syscall import TrapFrame
from simmach.simscript import compile as simscript_compile


# Flags as integer literals that the SimScript program uses directly.
_FLAGS_CREATE        = int(O_CREAT)               # 1
_FLAGS_CREATE_APPEND = int(O_CREAT | O_APPEND)    # 3
_MAP_FLAGS           = int(MAP_FILE | MAP_SHARED)  # 12
_PROT_RW             = int(PROT_READ | PROT_WRITE) # 3
_EAGAIN              = -11

SRC = f"""\
def main():
    write(1, "parent: hi\\n")
    pid = fork()
    if pid == 0:
        write(1, "child: hi\\n")
        exit(42)
    status = 0
    while waitpid(pid, status) == {_EAGAIN}:
        pass
    write(1, "parent: waited\\n")
    fd = open("/tmp/init.log", {_FLAGS_CREATE_APPEND})
    write(fd, "init log\\n")
    close(fd)
    fd2 = open("/tmp/mm.txt", {_FLAGS_CREATE})
    write(fd2, "hello\\n")
    ptr = mmap(0, 4096, {_PROT_RW}, {_MAP_FLAGS}, fd2, 0)
    store64(ptr, deref64("WORLD"))
    munmap(ptr, 4096)
    close(fd2)
    exit(0)
"""
# Note: 384263178567 == int.from_bytes(b"WORLD\x00\x00\x00", "little")


def main() -> None:
    physmem = PhysMem(size_bytes=1024 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=2048)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    rvx = simscript_compile(SRC)

    inode = fs.create_file("/bin/initscript")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/initscript\x00", user=True)

    entry = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    k.run_user_rv64(pid, entry)

    # Verify filesystem side effects (same as m15)
    log_inode = fs.lookup("/tmp/init.log")
    assert log_inode is not None, "/tmp/init.log not found"
    raw = fs.read_inode(log_inode, 0, 64)
    assert b"init log" in raw, f"/tmp/init.log content wrong: {raw!r}"

    mm_inode = fs.lookup("/tmp/mm.txt")
    assert mm_inode is not None, "/tmp/mm.txt not found"
    raw2 = fs.read_inode(mm_inode, 0, 16)
    assert raw2.startswith(b"WORLD"), f"/tmp/mm.txt content wrong: {raw2!r}"

    print("\nM18 SimScript init demo ok — same side effects as m15 verified")


if __name__ == "__main__":
    main()
