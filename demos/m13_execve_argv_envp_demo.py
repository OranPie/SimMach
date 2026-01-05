from __future__ import annotations

import struct

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.rvexe import PF_R, PF_X, PT_LOAD, RvProgramHeaderV1, build_rvexe_v1
from simmach.syscall import TrapFrame


def _u32(x: int) -> int:
    return int(x) & 0xFFFF_FFFF


def _enc_u(opcode: int, rd: int, imm20: int) -> int:
    return _u32((int(imm20) << 12) | (int(rd) << 7) | int(opcode))


def _enc_i(opcode: int, rd: int, funct3: int, rs1: int, imm12: int) -> int:
    imm12 &= 0xFFF
    return _u32((imm12 << 20) | (int(rs1) << 15) | (int(funct3) << 12) | (int(rd) << 7) | int(opcode))


def _lui(rd: int, imm20: int) -> int:
    return _enc_u(0x37, rd, imm20)


def _addi(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x13, rd, 0x0, rs1, imm12)


def _ld(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x03, rd, 0x3, rs1, imm12)


def _ecall() -> int:
    return 0x0000_0073


def _load_imm32(code: list[int], rd: int, val: int) -> None:
    upper = (int(val) + (1 << 11)) >> 12
    low = int(val) - (upper << 12)
    code.append(_lui(rd, upper & 0xFFFFF))
    code.append(_addi(rd, rd, low))


def main() -> None:
    physmem = PhysMem(size_bytes=512 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=1024)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    entry = 0x1000_0000

    # User program prints argv[0] (fixed 8 bytes) then envp[0] (fixed 12 bytes)
    # using a1(argv) and a2(envp). We ensure argv0/envp0 have these lengths.
    code: list[int] = []

    # Preserve envp pointer (a2) because we will clobber a2 as syscall arg.
    code.append(_addi(7, 12, 0))

    # t0 = argv0_ptr = *(a1)
    code.append(_ld(5, 11, 0))
    # write(fd=1, buf=t0, count=8)
    _load_imm32(code, 10, 1)
    code.append(_addi(11, 5, 0))
    _load_imm32(code, 12, 8)
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())

    # t1 = envp0_ptr = *(saved_envp_ptr)
    code.append(_ld(6, 7, 0))
    _load_imm32(code, 10, 1)
    code.append(_addi(11, 6, 0))
    _load_imm32(code, 12, 12)
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())

    _load_imm32(code, 10, 0)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    code_blob = b"".join(struct.pack("<I", insn) for insn in code)

    ph = RvProgramHeaderV1(
        type=PT_LOAD,
        flags=PF_R | PF_X,
        vaddr=entry,
        file_off=0,
        file_size=len(code_blob),
        mem_size=len(code_blob),
    )
    rvx = build_rvexe_v1(entry=entry, segments=[ph], payloads=[code_blob])

    prog = fs.create_file("/bin/printargs")
    fs.write_inode(prog, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)

    # layout in caller address space:
    # [path cstr]
    # [argv0 cstr][argv array]
    # [envp0 cstr][envp array]
    path_ptr = user_base
    argv0_ptr = user_base + 0x80
    argv_arr = user_base + 0x100
    envp0_ptr = user_base + 0x180
    envp_arr = user_base + 0x200

    aspace.write(path_ptr, b"/bin/printargs\x00", user=True)

    argv0 = b"argv0!!!"  # 8 bytes
    envp0 = b"KEY=VALUE!!\n"  # 12 bytes
    aspace.write(argv0_ptr, argv0, user=True)
    aspace.write(envp0_ptr, envp0, user=True)

    aspace.write(argv_arr, struct.pack("<QQ", argv0_ptr, 0), user=True)
    aspace.write(envp_arr, struct.pack("<QQ", envp0_ptr, 0), user=True)

    entry_ret = k.syscalls.dispatch(
        k,
        pid,
        TrapFrame(rax=int(Sysno.EXECVE), rdi=path_ptr, rsi=argv_arr, rdx=envp_arr),
    )
    assert entry_ret == entry

    k.run_user_rv64(pid, entry_ret)

    print("\nM13 execve argv/envp demo ok")


if __name__ == "__main__":
    main()
