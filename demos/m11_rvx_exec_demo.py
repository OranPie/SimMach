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
    return _u32((imm20 << 12) | (rd << 7) | opcode)


def _enc_i(opcode: int, rd: int, funct3: int, rs1: int, imm12: int) -> int:
    imm12 &= 0xFFF
    return _u32((imm12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode)


def _lui(rd: int, imm20: int) -> int:
    return _enc_u(0x37, rd, imm20)


def _addi(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x13, rd, 0x0, rs1, imm12)


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

    msg = b"/bin/init: hello from RVX exec!\n"

    entry = 0x1000_0000
    code: list[int] = []
    # a0=fd(1), a1=buf(addr), a2=len, a7=sysno
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, entry + 0x200)
    _load_imm32(code, 12, len(msg))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())
    _load_imm32(code, 10, 0)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    code_blob = b"".join(struct.pack("<I", insn) for insn in code)
    payload = code_blob + b"\x00" * (0x200 - len(code_blob)) + msg

    ph = RvProgramHeaderV1(
        type=PT_LOAD,
        flags=PF_R | PF_X,
        vaddr=entry,
        file_off=0,
        file_size=len(payload),
        mem_size=len(payload),
    )
    rvx = build_rvexe_v1(entry=entry, segments=[ph], payloads=[payload])

    init_inode = fs.create_file("/bin/init")
    fs.write_inode(init_inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/init\x00", user=True)

    entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    assert entry_ret == entry

    k.run_user_rv64(pid, entry_ret)


if __name__ == "__main__":
    main()
