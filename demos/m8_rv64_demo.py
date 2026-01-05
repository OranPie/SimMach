from __future__ import annotations

import struct

from constants import PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE, Sysno
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem


def _u32(x: int) -> int:
    return int(x) & 0xFFFF_FFFF


def _enc_u(opcode: int, rd: int, imm20: int) -> int:
    return _u32((imm20 << 12) | (rd << 7) | opcode)


def _enc_i(opcode: int, rd: int, funct3: int, rs1: int, imm12: int) -> int:
    imm12 &= 0xFFF
    return _u32((imm12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode)


def _enc_s(opcode: int, funct3: int, rs1: int, rs2: int, imm12: int) -> int:
    imm12 &= 0xFFF
    imm_lo = imm12 & 0x1F
    imm_hi = (imm12 >> 5) & 0x7F
    return _u32((imm_hi << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (imm_lo << 7) | opcode)


def _lui(rd: int, imm20: int) -> int:
    return _enc_u(0x37, rd, imm20)


def _addi(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x13, rd, 0x0, rs1, imm12)


def _ld(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x03, rd, 0x3, rs1, imm12)


def _sd(rs2: int, rs1: int, imm12: int) -> int:
    return _enc_s(0x23, 0x3, rs1, rs2, imm12)


def _ecall() -> int:
    return 0x0000_0073


def _load_imm64(code: list[int], rd: int, val: int) -> None:
    # Minimal: assume val fits in signed 32-bit for now.
    if val < -(1 << 31) or val > (1 << 31) - 1:
        raise ValueError("val out of range for demo")
    upper = (val + (1 << 11)) >> 12
    low = val - (upper << 12)
    code.append(_lui(rd, upper & 0xFFFFF))
    code.append(_addi(rd, rd, low))


def main() -> None:
    physmem = PhysMem(size_bytes=512 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)
    k = Kernel(kas)

    pid = k.create_process()
    aspace = k.processes[pid].aspace

    code_base = 0x1000_0000
    data_base = 0x1000_1000

    # Code page: RWX for simplicity in demo.
    aspace.map_page(code_base, PageFlags.USER | PageFlags.R | PageFlags.W | PageFlags.X)
    # Data page: RW.
    aspace.map_page(data_base, PageFlags.USER | PageFlags.R | PageFlags.W)

    msg = b"hello from rv64!\n"
    aspace.write(data_base, msg, user=True)

    # RV regs:
    # a0=x10, a1=x11, a2=x12, a7=x17
    code: list[int] = []

    _load_imm64(code, 10, 1)  # a0 = fd=1
    _load_imm64(code, 11, data_base)  # a1 = buf
    _load_imm64(code, 12, len(msg))  # a2 = count
    _load_imm64(code, 17, int(Sysno.WRITE))  # a7 = sysno
    code.append(_ecall())

    _load_imm64(code, 10, 0)  # a0 = status
    _load_imm64(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    blob = b"".join(struct.pack("<I", insn) for insn in code)
    aspace.write(code_base, blob, user=True)

    k.run_user_rv64(pid, code_base)


if __name__ == "__main__":
    main()
