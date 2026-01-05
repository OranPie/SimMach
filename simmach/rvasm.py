from __future__ import annotations


def u32(x: int) -> int:
    return int(x) & 0xFFFF_FFFF


def enc_u(opcode: int, rd: int, imm20: int) -> int:
    return u32((int(imm20) << 12) | (int(rd) << 7) | int(opcode))


def enc_i(opcode: int, rd: int, funct3: int, rs1: int, imm12: int) -> int:
    imm12 &= 0xFFF
    return u32((imm12 << 20) | (int(rs1) << 15) | (int(funct3) << 12) | (int(rd) << 7) | int(opcode))


def enc_s(opcode: int, funct3: int, rs1: int, rs2: int, imm12: int) -> int:
    imm12 &= 0xFFF
    imm_lo = imm12 & 0x1F
    imm_hi = (imm12 >> 5) & 0x7F
    return u32((imm_hi << 25) | (int(rs2) << 20) | (int(rs1) << 15) | (int(funct3) << 12) | (imm_lo << 7) | int(opcode))


def enc_b(opcode: int, funct3: int, rs1: int, rs2: int, off: int) -> int:
    if (int(off) & 1) != 0:
        raise ValueError("branch offset must be 2-byte aligned")
    imm = int(off)
    imm &= 0x1FFF
    imm_12 = (imm >> 12) & 0x1
    imm_10_5 = (imm >> 5) & 0x3F
    imm_4_1 = (imm >> 1) & 0xF
    imm_11 = (imm >> 11) & 0x1
    return u32(
        (imm_12 << 31)
        | (imm_10_5 << 25)
        | (int(rs2) << 20)
        | (int(rs1) << 15)
        | (int(funct3) << 12)
        | (imm_4_1 << 8)
        | (imm_11 << 7)
        | int(opcode)
    )


def enc_j(opcode: int, rd: int, off: int) -> int:
    if (int(off) & 1) != 0:
        raise ValueError("jal offset must be 2-byte aligned")
    imm = int(off)
    imm &= 0x1FFFFF
    imm_20 = (imm >> 20) & 0x1
    imm_10_1 = (imm >> 1) & 0x3FF
    imm_11 = (imm >> 11) & 0x1
    imm_19_12 = (imm >> 12) & 0xFF
    return u32(
        (imm_20 << 31)
        | (imm_10_1 << 21)
        | (imm_11 << 20)
        | (imm_19_12 << 12)
        | (int(rd) << 7)
        | int(opcode)
    )


def enc_r(opcode: int, rd: int, funct3: int, rs1: int, rs2: int, funct7: int) -> int:
    return u32(
        (int(funct7) << 25)
        | (int(rs2) << 20)
        | (int(rs1) << 15)
        | (int(funct3) << 12)
        | (int(rd) << 7)
        | int(opcode)
    )


def lui(rd: int, imm20: int) -> int:
    return enc_u(0x37, rd, imm20)


def auipc(rd: int, imm20: int) -> int:
    return enc_u(0x17, rd, imm20)


def addi(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x13, rd, 0x0, rs1, imm12)


def andi(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x13, rd, 0x7, rs1, imm12)


def ori(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x13, rd, 0x6, rs1, imm12)


def xori(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x13, rd, 0x4, rs1, imm12)


def slli(rd: int, rs1: int, shamt: int) -> int:
    imm = int(shamt) & 0x3F
    return enc_i(0x13, rd, 0x1, rs1, imm)


def srli(rd: int, rs1: int, shamt: int) -> int:
    imm = int(shamt) & 0x3F
    return enc_i(0x13, rd, 0x5, rs1, imm)


def srai(rd: int, rs1: int, shamt: int) -> int:
    imm = (0x20 << 5) | (int(shamt) & 0x3F)
    return enc_i(0x13, rd, 0x5, rs1, imm)


def ld(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x03, rd, 0x3, rs1, imm12)


def lb(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x03, rd, 0x0, rs1, imm12)


def lbu(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x03, rd, 0x4, rs1, imm12)


def lw(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x03, rd, 0x2, rs1, imm12)


def sd(rs2: int, rs1: int, imm12: int) -> int:
    return enc_s(0x23, 0x3, rs1, rs2, imm12)


def sb(rs2: int, rs1: int, imm12: int) -> int:
    return enc_s(0x23, 0x0, rs1, rs2, imm12)


def sw(rs2: int, rs1: int, imm12: int) -> int:
    return enc_s(0x23, 0x2, rs1, rs2, imm12)


def beq(rs1: int, rs2: int, off: int) -> int:
    return enc_b(0x63, 0x0, rs1, rs2, off)


def bne(rs1: int, rs2: int, off: int) -> int:
    return enc_b(0x63, 0x1, rs1, rs2, off)


def blt(rs1: int, rs2: int, off: int) -> int:
    return enc_b(0x63, 0x4, rs1, rs2, off)


def bge(rs1: int, rs2: int, off: int) -> int:
    return enc_b(0x63, 0x5, rs1, rs2, off)


def bltu(rs1: int, rs2: int, off: int) -> int:
    return enc_b(0x63, 0x6, rs1, rs2, off)


def bgeu(rs1: int, rs2: int, off: int) -> int:
    return enc_b(0x63, 0x7, rs1, rs2, off)


def jal(rd: int, off: int) -> int:
    return enc_j(0x6F, rd, off)


def jalr(rd: int, rs1: int, imm12: int = 0) -> int:
    return enc_i(0x67, rd, 0x0, rs1, imm12)


def add(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x0, rs1, rs2, 0x00)


def sub(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x0, rs1, rs2, 0x20)


def and_(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x7, rs1, rs2, 0x00)


def or_(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x6, rs1, rs2, 0x00)


def xor(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x4, rs1, rs2, 0x00)


def slt(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x2, rs1, rs2, 0x00)


def sltu(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x33, rd, 0x3, rs1, rs2, 0x00)


def ecall() -> int:
    return 0x0000_0073


def addiw(rd: int, rs1: int, imm12: int) -> int:
    return enc_i(0x1B, rd, 0x0, rs1, imm12)


def addw(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x3B, rd, 0x0, rs1, rs2, 0x00)


def subw(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x3B, rd, 0x0, rs1, rs2, 0x20)


def slliw(rd: int, rs1: int, shamt: int) -> int:
    imm = int(shamt) & 0x1F
    return enc_i(0x1B, rd, 0x1, rs1, imm)


def srliw(rd: int, rs1: int, shamt: int) -> int:
    imm = int(shamt) & 0x1F
    return enc_i(0x1B, rd, 0x5, rs1, imm)


def sraiw(rd: int, rs1: int, shamt: int) -> int:
    imm = (0x20 << 5) | (int(shamt) & 0x1F)
    return enc_i(0x1B, rd, 0x5, rs1, imm)


def sllw(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x3B, rd, 0x1, rs1, rs2, 0x00)


def srlw(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x3B, rd, 0x5, rs1, rs2, 0x00)


def sraw(rd: int, rs1: int, rs2: int) -> int:
    return enc_r(0x3B, rd, 0x5, rs1, rs2, 0x20)
