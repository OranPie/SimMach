from __future__ import annotations

from dataclasses import dataclass, field

from simmach.errors import InvalidAddress
from simmach.mem import AddressSpace


def _u32(x: int) -> int:
    return int(x) & 0xFFFF_FFFF


def _u64(x: int) -> int:
    return int(x) & 0xFFFF_FFFF_FFFF_FFFF


def _i64(x: int) -> int:
    x = _u64(x)
    if x & (1 << 63):
        return int(x - (1 << 64))
    return int(x)


def _sext32(x: int) -> int:
    x = int(x) & 0xFFFF_FFFF
    if x & (1 << 31):
        return int(x - (1 << 32))
    return int(x)


def _sign_extend(x: int, bits: int) -> int:
    x = int(x) & ((1 << bits) - 1)
    sign = 1 << (bits - 1)
    return int((x ^ sign) - sign)


def _get_bits(x: int, lo: int, hi: int) -> int:
    # inclusive bit range [lo, hi]
    mask = (1 << (hi - lo + 1)) - 1
    return (int(x) >> lo) & mask


def _imm_i(insn: int) -> int:
    return _sign_extend(_get_bits(insn, 20, 31), 12)


def _imm_s(insn: int) -> int:
    imm = (_get_bits(insn, 7, 11) | (_get_bits(insn, 25, 31) << 5))
    return _sign_extend(imm, 12)


def _imm_b(insn: int) -> int:
    imm = (
        (_get_bits(insn, 8, 11) << 1)
        | (_get_bits(insn, 25, 30) << 5)
        | (_get_bits(insn, 7, 7) << 11)
        | (_get_bits(insn, 31, 31) << 12)
    )
    return _sign_extend(imm, 13)


def _imm_u(insn: int) -> int:
    return _sign_extend(_get_bits(insn, 12, 31) << 12, 32)


def _imm_j(insn: int) -> int:
    imm = (
        (_get_bits(insn, 21, 30) << 1)
        | (_get_bits(insn, 20, 20) << 11)
        | (_get_bits(insn, 12, 19) << 12)
        | (_get_bits(insn, 31, 31) << 20)
    )
    return _sign_extend(imm, 21)


@dataclass(slots=True)
class RiscVCPU:
    aspace: AddressSpace
    pc: int
    regs: list[int] = field(default_factory=lambda: [0] * 32)

    def _read_u32_exec(self, addr: int) -> int:
        # Instruction fetch should require X permission.
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned instruction fetch")
        phys, _ = self.aspace.pagetable.walk(int(addr), execute=True, user=True)
        raw = self.aspace.physmem.read(int(phys), 4)
        return int.from_bytes(raw, "little", signed=False)

    def _read_u8(self, addr: int) -> int:
        raw = self.aspace.read(int(addr), 1, user=True)
        return int(raw[0])

    def _read_u16(self, addr: int) -> int:
        if (int(addr) & 1) != 0:
            raise InvalidAddress("misaligned halfword load")
        raw = self.aspace.read(int(addr), 2, user=True)
        return int.from_bytes(raw, "little", signed=False)

    def _read_u32(self, addr: int) -> int:
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned word load")
        raw = self.aspace.read(int(addr), 4, user=True)
        return int.from_bytes(raw, "little", signed=False)

    def _read_u64(self, addr: int) -> int:
        if (int(addr) & 7) != 0:
            raise InvalidAddress("misaligned doubleword load")
        raw = self.aspace.read(int(addr), 8, user=True)
        return int.from_bytes(raw, "little", signed=False)

    def _write_u8(self, addr: int, val: int) -> None:
        self.aspace.write(int(addr), bytes([int(val) & 0xFF]), user=True)

    def _write_u16(self, addr: int, val: int) -> None:
        if (int(addr) & 1) != 0:
            raise InvalidAddress("misaligned halfword store")
        self.aspace.write(int(addr), int(val & 0xFFFF).to_bytes(2, "little", signed=False), user=True)

    def _write_u32(self, addr: int, val: int) -> None:
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned word store")
        self.aspace.write(int(addr), int(val & 0xFFFF_FFFF).to_bytes(4, "little", signed=False), user=True)

    def _write_u64(self, addr: int, val: int) -> None:
        if (int(addr) & 7) != 0:
            raise InvalidAddress("misaligned doubleword store")
        self.aspace.write(int(addr), int(val).to_bytes(8, "little", signed=False), user=True)

    def _set_reg(self, rd: int, val: int) -> None:
        if rd == 0:
            return
        self.regs[rd] = _u64(val)

    def step(self, syscall_cb) -> None:
        insn = self._read_u32_exec(self.pc)
        opcode = _get_bits(insn, 0, 6)

        if opcode == 0x17:  # AUIPC
            rd = _get_bits(insn, 7, 11)
            imm = _imm_u(insn)
            self._set_reg(rd, int(self.pc) + int(imm))
            self.pc = _u64(self.pc + 4)
            return

        if opcode == 0x37:  # LUI
            rd = _get_bits(insn, 7, 11)
            imm = _imm_u(insn)
            self._set_reg(rd, imm)
            self.pc = _u64(self.pc + 4)
            return

        if opcode == 0x13:  # OP-IMM
            rd = _get_bits(insn, 7, 11)
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            imm = _imm_i(insn)

            if funct3 == 0x0:  # ADDI
                self._set_reg(rd, self.regs[rs1] + imm)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x2:  # SLTI
                self._set_reg(rd, 1 if _i64(self.regs[rs1]) < int(imm) else 0)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x3:  # SLTIU
                self._set_reg(rd, 1 if _u64(self.regs[rs1]) < _u64(imm) else 0)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x4:  # XORI
                self._set_reg(rd, self.regs[rs1] ^ _u64(imm))
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x6:  # ORI
                self._set_reg(rd, self.regs[rs1] | _u64(imm))
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x7:  # ANDI
                self._set_reg(rd, self.regs[rs1] & _u64(imm))
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x1:  # SLLI
                shamt = _get_bits(insn, 20, 25)
                self._set_reg(rd, _u64(self.regs[rs1] << shamt))
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x5:
                shamt = _get_bits(insn, 20, 25)
                funct7 = _get_bits(insn, 25, 31)
                if funct7 == 0x00:  # SRLI
                    self._set_reg(rd, _u64(self.regs[rs1]) >> shamt)
                    self.pc = _u64(self.pc + 4)
                    return
                if funct7 == 0x20:  # SRAI
                    self._set_reg(rd, _u64(_i64(self.regs[rs1]) >> shamt))
                    self.pc = _u64(self.pc + 4)
                    return
                raise RuntimeError("unsupported shift-right")

            raise RuntimeError(f"unsupported OP-IMM funct3={funct3}")

        if opcode == 0x33:  # OP
            rd = _get_bits(insn, 7, 11)
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            rs2 = _get_bits(insn, 20, 24)
            funct7 = _get_bits(insn, 25, 31)

            a = int(self.regs[rs1])
            b = int(self.regs[rs2])

            if funct3 == 0x0:
                if funct7 == 0x00:  # ADD
                    self._set_reg(rd, a + b)
                    self.pc = _u64(self.pc + 4)
                    return
                if funct7 == 0x20:  # SUB
                    self._set_reg(rd, a - b)
                    self.pc = _u64(self.pc + 4)
                    return

            if funct3 == 0x1 and funct7 == 0x00:  # SLL
                self._set_reg(rd, _u64(a << (b & 0x3F)))
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x2 and funct7 == 0x00:  # SLT
                self._set_reg(rd, 1 if _i64(a) < _i64(b) else 0)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x3 and funct7 == 0x00:  # SLTU
                self._set_reg(rd, 1 if _u64(a) < _u64(b) else 0)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x4 and funct7 == 0x00:  # XOR
                self._set_reg(rd, a ^ b)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x5:
                if funct7 == 0x00:  # SRL
                    self._set_reg(rd, _u64(a) >> (b & 0x3F))
                    self.pc = _u64(self.pc + 4)
                    return
                if funct7 == 0x20:  # SRA
                    self._set_reg(rd, _u64(_i64(a) >> (b & 0x3F)))
                    self.pc = _u64(self.pc + 4)
                    return

            if funct3 == 0x6 and funct7 == 0x00:  # OR
                self._set_reg(rd, a | b)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x7 and funct7 == 0x00:  # AND
                self._set_reg(rd, a & b)
                self.pc = _u64(self.pc + 4)
                return

            raise RuntimeError(
                f"unsupported OP pc={int(self.pc):#x} insn={int(insn):#x} funct3={int(funct3):#x} funct7={int(funct7):#x}"
            )

        if opcode == 0x1B:  # OP-IMM-32
            rd = _get_bits(insn, 7, 11)
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            imm = _imm_i(insn)

            if funct3 == 0x0:  # ADDIW
                v = _sext32(_sext32(self.regs[rs1]) + int(imm))
                self._set_reg(rd, v)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x1:  # SLLIW
                shamt = _get_bits(insn, 20, 24)
                v = _sext32((int(self.regs[rs1]) & 0xFFFF_FFFF) << shamt)
                self._set_reg(rd, v)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x5:
                shamt = _get_bits(insn, 20, 24)
                funct7 = _get_bits(insn, 25, 31)
                if funct7 == 0x00:  # SRLIW
                    v = (int(self.regs[rs1]) & 0xFFFF_FFFF) >> shamt
                    self._set_reg(rd, _sext32(v))
                    self.pc = _u64(self.pc + 4)
                    return
                if funct7 == 0x20:  # SRAIW
                    v = _sext32(self.regs[rs1]) >> shamt
                    self._set_reg(rd, _sext32(v))
                    self.pc = _u64(self.pc + 4)
                    return
                raise RuntimeError("unsupported shift-right-imm-32")

            raise RuntimeError("unsupported OP-IMM-32")

        if opcode == 0x3B:  # OP-32
            rd = _get_bits(insn, 7, 11)
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            rs2 = _get_bits(insn, 20, 24)
            funct7 = _get_bits(insn, 25, 31)

            a = int(self.regs[rs1])
            b = int(self.regs[rs2])

            if funct3 == 0x0:
                if funct7 == 0x00:  # ADDW
                    self._set_reg(rd, _sext32(_sext32(a) + _sext32(b)))
                    self.pc = _u64(self.pc + 4)
                    return
                if funct7 == 0x20:  # SUBW
                    self._set_reg(rd, _sext32(_sext32(a) - _sext32(b)))
                    self.pc = _u64(self.pc + 4)
                    return

            if funct3 == 0x1 and funct7 == 0x00:  # SLLW
                shamt = int(b) & 0x1F
                v = _sext32((int(a) & 0xFFFF_FFFF) << shamt)
                self._set_reg(rd, v)
                self.pc = _u64(self.pc + 4)
                return

            if funct3 == 0x5:
                shamt = int(b) & 0x1F
                if funct7 == 0x00:  # SRLW
                    v = (int(a) & 0xFFFF_FFFF) >> shamt
                    self._set_reg(rd, _sext32(v))
                    self.pc = _u64(self.pc + 4)
                    return
                if funct7 == 0x20:  # SRAW
                    v = _sext32(a) >> shamt
                    self._set_reg(rd, _sext32(v))
                    self.pc = _u64(self.pc + 4)
                    return

            raise RuntimeError("unsupported OP-32")

        if opcode == 0x03:  # LOAD
            rd = _get_bits(insn, 7, 11)
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            imm = _imm_i(insn)
            addr = _u64(self.regs[rs1] + imm)

            if funct3 == 0x0:  # LB
                v = self._read_u8(addr)
                self._set_reg(rd, _sign_extend(v, 8))
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x1:  # LH
                v = self._read_u16(addr)
                self._set_reg(rd, _sign_extend(v, 16))
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x2:  # LW
                v = self._read_u32(addr)
                self._set_reg(rd, _sign_extend(v, 32))
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x3:  # LD
                self._set_reg(rd, self._read_u64(addr))
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x4:  # LBU
                v = self._read_u8(addr)
                self._set_reg(rd, v)
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x5:  # LHU
                v = self._read_u16(addr)
                self._set_reg(rd, v)
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x6:  # LWU
                v = self._read_u32(addr)
                self._set_reg(rd, v)
                self.pc = _u64(self.pc + 4)
                return

            raise RuntimeError("unsupported LOAD")

        if opcode == 0x23:  # STORE
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            rs2 = _get_bits(insn, 20, 24)
            imm = _imm_s(insn)
            addr = _u64(self.regs[rs1] + imm)

            if funct3 == 0x0:  # SB
                self._write_u8(addr, self.regs[rs2])
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x1:  # SH
                self._write_u16(addr, self.regs[rs2])
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x2:  # SW
                self._write_u32(addr, self.regs[rs2])
                self.pc = _u64(self.pc + 4)
                return
            if funct3 == 0x3:  # SD
                self._write_u64(addr, self.regs[rs2])
                self.pc = _u64(self.pc + 4)
                return

            raise RuntimeError("unsupported STORE")

        if opcode == 0x63:  # BRANCH
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            rs2 = _get_bits(insn, 20, 24)
            imm = _imm_b(insn)

            taken = False
            if funct3 == 0x0:  # BEQ
                taken = self.regs[rs1] == self.regs[rs2]
            elif funct3 == 0x1:  # BNE
                taken = self.regs[rs1] != self.regs[rs2]
            elif funct3 == 0x4:  # BLT
                taken = _i64(self.regs[rs1]) < _i64(self.regs[rs2])
            elif funct3 == 0x5:  # BGE
                taken = _i64(self.regs[rs1]) >= _i64(self.regs[rs2])
            elif funct3 == 0x6:  # BLTU
                taken = _u64(self.regs[rs1]) < _u64(self.regs[rs2])
            elif funct3 == 0x7:  # BGEU
                taken = _u64(self.regs[rs1]) >= _u64(self.regs[rs2])
            else:
                raise RuntimeError(f"unsupported BRANCH funct3={funct3}")

            if taken:
                self.pc = _u64(self.pc + imm)
            else:
                self.pc = _u64(self.pc + 4)
            return

        if opcode == 0x6F:  # JAL
            rd = _get_bits(insn, 7, 11)
            imm = _imm_j(insn)
            next_pc = _u64(self.pc + 4)
            self._set_reg(rd, next_pc)
            self.pc = _u64(self.pc + imm)
            return

        if opcode == 0x67:  # JALR
            rd = _get_bits(insn, 7, 11)
            funct3 = _get_bits(insn, 12, 14)
            rs1 = _get_bits(insn, 15, 19)
            imm = _imm_i(insn)
            if funct3 != 0x0:
                raise RuntimeError(f"unsupported JALR funct3={funct3}")
            next_pc = _u64(self.pc + 4)
            target = _u64(self.regs[rs1] + imm) & ~1
            self._set_reg(rd, next_pc)
            self.pc = target
            return

        if opcode == 0x73:  # SYSTEM
            funct3 = _get_bits(insn, 12, 14)
            imm12 = _get_bits(insn, 20, 31)
            if funct3 == 0x0 and imm12 == 0:  # ECALL
                syscall_cb(self)
                self.pc = _u64(self.pc + 4)
                return
            raise RuntimeError("unsupported SYSTEM")

        raise RuntimeError(f"unsupported opcode={opcode:#x}")

    def run(self, syscall_cb, *, max_steps: int = 200_000) -> None:
        for _ in range(int(max_steps)):
            self.regs[0] = 0
            try:
                self.step(syscall_cb)
            except InvalidAddress:
                raise
        raise RuntimeError("rv64 program did not finish")
