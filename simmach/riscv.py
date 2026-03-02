from __future__ import annotations

from dataclasses import dataclass, field

from simmach.errors import InvalidAddress
from simmach.mem import AddressSpace


def _u64(x: int) -> int:
    return int(x) & 0xFFFF_FFFF_FFFF_FFFF


_MASK64 = 0xFFFF_FFFF_FFFF_FFFF


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


def _imm_i(insn: int) -> int:
    return _sign_extend(int(insn) >> 20, 12)


def _imm_s(insn: int) -> int:
    imm = ((int(insn) >> 7) & 0x1F) | (((int(insn) >> 25) & 0x7F) << 5)
    return _sign_extend(imm, 12)


def _imm_b(insn: int) -> int:
    imm = (
        (((int(insn) >> 8) & 0xF) << 1)
        | (((int(insn) >> 25) & 0x3F) << 5)
        | (((int(insn) >> 7) & 0x1) << 11)
        | (((int(insn) >> 31) & 0x1) << 12)
    )
    return _sign_extend(imm, 13)


def _imm_u(insn: int) -> int:
    return _sign_extend(int(insn) & 0xFFFFF000, 32)


def _imm_j(insn: int) -> int:
    imm = (
        (((int(insn) >> 21) & 0x3FF) << 1)
        | (((int(insn) >> 20) & 0x1) << 11)
        | (((int(insn) >> 12) & 0xFF) << 12)
        | (((int(insn) >> 31) & 0x1) << 20)
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
        return int(self.aspace.read_exec_u32(int(addr), user=True))

    def _read_u8(self, addr: int) -> int:
        return int(self.aspace.read_u8(int(addr), user=True))

    def _read_u16(self, addr: int) -> int:
        if (int(addr) & 1) != 0:
            raise InvalidAddress("misaligned halfword load")
        return int(self.aspace.read_u16(int(addr), user=True))

    def _read_u32(self, addr: int) -> int:
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned word load")
        return int(self.aspace.read_u32(int(addr), user=True))

    def _read_u64(self, addr: int) -> int:
        if (int(addr) & 7) != 0:
            raise InvalidAddress("misaligned doubleword load")
        return int(self.aspace.read_u64(int(addr), user=True))

    def _write_u8(self, addr: int, val: int) -> None:
        self.aspace.write_u8(int(addr), int(val), user=True)

    def _write_u16(self, addr: int, val: int) -> None:
        if (int(addr) & 1) != 0:
            raise InvalidAddress("misaligned halfword store")
        self.aspace.write_u16(int(addr), int(val), user=True)

    def _write_u32(self, addr: int, val: int) -> None:
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned word store")
        self.aspace.write_u32(int(addr), int(val), user=True)

    def _write_u64(self, addr: int, val: int) -> None:
        if (int(addr) & 7) != 0:
            raise InvalidAddress("misaligned doubleword store")
        self.aspace.write_u64(int(addr), int(val), user=True)

    def _set_reg(self, rd: int, val: int) -> None:
        if rd == 0:
            return
        self.regs[rd] = _u64(val)

    def step(self, syscall_cb) -> None:
        pc = int(self.pc)
        next_pc = (pc + 4) & _MASK64
        regs = self.regs
        set_reg = self._set_reg
        insn = self._read_u32_exec(pc)
        opcode = int(insn) & 0x7F

        if opcode == 0x17:  # AUIPC
            rd = (int(insn) >> 7) & 0x1F
            imm = _imm_u(insn)
            set_reg(rd, pc + int(imm))
            self.pc = next_pc
            return

        if opcode == 0x37:  # LUI
            rd = (int(insn) >> 7) & 0x1F
            set_reg(rd, _imm_u(insn))
            self.pc = next_pc
            return

        if opcode == 0x13:  # OP-IMM
            rd = (int(insn) >> 7) & 0x1F
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            imm = _imm_i(insn)

            if funct3 == 0x0:  # ADDI
                set_reg(rd, int(regs[rs1]) + int(imm))
                self.pc = next_pc
                return

            if funct3 == 0x2:  # SLTI
                set_reg(rd, 1 if _i64(regs[rs1]) < int(imm) else 0)
                self.pc = next_pc
                return

            if funct3 == 0x3:  # SLTIU
                set_reg(rd, 1 if _u64(regs[rs1]) < _u64(imm) else 0)
                self.pc = next_pc
                return

            if funct3 == 0x4:  # XORI
                set_reg(rd, int(regs[rs1]) ^ _u64(imm))
                self.pc = next_pc
                return

            if funct3 == 0x6:  # ORI
                set_reg(rd, int(regs[rs1]) | _u64(imm))
                self.pc = next_pc
                return

            if funct3 == 0x7:  # ANDI
                set_reg(rd, int(regs[rs1]) & _u64(imm))
                self.pc = next_pc
                return

            if funct3 == 0x1:  # SLLI
                shamt = (int(insn) >> 20) & 0x3F
                set_reg(rd, int(regs[rs1]) << shamt)
                self.pc = next_pc
                return

            if funct3 == 0x5:
                shamt = (int(insn) >> 20) & 0x3F
                funct7 = (int(insn) >> 25) & 0x7F
                if funct7 == 0x00:  # SRLI
                    set_reg(rd, _u64(regs[rs1]) >> shamt)
                    self.pc = next_pc
                    return
                if funct7 == 0x20:  # SRAI
                    set_reg(rd, _u64(_i64(regs[rs1]) >> shamt))
                    self.pc = next_pc
                    return
                raise RuntimeError("unsupported shift-right")

            raise RuntimeError(f"unsupported OP-IMM funct3={funct3}")

        if opcode == 0x33:  # OP
            rd = (int(insn) >> 7) & 0x1F
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            rs2 = (int(insn) >> 20) & 0x1F
            funct7 = (int(insn) >> 25) & 0x7F

            a = int(regs[rs1])
            b = int(regs[rs2])

            if funct3 == 0x0:
                if funct7 == 0x00:  # ADD
                    set_reg(rd, a + b)
                    self.pc = next_pc
                    return
                if funct7 == 0x20:  # SUB
                    set_reg(rd, a - b)
                    self.pc = next_pc
                    return
                if funct7 == 0x01:  # MUL (RV64M)
                    set_reg(rd, _i64(a) * _i64(b))
                    self.pc = next_pc
                    return

            if funct3 == 0x4 and funct7 == 0x01:  # DIV (RV64M)
                divisor = _i64(b)
                set_reg(rd, _i64(a) // divisor if divisor != 0 else -1)
                self.pc = next_pc
                return

            if funct3 == 0x6 and funct7 == 0x01:  # REM (RV64M)
                divisor = _i64(b)
                set_reg(rd, _i64(a) % divisor if divisor != 0 else _i64(a))
                self.pc = next_pc
                return

            if funct3 == 0x1 and funct7 == 0x00:  # SLL
                set_reg(rd, a << (b & 0x3F))
                self.pc = next_pc
                return

            if funct3 == 0x2 and funct7 == 0x00:  # SLT
                set_reg(rd, 1 if _i64(a) < _i64(b) else 0)
                self.pc = next_pc
                return

            if funct3 == 0x3 and funct7 == 0x00:  # SLTU
                set_reg(rd, 1 if _u64(a) < _u64(b) else 0)
                self.pc = next_pc
                return

            if funct3 == 0x4 and funct7 == 0x00:  # XOR
                set_reg(rd, a ^ b)
                self.pc = next_pc
                return

            if funct3 == 0x5:
                if funct7 == 0x00:  # SRL
                    set_reg(rd, _u64(a) >> (b & 0x3F))
                    self.pc = next_pc
                    return
                if funct7 == 0x20:  # SRA
                    set_reg(rd, _u64(_i64(a) >> (b & 0x3F)))
                    self.pc = next_pc
                    return

            if funct3 == 0x6 and funct7 == 0x00:  # OR
                set_reg(rd, a | b)
                self.pc = next_pc
                return

            if funct3 == 0x7 and funct7 == 0x00:  # AND
                set_reg(rd, a & b)
                self.pc = next_pc
                return

            raise RuntimeError(
                f"unsupported OP pc={pc:#x} insn={int(insn):#x} funct3={int(funct3):#x} funct7={int(funct7):#x}"
            )

        if opcode == 0x1B:  # OP-IMM-32
            rd = (int(insn) >> 7) & 0x1F
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            imm = _imm_i(insn)

            if funct3 == 0x0:  # ADDIW
                set_reg(rd, _sext32(_sext32(regs[rs1]) + int(imm)))
                self.pc = next_pc
                return

            if funct3 == 0x1:  # SLLIW
                shamt = (int(insn) >> 20) & 0x1F
                set_reg(rd, _sext32((int(regs[rs1]) & 0xFFFF_FFFF) << shamt))
                self.pc = next_pc
                return

            if funct3 == 0x5:
                shamt = (int(insn) >> 20) & 0x1F
                funct7 = (int(insn) >> 25) & 0x7F
                if funct7 == 0x00:  # SRLIW
                    v = (int(regs[rs1]) & 0xFFFF_FFFF) >> shamt
                    set_reg(rd, _sext32(v))
                    self.pc = next_pc
                    return
                if funct7 == 0x20:  # SRAIW
                    set_reg(rd, _sext32(_sext32(regs[rs1]) >> shamt))
                    self.pc = next_pc
                    return
                raise RuntimeError("unsupported shift-right-imm-32")

            raise RuntimeError("unsupported OP-IMM-32")

        if opcode == 0x3B:  # OP-32
            rd = (int(insn) >> 7) & 0x1F
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            rs2 = (int(insn) >> 20) & 0x1F
            funct7 = (int(insn) >> 25) & 0x7F

            a = int(regs[rs1])
            b = int(regs[rs2])

            if funct3 == 0x0:
                if funct7 == 0x00:  # ADDW
                    set_reg(rd, _sext32(_sext32(a) + _sext32(b)))
                    self.pc = next_pc
                    return
                if funct7 == 0x20:  # SUBW
                    set_reg(rd, _sext32(_sext32(a) - _sext32(b)))
                    self.pc = next_pc
                    return

            if funct3 == 0x1 and funct7 == 0x00:  # SLLW
                shamt = b & 0x1F
                set_reg(rd, _sext32((a & 0xFFFF_FFFF) << shamt))
                self.pc = next_pc
                return

            if funct3 == 0x5:
                shamt = b & 0x1F
                if funct7 == 0x00:  # SRLW
                    set_reg(rd, _sext32((a & 0xFFFF_FFFF) >> shamt))
                    self.pc = next_pc
                    return
                if funct7 == 0x20:  # SRAW
                    set_reg(rd, _sext32(_sext32(a) >> shamt))
                    self.pc = next_pc
                    return

            raise RuntimeError("unsupported OP-32")

        if opcode == 0x03:  # LOAD
            rd = (int(insn) >> 7) & 0x1F
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            imm = _imm_i(insn)
            addr = (int(regs[rs1]) + int(imm)) & _MASK64

            if funct3 == 0x0:  # LB
                set_reg(rd, _sign_extend(self._read_u8(addr), 8))
                self.pc = next_pc
                return
            if funct3 == 0x1:  # LH
                set_reg(rd, _sign_extend(self._read_u16(addr), 16))
                self.pc = next_pc
                return
            if funct3 == 0x2:  # LW
                set_reg(rd, _sign_extend(self._read_u32(addr), 32))
                self.pc = next_pc
                return
            if funct3 == 0x3:  # LD
                set_reg(rd, self._read_u64(addr))
                self.pc = next_pc
                return
            if funct3 == 0x4:  # LBU
                set_reg(rd, self._read_u8(addr))
                self.pc = next_pc
                return
            if funct3 == 0x5:  # LHU
                set_reg(rd, self._read_u16(addr))
                self.pc = next_pc
                return
            if funct3 == 0x6:  # LWU
                set_reg(rd, self._read_u32(addr))
                self.pc = next_pc
                return

            raise RuntimeError("unsupported LOAD")

        if opcode == 0x23:  # STORE
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            rs2 = (int(insn) >> 20) & 0x1F
            imm = _imm_s(insn)
            addr = (int(regs[rs1]) + int(imm)) & _MASK64
            v = int(regs[rs2])

            if funct3 == 0x0:  # SB
                self._write_u8(addr, v)
                self.pc = next_pc
                return
            if funct3 == 0x1:  # SH
                self._write_u16(addr, v)
                self.pc = next_pc
                return
            if funct3 == 0x2:  # SW
                self._write_u32(addr, v)
                self.pc = next_pc
                return
            if funct3 == 0x3:  # SD
                self._write_u64(addr, v)
                self.pc = next_pc
                return

            raise RuntimeError("unsupported STORE")

        if opcode == 0x63:  # BRANCH
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            rs2 = (int(insn) >> 20) & 0x1F
            imm = _imm_b(insn)

            taken = False
            if funct3 == 0x0:  # BEQ
                taken = regs[rs1] == regs[rs2]
            elif funct3 == 0x1:  # BNE
                taken = regs[rs1] != regs[rs2]
            elif funct3 == 0x4:  # BLT
                taken = _i64(regs[rs1]) < _i64(regs[rs2])
            elif funct3 == 0x5:  # BGE
                taken = _i64(regs[rs1]) >= _i64(regs[rs2])
            elif funct3 == 0x6:  # BLTU
                taken = _u64(regs[rs1]) < _u64(regs[rs2])
            elif funct3 == 0x7:  # BGEU
                taken = _u64(regs[rs1]) >= _u64(regs[rs2])
            else:
                raise RuntimeError(f"unsupported BRANCH funct3={funct3}")

            self.pc = (pc + int(imm)) & _MASK64 if taken else next_pc
            return

        if opcode == 0x6F:  # JAL
            rd = (int(insn) >> 7) & 0x1F
            set_reg(rd, next_pc)
            self.pc = (pc + int(_imm_j(insn))) & _MASK64
            return

        if opcode == 0x67:  # JALR
            rd = (int(insn) >> 7) & 0x1F
            funct3 = (int(insn) >> 12) & 0x7
            rs1 = (int(insn) >> 15) & 0x1F
            if funct3 != 0x0:
                raise RuntimeError(f"unsupported JALR funct3={funct3}")
            target = ((int(regs[rs1]) + int(_imm_i(insn))) & _MASK64) & ~1
            set_reg(rd, next_pc)
            self.pc = target
            return

        if opcode == 0x73:  # SYSTEM
            funct3 = (int(insn) >> 12) & 0x7
            imm12 = (int(insn) >> 20) & 0xFFF
            if funct3 == 0x0 and imm12 == 0:  # ECALL
                syscall_cb(self)
                # Syscall handlers may have adjusted pc (e.g. execve trampoline).
                self.pc = (int(self.pc) + 4) & _MASK64
                return
            raise RuntimeError("unsupported SYSTEM")

        raise RuntimeError(f"unsupported opcode={opcode:#x}")

    def run(self, syscall_cb, *, max_steps: int = 200_000) -> None:
        regs = self.regs
        step = self.step
        try:
            for _ in range(int(max_steps)):
                regs[0] = 0
                step(syscall_cb)
        except InvalidAddress:
            raise
        raise RuntimeError("rv64 program did not finish")
