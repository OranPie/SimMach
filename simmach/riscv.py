from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from constants import PAGE_SIZE, Sysno
from simmach.errors import InvalidAddress
from simmach.mem import AddressSpace


def _u64(x: int) -> int:
    return int(x) & 0xFFFF_FFFF_FFFF_FFFF


_MASK64 = 0xFFFF_FFFF_FFFF_FFFF
_PAGE_OFF_MASK = PAGE_SIZE - 1
_PAGE_MASK = ~_PAGE_OFF_MASK
_SYSCALLS_THAT_REMAP = frozenset((int(Sysno.MMAP), int(Sysno.MUNMAP), int(Sysno.EXECVE)))


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


@dataclass(slots=True, frozen=True)
class _DecodedInsn:
    insn: int
    opcode: int
    rd: int
    funct3: int
    rs1: int
    rs2: int
    funct7: int
    imm_i: int
    imm_s: int
    imm_b: int
    imm_j: int
    imm_u: int


@dataclass(slots=True, frozen=True)
class _Block:
    start_pc: int
    insns: tuple[_DecodedInsn, ...]


def _decode_insn(insn: int) -> _DecodedInsn:
    i = int(insn)
    return _DecodedInsn(
        insn=i,
        opcode=i & 0x7F,
        rd=(i >> 7) & 0x1F,
        funct3=(i >> 12) & 0x7,
        rs1=(i >> 15) & 0x1F,
        rs2=(i >> 20) & 0x1F,
        funct7=(i >> 25) & 0x7F,
        imm_i=_imm_i(i),
        imm_s=_imm_s(i),
        imm_b=_imm_b(i),
        imm_j=_imm_j(i),
        imm_u=_imm_u(i),
    )


@dataclass(slots=True)
class RiscVCPU:
    aspace: AddressSpace
    pc: int
    regs: list[int] = field(default_factory=lambda: [0] * 32)
    _decode_cache: Dict[int, _DecodedInsn] = field(default_factory=dict)
    _block_cache: Dict[int, _Block] = field(default_factory=dict)
    _ifetch_page: int = -1
    _ifetch_phys: int = 0
    _read_page: int = -1
    _read_phys: int = 0
    _write_page: int = -1
    _write_phys: int = 0

    def _reset_xlate_cache(self) -> None:
        self._ifetch_page = -1
        self._read_page = -1
        self._write_page = -1

    def _clear_code_cache(self) -> None:
        self._decode_cache.clear()
        self._block_cache.clear()

    def bind_aspace(self, aspace: AddressSpace) -> None:
        self.aspace = aspace
        self._reset_xlate_cache()
        self._clear_code_cache()

    def _translate_exec(self, addr: int) -> int:
        page = int(addr) & _PAGE_MASK
        off = int(addr) & _PAGE_OFF_MASK
        if page == self._ifetch_page:
            return self._ifetch_phys + off
        phys_addr, _ = self.aspace.pagetable.walk(int(addr), execute=True, user=True)
        self._ifetch_page = page
        self._ifetch_phys = int(phys_addr) - off
        return int(phys_addr)

    def _translate_read(self, addr: int) -> int:
        page = int(addr) & _PAGE_MASK
        off = int(addr) & _PAGE_OFF_MASK
        if page == self._read_page:
            return self._read_phys + off
        phys_addr, _ = self.aspace.pagetable.walk(int(addr), write=False, execute=False, user=True)
        self._read_page = page
        self._read_phys = int(phys_addr) - off
        return int(phys_addr)

    def _translate_write(self, addr: int) -> int:
        page = int(addr) & _PAGE_MASK
        off = int(addr) & _PAGE_OFF_MASK
        if page == self._write_page:
            return self._write_phys + off
        phys_addr, _ = self.aspace.pagetable.walk(int(addr), write=True, execute=False, user=True)
        self._write_page = page
        self._write_phys = int(phys_addr) - off
        return int(phys_addr)

    def _read_u32_exec(self, addr: int) -> int:
        # Instruction fetch should require X permission.
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned instruction fetch")
        phys_addr = self._translate_exec(int(addr))
        return int(self.aspace.physmem.read_u32(int(phys_addr)))

    def _read_u8(self, addr: int) -> int:
        phys_addr = self._translate_read(int(addr))
        return int(self.aspace.physmem.read_u8(int(phys_addr)))

    def _read_u16(self, addr: int) -> int:
        if (int(addr) & 1) != 0:
            raise InvalidAddress("misaligned halfword load")
        phys_addr = self._translate_read(int(addr))
        return int(self.aspace.physmem.read_u16(int(phys_addr)))

    def _read_u32(self, addr: int) -> int:
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned word load")
        phys_addr = self._translate_read(int(addr))
        return int(self.aspace.physmem.read_u32(int(phys_addr)))

    def _read_u64(self, addr: int) -> int:
        if (int(addr) & 7) != 0:
            raise InvalidAddress("misaligned doubleword load")
        phys_addr = self._translate_read(int(addr))
        return int(self.aspace.physmem.read_u64(int(phys_addr)))

    def _write_u8(self, addr: int, val: int) -> None:
        phys_addr = self._translate_write(int(addr))
        self.aspace.physmem.write_u8(int(phys_addr), int(val))

    def _write_u16(self, addr: int, val: int) -> None:
        if (int(addr) & 1) != 0:
            raise InvalidAddress("misaligned halfword store")
        phys_addr = self._translate_write(int(addr))
        self.aspace.physmem.write_u16(int(phys_addr), int(val))

    def _write_u32(self, addr: int, val: int) -> None:
        if (int(addr) & 3) != 0:
            raise InvalidAddress("misaligned word store")
        phys_addr = self._translate_write(int(addr))
        self.aspace.physmem.write_u32(int(phys_addr), int(val))

    def _write_u64(self, addr: int, val: int) -> None:
        if (int(addr) & 7) != 0:
            raise InvalidAddress("misaligned doubleword store")
        phys_addr = self._translate_write(int(addr))
        self.aspace.physmem.write_u64(int(phys_addr), int(val))

    def _set_reg(self, rd: int, val: int) -> None:
        if rd == 0:
            return
        self.regs[rd] = _u64(val)

    def _decode_at_pc(self, pc: int) -> _DecodedInsn:
        insn = int(self._read_u32_exec(int(pc)))
        d = self._decode_cache.get(int(pc))
        if d is None or d.insn != insn:
            d = _decode_insn(insn)
            self._decode_cache[int(pc)] = d
        return d

    def _build_block(self, start_pc: int, first: _DecodedInsn) -> _Block:
        insns: list[_DecodedInsn] = [first]
        pc = (int(start_pc) + 4) & _MASK64
        # Stop at control-flow instructions; cap linear block length.
        for _ in range(63):
            if insns[-1].opcode in (0x63, 0x6F, 0x67, 0x73):
                break
            d = self._decode_at_pc(pc)
            insns.append(d)
            pc = (pc + 4) & _MASK64
        return _Block(start_pc=int(start_pc), insns=tuple(insns))

    def _exec_decoded(self, pc: int, d: _DecodedInsn, syscall_cb) -> None:
        insn = d.insn
        next_pc = (pc + 4) & _MASK64
        regs = self.regs
        set_reg = self._set_reg
        opcode = d.opcode

        if opcode == 0x17:  # AUIPC
            set_reg(d.rd, pc + int(d.imm_u))
            self.pc = next_pc
            return

        if opcode == 0x37:  # LUI
            set_reg(d.rd, d.imm_u)
            self.pc = next_pc
            return

        if opcode == 0x13:  # OP-IMM
            rd = d.rd
            funct3 = d.funct3
            rs1 = d.rs1
            imm = d.imm_i

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
                shamt = (insn >> 20) & 0x3F
                set_reg(rd, int(regs[rs1]) << shamt)
                self.pc = next_pc
                return

            if funct3 == 0x5:
                shamt = (insn >> 20) & 0x3F
                funct7 = d.funct7
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
            rd = d.rd
            funct3 = d.funct3
            rs1 = d.rs1
            rs2 = d.rs2
            funct7 = d.funct7

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
            rd = d.rd
            funct3 = d.funct3
            rs1 = d.rs1
            imm = d.imm_i

            if funct3 == 0x0:  # ADDIW
                set_reg(rd, _sext32(_sext32(regs[rs1]) + int(imm)))
                self.pc = next_pc
                return

            if funct3 == 0x1:  # SLLIW
                shamt = d.rs2 & 0x1F
                set_reg(rd, _sext32((int(regs[rs1]) & 0xFFFF_FFFF) << shamt))
                self.pc = next_pc
                return

            if funct3 == 0x5:
                shamt = d.rs2 & 0x1F
                funct7 = d.funct7
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
            rd = d.rd
            funct3 = d.funct3
            rs1 = d.rs1
            rs2 = d.rs2
            funct7 = d.funct7

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
            rd = d.rd
            funct3 = d.funct3
            rs1 = d.rs1
            imm = d.imm_i
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
            funct3 = d.funct3
            rs1 = d.rs1
            rs2 = d.rs2
            imm = d.imm_s
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
            funct3 = d.funct3
            rs1 = d.rs1
            rs2 = d.rs2
            imm = d.imm_b

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
            set_reg(d.rd, next_pc)
            self.pc = (pc + int(d.imm_j)) & _MASK64
            return

        if opcode == 0x67:  # JALR
            rd = d.rd
            funct3 = d.funct3
            rs1 = d.rs1
            if funct3 != 0x0:
                raise RuntimeError(f"unsupported JALR funct3={funct3}")
            target = ((int(regs[rs1]) + int(d.imm_i)) & _MASK64) & ~1
            set_reg(rd, next_pc)
            self.pc = target
            return

        if opcode == 0x73:  # SYSTEM
            funct3 = d.funct3
            imm12 = int(insn) >> 20
            if funct3 == 0x0 and imm12 == 0:  # ECALL
                self.pc = int(pc)
                sysno = int(regs[17])
                syscall_cb(self)
                # Only remapping syscalls invalidate translation/decode caches.
                if sysno in _SYSCALLS_THAT_REMAP:
                    self._reset_xlate_cache()
                    self._clear_code_cache()
                # Syscall handlers may have adjusted pc (e.g. execve trampoline).
                self.pc = (int(self.pc) + 4) & _MASK64
                return
            raise RuntimeError("unsupported SYSTEM")

        raise RuntimeError(f"unsupported opcode={opcode:#x}")

    def step(self, syscall_cb) -> None:
        pc = int(self.pc)
        d = self._decode_at_pc(pc)
        self._exec_decoded(pc, d, syscall_cb)

    def _exec_block(self, block: _Block, syscall_cb, max_steps: int) -> int:
        consumed = 0
        pc = int(self.pc)
        expected_pc = int(block.start_pc)
        for d in block.insns:
            if consumed >= int(max_steps):
                break
            if int(pc) != int(expected_pc):
                break
            self._exec_decoded(pc, d, syscall_cb)
            consumed += 1
            new_pc = int(self.pc)
            next_pc = (pc + 4) & _MASK64
            if new_pc != next_pc:
                break
            pc = new_pc
            expected_pc = (expected_pc + 4) & _MASK64
        return consumed

    def run(self, syscall_cb, *, max_steps: int = 200_000) -> None:
        regs = self.regs
        remaining = int(max_steps)
        try:
            while remaining > 0:
                regs[0] = 0
                pc = int(self.pc)
                first = self._decode_at_pc(pc)
                block = self._block_cache.get(pc)
                if block is None or block.insns[0].insn != first.insn:
                    block = self._build_block(pc, first)
                    self._block_cache[pc] = block
                n = self._exec_block(block, syscall_cb, remaining)
                if n <= 0:
                    # Defensive fallback; should not happen.
                    self.step(syscall_cb)
                    n = 1
                remaining -= n
        except InvalidAddress:
            raise
        raise RuntimeError("rv64 program did not finish")
