from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Sequence


MAGIC_EXE_V1 = b"SMX1"

PT_LOAD = 1

PF_X = 1 << 0
PF_W = 1 << 1
PF_R = 1 << 2


_HDR = struct.Struct("<4sHHQI")
# magic[4], version(u16), ph_num(u16), entry(u64), ph_off(u32)
_VERSION_V1 = 1

_PH = struct.Struct("<IIQIII")
# type(u32) flags(u32) vaddr(u64) file_off(u32) file_size(u32) mem_size(u32)


@dataclass(frozen=True, slots=True)
class ExeHeaderV1:
    version: int
    ph_num: int
    entry: int
    ph_off: int

    def to_bytes(self) -> bytes:
        return _HDR.pack(MAGIC_EXE_V1, self.version, self.ph_num, self.entry, self.ph_off)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ExeHeaderV1":
        if len(data) < _HDR.size:
            raise ValueError("exe too small")
        magic, version, ph_num, entry, ph_off = _HDR.unpack_from(data, 0)
        if magic != MAGIC_EXE_V1:
            raise ValueError("bad exe magic")
        return cls(version=int(version), ph_num=int(ph_num), entry=int(entry), ph_off=int(ph_off))


@dataclass(frozen=True, slots=True)
class ProgramHeaderV1:
    type: int
    flags: int
    vaddr: int
    file_off: int
    file_size: int
    mem_size: int

    def to_bytes(self) -> bytes:
        return _PH.pack(
            int(self.type),
            int(self.flags),
            int(self.vaddr),
            int(self.file_off),
            int(self.file_size),
            int(self.mem_size),
        )

    @classmethod
    def from_bytes(cls, data: bytes, off: int) -> "ProgramHeaderV1":
        if off < 0 or off + _PH.size > len(data):
            raise ValueError("bad program header offset")
        t, flags, vaddr, file_off, file_size, mem_size = _PH.unpack_from(data, off)
        return cls(
            type=int(t),
            flags=int(flags),
            vaddr=int(vaddr),
            file_off=int(file_off),
            file_size=int(file_size),
            mem_size=int(mem_size),
        )


def parse_exe_v1(blob: bytes) -> tuple[ExeHeaderV1, list[ProgramHeaderV1]]:
    hdr = ExeHeaderV1.from_bytes(blob)
    if hdr.version != _VERSION_V1:
        raise ValueError("unsupported exe version")
    phs: List[ProgramHeaderV1] = []
    off = hdr.ph_off
    for _ in range(hdr.ph_num):
        phs.append(ProgramHeaderV1.from_bytes(blob, off))
        off += _PH.size
    return hdr, phs


# A tiny "user program" script instruction stream.
# Each instruction is 4x u64: (opcode, a1, a2, a3)
#
# opcode:
# - OP_SYSCALL: a1=sysno, a2=arg1, a3=arg2, and arg3 is stored in the next instruction field? (no)
#   For simplicity we define: (OP_SYSCALL, sysno, arg1, arg2) and arg3 is always 0.
#   If you need 3 args, encode as (OP_SYSCALL, sysno, arg1, arg2) and put arg3 in the next MOVI.
#
# Instead, we keep 3 args by using (OP_SYSCALL, sysno, arg1, arg2) and treat a3 as arg3.
# So: (OP_SYSCALL, sysno, arg1, arg2) would lose arg3, therefore we define:
# (OP_SYSCALL, sysno, arg1, arg2)??
#
# Final decision: (OP_SYSCALL, sysno, arg1, arg2) and arg3 is a3.
# Thus a1=sysno, a2=arg1, a3=arg2, but we need arg3 too. So we actually use:
# (OP_SYSCALL, sysno, arg1, arg2) and overload arg2/arg3? Not acceptable.
#
# Use full 4 u64: (OP_SYSCALL, sysno, arg1, arg2) and store arg3 in a3.
# That means: (OP_SYSCALL, sysno, arg1, arg2) with a3 present -> (OP_SYSCALL, sysno, arg1, arg2)???
# The tuple is (opcode, sysno, arg1, arg2) only 4 values.
# We need 5. Therefore: interpret as (opcode, sysno, arg1, arg2) and use a3 as arg3 by making 4-tuple
# actually (opcode, a1, a2, a3) where a1=sysno, a2=arg1, a3=arg2, and arg3 is stored in next op.
#
# To avoid this mess, we keep the original semantics but add opcode via sysno high bits.
# We'll instead define:
# (sysno, a1, a2, a3) as before, but allow register references via high-bit.
# This enables chaining without changing the instruction format.
_SCRIPT_OP = struct.Struct("<QQQQ")

REG_REF_MASK = 1 << 63


def reg_ref(index: int) -> int:
    if index < 0 or index > 255:
        raise ValueError("register index out of range")
    return REG_REF_MASK | int(index)


def build_script_exe(*, entry_vaddr: int, script_ops: Sequence[tuple[int, int, int, int]]) -> bytes:
    """Build a minimal EXE containing one PT_LOAD segment with the script bytecode.

    script_ops instruction format: (sysno, a1, a2, a3)
    - Any operand can be a register reference by using reg_ref(i).
      The interpreter will substitute it with registers[i].
    - The syscall return value is stored in registers[0].
    - Pseudo-instruction MOVI: sysno==0, interpreted as (0, reg_index, imm, 0)
      to set registers[reg_index]=imm.
    """

    payload = bytearray()
    for sysno, a1, a2, a3 in script_ops:
        payload += _SCRIPT_OP.pack(int(sysno), int(a1), int(a2), int(a3))

    # One PH right after header.
    ph_off = _HDR.size
    ph_num = 1
    file_off = ph_off + ph_num * _PH.size

    ph = ProgramHeaderV1(
        type=PT_LOAD,
        flags=PF_R,
        vaddr=entry_vaddr,
        file_off=file_off,
        file_size=len(payload),
        mem_size=len(payload),
    )
    hdr = ExeHeaderV1(version=_VERSION_V1, ph_num=ph_num, entry=entry_vaddr, ph_off=ph_off)

    return hdr.to_bytes() + ph.to_bytes() + bytes(payload)
