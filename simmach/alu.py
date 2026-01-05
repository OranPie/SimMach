from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar

from constants import CalcFlags, CalcOp
from simmach.errors import InvalidAddress
from simmach.mem import AddressSpace


_U64 = struct.Struct("<Q")
_I64 = struct.Struct("<q")


@dataclass(frozen=True, slots=True)
class CalcDesc:
    # 32 bytes total
    op: int
    flags: int
    a_ptr: int
    b_ptr: int
    out_ptr: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIQQQ")

    def to_bytes(self) -> bytes:
        return self._STRUCT.pack(int(self.op), int(self.flags), int(self.a_ptr), int(self.b_ptr), int(self.out_ptr))

    @classmethod
    def from_bytes(cls, data: bytes) -> "CalcDesc":
        if len(data) < cls._STRUCT.size:
            raise ValueError("buffer too small for CalcDesc")
        op, flags, a_ptr, b_ptr, out_ptr = cls._STRUCT.unpack_from(data, 0)
        return cls(op=int(op), flags=int(flags), a_ptr=int(a_ptr), b_ptr=int(b_ptr), out_ptr=int(out_ptr))


def _mask_u64(x: int) -> int:
    return x & 0xFFFF_FFFF_FFFF_FFFF


def _to_i64(x: int) -> int:
    x = _mask_u64(x)
    return x - (1 << 64) if (x >> 63) else x


def _from_i64(x: int) -> int:
    return _mask_u64(x)


class MemoryALU:
    def __init__(self, aspace: AddressSpace):
        self._aspace = aspace

    def read_desc_user(self, desc_ptr: int) -> CalcDesc:
        data = self._aspace.read(desc_ptr, CalcDesc._STRUCT.size, user=True)
        return CalcDesc.from_bytes(data)

    def _read_operand(self, ptr: int, signed: bool) -> int:
        raw = self._aspace.read(ptr, 8, user=True)
        if signed:
            return int(_I64.unpack(raw)[0])
        return int(_U64.unpack(raw)[0])

    def _write_result(self, ptr: int, value_u64: int) -> None:
        self._aspace.write(ptr, _U64.pack(_mask_u64(value_u64)), user=True)

    def exec(self, desc: CalcDesc) -> None:
        signed = bool(desc.flags & int(CalcFlags.SIGNED))
        trap_overflow = bool(desc.flags & int(CalcFlags.TRAP_OVERFLOW))

        a = self._read_operand(desc.a_ptr, signed=signed)
        b = self._read_operand(desc.b_ptr, signed=signed)

        if signed:
            # Use i64 semantics then encode back as u64 two's complement.
            res_i: int
            if desc.op == int(CalcOp.ADD):
                res_i = a + b
            elif desc.op == int(CalcOp.SUB):
                res_i = a - b
            elif desc.op == int(CalcOp.MUL):
                res_i = a * b
            elif desc.op == int(CalcOp.DIV):
                if b == 0:
                    raise ZeroDivisionError
                res_i = int(a // b)
            elif desc.op == int(CalcOp.AND):
                res_i = _to_i64(_from_i64(a) & _from_i64(b))
            elif desc.op == int(CalcOp.OR):
                res_i = _to_i64(_from_i64(a) | _from_i64(b))
            elif desc.op == int(CalcOp.XOR):
                res_i = _to_i64(_from_i64(a) ^ _from_i64(b))
            elif desc.op == int(CalcOp.SHL):
                sh = int(b) & 63
                res_i = _to_i64(_from_i64(a) << sh)
            elif desc.op == int(CalcOp.SHR):
                sh = int(b) & 63
                # arithmetic shift
                res_i = int(a >> sh)
            elif desc.op == int(CalcOp.CMP):
                res_i = -1 if a < b else (1 if a > b else 0)
            else:
                raise ValueError("unknown op")

            if trap_overflow and not (-2**63 <= res_i <= 2**63 - 1):
                raise OverflowError
            self._write_result(desc.out_ptr, _from_i64(res_i))
            return

        # Unsigned u64 semantics.
        res_u: int
        if desc.op == int(CalcOp.ADD):
            res_u = a + b
        elif desc.op == int(CalcOp.SUB):
            res_u = a - b
        elif desc.op == int(CalcOp.MUL):
            res_u = a * b
        elif desc.op == int(CalcOp.DIV):
            if b == 0:
                raise ZeroDivisionError
            res_u = a // b
        elif desc.op == int(CalcOp.AND):
            res_u = a & b
        elif desc.op == int(CalcOp.OR):
            res_u = a | b
        elif desc.op == int(CalcOp.XOR):
            res_u = a ^ b
        elif desc.op == int(CalcOp.SHL):
            sh = int(b) & 63
            res_u = a << sh
        elif desc.op == int(CalcOp.SHR):
            sh = int(b) & 63
            res_u = a >> sh
        elif desc.op == int(CalcOp.CMP):
            # encode -1/0/1 as i64 in u64 two's complement
            res = -1 if a < b else (1 if a > b else 0)
            self._write_result(desc.out_ptr, _from_i64(res))
            return
        else:
            raise ValueError("unknown op")

        if trap_overflow and res_u > 0xFFFF_FFFF_FFFF_FFFF:
            raise OverflowError
        self._write_result(desc.out_ptr, res_u)
