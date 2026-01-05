from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Sequence


MAGIC_RVEX_V1 = b"RVX1"

PT_LOAD = 1

PF_X = 1 << 0
PF_W = 1 << 1
PF_R = 1 << 2


_HDR = struct.Struct("<4sHHQI")
_VERSION_V1 = 1

_PH = struct.Struct("<IIQIII")


@dataclass(frozen=True, slots=True)
class RvExeHeaderV1:
    version: int
    ph_num: int
    entry: int
    ph_off: int

    def to_bytes(self) -> bytes:
        return _HDR.pack(MAGIC_RVEX_V1, self.version, self.ph_num, self.entry, self.ph_off)

    @classmethod
    def from_bytes(cls, data: bytes) -> "RvExeHeaderV1":
        if len(data) < _HDR.size:
            raise ValueError("exe too small")
        magic, version, ph_num, entry, ph_off = _HDR.unpack_from(data, 0)
        if magic != MAGIC_RVEX_V1:
            raise ValueError("bad exe magic")
        return cls(version=int(version), ph_num=int(ph_num), entry=int(entry), ph_off=int(ph_off))


@dataclass(frozen=True, slots=True)
class RvProgramHeaderV1:
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
    def from_bytes(cls, data: bytes, off: int) -> "RvProgramHeaderV1":
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


def parse_rvexe_v1(blob: bytes) -> tuple[RvExeHeaderV1, list[RvProgramHeaderV1]]:
    hdr = RvExeHeaderV1.from_bytes(blob)
    if hdr.version != _VERSION_V1:
        raise ValueError("unsupported exe version")
    phs: List[RvProgramHeaderV1] = []
    off = int(hdr.ph_off)
    for _ in range(int(hdr.ph_num)):
        phs.append(RvProgramHeaderV1.from_bytes(blob, off))
        off += _PH.size
    return hdr, phs


def build_rvexe_v1(*, entry: int, segments: Sequence[RvProgramHeaderV1], payloads: Sequence[bytes]) -> bytes:
    if len(segments) != len(payloads):
        raise ValueError("segments/payloads size mismatch")

    ph_off = _HDR.size
    ph_num = len(segments)
    file_off = ph_off + ph_num * _PH.size

    ph_bytes = bytearray()
    data_bytes = bytearray()
    cur_off = file_off
    for ph, data in zip(segments, payloads, strict=True):
        ph_bytes += RvProgramHeaderV1(
            type=int(ph.type),
            flags=int(ph.flags),
            vaddr=int(ph.vaddr),
            file_off=int(cur_off),
            file_size=len(data),
            mem_size=int(ph.mem_size),
        ).to_bytes()
        data_bytes += bytes(data)
        cur_off += len(data)

    hdr = RvExeHeaderV1(version=_VERSION_V1, ph_num=ph_num, entry=int(entry), ph_off=ph_off)
    return hdr.to_bytes() + bytes(ph_bytes) + bytes(data_bytes)
