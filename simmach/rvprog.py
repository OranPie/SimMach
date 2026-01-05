from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from simmach import rvasm
from simmach.rvexe import PF_R, PF_W, PF_X, PT_LOAD, RvProgramHeaderV1, build_rvexe_v1


@dataclass(slots=True)
class Segment:
    vaddr: int
    flags: int
    data: bytearray = field(default_factory=bytearray)


class Program:
    def __init__(self, *, entry: int, text_vaddr: int = 0x1000_0000, data_vaddr: int = 0x1000_4000):
        self.entry = int(entry)
        self.text = Segment(vaddr=int(text_vaddr), flags=int(PF_R | PF_X))
        self.data = Segment(vaddr=int(data_vaddr), flags=int(PF_R | PF_W))

        self._labels: Dict[str, Tuple[str, int]] = {}
        self._fix_b: List[Tuple[int, str, int, int, str]] = []
        self._fix_j: List[Tuple[int, str, int]] = []

    def label(self, name: str, *, section: str = "text") -> None:
        if section not in ("text", "data"):
            raise ValueError("bad section")
        if name in self._labels:
            raise ValueError("duplicate label")
        off = len(self.text.data) if section == "text" else len(self.data.data)
        self._labels[name] = (section, int(off))

    def _text_pc_of_insn(self, insn_index: int) -> int:
        return int(self.text.vaddr) + insn_index * 4

    def emit(self, insn: int) -> None:
        self.text.data += struct.pack("<I", int(insn) & 0xFFFF_FFFF)

    def db(self, b: bytes) -> int:
        off = len(self.data.data)
        self.data.data += bytes(b)
        return int(self.data.vaddr + off)

    def align_data(self, align: int) -> None:
        if align <= 0 or (align & (align - 1)) != 0:
            raise ValueError("align must be power of two")
        n = (-len(self.data.data)) & (align - 1)
        if n:
            self.data.data += b"\x00" * n

    def li(self, rd: int, val: int) -> None:
        # simple 32-bit immediate load
        upper = (int(val) + (1 << 11)) >> 12
        low = int(val) - (upper << 12)
        self.emit(rvasm.lui(rd, upper & 0xFFFFF))
        self.emit(rvasm.addi(rd, rd, low))

    def la(self, rd: int, label: str) -> None:
        sec, off = self._labels.get(label, (None, None))  # type: ignore[assignment]
        if sec is None:
            raise ValueError("unknown label")
        base = self.text.vaddr if sec == "text" else self.data.vaddr
        addr = int(base) + int(off)
        self.li(rd, addr)

    def bne(self, rs1: int, rs2: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_b.append((int(idx), str(target), int(rs1), int(rs2), "bne"))

    def beq(self, rs1: int, rs2: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_b.append((int(idx), str(target), int(rs1), int(rs2), "beq"))

    def blt(self, rs1: int, rs2: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_b.append((int(idx), str(target), int(rs1), int(rs2), "blt"))

    def bge(self, rs1: int, rs2: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_b.append((int(idx), str(target), int(rs1), int(rs2), "bge"))

    def bltu(self, rs1: int, rs2: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_b.append((int(idx), str(target), int(rs1), int(rs2), "bltu"))

    def bgeu(self, rs1: int, rs2: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_b.append((int(idx), str(target), int(rs1), int(rs2), "bgeu"))

    def jal(self, rd: int, target: str) -> None:
        idx = len(self.text.data) // 4
        self.emit(0)
        self._fix_j.append((int(idx), str(target), int(rd)))

    def jalr(self, rd: int, rs1: int, imm12: int = 0) -> None:
        self.emit(rvasm.jalr(int(rd), int(rs1), int(imm12)))

    def patch(self) -> None:
        for idx, target, rs1, rs2, kind in list(self._fix_b):
            sec, off = self._labels.get(target, (None, None))  # type: ignore[assignment]
            if sec != "text":
                raise ValueError("branch target must be in text")
            cur_pc = self._text_pc_of_insn(idx)
            tgt_pc = int(self.text.vaddr) + int(off)
            delta = int(tgt_pc - cur_pc)
            if kind == "beq":
                insn = rvasm.beq(rs1, rs2, delta)
            elif kind == "bne":
                insn = rvasm.bne(rs1, rs2, delta)
            elif kind == "blt":
                insn = rvasm.blt(rs1, rs2, delta)
            elif kind == "bge":
                insn = rvasm.bge(rs1, rs2, delta)
            elif kind == "bltu":
                insn = rvasm.bltu(rs1, rs2, delta)
            elif kind == "bgeu":
                insn = rvasm.bgeu(rs1, rs2, delta)
            else:
                raise ValueError("unknown branch kind")
            struct.pack_into("<I", self.text.data, idx * 4, int(insn) & 0xFFFF_FFFF)

        for idx, target, rd in list(self._fix_j):
            sec, off = self._labels.get(target, (None, None))  # type: ignore[assignment]
            if sec != "text":
                raise ValueError("jal target must be in text")
            cur_pc = self._text_pc_of_insn(idx)
            tgt_pc = int(self.text.vaddr) + int(off)
            delta = int(tgt_pc - cur_pc)
            insn = rvasm.jal(rd, delta)
            struct.pack_into("<I", self.text.data, idx * 4, int(insn) & 0xFFFF_FFFF)

    def build_rvx(self) -> bytes:
        self.patch()
        segs: List[RvProgramHeaderV1] = []
        payloads: List[bytes] = []
        segs.append(
            RvProgramHeaderV1(
                type=PT_LOAD,
                flags=int(self.text.flags),
                vaddr=int(self.text.vaddr),
                file_off=0,
                file_size=len(self.text.data),
                mem_size=len(self.text.data),
            )
        )
        payloads.append(bytes(self.text.data))
        if self.data.data:
            segs.append(
                RvProgramHeaderV1(
                    type=PT_LOAD,
                    flags=int(self.data.flags),
                    vaddr=int(self.data.vaddr),
                    file_off=0,
                    file_size=len(self.data.data),
                    mem_size=len(self.data.data),
                )
            )
            payloads.append(bytes(self.data.data))

        return build_rvexe_v1(entry=int(self.entry), segments=segs, payloads=payloads)
