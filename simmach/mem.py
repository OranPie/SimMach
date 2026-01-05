from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from typing import Dict, Iterable, List, Optional, Tuple

from constants import PAGE_SIZE
from simmach.errors import InvalidAddress, OOMError, PageFault
from structs import ObjectHeader, VirtAddr


def _is_page_aligned(addr: int) -> bool:
    return addr % PAGE_SIZE == 0


def _align_down(addr: int) -> int:
    return addr - (addr % PAGE_SIZE)


def _align_up(addr: int) -> int:
    r = addr % PAGE_SIZE
    return addr if r == 0 else (addr + (PAGE_SIZE - r))


def _align_up_to(addr: int, align: int) -> int:
    if align <= 0 or (align & (align - 1)) != 0:
        raise ValueError("align must be a power of two")
    return (addr + (align - 1)) & ~(align - 1)


class PageFlags(IntFlag):
    R = 1 << 0
    W = 1 << 1
    X = 1 << 2
    USER = 1 << 3


@dataclass(frozen=True, slots=True)
class PageMapping:
    phys_page_base: int
    flags: PageFlags


class PhysMem:
    def __init__(self, size_bytes: int):
        if size_bytes <= 0:
            raise ValueError("size_bytes must be positive")
        if size_bytes % PAGE_SIZE != 0:
            raise ValueError("size_bytes must be page-aligned")
        self._mem = bytearray(size_bytes)

    @property
    def size_bytes(self) -> int:
        return len(self._mem)

    def read(self, phys_addr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if phys_addr < 0 or phys_addr + size > self.size_bytes:
            raise InvalidAddress(f"phys read out of range: addr={phys_addr} size={size}")
        return bytes(self._mem[phys_addr : phys_addr + size])

    def write(self, phys_addr: int, data: bytes) -> None:
        if phys_addr < 0 or phys_addr + len(data) > self.size_bytes:
            raise InvalidAddress(
                f"phys write out of range: addr={phys_addr} size={len(data)}"
            )
        self._mem[phys_addr : phys_addr + len(data)] = data


class FrameAllocator:
    def __init__(self, physmem: PhysMem, reserved_ranges: Optional[Iterable[Tuple[int, int]]] = None):
        self._physmem = physmem
        self._total_frames = physmem.size_bytes // PAGE_SIZE
        self._free_frames = set(range(self._total_frames))

        if reserved_ranges:
            for start, end in reserved_ranges:
                if start < 0 or end < 0 or end < start:
                    raise ValueError("invalid reserved range")
                start = _align_down(start)
                end = _align_up(end)
                if end > physmem.size_bytes:
                    raise ValueError("reserved range exceeds physical memory")
                for phys_page_base in range(start, end, PAGE_SIZE):
                    frame = phys_page_base // PAGE_SIZE
                    self._free_frames.discard(frame)

    @property
    def total_frames(self) -> int:
        return self._total_frames

    def available_frames(self) -> int:
        return len(self._free_frames)

    def alloc_frame(self) -> int:
        try:
            frame = self._free_frames.pop()
        except KeyError as e:
            raise OOMError("out of physical frames") from e
        return frame * PAGE_SIZE

    def free_frame(self, phys_page_base: int) -> None:
        if not _is_page_aligned(phys_page_base):
            raise ValueError("phys_page_base must be page-aligned")
        if phys_page_base < 0 or phys_page_base >= self._physmem.size_bytes:
            raise InvalidAddress("phys_page_base out of range")
        frame = phys_page_base // PAGE_SIZE
        self._free_frames.add(frame)


class PageTable:
    def __init__(self):
        # Sv39-style 3-level page table:
        # root[vpn2][vpn1][vpn0] -> PageMapping
        self._l2: Dict[int, Dict[int, Dict[int, PageMapping]]] = {}
        self._tlb: Dict[Tuple[int, bool, bool, bool], Tuple[int, PageFlags]] = {}

    def _indices(self, virt_addr: int) -> Tuple[int, int, int, int]:
        virt_page_base = _align_down(virt_addr)
        vpn0 = (virt_page_base >> 12) & 0x1FF
        vpn1 = (virt_page_base >> 21) & 0x1FF
        vpn2 = (virt_page_base >> 30) & 0x1FF
        return int(virt_page_base), int(vpn2), int(vpn1), int(vpn0)

    def _get_leaf(self, virt_addr: int) -> PageMapping:
        virt_page_base, vpn2, vpn1, vpn0 = self._indices(virt_addr)
        l1 = self._l2.get(vpn2)
        if l1 is None:
            raise InvalidAddress(f"unmapped virt addr: {virt_page_base:#x}")
        l0 = l1.get(vpn1)
        if l0 is None:
            raise InvalidAddress(f"unmapped virt addr: {virt_page_base:#x}")
        m = l0.get(vpn0)
        if m is None:
            raise InvalidAddress(f"unmapped virt addr: {virt_page_base:#x}")
        return m

    def map_page(self, virt_page_base: int, phys_page_base: int, flags: PageFlags) -> None:
        if not _is_page_aligned(virt_page_base):
            raise ValueError("virt_page_base must be page-aligned")
        if not _is_page_aligned(phys_page_base):
            raise ValueError("phys_page_base must be page-aligned")
        _, vpn2, vpn1, vpn0 = self._indices(virt_page_base)
        l1 = self._l2.setdefault(vpn2, {})
        l0 = l1.setdefault(vpn1, {})
        if vpn0 in l0:
            raise ValueError("virtual page already mapped")
        l0[vpn0] = PageMapping(phys_page_base=phys_page_base, flags=flags)
        self._tlb.clear()

    def unmap_page(self, virt_page_base: int) -> PageMapping:
        if not _is_page_aligned(virt_page_base):
            raise ValueError("virt_page_base must be page-aligned")
        _, vpn2, vpn1, vpn0 = self._indices(virt_page_base)
        l1 = self._l2.get(vpn2)
        if l1 is None:
            raise InvalidAddress("virtual page not mapped")
        l0 = l1.get(vpn1)
        if l0 is None:
            raise InvalidAddress("virtual page not mapped")
        try:
            m = l0.pop(vpn0)
        except KeyError as e:
            raise InvalidAddress("virtual page not mapped") from e

        if not l0:
            l1.pop(vpn1, None)
        if not l1:
            self._l2.pop(vpn2, None)
        self._tlb.clear()
        return m

    def protect_page(self, virt_page_base: int, flags: PageFlags) -> None:
        if not _is_page_aligned(virt_page_base):
            raise ValueError("virt_page_base must be page-aligned")
        _, vpn2, vpn1, vpn0 = self._indices(virt_page_base)
        l1 = self._l2.get(vpn2)
        if l1 is None:
            raise InvalidAddress("virtual page not mapped")
        l0 = l1.get(vpn1)
        if l0 is None:
            raise InvalidAddress("virtual page not mapped")
        mapping = l0.get(vpn0)
        if mapping is None:
            raise InvalidAddress("virtual page not mapped")
        l0[vpn0] = PageMapping(phys_page_base=mapping.phys_page_base, flags=flags)
        self._tlb.clear()

    def walk(self, virt_addr: int, *, write: bool = False, execute: bool = False, user: bool = False) -> Tuple[int, PageFlags]:
        virt_page_base = _align_down(virt_addr)
        if user:
            cached = self._tlb.get((int(virt_page_base), bool(write), bool(execute), True))
            if cached is not None:
                phys_addr, flags = cached
                offset = virt_addr - virt_page_base
                return int(phys_addr + offset), PageFlags(flags)

        try:
            mapping = self._get_leaf(virt_page_base)
        except InvalidAddress as e:
            raise PageFault(int(virt_addr), "execute" if execute else ("write" if write else "read"), "not_present") from e

        if user:
            if not (mapping.flags & PageFlags.USER):
                raise PageFault(int(virt_addr), "execute" if execute else ("write" if write else "read"), "user_violation")
            if write and not (mapping.flags & PageFlags.W):
                raise PageFault(int(virt_addr), "write", "perm")
            if execute and not (mapping.flags & PageFlags.X):
                raise PageFault(int(virt_addr), "execute", "perm")
            if not execute and not (mapping.flags & PageFlags.R):
                raise PageFault(int(virt_addr), "read", "perm")

        offset = virt_addr - virt_page_base
        phys = int(mapping.phys_page_base)
        if user:
            self._tlb[(int(virt_page_base), bool(write), bool(execute), True)] = (phys, PageFlags(mapping.flags))
        return phys + offset, mapping.flags

    def dump_mappings(self) -> List[Tuple[int, int, PageFlags]]:
        out: List[Tuple[int, int, PageFlags]] = []
        for vpn2, l1 in self._l2.items():
            for vpn1, l0 in l1.items():
                for vpn0, m in l0.items():
                    virt_page_base = (int(vpn2) << 30) | (int(vpn1) << 21) | (int(vpn0) << 12)
                    out.append((virt_page_base, m.phys_page_base, m.flags))
        out.sort(key=lambda t: t[0])
        return out


class AddressSpace:
    def __init__(self, physmem: PhysMem, frame_alloc: FrameAllocator):
        self._physmem = physmem
        self._frame_alloc = frame_alloc
        self._pt = PageTable()
        self._reserved: List[Tuple[int, int]] = []

    @property
    def physmem(self) -> PhysMem:
        return self._physmem

    @property
    def frame_allocator(self) -> FrameAllocator:
        return self._frame_alloc

    @property
    def pagetable(self) -> PageTable:
        return self._pt

    def reserve_range(self, virt_start: int, virt_end: int) -> None:
        if virt_start < 0 or virt_end < 0 or virt_end < virt_start:
            raise ValueError("invalid reserve range")
        self._reserved.append((virt_start, virt_end))

    def _is_reserved(self, virt_page_base: int) -> bool:
        for start, end in self._reserved:
            if start <= virt_page_base < end:
                return True
        return False

    def map_range_identity(self, virt_start: int, virt_end: int, flags: PageFlags) -> None:
        if virt_start < 0 or virt_end < 0 or virt_end < virt_start:
            raise ValueError("invalid range")
        virt_start = _align_down(virt_start)
        virt_end = _align_up(virt_end)
        for page_base in range(virt_start, virt_end, PAGE_SIZE):
            if page_base + PAGE_SIZE > self._physmem.size_bytes:
                raise InvalidAddress("identity map exceeds physical memory")
            self._pt.map_page(page_base, page_base, flags)

    def map_page(self, virt_page_base: int, flags: PageFlags) -> int:
        if not _is_page_aligned(virt_page_base):
            raise ValueError("virt_page_base must be page-aligned")
        phys_page_base = self._frame_alloc.alloc_frame()
        self._pt.map_page(virt_page_base, phys_page_base, flags)
        return phys_page_base

    def unmap_page(self, virt_page_base: int, *, free_frame: bool = True) -> None:
        mapping = self._pt.unmap_page(virt_page_base)
        if free_frame:
            self._frame_alloc.free_frame(mapping.phys_page_base)

    def read(self, virt_addr: int, size: int, *, user: bool = False) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        out = bytearray()
        remaining = size
        cursor = virt_addr
        while remaining > 0:
            phys_addr, _ = self._pt.walk(cursor, write=False, execute=False, user=user)
            page_off = cursor % PAGE_SIZE
            n = min(remaining, PAGE_SIZE - page_off)
            out += self._physmem.read(phys_addr, n)
            cursor += n
            remaining -= n
        return bytes(out)

    def write(self, virt_addr: int, data: bytes, *, user: bool = False) -> None:
        remaining = len(data)
        cursor = virt_addr
        src_off = 0
        while remaining > 0:
            phys_addr, _ = self._pt.walk(cursor, write=True, execute=False, user=user)
            page_off = cursor % PAGE_SIZE
            n = min(remaining, PAGE_SIZE - page_off)
            self._physmem.write(phys_addr, data[src_off : src_off + n])
            cursor += n
            src_off += n
            remaining -= n


def _coalesce_spans(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not spans:
        return []
    spans = sorted(spans)
    out: List[Tuple[int, int]] = []
    cur_start, cur_len = spans[0]
    cur_end = cur_start + cur_len
    for start, length in spans[1:]:
        end = start + length
        if start <= cur_end:
            cur_end = max(cur_end, end)
            continue
        out.append((cur_start, cur_end - cur_start))
        cur_start, cur_end = start, end
    out.append((cur_start, cur_end - cur_start))
    return out


class PageAllocator:
    def __init__(
        self,
        aspace: AddressSpace,
        virt_base: int,
        size_bytes: int,
        flags: PageFlags,
    ):
        if size_bytes <= 0:
            raise ValueError("size_bytes must be positive")
        if not _is_page_aligned(virt_base):
            raise ValueError("virt_base must be page-aligned")
        if size_bytes % PAGE_SIZE != 0:
            raise ValueError("size_bytes must be page-aligned")

        self._aspace = aspace
        self._virt_base = virt_base
        self._size_bytes = size_bytes
        self._flags = flags

        self._free_spans: List[Tuple[int, int]] = [(virt_base, size_bytes)]
        self._allocated: Dict[int, int] = {}

    @property
    def virt_base(self) -> int:
        return self._virt_base

    @property
    def size_bytes(self) -> int:
        return self._size_bytes

    def alloc_pages(self, num_pages: int) -> int:
        if num_pages <= 0:
            raise ValueError("num_pages must be positive")
        need = num_pages * PAGE_SIZE

        for i, (start, length) in enumerate(self._free_spans):
            if length < need:
                continue
            alloc_base = start
            remain = length - need
            if remain == 0:
                del self._free_spans[i]
            else:
                self._free_spans[i] = (start + need, remain)

            for page_base in range(alloc_base, alloc_base + need, PAGE_SIZE):
                self._aspace.map_page(page_base, self._flags)

            self._allocated[alloc_base] = need
            return alloc_base

        raise OOMError("out of virtual heap pages")

    def free_pages(self, virt_base: int) -> None:
        size = self._allocated.pop(virt_base, None)
        if size is None:
            raise InvalidAddress("free_pages: unknown allocation")

        for page_base in range(virt_base, virt_base + size, PAGE_SIZE):
            self._aspace.unmap_page(page_base, free_frame=True)

        self._free_spans.append((virt_base, size))
        self._free_spans = _coalesce_spans(self._free_spans)


class ValueHeapAllocator:
    def __init__(
        self,
        aspace: AddressSpace,
        virt_base: int,
        size_bytes: int,
        flags: PageFlags,
    ):
        if size_bytes <= 0:
            raise ValueError("size_bytes must be positive")
        if not _is_page_aligned(virt_base):
            raise ValueError("virt_base must be page-aligned")
        if size_bytes % PAGE_SIZE != 0:
            raise ValueError("size_bytes must be page-aligned")

        self._aspace = aspace
        self._virt_base = virt_base
        self._size_bytes = size_bytes
        self._flags = flags

        self._brk = virt_base
        self._mapped_end = virt_base

        # Free-list spans within the value heap region: (start, length)
        self._free_spans: List[Tuple[int, int]] = []

    @property
    def virt_base(self) -> int:
        return self._virt_base

    @property
    def size_bytes(self) -> int:
        return self._size_bytes

    def _ensure_mapped_until(self, virt_end: int) -> None:
        if virt_end <= self._mapped_end:
            return

        region_end = self._virt_base + self._size_bytes
        if virt_end > region_end:
            raise OOMError("ValueHeap exhausted")

        map_from = _align_down(self._mapped_end)
        map_to = _align_up(virt_end)
        for page_base in range(map_from, map_to, PAGE_SIZE):
            self._aspace.map_page(page_base, self._flags)
        self._mapped_end = map_to

    def alloc_block(self, size_bytes: int, *, align: int = 16) -> VirtAddr:
        if size_bytes <= 0:
            raise ValueError("size_bytes must be positive")

        need = int(size_bytes)

        for i, (start, length) in enumerate(list(self._free_spans)):
            span_end = start + length
            alloc_base = _align_up_to(start, align)
            alloc_end = alloc_base + need
            if alloc_end > span_end:
                continue

            del self._free_spans[i]
            if alloc_base > start:
                self._free_spans.append((start, alloc_base - start))
            if alloc_end < span_end:
                self._free_spans.append((alloc_end, span_end - alloc_end))
            self._free_spans = _coalesce_spans(self._free_spans)

            self._ensure_mapped_until(alloc_end)
            return alloc_base

        alloc_base = _align_up_to(self._brk, align)
        alloc_end = alloc_base + need
        self._ensure_mapped_until(alloc_end)
        self._brk = alloc_end
        return alloc_base

    def free_block(self, virt_base: VirtAddr, size_bytes: int) -> None:
        if size_bytes <= 0:
            raise ValueError("size_bytes must be positive")
        start = int(virt_base)
        end = start + int(size_bytes)
        region_end = self._virt_base + self._size_bytes
        if start < self._virt_base or end > region_end:
            raise InvalidAddress("free_block: out of value heap range")
        self._free_spans.append((start, int(size_bytes)))
        self._free_spans = _coalesce_spans(self._free_spans)

    def free_object(self, obj_ptr: VirtAddr) -> None:
        header = self.read_object_header(obj_ptr)
        total = ObjectHeader._STRUCT.size + int(header.byte_cap)
        self.free_block(obj_ptr, total)

    def alloc_object(self, *, type_id: int, flags: int, byte_len: int, byte_cap: int) -> Tuple[VirtAddr, int]:
        if byte_len < 0 or byte_cap < 0 or byte_len > byte_cap:
            raise ValueError("invalid byte_len/byte_cap")
        obj_ptr = self.alloc_block(ObjectHeader._STRUCT.size + byte_cap, align=16)
        header = ObjectHeader(type=type_id, flags=flags, byte_len=byte_len, byte_cap=byte_cap)
        self.write_object_header(obj_ptr, header)
        return obj_ptr, byte_cap

    def write_object_header(self, obj_ptr: VirtAddr, header: ObjectHeader) -> None:
        self._aspace.write(int(obj_ptr), header.to_bytes(), user=False)

    def read_object_header(self, obj_ptr: VirtAddr) -> ObjectHeader:
        data = self._aspace.read(int(obj_ptr), ObjectHeader._STRUCT.size, user=False)
        return ObjectHeader.from_bytes(data)
