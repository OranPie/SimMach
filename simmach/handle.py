from __future__ import annotations

import struct
from dataclasses import replace
from typing import Any, Dict, Protocol, Tuple

from constants import (
    HANDLE_RECORD_SIZE,
    HANDLE_TABLE_HEADER_SIZE,
    STRING_OBJECT_SIZE,
    HandleType,
)
from simmach.errors import ResourceLimitError
from simmach.mem import AddressSpace, PageAllocator, ValueHeapAllocator
from structs import HandleRecord, HandleTableHeader, ObjectHeader, StringBody, VirtAddr


HANDLE_STATE_VALID = 1 << 0


class HandleTable:
    def __init__(self, aspace: AddressSpace, allocator: PageAllocator):
        self._aspace = aspace
        self._alloc = allocator
        self._base: int | None = None
        self._max_handles: int = 0

    @property
    def base(self) -> int:
        if self._base is None:
            raise RuntimeError("HandleTable not attached")
        return self._base

    @property
    def max_handles(self) -> int:
        return self._max_handles

    def attach(self, *, max_handles: int) -> None:
        if max_handles <= 0:
            raise ValueError("max_handles must be positive")
        if self._base is not None:
            raise RuntimeError("HandleTable already attached")

        total_bytes = HANDLE_TABLE_HEADER_SIZE + max_handles * HANDLE_RECORD_SIZE
        pages = (total_bytes + 4095) // 4096
        base = self._alloc.alloc_pages(pages)
        self._base = base
        self._max_handles = max_handles

        header = HandleTableHeader(max_handles=max_handles, next_id=max_handles + 1, free_head=1)
        self._write_header(header)

        for hid in range(1, max_handles + 1):
            next_free = hid + 1 if hid < max_handles else -1
            rec = HandleRecord(
                type=0,
                state=0,
                owner_pid=0,
                refcnt=0,
                obj_ptr=0,
                obj_len=next_free & 0xFFFF_FFFF if next_free != -1 else 0,
                obj_cap=0,
            )
            self._write_record(hid, rec)

    def _header_addr(self) -> int:
        return self.base

    def _records_base(self) -> int:
        return self.base + HANDLE_TABLE_HEADER_SIZE

    def _record_addr(self, handle_id: int) -> int:
        if handle_id <= 0 or handle_id > self._max_handles:
            raise ResourceLimitError("invalid handle id")
        return self._records_base() + (handle_id - 1) * HANDLE_RECORD_SIZE

    def _read_header(self) -> HandleTableHeader:
        data = self._aspace.read(self._header_addr(), HANDLE_TABLE_HEADER_SIZE, user=False)
        return HandleTableHeader.from_bytes(data)

    def _write_header(self, header: HandleTableHeader) -> None:
        self._aspace.write(self._header_addr(), header.to_bytes(), user=False)

    def _read_record(self, handle_id: int) -> HandleRecord:
        data = self._aspace.read(self._record_addr(handle_id), HANDLE_RECORD_SIZE, user=False)
        return HandleRecord.from_bytes(data)

    def _write_record(self, handle_id: int, rec: HandleRecord) -> None:
        self._aspace.write(self._record_addr(handle_id), rec.to_bytes(), user=False)

    def alloc_handle_id(self) -> int:
        header = self._read_header()
        if header.free_head != -1:
            hid = int(header.free_head)
            rec = self._read_record(hid)
            next_free = int(rec.obj_len) if rec.obj_len != 0 else -1
            header = replace(header, free_head=next_free)
            self._write_header(header)
            return hid

        if header.next_id <= self._max_handles:
            hid = int(header.next_id)
            header = replace(header, next_id=hid + 1)
            self._write_header(header)
            return hid

        raise ResourceLimitError("handle table full")

    def set_record(self, handle_id: int, rec: HandleRecord) -> None:
        self._write_record(handle_id, rec)

    def get_record(self, handle_id: int) -> HandleRecord:
        rec = self._read_record(handle_id)
        if not (rec.state & HANDLE_STATE_VALID):
            raise ResourceLimitError("invalid handle")
        return rec

    def free_handle_id(self, handle_id: int) -> None:
        header = self._read_header()
        rec = HandleRecord(
            type=0,
            state=0,
            owner_pid=0,
            refcnt=0,
            obj_ptr=0,
            obj_len=(header.free_head & 0xFFFF_FFFF) if header.free_head != -1 else 0,
            obj_cap=0,
        )
        self._write_record(handle_id, rec)
        header = replace(header, free_head=handle_id)
        self._write_header(header)


class Codec(Protocol):
    type_id: int

    def alloc(self, value: Any) -> Tuple[VirtAddr, int, int]:
        raise NotImplementedError

    def decode(self, obj_ptr: VirtAddr, record: HandleRecord) -> Any:
        raise NotImplementedError

    def encode(self, obj_ptr: VirtAddr, record: HandleRecord, value: Any) -> Tuple[VirtAddr, int, int]:
        raise NotImplementedError

    def free(self, obj_ptr: VirtAddr, record: HandleRecord) -> None:
        raise NotImplementedError


class Int64Codec:
    type_id = int(HandleType.Int64)
    _PAYLOAD: struct.Struct = struct.Struct("<q")

    def __init__(self, aspace: AddressSpace, heap: ValueHeapAllocator):
        self._aspace = aspace
        self._heap = heap

    def alloc(self, value: int) -> Tuple[VirtAddr, int, int]:
        obj_ptr, cap = self._heap.alloc_object(type_id=self.type_id, flags=0, byte_len=8, byte_cap=8)
        self._aspace.write(int(obj_ptr) + 16, self._PAYLOAD.pack(int(value)), user=False)
        return obj_ptr, 8, cap

    def decode(self, obj_ptr: VirtAddr, record: HandleRecord) -> int:
        data = self._aspace.read(int(obj_ptr) + 16, 8, user=False)
        return int(self._PAYLOAD.unpack(data)[0])

    def encode(self, obj_ptr: VirtAddr, record: HandleRecord, value: int) -> Tuple[VirtAddr, int, int]:
        self._heap.write_object_header(obj_ptr, ObjectHeader(type=self.type_id, flags=0, byte_len=8, byte_cap=8))
        self._aspace.write(int(obj_ptr) + 16, self._PAYLOAD.pack(int(value)), user=False)
        return obj_ptr, 8, 8

    def free(self, obj_ptr: VirtAddr, record: HandleRecord) -> None:
        self._heap.free_object(obj_ptr)


class BytesCodec:
    type_id = int(HandleType.Bytes)

    def __init__(self, aspace: AddressSpace, heap: ValueHeapAllocator):
        self._aspace = aspace
        self._heap = heap

    @staticmethod
    def _grow(old_cap: int, need: int) -> int:
        cap = max(16, old_cap)
        while cap < need:
            cap *= 2
        return cap

    def alloc(self, value: bytes) -> Tuple[VirtAddr, int, int]:
        data = bytes(value)
        cap = self._grow(0, len(data))
        obj_ptr, _ = self._heap.alloc_object(type_id=self.type_id, flags=0, byte_len=len(data), byte_cap=cap)
        if data:
            self._aspace.write(int(obj_ptr) + 16, data, user=False)
        return obj_ptr, len(data), cap

    def decode(self, obj_ptr: VirtAddr, record: HandleRecord) -> bytes:
        n = int(record.obj_len)
        if n == 0:
            return b""
        return self._aspace.read(int(obj_ptr) + 16, n, user=False)

    def encode(self, obj_ptr: VirtAddr, record: HandleRecord, value: bytes) -> Tuple[VirtAddr, int, int]:
        data = bytes(value)
        need = len(data)
        cap = int(record.obj_cap)
        cur_ptr = obj_ptr

        if need > cap:
            new_cap = self._grow(cap, need)
            new_ptr, _ = self._heap.alloc_object(type_id=self.type_id, flags=0, byte_len=need, byte_cap=new_cap)
            if data:
                self._aspace.write(int(new_ptr) + 16, data, user=False)
            return new_ptr, need, new_cap

        self._heap.write_object_header(cur_ptr, ObjectHeader(type=self.type_id, flags=0, byte_len=need, byte_cap=cap))
        if data:
            self._aspace.write(int(cur_ptr) + 16, data, user=False)
        return cur_ptr, need, cap

    def free(self, obj_ptr: VirtAddr, record: HandleRecord) -> None:
        self._heap.free_object(obj_ptr)


class StringCodec:
    type_id = int(HandleType.String)

    def __init__(self, aspace: AddressSpace, heap: ValueHeapAllocator, bytes_codec: BytesCodec):
        self._aspace = aspace
        self._heap = heap
        self._bytes = bytes_codec

    def alloc(self, value: str) -> Tuple[VirtAddr, int, int]:
        b = value.encode("utf-8")
        obj_ptr = self._heap.alloc_block(STRING_OBJECT_SIZE, align=16)
        header = ObjectHeader(type=self.type_id, flags=0, byte_len=len(b), byte_cap=48)
        self._heap.write_object_header(obj_ptr, header)
        self._write_body(obj_ptr, b)
        return obj_ptr, len(b), STRING_OBJECT_SIZE

    def decode(self, obj_ptr: VirtAddr, record: HandleRecord) -> str:
        body_bytes = self._aspace.read(int(obj_ptr) + 16, 48, user=False)
        body = StringBody.from_bytes(body_bytes)
        if body.mode == 0:
            return body.sso_bytes[: body.byte_len].decode("utf-8")
        data = self._aspace.read(int(body.heap_ptr), int(body.heap_len), user=False)
        return data.decode("utf-8")

    def encode(self, obj_ptr: VirtAddr, record: HandleRecord, value: str) -> Tuple[VirtAddr, int, int]:
        old_body_bytes = self._aspace.read(int(obj_ptr) + 16, 48, user=False)
        old_body = StringBody.from_bytes(old_body_bytes)
        if old_body.mode == 1 and int(old_body.heap_ptr) != 0:
            self._heap.free_object(int(old_body.heap_ptr) - 16)

        b = value.encode("utf-8")
        self._heap.write_object_header(obj_ptr, ObjectHeader(type=self.type_id, flags=0, byte_len=len(b), byte_cap=48))
        self._write_body(obj_ptr, b)
        return obj_ptr, len(b), STRING_OBJECT_SIZE

    def free(self, obj_ptr: VirtAddr, record: HandleRecord) -> None:
        body_bytes = self._aspace.read(int(obj_ptr) + 16, 48, user=False)
        body = StringBody.from_bytes(body_bytes)
        if body.mode == 1 and int(body.heap_ptr) != 0:
            self._heap.free_object(int(body.heap_ptr) - 16)
        self._heap.free_object(obj_ptr)

    def _write_body(self, obj_ptr: VirtAddr, utf8: bytes) -> None:
        if len(utf8) <= 24:
            sso = utf8 + b"\x00" * (24 - len(utf8))
            body = StringBody(
                mode=0,
                reserved=0,
                reserved2=0,
                byte_len=len(utf8),
                heap_ptr=0,
                heap_cap=0,
                heap_len=0,
                sso_bytes=sso,
            )
            self._aspace.write(int(obj_ptr) + 16, body.to_bytes(), user=False)
            return

        bytes_ptr, blen, bcap = self._bytes.alloc(utf8)
        body = StringBody(
            mode=1,
            reserved=0,
            reserved2=0,
            byte_len=len(utf8),
            heap_ptr=int(bytes_ptr) + 16,
            heap_cap=bcap,
            heap_len=blen,
            sso_bytes=b"\x00" * 24,
        )
        self._aspace.write(int(obj_ptr) + 16, body.to_bytes(), user=False)


class CodecRegistry:
    def __init__(self):
        self._codecs: Dict[int, Codec] = {}

    def register(self, codec: Codec) -> None:
        self._codecs[int(codec.type_id)] = codec

    def get(self, type_id: int) -> Codec:
        c = self._codecs.get(int(type_id))
        if c is None:
            raise KeyError(type_id)
        return c


class HandleManager:
    def __init__(self, table: HandleTable, registry: CodecRegistry):
        self._table = table
        self._registry = registry

    def alloc_typed(self, type_id: int, value: Any) -> int:
        hid = self._table.alloc_handle_id()
        codec = self._registry.get(type_id)
        obj_ptr, obj_len, obj_cap = codec.alloc(value)
        rec = HandleRecord(
            type=int(type_id),
            state=HANDLE_STATE_VALID,
            owner_pid=0,
            refcnt=1,
            obj_ptr=obj_ptr,
            obj_len=obj_len,
            obj_cap=obj_cap,
        )
        self._table.set_record(hid, rec)
        return hid

    def get_typed(self, handle_id: int) -> Any:
        rec = self._table.get_record(handle_id)
        codec = self._registry.get(int(rec.type))
        return codec.decode(rec.obj_ptr, rec)

    def set_typed(self, handle_id: int, value: Any) -> None:
        rec = self._table.get_record(handle_id)
        codec = self._registry.get(int(rec.type))
        new_ptr, new_len, new_cap = codec.encode(rec.obj_ptr, rec, value)
        if new_ptr != rec.obj_ptr or new_len != rec.obj_len or new_cap != rec.obj_cap:
            if new_ptr != rec.obj_ptr:
                codec.free(rec.obj_ptr, rec)
            rec = replace(rec, obj_ptr=new_ptr, obj_len=new_len, obj_cap=new_cap)
            self._table.set_record(handle_id, rec)

    def free(self, handle_id: int) -> None:
        rec = self._table.get_record(handle_id)
        codec = self._registry.get(int(rec.type))
        codec.free(rec.obj_ptr, rec)
        self._table.free_handle_id(handle_id)
