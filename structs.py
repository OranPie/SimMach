from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar, TypeAlias

from constants import (
    HANDLE_RECORD_SIZE,
    HANDLE_RECORD_VERSION,
    HANDLE_TABLE_HEADER_SIZE,
    HANDLE_TABLE_VERSION,
    LITTLE_ENDIAN,
    MAGIC_HANDLE_TABLE_HEADER,
    MAGIC_OBJECT_HEADER,
    OBJECT_HEADER_SIZE,
    STRING_BODY_SIZE,
)

VirtAddr: TypeAlias = int


def _u8(v: int) -> int:
    if not (0 <= v <= 0xFF):
        raise ValueError(f"u8 out of range: {v}")
    return v


def _u16(v: int) -> int:
    if not (0 <= v <= 0xFFFF):
        raise ValueError(f"u16 out of range: {v}")
    return v


def _u32(v: int) -> int:
    if not (0 <= v <= 0xFFFF_FFFF):
        raise ValueError(f"u32 out of range: {v}")
    return v


def _u64(v: int) -> int:
    if not (0 <= v <= 0xFFFF_FFFF_FFFF_FFFF):
        raise ValueError(f"u64 out of range: {v}")
    return v


@dataclass(frozen=True, slots=True)
class ObjectHeader:
    magic: int = MAGIC_OBJECT_HEADER
    type: int = 0
    flags: int = 0
    byte_len: int = 0
    byte_cap: int = 0

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(f"{LITTLE_ENDIAN}IHHII")

    def to_bytes(self) -> bytes:
        return self._STRUCT.pack(
            _u32(self.magic),
            _u16(self.type),
            _u16(self.flags),
            _u32(self.byte_len),
            _u32(self.byte_cap),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ObjectHeader":
        if len(data) < OBJECT_HEADER_SIZE:
            raise ValueError("buffer too small for ObjectHeader")
        magic, type_, flags, byte_len, byte_cap = cls._STRUCT.unpack_from(data, 0)
        return cls(
            magic=magic,
            type=type_,
            flags=flags,
            byte_len=byte_len,
            byte_cap=byte_cap,
        )


@dataclass(frozen=True, slots=True)
class HandleTableHeader:
    magic: int = MAGIC_HANDLE_TABLE_HEADER
    version: int = HANDLE_TABLE_VERSION
    record_size: int = HANDLE_RECORD_SIZE
    max_handles: int = 0
    next_id: int = 0
    free_head: int = -1
    reserved: bytes = b"\x00" * 40

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(f"{LITTLE_ENDIAN}IIIIIi40s")

    def to_bytes(self) -> bytes:
        if len(self.reserved) != 40:
            raise ValueError("reserved must be exactly 40 bytes")
        data = self._STRUCT.pack(
            _u32(self.magic),
            _u32(self.version),
            _u32(self.record_size),
            _u32(self.max_handles),
            _u32(self.next_id),
            int(self.free_head),
            self.reserved,
        )
        if len(data) != HANDLE_TABLE_HEADER_SIZE:
            raise AssertionError("HandleTableHeader size mismatch")
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "HandleTableHeader":
        if len(data) < HANDLE_TABLE_HEADER_SIZE:
            raise ValueError("buffer too small for HandleTableHeader")
        (magic, version, record_size, max_handles, next_id, free_head, reserved) = cls._STRUCT.unpack_from(
            data, 0
        )
        return cls(
            magic=magic,
            version=version,
            record_size=record_size,
            max_handles=max_handles,
            next_id=next_id,
            free_head=free_head,
            reserved=reserved,
        )


@dataclass(frozen=True, slots=True)
class HandleRecord:
    version: int = HANDLE_RECORD_VERSION
    type: int = 0
    state: int = 0
    owner_pid: int = 0
    refcnt: int = 1
    obj_ptr: VirtAddr = 0
    obj_len: int = 0
    obj_cap: int = 0

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(f"{LITTLE_ENDIAN}IHHIIQII")

    def to_bytes(self) -> bytes:
        return self._STRUCT.pack(
            _u32(self.version),
            _u16(self.type),
            _u16(self.state),
            _u32(self.owner_pid),
            _u32(self.refcnt),
            _u64(int(self.obj_ptr)),
            _u32(self.obj_len),
            _u32(self.obj_cap),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HandleRecord":
        if len(data) < HANDLE_RECORD_SIZE:
            raise ValueError("buffer too small for HandleRecord")
        (version, type_, state, owner_pid, refcnt, obj_ptr, obj_len, obj_cap) = cls._STRUCT.unpack_from(
            data, 0
        )
        return cls(
            version=version,
            type=type_,
            state=state,
            owner_pid=owner_pid,
            refcnt=refcnt,
            obj_ptr=obj_ptr,
            obj_len=obj_len,
            obj_cap=obj_cap,
        )


@dataclass(frozen=True, slots=True)
class StringBody:
    mode: int = 0
    reserved: int = 0
    reserved2: int = 0
    byte_len: int = 0
    heap_ptr: VirtAddr = 0
    heap_cap: int = 0
    heap_len: int = 0
    sso_bytes: bytes = b"\x00" * 24

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(f"{LITTLE_ENDIAN}BBHIQII24s")

    def to_bytes(self) -> bytes:
        if len(self.sso_bytes) != 24:
            raise ValueError("sso_bytes must be exactly 24 bytes")
        return self._STRUCT.pack(
            _u8(self.mode),
            _u8(self.reserved),
            _u16(self.reserved2),
            _u32(self.byte_len),
            _u64(int(self.heap_ptr)),
            _u32(self.heap_cap),
            _u32(self.heap_len),
            self.sso_bytes,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "StringBody":
        if len(data) < STRING_BODY_SIZE:
            raise ValueError("buffer too small for StringBody")
        (mode, reserved, reserved2, byte_len, heap_ptr, heap_cap, heap_len, sso_bytes) = cls._STRUCT.unpack_from(
            data, 0
        )
        return cls(
            mode=mode,
            reserved=reserved,
            reserved2=reserved2,
            byte_len=byte_len,
            heap_ptr=heap_ptr,
            heap_cap=heap_cap,
            heap_len=heap_len,
            sso_bytes=sso_bytes,
        )
