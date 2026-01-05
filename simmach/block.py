from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class BlockDevice:
    block_size: int
    num_blocks: int
    _data: bytearray = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.block_size <= 0:
            raise ValueError("block_size must be positive")
        if self.num_blocks <= 0:
            raise ValueError("num_blocks must be positive")
        self._data = bytearray(self.block_size * self.num_blocks)

    @property
    def size_bytes(self) -> int:
        return len(self._data)

    def read_block(self, block_no: int) -> bytes:
        if block_no < 0 or block_no >= self.num_blocks:
            raise ValueError("invalid block_no")
        off = block_no * self.block_size
        return bytes(self._data[off : off + self.block_size])

    def write_block(self, block_no: int, data: bytes) -> None:
        if block_no < 0 or block_no >= self.num_blocks:
            raise ValueError("invalid block_no")
        if len(data) != self.block_size:
            raise ValueError("data must be exactly one block")
        off = block_no * self.block_size
        self._data[off : off + self.block_size] = data

    def read_at(self, offset: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if offset < 0 or offset + size > self.size_bytes:
            raise ValueError("read_at out of range")
        return bytes(self._data[offset : offset + size])

    def write_at(self, offset: int, data: bytes) -> None:
        if offset < 0 or offset + len(data) > self.size_bytes:
            raise ValueError("write_at out of range")
        self._data[offset : offset + len(data)] = data
