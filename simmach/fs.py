from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from simmach.block import BlockDevice


_TINYFS_MAGIC = b"TFS1"


@dataclass(frozen=True, slots=True)
class Inode:
    start_block: int
    size_bytes: int


class TinyFS:
    """A minimal FS backed by BlockDevice.

    Layout:
    - block 0: superblock + directory table
      - magic: 4 bytes
      - nfiles: u32
      - entries: nfiles * 64 bytes
        - name: 48 bytes (nul-terminated utf-8)
        - start_block: u32
        - size_bytes: u32
        - reserved: 8 bytes

    All file data is stored in contiguous blocks starting at start_block.
    """

    _HDR = struct.Struct("<4sI")
    _ENT = struct.Struct("<48sII8s")

    def __init__(self, dev: BlockDevice):
        self._dev = dev
        self._index: Dict[str, Inode] = {}

    def format_and_mount(self, files: Dict[str, bytes]) -> None:
        if self._dev.block_size < 512:
            raise ValueError("block_size too small")

        # Simple contiguous allocator starting at block 1.
        next_block = 1
        entries = []
        for path, content in files.items():
            if not path.startswith("/"):
                raise ValueError("path must be absolute")
            data = bytes(content)
            blocks = (len(data) + self._dev.block_size - 1) // self._dev.block_size
            start = next_block
            next_block += blocks
            if next_block > self._dev.num_blocks:
                raise ValueError("not enough blocks")

            # write file blocks
            for i in range(blocks):
                chunk = data[i * self._dev.block_size : (i + 1) * self._dev.block_size]
                chunk = chunk + b"\x00" * (self._dev.block_size - len(chunk))
                self._dev.write_block(start + i, chunk)

            name = path.encode("utf-8")
            if len(name) >= 48:
                raise ValueError("path too long for TinyFS")
            name = name + b"\x00" * (48 - len(name))
            entries.append((name, start, len(data), b"\x00" * 8))

        # build block0
        raw = bytearray(self._dev.block_size)
        raw[0 : self._HDR.size] = self._HDR.pack(_TINYFS_MAGIC, len(entries))
        off = self._HDR.size
        for ent in entries:
            raw[off : off + self._ENT.size] = self._ENT.pack(*ent)
            off += self._ENT.size
            if off > self._dev.block_size:
                raise ValueError("directory too large")
        self._dev.write_block(0, bytes(raw))

        self.mount()

    def mount(self) -> None:
        block0 = self._dev.read_block(0)
        magic, nfiles = self._HDR.unpack_from(block0, 0)
        if magic != _TINYFS_MAGIC:
            raise ValueError("bad fs magic")

        self._index.clear()
        off = self._HDR.size
        for _ in range(int(nfiles)):
            name_raw, start_block, size_bytes, _ = self._ENT.unpack_from(block0, off)
            off += self._ENT.size
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8")
            self._index[name] = Inode(start_block=int(start_block), size_bytes=int(size_bytes))

    def lookup(self, path: str) -> Optional[Inode]:
        return self._index.get(path)

    def read_inode(self, inode: Inode, offset: int, count: int) -> bytes:
        if offset < 0 or count < 0:
            raise ValueError("invalid offset/count")
        if offset >= inode.size_bytes:
            return b""
        n = min(count, inode.size_bytes - offset)

        # translate to device offset
        dev_off = inode.start_block * self._dev.block_size + offset
        return self._dev.read_at(dev_off, n)


_BFS_MAGIC = b"BFS1"


@dataclass(slots=True)
class BetterInode:
    inum: int
    is_dir: bool
    size_bytes: int
    direct: List[int]


class BetterFS:
    _SB = struct.Struct("<4sIIIIII")
    _INODE = struct.Struct("<BBHI12II")
    _DENT = struct.Struct("<48sI12s")

    _TYPE_FILE = 1
    _TYPE_DIR = 2

    def __init__(self, dev: BlockDevice, *, max_inodes: int = 128):
        self._dev = dev
        self._max_inodes = int(max_inodes)
        self._inode_table: List[Optional[BetterInode]] = [None] * self._max_inodes
        self._data_bitmap: bytearray = bytearray()
        self._inode_start = 0
        self._inode_blocks = 0
        self._bm_start = 0
        self._bm_blocks = 0
        self._data_start = 0
        self._root_inum = 1

    def _bitmap_test(self, block_no: int) -> bool:
        byte_i = block_no // 8
        bit_i = block_no % 8
        return bool(self._data_bitmap[byte_i] & (1 << bit_i))

    def _bitmap_set(self, block_no: int, used: bool) -> None:
        byte_i = block_no // 8
        bit_i = block_no % 8
        if used:
            self._data_bitmap[byte_i] |= (1 << bit_i)
        else:
            self._data_bitmap[byte_i] &= ~(1 << bit_i)

    def _flush_superblock(self) -> None:
        raw = bytearray(self._dev.block_size)
        raw[0 : self._SB.size] = self._SB.pack(
            _BFS_MAGIC,
            int(self._dev.block_size),
            int(self._dev.num_blocks),
            int(self._inode_start),
            int(self._inode_blocks),
            int(self._bm_start),
            int(self._bm_blocks),
        )
        self._dev.write_block(0, bytes(raw))

    def _flush_bitmap(self) -> None:
        off = 0
        for b in range(self._bm_blocks):
            chunk = bytes(self._data_bitmap[off : off + self._dev.block_size])
            if len(chunk) < self._dev.block_size:
                chunk = chunk + b"\x00" * (self._dev.block_size - len(chunk))
            self._dev.write_block(self._bm_start + b, chunk)
            off += self._dev.block_size

    def _flush_inodes(self) -> None:
        per_block = self._dev.block_size // self._INODE.size
        idx = 0
        for b in range(self._inode_blocks):
            raw = bytearray(self._dev.block_size)
            for j in range(per_block):
                if idx >= self._max_inodes:
                    break
                inode = self._inode_table[idx]
                if inode is None:
                    packed = self._INODE.pack(0, 0, 0, 0, *([0] * 12), 0)
                else:
                    typ = self._TYPE_DIR if inode.is_dir else self._TYPE_FILE
                    direct = list(inode.direct)[:12]
                    direct += [0] * (12 - len(direct))
                    packed = self._INODE.pack(1, typ, 1, int(inode.size_bytes), *direct, 0)
                off = j * self._INODE.size
                raw[off : off + self._INODE.size] = packed
                idx += 1
            self._dev.write_block(self._inode_start + b, bytes(raw))

    def _load_superblock(self) -> None:
        block0 = self._dev.read_block(0)
        magic, block_size, num_blocks, inode_start, inode_blocks, bm_start, bm_blocks = self._SB.unpack_from(block0, 0)
        if magic != _BFS_MAGIC:
            raise ValueError("bad fs magic")
        if int(block_size) != int(self._dev.block_size) or int(num_blocks) != int(self._dev.num_blocks):
            raise ValueError("block device geometry mismatch")
        self._inode_start = int(inode_start)
        self._inode_blocks = int(inode_blocks)
        self._bm_start = int(bm_start)
        self._bm_blocks = int(bm_blocks)
        self._data_start = 1 + self._inode_blocks + self._bm_blocks

    def _load_bitmap(self) -> None:
        self._data_bitmap = bytearray(self._bm_blocks * self._dev.block_size)
        off = 0
        for b in range(self._bm_blocks):
            blk = self._dev.read_block(self._bm_start + b)
            self._data_bitmap[off : off + self._dev.block_size] = blk
            off += self._dev.block_size

    def _load_inodes(self) -> None:
        per_block = self._dev.block_size // self._INODE.size
        idx = 0
        for b in range(self._inode_blocks):
            raw = self._dev.read_block(self._inode_start + b)
            for j in range(per_block):
                if idx >= self._max_inodes:
                    break
                off = j * self._INODE.size
                used, typ, _nlink, size, *direct, _pad = self._INODE.unpack_from(raw, off)
                if used == 0:
                    self._inode_table[idx] = None
                else:
                    is_dir = int(typ) == self._TYPE_DIR
                    self._inode_table[idx] = BetterInode(
                        inum=idx,
                        is_dir=is_dir,
                        size_bytes=int(size),
                        direct=[int(x) for x in direct if int(x) != 0],
                    )
                idx += 1

    def format_and_mount(self, *, create_default_dirs: bool = True) -> None:
        if self._dev.block_size < 512:
            raise ValueError("block_size too small")

        self._inode_blocks = max(1, (self._max_inodes * self._INODE.size + self._dev.block_size - 1) // self._dev.block_size)
        self._inode_start = 1
        self._bm_start = self._inode_start + self._inode_blocks

        nbits = self._dev.num_blocks
        bm_bytes = (nbits + 7) // 8
        self._bm_blocks = max(1, (bm_bytes + self._dev.block_size - 1) // self._dev.block_size)
        self._data_start = 1 + self._inode_blocks + self._bm_blocks

        if self._data_start >= self._dev.num_blocks:
            raise ValueError("device too small")

        self._inode_table = [None] * self._max_inodes
        self._data_bitmap = bytearray(self._bm_blocks * self._dev.block_size)

        for blk in range(self._data_start):
            self._bitmap_set(blk, True)

        self._inode_table[0] = None
        root = BetterInode(inum=self._root_inum, is_dir=True, size_bytes=0, direct=[])
        self._inode_table[self._root_inum] = root
        self._ensure_dir_block(root)
        if create_default_dirs:
            self.mkdir("/tmp")
            self.mkdir("/bin")
            self.mkdir("/etc")

        self._flush_superblock()
        self._flush_inodes()
        self._flush_bitmap()

    def mount(self) -> None:
        self._load_superblock()
        self._load_bitmap()
        self._load_inodes()

    def _alloc_block(self) -> int:
        for blk in range(self._data_start, self._dev.num_blocks):
            if not self._bitmap_test(blk):
                self._bitmap_set(blk, True)
                self._flush_bitmap()
                self._dev.write_block(blk, b"\x00" * self._dev.block_size)
                return int(blk)
        raise ValueError("out of blocks")

    def _free_block(self, blk: int) -> None:
        if blk < self._data_start or blk >= self._dev.num_blocks:
            return
        self._bitmap_set(int(blk), False)
        self._flush_bitmap()

    def _alloc_inode(self, *, is_dir: bool) -> BetterInode:
        for i in range(1, self._max_inodes):
            if self._inode_table[i] is None:
                ino = BetterInode(inum=i, is_dir=bool(is_dir), size_bytes=0, direct=[])
                self._inode_table[i] = ino
                self._flush_inodes()
                return ino
        raise ValueError("out of inodes")

    def _get_inode(self, inum: int) -> BetterInode:
        inode = self._inode_table[int(inum)]
        if inode is None:
            raise ValueError("bad inum")
        return inode

    def _ensure_dir_block(self, inode: BetterInode) -> None:
        if inode.direct:
            return
        blk = self._alloc_block()
        inode.direct.append(int(blk))
        inode.size_bytes = 0
        self._flush_inodes()

    def _read_dir_entries(self, inode: BetterInode) -> List[Tuple[str, int]]:
        if not inode.is_dir:
            raise ValueError("not a directory")
        out: List[Tuple[str, int]] = []
        raw = self.read_inode(inode, 0, int(inode.size_bytes))
        for off in range(0, len(raw), self._DENT.size):
            ent = raw[off : off + self._DENT.size]
            if len(ent) < self._DENT.size:
                break
            name_raw, inum, _ = self._DENT.unpack(ent)
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8")
            if not name:
                continue
            out.append((name, int(inum)))
        return out

    def _lookup_child(self, parent: BetterInode, name: str) -> Optional[BetterInode]:
        for n, inum in self._read_dir_entries(parent):
            if n == name:
                return self._inode_table[int(inum)]
        return None

    def _write_dir_entries(self, inode: BetterInode, entries: List[Tuple[str, int]]) -> None:
        buf = bytearray()
        for name, inum in entries:
            bname = name.encode("utf-8")
            if len(bname) >= 48:
                raise ValueError("name too long")
            bname = bname + b"\x00" * (48 - len(bname))
            buf += self._DENT.pack(bname, int(inum), b"\x00" * 12)
        self.write_inode(inode, 0, bytes(buf), truncate=True)

    def _split_path(self, path: str) -> List[str]:
        if not path.startswith("/"):
            raise ValueError("path must be absolute")
        parts = [p for p in path.split("/") if p]
        return parts

    def lookup(self, path: str) -> Optional[BetterInode]:
        if path == "/":
            return self._get_inode(self._root_inum)
        parts = self._split_path(path)
        cur = self._get_inode(self._root_inum)
        for name in parts:
            if not cur.is_dir:
                return None
            entries = self._read_dir_entries(cur)
            nxt = None
            for n, inum in entries:
                if n == name:
                    nxt = self._inode_table[inum]
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur

    def mkdir(self, path: str) -> BetterInode:
        return self._create_path(path, is_dir=True)

    def create_file(self, path: str) -> BetterInode:
        return self._create_path(path, is_dir=False)

    def _create_path(self, path: str, *, is_dir: bool) -> BetterInode:
        if path == "/":
            raise ValueError("cannot create root")
        parts = self._split_path(path)
        parent_parts = parts[:-1]
        leaf = parts[-1]

        parent = self._get_inode(self._root_inum)
        for name in parent_parts:
            nxt = self._lookup_child(parent, name)
            if nxt is None:
                nxt = self._create_child(parent, name, is_dir=True)
            parent = nxt

        entries = self._read_dir_entries(parent)
        for n, inum in entries:
            if n == leaf:
                inode = self._inode_table[inum]
                if inode is None:
                    raise ValueError("dangling dir entry")
                return inode

        child = self._create_child(parent, leaf, is_dir=is_dir)
        return child

    def _create_child(self, parent: BetterInode, name: str, *, is_dir: bool) -> BetterInode:
        if not parent.is_dir:
            raise ValueError("parent not dir")
        child = self._alloc_inode(is_dir=is_dir)
        if is_dir:
            self._ensure_dir_block(child)

        entries = self._read_dir_entries(parent)
        entries.append((name, int(child.inum)))
        self._write_dir_entries(parent, entries)
        self._flush_inodes()
        return child

    def listdir(self, path: str) -> List[str]:
        inode = self.lookup(path)
        if inode is None or not inode.is_dir:
            raise ValueError("not a directory")
        return [n for (n, _) in self._read_dir_entries(inode)]

    def read_inode(self, inode: BetterInode, offset: int, count: int) -> bytes:
        if offset < 0 or count < 0:
            raise ValueError("invalid offset/count")
        if offset >= inode.size_bytes:
            return b""
        n = min(count, inode.size_bytes - offset)

        out = bytearray()
        remaining = n
        cursor = int(offset)
        while remaining > 0:
            blk_i = cursor // self._dev.block_size
            blk_off = cursor % self._dev.block_size
            if blk_i >= len(inode.direct):
                break
            blk_no = int(inode.direct[blk_i])
            raw = self._dev.read_block(blk_no)
            take = min(remaining, self._dev.block_size - blk_off)
            out += raw[blk_off : blk_off + take]
            cursor += take
            remaining -= take
        return bytes(out)

    def truncate_inode(self, inode: BetterInode, new_size: int) -> None:
        if new_size < 0:
            raise ValueError("new_size must be non-negative")
        old_size = int(inode.size_bytes)
        if new_size == old_size:
            return

        if new_size < old_size:
            need_blocks = (new_size + self._dev.block_size - 1) // self._dev.block_size if new_size > 0 else 0
            while len(inode.direct) > need_blocks:
                blk = inode.direct.pop()
                self._free_block(int(blk))
            inode.size_bytes = int(new_size)
            self._flush_inodes()
            return

        self._ensure_capacity(inode, new_size)
        inode.size_bytes = int(new_size)
        self._flush_inodes()

    def _ensure_capacity(self, inode: BetterInode, size_bytes: int) -> None:
        need_blocks = (int(size_bytes) + self._dev.block_size - 1) // self._dev.block_size
        while len(inode.direct) < need_blocks:
            inode.direct.append(self._alloc_block())
        self._flush_inodes()

    def write_inode(self, inode: BetterInode, offset: int, data: bytes, *, truncate: bool = False) -> int:
        if offset < 0:
            raise ValueError("offset must be non-negative")

        end = int(offset) + len(data)
        if truncate:
            self.truncate_inode(inode, end)
        else:
            if end > inode.size_bytes:
                self._ensure_capacity(inode, end)
                inode.size_bytes = int(end)
                self._flush_inodes()

        remaining = len(data)
        cursor = int(offset)
        src_off = 0
        while remaining > 0:
            blk_i = cursor // self._dev.block_size
            blk_off = cursor % self._dev.block_size
            blk_no = int(inode.direct[blk_i])
            raw = bytearray(self._dev.read_block(blk_no))
            take = min(remaining, self._dev.block_size - blk_off)
            raw[blk_off : blk_off + take] = data[src_off : src_off + take]
            self._dev.write_block(blk_no, bytes(raw))
            cursor += take
            src_off += take
            remaining -= take
        return len(data)
