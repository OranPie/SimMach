from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from simmach.mem import AddressSpace


@dataclass(slots=True)
class Process:
    pid: int
    aspace: AddressSpace
    cwd: str = "/"
    exit_status: Optional[int] = None
    start_rip: Optional[int] = None
    start_rsp: Optional[int] = None
    start_a0: Optional[int] = None
    start_a1: Optional[int] = None
    start_a2: Optional[int] = None
    parent_pid: int = 0
    children: List[int] = field(default_factory=list)
    zombie_children: List[int] = field(default_factory=list)
    fds: Dict[int, Union[str, "OpenFile", Any]] = field(default_factory=dict)
    next_fd: int = 3

    # Per-process mmap bookkeeping (anonymous mappings)
    mmap_base: int = 0x2000_0000
    mmap_end: int = 0x3000_0000
    mmap_regions: List[Tuple[int, int]] = field(default_factory=list)
    mmap_files: Dict[int, "MmapFileMapping"] = field(default_factory=dict)


@dataclass(slots=True)
class MmapFileMapping:
    base: int
    length: int
    inode: Any
    file_off: int
    shared: bool


@dataclass(slots=True)
class OpenFile:
    inode: Any
    offset: int = 0


@dataclass(slots=True)
class Thread:
    tid: int
    pid: int
    script: List[Tuple[int, int, int, int]]
    ip: int = 0
    runnable: bool = True

    def next_op(self) -> Optional[Tuple[int, int, int, int]]:
        if self.ip >= len(self.script):
            return None
        op = self.script[self.ip]
        self.ip += 1
        return op
