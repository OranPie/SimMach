from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict

from constants import Errno


@dataclass(slots=True)
class TrapFrame:
    rax: int = 0
    rdi: int = 0
    rsi: int = 0
    rdx: int = 0
    r10: int = 0
    r8: int = 0
    r9: int = 0


SyscallHandler = Callable[["Kernel", int, TrapFrame], int]


class SyscallTable:
    def __init__(self):
        self._handlers: Dict[int, SyscallHandler] = {}

    def register(self, sysno: int, fn: SyscallHandler) -> None:
        self._handlers[int(sysno)] = fn

    def dispatch(self, kernel: "Kernel", pid: int, tf: TrapFrame) -> int:
        fn = self._handlers.get(int(tf.rax))
        if fn is None:
            return int(Errno.EINVAL)
        return int(fn(kernel, pid, tf))
