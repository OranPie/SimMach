from __future__ import annotations

from dataclasses import dataclass

from constants import Errno
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace

@dataclass(slots=True)
class ShellEnv:
    k: Kernel
    fs: BetterFS
    kas: AddressSpace
    cwd: str = "/"

def _errno_name(x: int) -> str | None:
    try:
        return Errno(int(x)).name
    except Exception:
        return None
