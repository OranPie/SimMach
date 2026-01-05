from __future__ import annotations

from dataclasses import dataclass


class SimMachError(Exception):
    pass


class OOMError(SimMachError):
    pass


class InvalidAddress(SimMachError):
    pass


@dataclass(slots=True)
class PageFault(InvalidAddress):
    virt_addr: int
    access: str
    reason: str


class ResourceLimitError(SimMachError):
    pass
