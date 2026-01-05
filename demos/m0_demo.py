from __future__ import annotations

from constants import PAGE_SIZE
from simmach.errors import InvalidAddress, OOMError
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem


def main() -> None:
    physmem = PhysMem(size_bytes=2 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    v0 = 0x1000_0000

    # 1) map a page and roundtrip read/write
    aspace.map_page(v0, PageFlags.R | PageFlags.W)
    aspace.write(v0 + 123, b"hello")
    assert aspace.read(v0 + 123, 5) == b"hello"

    # 2) unmapped access -> InvalidAddress
    try:
        aspace.read(v0 + PAGE_SIZE, 1)
        raise AssertionError("expected InvalidAddress")
    except InvalidAddress:
        pass

    # 3) OOM when allocating beyond physical frames
    aspace.map_page(v0 + PAGE_SIZE, PageFlags.R | PageFlags.W)
    try:
        aspace.map_page(v0 + 2 * PAGE_SIZE, PageFlags.R | PageFlags.W)
        raise AssertionError("expected OOMError")
    except OOMError:
        pass

    # 4) dump mappings
    for virt_base, phys_base, flags in aspace.pagetable.dump_mappings():
        print(f"{virt_base:#x} -> {phys_base:#x} flags={int(flags)}")

    print("M0 demo ok")


if __name__ == "__main__":
    main()
