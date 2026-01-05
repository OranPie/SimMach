from __future__ import annotations

from constants import PAGE_SIZE
from simmach.errors import OOMError
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem, ValueHeapAllocator
from structs import ObjectHeader


def main() -> None:
    # 3 pages of physical memory: enough for a couple of heap pages + some slack
    physmem = PhysMem(size_bytes=3 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    valueheap_base = 0x2000_0000
    valueheap_size = 2 * PAGE_SIZE

    valueheap = ValueHeapAllocator(
        aspace=aspace,
        virt_base=valueheap_base,
        size_bytes=valueheap_size,
        flags=PageFlags.R | PageFlags.W,
    )

    # 1) allocate an object block, header should be written into memory
    obj_ptr, _ = valueheap.alloc_object(type_id=1, flags=0, byte_len=8, byte_cap=16)
    hdr = valueheap.read_object_header(obj_ptr)
    assert isinstance(hdr, ObjectHeader)
    assert hdr.type == 1
    assert hdr.byte_len == 8
    assert hdr.byte_cap == 16

    # 2) mutate header in-place
    valueheap.write_object_header(obj_ptr, ObjectHeader(type=2, flags=3, byte_len=4, byte_cap=32))
    hdr2 = valueheap.read_object_header(obj_ptr)
    assert hdr2.type == 2
    assert hdr2.flags == 3
    assert hdr2.byte_len == 4
    assert hdr2.byte_cap == 32

    # 3) OOM when exhausting ValueHeap virtual region
    try:
        while True:
            valueheap.alloc_block(PAGE_SIZE, align=16)
    except OOMError:
        pass

    print("M1 demo ok")


if __name__ == "__main__":
    main()
