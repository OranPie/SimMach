from __future__ import annotations

from constants import PAGE_SIZE, HandleType
from simmach.errors import ResourceLimitError
from simmach.mem import AddressSpace, FrameAllocator, PageAllocator, PageFlags, PhysMem, ValueHeapAllocator
from simmach.handle import BytesCodec, CodecRegistry, HandleManager, HandleTable, Int64Codec, StringCodec


def main() -> None:
    physmem = PhysMem(size_bytes=64 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)

    ht_base = 0x3000_0000
    ht_alloc = PageAllocator(aspace, ht_base, 4 * PAGE_SIZE, PageFlags.R | PageFlags.W)
    ht = HandleTable(aspace, ht_alloc)
    ht.attach(max_handles=3)

    vh_base = 0x4000_0000
    vh = ValueHeapAllocator(aspace, vh_base, 32 * PAGE_SIZE, PageFlags.R | PageFlags.W)

    reg = CodecRegistry()
    bytes_codec = BytesCodec(aspace, vh)
    reg.register(bytes_codec)
    reg.register(Int64Codec(aspace, vh))
    reg.register(StringCodec(aspace, vh, bytes_codec))

    hm = HandleManager(ht, reg)

    h1 = hm.alloc_typed(int(HandleType.Int64), 42)
    assert hm.get_typed(h1) == 42
    hm.set_typed(h1, -7)
    assert hm.get_typed(h1) == -7

    hs = hm.alloc_typed(int(HandleType.String), "hi")
    assert hm.get_typed(hs) == "hi"

    hl = hm.alloc_typed(int(HandleType.String), "A" * 100)
    assert hm.get_typed(hl) == "A" * 100

    try:
        hm.alloc_typed(int(HandleType.Int64), 1)
        raise AssertionError("expected ResourceLimitError")
    except ResourceLimitError:
        pass

    hm.free(h1)
    h4 = hm.alloc_typed(int(HandleType.Int64), 123)
    assert hm.get_typed(h4) == 123

    print("M1 handle demo ok")


if __name__ == "__main__":
    main()
