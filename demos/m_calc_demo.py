from __future__ import annotations

import struct

from constants import CalcFlags, CalcOp, PAGE_SIZE, Sysno
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.syscall import TrapFrame

_U64 = struct.Struct("<Q")


def main() -> None:
    physmem = PhysMem(size_bytes=128 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    aspace = AddressSpace(physmem, frame_alloc)
    k = Kernel(aspace)
    pid = k.create_process()

    pas = k.processes[pid].aspace
    user = 0x1000_0000
    pas.map_page(user, PageFlags.R | PageFlags.W | PageFlags.USER)

    # Layout in user page
    desc_ptr = user + 0x00
    a_ptr = user + 0x40
    b_ptr = user + 0x48
    out_ptr = user + 0x50

    # a=7, b=5
    pas.write(a_ptr, _U64.pack(7), user=True)
    pas.write(b_ptr, _U64.pack(5), user=True)

    # desc: op=u64 add
    desc = struct.pack("<IIQQQ", int(CalcOp.ADD), 0, a_ptr, b_ptr, out_ptr)
    pas.write(desc_ptr, desc, user=True)

    tf = TrapFrame(rax=int(Sysno.CALC), rdi=desc_ptr)
    assert k.syscalls.dispatch(k, pid, tf) == 0
    assert _U64.unpack(pas.read(out_ptr, 8, user=True))[0] == 12

    # cmp: 7 > 5 => 1 (encoded as i64 => u64 1)
    desc2 = struct.pack("<IIQQQ", int(CalcOp.CMP), 0, a_ptr, b_ptr, out_ptr)
    pas.write(desc_ptr, desc2, user=True)
    assert k.syscalls.dispatch(k, pid, tf) == 0
    assert _U64.unpack(pas.read(out_ptr, 8, user=True))[0] == 1

    # div0 -> -EINVAL
    pas.write(b_ptr, _U64.pack(0), user=True)
    desc3 = struct.pack("<IIQQQ", int(CalcOp.DIV), 0, a_ptr, b_ptr, out_ptr)
    pas.write(desc_ptr, desc3, user=True)
    r = k.syscalls.dispatch(k, pid, tf)
    assert r < 0

    # EFAULT: out_ptr unmapped
    bad_out = user + PAGE_SIZE + 0x10
    desc4 = struct.pack("<IIQQQ", int(CalcOp.ADD), 0, a_ptr, a_ptr, bad_out)
    pas.write(desc_ptr, desc4, user=True)
    r2 = k.syscalls.dispatch(k, pid, tf)
    assert r2 < 0

    print("calc demo ok")


if __name__ == "__main__":
    main()
