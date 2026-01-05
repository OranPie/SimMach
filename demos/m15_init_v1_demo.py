from __future__ import annotations

import struct

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.rvexe import PF_R, PF_W, PF_X, PT_LOAD, RvProgramHeaderV1, build_rvexe_v1
from simmach.syscall import TrapFrame


def _u32(x: int) -> int:
    return int(x) & 0xFFFF_FFFF


def _enc_u(opcode: int, rd: int, imm20: int) -> int:
    return _u32((int(imm20) << 12) | (int(rd) << 7) | int(opcode))


def _enc_i(opcode: int, rd: int, funct3: int, rs1: int, imm12: int) -> int:
    imm12 &= 0xFFF
    return _u32((imm12 << 20) | (int(rs1) << 15) | (int(funct3) << 12) | (int(rd) << 7) | int(opcode))


def _enc_s(opcode: int, funct3: int, rs1: int, rs2: int, imm12: int) -> int:
    imm12 &= 0xFFF
    imm_lo = imm12 & 0x1F
    imm_hi = (imm12 >> 5) & 0x7F
    return _u32((imm_hi << 25) | (int(rs2) << 20) | (int(rs1) << 15) | (int(funct3) << 12) | (imm_lo << 7) | int(opcode))


def _enc_b(opcode: int, funct3: int, rs1: int, rs2: int, off: int) -> int:
    if (off & 1) != 0:
        raise ValueError("branch offset must be 2-byte aligned")
    imm = int(off)
    imm &= 0x1FFF
    imm_12 = (imm >> 12) & 0x1
    imm_10_5 = (imm >> 5) & 0x3F
    imm_4_1 = (imm >> 1) & 0xF
    imm_11 = (imm >> 11) & 0x1
    return _u32(
        (imm_12 << 31)
        | (imm_10_5 << 25)
        | (int(rs2) << 20)
        | (int(rs1) << 15)
        | (int(funct3) << 12)
        | (imm_4_1 << 8)
        | (imm_11 << 7)
        | int(opcode)
    )


def _enc_j(opcode: int, rd: int, off: int) -> int:
    if (off & 1) != 0:
        raise ValueError("jal offset must be 2-byte aligned")
    imm = int(off)
    imm &= 0x1FFFFF
    imm_20 = (imm >> 20) & 0x1
    imm_10_1 = (imm >> 1) & 0x3FF
    imm_11 = (imm >> 11) & 0x1
    imm_19_12 = (imm >> 12) & 0xFF
    return _u32(
        (imm_20 << 31)
        | (imm_10_1 << 21)
        | (imm_11 << 20)
        | (imm_19_12 << 12)
        | (int(rd) << 7)
        | int(opcode)
    )


def _jal(rd: int, off: int) -> int:
    return _enc_j(0x6F, rd, off)


def _lui(rd: int, imm20: int) -> int:
    return _enc_u(0x37, rd, imm20)


def _addi(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x13, rd, 0x0, rs1, imm12)


def _ld(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x03, rd, 0x3, rs1, imm12)


def _sd(rs2: int, rs1: int, imm12: int) -> int:
    return _enc_s(0x23, 0x3, rs1, rs2, imm12)


def _beq(rs1: int, rs2: int, off: int) -> int:
    return _enc_b(0x63, 0x0, rs1, rs2, off)


def _bne(rs1: int, rs2: int, off: int) -> int:
    return _enc_b(0x63, 0x1, rs1, rs2, off)


def _ecall() -> int:
    return 0x0000_0073


def _load_imm32(code: list[int], rd: int, val: int) -> None:
    upper = (int(val) + (1 << 11)) >> 12
    low = int(val) - (upper << 12)
    code.append(_lui(rd, upper & 0xFFFFF))
    code.append(_addi(rd, rd, low))


def main() -> None:
    physmem = PhysMem(size_bytes=1024 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=2048)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    entry = 0x1000_0000
    data = 0x1000_4000

    s_child = b"child: hi\n"
    s_parent = b"parent: hi\n"
    s_done = b"parent: waited\n"
    s_log = b"init log\n"
    path_log = b"/tmp/init.log\x00"
    path_mm = b"/tmp/mm.txt\x00"
    seed = b"hello\n"
    world8 = b"WORLD\x00\x00\x00"

    labels: dict[str, int] = {}
    fix_b: list[tuple[int, str, str, int, int]] = []
    fix_j: list[tuple[int, str, int]] = []

    code: list[int] = []

    def mark(name: str) -> None:
        labels[name] = len(code)

    def beq_to(rs1: int, rs2: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fix_b.append((idx, label, "beq", int(rs1), int(rs2)))

    def bne_to(rs1: int, rs2: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fix_b.append((idx, label, "bne", int(rs1), int(rs2)))

    def jal_to(rd: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fix_j.append((idx, label, int(rd)))

    # Helpers: syscall wrapper pattern: set a0..a5, a7 and ecall.
    mark("start")

    # print parent hi
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, data + 0x000)
    _load_imm32(code, 12, len(s_parent))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())

    # fork
    _load_imm32(code, 17, int(Sysno.FORK))
    code.append(_ecall())
    # if a0 == 0 -> child
    beq_to(10, 0, "child")

    # parent path: save child pid to s0(x8)
    code.append(_addi(8, 10, 0))

    # waitpid loop: r = waitpid(child, status_ptr)
    mark("wait_loop")
    code.append(_addi(10, 8, 0))
    _load_imm32(code, 11, data + 0x100)  # status ptr
    _load_imm32(code, 17, int(Sysno.WAITPID))
    code.append(_ecall())
    # if ret == -11 (EAGAIN) => loop
    _load_imm32(code, 6, -11)
    beq_to(10, 6, "wait_loop")

    # print waited
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, data + 0x040)
    _load_imm32(code, 12, len(s_done))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())

    # open /tmp/init.log with create|append flags = 3
    _load_imm32(code, 10, data + 0x080)  # path
    _load_imm32(code, 11, 3)
    _load_imm32(code, 12, 0)
    _load_imm32(code, 17, int(Sysno.OPEN))
    code.append(_ecall())
    # fd in a0 -> s1(x9)
    code.append(_addi(9, 10, 0))

    # write log line
    code.append(_addi(10, 9, 0))
    _load_imm32(code, 11, data + 0x060)
    _load_imm32(code, 12, len(s_log))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())

    # close
    code.append(_addi(10, 9, 0))
    _load_imm32(code, 17, int(Sysno.CLOSE))
    code.append(_ecall())

    # mmap shared file smoke test:
    # open/create /tmp/mm.txt
    _load_imm32(code, 10, data + 0x0A0)
    _load_imm32(code, 11, 1)
    _load_imm32(code, 12, 0)
    _load_imm32(code, 17, int(Sysno.OPEN))
    code.append(_ecall())
    code.append(_addi(9, 10, 0))

    # write seed
    code.append(_addi(10, 9, 0))
    _load_imm32(code, 11, data + 0x0C0)
    _load_imm32(code, 12, len(seed))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())

    # mmap(addr=0, len=4096, prot=RW=3, flags=MAP_FILE|MAP_SHARED=12, fd=s1, off=0)
    _load_imm32(code, 10, 0)
    _load_imm32(code, 11, 4096)
    _load_imm32(code, 12, 3)
    _load_imm32(code, 13, 12)
    code.append(_addi(14, 9, 0))
    _load_imm32(code, 15, 0)
    _load_imm32(code, 17, int(Sysno.MMAP))
    code.append(_ecall())
    # mapped addr -> t0(x5)
    code.append(_addi(5, 10, 0))

    # copy 8 bytes "WORLD..." into mapping: t1=*(world8); *(map)=t1
    _load_imm32(code, 6, data + 0x0D0)
    code.append(_ld(7, 6, 0))
    code.append(_sd(7, 5, 0))

    # munmap(map,4096)
    code.append(_addi(10, 5, 0))
    _load_imm32(code, 11, 4096)
    _load_imm32(code, 17, int(Sysno.MUNMAP))
    code.append(_ecall())

    # close mm fd
    code.append(_addi(10, 9, 0))
    _load_imm32(code, 17, int(Sysno.CLOSE))
    code.append(_ecall())

    # exit 0
    _load_imm32(code, 10, 0)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    mark("child")
    # child prints
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, data + 0x020)
    _load_imm32(code, 12, len(s_child))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())
    # exit 42
    _load_imm32(code, 10, 42)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    # Patch branches/jumps
    for idx, label, kind, rs1, rs2 in fix_b:
        cur_pc = entry + idx * 4
        tgt_pc = entry + labels[label] * 4
        off = tgt_pc - cur_pc
        if kind == "beq":
            code[idx] = _beq(rs1, rs2, off)
        else:
            code[idx] = _bne(rs1, rs2, off)

    for idx, label, rd in fix_j:
        cur_pc = entry + idx * 4
        tgt_pc = entry + labels[label] * 4
        off = tgt_pc - cur_pc
        code[idx] = _jal(rd, off)

    code_blob = b"".join(struct.pack("<I", insn) for insn in code)

    # Build data blob
    data_blob = bytearray(0x200)
    data_blob[0x000 : 0x000 + len(s_parent)] = s_parent
    data_blob[0x020 : 0x020 + len(s_child)] = s_child
    data_blob[0x040 : 0x040 + len(s_done)] = s_done
    data_blob[0x060 : 0x060 + len(s_log)] = s_log
    data_blob[0x080 : 0x080 + len(path_log)] = path_log
    data_blob[0x0A0 : 0x0A0 + len(path_mm)] = path_mm
    data_blob[0x0C0 : 0x0C0 + len(seed)] = seed
    data_blob[0x0D0 : 0x0D0 + len(world8)] = world8

    ph_text = RvProgramHeaderV1(type=PT_LOAD, flags=PF_R | PF_X, vaddr=entry, file_off=0, file_size=len(code_blob), mem_size=len(code_blob))
    ph_data = RvProgramHeaderV1(type=PT_LOAD, flags=PF_R | PF_W, vaddr=data, file_off=0, file_size=len(data_blob), mem_size=len(data_blob))
    rvx = build_rvexe_v1(entry=entry, segments=[ph_text, ph_data], payloads=[code_blob, bytes(data_blob)])

    inode = fs.create_file("/bin/initv1")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/initv1\x00", user=True)

    entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    assert entry_ret == entry

    k.run_user_rv64(pid, entry_ret)

    # Verify side effects in FS
    log_inode = fs.lookup("/tmp/init.log")
    assert log_inode is not None
    raw = fs.read_inode(log_inode, 0, 64)
    assert b"init log" in raw

    mm_inode = fs.lookup("/tmp/mm.txt")
    assert mm_inode is not None
    raw2 = fs.read_inode(mm_inode, 0, 16)
    assert raw2.startswith(b"WORLD")

    print("\nM15 init v1 demo ok")


if __name__ == "__main__":
    main()
