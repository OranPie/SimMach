from __future__ import annotations

import struct

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.rvexe import PF_R, PF_X, PT_LOAD, RvProgramHeaderV1, build_rvexe_v1
from simmach.syscall import TrapFrame


def _u32(x: int) -> int:
    return int(x) & 0xFFFF_FFFF


def _enc_u(opcode: int, rd: int, imm20: int) -> int:
    return _u32((int(imm20) << 12) | (int(rd) << 7) | int(opcode))


def _enc_i(opcode: int, rd: int, funct3: int, rs1: int, imm12: int) -> int:
    imm12 &= 0xFFF
    return _u32((imm12 << 20) | (int(rs1) << 15) | (int(funct3) << 12) | (int(rd) << 7) | int(opcode))


def _enc_r(opcode: int, rd: int, funct3: int, rs1: int, rs2: int, funct7: int) -> int:
    return _u32(
        (int(funct7) << 25)
        | (int(rs2) << 20)
        | (int(rs1) << 15)
        | (int(funct3) << 12)
        | (int(rd) << 7)
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


def _addiw(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x1B, rd, 0x0, rs1, imm12)


def _addw(rd: int, rs1: int, rs2: int) -> int:
    return _enc_r(0x3B, rd, 0x0, rs1, rs2, 0x00)


def _subw(rd: int, rs1: int, rs2: int) -> int:
    return _enc_r(0x3B, rd, 0x0, rs1, rs2, 0x20)


def _sraiw(rd: int, rs1: int, shamt: int) -> int:
    # funct3=101, funct7=0100000, shamt[4:0]
    imm = (0x20 << 5) | (int(shamt) & 0x1F)
    return _enc_i(0x1B, rd, 0x5, rs1, imm)


def _bne(rs1: int, rs2: int, off: int) -> int:
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
        | (0x1 << 12)
        | (imm_4_1 << 8)
        | (imm_11 << 7)
        | 0x63
    )


def _ecall() -> int:
    return 0x0000_0073


def _load_imm32(code: list[int], rd: int, val: int) -> None:
    upper = (int(val) + (1 << 11)) >> 12
    low = int(val) - (upper << 12)
    code.append(_lui(rd, upper & 0xFFFFF))
    code.append(_addi(rd, rd, low))


def main() -> None:
    physmem = PhysMem(size_bytes=512 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=1024)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    entry = 0x1000_0000
    ok_msg = b"w instr ok\n"
    bad_msg = b"w instr FAIL\n"

    labels: dict[str, int] = {}
    fix_bne: list[tuple[int, str, int, int]] = []
    fix_jal: list[tuple[int, str, int]] = []

    code: list[int] = []

    def mark(name: str) -> None:
        labels[name] = len(code)

    def bne_to(rs1: int, rs2: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fix_bne.append((idx, label, int(rs1), int(rs2)))

    def jal_to(rd: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fix_jal.append((idx, label, int(rd)))

    mark("start")

    _load_imm32(code, 5, -1)
    code.append(_addiw(6, 5, 1))
    bne_to(6, 0, "fail")

    _load_imm32(code, 7, 1)
    code.append(_addw(6, 5, 7))
    bne_to(6, 0, "fail")

    _load_imm32(code, 5, 0x8000_0000)
    code.append(_sraiw(6, 5, 31))
    _load_imm32(code, 7, -1)
    bne_to(6, 7, "fail")

    _load_imm32(code, 5, 0)
    _load_imm32(code, 7, 1)
    code.append(_subw(6, 5, 7))
    _load_imm32(code, 7, -1)
    bne_to(6, 7, "fail")

    jal_to(0, "ok")

    mark("fail")
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, entry + 0x220)
    _load_imm32(code, 12, len(bad_msg))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())
    _load_imm32(code, 10, 1)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    mark("ok")
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, entry + 0x200)
    _load_imm32(code, 12, len(ok_msg))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())
    _load_imm32(code, 10, 0)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    for idx, label, rs1, rs2 in fix_bne:
        cur_pc = entry + idx * 4
        tgt_pc = entry + labels[label] * 4
        off = tgt_pc - cur_pc
        code[idx] = _bne(int(rs1), int(rs2), off)

    for idx, label, rd in fix_jal:
        cur_pc = entry + idx * 4
        tgt_pc = entry + labels[label] * 4
        off = tgt_pc - cur_pc
        code[idx] = _jal(int(rd), off)

    code_blob = b"".join(struct.pack("<I", insn) for insn in code)
    payload = code_blob
    if len(payload) > 0x200:
        raise ValueError("code too large")
    payload = payload + b"\x00" * (0x200 - len(payload)) + ok_msg
    payload = payload + b"\x00" * (0x220 - len(payload)) + bad_msg

    ph = RvProgramHeaderV1(
        type=PT_LOAD,
        flags=PF_R | PF_X,
        vaddr=entry,
        file_off=0,
        file_size=len(payload),
        mem_size=len(payload),
    )
    rvx = build_rvexe_v1(entry=entry, segments=[ph], payloads=[payload])

    inode = fs.create_file("/bin/wtest")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/wtest\x00", user=True)

    entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    assert entry_ret == entry
    k.run_user_rv64(pid, entry_ret)


if __name__ == "__main__":
    main()
