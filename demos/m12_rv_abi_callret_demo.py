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


def _enc_b(opcode: int, funct3: int, rs1: int, rs2: int, off: int) -> int:
    # off is signed byte offset relative to current pc
    if (off & 1) != 0:
        raise ValueError("branch offset must be 2-byte aligned")
    imm = int(off)
    if imm < -(1 << 12) or imm > (1 << 12) - 2:
        raise ValueError("branch offset out of range")
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
    if imm < -(1 << 20) or imm > (1 << 20) - 2:
        raise ValueError("jal offset out of range")
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


def _auipc(rd: int, imm20: int) -> int:
    return _enc_u(0x17, rd, imm20)


def _lui(rd: int, imm20: int) -> int:
    return _enc_u(0x37, rd, imm20)


def _addi(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x13, rd, 0x0, rs1, imm12)


def _ld(rd: int, rs1: int, imm12: int) -> int:
    return _enc_i(0x03, rd, 0x3, rs1, imm12)


def _jalr(rd: int, rs1: int, imm12: int = 0) -> int:
    return _enc_i(0x67, rd, 0x0, rs1, imm12)


def _beq(rs1: int, rs2: int, off: int) -> int:
    return _enc_b(0x63, 0x0, rs1, rs2, off)


def _bne(rs1: int, rs2: int, off: int) -> int:
    return _enc_b(0x63, 0x1, rs1, rs2, off)


def _jal(rd: int, off: int) -> int:
    return _enc_j(0x6F, rd, off)


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

    ok_msg = b"abi+callret ok\n"
    bad_msg = b"abi+callret FAIL\n"

    labels: dict[str, int] = {}
    fixups_b: list[tuple[int, str, str]] = []
    fixups_j: list[tuple[int, str, str, int]] = []

    code: list[int] = []

    def mark(name: str) -> None:
        labels[name] = len(code)

    def bne_to(rs1: int, rs2: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fixups_b.append((idx, label, "bne"))
        code[idx] = (rs1, rs2)  # type: ignore[assignment]

    def beq_to(rs1: int, rs2: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fixups_b.append((idx, label, "beq"))
        code[idx] = (rs1, rs2)  # type: ignore[assignment]

    def jal_to(rd: int, label: str) -> None:
        idx = len(code)
        code.append(0)
        fixups_j.append((idx, label, "jal", rd))

    # Registers:
    # x2=sp, x10=a0(argc), x11=a1(argv), x12=a2(envp)
    # temporaries: x5(t0), x6(t1), x7(t2)

    mark("start")

    # ABI checks
    bne_to(10, 0, "fail")

    code.append(_addi(5, 2, 8))
    bne_to(11, 5, "fail")

    code.append(_addi(5, 2, 16))
    bne_to(12, 5, "fail")

    code.append(_ld(6, 2, 0))
    bne_to(6, 0, "fail")

    code.append(_ld(6, 11, 0))
    bne_to(6, 0, "fail")

    code.append(_ld(6, 12, 0))
    bne_to(6, 0, "fail")

    # CALL/RET test
    # t0 = pc (auipc) + offset_to_func, jalr ra, t0
    mark("call_site")
    code.append(_auipc(5, 0))
    # placeholder addi t0, t0, imm
    addi_off_idx = len(code)
    code.append(0)
    code.append(_jalr(1, 5, 0))

    # check return value a0 == 42
    _load_imm32(code, 6, 42)
    bne_to(10, 6, "fail")

    # success: write ok_msg
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, entry + 0x400)
    _load_imm32(code, 12, len(ok_msg))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())
    _load_imm32(code, 10, 0)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    jal_to(0, "end")

    mark("fail")
    _load_imm32(code, 10, 1)
    _load_imm32(code, 11, entry + 0x440)
    _load_imm32(code, 12, len(bad_msg))
    _load_imm32(code, 17, int(Sysno.WRITE))
    code.append(_ecall())
    _load_imm32(code, 10, 1)
    _load_imm32(code, 17, int(Sysno.EXIT))
    code.append(_ecall())

    mark("func")
    _load_imm32(code, 10, 42)
    code.append(_jalr(0, 1, 0))

    mark("end")
    code.append(_ecall())

    # Patch call addi offset to func (12-bit signed)
    call_site_addr = entry + labels["call_site"] * 4
    func_addr = entry + labels["func"] * 4
    addi_pc = entry + addi_off_idx * 4
    off = func_addr - call_site_addr
    # AUIPC uses PC of itself; ADDI runs at next instruction, but we used auipc at call_site.
    # We want t0 = call_site_pc + off
    addi_imm = off
    if addi_imm < -(1 << 11) or addi_imm > (1 << 11) - 1:
        raise ValueError("func too far for addi")
    code[addi_off_idx] = _addi(5, 5, addi_imm)

    # Patch branches
    for idx, label, kind in fixups_b:
        rs1, rs2 = code[idx]  # type: ignore[misc]
        cur_pc = entry + idx * 4
        tgt_pc = entry + labels[label] * 4
        off = tgt_pc - cur_pc
        if kind == "bne":
            code[idx] = _bne(int(rs1), int(rs2), off)
        else:
            code[idx] = _beq(int(rs1), int(rs2), off)

    # Patch jal
    for idx, label, _, rd in fixups_j:
        cur_pc = entry + idx * 4
        tgt_pc = entry + labels[label] * 4
        off = tgt_pc - cur_pc
        code[idx] = _jal(int(rd), off)

    code_blob = b"".join(struct.pack("<I", insn) for insn in code)

    payload = code_blob
    if len(payload) > 0x400:
        raise ValueError("code too large")
    payload = payload + b"\x00" * (0x400 - len(payload)) + ok_msg
    payload = payload + b"\x00" * (0x440 - len(payload)) + bad_msg

    ph = RvProgramHeaderV1(
        type=PT_LOAD,
        flags=PF_R | PF_X,
        vaddr=entry,
        file_off=0,
        file_size=len(payload),
        mem_size=len(payload),
    )
    rvx = build_rvexe_v1(entry=entry, segments=[ph], payloads=[payload])

    inode = fs.create_file("/bin/abi")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace

    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/abi\x00", user=True)

    entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
    assert entry_ret == entry

    k.run_user_rv64(pid, entry_ret)


if __name__ == "__main__":
    main()
