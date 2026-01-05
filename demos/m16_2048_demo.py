from __future__ import annotations

import sys
import termios
import tty

from constants import PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.mem import PageFlags
from simmach.rvprog import Program
from simmach import rvlib
from simmach import rvasm
from simmach.syscall import TrapFrame


class _RawTerminal:
    def __init__(self) -> None:
        self._tty = None
        try:
            self._tty = open("/dev/tty", "rb", buffering=0)
            self._fd = self._tty.fileno()
        except Exception:
            if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                self._fd = sys.stdin.fileno()
            else:
                self._fd = -1
        self._old: list[int] | None = None

    def __enter__(self) -> "_RawTerminal":
        if self._fd < 0:
            raise RuntimeError("2048 requires a real TTY. Run from a terminal.")
        self._old = termios.tcgetattr(self._fd)

        new = termios.tcgetattr(self._fd)
        # Disable canonical mode + echo so we can read arrow key escape bytes immediately,
        # but keep ISIG and output processing so Ctrl-C works and '\n' returns to column 0.
        new[3] = new[3] & ~(termios.ICANON | termios.ECHO)
        new[3] = new[3] | termios.ISIG

        new[6][termios.VMIN] = 1
        new[6][termios.VTIME] = 0

        termios.tcsetattr(self._fd, termios.TCSADRAIN, new)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if self._old is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        if self._tty is not None:
            try:
                self._tty.close()
            except Exception:
                pass


def main() -> None:
    physmem = PhysMem(size_bytes=2048 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=4096)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()

    entry = 0x1000_0000
    p = Program(entry=entry, text_vaddr=entry, data_vaddr=0x1000_4000)

    ansi_clear = p.db(b"\x1b[2J\x1b[H")
    banner = p.db(b"2048 (arrow keys). q=quit, r=restart\n\n")
    game_over = p.db(b"\nGAME OVER\n")
    you_win = p.db(b"\nYOU WIN!\n")

    k_up = p.db(b"KEY=UP\n")
    k_down = p.db(b"KEY=DOWN\n")
    k_left = p.db(b"KEY=LEFT\n")
    k_right = p.db(b"KEY=RIGHT\n")
    k_r = p.db(b"KEY=R\n")
    k_q = p.db(b"KEY=Q\n")

    cell_sep = p.db(b"|")
    row_bar = p.db(b"+-----+-----+-----+-----+\n")
    nl = p.db(b"\n")

    # Tile strings: fixed width 5.
    tiles: list[bytes] = [b"     "]
    v = 2
    for _ in range(1, 12):
        s = str(v).rjust(5).encode("ascii")
        tiles.append(s)
        v *= 2
    # 4096+ if ever reached
    tiles.append(b" 4096")

    p.align_data(8)
    tile_ptrs_off = len(p.data.data)
    for t in tiles:
        addr = p.db(t)
        p.align_data(8)
        p.db(addr.to_bytes(8, "little"))

    tile_ptrs = p.data.vaddr + tile_ptrs_off + sum(((len(t) + (-len(t) & 7)) + 8) for t in tiles) - len(tiles) * 8
    # The above layout is awkward; instead store pointers in a separate table.
    # Rebuild table cleanly.
    p.data.data = p.data.data[:tile_ptrs_off]
    tile_str_addrs: list[int] = []
    for t in tiles:
        p.align_data(1)
        tile_str_addrs.append(p.db(t))
    p.align_data(8)
    tile_table = p.db(b"".join(a.to_bytes(8, "little") for a in tile_str_addrs))

    p.align_data(8)
    board = p.db(b"\x00" * 16)  # 16 bytes: exponent (0 empty, 1 => 2, ...)
    p.align_data(8)
    seed = p.db((0x1234_5678_9ABC_DEF0).to_bytes(8, "little"))
    p.align_data(8)
    buf = p.db(b"\x00" * 8)
    p.align_data(8)
    scratch = p.db(b"\x00" * 16)  # for line work
    p.align_data(8)
    tmp2 = p.db(b"\x00" * 16)

    # Registers
    A0 = rvlib.A0
    A1 = rvlib.A1
    A2 = rvlib.A2
    A7 = rvlib.A7
    S0 = rvlib.S0  # board base
    S1 = rvlib.S1  # tile table
    T0 = rvlib.T0
    T1 = rvlib.T1
    T2 = rvlib.T2
    S2 = 18  # seed ptr
    S3 = 19  # buf ptr
    S4 = 20  # scratch
    S5 = 21  # tmp2
    S6 = 22  # state for escape parsing
    S7 = 23  # do_move line index (callee-saved)
    S8 = 24  # do_move saved return address (x1)
    S9 = 25  # do_move global changed (callee-saved)

    def _write_const(addr: int, n: int) -> None:
        rvlib.sys_write(p, fd=1, buf=addr, count=n)

    def _load8(rd: int, base: int, off: int) -> None:
        p.emit(rvasm.lbu(rd, base, off))

    def _store8(rs: int, base: int, off: int) -> None:
        p.emit(rvasm.sb(rs, base, off))

    def _xorshift64() -> None:
        # seed = seed ^ (seed<<13); seed ^= seed>>7; seed ^= seed<<17
        # uses T0/T1
        p.emit(rvasm.ld(T0, S2, 0))
        p.emit(rvasm.slli(T1, T0, 13))
        p.emit(rvasm.xor(T0, T0, T1))
        p.emit(rvasm.srli(T1, T0, 7))
        p.emit(rvasm.xor(T0, T0, T1))
        p.emit(rvasm.slli(T1, T0, 17))
        p.emit(rvasm.xor(T0, T0, T1))
        p.emit(rvasm.sd(T0, S2, 0))

    # start
    p.label("start")
    p.li(S0, board)
    p.li(S1, tile_table)
    p.li(S2, seed)
    p.li(S3, buf)
    p.li(S4, scratch)
    p.li(S5, tmp2)

    # init: add two tiles
    p.jal(0, "restart")

    # ---------------------------------
    # render
    p.label("render")
    _write_const(ansi_clear, len(b"\x1b[2J\x1b[H"))
    _write_const(banner, len(b"2048 (arrow keys). q=quit, r=restart\n\n"))
    _write_const(row_bar, len(b"+-----+-----+-----+-----+\n"))

    p.li(T0, 0)  # row i
    p.label("render_row_loop")
    p.li(T1, 4)
    p.bge(T0, T1, "render_done")

    # print row
    p.li(T1, 0)  # col j
    p.label("render_col_loop")
    p.li(T2, 4)
    p.bge(T1, T2, "render_row_end")

    _write_const(cell_sep, 1)

    # idx = i*4 + j
    p.emit(rvasm.slli(T2, T0, 2))
    p.emit(rvasm.add(T2, T2, T1))

    # exp = board[idx]
    p.emit(rvasm.add(T2, T2, S0))
    p.emit(rvasm.lbu(A0, T2, 0))

    # ptr = tile_table[exp]
    p.emit(rvasm.slli(A1, A0, 3))
    p.emit(rvasm.add(A1, A1, S1))
    p.emit(rvasm.ld(A1, A1, 0))

    # write 5 bytes
    p.li(A0, 1)
    p.li(A2, 5)
    p.li(A7, int(Sysno.WRITE))
    rvlib.ecall(p)

    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "render_col_loop")

    p.label("render_row_end")
    _write_const(cell_sep, 1)
    _write_const(nl, 1)
    _write_const(row_bar, len(b"+-----+-----+-----+-----+\n"))

    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "render_row_loop")

    p.label("render_done")
    rvlib.sys_readkey(p)

    # Debug echo: preserve A0 while calling sys_write.
    p.emit(rvasm.addi(T0, A0, 0))

    p.li(T1, 1)
    p.beq(T0, T1, "dbg_up")
    p.li(T1, 2)
    p.beq(T0, T1, "dbg_down")
    p.li(T1, 3)
    p.beq(T0, T1, "dbg_left")
    p.li(T1, 4)
    p.beq(T0, T1, "dbg_right")
    p.li(T1, 5)
    p.beq(T0, T1, "dbg_r")
    p.li(T1, 6)
    p.beq(T0, T1, "dbg_q")
    p.jal(0, "dbg_ret")

    p.label("dbg_up")
    rvlib.sys_write(p, fd=1, buf=k_up, count=len(b"KEY=UP\n"))
    p.jal(0, "dbg_ret")

    p.label("dbg_down")
    rvlib.sys_write(p, fd=1, buf=k_down, count=len(b"KEY=DOWN\n"))
    p.jal(0, "dbg_ret")

    p.label("dbg_left")
    rvlib.sys_write(p, fd=1, buf=k_left, count=len(b"KEY=LEFT\n"))
    p.jal(0, "dbg_ret")

    p.label("dbg_right")
    rvlib.sys_write(p, fd=1, buf=k_right, count=len(b"KEY=RIGHT\n"))
    p.jal(0, "dbg_ret")

    p.label("dbg_r")
    rvlib.sys_write(p, fd=1, buf=k_r, count=len(b"KEY=R\n"))
    p.jal(0, "dbg_ret")

    p.label("dbg_q")
    rvlib.sys_write(p, fd=1, buf=k_q, count=len(b"KEY=Q\n"))

    p.label("dbg_ret")
    p.emit(rvasm.addi(A0, T0, 0))
    p.jalr(0, 1, 0)

    # ---------------------------------
    # restart
    p.label("restart")
    # zero board
    p.li(T0, 0)
    p.label("rst_loop")
    p.li(T1, 16)
    p.bge(T0, T1, "rst_done")
    _store8(0, S0, 0)  # store x0 to board[0].. but need offset
    p.emit(rvasm.add(T2, S0, T0))
    p.emit(rvasm.sb(0, T2, 0))
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "rst_loop")

    p.label("rst_done")
    p.jal(1, "spawn_tile")
    p.jal(1, "spawn_tile")
    p.jal(0, "main_loop")

    # ---------------------------------
    # spawn_tile: pick random empty and place 2/4. Uses scratch as empties list.
    p.label("spawn_tile")
    _xorshift64()
    p.emit(rvasm.ld(T0, S2, 0))

    # build empties list in scratch, count in T1
    p.li(T1, 0)
    p.li(T2, 0)
    p.label("sp_scan")
    p.li(A0, 16)
    p.bge(T2, A0, "sp_scandone")
    p.emit(rvasm.add(A1, S0, T2))
    p.emit(rvasm.lbu(A2, A1, 0))
    p.beq(A2, 0, "sp_is_empty")
    p.jal(0, "sp_next")

    p.label("sp_is_empty")
    p.emit(rvasm.add(A1, S4, T1))
    p.emit(rvasm.sb(T2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))

    p.label("sp_next")
    p.emit(rvasm.addi(T2, T2, 1))
    p.jal(0, "sp_scan")

    p.label("sp_scandone")
    p.beq(T1, 0, "sp_ret")

    # idx = rand % count (use low byte & while >= count)
    p.emit(rvasm.andi(T2, T0, 0xFF))
    p.label("sp_mod")
    p.blt(T2, T1, "sp_mod_done")
    p.emit(rvasm.sub(T2, T2, T1))
    p.jal(0, "sp_mod")

    p.label("sp_mod_done")
    p.emit(rvasm.add(A0, S4, T2))
    p.emit(rvasm.lbu(A0, A0, 0))  # board index

    # choose exponent 1 (2) or 2 (4): 90% 2; simple: if (rand & 0xF)==0 -> 4
    p.emit(rvasm.andi(A1, T0, 0xF))
    p.beq(A1, 0, "sp_put4")
    p.li(A1, 1)
    p.jal(0, "sp_put")

    p.label("sp_put4")
    p.li(A1, 2)

    p.label("sp_put")
    p.emit(rvasm.add(A2, S0, A0))
    p.emit(rvasm.sb(A1, A2, 0))

    p.label("sp_ret")
    p.jalr(0, 1, 0)

    # ---------------------------------
    # main_loop
    p.label("main_loop")
    p.jal(1, "render")

    # key code in A0 (returned from render -> read_key)
    p.li(T0, 6)
    p.beq(A0, T0, "quit")
    p.li(T0, 5)
    p.beq(A0, T0, "restart")

    # move
    p.emit(rvasm.addi(T1, A0, 0))  # dir
    p.jal(1, "do_move")
    # do_move returns changed in A0 (0/1)
    p.beq(A0, 0, "main_loop")

    p.jal(1, "spawn_tile")

    p.jal(1, "check_win")
    p.beq(A0, 0, "chk_lose")
    _write_const(you_win, len(b"\nYOU WIN!\n"))
    p.jal(0, "main_loop")

    p.label("chk_lose")
    p.jal(1, "check_lose")
    p.beq(A0, 0, "main_loop")
    _write_const(game_over, len(b"\nGAME OVER\n"))
    p.jal(0, "main_loop")

    p.label("quit")
    rvlib.sys_exit(p, 0)

    # ---------------------------------
    # check_win: return 1 if any tile exponent == 11 (2048)
    p.label("check_win")
    p.li(T0, 0)
    p.label("cw_loop")
    p.li(T1, 16)
    p.bge(T0, T1, "cw_no")
    p.emit(rvasm.add(T2, S0, T0))
    p.emit(rvasm.lbu(A0, T2, 0))
    p.li(T1, 11)
    p.beq(A0, T1, "cw_yes")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "cw_loop")

    p.label("cw_yes")
    p.li(A0, 1)
    p.jalr(0, 1, 0)

    p.label("cw_no")
    p.li(A0, 0)
    p.jalr(0, 1, 0)

    # ---------------------------------
    # check_lose: return 1 if no moves
    p.label("check_lose")
    # any empty?
    p.li(T0, 0)
    p.label("cl_empty_loop")
    p.li(T1, 16)
    p.bge(T0, T1, "cl_no_empty")
    p.emit(rvasm.add(T2, S0, T0))
    p.emit(rvasm.lbu(A0, T2, 0))
    p.beq(A0, 0, "cl_not_lose")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "cl_empty_loop")

    p.label("cl_no_empty")
    # check horizontal adjacency
    p.li(T0, 0)
    p.label("cl_h_loop")
    p.li(T1, 4)
    p.bge(T0, T1, "cl_v_check")
    p.li(T2, 0)
    p.label("cl_h_col")
    p.li(A0, 3)
    p.bge(T2, A0, "cl_h_nextrow")

    # idx = r*4+c
    p.emit(rvasm.slli(A1, T0, 2))
    p.emit(rvasm.add(A1, A1, T2))
    p.emit(rvasm.add(A1, A1, S0))
    p.emit(rvasm.lbu(A2, A1, 0))
    p.emit(rvasm.lbu(A0, A1, 1))
    p.beq(A2, A0, "cl_not_lose")

    p.emit(rvasm.addi(T2, T2, 1))
    p.jal(0, "cl_h_col")

    p.label("cl_h_nextrow")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "cl_h_loop")

    # check vertical adjacency
    p.label("cl_v_check")
    p.li(T0, 0)
    p.label("cl_v_row")
    p.li(T1, 3)
    p.bge(T0, T1, "cl_lose")
    p.li(T2, 0)
    p.label("cl_v_col")
    p.li(A0, 4)
    p.bge(T2, A0, "cl_v_nextrow")

    # idx = r*4 + c
    p.emit(rvasm.slli(A1, T0, 2))
    p.emit(rvasm.add(A1, A1, T2))
    p.emit(rvasm.add(A1, A1, S0))
    p.emit(rvasm.lbu(A2, A1, 0))
    # idx+4
    p.emit(rvasm.lbu(A0, A1, 4))
    p.beq(A2, A0, "cl_not_lose")

    p.emit(rvasm.addi(T2, T2, 1))
    p.jal(0, "cl_v_col")

    p.label("cl_v_nextrow")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "cl_v_row")

    p.label("cl_not_lose")
    p.li(A0, 0)
    p.jalr(0, 1, 0)

    p.label("cl_lose")
    p.li(A0, 1)
    p.jalr(0, 1, 0)

    # ---------------------------------
    # do_move(dir in T1): returns changed in A0
    # This is a simplified implementation: it handles moves by applying the line merge
    # to each row/col; merging logic is implemented in merge_line.
    p.label("do_move")
    # do_move calls merge_line, so preserve return address (x1) across nested jal
    p.emit(rvasm.addi(S8, 1, 0))
    # Save dir in S6
    p.emit(rvasm.addi(S6, T1, 0))
    p.li(S9, 0)  # global changed
    p.li(S7, 0)  # line index 0..3
    p.label("mv_line_loop")
    p.li(T1, 4)
    p.bge(S7, T1, "mv_done")

    # load line into scratch depending on dir
    # dir: 3 left,4 right => row; 1 up,2 down => col
    p.li(T1, 3)
    p.beq(S6, T1, "mv_row")
    p.li(T1, 4)
    p.beq(S6, T1, "mv_row")
    p.jal(0, "mv_col")

    p.label("mv_row")
    # base idx = row*4
    p.emit(rvasm.slli(T2, S7, 2))
    # for j=0..3 load board[base+j] into scratch[j]
    p.li(T1, 0)
    p.label("mv_row_ld")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_row_ld_done")
    p.emit(rvasm.add(A1, T2, T1))
    p.emit(rvasm.add(A1, A1, S0))
    p.emit(rvasm.lbu(A2, A1, 0))
    p.emit(rvasm.add(A1, S4, T1))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_row_ld")

    p.label("mv_row_ld_done")
    # if dir==right reverse scratch into tmp2
    p.li(T1, 4)
    p.beq(S6, T1, "mv_rev_in")
    p.jal(0, "mv_merge")

    p.label("mv_rev_in")
    p.li(T1, 0)
    p.label("mv_rev_in_loop")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_rev_in_done")
    p.li(A2, 3)
    p.emit(rvasm.sub(A2, A2, T1))
    p.emit(rvasm.add(A1, S4, A2))
    p.emit(rvasm.lbu(A1, A1, 0))
    p.emit(rvasm.add(A2, S5, T1))
    p.emit(rvasm.sb(A1, A2, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_rev_in_loop")

    p.label("mv_rev_in_done")
    # swap scratch and tmp2 by copying tmp2->scratch
    p.li(T1, 0)
    p.label("mv_cpy_t2")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_merge")
    p.emit(rvasm.add(A2, S5, T1))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.emit(rvasm.add(A1, S4, T1))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_cpy_t2")

    p.label("mv_col")
    # load column into scratch
    p.li(T1, 0)
    p.label("mv_col_ld")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_col_ld_done")
    # idx = r*4 + col
    p.emit(rvasm.slli(A2, T1, 2))
    p.emit(rvasm.add(A2, A2, S7))
    p.emit(rvasm.add(A2, A2, S0))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.emit(rvasm.add(A1, S4, T1))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_col_ld")

    p.label("mv_col_ld_done")
    # if dir==down reverse
    p.li(T1, 2)
    p.beq(S6, T1, "mv_rev_in")

    p.label("mv_merge")
    # merge_line(scratch -> tmp2), returns changed in A0 (0/1) and also writes tmp2
    p.jal(1, "merge_line")
    # if changed set global changed
    p.beq(A0, 0, "mv_store_back")
    p.li(S9, 1)

    p.label("mv_store_back")
    # store tmp2 back (reverse back if needed)
    # determine if need reverse_out: right or down
    p.li(T1, 4)
    p.beq(S6, T1, "mv_rev_out")
    p.li(T1, 2)
    p.beq(S6, T1, "mv_rev_out")
    # left/up: copy tmp2 -> scratch, then write back
    p.li(T1, 0)
    p.label("mv_cpy_out")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_out_norev")
    p.emit(rvasm.add(A2, S5, T1))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.emit(rvasm.add(A1, S4, T1))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_cpy_out")

    p.label("mv_rev_out")
    # reverse tmp2 into scratch
    p.li(T1, 0)
    p.label("mv_rev_out_loop")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_out_norev")
    p.li(A2, 3)
    p.emit(rvasm.sub(A2, A2, T1))
    p.emit(rvasm.add(A1, S5, A2))
    p.emit(rvasm.lbu(A1, A1, 0))
    p.emit(rvasm.add(A2, S4, T1))
    p.emit(rvasm.sb(A1, A2, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_rev_out_loop")
    
    p.label("mv_out_norev")
    # write scratch (which now contains output line) back
    # decide row/col by dir
    p.li(T1, 3)
    p.beq(S6, T1, "mv_w_row")
    p.li(T1, 4)
    p.beq(S6, T1, "mv_w_row")
    p.jal(0, "mv_w_col")

    p.label("mv_w_row")
    p.emit(rvasm.slli(T2, S7, 2))
    p.li(T1, 0)
    p.label("mv_w_row_loop")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_next_line")
    p.emit(rvasm.add(A2, S4, T1))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.emit(rvasm.add(A1, T2, T1))
    p.emit(rvasm.add(A1, A1, S0))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_w_row_loop")

    p.label("mv_w_col")
    p.li(T1, 0)
    p.label("mv_w_col_loop")
    p.li(A1, 4)
    p.bge(T1, A1, "mv_next_line")
    p.emit(rvasm.add(A2, S4, T1))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.emit(rvasm.slli(A1, T1, 2))
    p.emit(rvasm.add(A1, A1, S7))
    p.emit(rvasm.add(A1, A1, S0))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.jal(0, "mv_w_col_loop")

    p.label("mv_next_line")
    p.emit(rvasm.addi(S7, S7, 1))
    p.jal(0, "mv_line_loop")

    p.label("mv_done")
    p.emit(rvasm.addi(A0, S9, 0))
    p.emit(rvasm.addi(1, S8, 0))
    p.jalr(0, 1, 0)

    # ---------------------------------
    # merge_line: input scratch[0..3], output in tmp2[0..3], returns changed in A0
    p.label("merge_line")
    # Clear tmp2
    p.li(T2, 0)
    p.label("ml_clr")
    p.li(A1, 4)
    p.bge(T2, A1, "ml_comp")
    p.emit(rvasm.add(A2, S5, T2))
    p.emit(rvasm.sb(0, A2, 0))
    p.emit(rvasm.addi(T2, T2, 1))
    p.jal(0, "ml_clr")

    # Compress scratch nonzeros into tmp2
    p.label("ml_comp")
    p.li(T0, 0)  # i
    p.li(T1, 0)  # outpos
    p.label("ml_comp_loop")
    p.li(A1, 4)
    p.bge(T0, A1, "ml_merge")
    p.emit(rvasm.add(A2, S4, T0))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.beq(A2, 0, "ml_comp_next")
    p.emit(rvasm.add(A1, S5, T1))
    p.emit(rvasm.sb(A2, A1, 0))
    p.emit(rvasm.addi(T1, T1, 1))
    p.label("ml_comp_next")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "ml_comp_loop")

    # Merge adjacent equals in tmp2 in-place
    p.label("ml_merge")
    p.li(T0, 0)  # i
    p.label("ml_merge_loop")
    p.li(A1, 3)
    p.bge(T0, A1, "ml_changed")
    p.emit(rvasm.add(A2, S5, T0))
    p.emit(rvasm.lbu(A1, A2, 0))
    p.beq(A1, 0, "ml_merge_next")
    p.emit(rvasm.lbu(T2, A2, 1))
    p.bne(T2, A1, "ml_merge_next")

    # merge: tmp2[i]++, shift left tmp2[i+1..]
    p.emit(rvasm.addi(A1, A1, 1))
    p.emit(rvasm.sb(A1, A2, 0))
    p.emit(rvasm.addi(T2, T0, 1))  # j = i+1
    p.label("ml_shift")
    p.li(A1, 3)
    p.bge(T2, A1, "ml_shift_last")
    p.emit(rvasm.add(A2, S5, T2))
    p.emit(rvasm.lbu(A1, A2, 1))
    p.emit(rvasm.sb(A1, A2, 0))
    p.emit(rvasm.addi(T2, T2, 1))
    p.jal(0, "ml_shift")

    p.label("ml_shift_last")
    p.emit(rvasm.addi(A2, S5, 3))
    p.emit(rvasm.sb(0, A2, 0))
    p.emit(rvasm.addi(T0, T0, 2))
    p.jal(0, "ml_merge_loop")

    p.label("ml_merge_next")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "ml_merge_loop")

    # changed = any scratch[i] != tmp2[i]
    p.label("ml_changed")
    p.li(A0, 0)
    p.li(T0, 0)
    p.label("ml_changed_loop")
    p.li(A1, 4)
    p.bge(T0, A1, "ml_ret")
    p.emit(rvasm.add(A2, S4, T0))
    p.emit(rvasm.lbu(A2, A2, 0))
    p.emit(rvasm.add(A1, S5, T0))
    p.emit(rvasm.lbu(A1, A1, 0))
    p.beq(A2, A1, "ml_changed_next")
    p.li(A0, 1)
    p.jal(0, "ml_ret")
    p.label("ml_changed_next")
    p.emit(rvasm.addi(T0, T0, 1))
    p.jal(0, "ml_changed_loop")

    p.label("ml_ret")
    p.jalr(0, 1, 0)

    rvx = p.build_rvx()
    inode = fs.create_file("/bin/2048")
    fs.write_inode(inode, 0, rvx, truncate=True)

    k = Kernel(kas)
    k.set_fs(fs)

    pid = k.create_process()
    aspace = k.processes[pid].aspace
    user_base = 0x2000_0000
    aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
    aspace.write(user_base, b"/bin/2048\x00", user=True)

    with _RawTerminal():
        try:
            entry_ret = k.syscalls.dispatch(k, pid, TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0))
            assert entry_ret == entry
            k.run_user_rv64(pid, entry_ret, max_steps=500_000_000)
        except KeyboardInterrupt:
            print("\nInterrupted (Ctrl-C).")
            return


if __name__ == "__main__":
    main()
