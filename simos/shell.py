from __future__ import annotations

import shlex
import struct
import sys
import termios
from dataclasses import dataclass
from typing import Iterable, Sequence

from constants import Errno, O_CREAT, O_TRUNC, PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.rvprog import Program
from simmach import rvlib
from simmach import rvasm
from simmach.syscall import TrapFrame

try:
    import readline  # type: ignore
except Exception:
    readline = None


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


def _gen_sh_parser(sh: Program, *, linebuf: int, argvbuf: int, redirmeta: int, stageargvbuf: int, pathbufs: int, binprefix: int, stagepathbuf: int, execfail: int, reg_tok_count: int, reg_cmd_name: int, reg_stage_count: int) -> None:
    A0, A1, A2, A3, A4, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A4, rvlib.A7
    T0, T1, T2, T3, T4, T5 = rvlib.T0, rvlib.T1, rvlib.T2, rvlib.T3, rvlib.T4, rvlib.T5
    S0, S1, S2 = rvlib.S0, rvlib.S1, rvlib.S2

    REG_LINE_CURSOR = T0
    REG_CHAR = T1
    REG_SCRATCH = T2
    REG_TOK_COUNT = reg_tok_count
    REG_REDIR_IDX = A4
    REG_CMD_NAME = reg_cmd_name
    REG_STAGE_COUNT = reg_stage_count

    sh.li(REG_TOK_COUNT, 0)
    sh.emit(rvasm.addi(REG_LINE_CURSOR, S0, 0))

    sh.label("parse_skip")
    sh.emit(rvasm.lbu(REG_CHAR, REG_LINE_CURSOR, 0))
    sh.beq(REG_CHAR, 0, "parse_done")
    sh.li(REG_SCRATCH, 10)
    sh.beq(REG_CHAR, REG_SCRATCH, "parse_nl")
    sh.li(REG_SCRATCH, 32)
    sh.bne(REG_CHAR, REG_SCRATCH, "parse_tok")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(0, "parse_skip")

    sh.label("parse_nl")
    sh.emit(rvasm.sb(0, REG_LINE_CURSOR, 0))
    sh.jal(0, "parse_done")

    sh.label("parse_tok")
    sh.emit(rvasm.slli(REG_SCRATCH, REG_TOK_COUNT, 3))
    sh.emit(rvasm.add(REG_SCRATCH, S1, REG_SCRATCH))
    sh.emit(rvasm.sd(REG_LINE_CURSOR, REG_SCRATCH, 0))
    sh.emit(rvasm.addi(REG_TOK_COUNT, REG_TOK_COUNT, 1))

    sh.label("scan_tok")
    sh.emit(rvasm.lbu(REG_CHAR, REG_LINE_CURSOR, 0))
    sh.beq(REG_CHAR, 0, "parse_done")
    sh.li(REG_SCRATCH, 10)
    sh.beq(REG_CHAR, REG_SCRATCH, "scan_nl")
    sh.li(REG_SCRATCH, 32)
    sh.beq(REG_CHAR, REG_SCRATCH, "scan_sp")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(0, "scan_tok")

    sh.label("scan_sp")
    sh.emit(rvasm.sb(0, REG_LINE_CURSOR, 0))
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(0, "parse_skip")

    sh.label("scan_nl")
    sh.emit(rvasm.sb(0, REG_LINE_CURSOR, 0))
    sh.jal(0, "parse_done")

    sh.label("parse_done")
    sh.emit(rvasm.slli(REG_SCRATCH, REG_TOK_COUNT, 3))
    sh.emit(rvasm.add(REG_SCRATCH, S1, REG_SCRATCH))
    sh.emit(rvasm.sd(0, REG_SCRATCH, 0))
    sh.beq(REG_TOK_COUNT, 0, "loop")

    sh.emit(rvasm.ld(REG_CMD_NAME, S1, 0))

    # Output redirection: detect a single '>' token (must be space-separated).
    sh.li(REG_LINE_CURSOR, 0)
    sh.li(REG_REDIR_IDX, -1)
    sh.label("scan_redir")
    sh.beq(REG_LINE_CURSOR, REG_TOK_COUNT, "redir_scan_done")
    sh.emit(rvasm.slli(REG_CHAR, REG_LINE_CURSOR, 3))
    sh.emit(rvasm.add(REG_CHAR, S1, REG_CHAR))
    sh.emit(rvasm.ld(A0, REG_CHAR, 0))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.li(A2, 62)
    sh.bne(A1, A2, "redir_next")
    sh.emit(rvasm.lbu(A1, A0, 1))
    sh.bne(A1, 0, "redir_next")
    sh.emit(rvasm.addi(REG_REDIR_IDX, REG_LINE_CURSOR, 0))
    sh.jal(0, "redir_scan_done")
    sh.label("redir_next")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(0, "scan_redir")
    sh.label("redir_scan_done")
    sh.blt(REG_REDIR_IDX, 0, "redir_done")
    sh.beq(REG_REDIR_IDX, 0, "redir_syntax")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_TOK_COUNT, -1))
    sh.beq(REG_REDIR_IDX, REG_LINE_CURSOR, "redir_syntax")

    # Split argv in-place: argv[redir_idx] = 0; save path=argv[redir_idx+1] in redirmeta.
    sh.emit(rvasm.addi(REG_SCRATCH, REG_REDIR_IDX, 0))
    sh.emit(rvasm.slli(REG_CHAR, REG_REDIR_IDX, 3))
    sh.emit(rvasm.add(REG_CHAR, S1, REG_CHAR))
    sh.emit(rvasm.sd(0, REG_CHAR, 0))
    sh.emit(rvasm.addi(REG_REDIR_IDX, REG_REDIR_IDX, 1))
    sh.emit(rvasm.slli(REG_CHAR, REG_REDIR_IDX, 3))
    sh.emit(rvasm.add(REG_CHAR, S1, REG_CHAR))
    sh.emit(rvasm.ld(A0, REG_CHAR, 0))
    sh.li(A3, redirmeta)
    sh.li(T0, 1)
    sh.emit(rvasm.sd(T0, A3, 0))
    sh.emit(rvasm.sd(A0, A3, 8))
    sh.emit(rvasm.addi(REG_TOK_COUNT, REG_SCRATCH, 0))
    sh.jal(0, "redir_done")

    sh.label("redir_syntax")
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    sh.jal(0, "loop")

    sh.label("redir_done")

    # Pipeline support: multi-stage 'a | b | c' (must be space-separated).
    sh.li(REG_STAGE_COUNT, 1)
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.sd(S1, A3, 0))
    sh.li(REG_LINE_CURSOR, 0)
    sh.label("scan_pipe_multi")
    sh.beq(REG_LINE_CURSOR, REG_TOK_COUNT, "scan_pipe_multi_done")
    sh.emit(rvasm.slli(REG_CHAR, REG_LINE_CURSOR, 3))
    sh.emit(rvasm.add(REG_CHAR, S1, REG_CHAR))
    sh.emit(rvasm.ld(A0, REG_CHAR, 0))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.li(A2, 124)
    sh.bne(A1, A2, "scan_pipe_multi_next")
    sh.emit(rvasm.lbu(A1, A0, 1))
    sh.bne(A1, 0, "scan_pipe_multi_next")
    sh.beq(REG_LINE_CURSOR, 0, "pipe_syntax_multi")
    sh.emit(rvasm.addi(REG_SCRATCH, REG_TOK_COUNT, -1))
    sh.beq(REG_LINE_CURSOR, REG_SCRATCH, "pipe_syntax_multi")
    sh.emit(rvasm.addi(REG_SCRATCH, REG_LINE_CURSOR, 1))
    sh.emit(rvasm.slli(T3, REG_SCRATCH, 3))
    sh.emit(rvasm.add(T3, S1, T3))
    sh.emit(rvasm.ld(A0, T3, 0))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.li(A2, 124)
    sh.bne(A1, A2, "pipe_tok_ok")
    sh.emit(rvasm.lbu(A1, A0, 1))
    sh.beq(A1, 0, "pipe_syntax_multi")
    sh.label("pipe_tok_ok")

    sh.emit(rvasm.sd(0, REG_CHAR, 0))
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T4, REG_STAGE_COUNT, 3))
    sh.emit(rvasm.add(T4, A3, T4))
    sh.emit(rvasm.sd(T3, T4, 0))
    sh.emit(rvasm.addi(REG_STAGE_COUNT, REG_STAGE_COUNT, 1))
    sh.li(T5, 4)
    sh.blt(REG_STAGE_COUNT, T5, "scan_pipe_multi_next")
    sh.jal(0, "pipe_syntax_multi")

    sh.label("scan_pipe_multi_next")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(0, "scan_pipe_multi")
    sh.label("scan_pipe_multi_done")
    sh.li(REG_LINE_CURSOR, 2)
    sh.blt(REG_STAGE_COUNT, REG_LINE_CURSOR, "no_pipe")

    sh.li(REG_LINE_CURSOR, 0)
    sh.label("build_stage_paths")
    sh.beq(REG_LINE_CURSOR, REG_STAGE_COUNT, "build_stage_paths_done")
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(REG_CHAR, REG_LINE_CURSOR, 3))
    sh.emit(rvasm.add(REG_CHAR, A3, REG_CHAR))
    sh.emit(rvasm.ld(REG_SCRATCH, REG_CHAR, 0))
    sh.emit(rvasm.ld(A3, REG_SCRATCH, 0))

    sh.li(T3, 0)
    sh.label("bp_scan_slash")
    sh.emit(rvasm.add(A0, A3, T3))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.beq(A1, 0, "bp_no_slash")
    sh.li(A2, 47)
    sh.beq(A1, A2, "bp_has_slash")
    sh.emit(rvasm.addi(T3, T3, 1))
    sh.jal(0, "bp_scan_slash")

    sh.label("bp_has_slash")
    sh.emit(rvasm.addi(T4, A3, 0))
    sh.jal(0, "bp_path_done")

    sh.label("bp_no_slash")
    sh.emit(rvasm.slli(T4, REG_LINE_CURSOR, 7))
    sh.emit(rvasm.add(T4, S2, T4))
    sh.li(T5, 0)
    sh.label("bp_cpy_pre")
    sh.emit(rvasm.add(REG_CHAR, 27, T5))
    sh.emit(rvasm.lbu(REG_SCRATCH, REG_CHAR, 0))
    sh.emit(rvasm.add(REG_CHAR, T4, T5))
    sh.emit(rvasm.sb(REG_SCRATCH, REG_CHAR, 0))
    sh.beq(REG_SCRATCH, 0, "bp_cpy_pre_done")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.jal(0, "bp_cpy_pre")
    sh.label("bp_cpy_pre_done")
    sh.emit(rvasm.addi(T5, T5, -1))
    sh.li(REG_CHAR, 0)
    sh.label("bp_cpy_cmd")
    sh.emit(rvasm.add(A0, A3, REG_CHAR))
    sh.emit(rvasm.lbu(REG_SCRATCH, A0, 0))
    sh.emit(rvasm.add(A0, T4, T5))
    sh.emit(rvasm.sb(REG_SCRATCH, A0, 0))
    sh.beq(REG_SCRATCH, 0, "bp_path_done")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.emit(rvasm.addi(REG_CHAR, REG_CHAR, 1))
    sh.jal(0, "bp_cpy_cmd")

    sh.label("bp_path_done")
    sh.li(A3, stagepathbuf)
    sh.emit(rvasm.slli(REG_CHAR, REG_LINE_CURSOR, 3))
    sh.emit(rvasm.add(REG_CHAR, A3, REG_CHAR))
    sh.emit(rvasm.sd(T4, REG_CHAR, 0))
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(0, "build_stage_paths")

    sh.label("build_stage_paths_done")


def _gen_sh_line_editor(sh: Program, *, linebuf: int, iobuf_reg: int, histmeta: int, histbuf: int, histlens: int, prompt: int, prompt_len: int, cr: int, nl: int, clreol: int, bsseq: int, redirmeta: int, reg_hist_idx: int, reg_line_len: int) -> None:
    A0, A1, A2, A3, A4, A5, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A4, rvlib.A5, rvlib.A7
    T0, T1, T2 = rvlib.T0, rvlib.T1, rvlib.T2
    S0 = rvlib.S0
    REG_HIST_IDX = reg_hist_idx
    REG_LINE_LEN = reg_line_len
    REG_IOBUF = iobuf_reg

    sh.label("loop")
    rvlib.sys_write(sh, fd=1, buf=prompt, count=prompt_len)
    sh.li(A3, redirmeta)
    sh.emit(rvasm.sd(0, A3, 0))
    sh.emit(rvasm.sd(0, A3, 8))
    
    sh.li(REG_HIST_IDX, 0)
    sh.li(REG_LINE_LEN, 0)
    sh.label("rl_read_loop")
    rvlib.sys_read_reg(sh, fd_reg=0, buf_reg=REG_IOBUF, count_reg=1)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, REG_IOBUF, 0))

    sh.li(T0, 10)
    sh.beq(T1, T0, "rl_enter")
    sh.li(T0, 13)
    sh.beq(T1, T0, "rl_enter")

    sh.li(T0, 127)
    sh.beq(T1, T0, "rl_backspace")
    sh.li(T0, 8)
    sh.beq(T1, T0, "rl_backspace")

    sh.li(T0, 0x1B)
    sh.beq(T1, T0, "rl_esc")

    sh.li(T0, 255)
    sh.bge(REG_LINE_LEN, T0, "rl_read_loop")
    sh.emit(rvasm.add(T2, S0, REG_LINE_LEN))
    sh.emit(rvasm.sb(T1, T2, 0))
    sh.emit(rvasm.addi(REG_LINE_LEN, REG_LINE_LEN, 1))
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, REG_IOBUF, 0))
    sh.li(A2, 1)
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    sh.jal(0, "rl_read_loop")

    sh.label("rl_backspace")
    sh.beq(REG_LINE_LEN, 0, "rl_read_loop")
    sh.emit(rvasm.addi(REG_LINE_LEN, REG_LINE_LEN, -1))
    rvlib.sys_write(sh, fd=1, buf=bsseq, count=3)
    sh.jal(0, "rl_read_loop")

    sh.label("rl_esc")
    rvlib.sys_read_reg(sh, fd_reg=0, buf_reg=REG_IOBUF, count_reg=1)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, REG_IOBUF, 0))
    sh.li(T0, 91)
    sh.bne(T1, T0, "rl_read_loop")
    rvlib.sys_read_reg(sh, fd_reg=0, buf_reg=REG_IOBUF, count_reg=1)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, REG_IOBUF, 0))
    sh.li(T0, 65)
    sh.beq(T1, T0, "rl_hist_up")
    sh.li(T0, 66)
    sh.beq(T1, T0, "rl_hist_down")
    sh.jal(0, "rl_read_loop")

    sh.label("rl_hist_up")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, 0, "rl_read_loop")
    sh.emit(rvasm.addi(T1, T0, -1))
    sh.bge(REG_HIST_IDX, T1, "rl_hist_load")
    sh.emit(rvasm.addi(REG_HIST_IDX, REG_HIST_IDX, 1))
    sh.label("rl_hist_load")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T2, A3, 8))
    sh.emit(rvasm.addi(T2, T2, -1))
    sh.emit(rvasm.sub(T2, T2, REG_HIST_IDX))
    sh.li(T1, 0)
    sh.bge(T2, T1, "rl_hist_idx_ok")
    sh.emit(rvasm.addi(T2, T2, 8))
    sh.label("rl_hist_idx_ok")
    sh.emit(rvasm.slli(T1, T2, 3))
    sh.li(A3, histlens)
    sh.emit(rvasm.add(T1, A3, T1))
    sh.emit(rvasm.ld(T1, T1, 0))
    sh.emit(rvasm.addi(REG_LINE_LEN, T1, 0))
    sh.emit(rvasm.slli(T0, T2, 8))
    sh.li(A3, histbuf)
    sh.emit(rvasm.add(T0, A3, T0))
    sh.li(T1, 0)
    sh.label("rl_hist_cpy")
    sh.beq(T1, REG_LINE_LEN, "rl_hist_cpy_done")
    sh.emit(rvasm.add(A0, T0, T1))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.emit(rvasm.add(A0, S0, T1))
    sh.emit(rvasm.sb(A1, A0, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.jal(0, "rl_hist_cpy")
    sh.label("rl_hist_cpy_done")
    sh.emit(rvasm.add(T0, S0, REG_LINE_LEN))
    sh.emit(rvasm.sb(0, T0, 0))
    sh.jal(1, "rl_redraw")

    sh.label("rl_hist_down")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, 0, "rl_read_loop")
    sh.beq(REG_HIST_IDX, 0, "rl_hist_clear")
    sh.emit(rvasm.addi(REG_HIST_IDX, REG_HIST_IDX, -1))
    sh.jal(0, "rl_hist_load")
    sh.label("rl_hist_clear")
    sh.li(REG_LINE_LEN, 0)
    sh.emit(rvasm.sb(0, S0, 0))
    sh.jal(1, "rl_redraw")

    sh.label("rl_redraw")
    rvlib.sys_write(sh, fd=1, buf=cr, count=1)
    rvlib.sys_write(sh, fd=1, buf=prompt, count=prompt_len)
    rvlib.sys_write(sh, fd=1, buf=clreol, count=3)
    sh.beq(REG_LINE_LEN, 0, "rl_redraw_done")
    rvlib.sys_write_reg(sh, fd_reg=1, buf_reg=S0, count_reg=REG_LINE_LEN)
    sh.label("rl_redraw_done")
    sh.jalr(0, 1, 0)

    sh.label("rl_enter")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.emit(rvasm.add(T0, S0, REG_LINE_LEN))
    sh.li(T1, 10)
    sh.emit(rvasm.sb(T1, T0, 0))
    sh.emit(rvasm.addi(REG_LINE_LEN, REG_LINE_LEN, 1))
    sh.emit(rvasm.add(T0, S0, REG_LINE_LEN))
    sh.emit(rvasm.sb(0, T0, 0))
    sh.emit(rvasm.addi(A0, REG_LINE_LEN, 0))
    sh.li(T0, 1)
    sh.blt(A0, T0, "loop")

    sh.emit(rvasm.addi(T2, REG_LINE_LEN, -1))
    sh.beq(T2, 0, "rl_hist_save_done")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.emit(rvasm.ld(T1, A3, 8))
    sh.li(A3, 8)
    sh.bge(T0, A3, "rl_hist_cnt_ok")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.label("rl_hist_cnt_ok")
    sh.li(A3, histmeta)
    sh.emit(rvasm.sd(T0, A3, 0))
    sh.emit(rvasm.slli(A4, T1, 8))
    sh.li(A3, histbuf)
    sh.emit(rvasm.add(A4, A3, A4))
    sh.li(A5, 0)
    sh.label("rl_hist_save_cpy")
    sh.beq(A5, T2, "rl_hist_save_cpy_done")
    sh.emit(rvasm.add(A0, S0, A5))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.emit(rvasm.add(A0, A4, A5))
    sh.emit(rvasm.sb(A1, A0, 0))
    sh.emit(rvasm.addi(A5, A5, 1))
    sh.jal(0, "rl_hist_save_cpy")
    sh.label("rl_hist_save_cpy_done")
    sh.emit(rvasm.add(A0, A4, T2))
    sh.emit(rvasm.sb(0, A0, 0))
    sh.emit(rvasm.slli(A0, T1, 3))
    sh.li(A3, histlens)
    sh.emit(rvasm.add(A0, A3, A0))
    sh.emit(rvasm.sd(T2, A0, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.li(A0, 8)
    sh.blt(T1, A0, "rl_hist_next_ok")
    sh.li(T1, 0)
    sh.label("rl_hist_next_ok")
    sh.li(A3, histmeta)
    sh.emit(rvasm.sd(T1, A3, 8))
    sh.label("rl_hist_save_done")


def _gen_sh_utils(sh: Program, *, iobuf_reg: int) -> None:
    A0, A1, A2, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A7
    T0, T1, T2 = rvlib.T0, rvlib.T1, rvlib.T2

    sh.label("strcmp")
    sh.label("sc_loop")
    sh.emit(rvasm.lbu(T0, A0, 0))
    sh.emit(rvasm.lbu(T1, A1, 0))
    sh.bne(T0, T1, "sc_ne")
    sh.beq(T0, 0, "sc_eq")
    sh.emit(rvasm.addi(A0, A0, 1))
    sh.emit(rvasm.addi(A1, A1, 1))
    sh.jal(0, "sc_loop")
    sh.label("sc_ne")
    sh.li(A0, 1)
    sh.jalr(0, 1, 0)
    sh.label("sc_eq")
    sh.li(A0, 0)
    sh.jalr(0, 1, 0)

    sh.label("strlen")
    sh.li(T0, 0)
    sh.label("sl_loop")
    sh.emit(rvasm.add(T1, A0, T0))
    sh.emit(rvasm.lbu(T2, T1, 0))
    sh.beq(T2, 0, "sl_done")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "sl_loop")
    sh.label("sl_done")
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.jalr(0, 1, 0)

    sh.label("print_dec")
    sh.emit(rvasm.addi(T0, A0, 0))
    sh.beq(T0, 0, "pd_zero")
    sh.li(T1, 0)
    sh.label("pd_outer")
    sh.beq(T0, 0, "pd_done")
    sh.li(T2, 0)
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.label("pd_div")
    sh.li(A1, 10)
    sh.blt(A0, A1, "pd_div_done")
    sh.emit(rvasm.addi(A0, A0, -10))
    sh.emit(rvasm.addi(T2, T2, 1))
    sh.jal(0, "pd_div")
    sh.label("pd_div_done")
    sh.emit(rvasm.addi(A2, A0, 48))
    sh.emit(rvasm.add(A1, iobuf_reg, T1))
    sh.emit(rvasm.sb(A2, A1, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.emit(rvasm.addi(T0, T2, 0))
    sh.jal(0, "pd_outer")
    sh.label("pd_zero")
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, iobuf_reg, 0))
    sh.li(A2, 48)
    sh.emit(rvasm.sb(A2, A1, 0))
    sh.li(T1, 1)
    sh.label("pd_done")
    sh.emit(rvasm.addi(T1, T1, -1))
    sh.blt(T1, 0, "pd_ret")
    sh.emit(rvasm.add(A1, iobuf_reg, T1))
    rvlib.sys_write_reg(sh, fd_reg=1, buf_reg=A1, count_reg=1)
    sh.jal(0, "pd_done")
    sh.label("pd_ret")
    sh.jalr(0, 1, 0)


def _gen_sh_builtins(sh: Program, *, iobuf_reg: int, direntbuf_reg: int, cwdbuf_reg: int, binprefix_reg: int, dotpath: int, rootpath: int, helpmsg: int, catusage: int, lsusage: int, openfail: int, readfail: int, nl: int, sp: int, reg_tok_count: int, reg_cmd_name: int, reg_argvbuf: int, reg_last_status: int) -> None:
    A0, A1, A2, A3, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A7
    T0, T1, T2 = rvlib.T0, rvlib.T1, rvlib.T2
    S6 = rvlib.S6

    sh.label("do_exit")
    rvlib.sys_exit(sh, 0)

    sh.label("do_help")
    rvlib.sys_write(sh, fd=1, buf=helpmsg, count=len(b"builtins: help exit echo cat ls cd pwd status\n"))
    sh.jal(0, "loop")

    sh.label("do_echo")
    sh.li(T0, 1)
    sh.label("echo_loop")
    sh.bge(T0, reg_tok_count, "echo_done")
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, reg_argvbuf, T1))
    sh.emit(rvasm.ld(A1, T1, 0))
    sh.emit(rvasm.addi(A0, A1, 0))
    sh.jal(1, "strlen")
    rvlib.sys_write_reg(sh, fd_reg=1, buf_reg=A1, count_reg=A0)
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.bge(T0, reg_tok_count, "echo_done")
    rvlib.sys_write(sh, fd=1, buf=sp, count=1)
    sh.jal(0, "echo_loop")
    sh.label("echo_done")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "loop")

    sh.label("do_status")
    sh.emit(rvasm.addi(A0, reg_last_status, 0))
    sh.jal(1, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "loop")

    sh.label("do_cat")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "cat_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    rvlib.sys_open_ro_reg(sh, path_reg=A0)
    sh.blt(A0, 0, "open_failed")
    sh.emit(rvasm.addi(S6, A0, 0))
    sh.label("cat_read")
    rvlib.sys_read_reg(sh, fd_reg=S6, buf_reg=iobuf_reg, count_reg=256)
    sh.beq(A0, 0, "cat_close")
    sh.blt(A0, 0, "read_failed")
    sh.emit(rvasm.addi(T2, A0, 0))
    rvlib.sys_write_reg(sh, fd_reg=1, buf_reg=iobuf_reg, count_reg=T2)
    sh.jal(0, "cat_read")
    sh.label("cat_close")
    rvlib.sys_close(sh, fd_reg=S6)
    sh.jal(0, "loop")
    sh.label("cat_usage")
    rvlib.sys_write(sh, fd=1, buf=catusage, count=len(b"usage: cat <file>\n"))
    sh.jal(0, "loop")

    sh.label("do_ls")
    sh.li(T0, 1)
    sh.beq(reg_tok_count, T0, "ls_root")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "ls_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.jal(0, "ls_open")
    sh.label("ls_root")
    sh.li(A0, dotpath)
    sh.label("ls_open")
    rvlib.sys_open_ro_reg(sh, path_reg=A0)
    sh.blt(A0, 0, "open_failed")
    sh.emit(rvasm.addi(S6, A0, 0))
    sh.label("ls_read")
    rvlib.sys_read_reg(sh, fd_reg=S6, buf_reg=direntbuf_reg, count_reg=64)
    sh.li(T0, 64)
    sh.blt(A0, T0, "ls_close")
    sh.emit(rvasm.lbu(T1, direntbuf_reg, 0))
    sh.beq(T1, 0, "ls_read")
    sh.emit(rvasm.addi(A0, direntbuf_reg, 0))
    sh.jal(1, "strlen")
    rvlib.sys_write_reg(sh, fd_reg=1, buf_reg=direntbuf_reg, count_reg=A0)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "ls_read")
    sh.label("ls_close")
    rvlib.sys_close(sh, fd_reg=S6)
    sh.jal(0, "loop")
    sh.label("ls_usage")
    rvlib.sys_write(sh, fd=1, buf=lsusage, count=len(b"usage: ls [dir]\n"))
    sh.jal(0, "loop")

    sh.label("do_cd")
    sh.li(T0, 1)
    sh.beq(reg_tok_count, T0, "cd_root")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "cd_root")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.jal(0, "cd_call")
    sh.label("cd_root")
    sh.li(A0, rootpath)
    sh.label("cd_call")
    rvlib.sys_chdir_reg(sh, path_reg=A0)
    sh.jal(0, "loop")

    sh.label("do_pwd")
    rvlib.sys_getcwd_reg(sh, buf_reg=cwdbuf_reg, size_reg=128)
    sh.emit(rvasm.addi(A0, cwdbuf_reg, 0))
    sh.jal(1, "strlen")
    rvlib.sys_write_reg(sh, fd_reg=1, buf_reg=cwdbuf_reg, count_reg=A0)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "loop")

    sh.label("open_failed")
    rvlib.sys_write(sh, fd=1, buf=openfail, count=len(b"open failed\n"))
    sh.jal(0, "loop")

    sh.label("read_failed")
    rvlib.sys_write(sh, fd=1, buf=readfail, count=len(b"read failed\n"))
    sh.jal(0, "cat_close")


def _gen_sh_exec(sh: Program, *, stageargvbuf: int, stagepathbuf: int, pipebuf: int, statusbuf: int, redirmeta: int, argvbuf: int, pathbufs: int, binprefix_reg: int, execfail: int, ex_enoent: int, ex_eacces: int, ex_einval: int, ex_efault: int, ex_enomem: int, openfail: int, cmd_exit: int, cmd_help: int, cmd_echo: int, cmd_cat: int, cmd_ls: int, cmd_cd: int, cmd_pwd: int, cmd_status: int, reg_prev_pipe_read: int, reg_last_status: int, reg_current_stage: int, reg_stage_count: int) -> None:
    A0, A1, A2, A3, A4, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A4, rvlib.A7
    T0, T1, T2, T3, T4, T5 = rvlib.T0, rvlib.T1, rvlib.T2, rvlib.T3, rvlib.T4, rvlib.T5
    S1, S2, S3, S4, S5, S6 = rvlib.S1, rvlib.S2, rvlib.S3, rvlib.S4, rvlib.S5, rvlib.S6
    REG_PREV_PIPE_READ = reg_prev_pipe_read
    REG_CURRENT_STAGE = reg_current_stage
    REG_STAGE_COUNT = reg_stage_count

    sh.li(REG_PREV_PIPE_READ, -1) # prev_pipe_read_fd
    sh.li(REG_CURRENT_STAGE, 0) # current_stage
    sh.label("pipe_exec_loop")
    sh.beq(REG_CURRENT_STAGE, REG_STAGE_COUNT, "pipe_exec_done") # 16 is stage_count
    sh.emit(rvasm.addi(T4, REG_STAGE_COUNT, -1))
    sh.beq(REG_CURRENT_STAGE, T4, "pipe_last_stage")
    rvlib.sys_pipe(sh, pipefd_addr=pipebuf)
    sh.emit(rvasm.ld(T0, 29, 0)) # 29 is pipebuf address
    sh.emit(rvasm.ld(T1, 29, 8))
    sh.jal(0, "pipe_have_pipe")

    sh.label("pipe_last_stage")
    sh.li(T0, -1)
    sh.li(T1, -1)

    sh.label("pipe_have_pipe")
    rvlib.sys_fork(sh)
    sh.beq(A0, 0, "pipe_child")

    sh.blt(REG_PREV_PIPE_READ, 0, "pipe_parent_no_prev")
    rvlib.sys_close(sh, fd_reg=REG_PREV_PIPE_READ)
    sh.label("pipe_parent_no_prev")
    sh.blt(T1, 0, "pipe_parent_no_w")
    rvlib.sys_close(sh, fd_reg=T1)
    sh.label("pipe_parent_no_w")
    sh.emit(rvasm.addi(REG_PREV_PIPE_READ, T0, 0))
    sh.emit(rvasm.addi(REG_CURRENT_STAGE, REG_CURRENT_STAGE, 1))
    sh.jal(0, "pipe_exec_loop")

    sh.label("pipe_child")
    sh.blt(REG_PREV_PIPE_READ, 0, "pipe_child_no_prev")
    rvlib.sys_dup2(sh, oldfd_reg=REG_PREV_PIPE_READ, newfd=0)
    rvlib.sys_close(sh, fd_reg=REG_PREV_PIPE_READ)
    sh.label("pipe_child_no_prev")
    sh.blt(T1, 0, "pipe_child_no_w")
    rvlib.sys_dup2(sh, oldfd_reg=T1, newfd=1)
    sh.label("pipe_child_no_w")
    sh.blt(T0, 0, "pipe_child_no_r")
    rvlib.sys_close(sh, fd_reg=T0)
    sh.label("pipe_child_no_r")
    sh.blt(T1, 0, "pipe_child_no_close_w")
    rvlib.sys_close(sh, fd_reg=T1)
    sh.label("pipe_child_no_close_w")

    sh.emit(rvasm.addi(T4, REG_STAGE_COUNT, -1))
    sh.bne(REG_CURRENT_STAGE, T4, "pipe_child_skip_redir")
    sh.li(A3, redirmeta)
    sh.emit(rvasm.ld(T5, A3, 0))
    sh.beq(T5, 0, "pipe_child_skip_redir")
    sh.emit(rvasm.ld(A0, A3, 8))
    rvlib.sys_open_create_trunc_reg(sh, path_reg=A0)
    sh.li(T5, 0)
    sh.blt(A0, T5, "redir_open_failed")
    sh.emit(rvasm.addi(T5, A0, 0))
    rvlib.sys_dup2(sh, oldfd_reg=T5, newfd=1)
    rvlib.sys_close(sh, fd_reg=T5)

    sh.label("pipe_child_skip_redir")
    sh.li(A3, stagepathbuf)
    sh.emit(rvasm.slli(T2, REG_CURRENT_STAGE, 3))
    sh.emit(rvasm.add(T2, A3, T2))
    sh.emit(rvasm.ld(A0, T2, 0))
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T2, REG_CURRENT_STAGE, 3))
    sh.emit(rvasm.add(T2, A3, T2))
    sh.emit(rvasm.ld(A1, T2, 0))
    rvlib.sys_execve_reg(sh, path_reg=A0, argv_reg=A1)
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    rvlib.sys_exit(sh, 1)

    sh.label("pipe_exec_done")
    sh.blt(REG_PREV_PIPE_READ, 0, "pipe_close_prev_done")
    rvlib.sys_close(sh, fd_reg=REG_PREV_PIPE_READ)
    sh.label("pipe_close_prev_done")

    sh.emit(rvasm.addi(T0, REG_STAGE_COUNT, 0))
    sh.label("pipe_wait_loop")
    sh.beq(T0, 0, "pipe_wait_done")
    sh.li(T2, -1)
    rvlib.sys_waitpid(sh, child_pid_reg=T2, status_addr=statusbuf)
    sh.li(T1, -11) # ECHILD
    sh.beq(A0, T1, "pipe_wait_loop")
    sh.emit(rvasm.ld(reg_last_status, S3, 0))
    sh.emit(rvasm.addi(T0, T0, -1))
    sh.jal(0, "pipe_wait_loop")
    sh.label("pipe_wait_done")
    sh.jal(0, "loop")

    sh.label("pipe_syntax_multi")
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    sh.jal(0, "loop")

    sh.label("no_pipe")

    sh.li(A3, redirmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.bne(T0, 0, "external_dispatch")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_exit)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_exit")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_help)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_help")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_echo)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_echo")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_cat)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_cat")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_ls)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_ls")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_cd)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_cd")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_pwd)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_pwd")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_status)
    sh.jal(1, "strcmp")
    sh.beq(A0, 0, "do_status")

    sh.label("external_dispatch")

    # If command contains '/', treat it as a path (absolute or relative).
    sh.li(T0, 0)
    sh.label("scan_slash")
    sh.emit(rvasm.add(A0, S5, T0))
    sh.emit(rvasm.lbu(T1, A0, 0))
    sh.beq(T1, 0, "no_slash")
    sh.li(T2, 47)
    sh.beq(T1, T2, "has_slash")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "scan_slash")

    sh.label("has_slash")
    sh.emit(rvasm.addi(S6, S5, 0))
    sh.jal(0, "run_cmd")

    sh.label("no_slash")
    sh.li(T0, 0)
    sh.label("cpy_pre")
    sh.emit(rvasm.add(T1, 27, T0))
    sh.emit(rvasm.lbu(T2, T1, 0))
    sh.emit(rvasm.add(T1, S2, T0))
    sh.emit(rvasm.sb(T2, T1, 0))
    sh.beq(T2, 0, "cpy_pre_done")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "cpy_pre")

    sh.label("cpy_pre_done")
    sh.emit(rvasm.addi(T0, T0, -1))
    sh.li(T1, 0)
    sh.label("cpy_cmd")
    sh.emit(rvasm.add(A0, S5, T1))
    sh.emit(rvasm.lbu(T2, A0, 0))
    sh.emit(rvasm.add(A0, S2, T0))
    sh.emit(rvasm.sb(T2, A0, 0))
    sh.beq(T2, 0, "path_ready")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.jal(0, "cpy_cmd")

    sh.label("path_ready")
    sh.emit(rvasm.addi(S6, S2, 0))

    sh.label("run_cmd")
    rvlib.sys_fork(sh)
    sh.beq(A0, 0, "child")
    sh.emit(rvasm.addi(T0, A0, 0))

    sh.label("wait_loop")
    rvlib.sys_waitpid(sh, child_pid_reg=T0, status_addr=statusbuf)
    sh.li(T1, -11)
    sh.beq(A0, T1, "wait_loop")
    sh.emit(rvasm.ld(reg_last_status, S3, 0))
    sh.jal(0, "loop")

    sh.label("child")
    sh.li(A3, redirmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, 0, "child_execve")
    sh.emit(rvasm.ld(A0, A3, 8))
    rvlib.sys_open_create_trunc_reg(sh, path_reg=A0)
    sh.li(T1, 0)
    sh.blt(A0, T1, "redir_open_failed")
    sh.emit(rvasm.addi(T0, A0, 0))
    rvlib.sys_dup2(sh, oldfd_reg=T0, newfd=1)
    rvlib.sys_close(sh, fd_reg=T0)

    sh.label("child_execve")
    rvlib.sys_execve_reg(sh, path_reg=S6, argv_reg=S1)

    # A0 contains negative errno on failure.
    sh.li(T0, int(Errno.ENOENT))
    sh.beq(A0, T0, "ex_msg_enoent")
    sh.li(T0, int(Errno.EACCES))
    sh.beq(A0, T0, "ex_msg_eacces")
    sh.li(T0, int(Errno.EINVAL))
    sh.beq(A0, T0, "ex_msg_einval")
    sh.li(T0, int(Errno.EFAULT))
    sh.beq(A0, T0, "ex_msg_efault")
    sh.li(T0, int(Errno.ENOMEM))
    sh.beq(A0, T0, "ex_msg_enomem")
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    sh.jal(0, "ex_msg_done")

    sh.label("ex_msg_enoent")
    rvlib.sys_write(sh, fd=1, buf=ex_enoent, count=len(b"execve: not found\n"))
    sh.jal(0, "ex_msg_done")
    sh.label("ex_msg_eacces")
    rvlib.sys_write(sh, fd=1, buf=ex_eacces, count=len(b"execve: access denied\n"))
    sh.jal(0, "ex_msg_done")
    sh.label("ex_msg_einval")
    rvlib.sys_write(sh, fd=1, buf=ex_einval, count=len(b"execve: invalid\n"))
    sh.jal(0, "ex_msg_done")
    sh.label("ex_msg_efault")
    rvlib.sys_write(sh, fd=1, buf=ex_efault, count=len(b"execve: bad address\n"))
    sh.jal(0, "ex_msg_done")
    sh.label("ex_msg_enomem")
    rvlib.sys_write(sh, fd=1, buf=ex_enomem, count=len(b"execve: no memory\n"))

    sh.label("ex_msg_done")
    rvlib.sys_exit(sh, 1)

    sh.label("redir_open_failed")
    rvlib.sys_write(sh, fd=1, buf=openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(sh, 1)


    p_mkdir = Program(entry=0x1000_0000)
    mkdir_usage = p_mkdir.db(b"usage: mkdir <path>\n")
    p_mkdir.label("_start")
    p_mkdir.li(rvlib.T0, 2)
    p_mkdir.blt(rvlib.A0, rvlib.T0, "mkdir_usage")
    p_mkdir.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_mkdir_reg(p_mkdir, path_reg=rvlib.A0)
    p_mkdir.li(rvlib.T0, 0)
    p_mkdir.blt(rvlib.A0, rvlib.T0, "mkdir_fail")
    rvlib.sys_exit(p_mkdir, 0)
    p_mkdir.label("mkdir_usage")
    rvlib.sys_write(p_mkdir, fd=1, buf=mkdir_usage, count=len(b"usage: mkdir <path>\n"))
    rvlib.sys_exit(p_mkdir, 1)
    p_mkdir.label("mkdir_fail")
    rvlib.sys_exit(p_mkdir, 1)
    mkdir_rvx = p_mkdir.build_rvx()
    mkdir_ino = fs.create_file("/bin/mkdir")
    fs.write_inode(mkdir_ino, 0, mkdir_rvx, truncate=True)

    p_rm = Program(entry=0x1000_0000)
    rm_usage = p_rm.db(b"usage: rm <path>\n")
    p_rm.label("_start")
    p_rm.li(rvlib.T0, 2)
    p_rm.blt(rvlib.A0, rvlib.T0, "rm_usage")
    p_rm.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_unlink_reg(p_rm, path_reg=rvlib.A0)
    p_rm.li(rvlib.T0, 0)
    p_rm.blt(rvlib.A0, rvlib.T0, "rm_fail")
    rvlib.sys_exit(p_rm, 0)
    p_rm.label("rm_usage")
    rvlib.sys_write(p_rm, fd=1, buf=rm_usage, count=len(b"usage: rm <path>\n"))
    rvlib.sys_exit(p_rm, 1)
    p_rm.label("rm_fail")
    rvlib.sys_exit(p_rm, 1)
    rm_rvx = p_rm.build_rvx()
    rm_ino = fs.create_file("/bin/rm")
    fs.write_inode(rm_ino, 0, rm_rvx, truncate=True)

    p_mv = Program(entry=0x1000_0000)
    mv_usage = p_mv.db(b"usage: mv <old> <new>\n")
    p_mv.label("_start")
    p_mv.li(rvlib.T0, 3)
    p_mv.blt(rvlib.A0, rvlib.T0, "mv_usage")
    p_mv.emit(rvasm.ld(rvlib.S0, rvlib.A1, 8))
    p_mv.emit(rvasm.ld(rvlib.S1, rvlib.A1, 16))
    rvlib.sys_rename_reg(p_mv, old_reg=rvlib.S0, new_reg=rvlib.S1)
    p_mv.li(rvlib.T0, 0)
    p_mv.blt(rvlib.A0, rvlib.T0, "mv_fail")
    rvlib.sys_exit(p_mv, 0)
    p_mv.label("mv_usage")
    rvlib.sys_write(p_mv, fd=1, buf=mv_usage, count=len(b"usage: mv <old> <new>\n"))
    rvlib.sys_exit(p_mv, 1)
    p_mv.label("mv_fail")
    rvlib.sys_exit(p_mv, 1)
    mv_rvx = p_mv.build_rvx()
    mv_ino = fs.create_file("/bin/mv")
    fs.write_inode(mv_ino, 0, mv_rvx, truncate=True)

    p = Program(entry=0x1000_0000)

    msg = p.db(b"hello from simos\n")

    A0 = rvlib.A0
    A1 = rvlib.A1
    A2 = rvlib.A2

    p.label("_start")
    rvlib.sys_write(p, fd=1, buf=msg, count=len(b"hello from simos\n"))
    p.li(A0, 0)
    rvlib.sys_exit(p, A0)

    rvx = p.build_rvx()
    ino = fs.create_file("/bin/hello")
    fs.write_inode(ino, 0, rvx, truncate=True)

    p_true = Program(entry=0x1000_0000)
    p_true.label("_start")
    rvlib.sys_exit(p_true, 0)
    true_rvx = p_true.build_rvx()
    true_ino = fs.create_file("/bin/true")
    fs.write_inode(true_ino, 0, true_rvx, truncate=True)

    p_false = Program(entry=0x1000_0000)
    p_false.label("_start")
    rvlib.sys_exit(p_false, 1)
    false_rvx = p_false.build_rvx()
    false_ino = fs.create_file("/bin/false")
    fs.write_inode(false_ino, 0, false_rvx, truncate=True)

    p_pwd = Program(entry=0x1000_0000)
    pwd_nl = p_pwd.db(b"\n")
    p_pwd.align_data(8)
    pwd_buf = p_pwd.db(b"\x00" * 128)
    A0 = rvlib.A0
    A1 = rvlib.A1
    A2 = rvlib.A2
    A7 = rvlib.A7
    T0 = rvlib.T0
    T1 = rvlib.T1
    T2 = rvlib.T2
    S0 = rvlib.S0
    p_pwd.label("_start")
    p_pwd.li(S0, pwd_buf)
    rvlib.sys_getcwd_reg(p_pwd, buf_reg=S0, size_reg=128)
    p_pwd.li(T0, 0)
    p_pwd.label("pwd_len")
    p_pwd.emit(rvasm.add(T1, S0, T0))
    p_pwd.emit(rvasm.lbu(T2, T1, 0))
    p_pwd.beq(T2, 0, "pwd_len_done")
    p_pwd.emit(rvasm.addi(T0, T0, 1))
    p_pwd.jal(0, "pwd_len")
    p_pwd.label("pwd_len_done")
    rvlib.sys_write_reg(p_pwd, fd_reg=1, buf_reg=S0, count_reg=T0)
    rvlib.sys_write(p_pwd, fd=1, buf=pwd_nl, count=1)
    rvlib.sys_exit(p_pwd, 0)
    pwd_rvx = p_pwd.build_rvx()
    pwd_ino = fs.create_file("/bin/pwd")
    fs.write_inode(pwd_ino, 0, pwd_rvx, truncate=True)

    p_echo = Program(entry=0x1000_0000)
    echo_sp = p_echo.db(b" ")
    echo_nl = p_echo.db(b"\n")
    p_echo.label("_start")
    # argc in a0, argv in a1
    p_echo.emit(rvasm.addi(rvlib.S0, A0, 0))
    p_echo.emit(rvasm.addi(rvlib.S1, A1, 0))
    p_echo.li(T0, 1)  # i
    p_echo.label("echo_loop")
    p_echo.bge(T0, rvlib.S0, "echo_done")
    p_echo.emit(rvasm.slli(T1, T0, 3))
    p_echo.emit(rvasm.add(T1, rvlib.S1, T1))
    p_echo.emit(rvasm.ld(A1, T1, 0))
    p_echo.emit(rvasm.addi(18, A1, 0))
    p_echo.emit(rvasm.addi(T2, A1, 0))
    p_echo.li(T1, 0)
    p_echo.label("echo_strlen")
    p_echo.emit(rvasm.lbu(A2, T2, 0))
    p_echo.beq(A2, 0, "echo_strlen_done")
    p_echo.emit(rvasm.addi(T2, T2, 1))
    p_echo.emit(rvasm.addi(T1, T1, 1))
    p_echo.jal(0, "echo_strlen")
    p_echo.label("echo_strlen_done")
    rvlib.sys_write_reg(p_echo, fd_reg=1, buf_reg=18, count_reg=T1)
    p_echo.emit(rvasm.addi(T0, T0, 1))
    p_echo.bge(T0, rvlib.S0, "echo_loop")
    rvlib.sys_write(p_echo, fd=1, buf=echo_sp, count=1)
    p_echo.jal(0, "echo_loop")
    p_echo.label("echo_done")
    rvlib.sys_write(p_echo, fd=1, buf=echo_nl, count=1)
    rvlib.sys_exit(p_echo, 0)
    echo_rvx = p_echo.build_rvx()
    echo_ino = fs.create_file("/bin/echo")
    fs.write_inode(echo_ino, 0, echo_rvx, truncate=True)

    p_cat = Program(entry=0x1000_0000)
    cat_usage = p_cat.db(b"usage: cat <file>\n")
    cat_openfail = p_cat.db(b"open failed\n")
    cat_readfail = p_cat.db(b"read failed\n")
    p_cat.align_data(8)
    cat_buf = p_cat.db(b"\x00" * 256)
    p_cat.label("_start")
    p_cat.li(rvlib.T0, 2)
    p_cat.blt(rvlib.A0, rvlib.T0, "cat_stdin")
    p_cat.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_cat, path_reg=rvlib.A0)
    p_cat.blt(rvlib.A0, 0, "cat_openfail")
    p_cat.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_cat.jal(0, "cat_read")

    p_cat.label("cat_stdin")
    p_cat.li(rvlib.S0, 0)
    p_cat.label("cat_read")
    rvlib.sys_read_reg(p_cat, fd_reg=rvlib.S0, buf_reg=cat_buf, count_reg=256)
    p_cat.beq(rvlib.A0, 0, "cat_close_ok")
    p_cat.blt(rvlib.A0, 0, "cat_readfail")
    p_cat.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    rvlib.sys_write_reg(p_cat, fd_reg=1, buf_reg=cat_buf, count_reg=rvlib.T0)
    p_cat.jal(0, "cat_read")
    p_cat.label("cat_close_ok")
    rvlib.sys_close(p_cat, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_cat, 0)
    p_cat.label("cat_openfail")
    rvlib.sys_write(p_cat, fd=1, buf=cat_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_cat, 1)
    p_cat.label("cat_readfail")
    rvlib.sys_write(p_cat, fd=1, buf=cat_readfail, count=len(b"read failed\n"))
    rvlib.sys_close(p_cat, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_cat, 1)
    cat_rvx = p_cat.build_rvx()
    cat_ino = fs.create_file("/bin/cat")
    fs.write_inode(cat_ino, 0, cat_rvx, truncate=True)

    p_ls = Program(entry=0x1000_0000)
    ls_usage_exe = p_ls.db(b"usage: ls [dir]\n")
    ls_openfail_exe = p_ls.db(b"open failed\n")
    ls_nl = p_ls.db(b"\n")
    dot = p_ls.db(b".\x00")
    p_ls.align_data(8)
    ls_ent = p_ls.db(b"\x00" * 64)
    p_ls.label("_start")
    p_ls.li(rvlib.T0, 2)
    p_ls.blt(rvlib.A0, rvlib.T0, "ls_default")
    p_ls.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    p_ls.jal(0, "ls_open")
    p_ls.label("ls_default")
    p_ls.li(rvlib.A0, dot)
    p_ls.label("ls_open")
    rvlib.sys_open_ro_reg(p_ls, path_reg=rvlib.A0)
    p_ls.blt(rvlib.A0, 0, "ls_openfail")
    p_ls.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_ls.label("ls_read")
    rvlib.sys_read_reg(p_ls, fd_reg=rvlib.S0, buf_reg=ls_ent, count_reg=64)
    p_ls.li(rvlib.T0, 64)
    p_ls.blt(rvlib.A0, rvlib.T0, "ls_close")
    p_ls.emit(rvasm.lbu(rvlib.T1, ls_ent, 0))
    p_ls.beq(rvlib.T1, 0, "ls_read")
    p_ls.li(rvlib.T0, 0)
    p_ls.label("ls_strlen")
    p_ls.emit(rvasm.add(rvlib.T2, ls_ent, rvlib.T0))
    p_ls.emit(rvasm.lbu(rvlib.T2, rvlib.T2, 0))
    p_ls.beq(rvlib.T2, 0, "ls_print")
    p_ls.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_ls.jal(0, "ls_strlen")
    p_ls.label("ls_print")
    rvlib.sys_write_reg(p_ls, fd_reg=1, buf_reg=ls_ent, count_reg=rvlib.T0)
    rvlib.sys_write(p_ls, fd=1, buf=ls_nl, count=1)
    p_ls.jal(0, "ls_read")
    p_ls.label("ls_close")
    rvlib.sys_close(p_ls, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_ls, 0)
    p_ls.label("ls_usage")
    rvlib.sys_write(p_ls, fd=1, buf=ls_usage_exe, count=len(b"usage: ls [dir]\n"))
    rvlib.sys_exit(p_ls, 1)
    p_ls.label("ls_openfail")
    rvlib.sys_write(p_ls, fd=1, buf=ls_openfail_exe, count=len(b"open failed\n"))
    rvlib.sys_exit(p_ls, 1)
    ls_rvx = p_ls.build_rvx()
    ls_ino = fs.create_file("/bin/ls")
    fs.write_inode(ls_ino, 0, ls_rvx, truncate=True)

    p_touch = Program(entry=0x1000_0000)
    touch_usage = p_touch.db(b"usage: touch <file>\n")
    touch_openfail = p_touch.db(b"open failed\n")
    p_touch.label("_start")
    p_touch.li(rvlib.T0, 2)
    p_touch.blt(rvlib.A0, rvlib.T0, "touch_usage")
    p_touch.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_reg(p_touch, path_reg=rvlib.A0, flags=int(O_CREAT))
    p_touch.blt(rvlib.A0, 0, "touch_openfail")
    rvlib.sys_close(p_touch, fd_reg=rvlib.A0)
    rvlib.sys_exit(p_touch, 0)
    p_touch.label("touch_usage")
    rvlib.sys_write(p_touch, fd=1, buf=touch_usage, count=len(b"usage: touch <file>\n"))
    rvlib.sys_exit(p_touch, 1)
    p_touch.label("touch_openfail")
    rvlib.sys_write(p_touch, fd=1, buf=touch_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_touch, 1)
    touch_rvx = p_touch.build_rvx()
    touch_ino = fs.create_file("/bin/touch")
    fs.write_inode(touch_ino, 0, touch_rvx, truncate=True)

    p_cp = Program(entry=0x1000_0000)
    cp_usage = p_cp.db(b"usage: cp <src> <dst>\n")
    cp_openfail = p_cp.db(b"open failed\n")
    cp_readfail = p_cp.db(b"read failed\n")
    cp_writefail = p_cp.db(b"write failed\n")
    p_cp.align_data(8)
    cp_buf = p_cp.db(b"\x00" * 256)
    p_cp.label("_start")
    p_cp.li(rvlib.T0, 3)
    p_cp.blt(rvlib.A0, rvlib.T0, "cp_usage")

    p_cp.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_reg(p_cp, path_reg=rvlib.A0, flags=0)
    p_cp.blt(rvlib.A0, 0, "cp_openfail")
    p_cp.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))

    p_cp.emit(rvasm.ld(rvlib.A0, rvlib.A1, 16))
    rvlib.sys_open_create_trunc_reg(p_cp, path_reg=rvlib.A0)
    p_cp.blt(rvlib.A0, 0, "cp_openfail2")
    p_cp.emit(rvasm.addi(rvlib.S1, rvlib.A0, 0))

    p_cp.label("cp_loop")
    rvlib.sys_read_reg(p_cp, fd_reg=rvlib.S0, buf_reg=cp_buf, count_reg=256)
    p_cp.beq(rvlib.A0, 0, "cp_done")
    p_cp.blt(rvlib.A0, 0, "cp_readfail")
    p_cp.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))

    rvlib.sys_write_reg(p_cp, fd_reg=rvlib.S1, buf_reg=cp_buf, count_reg=rvlib.T0)
    p_cp.blt(rvlib.A0, 0, "cp_writefail")
    p_cp.jal(0, "cp_loop")

    p_cp.label("cp_done")
    rvlib.sys_close(p_cp, fd_reg=rvlib.S0)
    rvlib.sys_close(p_cp, fd_reg=rvlib.S1)
    rvlib.sys_exit(p_cp, 0)

    p_cp.label("cp_usage")
    rvlib.sys_write(p_cp, fd=1, buf=cp_usage, count=len(b"usage: cp <src> <dst>\n"))
    rvlib.sys_exit(p_cp, 1)
    p_cp.label("cp_openfail2")
    rvlib.sys_close(p_cp, fd_reg=rvlib.S0)
    p_cp.label("cp_openfail")
    rvlib.sys_write(p_cp, fd=1, buf=cp_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_cp, 1)
    p_cp.label("cp_readfail")
    rvlib.sys_write(p_cp, fd=1, buf=cp_readfail, count=len(b"read failed\n"))
    rvlib.sys_close(p_cp, fd_reg=rvlib.S0)
    rvlib.sys_close(p_cp, fd_reg=rvlib.S1)
    rvlib.sys_exit(p_cp, 1)
    p_cp.label("cp_writefail")
    rvlib.sys_write(p_cp, fd=1, buf=cp_writefail, count=len(b"write failed\n"))
    rvlib.sys_close(p_cp, fd_reg=rvlib.S0)
    rvlib.sys_close(p_cp, fd_reg=rvlib.S1)
    rvlib.sys_exit(p_cp, 1)
    cp_rvx = p_cp.build_rvx()
    cp_ino = fs.create_file("/bin/cp")
    fs.write_inode(cp_ino, 0, cp_rvx, truncate=True)

    p_head = Program(entry=0x1000_0000)
    head_usage = p_head.db(b"usage: head <file>\n")
    p_head.align_data(8)
    head_buf = p_head.db(b"\x00" * 256)
    p_head.label("_start")
    p_head.li(rvlib.T0, 2)
    p_head.blt(rvlib.A0, rvlib.T0, "head_usage")
    p_head.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_head, path_reg=rvlib.A0)
    p_head.blt(rvlib.A0, 0, "head_usage")
    p_head.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_head.li(rvlib.T2, 0)
    p_head.label("head_read")
    rvlib.sys_read_reg(p_head, fd_reg=rvlib.S0, buf_reg=head_buf, count_reg=256)
    p_head.beq(rvlib.A0, 0, "head_close")
    p_head.blt(rvlib.A0, 0, "head_close")
    p_head.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_head.li(rvlib.T1, 0)
    p_head.emit(rvasm.addi(18, rvlib.T0, 0))
    p_head.label("head_scan")
    p_head.beq(rvlib.T1, rvlib.T0, "head_scan_done")
    p_head.emit(rvasm.add(19, head_buf, rvlib.T1))
    p_head.emit(rvasm.lbu(19, 19, 0))
    p_head.li(20, 10)
    p_head.bne(19, 20, "head_scan_next")
    p_head.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_head.li(20, 10)
    p_head.bne(rvlib.T2, 20, "head_scan_next")
    p_head.emit(rvasm.addi(18, rvlib.T1, 1))
    p_head.jal(0, "head_scan_done")
    p_head.label("head_scan_next")
    p_head.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_head.jal(0, "head_scan")
    p_head.label("head_scan_done")
    rvlib.sys_write_reg(p_head, fd_reg=1, buf_reg=head_buf, count_reg=18)
    p_head.li(20, 10)
    p_head.beq(rvlib.T2, 20, "head_close")
    p_head.jal(0, "head_read")
    p_head.label("head_close")
    rvlib.sys_close(p_head, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_head, 0)
    p_head.label("head_usage")
    rvlib.sys_write(p_head, fd=1, buf=head_usage, count=len(b"usage: head <file>\n"))
    rvlib.sys_exit(p_head, 1)
    head_rvx = p_head.build_rvx()
    head_ino = fs.create_file("/bin/head")
    fs.write_inode(head_ino, 0, head_rvx, truncate=True)

    p_wc = Program(entry=0x1000_0000)
    wc_readfail = p_wc.db(b"read failed\n")
    wc_sp = p_wc.db(b" ")
    wc_nl = p_wc.db(b"\n")
    p_wc.align_data(8)
    wc_buf = p_wc.db(b"\x00" * 256)
    p_wc.align_data(8)
    wc_digits = p_wc.db(b"\x00" * 32)
    p_wc.label("_start")
    p_wc.li(rvlib.S0, 0)
    p_wc.li(rvlib.S1, 0)
    p_wc.li(18, 0)
    p_wc.li(rvlib.T0, 2)
    p_wc.blt(rvlib.A0, rvlib.T0, "wc_loop")
    p_wc.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_wc, path_reg=rvlib.A0)
    p_wc.blt(rvlib.A0, 0, "wc_readfail")
    p_wc.emit(rvasm.addi(18, rvlib.A0, 0))
    p_wc.label("wc_loop")
    rvlib.sys_read_reg(p_wc, fd_reg=18, buf_reg=wc_buf, count_reg=256)
    p_wc.beq(rvlib.A0, 0, "wc_done")
    p_wc.blt(rvlib.A0, 0, "wc_readfail")
    p_wc.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_wc.emit(rvasm.add(rvlib.S0, rvlib.S0, rvlib.T0))
    p_wc.li(rvlib.T1, 0)
    p_wc.label("wc_scan")
    p_wc.beq(rvlib.T1, rvlib.T0, "wc_loop")
    p_wc.emit(rvasm.add(rvlib.T2, wc_buf, rvlib.T1))
    p_wc.emit(rvasm.lbu(rvlib.T2, rvlib.T2, 0))
    p_wc.li(20, 10)
    p_wc.bne(rvlib.T2, 20, "wc_scan_next")
    p_wc.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_wc.label("wc_scan_next")
    p_wc.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_wc.jal(0, "wc_scan")

    p_wc.label("wc_done")
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p_wc.jal(1, "print_dec")
    rvlib.sys_write(p_wc, fd=1, buf=wc_sp, count=1)
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_wc.jal(1, "print_dec")
    rvlib.sys_write(p_wc, fd=1, buf=wc_nl, count=1)
    rvlib.sys_exit(p_wc, 0)

    p_wc.label("wc_readfail")
    rvlib.sys_write(p_wc, fd=1, buf=wc_readfail, count=len(b"read failed\n"))
    rvlib.sys_exit(p_wc, 1)

    p_wc.label("print_dec")
    p_wc.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_wc.beq(rvlib.T0, 0, "pd_zero")
    p_wc.li(rvlib.T1, 0)
    p_wc.label("pd_outer")
    p_wc.beq(rvlib.T0, 0, "pd_done")
    p_wc.li(rvlib.T2, 0)
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_wc.label("pd_div")
    p_wc.li(rvlib.A1, 10)
    p_wc.blt(rvlib.A0, rvlib.A1, "pd_div_done")
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.A0, -10))
    p_wc.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_wc.jal(0, "pd_div")
    p_wc.label("pd_div_done")
    p_wc.emit(rvasm.addi(rvlib.A2, rvlib.A0, 48))
    p_wc.emit(rvasm.add(rvlib.A1, wc_digits, rvlib.T1))
    p_wc.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_wc.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_wc.emit(rvasm.addi(rvlib.T0, rvlib.T2, 0))
    p_wc.jal(0, "pd_outer")
    p_wc.label("pd_zero")
    p_wc.emit(rvasm.add(rvlib.A1, wc_digits, 0))
    p_wc.li(rvlib.A2, 48)
    p_wc.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_wc.li(rvlib.T1, 1)
    p_wc.label("pd_done")
    p_wc.emit(rvasm.addi(rvlib.T1, rvlib.T1, -1))
    p_wc.blt(rvlib.T1, 0, "pd_ret")
    p_wc.emit(rvasm.add(rvlib.A1, wc_digits, rvlib.T1))
    p_wc.li(rvlib.A0, 1)
    p_wc.li(rvlib.A2, 1)
    p_wc.li(rvlib.A7, int(Sysno.WRITE))
    rvlib.ecall(p_wc)
    p_wc.jal(0, "pd_done")
    p_wc.label("pd_ret")
    p_wc.jalr(0, 1, 0)

    wc_rvx = p_wc.build_rvx()
    wc_ino = fs.create_file("/bin/wc")
    fs.write_inode(wc_ino, 0, wc_rvx, truncate=True)

    sh = Program(entry=0x1000_0000)

    prompt = sh.db(b"sh$ ")
    nl = sh.db(b"\n")
    cr = sh.db(b"\r")
    clreol = sh.db(b"\x1b[K")
    bsseq = sh.db(b"\b \b")
    sp = sh.db(b" ")
    helpmsg = sh.db(b"builtins: help exit echo cat ls cd pwd status\n")
    execfail = sh.db(b"execve: failed\n")
    ex_enoent = sh.db(b"execve: not found\n")
    ex_eacces = sh.db(b"execve: access denied\n")
    ex_einval = sh.db(b"execve: invalid\n")
    ex_efault = sh.db(b"execve: bad address\n")
    ex_enomem = sh.db(b"execve: no memory\n")
    openfail = sh.db(b"open failed\n")
    readfail = sh.db(b"read failed\n")
    catusage = sh.db(b"usage: cat <file>\n")
    lsusage = sh.db(b"usage: ls [dir]\n")
    binprefix = sh.db(b"/bin/")
    dotpath = sh.db(b".\x00")
    rootpath = sh.db(b"/\x00")
    cmd_exit = sh.db(b"exit\x00")
    cmd_help = sh.db(b"help\x00")
    cmd_echo = sh.db(b"echo\x00")
    cmd_cat = sh.db(b"cat\x00")
    cmd_ls = sh.db(b"ls\x00")
    cmd_cd = sh.db(b"cd\x00")
    cmd_pwd = sh.db(b"pwd\x00")
    cmd_status = sh.db(b"status\x00")

    sh.align_data(8)
    linebuf = sh.db(b"\x00" * 256)
    sh.align_data(8)
    histbuf = sh.db(b"\x00" * (256 * 8))
    sh.align_data(8)
    histlens = sh.db(b"\x00" * (8 * 8))
    sh.align_data(8)
    histmeta = sh.db(b"\x00" * 16)
    sh.align_data(8)
    redirmeta = sh.db(b"\x00" * 16)
    sh.align_data(8)
    pathbufs = sh.db(b"\x00" * (128 * 4))
    sh.align_data(8)
    stageargvbuf = sh.db(b"\x00" * (8 * 4))
    sh.align_data(8)
    stagepathbuf = sh.db(b"\x00" * (8 * 4))
    sh.align_data(8)
    argvbuf = sh.db(b"\x00" * (8 * 32))
    sh.align_data(8)
    iobuf = sh.db(b"\x00" * 256)
    sh.align_data(8)
    direntbuf = sh.db(b"\x00" * 64)
    sh.align_data(8)
    pipebuf = sh.db(b"\x00" * 16)
    sh.align_data(8)
    cwdbuf = sh.db(b"\x00" * 128)
    sh.align_data(8)
    statusbuf = sh.db(b"\x00" * 8)

    A0 = rvlib.A0
    A1 = rvlib.A1
    A2 = rvlib.A2
    A3 = rvlib.A3
    A7 = rvlib.A7
    T0 = rvlib.T0
    T1 = rvlib.T1
    T2 = rvlib.T2
    T3 = 31
    T4 = 14
    T5 = 12
    S0 = rvlib.S0
    S1 = rvlib.S1
    S2 = 18
    S3 = 19
    S4 = 20
    S5 = 21
    S6 = 22

    # Register assignments for shell state
    REG_IOBUF = rvlib.S7
    REG_DIRENTBUF = rvlib.S8

    sh.label("_start")
    sh.li(rvlib.S0, linebuf)
    sh.li(rvlib.S1, argvbuf)
    sh.li(rvlib.S2, pathbufs)
    sh.li(rvlib.S3, statusbuf)
    sh.li(REG_IOBUF, iobuf)
    sh.li(REG_DIRENTBUF, direntbuf)
    sh.li(REG_CWDBUF, cwdbuf)
    sh.li(REG_LAST_STATUS, 0)
    sh.li(REG_BIN_PREFIX, binprefix)
    sh.li(REG_PATH_SCRATCH, pathbufs + 128)
    sh.li(REG_PIPEBUF_ADDR, pipebuf)
    sh.li(REG_REDIR_META_ADDR, redirmeta)

    _gen_sh_line_editor(
        sh,
        linebuf=linebuf,
        iobuf_reg=REG_IOBUF,
        histmeta=histmeta,
        histbuf=histbuf,
        histlens=histlens,
        prompt=prompt,
        prompt_len=len(b"sh$ "),
        cr=cr,
        nl=nl,
        clreol=clreol,
        bsseq=bsseq,
        redirmeta=REG_REDIR_META_ADDR,
        reg_hist_idx=A4, # 14
        reg_line_len=A5, # 15
    )

    _gen_sh_parser(
        sh,
        linebuf=linebuf,
        argvbuf=argvbuf,
        redirmeta=REG_REDIR_META_ADDR,
        stageargvbuf=stageargvbuf,
        pathbufs=pathbufs,
        binprefix=REG_BIN_PREFIX,
        stagepathbuf=stagepathbuf,
        execfail=execfail,
        reg_tok_count=REG_TOK_COUNT,
        reg_cmd_name=REG_CMD_NAME,
        reg_stage_count=REG_STAGE_COUNT,
    )

    _gen_sh_exec(
        sh,
        stageargvbuf=stageargvbuf,
        stagepathbuf=stagepathbuf,
        pipebuf=REG_PIPEBUF_ADDR,
        statusbuf=statusbuf,
        redirmeta=REG_REDIR_META_ADDR,
        argvbuf=argvbuf,
        pathbufs=pathbufs,
        binprefix_reg=REG_BIN_PREFIX,
        execfail=execfail,
        ex_enoent=ex_enoent,
        ex_eacces=ex_eacces,
        ex_einval=ex_einval,
        ex_efault=ex_efault,
        ex_enomem=ex_enomem,
        openfail=openfail,
        cmd_exit=cmd_exit,
        cmd_help=cmd_help,
        cmd_echo=cmd_echo,
        cmd_cat=cmd_cat,
        cmd_ls=cmd_ls,
        cmd_cd=cmd_cd,
        cmd_pwd=cmd_pwd,
        cmd_status=cmd_status,
        reg_prev_pipe_read=REG_PREV_PIPE_READ,
        reg_last_status=REG_LAST_STATUS,
        reg_current_stage=REG_CURRENT_STAGE,
        reg_stage_count=REG_STAGE_COUNT,
    )

    _gen_sh_builtins(
        sh,
        iobuf_reg=REG_IOBUF,
        direntbuf_reg=REG_DIRENTBUF,
        cwdbuf_reg=REG_CWDBUF,
        binprefix_reg=REG_BIN_PREFIX,
        dotpath=dotpath,
        rootpath=rootpath,
        helpmsg=helpmsg,
        catusage=catusage,
        lsusage=lsusage,
        openfail=openfail,
        readfail=readfail,
        nl=nl,
        sp=sp,
        reg_tok_count=REG_TOK_COUNT,
        reg_cmd_name=REG_CMD_NAME,
        reg_argvbuf=S1,
        reg_last_status=REG_LAST_STATUS,
    )

    _gen_sh_utils(sh, iobuf_reg=REG_IOBUF)

    sh_rvx = sh.build_rvx()
    sh_ino = fs.create_file("/bin/sh")
    fs.write_inode(sh_ino, 0, sh_rvx, truncate=True)


def _map_user_range(aspace: AddressSpace, base: int, size: int) -> None:
    n_pages = (int(size) + PAGE_SIZE - 1) // PAGE_SIZE
    for i in range(n_pages):
        aspace.map_page(int(base + i * PAGE_SIZE), PageFlags.USER | PageFlags.R | PageFlags.W)


def _write_cstring(aspace: AddressSpace, addr: int, s: str) -> int:
    b = s.encode("utf-8") + b"\x00"
    aspace.write(int(addr), b, user=True)
    return int(addr + len(b))


def _write_ptr_array(aspace: AddressSpace, addr: int, ptrs: Sequence[int]) -> None:
    raw = b"".join(struct.pack("<Q", int(p)) for p in ptrs)
    aspace.write(int(addr), raw, user=True)


def _prepare_exec_args(aspace: AddressSpace, *, base: int, path: str, argv: Sequence[str]) -> tuple[int, int, int, int]:
    cursor = int(base)
    path_ptr = cursor
    cursor = _write_cstring(aspace, cursor, path)

    arg_ptrs: list[int] = []
    for a in argv:
        arg_ptrs.append(cursor)
        cursor = _write_cstring(aspace, cursor, a)

    argv_arr = (cursor + 7) & ~7
    _write_ptr_array(aspace, argv_arr, [*arg_ptrs, 0])

    envp_arr = argv_arr + 8 * (len(arg_ptrs) + 1)
    _write_ptr_array(aspace, envp_arr, [0])

    end = envp_arr + 8
    return int(path_ptr), int(argv_arr), int(envp_arr), int(end)


class _CbreakTerminal:
    def __init__(self) -> None:
        self._fd = -1
        self._old: list[int] | None = None
        try:
            self._fd = open("/dev/tty", "rb", buffering=0).fileno()
        except Exception:
            try:
                if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                    self._fd = sys.stdin.fileno()
            except Exception:
                self._fd = -1

    def __enter__(self) -> "_CbreakTerminal":
        if self._fd < 0:
            return self
        try:
            self._old = termios.tcgetattr(self._fd)
            new = termios.tcgetattr(self._fd)
            new[3] = new[3] & ~(termios.ICANON | termios.ECHO)
            new[3] = new[3] | termios.ISIG
            new[6][termios.VMIN] = 1
            new[6][termios.VTIME] = 0
            termios.tcsetattr(self._fd, termios.TCSADRAIN, new)
        except Exception:
            self._old = None
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if self._fd < 0:
            return
        if self._old is None:
            return
        try:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        except Exception:
            pass


def _run_program(env: ShellEnv, path: str, argv: Sequence[str]) -> int:
    pid = env.k.create_process()
    aspace = env.k.processes[pid].aspace

    user_base = 0x2000_0000

    max_str_bytes = 4096
    max_ptr_bytes = 4096
    _map_user_range(aspace, user_base, max_str_bytes + max_ptr_bytes)

    path_ptr, argv_ptr, envp_ptr, _ = _prepare_exec_args(aspace, base=user_base, path=path, argv=argv)

    entry_ret = int(
        env.k.syscalls.dispatch(
            env.k,
            pid,
            TrapFrame(rax=int(Sysno.EXECVE), rdi=path_ptr, rsi=argv_ptr, rdx=envp_ptr),
        )
    )
    if entry_ret < 0:
        try:
            env.k._reap_process(pid)
        except Exception:
            pass
        return int(entry_ret)

    try:
        with _CbreakTerminal():
            env.k.run_user_rv64(pid, entry_ret, max_steps=200_000_000)
    except KeyboardInterrupt:
        print("\nInterrupted (Ctrl-C).")
    finally:
        try:
            env.k._reap_process(pid)
        except Exception:
            pass

    return 0


def _cmd_help() -> None:
    print("commands:")
    print("  help")
    print("  exit")
    print("  pwd")
    print("  cd [path]")
    print("  ls [path]")
    print("  stat <path>")
    print("  cat <path>")
    print("  hexdump <path>")
    print("  mkdir <path>")
    print("  touch <path>")
    print("  write <path> <text...>")
    print("  append <path> <text...>")
    print("  echo [text...]")
    print("  run <path|cmd> [args...]")


def _norm_path(path: str) -> str:
    if path == "":
        return "/"
    if not path.startswith("/"):
        raise ValueError("path must be absolute")
    parts: list[str] = []
    for p in path.split("/"):
        if not p or p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/" + "/".join(parts)


def _resolve_path(env: ShellEnv, path: str) -> str:
    if path.startswith("/"):
        return _norm_path(path)
    base = env.cwd
    if not base.endswith("/"):
        base += "/"
    return _norm_path(base + path)


def _resolve_cmd(env: ShellEnv, cmd: str) -> str:
    if "/" in cmd:
        return _resolve_path(env, cmd)
    p = f"/bin/{cmd}"
    return p


def _cmd_ls(env: ShellEnv, path: str) -> None:
    try:
        ap = _resolve_path(env, path)
        names = env.fs.listdir(ap)
    except Exception as e:
        print(f"ls: {e}")
        return
    for n in names:
        print(n)


def _cmd_cat(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        data = env.fs.read_file(ap)
        try:
            sys.stdout.write(data.decode("utf-8", errors="replace"))
        except Exception:
            sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.write("\n")
    except Exception as e:
        print(f"cat: {e}")


def _cmd_stat(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    ino = env.fs.lookup(ap)
    if ino is None:
        print("stat: no such file")
        return
    typ = "dir" if ino.is_dir else "file"
    print(f"path: {ap}")
    print(f"type: {typ}")
    print(f"size: {int(ino.size_bytes)}")
    if not ino.is_dir:
        print(f"blocks: {len(ino.direct)}")


def _cmd_mkdir(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        env.fs.mkdir(ap)
    except Exception as e:
        print(f"mkdir: {e}")


def _cmd_touch(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        if not env.fs.exists(ap):
            env.fs.create_file(ap)
    except Exception as e:
        print(f"touch: {e}")


def _cmd_write(env: ShellEnv, path: str, text: str, *, append: bool) -> None:
    ap = _resolve_path(env, path)
    data = text.encode("utf-8")
    try:
        env.fs.write_file(ap, data, create=True, truncate=not append, append=append)
    except Exception as e:
        print(f"write: {e}")


def _cmd_hexdump(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        data = env.fs.read_file(ap)
        width = 16
        for i in range(0, len(data), width):
            chunk = data[i : i + width]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{i:08x}  {hx:<47}  |{asc}|")
    except Exception as e:
        print(f"hexdump: {e}")


def _make_env() -> ShellEnv:
    physmem = PhysMem(size_bytes=2048 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=4096)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()
    _install_base_bins(fs)

    k = Kernel(kas)
    k.set_fs(fs)
    return ShellEnv(k=k, fs=fs, kas=kas)


def _read_host_line() -> str | None:
    try:
        return input("simos$ ")
    except EOFError:
        print()
        return None
    except KeyboardInterrupt:
        print()
        return ""


def _parse_host_line(line: str) -> list[str] | None:
    line = line.strip()
    if not line:
        return []
    try:
        return list(shlex.split(line))
    except ValueError as e:
        print(f"parse error: {e}")
        return None


def _dispatch_host_command(env: ShellEnv, parts: Sequence[str]) -> bool:
    if not parts:
        return True
    cmd, *args = parts

    if cmd in ("exit", "quit"):
        return False
    if cmd == "help":
        _cmd_help()
        return True
    if cmd == "pwd":
        print(env.cwd)
        return True
    if cmd == "cd":
        target = args[0] if args else "/"
        ap = _resolve_path(env, target)
        ino = env.fs.lookup(ap)
        if ino is None or not ino.is_dir:
            print("cd: not a directory")
            return True
        env.cwd = ap
        return True
    if cmd == "ls":
        _cmd_ls(env, args[0] if args else env.cwd)
        return True
    if cmd == "stat":
        if not args:
            print("stat: missing path")
            return True
        _cmd_stat(env, args[0])
        return True
    if cmd == "cat":
        if not args:
            print("cat: missing path")
            return True
        _cmd_cat(env, args[0])
        return True
    if cmd == "hexdump":
        if not args:
            print("hexdump: missing path")
            return True
        _cmd_hexdump(env, args[0])
        return True
    if cmd == "mkdir":
        if not args:
            print("mkdir: missing path")
            return True
        _cmd_mkdir(env, args[0])
        return True
    if cmd == "touch":
        if not args:
            print("touch: missing path")
            return True
        _cmd_touch(env, args[0])
        return True
    if cmd == "write":
        if len(args) < 2:
            print("write: usage: write <path> <text...>")
            return True
        _cmd_write(env, args[0], " ".join(args[1:]), append=False)
        return True
    if cmd == "append":
        if len(args) < 2:
            print("append: usage: append <path> <text...>")
            return True
        _cmd_write(env, args[0], " ".join(args[1:]), append=True)
        return True
    if cmd == "echo":
        print(" ".join(args))
        return True
    if cmd == "run":
        if not args:
            print("run: missing path")
            return True
        path = _resolve_cmd(env, args[0])
        argv = [path, *args[1:]]
        rc = _run_program(env, path, argv)
        if rc != 0:
            name = _errno_name(rc)
            if name is None:
                print(f"run: execve failed: {rc}")
            else:
                print(f"run: execve failed: {name} ({rc})")
        return True

    print("unknown command")
    return True


def repl() -> None:
    env = _make_env()
    _cmd_help()

    while True:
        line = _read_host_line()
        if line is None:
            return
        parts = _parse_host_line(line)
        if parts is None:
            continue
        if parts == []:
            continue
        if not _dispatch_host_command(env, parts):
            return
