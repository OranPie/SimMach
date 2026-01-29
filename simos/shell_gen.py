from __future__ import annotations

from constants import Errno, Sysno
from simmach import rvasm, rvlib
from simmach.rvprog import Program

def _gen_sh_parser(
    sh: Program,
    *,
    linebuf: int,
    argvbuf: int,
    redirmeta: int,
    stageargvbuf: int,
    pathbufs: int,
    binprefix: int,
    stagepathbuf: int,
    execfail: int,
    reg_tok_count: int,
    reg_cmd_name: int,
    reg_stage_count: int,
    expbuf: int,
    varcount: int,
    varnames: int,
    varvalues: int,
) -> None:
    A0, A1, A2, A3, A4, A5, A6, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A4, rvlib.A5, rvlib.A6, rvlib.A7
    T0, T1, T2, T3, T4, T5, T6 = rvlib.T0, rvlib.T1, rvlib.T2, rvlib.T3, rvlib.T4, rvlib.T5, rvlib.T6
    S0, S1, S2, S6, S7 = rvlib.S0, rvlib.S1, rvlib.S2, rvlib.S6, rvlib.S7

    REG_LINE_CURSOR = T0
    REG_CHAR = T1
    REG_SCRATCH = T2
    REG_WRITE_CURSOR = T3
    REG_IN_QUOTE = T4
    REG_TOK_COUNT = reg_tok_count
    REG_REDIR_IDX = A4
    REG_CMD_NAME = reg_cmd_name
    REG_STAGE_COUNT = reg_stage_count

    sh.li(REG_TOK_COUNT, 0)
    sh.emit(rvasm.addi(REG_LINE_CURSOR, S0, 0))
    sh.emit(rvasm.addi(REG_WRITE_CURSOR, S0, 0))
    sh.li(REG_IN_QUOTE, 0)
    sh.emit(rvasm.addi(A3, redirmeta, 0))
    sh.emit(rvasm.sd(rvlib.ZERO, A3, 0))

    sh.label("parse_skip")
    sh.emit(rvasm.lbu(REG_CHAR, REG_LINE_CURSOR, 0))
    sh.beq(REG_CHAR, rvlib.ZERO, "parse_done")
    sh.li(REG_SCRATCH, 10)
    sh.beq(REG_CHAR, REG_SCRATCH, "parse_nl")
    sh.li(REG_SCRATCH, 32)
    sh.bne(REG_CHAR, REG_SCRATCH, "parse_tok")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "parse_skip")

    sh.label("parse_nl")
    sh.emit(rvasm.sb(rvlib.ZERO, REG_WRITE_CURSOR, 0))
    sh.jal(rvlib.ZERO, "parse_done")

    sh.label("parse_tok")
    sh.emit(rvasm.slli(REG_SCRATCH, REG_TOK_COUNT, 3))
    sh.emit(rvasm.add(REG_SCRATCH, S1, REG_SCRATCH))
    sh.emit(rvasm.sd(REG_WRITE_CURSOR, REG_SCRATCH, 0))
    sh.emit(rvasm.addi(REG_TOK_COUNT, REG_TOK_COUNT, 1))

    sh.label("scan_tok")
    sh.emit(rvasm.lbu(REG_CHAR, REG_LINE_CURSOR, 0))
    sh.beq(REG_CHAR, rvlib.ZERO, "tok_end")
    sh.li(REG_SCRATCH, 10)
    sh.beq(REG_CHAR, REG_SCRATCH, "tok_end")
    sh.li(REG_SCRATCH, 34)
    sh.beq(REG_CHAR, REG_SCRATCH, "tok_quote")
    sh.li(REG_SCRATCH, 32)
    sh.beq(REG_CHAR, REG_SCRATCH, "tok_space")
    sh.emit(rvasm.sb(REG_CHAR, REG_WRITE_CURSOR, 0))
    sh.emit(rvasm.addi(REG_WRITE_CURSOR, REG_WRITE_CURSOR, 1))
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "scan_tok")

    sh.label("tok_quote")
    sh.beq(REG_IN_QUOTE, rvlib.ZERO, "tok_quote_on")
    sh.li(REG_IN_QUOTE, 0)
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "scan_tok")
    sh.label("tok_quote_on")
    sh.li(REG_IN_QUOTE, 1)
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "scan_tok")

    sh.label("tok_space")
    sh.bne(REG_IN_QUOTE, rvlib.ZERO, "tok_space_copy")
    sh.emit(rvasm.sb(rvlib.ZERO, REG_WRITE_CURSOR, 0))
    sh.emit(rvasm.addi(REG_WRITE_CURSOR, REG_WRITE_CURSOR, 1))
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "parse_skip")
    sh.label("tok_space_copy")
    sh.emit(rvasm.sb(REG_CHAR, REG_WRITE_CURSOR, 0))
    sh.emit(rvasm.addi(REG_WRITE_CURSOR, REG_WRITE_CURSOR, 1))
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "scan_tok")

    sh.label("tok_end")
    sh.emit(rvasm.sb(rvlib.ZERO, REG_WRITE_CURSOR, 0))
    sh.emit(rvasm.addi(REG_WRITE_CURSOR, REG_WRITE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "parse_done")

    sh.label("parse_done")
    sh.emit(rvasm.slli(REG_SCRATCH, REG_TOK_COUNT, 3))
    sh.emit(rvasm.add(REG_SCRATCH, S1, REG_SCRATCH))
    sh.emit(rvasm.sd(rvlib.ZERO, REG_SCRATCH, 0))
    sh.beq(REG_TOK_COUNT, rvlib.ZERO, "loop")

    sh.emit(rvasm.ld(REG_CMD_NAME, S1, 0))

    # Expand $VAR in argv into expbuf.
    sh.li(T0, 0)
    sh.li(S7, expbuf)
    sh.li(T4, 512)
    sh.emit(rvasm.add(T4, S7, T4))
    sh.label("expand_loop")
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, S1, T1))
    sh.emit(rvasm.ld(T2, T1, 0))
    sh.beq(T2, rvlib.ZERO, "expand_done")
    sh.emit(rvasm.lbu(T3, T2, 0))
    sh.li(T5, 62)
    sh.beq(T3, T5, "expand_next")
    sh.li(T5, 124)
    sh.beq(T3, T5, "expand_next")
    sh.emit(rvasm.addi(A0, T2, 0))
    sh.emit(rvasm.addi(A1, S7, 0))
    sh.emit(rvasm.addi(A2, T4, 0))
    sh.li(A3, varcount)
    sh.li(A4, varnames)
    sh.li(A5, varvalues)
    sh.jal(rvlib.RA, "expand_token")
    sh.emit(rvasm.sd(A0, T1, 0))
    sh.emit(rvasm.addi(S7, A1, 0))
    sh.label("expand_next")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(rvlib.ZERO, "expand_loop")
    sh.label("expand_done")

    sh.label("expand_token")
    sh.emit(rvasm.addi(T0, A0, 0))  # src_orig
    sh.emit(rvasm.addi(S6, A1, 0))  # exp_orig
    sh.li(T2, 0)  # any_expand
    sh.emit(rvasm.addi(S7, A1, 0))  # dest
    sh.emit(rvasm.addi(T4, A2, -1))  # exp_end_minus1
    sh.label("expand_loop_char")
    sh.emit(rvasm.lbu(T5, A0, 0))
    sh.beq(T5, rvlib.ZERO, "expand_finish")
    sh.li(T6, 36)
    sh.beq(T5, T6, "expand_dollar")
    sh.bge(S7, T4, "expand_overflow")
    sh.emit(rvasm.sb(T5, S7, 0))
    sh.emit(rvasm.addi(S7, S7, 1))
    sh.emit(rvasm.addi(A0, A0, 1))
    sh.jal(rvlib.ZERO, "expand_loop_char")

    sh.label("expand_dollar")
    sh.emit(rvasm.addi(A0, A0, 1))
    sh.emit(rvasm.lbu(T5, A0, 0))
    sh.beq(T5, rvlib.ZERO, "expand_copy_dollar")
    sh.li(T6, 95)
    sh.beq(T5, T6, "expand_var_start")
    sh.li(T6, 48)
    sh.blt(T5, T6, "expand_copy_dollar")
    sh.li(T6, 58)
    sh.blt(T5, T6, "expand_var_start")
    sh.li(T6, 65)
    sh.blt(T5, T6, "expand_copy_dollar")
    sh.li(T6, 91)
    sh.blt(T5, T6, "expand_var_start")
    sh.li(T6, 97)
    sh.blt(T5, T6, "expand_copy_dollar")
    sh.li(T6, 123)
    sh.blt(T5, T6, "expand_var_start")
    sh.jal(rvlib.ZERO, "expand_copy_dollar")

    sh.label("expand_copy_dollar")
    sh.li(T5, 36)
    sh.bge(S7, T4, "expand_overflow")
    sh.emit(rvasm.sb(T5, S7, 0))
    sh.emit(rvasm.addi(S7, S7, 1))
    sh.jal(rvlib.ZERO, "expand_loop_char")

    sh.label("expand_var_start")
    sh.li(T2, 1)
    sh.emit(rvasm.addi(T6, A0, 0))  # name_start
    sh.label("expand_name_scan")
    sh.emit(rvasm.lbu(T5, A0, 0))
    sh.beq(T5, rvlib.ZERO, "expand_name_end")
    sh.li(T1, 95)
    sh.beq(T5, T1, "expand_name_advance")
    sh.li(T1, 48)
    sh.blt(T5, T1, "expand_name_end")
    sh.li(T1, 58)
    sh.blt(T5, T1, "expand_name_advance")
    sh.li(T1, 65)
    sh.blt(T5, T1, "expand_name_end")
    sh.li(T1, 91)
    sh.blt(T5, T1, "expand_name_advance")
    sh.li(T1, 97)
    sh.blt(T5, T1, "expand_name_end")
    sh.li(T1, 123)
    sh.blt(T5, T1, "expand_name_advance")
    sh.jal(rvlib.ZERO, "expand_name_end")
    sh.label("expand_name_advance")
    sh.emit(rvasm.addi(A0, A0, 1))
    sh.jal(rvlib.ZERO, "expand_name_scan")

    sh.label("expand_name_end")
    sh.emit(rvasm.addi(A6, A0, 0))  # name_end
    sh.emit(rvasm.lbu(T1, A6, 0))
    sh.emit(rvasm.sb(rvlib.ZERO, A6, 0))
    sh.emit(rvasm.ld(A7, A3, 0))  # varcount
    sh.li(T5, 0)  # idx
    sh.label("expand_var_lookup")
    sh.bge(T5, A7, "expand_var_not_found")
    sh.emit(rvasm.slli(T3, T5, 5))
    sh.emit(rvasm.add(T3, A4, T3))
    sh.emit(rvasm.addi(A0, T6, 0))
    sh.emit(rvasm.addi(A1, T3, 0))
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "expand_var_found")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.jal(rvlib.ZERO, "expand_var_lookup")

    sh.label("expand_var_not_found")
    sh.emit(rvasm.sb(T1, A6, 0))
    sh.jal(rvlib.ZERO, "expand_loop_char")

    sh.label("expand_var_found")
    sh.emit(rvasm.sb(T1, A6, 0))
    sh.emit(rvasm.slli(T3, T5, 7))
    sh.emit(rvasm.add(T3, A5, T3))
    sh.label("expand_copy_val")
    sh.emit(rvasm.lbu(T1, T3, 0))
    sh.beq(T1, rvlib.ZERO, "expand_loop_char")
    sh.bge(S7, T4, "expand_overflow")
    sh.emit(rvasm.sb(T1, S7, 0))
    sh.emit(rvasm.addi(S7, S7, 1))
    sh.emit(rvasm.addi(T3, T3, 1))
    sh.jal(rvlib.ZERO, "expand_copy_val")

    sh.label("expand_finish")
    sh.beq(T2, rvlib.ZERO, "expand_no_change")
    sh.emit(rvasm.sb(rvlib.ZERO, S7, 0))
    sh.emit(rvasm.addi(A0, S6, 0))
    sh.emit(rvasm.addi(A1, S7, 1))
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    sh.label("expand_no_change")
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.emit(rvasm.addi(A1, S6, 0))
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    sh.label("expand_overflow")
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.emit(rvasm.addi(A1, S6, 0))
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    # Output redirection: detect a single '>' or '>>' token (must be space-separated).
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
    sh.beq(A1, rvlib.ZERO, "redir_set_trunc")
    sh.li(A2, 62)
    sh.bne(A1, A2, "redir_next")
    sh.emit(rvasm.lbu(A1, A0, 2))
    sh.bne(A1, rvlib.ZERO, "redir_next")
    sh.jal(rvlib.ZERO, "redir_set_append")
    sh.label("redir_set_trunc")
    sh.emit(rvasm.addi(REG_REDIR_IDX, REG_LINE_CURSOR, 0))
    sh.li(T5, 1)
    sh.jal(rvlib.ZERO, "redir_scan_done")
    sh.label("redir_set_append")
    sh.emit(rvasm.addi(REG_REDIR_IDX, REG_LINE_CURSOR, 0))
    sh.li(T5, 2)
    sh.jal(rvlib.ZERO, "redir_scan_done")
    sh.label("redir_next")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "scan_redir")
    sh.label("redir_scan_done")
    sh.blt(REG_REDIR_IDX, rvlib.ZERO, "redir_done")
    sh.beq(REG_REDIR_IDX, rvlib.ZERO, "redir_syntax")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_TOK_COUNT, -1))
    sh.beq(REG_REDIR_IDX, REG_LINE_CURSOR, "redir_syntax")

    # Split argv in-place: argv[redir_idx] = 0; save path=argv[redir_idx+1] in redirmeta.
    sh.emit(rvasm.addi(REG_SCRATCH, REG_REDIR_IDX, 0))
    sh.emit(rvasm.slli(REG_CHAR, REG_REDIR_IDX, 3))
    sh.emit(rvasm.add(REG_CHAR, S1, REG_CHAR))
    sh.emit(rvasm.sd(rvlib.ZERO, REG_CHAR, 0))
    sh.emit(rvasm.addi(REG_REDIR_IDX, REG_REDIR_IDX, 1))
    sh.emit(rvasm.slli(REG_CHAR, REG_REDIR_IDX, 3))
    sh.emit(rvasm.add(REG_CHAR, S1, REG_CHAR))
    sh.emit(rvasm.ld(A0, REG_CHAR, 0))
    sh.emit(rvasm.addi(A3, redirmeta, 0))
    sh.emit(rvasm.sd(T5, A3, 0))
    sh.emit(rvasm.sd(A0, A3, 8))
    sh.emit(rvasm.addi(REG_TOK_COUNT, REG_SCRATCH, 0))
    sh.jal(rvlib.ZERO, "redir_done")

    sh.label("redir_syntax")
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    sh.jal(rvlib.ZERO, "loop")

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
    sh.bne(A1, rvlib.ZERO, "scan_pipe_multi_next")
    sh.beq(REG_LINE_CURSOR, rvlib.ZERO, "pipe_syntax_multi")
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
    sh.beq(A1, rvlib.ZERO, "pipe_syntax_multi")
    sh.label("pipe_tok_ok")

    sh.emit(rvasm.sd(rvlib.ZERO, REG_CHAR, 0))
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T4, REG_STAGE_COUNT, 3))
    sh.emit(rvasm.add(T4, A3, T4))
    sh.emit(rvasm.sd(T3, T4, 0))
    sh.emit(rvasm.addi(REG_STAGE_COUNT, REG_STAGE_COUNT, 1))
    sh.li(T5, 4)
    sh.blt(REG_STAGE_COUNT, T5, "scan_pipe_multi_next")
    sh.jal(rvlib.ZERO, "pipe_syntax_multi")

    sh.label("scan_pipe_multi_next")
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "scan_pipe_multi")
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
    sh.emit(rvasm.addi(A3, REG_SCRATCH, 0))

    sh.li(T3, 0)
    sh.label("bp_scan_slash")
    sh.emit(rvasm.add(A0, A3, T3))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.beq(A1, rvlib.ZERO, "bp_no_slash")
    sh.li(A2, 47)
    sh.beq(A1, A2, "bp_has_slash")
    sh.emit(rvasm.addi(T3, T3, 1))
    sh.jal(rvlib.ZERO, "bp_scan_slash")

    sh.label("bp_has_slash")
    sh.emit(rvasm.addi(T4, A3, 0))
    sh.jal(rvlib.ZERO, "bp_path_done")

    sh.label("bp_no_slash")
    sh.emit(rvasm.slli(T4, REG_LINE_CURSOR, 7))
    sh.emit(rvasm.add(T4, S2, T4))
    sh.li(T5, 0)
    sh.label("bp_cpy_pre")
    sh.emit(rvasm.add(REG_CHAR, binprefix, T5))
    sh.emit(rvasm.lbu(REG_SCRATCH, REG_CHAR, 0))
    sh.emit(rvasm.add(REG_CHAR, T4, T5))
    sh.emit(rvasm.sb(REG_SCRATCH, REG_CHAR, 0))
    sh.beq(REG_SCRATCH, rvlib.ZERO, "bp_cpy_pre_done")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.jal(rvlib.ZERO, "bp_cpy_pre")
    sh.label("bp_cpy_pre_done")
    sh.emit(rvasm.addi(T5, T5, -1))
    sh.li(REG_CHAR, 0)
    sh.label("bp_cpy_cmd")
    sh.emit(rvasm.add(A0, A3, REG_CHAR))
    sh.emit(rvasm.lbu(REG_SCRATCH, A0, 0))
    sh.emit(rvasm.add(A0, T4, T5))
    sh.emit(rvasm.sb(REG_SCRATCH, A0, 0))
    sh.beq(REG_SCRATCH, rvlib.ZERO, "bp_path_done")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.emit(rvasm.addi(REG_CHAR, REG_CHAR, 1))
    sh.jal(rvlib.ZERO, "bp_cpy_cmd")

    sh.label("bp_path_done")
    sh.li(A3, stagepathbuf)
    sh.emit(rvasm.slli(REG_CHAR, REG_LINE_CURSOR, 3))
    sh.emit(rvasm.add(REG_CHAR, A3, REG_CHAR))
    sh.emit(rvasm.sd(T4, REG_CHAR, 0))
    sh.emit(rvasm.addi(REG_LINE_CURSOR, REG_LINE_CURSOR, 1))
    sh.jal(rvlib.ZERO, "build_stage_paths")

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
    sh.emit(rvasm.addi(A3, redirmeta, 0))
    sh.emit(rvasm.sd(rvlib.ZERO, A3, 0))
    sh.emit(rvasm.sd(rvlib.ZERO, A3, 8))
    
    sh.li(REG_HIST_IDX, 0)
    sh.li(REG_LINE_LEN, 0)
    sh.label("rl_read_loop")
    rvlib.sys_read_fd_reg_cnt(sh, fd=0, buf_reg=REG_IOBUF, count=1)
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
    sh.jal(rvlib.ZERO, "rl_read_loop")

    sh.label("rl_backspace")
    sh.beq(REG_LINE_LEN, rvlib.ZERO, "rl_read_loop")
    sh.emit(rvasm.addi(REG_LINE_LEN, REG_LINE_LEN, -1))
    rvlib.sys_write(sh, fd=1, buf=bsseq, count=3)
    sh.jal(rvlib.ZERO, "rl_read_loop")

    sh.label("rl_esc")
    rvlib.sys_read_fd_reg_cnt(sh, fd=0, buf_reg=REG_IOBUF, count=1)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, REG_IOBUF, 0))
    sh.li(T0, 91)
    sh.bne(T1, T0, "rl_read_loop")
    rvlib.sys_read_fd_reg_cnt(sh, fd=0, buf_reg=REG_IOBUF, count=1)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, REG_IOBUF, 0))
    sh.li(T0, 65)
    sh.beq(T1, T0, "rl_hist_up")
    sh.li(T0, 66)
    sh.beq(T1, T0, "rl_hist_down")
    sh.jal(rvlib.ZERO, "rl_read_loop")

    sh.label("rl_hist_up")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, rvlib.ZERO, "rl_read_loop")
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
    sh.jal(rvlib.ZERO, "rl_hist_cpy")
    sh.label("rl_hist_cpy_done")
    sh.emit(rvasm.add(T0, S0, REG_LINE_LEN))
    sh.emit(rvasm.sb(rvlib.ZERO, T0, 0))
    sh.jal(rvlib.RA, "rl_redraw")

    sh.label("rl_hist_down")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, rvlib.ZERO, "rl_read_loop")
    sh.beq(REG_HIST_IDX, rvlib.ZERO, "rl_hist_clear")
    sh.emit(rvasm.addi(REG_HIST_IDX, REG_HIST_IDX, -1))
    sh.jal(rvlib.ZERO, "rl_hist_load")
    sh.label("rl_hist_clear")
    sh.li(REG_LINE_LEN, 0)
    sh.emit(rvasm.sb(rvlib.ZERO, S0, 0))
    sh.jal(rvlib.RA, "rl_redraw")

    sh.label("rl_redraw")
    rvlib.sys_write(sh, fd=1, buf=cr, count=1)
    rvlib.sys_write(sh, fd=1, buf=prompt, count=prompt_len)
    rvlib.sys_write(sh, fd=1, buf=clreol, count=3)
    sh.beq(REG_LINE_LEN, rvlib.ZERO, "rl_redraw_done")
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=S0, count_reg=REG_LINE_LEN)
    sh.label("rl_redraw_done")
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    sh.label("rl_enter")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.emit(rvasm.add(T0, S0, REG_LINE_LEN))
    sh.li(T1, 10)
    sh.emit(rvasm.sb(T1, T0, 0))
    sh.emit(rvasm.addi(REG_LINE_LEN, REG_LINE_LEN, 1))
    sh.emit(rvasm.add(T0, S0, REG_LINE_LEN))
    sh.emit(rvasm.sb(rvlib.ZERO, T0, 0))
    sh.emit(rvasm.addi(A0, REG_LINE_LEN, 0))
    sh.li(T0, 1)
    sh.blt(A0, T0, "loop")

    sh.emit(rvasm.addi(T2, REG_LINE_LEN, -1))
    sh.beq(T2, rvlib.ZERO, "rl_hist_save_done")
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
    sh.jal(rvlib.ZERO, "rl_hist_save_cpy")
    sh.label("rl_hist_save_cpy_done")
    sh.emit(rvasm.add(A0, A4, T2))
    sh.emit(rvasm.sb(rvlib.ZERO, A0, 0))
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
    A0, A1, A2, A3, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A7
    T0, T1, T2, T3 = rvlib.T0, rvlib.T1, rvlib.T2, rvlib.T3

    sh.label("strcmp")
    sh.label("sc_loop")
    sh.emit(rvasm.lbu(T0, A0, 0))
    sh.emit(rvasm.lbu(T1, A1, 0))
    sh.bne(T0, T1, "sc_ne")
    sh.beq(T0, rvlib.ZERO, "sc_eq")
    sh.emit(rvasm.addi(A0, A0, 1))
    sh.emit(rvasm.addi(A1, A1, 1))
    sh.jal(rvlib.ZERO, "sc_loop")
    sh.label("sc_ne")
    sh.li(A0, 1)
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)
    sh.label("sc_eq")
    sh.li(A0, 0)
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    # strcpy: copy string from A1 to A2
    sh.label("strcpy")
    sh.label("scp_loop")
    sh.emit(rvasm.lbu(T0, A1, 0))
    sh.emit(rvasm.sb(T0, A2, 0))
    sh.beq(T0, rvlib.ZERO, "scp_done")
    sh.emit(rvasm.addi(A1, A1, 1))
    sh.emit(rvasm.addi(A2, A2, 1))
    sh.jal(rvlib.ZERO, "scp_loop")
    sh.label("scp_done")
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    sh.label("strlen")
    sh.li(T0, 0)
    sh.label("sl_loop")
    sh.emit(rvasm.add(T1, A0, T0))
    sh.emit(rvasm.lbu(T2, T1, 0))
    sh.beq(T2, rvlib.ZERO, "sl_done")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(rvlib.ZERO, "sl_loop")
    sh.label("sl_done")
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    # atoi: parse unsigned decimal in A0, return A0=result, A1=valid (1/0)
    sh.label("atoi")
    sh.li(T0, 0)
    sh.li(T1, 0)
    sh.label("atoi_loop")
    sh.emit(rvasm.lbu(T2, A0, 0))
    sh.beq(T2, rvlib.ZERO, "atoi_done")
    sh.li(T3, 48)
    sh.blt(T2, T3, "atoi_bad")
    sh.li(T3, 58)
    sh.bge(T2, T3, "atoi_bad")
    sh.li(T1, 1)
    sh.emit(rvasm.slli(T3, T0, 3))
    sh.emit(rvasm.slli(A2, T0, 1))
    sh.emit(rvasm.add(T0, T3, A2))
    sh.emit(rvasm.addi(T2, T2, -48))
    sh.emit(rvasm.add(T0, T0, T2))
    sh.emit(rvasm.addi(A0, A0, 1))
    sh.jal(rvlib.ZERO, "atoi_loop")
    sh.label("atoi_bad")
    sh.li(T1, 0)
    sh.label("atoi_done")
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.emit(rvasm.addi(A1, T1, 0))
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

    sh.label("print_dec")
    sh.emit(rvasm.addi(T0, A0, 0))
    sh.beq(T0, rvlib.ZERO, "pd_zero")
    sh.li(T1, 0)
    sh.label("pd_outer")
    sh.beq(T0, rvlib.ZERO, "pd_done")
    sh.li(T2, 0)
    sh.emit(rvasm.addi(A0, T0, 0))
    sh.label("pd_div")
    sh.li(A1, 10)
    sh.blt(A0, A1, "pd_div_done")
    sh.emit(rvasm.addi(A0, A0, -10))
    sh.emit(rvasm.addi(T2, T2, 1))
    sh.jal(rvlib.ZERO, "pd_div")
    sh.label("pd_div_done")
    sh.emit(rvasm.addi(A2, A0, 48))
    sh.emit(rvasm.add(A1, iobuf_reg, T1))
    sh.emit(rvasm.sb(A2, A1, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.emit(rvasm.addi(T0, T2, 0))
    sh.jal(rvlib.ZERO, "pd_outer")
    sh.label("pd_zero")
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, iobuf_reg, 0))
    sh.li(A2, 48)
    sh.emit(rvasm.sb(A2, A1, 0))
    sh.li(T1, 1)
    sh.label("pd_done")
    sh.emit(rvasm.addi(T1, T1, -1))
    sh.blt(T1, rvlib.ZERO, "pd_ret")
    sh.emit(rvasm.add(A1, iobuf_reg, T1))
    rvlib.sys_write_fd_reg_cnt(sh, fd=1, buf_reg=A1, count=1)
    sh.jal(rvlib.ZERO, "pd_done")
    sh.label("pd_ret")
    sh.jalr(rvlib.ZERO, rvlib.RA, 0)

def _gen_sh_builtins(
    sh: Program,
    *,
    iobuf_reg: int,
    direntbuf_reg: int,
    cwdbuf_reg: int,
    binprefix_reg: int,
    dotpath: int,
    rootpath: int,
    helpmsg: int,
    catusage: int,
    lsusage: int,
    openfail: int,
    readfail: int,
    nl: int,
    sp: int,
    reg_tok_count: int,
    reg_cmd_name: int,
    reg_argvbuf: int,
    reg_last_status: int,
    varcount: int,
    varnames: int,
    varvalues: int,
    var_equals: int,
    mkdir_usage: int,
    mkdir_fail: int,
    rm_usage: int,
    rm_fail: int,
    mv_usage: int,
    mv_fail: int,
    touch_usage: int,
    touch_fail: int,
    stat_usage: int,
    stat_fail: int,
    stat_type: int,
    stat_file: int,
    stat_dir: int,
    stat_inum: int,
    stat_size: int,
    statbuf: int,
    sleep_usage: int,
) -> None:
    A0, A1, A2, A3, A7 = rvlib.A0, rvlib.A1, rvlib.A2, rvlib.A3, rvlib.A7
    T0, T1, T2, T3 = rvlib.T0, rvlib.T1, rvlib.T2, rvlib.T3
    S6 = rvlib.S6

    sh.label("do_exit")
    rvlib.sys_exit(sh, rvlib.ZERO)

    sh.label("do_help")
    rvlib.sys_write(
        sh,
        fd=1,
        buf=helpmsg,
        count=len(b"builtins: help exit echo cat ls cd pwd status set unset export mkdir rm mv touch stat sleep pid ppid\n"),
    )
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_echo")
    sh.li(T0, 1)
    sh.label("echo_loop")
    sh.bge(T0, reg_tok_count, "echo_done")
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, reg_argvbuf, T1))
    sh.emit(rvasm.ld(A1, T1, 0))
    sh.emit(rvasm.addi(A0, A1, 0))
    sh.jal(rvlib.RA, "strlen")
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=A1, count_reg=A0)
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.bge(T0, reg_tok_count, "echo_done")
    rvlib.sys_write(sh, fd=1, buf=sp, count=1)
    sh.jal(rvlib.ZERO, "echo_loop")
    sh.label("echo_done")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_status")
    sh.emit(rvasm.addi(A0, reg_last_status, 0))
    sh.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "loop")

    # do_set - list all variables or set a variable
    sh.label("do_set")
    sh.li(T0, 3)
    sh.blt(reg_tok_count, T0, "set_list")
    # Set variable: set VAR value
    sh.jal(rvlib.ZERO, "set_var")
    sh.label("set_list")
    # List all variables
    sh.li(T0, varcount)
    sh.emit(rvasm.ld(T1, T0, 0))  # T1 = var count
    sh.emit(rvasm.addi(rvlib.S6, T1, 0))  # S6 = var count (saved)
    sh.li(rvlib.S7, 0)  # S7 = index (saved)
    sh.label("set_list_loop")
    sh.bge(rvlib.S7, rvlib.S6, "set_list_done")
    # Print varname[S7]
    sh.li(A1, varnames)
    sh.emit(rvasm.slli(T2, rvlib.S7, 5))  # T2 = S7 * 32
    sh.emit(rvasm.add(A1, A1, T2))
    # Check if varname is empty (deleted variable)
    sh.emit(rvasm.lbu(T0, A1, 0))
    sh.beq(T0, rvlib.ZERO, "set_list_next")
    sh.emit(rvasm.addi(A0, A1, 0))
    sh.jal(rvlib.RA, "strlen")
    # Reload A1 after strlen
    sh.li(A1, varnames)
    sh.emit(rvasm.slli(T2, rvlib.S7, 5))
    sh.emit(rvasm.add(A1, A1, T2))
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=A1, count_reg=A0)
    # Print "="
    rvlib.sys_write(sh, fd=1, buf=var_equals, count=1)
    # Print varvalue[S7]
    sh.li(A1, varvalues)
    sh.emit(rvasm.slli(T2, rvlib.S7, 7))  # T2 = S7 * 128
    sh.emit(rvasm.add(A1, A1, T2))
    sh.emit(rvasm.addi(A0, A1, 0))
    sh.jal(rvlib.RA, "strlen")
    # Reload A1 after strlen
    sh.li(A1, varvalues)
    sh.emit(rvasm.slli(T2, rvlib.S7, 7))
    sh.emit(rvasm.add(A1, A1, T2))
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=A1, count_reg=A0)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.label("set_list_next")
    sh.emit(rvasm.addi(rvlib.S7, rvlib.S7, 1))
    sh.jal(rvlib.ZERO, "set_list_loop")
    sh.label("set_list_done")
    sh.jal(rvlib.ZERO, "loop")

    # set_var - set VAR value
    sh.label("set_var")
    # S6 = argv[1] (var name), S7 = argv[2] (value)
    sh.emit(rvasm.ld(rvlib.S6, reg_argvbuf, 8))
    sh.emit(rvasm.ld(rvlib.S7, reg_argvbuf, 16))
    # Look for existing variable
    sh.li(T0, varcount)
    sh.emit(rvasm.ld(T1, T0, 0))  # T1 = var count
    sh.emit(rvasm.addi(rvlib.S8, T1, 0))  # S8 = var count (saved)
    sh.li(rvlib.S9, 0)  # S9 = index (saved)
    sh.label("set_var_find")
    sh.bge(rvlib.S9, rvlib.S8, "set_var_new")
    # Compare varnames[S9] with S6
    sh.li(T2, varnames)
    sh.emit(rvasm.slli(T3, rvlib.S9, 5))
    sh.emit(rvasm.add(T2, T2, T3))
    sh.emit(rvasm.addi(A0, rvlib.S6, 0))  # A0 = var name
    sh.emit(rvasm.addi(A1, T2, 0))  # A1 = &varnames[S9]
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "set_var_update")
    sh.emit(rvasm.addi(rvlib.S9, rvlib.S9, 1))
    sh.jal(rvlib.ZERO, "set_var_find")

    # Update existing variable value
    sh.label("set_var_update")
    sh.emit(rvasm.addi(A1, rvlib.S7, 0))  # A1 = value
    sh.li(A2, varvalues)
    sh.emit(rvasm.slli(A3, rvlib.S9, 7))
    sh.emit(rvasm.add(A2, A2, A3))  # A2 = &varvalues[S9]
    sh.jal(rvlib.RA, "strcpy")
    sh.jal(rvlib.ZERO, "loop")

    # Add new variable
    sh.label("set_var_new")
    sh.li(T2, 32)
    sh.bge(rvlib.S8, T2, "loop")  # Max 32 variables
    # Copy name to varnames[S8]
    sh.emit(rvasm.addi(A1, rvlib.S6, 0))  # A1 = var name
    sh.li(A2, varnames)
    sh.emit(rvasm.slli(A3, rvlib.S8, 5))
    sh.emit(rvasm.add(A2, A2, A3))
    sh.jal(rvlib.RA, "strcpy")
    # Copy value to varvalues[S8]
    sh.emit(rvasm.addi(A1, rvlib.S7, 0))  # A1 = value
    sh.li(A2, varvalues)
    sh.emit(rvasm.slli(A3, rvlib.S8, 7))
    sh.emit(rvasm.add(A2, A2, A3))
    sh.jal(rvlib.RA, "strcpy")
    # Increment varcount
    sh.li(T0, varcount)
    sh.emit(rvasm.ld(T1, T0, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.emit(rvasm.sd(T1, T0, 0))
    sh.jal(rvlib.ZERO, "loop")

    # do_unset - remove a variable
    sh.label("do_unset")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "loop")
    # S6 = var name to unset
    sh.emit(rvasm.ld(rvlib.S6, reg_argvbuf, 8))
    # Find variable
    sh.li(T0, varcount)
    sh.emit(rvasm.ld(T1, T0, 0))
    sh.emit(rvasm.addi(rvlib.S7, T1, 0))  # S7 = var count (saved)
    sh.li(rvlib.S8, 0)  # S8 = index (saved)
    sh.label("unset_find")
    sh.bge(rvlib.S8, rvlib.S7, "loop")  # Not found
    # Compare varnames[S8] with S6
    sh.li(T2, varnames)
    sh.emit(rvasm.slli(T3, rvlib.S8, 5))
    sh.emit(rvasm.add(T2, T2, T3))
    sh.emit(rvasm.addi(A0, rvlib.S6, 0))  # A0 = var name
    sh.emit(rvasm.addi(A1, T2, 0))  # A1 = &varnames[S8]
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "unset_found")
    sh.emit(rvasm.addi(rvlib.S8, rvlib.S8, 1))
    sh.jal(rvlib.ZERO, "unset_find")

    # Found - remove by clearing the variable name
    sh.label("unset_found")
    # Decrement count first
    sh.li(T0, varcount)
    sh.emit(rvasm.ld(T1, T0, 0))
    sh.emit(rvasm.addi(T1, T1, -1))
    sh.emit(rvasm.sd(T1, T0, 0))
    # Clear the variable name (set first byte to 0)
    sh.li(T2, varnames)
    sh.emit(rvasm.slli(T3, rvlib.S8, 5))
    sh.emit(rvasm.add(T2, T2, T3))
    sh.emit(rvasm.sb(rvlib.ZERO, T2, 0))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_export")
    sh.jal(rvlib.ZERO, "do_set")

    sh.label("do_mkdir")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "mkdir_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    rvlib.sys_mkdir_reg(sh, path_reg=A0)
    sh.blt(A0, rvlib.ZERO, "mkdir_fail")
    sh.jal(rvlib.ZERO, "loop")
    sh.label("mkdir_usage")
    rvlib.sys_write(sh, fd=1, buf=mkdir_usage, count=len(b"usage: mkdir <path>\n"))
    sh.jal(rvlib.ZERO, "loop")
    sh.label("mkdir_fail")
    rvlib.sys_write(sh, fd=1, buf=mkdir_fail, count=len(b"mkdir failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_rm")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "rm_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    rvlib.sys_unlink_reg(sh, path_reg=A0)
    sh.blt(A0, rvlib.ZERO, "rm_fail")
    sh.jal(rvlib.ZERO, "loop")
    sh.label("rm_usage")
    rvlib.sys_write(sh, fd=1, buf=rm_usage, count=len(b"usage: rm <path>\n"))
    sh.jal(rvlib.ZERO, "loop")
    sh.label("rm_fail")
    rvlib.sys_write(sh, fd=1, buf=rm_fail, count=len(b"rm failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_mv")
    sh.li(T0, 3)
    sh.blt(reg_tok_count, T0, "mv_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.emit(rvasm.ld(A1, reg_argvbuf, 16))
    rvlib.sys_rename_reg(sh, old_reg=A0, new_reg=A1)
    sh.blt(A0, rvlib.ZERO, "mv_fail")
    sh.jal(rvlib.ZERO, "loop")
    sh.label("mv_usage")
    rvlib.sys_write(sh, fd=1, buf=mv_usage, count=len(b"usage: mv <old> <new>\n"))
    sh.jal(rvlib.ZERO, "loop")
    sh.label("mv_fail")
    rvlib.sys_write(sh, fd=1, buf=mv_fail, count=len(b"mv failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_touch")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "touch_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    rvlib.sys_open_reg(sh, path_reg=A0, flags=1)
    sh.blt(A0, rvlib.ZERO, "touch_fail")
    rvlib.sys_close(sh, fd_reg=A0)
    sh.jal(rvlib.ZERO, "loop")
    sh.label("touch_usage")
    rvlib.sys_write(sh, fd=1, buf=touch_usage, count=len(b"usage: touch <file>\n"))
    sh.jal(rvlib.ZERO, "loop")
    sh.label("touch_fail")
    rvlib.sys_write(sh, fd=1, buf=touch_fail, count=len(b"touch failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_sleep")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "sleep_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.jal(rvlib.RA, "atoi")
    sh.beq(A1, rvlib.ZERO, "sleep_usage")
    rvlib.sys_sleep(sh, ms_reg=A0)
    sh.jal(rvlib.ZERO, "loop")
    sh.label("sleep_usage")
    rvlib.sys_write(sh, fd=1, buf=sleep_usage, count=len(b"usage: sleep <ms>\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_stat")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "stat_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.li(A1, statbuf)
    rvlib.sys_stat_reg(sh, path_reg=A0, stat_reg=A1)
    sh.blt(A0, rvlib.ZERO, "stat_fail")

    rvlib.sys_write(sh, fd=1, buf=stat_type, count=len(b"type: "))
    sh.li(T2, statbuf)
    sh.emit(rvasm.lw(T0, T2, 0))  # mode
    sh.emit(rvasm.andi(T1, T0, 2))
    sh.beq(T1, rvlib.ZERO, "stat_type_file")
    rvlib.sys_write(sh, fd=1, buf=stat_dir, count=len(b"dir\n"))
    sh.jal(rvlib.ZERO, "stat_type_done")
    sh.label("stat_type_file")
    rvlib.sys_write(sh, fd=1, buf=stat_file, count=len(b"file\n"))
    sh.label("stat_type_done")

    rvlib.sys_write(sh, fd=1, buf=stat_inum, count=len(b"inum: "))
    sh.emit(rvasm.lw(A0, T2, 4))
    sh.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)

    rvlib.sys_write(sh, fd=1, buf=stat_size, count=len(b"size: "))
    sh.emit(rvasm.ld(A0, T2, 8))
    sh.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "loop")
    sh.label("stat_usage")
    rvlib.sys_write(sh, fd=1, buf=stat_usage, count=len(b"usage: stat <path>\n"))
    sh.jal(rvlib.ZERO, "loop")
    sh.label("stat_fail")
    rvlib.sys_write(sh, fd=1, buf=stat_fail, count=len(b"stat failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_pid")
    rvlib.sys_getpid(sh)
    sh.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_ppid")
    rvlib.sys_getppid(sh)
    sh.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_cat")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "cat_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    rvlib.sys_open_ro_reg(sh, path_reg=A0)
    sh.blt(A0, rvlib.ZERO, "open_failed")
    sh.emit(rvasm.addi(S6, A0, 0))
    sh.label("cat_read")
    rvlib.sys_read_reg_reg_cnt(sh, fd_reg=S6, buf_reg=iobuf_reg, count=256)
    sh.beq(A0, rvlib.ZERO, "cat_close")
    sh.blt(A0, rvlib.ZERO, "read_failed")
    sh.emit(rvasm.addi(T2, A0, 0))
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=iobuf_reg, count_reg=T2)
    sh.jal(rvlib.ZERO, "cat_read")
    sh.label("cat_close")
    rvlib.sys_close(sh, fd_reg=S6)
    sh.jal(rvlib.ZERO, "loop")
    sh.label("cat_usage")
    rvlib.sys_write(sh, fd=1, buf=catusage, count=len(b"usage: cat <file>\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_ls")
    sh.li(T0, 1)
    sh.beq(reg_tok_count, T0, "ls_root")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "ls_usage")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.jal(rvlib.ZERO, "ls_open")
    sh.label("ls_root")
    sh.li(A0, dotpath)
    sh.label("ls_open")
    rvlib.sys_open_ro_reg(sh, path_reg=A0)
    sh.blt(A0, rvlib.ZERO, "open_failed")
    sh.emit(rvasm.addi(S6, A0, 0))
    sh.label("ls_read")
    rvlib.sys_read_reg_reg_cnt(sh, fd_reg=S6, buf_reg=direntbuf_reg, count=64)
    sh.li(T0, 64)
    sh.blt(A0, T0, "ls_close")
    sh.emit(rvasm.lbu(T1, direntbuf_reg, 0))
    sh.beq(T1, rvlib.ZERO, "ls_read")
    sh.emit(rvasm.addi(A0, direntbuf_reg, 0))
    sh.jal(rvlib.RA, "strlen")
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=direntbuf_reg, count_reg=A0)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "ls_read")
    sh.label("ls_close")
    rvlib.sys_close(sh, fd_reg=S6)
    sh.jal(rvlib.ZERO, "loop")
    sh.label("ls_usage")
    rvlib.sys_write(sh, fd=1, buf=lsusage, count=len(b"usage: ls [dir]\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_cd")
    sh.li(T0, 1)
    sh.beq(reg_tok_count, T0, "cd_root")
    sh.li(T0, 2)
    sh.blt(reg_tok_count, T0, "cd_root")
    sh.emit(rvasm.ld(A0, reg_argvbuf, 8))
    sh.jal(rvlib.ZERO, "cd_call")
    sh.label("cd_root")
    sh.li(A0, rootpath)
    sh.label("cd_call")
    rvlib.sys_chdir_reg(sh, path_reg=A0)
    sh.jal(rvlib.ZERO, "loop")

    sh.label("do_pwd")
    rvlib.sys_getcwd_reg_cnt(sh, buf_reg=cwdbuf_reg, size=128)
    sh.emit(rvasm.addi(A0, cwdbuf_reg, 0))
    sh.jal(rvlib.RA, "strlen")
    rvlib.sys_write_fd_reg_reg(sh, fd=1, buf_reg=cwdbuf_reg, count_reg=A0)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(rvlib.ZERO, "loop")

    sh.label("open_failed")
    rvlib.sys_write(sh, fd=1, buf=openfail, count=len(b"open failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("read_failed")
    rvlib.sys_write(sh, fd=1, buf=readfail, count=len(b"read failed\n"))
    sh.jal(rvlib.ZERO, "cat_close")

def _gen_sh_exec(
    sh: Program,
    *,
    stageargvbuf: int,
    stagepathbuf: int,
    pipebuf_reg: int,
    statusbuf: int,
    reg_status_addr: int,
    redirmeta_reg: int,
    argvbuf: int,
    pathbufs: int,
    binprefix_reg: int,
    execfail: int,
    ex_enoent: int,
    ex_eacces: int,
    ex_einval: int,
    ex_efault: int,
    ex_enomem: int,
    openfail: int,
    cmd_exit: int,
    cmd_help: int,
    cmd_echo: int,
    cmd_cat: int,
    cmd_ls: int,
    cmd_cd: int,
    cmd_pwd: int,
    cmd_status: int,
    cmd_set: int,
    cmd_unset: int,
    cmd_export: int,
    cmd_mkdir: int,
    cmd_rm: int,
    cmd_mv: int,
    cmd_touch: int,
    cmd_stat: int,
    cmd_sleep: int,
    cmd_pid: int,
    cmd_ppid: int,
    reg_prev_pipe_read: int,
    reg_last_status: int,
    reg_current_stage: int,
    reg_stage_count: int,
) -> None:
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
    rvlib.sys_pipe_reg(sh, pipefd_reg=pipebuf_reg)
    sh.emit(rvasm.ld(T0, pipebuf_reg, 0))
    sh.emit(rvasm.ld(T1, pipebuf_reg, 8))
    sh.jal(rvlib.ZERO, "pipe_have_pipe")

    sh.label("pipe_last_stage")
    sh.li(T0, -1)
    sh.li(T1, -1)

    sh.label("pipe_have_pipe")
    rvlib.sys_fork(sh)
    sh.beq(A0, rvlib.ZERO, "pipe_child")

    sh.blt(REG_PREV_PIPE_READ, rvlib.ZERO, "pipe_parent_no_prev")
    rvlib.sys_close(sh, fd_reg=REG_PREV_PIPE_READ)
    sh.label("pipe_parent_no_prev")
    sh.blt(T1, rvlib.ZERO, "pipe_parent_no_w")
    rvlib.sys_close(sh, fd_reg=T1)
    sh.label("pipe_parent_no_w")
    sh.emit(rvasm.addi(REG_PREV_PIPE_READ, T0, 0))
    sh.emit(rvasm.addi(REG_CURRENT_STAGE, REG_CURRENT_STAGE, 1))
    sh.jal(rvlib.ZERO, "pipe_exec_loop")

    sh.label("pipe_child")
    sh.blt(REG_PREV_PIPE_READ, rvlib.ZERO, "pipe_child_no_prev")
    rvlib.sys_dup2(sh, oldfd_reg=REG_PREV_PIPE_READ, newfd=0)
    rvlib.sys_close(sh, fd_reg=REG_PREV_PIPE_READ)
    sh.label("pipe_child_no_prev")
    sh.blt(T1, rvlib.ZERO, "pipe_child_no_w")
    rvlib.sys_dup2(sh, oldfd_reg=T1, newfd=1)
    sh.label("pipe_child_no_w")
    sh.blt(T0, rvlib.ZERO, "pipe_child_no_r")
    rvlib.sys_close(sh, fd_reg=T0)
    sh.label("pipe_child_no_r")
    sh.blt(T1, rvlib.ZERO, "pipe_child_no_close_w")
    rvlib.sys_close(sh, fd_reg=T1)
    sh.label("pipe_child_no_close_w")

    sh.emit(rvasm.addi(T4, REG_STAGE_COUNT, -1))
    sh.bne(REG_CURRENT_STAGE, T4, "pipe_child_skip_redir")
    sh.emit(rvasm.ld(T5, redirmeta_reg, 0))
    sh.beq(T5, rvlib.ZERO, "pipe_child_skip_redir")
    sh.emit(rvasm.ld(A0, redirmeta_reg, 8))
    sh.li(T4, 2)
    sh.beq(T5, T4, "redir_open_append")
    rvlib.sys_open_create_trunc_reg(sh, path_reg=A0)
    sh.jal(rvlib.ZERO, "redir_open_done")
    sh.label("redir_open_append")
    rvlib.sys_open_append_reg(sh, path_reg=A0, create=True)
    sh.label("redir_open_done")
    sh.li(T5, 0)
    sh.blt(A0, T5, "redir_open_failed")
    sh.emit(rvasm.addi(T5, A0, 0))
    rvlib.sys_dup2(sh, oldfd_reg=T5, newfd=1)
    rvlib.sys_close(sh, fd_reg=T5)

    sh.label("pipe_child_skip_redir")
    # Determine path and argv for this stage
    sh.li(A3, stagepathbuf)
    sh.emit(rvasm.slli(T2, REG_CURRENT_STAGE, 3))
    sh.emit(rvasm.add(T2, A3, T2))
    sh.emit(rvasm.ld(A0, T2, 0)) # A0 = path
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T2, REG_CURRENT_STAGE, 3))
    sh.emit(rvasm.add(T2, A3, T2))
    sh.emit(rvasm.ld(A1, T2, 0)) # A1 = argv
    rvlib.sys_execve_reg(sh, path_reg=A0, argv_reg=A1)
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    rvlib.sys_exit(sh, 1)

    sh.label("pipe_exec_done")
    sh.blt(REG_PREV_PIPE_READ, rvlib.ZERO, "pipe_close_prev_done")
    rvlib.sys_close(sh, fd_reg=REG_PREV_PIPE_READ)
    sh.label("pipe_close_prev_done")

    sh.emit(rvasm.addi(T0, REG_STAGE_COUNT, 0))
    sh.label("pipe_wait_loop")
    sh.beq(T0, rvlib.ZERO, "pipe_wait_done")
    sh.li(T2, -1)
    rvlib.sys_waitpid(sh, child_pid_reg=T2, status_addr=statusbuf)
    sh.li(T1, -11) # ECHILD
    sh.beq(A0, T1, "pipe_wait_loop")
    sh.emit(rvasm.ld(reg_last_status, reg_status_addr, 0))
    sh.emit(rvasm.addi(T0, T0, -1))
    sh.jal(rvlib.ZERO, "pipe_wait_loop")
    sh.label("pipe_wait_done")
    sh.jal(rvlib.ZERO, "loop")

    sh.label("pipe_syntax_multi")
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("no_pipe")

    sh.emit(rvasm.ld(T0, redirmeta_reg, 0))
    sh.bne(T0, rvlib.ZERO, "external_dispatch")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_exit)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_exit")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_help)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_help")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_echo)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_echo")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_cat)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_cat")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_ls)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_ls")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_cd)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_cd")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_pwd)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_pwd")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_status)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_status")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_set)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_set")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_unset)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_unset")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_export)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_export")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_mkdir)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_mkdir")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_rm)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_rm")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_mv)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_mv")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_touch)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_touch")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_stat)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_stat")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_sleep)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_sleep")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_pid)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_pid")

    sh.emit(rvasm.addi(A0, S5, 0))
    sh.li(A1, cmd_ppid)
    sh.jal(rvlib.RA, "strcmp")
    sh.beq(A0, rvlib.ZERO, "do_ppid")

    sh.label("external_dispatch")

    # If command contains '/', treat it as a path (absolute or relative).
    sh.li(T0, 0)
    sh.label("scan_slash")
    sh.emit(rvasm.add(A0, S5, T0))
    sh.emit(rvasm.lbu(T1, A0, 0))
    sh.beq(T1, rvlib.ZERO, "no_slash")
    sh.li(T2, 47)
    sh.beq(T1, T2, "has_slash")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(rvlib.ZERO, "scan_slash")

    sh.label("has_slash")
    sh.emit(rvasm.addi(S6, S5, 0))
    sh.jal(rvlib.ZERO, "run_cmd")

    sh.label("no_slash")
    sh.li(T0, 0)
    sh.label("cpy_pre")
    sh.emit(rvasm.add(T1, binprefix_reg, T0))
    sh.emit(rvasm.lbu(T2, T1, 0))
    sh.emit(rvasm.add(T1, S2, T0))
    sh.emit(rvasm.sb(T2, T1, 0))
    sh.beq(T2, rvlib.ZERO, "cpy_pre_done")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(rvlib.ZERO, "cpy_pre")

    sh.label("cpy_pre_done")
    sh.emit(rvasm.addi(T0, T0, -1))
    sh.li(T1, 0)
    sh.label("cpy_cmd")
    sh.emit(rvasm.add(A0, S5, T1))
    sh.emit(rvasm.lbu(T2, A0, 0))
    sh.emit(rvasm.add(A0, S2, T0))
    sh.emit(rvasm.sb(T2, A0, 0))
    sh.beq(T2, rvlib.ZERO, "path_ready")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.jal(rvlib.ZERO, "cpy_cmd")

    sh.label("path_ready")
    sh.emit(rvasm.addi(S6, S2, 0))

    sh.label("run_cmd")
    rvlib.sys_fork(sh)
    sh.beq(A0, rvlib.ZERO, "child")
    sh.emit(rvasm.addi(T0, A0, 0))

    sh.label("wait_loop")
    rvlib.sys_waitpid(sh, child_pid_reg=T0, status_addr=statusbuf)
    sh.li(T1, -11)
    sh.beq(A0, T1, "wait_loop")
    sh.emit(rvasm.ld(reg_last_status, reg_status_addr, 0))
    sh.jal(rvlib.ZERO, "loop")

    sh.label("child")
    sh.emit(rvasm.ld(T0, redirmeta_reg, 0))
    sh.beq(T0, rvlib.ZERO, "child_execve")
    sh.emit(rvasm.ld(A0, redirmeta_reg, 8))
    sh.li(T2, 2)
    sh.beq(T0, T2, "child_open_append")
    rvlib.sys_open_create_trunc_reg(sh, path_reg=A0)
    sh.jal(rvlib.ZERO, "child_open_done")
    sh.label("child_open_append")
    rvlib.sys_open_append_reg(sh, path_reg=A0, create=True)
    sh.label("child_open_done")
    sh.blt(A0, rvlib.ZERO, "redir_open_failed")
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
    sh.jal(rvlib.ZERO, "ex_msg_done")

    sh.label("ex_msg_enoent")
    rvlib.sys_write(sh, fd=1, buf=ex_enoent, count=len(b"execve: not found\n"))
    sh.jal(rvlib.ZERO, "ex_msg_done")
    sh.label("ex_msg_eacces")
    rvlib.sys_write(sh, fd=1, buf=ex_eacces, count=len(b"execve: access denied\n"))
    sh.jal(rvlib.ZERO, "ex_msg_done")
    sh.label("ex_msg_einval")
    rvlib.sys_write(sh, fd=1, buf=ex_einval, count=len(b"execve: invalid\n"))
    sh.jal(rvlib.ZERO, "ex_msg_done")
    sh.label("ex_msg_efault")
    rvlib.sys_write(sh, fd=1, buf=ex_efault, count=len(b"execve: bad address\n"))
    sh.jal(rvlib.ZERO, "ex_msg_done")
    sh.label("ex_msg_enomem")
    rvlib.sys_write(sh, fd=1, buf=ex_enomem, count=len(b"execve: no memory\n"))

    sh.label("ex_msg_done")
    rvlib.sys_exit(sh, 1)

    sh.label("redir_open_failed")
    rvlib.sys_write(sh, fd=1, buf=openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(sh, 1)
