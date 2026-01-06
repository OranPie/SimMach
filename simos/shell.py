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


def _install_base_bins(fs: BetterFS) -> None:
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
    rvlib.sys_getcwd(p_pwd, buf_addr=pwd_buf, size=128)
    p_pwd.li(T0, 0)
    p_pwd.label("pwd_len")
    p_pwd.emit(rvasm.add(T1, S0, T0))
    p_pwd.emit(rvasm.lbu(T2, T1, 0))
    p_pwd.beq(T2, 0, "pwd_len_done")
    p_pwd.emit(rvasm.addi(T0, T0, 1))
    p_pwd.jal(0, "pwd_len")
    p_pwd.label("pwd_len_done")
    p_pwd.li(A0, 1)
    p_pwd.li(A1, pwd_buf)
    p_pwd.emit(rvasm.addi(A2, T0, 0))
    p_pwd.li(A7, int(Sysno.WRITE))
    rvlib.ecall(p_pwd)
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
    p_echo.emit(rvasm.addi(A1, 18, 0))
    p_echo.emit(rvasm.addi(A2, T1, 0))
    p_echo.li(A0, 1)
    p_echo.li(A7, int(Sysno.WRITE))
    rvlib.ecall(p_echo)
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
    p_cat.blt(rvlib.A0, rvlib.T0, "cat_usage")
    p_cat.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    p_cat.li(rvlib.A1, 0)
    p_cat.li(rvlib.A7, int(Sysno.OPEN))
    rvlib.ecall(p_cat)
    p_cat.blt(rvlib.A0, 0, "cat_openfail")
    p_cat.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_cat.label("cat_read")
    p_cat.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_cat.li(rvlib.A1, cat_buf)
    p_cat.li(rvlib.A2, 256)
    p_cat.li(rvlib.A7, int(Sysno.READ))
    rvlib.ecall(p_cat)
    p_cat.beq(rvlib.A0, 0, "cat_close_ok")
    p_cat.blt(rvlib.A0, 0, "cat_readfail")
    p_cat.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_cat.li(rvlib.A0, 1)
    p_cat.li(rvlib.A1, cat_buf)
    p_cat.emit(rvasm.addi(rvlib.A2, rvlib.T0, 0))
    p_cat.li(rvlib.A7, int(Sysno.WRITE))
    rvlib.ecall(p_cat)
    p_cat.jal(0, "cat_read")
    p_cat.label("cat_close_ok")
    p_cat.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_cat.li(rvlib.A7, int(Sysno.CLOSE))
    rvlib.ecall(p_cat)
    rvlib.sys_exit(p_cat, 0)
    p_cat.label("cat_usage")
    rvlib.sys_write(p_cat, fd=1, buf=cat_usage, count=len(b"usage: cat <file>\n"))
    rvlib.sys_exit(p_cat, 1)
    p_cat.label("cat_openfail")
    rvlib.sys_write(p_cat, fd=1, buf=cat_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_cat, 1)
    p_cat.label("cat_readfail")
    rvlib.sys_write(p_cat, fd=1, buf=cat_readfail, count=len(b"read failed\n"))
    p_cat.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_cat.li(rvlib.A7, int(Sysno.CLOSE))
    rvlib.ecall(p_cat)
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
    p_ls.li(rvlib.A1, 0)
    p_ls.li(rvlib.A7, int(Sysno.OPEN))
    rvlib.ecall(p_ls)
    p_ls.blt(rvlib.A0, 0, "ls_openfail")
    p_ls.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_ls.label("ls_read")
    p_ls.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_ls.li(rvlib.A1, ls_ent)
    p_ls.li(rvlib.A2, 64)
    p_ls.li(rvlib.A7, int(Sysno.READ))
    rvlib.ecall(p_ls)
    p_ls.li(rvlib.T0, 64)
    p_ls.blt(rvlib.A0, rvlib.T0, "ls_close")
    p_ls.emit(rvasm.lbu(rvlib.T1, rvlib.A1, 0))
    p_ls.beq(rvlib.T1, 0, "ls_read")
    p_ls.li(rvlib.T0, 0)
    p_ls.label("ls_strlen")
    p_ls.emit(rvasm.add(rvlib.T2, rvlib.A1, rvlib.T0))
    p_ls.emit(rvasm.lbu(rvlib.T2, rvlib.T2, 0))
    p_ls.beq(rvlib.T2, 0, "ls_print")
    p_ls.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_ls.jal(0, "ls_strlen")
    p_ls.label("ls_print")
    p_ls.li(rvlib.A0, 1)
    p_ls.li(rvlib.A7, int(Sysno.WRITE))
    p_ls.emit(rvasm.addi(rvlib.A2, rvlib.T0, 0))
    rvlib.ecall(p_ls)
    rvlib.sys_write(p_ls, fd=1, buf=ls_nl, count=1)
    p_ls.jal(0, "ls_read")
    p_ls.label("ls_close")
    p_ls.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_ls.li(rvlib.A7, int(Sysno.CLOSE))
    rvlib.ecall(p_ls)
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

    sh.label("_start")
    sh.li(S0, linebuf)
    sh.li(S1, argvbuf)
    sh.li(S2, pathbufs)
    sh.li(S3, statusbuf)
    sh.li(23, iobuf)
    sh.li(24, direntbuf)
    sh.li(25, cwdbuf)
    sh.li(26, 0)
    sh.li(27, binprefix)
    sh.li(28, pathbufs + 128)
    sh.li(29, pipebuf)

    sh.label("loop")
    rvlib.sys_write(sh, fd=1, buf=prompt, count=len(b"sh$ "))
    sh.li(A3, redirmeta)
    sh.emit(rvasm.sd(0, A3, 0))
    sh.emit(rvasm.sd(0, A3, 8))
    sh.li(14, 0)
    sh.li(15, 0)
    sh.label("rl_read_loop")
    sh.li(A0, 0)
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.li(A2, 1)
    sh.li(A7, int(Sysno.READ))
    rvlib.ecall(sh)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, 23, 0))

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
    sh.bge(15, T0, "rl_read_loop")
    sh.emit(rvasm.add(T2, S0, 15))
    sh.emit(rvasm.sb(T1, T2, 0))
    sh.emit(rvasm.addi(15, 15, 1))
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.li(A2, 1)
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    sh.jal(0, "rl_read_loop")

    sh.label("rl_backspace")
    sh.beq(15, 0, "rl_read_loop")
    sh.emit(rvasm.addi(15, 15, -1))
    rvlib.sys_write(sh, fd=1, buf=bsseq, count=3)
    sh.jal(0, "rl_read_loop")

    sh.label("rl_esc")
    sh.li(A0, 0)
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.li(A2, 1)
    sh.li(A7, int(Sysno.READ))
    rvlib.ecall(sh)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, 23, 0))
    sh.li(T0, 91)
    sh.bne(T1, T0, "rl_read_loop")
    sh.li(A0, 0)
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.li(A2, 1)
    sh.li(A7, int(Sysno.READ))
    rvlib.ecall(sh)
    sh.li(T0, 1)
    sh.blt(A0, T0, "rl_read_loop")
    sh.emit(rvasm.lbu(T1, 23, 0))
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
    sh.bge(14, T1, "rl_hist_load")
    sh.emit(rvasm.addi(14, 14, 1))
    sh.label("rl_hist_load")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T2, A3, 8))
    sh.emit(rvasm.addi(T2, T2, -1))
    sh.emit(rvasm.sub(T2, T2, 14))
    sh.li(T1, 0)
    sh.bge(T2, T1, "rl_hist_idx_ok")
    sh.emit(rvasm.addi(T2, T2, 8))
    sh.label("rl_hist_idx_ok")
    sh.emit(rvasm.slli(T1, T2, 3))
    sh.li(A3, histlens)
    sh.emit(rvasm.add(T1, A3, T1))
    sh.emit(rvasm.ld(T1, T1, 0))
    sh.emit(rvasm.addi(15, T1, 0))
    sh.emit(rvasm.slli(T0, T2, 8))
    sh.li(A3, histbuf)
    sh.emit(rvasm.add(T0, A3, T0))
    sh.li(T1, 0)
    sh.label("rl_hist_cpy")
    sh.beq(T1, 15, "rl_hist_cpy_done")
    sh.emit(rvasm.add(A0, T0, T1))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.emit(rvasm.add(A0, S0, T1))
    sh.emit(rvasm.sb(A1, A0, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.jal(0, "rl_hist_cpy")
    sh.label("rl_hist_cpy_done")
    sh.emit(rvasm.add(T0, S0, 15))
    sh.emit(rvasm.sb(0, T0, 0))
    sh.jal(1, "rl_redraw")

    sh.label("rl_hist_down")
    sh.li(A3, histmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, 0, "rl_read_loop")
    sh.beq(14, 0, "rl_hist_clear")
    sh.emit(rvasm.addi(14, 14, -1))
    sh.jal(0, "rl_hist_load")
    sh.label("rl_hist_clear")
    sh.li(15, 0)
    sh.emit(rvasm.sb(0, S0, 0))
    sh.jal(1, "rl_redraw")

    sh.label("rl_redraw")
    rvlib.sys_write(sh, fd=1, buf=cr, count=1)
    rvlib.sys_write(sh, fd=1, buf=prompt, count=len(b"sh$ "))
    rvlib.sys_write(sh, fd=1, buf=clreol, count=3)
    sh.beq(15, 0, "rl_redraw_done")
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, S0, 0))
    sh.emit(rvasm.addi(A2, 15, 0))
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    sh.label("rl_redraw_done")
    sh.jalr(0, 1, 0)

    sh.label("rl_enter")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.emit(rvasm.add(T0, S0, 15))
    sh.li(T1, 10)
    sh.emit(rvasm.sb(T1, T0, 0))
    sh.emit(rvasm.addi(15, 15, 1))
    sh.emit(rvasm.add(T0, S0, 15))
    sh.emit(rvasm.sb(0, T0, 0))
    sh.emit(rvasm.addi(A0, 15, 0))
    sh.li(T0, 1)
    sh.blt(A0, T0, "loop")

    sh.emit(rvasm.addi(T2, 15, -1))
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

    sh.li(S4, 0)
    sh.emit(rvasm.addi(T0, S0, 0))

    sh.label("parse_skip")
    sh.emit(rvasm.lbu(T1, T0, 0))
    sh.beq(T1, 0, "parse_done")
    sh.li(T2, 10)
    sh.beq(T1, T2, "parse_nl")
    sh.li(T2, 32)
    sh.bne(T1, T2, "parse_tok")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "parse_skip")

    sh.label("parse_nl")
    sh.emit(rvasm.sb(0, T0, 0))
    sh.jal(0, "parse_done")

    sh.label("parse_tok")
    sh.emit(rvasm.slli(T2, S4, 3))
    sh.emit(rvasm.add(T2, S1, T2))
    sh.emit(rvasm.sd(T0, T2, 0))
    sh.emit(rvasm.addi(S4, S4, 1))

    sh.label("scan_tok")
    sh.emit(rvasm.lbu(T1, T0, 0))
    sh.beq(T1, 0, "parse_done")
    sh.li(T2, 10)
    sh.beq(T1, T2, "scan_nl")
    sh.li(T2, 32)
    sh.beq(T1, T2, "scan_sp")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "scan_tok")

    sh.label("scan_sp")
    sh.emit(rvasm.sb(0, T0, 0))
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "parse_skip")

    sh.label("scan_nl")
    sh.emit(rvasm.sb(0, T0, 0))
    sh.jal(0, "parse_done")

    sh.label("parse_done")
    sh.emit(rvasm.slli(T2, S4, 3))
    sh.emit(rvasm.add(T2, S1, T2))
    sh.emit(rvasm.sd(0, T2, 0))
    sh.beq(S4, 0, "loop")

    sh.emit(rvasm.ld(S5, S1, 0))

    # Output redirection: detect a single '>' token (must be space-separated).
    sh.li(T0, 0)
    sh.li(14, -1)
    sh.label("scan_redir")
    sh.beq(T0, S4, "redir_scan_done")
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, S1, T1))
    sh.emit(rvasm.ld(A0, T1, 0))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.li(A2, 62)
    sh.bne(A1, A2, "redir_next")
    sh.emit(rvasm.lbu(A1, A0, 1))
    sh.bne(A1, 0, "redir_next")
    sh.emit(rvasm.addi(14, T0, 0))
    sh.jal(0, "redir_scan_done")
    sh.label("redir_next")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "scan_redir")
    sh.label("redir_scan_done")
    sh.blt(14, 0, "redir_done")
    sh.beq(14, 0, "redir_syntax")
    sh.emit(rvasm.addi(T0, S4, -1))
    sh.beq(14, T0, "redir_syntax")

    # Split argv in-place: argv[redir_idx] = 0; save path=argv[redir_idx+1] in redirmeta.
    sh.emit(rvasm.addi(T2, 14, 0))
    sh.emit(rvasm.slli(T1, 14, 3))
    sh.emit(rvasm.add(T1, S1, T1))
    sh.emit(rvasm.sd(0, T1, 0))
    sh.emit(rvasm.addi(14, 14, 1))
    sh.emit(rvasm.slli(T1, 14, 3))
    sh.emit(rvasm.add(T1, S1, T1))
    sh.emit(rvasm.ld(A0, T1, 0))
    sh.li(A3, redirmeta)
    sh.li(T0, 1)
    sh.emit(rvasm.sd(T0, A3, 0))
    sh.emit(rvasm.sd(A0, A3, 8))
    sh.emit(rvasm.addi(S4, T2, 0))
    sh.jal(0, "redir_done")

    sh.label("redir_syntax")
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    sh.jal(0, "loop")

    sh.label("redir_done")

    # Pipeline support: multi-stage 'a | b | c' (must be space-separated).
    sh.li(16, 1)
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.sd(S1, A3, 0))
    sh.li(T0, 0)
    sh.label("scan_pipe_multi")
    sh.beq(T0, S4, "scan_pipe_multi_done")
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, S1, T1))
    sh.emit(rvasm.ld(A0, T1, 0))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.li(A2, 124)
    sh.bne(A1, A2, "scan_pipe_multi_next")
    sh.emit(rvasm.lbu(A1, A0, 1))
    sh.bne(A1, 0, "scan_pipe_multi_next")
    sh.beq(T0, 0, "pipe_syntax_multi")
    sh.emit(rvasm.addi(T2, S4, -1))
    sh.beq(T0, T2, "pipe_syntax_multi")
    sh.emit(rvasm.addi(T2, T0, 1))
    sh.emit(rvasm.slli(T3, T2, 3))
    sh.emit(rvasm.add(T3, S1, T3))
    sh.emit(rvasm.ld(A0, T3, 0))
    sh.emit(rvasm.lbu(A1, A0, 0))
    sh.li(A2, 124)
    sh.bne(A1, A2, "pipe_tok_ok")
    sh.emit(rvasm.lbu(A1, A0, 1))
    sh.beq(A1, 0, "pipe_syntax_multi")
    sh.label("pipe_tok_ok")

    sh.emit(rvasm.sd(0, T1, 0))
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T4, 16, 3))
    sh.emit(rvasm.add(T4, A3, T4))
    sh.emit(rvasm.sd(T3, T4, 0))
    sh.emit(rvasm.addi(16, 16, 1))
    sh.li(T5, 4)
    sh.blt(16, T5, "scan_pipe_multi_next")
    sh.jal(0, "pipe_syntax_multi")

    sh.label("scan_pipe_multi_next")
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "scan_pipe_multi")
    sh.label("scan_pipe_multi_done")
    sh.li(T0, 2)
    sh.blt(16, T0, "no_pipe")

    sh.li(T0, 0)
    sh.label("build_stage_paths")
    sh.beq(T0, 16, "build_stage_paths_done")
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, A3, T1))
    sh.emit(rvasm.ld(T2, T1, 0))
    sh.emit(rvasm.ld(A3, T2, 0))

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
    sh.emit(rvasm.slli(T4, T0, 7))
    sh.emit(rvasm.add(T4, S2, T4))
    sh.li(T5, 0)
    sh.label("bp_cpy_pre")
    sh.emit(rvasm.add(T1, 27, T5))
    sh.emit(rvasm.lbu(T2, T1, 0))
    sh.emit(rvasm.add(T1, T4, T5))
    sh.emit(rvasm.sb(T2, T1, 0))
    sh.beq(T2, 0, "bp_cpy_pre_done")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.jal(0, "bp_cpy_pre")
    sh.label("bp_cpy_pre_done")
    sh.emit(rvasm.addi(T5, T5, -1))
    sh.li(T1, 0)
    sh.label("bp_cpy_cmd")
    sh.emit(rvasm.add(A0, A3, T1))
    sh.emit(rvasm.lbu(T2, A0, 0))
    sh.emit(rvasm.add(A0, T4, T5))
    sh.emit(rvasm.sb(T2, A0, 0))
    sh.beq(T2, 0, "bp_path_done")
    sh.emit(rvasm.addi(T5, T5, 1))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.jal(0, "bp_cpy_cmd")

    sh.label("bp_path_done")
    sh.li(A3, stagepathbuf)
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, A3, T1))
    sh.emit(rvasm.sd(T4, T1, 0))
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.jal(0, "build_stage_paths")

    sh.label("build_stage_paths_done")

    sh.li(30, -1)
    sh.li(15, 0)
    sh.label("pipe_exec_loop")
    sh.beq(15, 16, "pipe_exec_done")
    sh.emit(rvasm.addi(T4, 16, -1))
    sh.beq(15, T4, "pipe_last_stage")
    rvlib.sys_pipe(sh, pipefd_addr=pipebuf)
    sh.emit(rvasm.ld(T0, 29, 0))
    sh.emit(rvasm.ld(T1, 29, 8))
    sh.jal(0, "pipe_have_pipe")

    sh.label("pipe_last_stage")
    sh.li(T0, -1)
    sh.li(T1, -1)

    sh.label("pipe_have_pipe")
    rvlib.sys_fork(sh)
    sh.beq(A0, 0, "pipe_child")

    sh.blt(30, 0, "pipe_parent_no_prev")
    rvlib.sys_close(sh, fd_reg=30)
    sh.label("pipe_parent_no_prev")
    sh.blt(T1, 0, "pipe_parent_no_w")
    rvlib.sys_close(sh, fd_reg=T1)
    sh.label("pipe_parent_no_w")
    sh.emit(rvasm.addi(30, T0, 0))
    sh.emit(rvasm.addi(15, 15, 1))
    sh.jal(0, "pipe_exec_loop")

    sh.label("pipe_child")
    sh.blt(30, 0, "pipe_child_no_prev")
    rvlib.sys_dup2(sh, oldfd_reg=30, newfd=0)
    rvlib.sys_close(sh, fd_reg=30)
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

    sh.emit(rvasm.addi(T4, 16, -1))
    sh.bne(15, T4, "pipe_child_skip_redir")
    sh.li(A3, redirmeta)
    sh.emit(rvasm.ld(T5, A3, 0))
    sh.beq(T5, 0, "pipe_child_skip_redir")
    sh.emit(rvasm.ld(A0, A3, 8))
    sh.li(A1, int(O_CREAT | O_TRUNC))
    sh.li(A7, int(Sysno.OPEN))
    rvlib.ecall(sh)
    sh.li(T5, 0)
    sh.blt(A0, T5, "redir_open_failed")
    sh.emit(rvasm.addi(T5, A0, 0))
    rvlib.sys_dup2(sh, oldfd_reg=T5, newfd=1)
    rvlib.sys_close(sh, fd_reg=T5)

    sh.label("pipe_child_skip_redir")
    sh.li(A3, stagepathbuf)
    sh.emit(rvasm.slli(T2, 15, 3))
    sh.emit(rvasm.add(T2, A3, T2))
    sh.emit(rvasm.ld(A0, T2, 0))
    sh.li(A3, stageargvbuf)
    sh.emit(rvasm.slli(T2, 15, 3))
    sh.emit(rvasm.add(T2, A3, T2))
    sh.emit(rvasm.ld(A1, T2, 0))
    sh.li(A2, 0)
    sh.li(A7, int(Sysno.EXECVE))
    rvlib.ecall(sh)
    rvlib.sys_write(sh, fd=1, buf=execfail, count=len(b"execve: failed\n"))
    rvlib.sys_exit(sh, 1)

    sh.label("pipe_exec_done")
    sh.blt(30, 0, "pipe_close_prev_done")
    rvlib.sys_close(sh, fd_reg=30)
    sh.label("pipe_close_prev_done")

    sh.emit(rvasm.addi(T0, 16, 0))
    sh.label("pipe_wait_loop")
    sh.beq(T0, 0, "pipe_wait_done")
    sh.li(T2, -1)
    rvlib.sys_waitpid(sh, child_pid_reg=T2, status_addr=statusbuf)
    sh.li(T1, -11)
    sh.beq(A0, T1, "pipe_wait_loop")
    sh.emit(rvasm.ld(26, S3, 0))
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
    sh.emit(rvasm.ld(26, S3, 0))
    sh.jal(0, "loop")

    sh.label("child")
    sh.li(A3, redirmeta)
    sh.emit(rvasm.ld(T0, A3, 0))
    sh.beq(T0, 0, "child_execve")
    sh.emit(rvasm.ld(A0, A3, 8))
    sh.li(A1, int(O_CREAT | O_TRUNC))
    sh.li(A7, int(Sysno.OPEN))
    rvlib.ecall(sh)
    sh.li(T1, 0)
    sh.blt(A0, T1, "redir_open_failed")
    sh.emit(rvasm.addi(T0, A0, 0))
    rvlib.sys_dup2(sh, oldfd_reg=T0, newfd=1)
    rvlib.sys_close(sh, fd_reg=T0)

    sh.label("child_execve")
    sh.emit(rvasm.addi(A0, S6, 0))
    sh.emit(rvasm.addi(A1, S1, 0))
    sh.li(A2, 0)
    sh.li(A7, int(Sysno.EXECVE))
    rvlib.ecall(sh)

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

    sh.label("do_exit")
    rvlib.sys_exit(sh, 0)

    sh.label("do_help")
    rvlib.sys_write(sh, fd=1, buf=helpmsg, count=len(b"builtins: help exit echo cat ls cd pwd status\n"))
    sh.jal(0, "loop")

    sh.label("do_echo")
    sh.li(T0, 1)
    sh.label("echo_loop")
    sh.bge(T0, S4, "echo_done")
    sh.emit(rvasm.slli(T1, T0, 3))
    sh.emit(rvasm.add(T1, S1, T1))
    sh.emit(rvasm.ld(A1, T1, 0))
    sh.emit(rvasm.addi(A0, A1, 0))
    sh.jal(1, "strlen")
    sh.emit(rvasm.addi(A2, A0, 0))
    sh.li(A0, 1)
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    sh.emit(rvasm.addi(T0, T0, 1))
    sh.bge(T0, S4, "echo_loop")
    rvlib.sys_write(sh, fd=1, buf=sp, count=1)
    sh.jal(0, "echo_loop")

    sh.label("echo_done")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "loop")

    sh.label("do_status")
    sh.emit(rvasm.addi(A0, 26, 0))
    sh.jal(1, "print_dec")
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "loop")

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
    sh.emit(rvasm.add(A1, 23, T1))
    sh.emit(rvasm.sb(A2, A1, 0))
    sh.emit(rvasm.addi(T1, T1, 1))
    sh.emit(rvasm.addi(T0, T2, 0))
    sh.jal(0, "pd_outer")
    sh.label("pd_zero")
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.li(A2, 48)
    sh.emit(rvasm.sb(A2, A1, 0))
    sh.li(T1, 1)
    sh.label("pd_done")
    sh.emit(rvasm.addi(T1, T1, -1))
    sh.blt(T1, 0, "pd_ret")
    sh.emit(rvasm.add(A1, 23, T1))
    sh.li(A0, 1)
    sh.li(A2, 1)
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    sh.jal(0, "pd_done")
    sh.label("pd_ret")
    sh.jalr(0, 1, 0)

    sh.label("do_cat")
    sh.li(T0, 2)
    sh.blt(S4, T0, "cat_usage")
    sh.emit(rvasm.ld(A0, S1, 8))
    sh.li(A1, 0)
    sh.li(A7, int(Sysno.OPEN))
    rvlib.ecall(sh)
    sh.blt(A0, 0, "open_failed")
    sh.emit(rvasm.addi(S6, A0, 0))
    sh.label("cat_read")
    sh.emit(rvasm.addi(A0, S6, 0))
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.li(A2, 256)
    sh.li(A7, int(Sysno.READ))
    rvlib.ecall(sh)
    sh.beq(A0, 0, "cat_close")
    sh.blt(A0, 0, "read_failed")
    sh.emit(rvasm.addi(T2, A0, 0))
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, 23, 0))
    sh.emit(rvasm.addi(A2, T2, 0))
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    sh.jal(0, "cat_read")

    sh.label("cat_close")
    sh.emit(rvasm.addi(A0, S6, 0))
    sh.li(A7, int(Sysno.CLOSE))
    rvlib.ecall(sh)
    sh.jal(0, "loop")

    sh.label("cat_usage")
    rvlib.sys_write(sh, fd=1, buf=catusage, count=len(b"usage: cat <file>\n"))
    sh.jal(0, "loop")

    sh.label("do_ls")
    sh.li(T0, 1)
    sh.beq(S4, T0, "ls_root")
    sh.li(T0, 2)
    sh.blt(S4, T0, "ls_usage")
    sh.emit(rvasm.ld(A0, S1, 8))
    sh.jal(0, "ls_open")

    sh.label("ls_root")
    sh.li(A0, dotpath)

    sh.label("ls_open")
    sh.li(A1, 0)
    sh.li(A7, int(Sysno.OPEN))
    rvlib.ecall(sh)
    sh.blt(A0, 0, "open_failed")
    sh.emit(rvasm.addi(S6, A0, 0))

    sh.label("ls_read")
    sh.emit(rvasm.addi(A0, S6, 0))
    sh.emit(rvasm.addi(A1, 24, 0))
    sh.li(A2, 64)
    sh.li(A7, int(Sysno.READ))
    rvlib.ecall(sh)
    sh.li(T0, 64)
    sh.blt(A0, T0, "ls_close")
    sh.emit(rvasm.lbu(T1, 24, 0))
    sh.beq(T1, 0, "ls_read")
    sh.emit(rvasm.addi(A0, 24, 0))
    sh.jal(1, "strlen")
    sh.emit(rvasm.addi(A2, A0, 0))
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, 24, 0))
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "ls_read")

    sh.label("ls_close")
    sh.emit(rvasm.addi(A0, S6, 0))
    sh.li(A7, int(Sysno.CLOSE))
    rvlib.ecall(sh)
    sh.jal(0, "loop")

    sh.label("ls_usage")
    rvlib.sys_write(sh, fd=1, buf=lsusage, count=len(b"usage: ls [dir]\n"))
    sh.jal(0, "loop")

    sh.label("do_cd")
    sh.li(T0, 1)
    sh.beq(S4, T0, "cd_root")
    sh.li(T0, 2)
    sh.blt(S4, T0, "cd_root")
    sh.emit(rvasm.ld(A0, S1, 8))
    sh.jal(0, "cd_call")

    sh.label("cd_root")
    sh.li(A0, rootpath)

    sh.label("cd_call")
    sh.li(A7, int(Sysno.CHDIR))
    rvlib.ecall(sh)
    sh.jal(0, "loop")

    sh.label("do_pwd")
    sh.emit(rvasm.addi(A0, 25, 0))
    sh.li(A1, 128)
    sh.li(A7, int(Sysno.GETCWD))
    rvlib.ecall(sh)
    sh.emit(rvasm.addi(A0, 25, 0))
    sh.jal(1, "strlen")
    sh.emit(rvasm.addi(A2, A0, 0))
    sh.li(A0, 1)
    sh.emit(rvasm.addi(A1, 25, 0))
    sh.li(A7, int(Sysno.WRITE))
    rvlib.ecall(sh)
    rvlib.sys_write(sh, fd=1, buf=nl, count=1)
    sh.jal(0, "loop")

    sh.label("open_failed")
    rvlib.sys_write(sh, fd=1, buf=openfail, count=len(b"open failed\n"))
    sh.jal(0, "loop")

    sh.label("read_failed")
    rvlib.sys_write(sh, fd=1, buf=readfail, count=len(b"read failed\n"))
    sh.jal(0, "cat_close")

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
    ino = env.fs.lookup(ap)
    if ino is None:
        print("cat: no such file")
        return
    if ino.is_dir:
        print("cat: is a directory")
        return
    data = env.fs.read_inode(ino, 0, int(ino.size_bytes))
    try:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
    except Exception:
        sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
        sys.stdout.write("\n")


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


def _cmd_mkdir(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        env.fs.mkdir(ap)
    except Exception as e:
        print(f"mkdir: {e}")


def _cmd_touch(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    ino = env.fs.lookup(ap)
    if ino is None:
        try:
            env.fs.create_file(ap)
        except Exception as e:
            print(f"touch: {e}")
            return


def _cmd_write(env: ShellEnv, path: str, text: str, *, append: bool) -> None:
    ap = _resolve_path(env, path)
    ino = env.fs.lookup(ap)
    if ino is None:
        try:
            ino = env.fs.create_file(ap)
        except Exception as e:
            print(f"write: {e}")
            return
    if ino.is_dir:
        print("write: is a directory")
        return
    data = text.encode("utf-8")
    off = int(ino.size_bytes) if append else 0
    try:
        env.fs.write_inode(ino, off, data, truncate=not append)
    except Exception as e:
        print(f"write: {e}")


def _cmd_hexdump(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    ino = env.fs.lookup(ap)
    if ino is None:
        print("hexdump: no such file")
        return
    if ino.is_dir:
        print("hexdump: is a directory")
        return
    data = env.fs.read_inode(ino, 0, int(ino.size_bytes))
    width = 16
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{i:08x}  {hx:<47}  |{asc}|")


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
