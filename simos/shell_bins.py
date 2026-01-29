from __future__ import annotations

from constants import O_CREAT, Sysno
from simmach import rvasm, rvlib
from simmach.fs import BetterFS
from simmach.rvprog import Program

from simos.shell_gen import _gen_sh_builtins, _gen_sh_exec, _gen_sh_line_editor, _gen_sh_parser, _gen_sh_utils

def _install_base_bins(fs: BetterFS) -> None:
    p_mkdir = Program(entry=0x1000_0000)
    mkdir_usage = p_mkdir.db(b"usage: mkdir <path>\n")
    p_mkdir.label("_start")
    p_mkdir.li(rvlib.T0, 2)
    p_mkdir.blt(rvlib.A0, rvlib.T0, "mkdir_usage")
    p_mkdir.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_mkdir_reg(p_mkdir, path_reg=rvlib.A0)
    p_mkdir.blt(rvlib.A0, rvlib.ZERO, "mkdir_fail")
    rvlib.sys_exit(p_mkdir, rvlib.ZERO)
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
    p_rm.blt(rvlib.A0, rvlib.ZERO, "rm_fail")
    rvlib.sys_exit(p_rm, rvlib.ZERO)
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
    p_mv.blt(rvlib.A0, rvlib.ZERO, "mv_fail")
    rvlib.sys_exit(p_mv, rvlib.ZERO)
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
    rvlib.sys_getcwd_reg_cnt(p_pwd, buf_reg=S0, size=128)
    p_pwd.li(T0, 0)
    p_pwd.label("pwd_len")
    p_pwd.emit(rvasm.add(T1, S0, T0))
    p_pwd.emit(rvasm.lbu(T2, T1, 0))
    p_pwd.beq(T2, rvlib.ZERO, "pwd_len_done")
    p_pwd.emit(rvasm.addi(T0, T0, 1))
    p_pwd.jal(rvlib.ZERO, "pwd_len")
    p_pwd.label("pwd_len_done")
    rvlib.sys_write_fd_reg_reg(p_pwd, fd=1, buf_reg=rvlib.S0, count_reg=rvlib.T0)
    rvlib.sys_write(p_pwd, fd=1, buf=pwd_nl, count=1)
    rvlib.sys_exit(p_pwd, rvlib.ZERO)
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
    p_echo.emit(rvasm.addi(rvlib.S2, A1, 0))
    p_echo.emit(rvasm.addi(T2, A1, 0))
    p_echo.li(T1, 0)
    p_echo.label("echo_strlen")
    p_echo.emit(rvasm.lbu(A2, T2, 0))
    p_echo.beq(A2, rvlib.ZERO, "echo_strlen_done")
    p_echo.emit(rvasm.addi(T2, T2, 1))
    p_echo.emit(rvasm.addi(T1, T1, 1))
    p_echo.jal(rvlib.ZERO, "echo_strlen")
    p_echo.label("echo_strlen_done")
    rvlib.sys_write_fd_reg_reg(p_echo, fd=1, buf_reg=rvlib.S2, count_reg=T1)
    p_echo.emit(rvasm.addi(T0, T0, 1))
    p_echo.bge(T0, rvlib.S0, "echo_done")
    rvlib.sys_write(p_echo, fd=1, buf=echo_sp, count=1)
    p_echo.jal(rvlib.ZERO, "echo_loop")
    p_echo.label("echo_done")
    rvlib.sys_write(p_echo, fd=1, buf=echo_nl, count=1)
    rvlib.sys_exit(p_echo, rvlib.ZERO)
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
    p_cat.blt(rvlib.A0, rvlib.ZERO, "cat_openfail")
    p_cat.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_cat.jal(rvlib.ZERO, "cat_read")

    p_cat.label("cat_stdin")
    p_cat.li(rvlib.S0, 0)
    p_cat.label("cat_read")
    p_cat.li(rvlib.A1, cat_buf)
    rvlib.sys_read_reg_reg_cnt(p_cat, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=256)
    p_cat.beq(rvlib.A0, rvlib.ZERO, "cat_close_ok")
    p_cat.blt(rvlib.A0, rvlib.ZERO, "cat_readfail")
    p_cat.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_cat.li(rvlib.A1, cat_buf)
    rvlib.sys_write_fd_reg_reg(p_cat, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.T0)
    p_cat.jal(rvlib.ZERO, "cat_read")
    p_cat.label("cat_close_ok")
    rvlib.sys_close(p_cat, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_cat, rvlib.ZERO)
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
    p_ls.jal(rvlib.ZERO, "ls_open")
    p_ls.label("ls_default")
    p_ls.li(rvlib.A0, dot)
    p_ls.label("ls_open")
    rvlib.sys_open_ro_reg(p_ls, path_reg=rvlib.A0)
    p_ls.blt(rvlib.A0, rvlib.ZERO, "ls_openfail")
    p_ls.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_ls.label("ls_read")
    p_ls.li(rvlib.A1, ls_ent)
    rvlib.sys_read_reg_reg_cnt(p_ls, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=64)
    p_ls.li(rvlib.T0, 64)
    p_ls.blt(rvlib.A0, rvlib.T0, "ls_close")
    p_ls.emit(rvasm.lbu(rvlib.T1, ls_ent, 0))
    p_ls.beq(rvlib.T1, rvlib.ZERO, "ls_read")
    p_ls.li(rvlib.T0, 0)
    p_ls.label("ls_strlen")
    p_ls.li(rvlib.T3, ls_ent)
    p_ls.emit(rvasm.add(rvlib.T2, rvlib.T3, rvlib.T0))
    p_ls.emit(rvasm.lbu(rvlib.T2, rvlib.T2, 0))
    p_ls.beq(rvlib.T2, rvlib.ZERO, "ls_print")
    p_ls.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_ls.jal(rvlib.ZERO, "ls_strlen")
    p_ls.label("ls_print")
    p_ls.li(rvlib.A1, ls_ent)
    rvlib.sys_write_fd_reg_reg(p_ls, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.T0)
    rvlib.sys_write(p_ls, fd=1, buf=ls_nl, count=1)
    p_ls.jal(rvlib.ZERO, "ls_read")
    p_ls.label("ls_close")
    rvlib.sys_close(p_ls, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_ls, rvlib.ZERO)
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
    p_touch.blt(rvlib.A0, rvlib.ZERO, "touch_openfail")
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
    p_cp.blt(rvlib.A0, rvlib.ZERO, "cp_openfail")
    p_cp.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))

    p_cp.emit(rvasm.ld(rvlib.A0, rvlib.A1, 16))
    rvlib.sys_open_create_trunc_reg(p_cp, path_reg=rvlib.A0)
    p_cp.blt(rvlib.A0, rvlib.ZERO, "cp_openfail2")
    p_cp.emit(rvasm.addi(rvlib.S1, rvlib.A0, 0))

    p_cp.label("cp_loop")
    p_cp.li(rvlib.A1, cp_buf)
    rvlib.sys_read_reg_reg_cnt(p_cp, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=256)
    p_cp.beq(rvlib.A0, rvlib.ZERO, "cp_done")
    p_cp.blt(rvlib.A0, rvlib.ZERO, "cp_readfail")
    p_cp.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))

    p_cp.li(rvlib.A1, cp_buf)
    rvlib.sys_write_reg(p_cp, fd_reg=rvlib.S1, buf_reg=rvlib.A1, count_reg=rvlib.T0)
    p_cp.blt(rvlib.A0, rvlib.ZERO, "cp_writefail")
    p_cp.jal(rvlib.ZERO, "cp_loop")

    p_cp.label("cp_done")
    rvlib.sys_close(p_cp, fd_reg=rvlib.S0)
    rvlib.sys_close(p_cp, fd_reg=rvlib.S1)
    rvlib.sys_exit(p_cp, rvlib.ZERO)

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

    p_wc = Program(entry=0x1000_0000)
    wc_readfail = p_wc.db(b"read failed\n")
    wc_sp = p_wc.db(b" ")
    wc_nl = p_wc.db(b"\n")
    p_wc.align_data(8)
    wc_buf = p_wc.db(b"\x00" * 256)
    p_wc.align_data(8)
    wc_digits = p_wc.db(b"\x00" * 32)
    p_wc.label("_start")
    p_wc.li(rvlib.S0, rvlib.ZERO)
    p_wc.li(rvlib.S1, rvlib.ZERO)
    p_wc.li(rvlib.S2, rvlib.ZERO)
    p_wc.li(rvlib.T0, 2)
    p_wc.blt(rvlib.A0, rvlib.T0, "wc_loop")
    p_wc.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_wc, path_reg=rvlib.A0)
    p_wc.blt(rvlib.A0, rvlib.ZERO, "wc_readfail")
    p_wc.emit(rvasm.addi(rvlib.S2, rvlib.A0, 0))
    p_wc.label("wc_loop")
    p_wc.li(rvlib.A1, wc_buf)
    rvlib.sys_read_reg_reg_cnt(p_wc, fd_reg=rvlib.S2, buf_reg=rvlib.A1, count=256)
    p_wc.beq(rvlib.A0, rvlib.ZERO, "wc_done")
    p_wc.blt(rvlib.A0, rvlib.ZERO, "wc_readfail")
    p_wc.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_wc.emit(rvasm.add(rvlib.S0, rvlib.S0, rvlib.T0))
    p_wc.li(rvlib.T1, 0)
    p_wc.label("wc_scan")
    p_wc.beq(rvlib.T1, rvlib.T0, "wc_loop")
    p_wc.li(rvlib.S5, wc_buf)
    p_wc.emit(rvasm.add(rvlib.T2, rvlib.S5, rvlib.T1))
    p_wc.emit(rvasm.lbu(rvlib.T2, rvlib.T2, 0))
    p_wc.li(rvlib.S4, 10)
    p_wc.bne(rvlib.T2, rvlib.S4, "wc_scan_next")
    p_wc.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_wc.label("wc_scan_next")
    p_wc.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_wc.jal(rvlib.ZERO, "wc_scan")

    p_wc.label("wc_done")
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p_wc.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(p_wc, fd=1, buf=wc_sp, count=1)
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.S0, 0))
    p_wc.jal(rvlib.RA, "print_dec")
    rvlib.sys_write(p_wc, fd=1, buf=wc_nl, count=1)
    rvlib.sys_exit(p_wc, rvlib.ZERO)

    p_wc.label("wc_readfail")
    rvlib.sys_write(p_wc, fd=1, buf=wc_readfail, count=len(b"read failed\n"))
    rvlib.sys_exit(p_wc, 1)

    p_wc.label("print_dec")
    p_wc.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_wc.beq(rvlib.T0, rvlib.ZERO, "pd_zero")
    p_wc.li(rvlib.T1, rvlib.ZERO)
    p_wc.label("pd_outer")
    p_wc.beq(rvlib.T0, rvlib.ZERO, "pd_done")
    p_wc.li(rvlib.T2, rvlib.ZERO)
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_wc.label("pd_div")
    p_wc.li(rvlib.A1, 10)
    p_wc.blt(rvlib.A0, rvlib.A1, "pd_div_done")
    p_wc.emit(rvasm.addi(rvlib.A0, rvlib.A0, -10))
    p_wc.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_wc.jal(rvlib.ZERO, "pd_div")
    p_wc.label("pd_div_done")
    p_wc.emit(rvasm.addi(rvlib.A2, rvlib.A0, 48))
    p_wc.li(rvlib.A3, wc_digits)
    p_wc.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    p_wc.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_wc.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_wc.emit(rvasm.addi(rvlib.T0, rvlib.T2, 0))
    p_wc.jal(rvlib.ZERO, "pd_outer")
    p_wc.label("pd_zero")
    p_wc.li(rvlib.A3, wc_digits)
    p_wc.emit(rvasm.addi(rvlib.A1, rvlib.A3, 0))
    p_wc.li(rvlib.A2, 48)
    p_wc.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_wc.li(rvlib.T1, 1)
    p_wc.label("pd_done")
    p_wc.emit(rvasm.addi(rvlib.T1, rvlib.T1, -1))
    p_wc.blt(rvlib.T1, rvlib.ZERO, "pd_ret")
    p_wc.li(rvlib.A3, wc_digits)
    p_wc.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    rvlib.sys_write_fd_reg_cnt(p_wc, fd=1, buf_reg=rvlib.A1, count=1)
    p_wc.jal(rvlib.ZERO, "pd_done")
    p_wc.label("pd_ret")
    p_wc.jalr(rvlib.ZERO, rvlib.RA, 0)
    wc_rvx = p_wc.build_rvx()
    wc_ino = fs.create_file("/bin/wc")
    fs.write_inode(wc_ino, 0, wc_rvx, truncate=True)

    p_head = Program(entry=0x1000_0000)
    head_usage = p_head.db(b"usage: head <file>\n")
    p_head.align_data(8)
    head_buf = p_head.db(b"\x00" * 256)
    p_head.label("_start")
    p_head.li(rvlib.T0, 2)
    p_head.blt(rvlib.A0, rvlib.ZERO, "head_usage")
    p_head.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_head, path_reg=rvlib.A0)
    p_head.blt(rvlib.A0, rvlib.ZERO, "head_usage")
    p_head.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_head.li(rvlib.T2, 0)
    p_head.label("head_read")
    p_head.li(rvlib.A1, head_buf)
    rvlib.sys_read_reg_reg_cnt(p_head, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=256)
    p_head.beq(rvlib.A0, rvlib.ZERO, "head_close")
    p_head.blt(rvlib.A0, rvlib.ZERO, "head_close")
    p_head.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_head.li(rvlib.T1, 0)
    p_head.emit(rvasm.addi(rvlib.S2, rvlib.T0, 0))
    p_head.label("head_scan")
    p_head.beq(rvlib.T1, rvlib.T0, "head_scan_done")
    p_head.li(rvlib.S5, head_buf)
    p_head.emit(rvasm.add(rvlib.S3, rvlib.S5, rvlib.T1))
    p_head.emit(rvasm.lbu(rvlib.S3, rvlib.S3, 0))
    p_head.li(rvlib.S4, 10)
    p_head.bne(rvlib.S3, rvlib.S4, "head_scan_next")
    p_head.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_head.li(rvlib.S4, 10)
    p_head.bne(rvlib.T2, rvlib.S4, "head_scan_next")
    p_head.emit(rvasm.addi(rvlib.S2, rvlib.T1, 1))
    p_head.jal(rvlib.ZERO, "head_scan_done")
    p_head.label("head_scan_next")
    p_head.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_head.jal(rvlib.ZERO, "head_scan")
    p_head.label("head_scan_done")
    p_head.li(rvlib.A1, head_buf)
    rvlib.sys_write_fd_reg_reg(p_head, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.S2)
    p_head.li(rvlib.S4, 10)
    p_head.beq(rvlib.T2, rvlib.S4, "head_close")
    p_head.jal(rvlib.ZERO, "head_read")
    p_head.label("head_close")
    rvlib.sys_close(p_head, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_head, rvlib.ZERO)
    p_head.label("head_usage")
    rvlib.sys_write(p_head, fd=1, buf=head_usage, count=len(b"usage: head <file>\n"))
    rvlib.sys_exit(p_head, 1)
    head_rvx = p_head.build_rvx()
    head_ino = fs.create_file("/bin/head")
    fs.write_inode(head_ino, 0, head_rvx, truncate=True)

    # ===== TIER 1: Simple Utilities =====

    # clear - clear terminal screen
    p_clear = Program(entry=0x1000_0000)
    clear_seq = p_clear.db(b"\x1b[2J\x1b[H")
    p_clear.label("_start")
    rvlib.sys_write(p_clear, fd=1, buf=clear_seq, count=7)
    rvlib.sys_exit(p_clear, 0)
    clear_rvx = p_clear.build_rvx()
    clear_ino = fs.create_file("/bin/clear")
    fs.write_inode(clear_ino, 0, clear_rvx, truncate=True)

    # uname - print system information
    p_uname = Program(entry=0x1000_0000)
    uname_msg = p_uname.db(b"SimMach RV64\n")
    p_uname.label("_start")
    rvlib.sys_write(p_uname, fd=1, buf=uname_msg, count=13)
    rvlib.sys_exit(p_uname, 0)
    uname_rvx = p_uname.build_rvx()
    uname_ino = fs.create_file("/bin/uname")
    fs.write_inode(uname_ino, 0, uname_rvx, truncate=True)

    # id - print user identity
    p_id = Program(entry=0x1000_0000)
    id_msg = p_id.db(b"uid=0(root) gid=0(root)\n")
    p_id.label("_start")
    rvlib.sys_write(p_id, fd=1, buf=id_msg, count=24)
    rvlib.sys_exit(p_id, 0)
    id_rvx = p_id.build_rvx()
    id_ino = fs.create_file("/bin/id")
    fs.write_inode(id_ino, 0, id_rvx, truncate=True)

    # yes - repeatedly output "y" or given string
    p_yes = Program(entry=0x1000_0000)
    yes_default = p_yes.db(b"y")
    yes_nl = p_yes.db(b"\n")
    p_yes.align_data(8)
    p_yes.label("_start")
    # argc in A0, argv in A1
    p_yes.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = argc
    p_yes.emit(rvasm.addi(rvlib.S1, rvlib.A1, 0))  # S1 = argv
    p_yes.li(rvlib.T0, 2)
    p_yes.blt(rvlib.S0, rvlib.T0, "yes_use_default")
    # Use argv[1]
    p_yes.emit(rvasm.ld(rvlib.S2, rvlib.S1, 8))  # S2 = argv[1]
    p_yes.jal(rvlib.ZERO, "yes_calc_len")
    p_yes.label("yes_use_default")
    p_yes.li(rvlib.S2, yes_default)
    p_yes.li(rvlib.S3, 1)  # length = 1
    p_yes.jal(rvlib.ZERO, "yes_loop")
    p_yes.label("yes_calc_len")
    # Calculate string length
    p_yes.li(rvlib.S3, 0)
    p_yes.label("yes_len_loop")
    p_yes.emit(rvasm.add(rvlib.T0, rvlib.S2, rvlib.S3))
    p_yes.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_yes.beq(rvlib.T1, rvlib.ZERO, "yes_loop")
    p_yes.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_yes.jal(rvlib.ZERO, "yes_len_loop")
    p_yes.label("yes_loop")
    rvlib.sys_write_fd_reg_reg(p_yes, fd=1, buf_reg=rvlib.S2, count_reg=rvlib.S3)
    rvlib.sys_write(p_yes, fd=1, buf=yes_nl, count=1)
    p_yes.jal(rvlib.ZERO, "yes_loop")
    yes_rvx = p_yes.build_rvx()
    yes_ino = fs.create_file("/bin/yes")
    fs.write_inode(yes_ino, 0, yes_rvx, truncate=True)

    # seq - print sequence of numbers (seq [start] end)
    p_seq = Program(entry=0x1000_0000)
    seq_usage = p_seq.db(b"usage: seq [start] end\n")
    seq_nl = p_seq.db(b"\n")
    p_seq.align_data(8)
    seq_digits = p_seq.db(b"\x00" * 32)
    p_seq.label("_start")
    p_seq.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = argc
    p_seq.emit(rvasm.addi(rvlib.S1, rvlib.A1, 0))  # S1 = argv
    p_seq.li(rvlib.T0, 2)
    p_seq.blt(rvlib.S0, rvlib.T0, "seq_usage")
    # Parse arguments
    p_seq.li(rvlib.T0, 3)
    p_seq.blt(rvlib.S0, rvlib.T0, "seq_one_arg")
    # Two args: start and end
    p_seq.emit(rvasm.ld(rvlib.A0, rvlib.S1, 8))
    p_seq.jal(rvlib.RA, "seq_atoi")
    p_seq.emit(rvasm.addi(rvlib.S2, rvlib.A0, 0))  # S2 = start
    p_seq.emit(rvasm.ld(rvlib.A0, rvlib.S1, 16))
    p_seq.jal(rvlib.RA, "seq_atoi")
    p_seq.emit(rvasm.addi(rvlib.S3, rvlib.A0, 0))  # S3 = end
    p_seq.jal(rvlib.ZERO, "seq_loop")
    p_seq.label("seq_one_arg")
    p_seq.li(rvlib.S2, 1)  # start = 1
    p_seq.emit(rvasm.ld(rvlib.A0, rvlib.S1, 8))
    p_seq.jal(rvlib.RA, "seq_atoi")
    p_seq.emit(rvasm.addi(rvlib.S3, rvlib.A0, 0))  # S3 = end
    p_seq.label("seq_loop")
    p_seq.blt(rvlib.S3, rvlib.S2, "seq_done")
    p_seq.emit(rvasm.addi(rvlib.A0, rvlib.S2, 0))
    p_seq.jal(rvlib.RA, "seq_print_dec")
    rvlib.sys_write(p_seq, fd=1, buf=seq_nl, count=1)
    p_seq.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_seq.jal(rvlib.ZERO, "seq_loop")
    p_seq.label("seq_done")
    rvlib.sys_exit(p_seq, 0)
    p_seq.label("seq_usage")
    rvlib.sys_write(p_seq, fd=1, buf=seq_usage, count=len(b"usage: seq [start] end\n"))
    rvlib.sys_exit(p_seq, 1)

    # atoi subroutine
    p_seq.label("seq_atoi")
    p_seq.li(rvlib.T0, 0)  # result
    p_seq.label("seq_atoi_loop")
    p_seq.emit(rvasm.lbu(rvlib.T1, rvlib.A0, 0))
    p_seq.beq(rvlib.T1, rvlib.ZERO, "seq_atoi_done")
    p_seq.li(rvlib.T2, 48)
    p_seq.blt(rvlib.T1, rvlib.T2, "seq_atoi_done")
    p_seq.li(rvlib.T2, 58)
    p_seq.bge(rvlib.T1, rvlib.T2, "seq_atoi_done")
    # result = result * 10 + digit
    p_seq.emit(rvasm.slli(rvlib.T2, rvlib.T0, 3))
    p_seq.emit(rvasm.slli(rvlib.T3, rvlib.T0, 1))
    p_seq.emit(rvasm.add(rvlib.T0, rvlib.T2, rvlib.T3))
    p_seq.emit(rvasm.addi(rvlib.T1, rvlib.T1, -48))
    p_seq.emit(rvasm.add(rvlib.T0, rvlib.T0, rvlib.T1))
    p_seq.emit(rvasm.addi(rvlib.A0, rvlib.A0, 1))
    p_seq.jal(rvlib.ZERO, "seq_atoi_loop")
    p_seq.label("seq_atoi_done")
    p_seq.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_seq.jalr(rvlib.ZERO, rvlib.RA, 0)

    # print_dec subroutine
    p_seq.label("seq_print_dec")
    p_seq.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_seq.beq(rvlib.T0, rvlib.ZERO, "seq_pd_zero")
    p_seq.li(rvlib.T1, 0)  # digit count
    p_seq.label("seq_pd_outer")
    p_seq.beq(rvlib.T0, rvlib.ZERO, "seq_pd_print")
    p_seq.li(rvlib.T2, 0)  # quotient
    p_seq.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_seq.label("seq_pd_div")
    p_seq.li(rvlib.A1, 10)
    p_seq.blt(rvlib.A0, rvlib.A1, "seq_pd_div_done")
    p_seq.emit(rvasm.addi(rvlib.A0, rvlib.A0, -10))
    p_seq.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_seq.jal(rvlib.ZERO, "seq_pd_div")
    p_seq.label("seq_pd_div_done")
    p_seq.emit(rvasm.addi(rvlib.A2, rvlib.A0, 48))
    p_seq.li(rvlib.A3, seq_digits)
    p_seq.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    p_seq.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_seq.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_seq.emit(rvasm.addi(rvlib.T0, rvlib.T2, 0))
    p_seq.jal(rvlib.ZERO, "seq_pd_outer")
    p_seq.label("seq_pd_zero")
    p_seq.li(rvlib.A3, seq_digits)
    p_seq.li(rvlib.A2, 48)
    p_seq.emit(rvasm.sb(rvlib.A2, rvlib.A3, 0))
    p_seq.li(rvlib.T1, 1)
    p_seq.label("seq_pd_print")
    p_seq.emit(rvasm.addi(rvlib.T1, rvlib.T1, -1))
    p_seq.blt(rvlib.T1, rvlib.ZERO, "seq_pd_ret")
    p_seq.li(rvlib.A3, seq_digits)
    p_seq.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    rvlib.sys_write_fd_reg_cnt(p_seq, fd=1, buf_reg=rvlib.A1, count=1)
    p_seq.jal(rvlib.ZERO, "seq_pd_print")
    p_seq.label("seq_pd_ret")
    p_seq.jalr(rvlib.ZERO, rvlib.RA, 0)

    seq_rvx = p_seq.build_rvx()
    seq_ino = fs.create_file("/bin/seq")
    fs.write_inode(seq_ino, 0, seq_rvx, truncate=True)

    # sleep - sleep for N milliseconds
    p_sleep = Program(entry=0x1000_0000)
    sleep_usage = p_sleep.db(b"usage: sleep <ms>\n")
    p_sleep.label("_start")
    p_sleep.li(rvlib.T0, 2)
    p_sleep.blt(rvlib.A0, rvlib.T0, "sleep_usage")
    p_sleep.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))  # argv[1]
    p_sleep.jal(rvlib.RA, "sleep_atoi")
    p_sleep.beq(rvlib.T1, rvlib.ZERO, "sleep_usage")
    rvlib.sys_sleep(p_sleep, ms_reg=rvlib.A0)
    rvlib.sys_exit(p_sleep, 0)

    p_sleep.label("sleep_usage")
    rvlib.sys_write(p_sleep, fd=1, buf=sleep_usage, count=len(b"usage: sleep <ms>\n"))
    rvlib.sys_exit(p_sleep, 1)

    # atoi subroutine (returns A0=result, T1=valid)
    p_sleep.label("sleep_atoi")
    p_sleep.li(rvlib.T0, 0)  # result
    p_sleep.li(rvlib.T1, 0)  # saw_digit
    p_sleep.label("sleep_atoi_loop")
    p_sleep.emit(rvasm.lbu(rvlib.T2, rvlib.A0, 0))
    p_sleep.beq(rvlib.T2, rvlib.ZERO, "sleep_atoi_done")
    p_sleep.li(rvlib.T3, 48)
    p_sleep.blt(rvlib.T2, rvlib.T3, "sleep_atoi_bad")
    p_sleep.li(rvlib.T3, 58)
    p_sleep.bge(rvlib.T2, rvlib.T3, "sleep_atoi_bad")
    p_sleep.li(rvlib.T1, 1)
    p_sleep.emit(rvasm.slli(rvlib.T3, rvlib.T0, 3))
    p_sleep.emit(rvasm.slli(rvlib.T4, rvlib.T0, 1))
    p_sleep.emit(rvasm.add(rvlib.T0, rvlib.T3, rvlib.T4))
    p_sleep.emit(rvasm.addi(rvlib.T2, rvlib.T2, -48))
    p_sleep.emit(rvasm.add(rvlib.T0, rvlib.T0, rvlib.T2))
    p_sleep.emit(rvasm.addi(rvlib.A0, rvlib.A0, 1))
    p_sleep.jal(rvlib.ZERO, "sleep_atoi_loop")
    p_sleep.label("sleep_atoi_bad")
    p_sleep.li(rvlib.T1, 0)
    p_sleep.label("sleep_atoi_done")
    p_sleep.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_sleep.jalr(rvlib.ZERO, rvlib.RA, 0)

    sleep_rvx = p_sleep.build_rvx()
    sleep_ino = fs.create_file("/bin/sleep")
    fs.write_inode(sleep_ino, 0, sleep_rvx, truncate=True)

    # stat - print basic file info
    p_stat = Program(entry=0x1000_0000)
    stat_usage = p_stat.db(b"usage: stat <path>\n")
    stat_fail = p_stat.db(b"stat failed\n")
    stat_type = p_stat.db(b"type: ")
    stat_file = p_stat.db(b"file\n")
    stat_dir = p_stat.db(b"dir\n")
    stat_inum = p_stat.db(b"inum: ")
    stat_size = p_stat.db(b"size: ")
    stat_nl = p_stat.db(b"\n")
    p_stat.align_data(8)
    stat_buf = p_stat.db(b"\x00" * 16)
    p_stat.align_data(8)
    stat_digits = p_stat.db(b"\x00" * 32)

    p_stat.label("_start")
    p_stat.li(rvlib.T0, 2)
    p_stat.blt(rvlib.A0, rvlib.T0, "stat_usage")
    p_stat.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))  # argv[1]
    p_stat.li(rvlib.A1, stat_buf)
    rvlib.sys_stat_reg(p_stat, path_reg=rvlib.A0, stat_reg=rvlib.A1)
    p_stat.blt(rvlib.A0, rvlib.ZERO, "stat_failed")

    rvlib.sys_write(p_stat, fd=1, buf=stat_type, count=len(b"type: "))
    p_stat.emit(rvasm.lw(rvlib.T0, stat_buf, 0))  # mode
    p_stat.emit(rvasm.andi(rvlib.T1, rvlib.T0, 2))
    p_stat.beq(rvlib.T1, rvlib.ZERO, "stat_type_file")
    rvlib.sys_write(p_stat, fd=1, buf=stat_dir, count=len(b"dir\n"))
    p_stat.jal(rvlib.ZERO, "stat_type_done")
    p_stat.label("stat_type_file")
    rvlib.sys_write(p_stat, fd=1, buf=stat_file, count=len(b"file\n"))
    p_stat.label("stat_type_done")

    rvlib.sys_write(p_stat, fd=1, buf=stat_inum, count=len(b"inum: "))
    p_stat.emit(rvasm.lw(rvlib.A0, stat_buf, 4))
    p_stat.jal(rvlib.RA, "stat_print_dec")
    rvlib.sys_write(p_stat, fd=1, buf=stat_nl, count=1)

    rvlib.sys_write(p_stat, fd=1, buf=stat_size, count=len(b"size: "))
    p_stat.emit(rvasm.ld(rvlib.A0, stat_buf, 8))
    p_stat.jal(rvlib.RA, "stat_print_dec")
    rvlib.sys_write(p_stat, fd=1, buf=stat_nl, count=1)
    rvlib.sys_exit(p_stat, 0)

    p_stat.label("stat_failed")
    rvlib.sys_write(p_stat, fd=1, buf=stat_fail, count=len(b"stat failed\n"))
    rvlib.sys_exit(p_stat, 1)
    p_stat.label("stat_usage")
    rvlib.sys_write(p_stat, fd=1, buf=stat_usage, count=len(b"usage: stat <path>\n"))
    rvlib.sys_exit(p_stat, 1)

    # print_dec subroutine (A0 input)
    p_stat.label("stat_print_dec")
    p_stat.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_stat.beq(rvlib.T0, rvlib.ZERO, "stat_pd_zero")
    p_stat.li(rvlib.T1, 0)  # digit count
    p_stat.label("stat_pd_outer")
    p_stat.beq(rvlib.T0, rvlib.ZERO, "stat_pd_print")
    p_stat.li(rvlib.T2, 0)  # quotient
    p_stat.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_stat.label("stat_pd_div")
    p_stat.li(rvlib.A1, 10)
    p_stat.blt(rvlib.A0, rvlib.A1, "stat_pd_div_done")
    p_stat.emit(rvasm.addi(rvlib.A0, rvlib.A0, -10))
    p_stat.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_stat.jal(rvlib.ZERO, "stat_pd_div")
    p_stat.label("stat_pd_div_done")
    p_stat.emit(rvasm.addi(rvlib.A2, rvlib.A0, 48))
    p_stat.li(rvlib.A3, stat_digits)
    p_stat.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    p_stat.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_stat.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_stat.emit(rvasm.addi(rvlib.T0, rvlib.T2, 0))
    p_stat.jal(rvlib.ZERO, "stat_pd_outer")
    p_stat.label("stat_pd_zero")
    p_stat.li(rvlib.A3, stat_digits)
    p_stat.li(rvlib.A2, 48)
    p_stat.emit(rvasm.sb(rvlib.A2, rvlib.A3, 0))
    p_stat.li(rvlib.T1, 1)
    p_stat.label("stat_pd_print")
    p_stat.emit(rvasm.addi(rvlib.T1, rvlib.T1, -1))
    p_stat.blt(rvlib.T1, rvlib.ZERO, "stat_pd_ret")
    p_stat.li(rvlib.A3, stat_digits)
    p_stat.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    rvlib.sys_write_fd_reg_cnt(p_stat, fd=1, buf_reg=rvlib.A1, count=1)
    p_stat.jal(rvlib.ZERO, "stat_pd_print")
    p_stat.label("stat_pd_ret")
    p_stat.jalr(rvlib.ZERO, rvlib.RA, 0)

    stat_rvx = p_stat.build_rvx()
    stat_ino = fs.create_file("/bin/stat")
    fs.write_inode(stat_ino, 0, stat_rvx, truncate=True)

    # basename - strip directory from path
    p_bn = Program(entry=0x1000_0000)
    bn_usage = p_bn.db(b"usage: basename <path>\n")
    bn_nl = p_bn.db(b"\n")
    p_bn.label("_start")
    p_bn.li(rvlib.T0, 2)
    p_bn.blt(rvlib.A0, rvlib.T0, "bn_usage")
    p_bn.emit(rvasm.ld(rvlib.S0, rvlib.A1, 8))  # S0 = path
    # Find last '/'
    p_bn.emit(rvasm.addi(rvlib.S1, rvlib.S0, 0))  # S1 = result (start of basename)
    p_bn.emit(rvasm.addi(rvlib.T0, rvlib.S0, 0))  # T0 = cursor
    p_bn.label("bn_scan")
    p_bn.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_bn.beq(rvlib.T1, rvlib.ZERO, "bn_print")
    p_bn.li(rvlib.T2, 47)  # '/'
    p_bn.bne(rvlib.T1, rvlib.T2, "bn_next")
    p_bn.emit(rvasm.addi(rvlib.S1, rvlib.T0, 1))  # S1 = after slash
    p_bn.label("bn_next")
    p_bn.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_bn.jal(rvlib.ZERO, "bn_scan")
    p_bn.label("bn_print")
    # Calculate length
    p_bn.li(rvlib.S2, 0)
    p_bn.label("bn_len")
    p_bn.emit(rvasm.add(rvlib.T0, rvlib.S1, rvlib.S2))
    p_bn.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_bn.beq(rvlib.T1, rvlib.ZERO, "bn_write")
    p_bn.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_bn.jal(rvlib.ZERO, "bn_len")
    p_bn.label("bn_write")
    rvlib.sys_write_fd_reg_reg(p_bn, fd=1, buf_reg=rvlib.S1, count_reg=rvlib.S2)
    rvlib.sys_write(p_bn, fd=1, buf=bn_nl, count=1)
    rvlib.sys_exit(p_bn, 0)
    p_bn.label("bn_usage")
    rvlib.sys_write(p_bn, fd=1, buf=bn_usage, count=len(b"usage: basename <path>\n"))
    rvlib.sys_exit(p_bn, 1)
    bn_rvx = p_bn.build_rvx()
    bn_ino = fs.create_file("/bin/basename")
    fs.write_inode(bn_ino, 0, bn_rvx, truncate=True)

    # dirname - strip filename from path
    p_dn = Program(entry=0x1000_0000)
    dn_usage = p_dn.db(b"usage: dirname <path>\n")
    dn_dot = p_dn.db(b".")
    dn_nl = p_dn.db(b"\n")
    p_dn.label("_start")
    p_dn.li(rvlib.T0, 2)
    p_dn.blt(rvlib.A0, rvlib.T0, "dn_usage")
    p_dn.emit(rvasm.ld(rvlib.S0, rvlib.A1, 8))  # S0 = path
    # Find last '/'
    p_dn.li(rvlib.S1, -1)  # S1 = last slash position
    p_dn.li(rvlib.T0, 0)   # T0 = cursor index
    p_dn.label("dn_scan")
    p_dn.emit(rvasm.add(rvlib.T2, rvlib.S0, rvlib.T0))
    p_dn.emit(rvasm.lbu(rvlib.T1, rvlib.T2, 0))
    p_dn.beq(rvlib.T1, rvlib.ZERO, "dn_check")
    p_dn.li(rvlib.T2, 47)  # '/'
    p_dn.bne(rvlib.T1, rvlib.T2, "dn_next")
    p_dn.emit(rvasm.addi(rvlib.S1, rvlib.T0, 0))
    p_dn.label("dn_next")
    p_dn.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_dn.jal(rvlib.ZERO, "dn_scan")
    p_dn.label("dn_check")
    p_dn.blt(rvlib.S1, rvlib.ZERO, "dn_print_dot")
    p_dn.beq(rvlib.S1, rvlib.ZERO, "dn_print_slash")
    # Print path up to last slash
    rvlib.sys_write_fd_reg_reg(p_dn, fd=1, buf_reg=rvlib.S0, count_reg=rvlib.S1)
    rvlib.sys_write(p_dn, fd=1, buf=dn_nl, count=1)
    rvlib.sys_exit(p_dn, 0)
    p_dn.label("dn_print_slash")
    p_dn.li(rvlib.S1, 1)
    rvlib.sys_write_fd_reg_reg(p_dn, fd=1, buf_reg=rvlib.S0, count_reg=rvlib.S1)
    rvlib.sys_write(p_dn, fd=1, buf=dn_nl, count=1)
    rvlib.sys_exit(p_dn, 0)
    p_dn.label("dn_print_dot")
    rvlib.sys_write(p_dn, fd=1, buf=dn_dot, count=1)
    rvlib.sys_write(p_dn, fd=1, buf=dn_nl, count=1)
    rvlib.sys_exit(p_dn, 0)
    p_dn.label("dn_usage")
    rvlib.sys_write(p_dn, fd=1, buf=dn_usage, count=len(b"usage: dirname <path>\n"))
    rvlib.sys_exit(p_dn, 1)
    dn_rvx = p_dn.build_rvx()
    dn_ino = fs.create_file("/bin/dirname")
    fs.write_inode(dn_ino, 0, dn_rvx, truncate=True)

    # ===== TIER 2: File Processing Utilities =====

    # tee - read stdin, write to stdout and file
    p_tee = Program(entry=0x1000_0000)
    tee_usage = p_tee.db(b"usage: tee <file>\n")
    tee_openfail = p_tee.db(b"open failed\n")
    p_tee.align_data(8)
    tee_buf = p_tee.db(b"\x00" * 256)
    p_tee.label("_start")
    p_tee.li(rvlib.T0, 2)
    p_tee.blt(rvlib.A0, rvlib.T0, "tee_usage")
    p_tee.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_create_trunc_reg(p_tee, path_reg=rvlib.A0)
    p_tee.blt(rvlib.A0, rvlib.ZERO, "tee_openfail")
    p_tee.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = file fd
    p_tee.label("tee_loop")
    p_tee.li(rvlib.A1, tee_buf)
    rvlib.sys_read_fd_reg_cnt(p_tee, fd=0, buf_reg=rvlib.A1, count=256)
    p_tee.beq(rvlib.A0, rvlib.ZERO, "tee_close")
    p_tee.blt(rvlib.A0, rvlib.ZERO, "tee_close")
    p_tee.emit(rvasm.addi(rvlib.S1, rvlib.A0, 0))  # S1 = bytes read
    p_tee.li(rvlib.A1, tee_buf)
    rvlib.sys_write_fd_reg_reg(p_tee, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.S1)
    p_tee.li(rvlib.A1, tee_buf)
    rvlib.sys_write_reg(p_tee, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count_reg=rvlib.S1)
    p_tee.jal(rvlib.ZERO, "tee_loop")
    p_tee.label("tee_close")
    rvlib.sys_close(p_tee, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_tee, 0)
    p_tee.label("tee_usage")
    rvlib.sys_write(p_tee, fd=1, buf=tee_usage, count=len(b"usage: tee <file>\n"))
    rvlib.sys_exit(p_tee, 1)
    p_tee.label("tee_openfail")
    rvlib.sys_write(p_tee, fd=1, buf=tee_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_tee, 1)
    tee_rvx = p_tee.build_rvx()
    tee_ino = fs.create_file("/bin/tee")
    fs.write_inode(tee_ino, 0, tee_rvx, truncate=True)

    # rev - reverse each line
    p_rev = Program(entry=0x1000_0000)
    p_rev.align_data(8)
    rev_buf = p_rev.db(b"\x00" * 256)
    p_rev.label("_start")
    # Check if file argument provided
    p_rev.li(rvlib.T0, 2)
    p_rev.blt(rvlib.A0, rvlib.T0, "rev_stdin")
    # Open file from argv[1]
    p_rev.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_rev, path_reg=rvlib.A0)
    p_rev.blt(rvlib.A0, rvlib.ZERO, "rev_done")
    p_rev.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_rev.jal(rvlib.ZERO, "rev_readline")
    p_rev.label("rev_stdin")
    p_rev.li(rvlib.S0, 0)  # fd = stdin
    p_rev.label("rev_readline")
    p_rev.li(rvlib.S1, 0)  # line length
    p_rev.label("rev_readchar")
    p_rev.li(rvlib.T0, 255)
    p_rev.bge(rvlib.S1, rvlib.T0, "rev_reverse")
    p_rev.li(rvlib.A1, rev_buf)
    p_rev.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    rvlib.sys_read_reg_reg_cnt(p_rev, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=1)
    p_rev.beq(rvlib.A0, rvlib.ZERO, "rev_eof")
    p_rev.blt(rvlib.A0, rvlib.ZERO, "rev_done")
    p_rev.li(rvlib.A1, rev_buf)
    p_rev.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S1))
    p_rev.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_rev.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_rev.li(rvlib.T2, 10)
    p_rev.beq(rvlib.T1, rvlib.T2, "rev_reverse")
    p_rev.jal(rvlib.ZERO, "rev_readchar")
    p_rev.label("rev_eof")
    p_rev.beq(rvlib.S1, rvlib.ZERO, "rev_done")
    p_rev.label("rev_reverse")
    p_rev.emit(rvasm.addi(rvlib.S1, rvlib.S1, -1))
    p_rev.label("rev_print")
    p_rev.blt(rvlib.S1, rvlib.ZERO, "rev_nl")
    p_rev.li(rvlib.A1, rev_buf)
    p_rev.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    p_rev.emit(rvasm.lbu(rvlib.T0, rvlib.A1, 0))
    p_rev.li(rvlib.T1, 10)
    p_rev.beq(rvlib.T0, rvlib.T1, "rev_skip_nl")
    rvlib.sys_write_fd_reg_cnt(p_rev, fd=1, buf_reg=rvlib.A1, count=1)
    p_rev.label("rev_skip_nl")
    p_rev.emit(rvasm.addi(rvlib.S1, rvlib.S1, -1))
    p_rev.jal(rvlib.ZERO, "rev_print")
    p_rev.label("rev_nl")
    p_rev.li(rvlib.A1, rev_buf)
    p_rev.li(rvlib.T0, 10)
    p_rev.emit(rvasm.sb(rvlib.T0, rvlib.A1, 0))
    rvlib.sys_write_fd_reg_cnt(p_rev, fd=1, buf_reg=rvlib.A1, count=1)
    p_rev.jal(rvlib.ZERO, "rev_readline")
    p_rev.label("rev_done")
    rvlib.sys_exit(p_rev, 0)
    rev_rvx = p_rev.build_rvx()
    rev_ino = fs.create_file("/bin/rev")
    fs.write_inode(rev_ino, 0, rev_rvx, truncate=True)

    # nl - number lines
    p_nl = Program(entry=0x1000_0000)
    nl_tab = p_nl.db(b"\t")
    p_nl.align_data(8)
    nl_buf = p_nl.db(b"\x00" * 256)
    p_nl.align_data(8)
    nl_digits = p_nl.db(b"\x00" * 16)
    p_nl.label("_start")
    # Check if file argument provided
    p_nl.li(rvlib.T0, 2)
    p_nl.blt(rvlib.A0, rvlib.T0, "nl_stdin")
    # Open file from argv[1]
    p_nl.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_nl, path_reg=rvlib.A0)
    p_nl.blt(rvlib.A0, rvlib.ZERO, "nl_done")
    p_nl.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_nl.jal(rvlib.ZERO, "nl_start")
    p_nl.label("nl_stdin")
    p_nl.li(rvlib.S0, 0)  # fd = stdin
    p_nl.label("nl_start")
    p_nl.li(rvlib.S2, 1)  # line number
    p_nl.label("nl_readline")
    p_nl.li(rvlib.S1, 0)  # line length
    p_nl.label("nl_readchar")
    p_nl.li(rvlib.T0, 255)
    p_nl.bge(rvlib.S1, rvlib.T0, "nl_printline")
    p_nl.li(rvlib.A1, nl_buf)
    p_nl.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    rvlib.sys_read_reg_reg_cnt(p_nl, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=1)
    p_nl.beq(rvlib.A0, rvlib.ZERO, "nl_eof")
    p_nl.blt(rvlib.A0, rvlib.ZERO, "nl_done")
    p_nl.li(rvlib.A1, nl_buf)
    p_nl.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S1))
    p_nl.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_nl.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_nl.li(rvlib.T2, 10)
    p_nl.beq(rvlib.T1, rvlib.T2, "nl_printline")
    p_nl.jal(rvlib.ZERO, "nl_readchar")
    p_nl.label("nl_eof")
    p_nl.beq(rvlib.S1, rvlib.ZERO, "nl_done")
    p_nl.label("nl_printline")
    # Print line number
    p_nl.emit(rvasm.addi(rvlib.A0, rvlib.S2, 0))
    p_nl.jal(rvlib.RA, "nl_print_dec")
    rvlib.sys_write(p_nl, fd=1, buf=nl_tab, count=1)
    # Print line content
    p_nl.li(rvlib.A1, nl_buf)
    rvlib.sys_write_fd_reg_reg(p_nl, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.S1)
    p_nl.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_nl.jal(rvlib.ZERO, "nl_readline")
    p_nl.label("nl_done")
    rvlib.sys_exit(p_nl, 0)

    # print_dec subroutine for nl
    p_nl.label("nl_print_dec")
    p_nl.emit(rvasm.addi(rvlib.T0, rvlib.A0, 0))
    p_nl.beq(rvlib.T0, rvlib.ZERO, "nl_pd_zero")
    p_nl.li(rvlib.T1, 0)
    p_nl.label("nl_pd_outer")
    p_nl.beq(rvlib.T0, rvlib.ZERO, "nl_pd_print")
    p_nl.li(rvlib.T2, 0)
    p_nl.emit(rvasm.addi(rvlib.A0, rvlib.T0, 0))
    p_nl.label("nl_pd_div")
    p_nl.li(rvlib.A1, 10)
    p_nl.blt(rvlib.A0, rvlib.A1, "nl_pd_div_done")
    p_nl.emit(rvasm.addi(rvlib.A0, rvlib.A0, -10))
    p_nl.emit(rvasm.addi(rvlib.T2, rvlib.T2, 1))
    p_nl.jal(rvlib.ZERO, "nl_pd_div")
    p_nl.label("nl_pd_div_done")
    p_nl.emit(rvasm.addi(rvlib.A2, rvlib.A0, 48))
    p_nl.li(rvlib.A3, nl_digits)
    p_nl.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    p_nl.emit(rvasm.sb(rvlib.A2, rvlib.A1, 0))
    p_nl.emit(rvasm.addi(rvlib.T1, rvlib.T1, 1))
    p_nl.emit(rvasm.addi(rvlib.T0, rvlib.T2, 0))
    p_nl.jal(rvlib.ZERO, "nl_pd_outer")
    p_nl.label("nl_pd_zero")
    p_nl.li(rvlib.A3, nl_digits)
    p_nl.li(rvlib.A2, 48)
    p_nl.emit(rvasm.sb(rvlib.A2, rvlib.A3, 0))
    p_nl.li(rvlib.T1, 1)
    p_nl.label("nl_pd_print")
    p_nl.emit(rvasm.addi(rvlib.T1, rvlib.T1, -1))
    p_nl.blt(rvlib.T1, rvlib.ZERO, "nl_pd_ret")
    p_nl.li(rvlib.A3, nl_digits)
    p_nl.emit(rvasm.add(rvlib.A1, rvlib.A3, rvlib.T1))
    rvlib.sys_write_fd_reg_cnt(p_nl, fd=1, buf_reg=rvlib.A1, count=1)
    p_nl.jal(rvlib.ZERO, "nl_pd_print")
    p_nl.label("nl_pd_ret")
    p_nl.jalr(rvlib.ZERO, rvlib.RA, 0)

    nl_rvx = p_nl.build_rvx()
    nl_ino = fs.create_file("/bin/nl")
    fs.write_inode(nl_ino, 0, nl_rvx, truncate=True)

    # uniq - filter adjacent duplicate lines
    p_uniq = Program(entry=0x1000_0000)
    p_uniq.align_data(8)
    uniq_cur = p_uniq.db(b"\x00" * 256)
    p_uniq.align_data(8)
    uniq_prev = p_uniq.db(b"\x00" * 256)
    p_uniq.label("_start")
    # Check if file argument provided
    p_uniq.li(rvlib.T0, 2)
    p_uniq.blt(rvlib.A0, rvlib.T0, "uniq_stdin")
    # Open file from argv[1]
    p_uniq.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_uniq, path_reg=rvlib.A0)
    p_uniq.blt(rvlib.A0, rvlib.ZERO, "uniq_done")
    p_uniq.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_uniq.jal(rvlib.ZERO, "uniq_start")
    p_uniq.label("uniq_stdin")
    p_uniq.li(rvlib.S0, 0)  # fd = stdin
    p_uniq.label("uniq_start")
    p_uniq.li(rvlib.S3, 0)  # prev_len = 0 (no previous line)
    p_uniq.label("uniq_readline")
    p_uniq.li(rvlib.S1, 0)  # cur_len
    p_uniq.label("uniq_readchar")
    p_uniq.li(rvlib.T0, 255)
    p_uniq.bge(rvlib.S1, rvlib.T0, "uniq_compare")
    p_uniq.li(rvlib.A1, uniq_cur)
    p_uniq.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    rvlib.sys_read_reg_reg_cnt(p_uniq, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=1)
    p_uniq.beq(rvlib.A0, rvlib.ZERO, "uniq_eof")
    p_uniq.blt(rvlib.A0, rvlib.ZERO, "uniq_done")
    p_uniq.li(rvlib.A1, uniq_cur)
    p_uniq.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S1))
    p_uniq.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_uniq.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_uniq.li(rvlib.T2, 10)
    p_uniq.beq(rvlib.T1, rvlib.T2, "uniq_compare")
    p_uniq.jal(rvlib.ZERO, "uniq_readchar")
    p_uniq.label("uniq_eof")
    p_uniq.beq(rvlib.S1, rvlib.ZERO, "uniq_done")
    p_uniq.label("uniq_compare")
    # Compare cur with prev
    p_uniq.bne(rvlib.S1, rvlib.S3, "uniq_print")
    p_uniq.li(rvlib.T0, 0)
    p_uniq.label("uniq_cmp_loop")
    p_uniq.beq(rvlib.T0, rvlib.S1, "uniq_skip")
    p_uniq.li(rvlib.A0, uniq_cur)
    p_uniq.emit(rvasm.add(rvlib.A0, rvlib.A0, rvlib.T0))
    p_uniq.emit(rvasm.lbu(rvlib.T1, rvlib.A0, 0))
    p_uniq.li(rvlib.A0, uniq_prev)
    p_uniq.emit(rvasm.add(rvlib.A0, rvlib.A0, rvlib.T0))
    p_uniq.emit(rvasm.lbu(rvlib.T2, rvlib.A0, 0))
    p_uniq.bne(rvlib.T1, rvlib.T2, "uniq_print")
    p_uniq.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_uniq.jal(rvlib.ZERO, "uniq_cmp_loop")
    p_uniq.label("uniq_skip")
    p_uniq.jal(rvlib.ZERO, "uniq_readline")
    p_uniq.label("uniq_print")
    p_uniq.li(rvlib.A1, uniq_cur)
    rvlib.sys_write_fd_reg_reg(p_uniq, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.S1)
    # Copy cur to prev
    p_uniq.li(rvlib.T0, 0)
    p_uniq.label("uniq_copy")
    p_uniq.beq(rvlib.T0, rvlib.S1, "uniq_copy_done")
    p_uniq.li(rvlib.A0, uniq_cur)
    p_uniq.emit(rvasm.add(rvlib.A0, rvlib.A0, rvlib.T0))
    p_uniq.emit(rvasm.lbu(rvlib.T1, rvlib.A0, 0))
    p_uniq.li(rvlib.A0, uniq_prev)
    p_uniq.emit(rvasm.add(rvlib.A0, rvlib.A0, rvlib.T0))
    p_uniq.emit(rvasm.sb(rvlib.T1, rvlib.A0, 0))
    p_uniq.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_uniq.jal(rvlib.ZERO, "uniq_copy")
    p_uniq.label("uniq_copy_done")
    p_uniq.emit(rvasm.addi(rvlib.S3, rvlib.S1, 0))
    p_uniq.jal(rvlib.ZERO, "uniq_readline")
    p_uniq.label("uniq_done")
    rvlib.sys_exit(p_uniq, 0)
    uniq_rvx = p_uniq.build_rvx()
    uniq_ino = fs.create_file("/bin/uniq")
    fs.write_inode(uniq_ino, 0, uniq_rvx, truncate=True)

    # xxd - hexdump
    p_xxd = Program(entry=0x1000_0000)
    xxd_usage = p_xxd.db(b"usage: xxd <file>\n")
    xxd_openfail = p_xxd.db(b"open failed\n")
    xxd_colon = p_xxd.db(b": ")
    xxd_sp = p_xxd.db(b" ")
    xxd_nl = p_xxd.db(b"\n")
    xxd_hex = p_xxd.db(b"0123456789abcdef")
    p_xxd.align_data(8)
    xxd_buf = p_xxd.db(b"\x00" * 16)
    p_xxd.align_data(8)
    xxd_out = p_xxd.db(b"\x00" * 8)
    p_xxd.label("_start")
    p_xxd.li(rvlib.T0, 2)
    p_xxd.blt(rvlib.A0, rvlib.T0, "xxd_usage")
    p_xxd.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_xxd, path_reg=rvlib.A0)
    p_xxd.blt(rvlib.A0, rvlib.ZERO, "xxd_openfail")
    p_xxd.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = fd
    p_xxd.li(rvlib.S1, 0)  # S1 = offset
    p_xxd.label("xxd_loop")
    p_xxd.li(rvlib.A1, xxd_buf)
    rvlib.sys_read_reg_reg_cnt(p_xxd, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=16)
    p_xxd.beq(rvlib.A0, rvlib.ZERO, "xxd_close")
    p_xxd.blt(rvlib.A0, rvlib.ZERO, "xxd_close")
    p_xxd.emit(rvasm.addi(rvlib.S2, rvlib.A0, 0))  # S2 = bytes read
    # Print offset (8 hex digits)
    p_xxd.emit(rvasm.addi(rvlib.A0, rvlib.S1, 0))
    p_xxd.jal(rvlib.RA, "xxd_print_offset")
    rvlib.sys_write(p_xxd, fd=1, buf=xxd_colon, count=2)
    # Print hex bytes
    p_xxd.li(rvlib.S3, 0)
    p_xxd.label("xxd_hex_loop")
    p_xxd.beq(rvlib.S3, rvlib.S2, "xxd_hex_done")
    p_xxd.li(rvlib.A1, xxd_buf)
    p_xxd.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S3))
    p_xxd.emit(rvasm.lbu(rvlib.A0, rvlib.A1, 0))
    p_xxd.jal(rvlib.RA, "xxd_print_byte")
    rvlib.sys_write(p_xxd, fd=1, buf=xxd_sp, count=1)
    p_xxd.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_xxd.jal(rvlib.ZERO, "xxd_hex_loop")
    p_xxd.label("xxd_hex_done")
    rvlib.sys_write(p_xxd, fd=1, buf=xxd_nl, count=1)
    p_xxd.emit(rvasm.add(rvlib.S1, rvlib.S1, rvlib.S2))
    p_xxd.jal(rvlib.ZERO, "xxd_loop")
    p_xxd.label("xxd_close")
    rvlib.sys_close(p_xxd, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_xxd, 0)
    p_xxd.label("xxd_usage")
    rvlib.sys_write(p_xxd, fd=1, buf=xxd_usage, count=len(b"usage: xxd <file>\n"))
    rvlib.sys_exit(p_xxd, 1)
    p_xxd.label("xxd_openfail")
    rvlib.sys_write(p_xxd, fd=1, buf=xxd_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_xxd, 1)

    # print_offset subroutine (8 hex digits)
    p_xxd.label("xxd_print_offset")
    p_xxd.li(rvlib.T0, 7)
    p_xxd.label("xxd_po_loop")
    p_xxd.blt(rvlib.T0, rvlib.ZERO, "xxd_po_ret")
    p_xxd.emit(rvasm.slli(rvlib.T1, rvlib.T0, 2))
    p_xxd.emit(rvasm.srli(rvlib.T2, rvlib.A0, rvlib.T1))
    p_xxd.li(rvlib.T3, 15)
    p_xxd.emit(rvasm.and_(rvlib.T2, rvlib.T2, rvlib.T3))
    p_xxd.li(rvlib.T3, xxd_hex)
    p_xxd.emit(rvasm.add(rvlib.T3, rvlib.T3, rvlib.T2))
    rvlib.sys_write_fd_reg_cnt(p_xxd, fd=1, buf_reg=rvlib.T3, count=1)
    p_xxd.emit(rvasm.addi(rvlib.T0, rvlib.T0, -1))
    p_xxd.jal(rvlib.ZERO, "xxd_po_loop")
    p_xxd.label("xxd_po_ret")
    p_xxd.jalr(rvlib.ZERO, rvlib.RA, 0)

    # print_byte subroutine (2 hex digits)
    p_xxd.label("xxd_print_byte")
    # Save A0 to T4 before syscalls corrupt it
    p_xxd.emit(rvasm.addi(rvlib.T4, rvlib.A0, 0))
    p_xxd.emit(rvasm.srli(rvlib.T0, rvlib.T4, 4))
    p_xxd.li(rvlib.T1, 15)
    p_xxd.emit(rvasm.and_(rvlib.T0, rvlib.T0, rvlib.T1))
    p_xxd.li(rvlib.T2, xxd_hex)
    p_xxd.emit(rvasm.add(rvlib.T2, rvlib.T2, rvlib.T0))
    rvlib.sys_write_fd_reg_cnt(p_xxd, fd=1, buf_reg=rvlib.T2, count=1)
    # Use saved T4 for low nibble
    p_xxd.li(rvlib.T1, 15)
    p_xxd.emit(rvasm.and_(rvlib.T0, rvlib.T4, rvlib.T1))
    p_xxd.li(rvlib.T2, xxd_hex)
    p_xxd.emit(rvasm.add(rvlib.T2, rvlib.T2, rvlib.T0))
    rvlib.sys_write_fd_reg_cnt(p_xxd, fd=1, buf_reg=rvlib.T2, count=1)
    p_xxd.jalr(rvlib.ZERO, rvlib.RA, 0)

    xxd_rvx = p_xxd.build_rvx()
    xxd_ino = fs.create_file("/bin/xxd")
    fs.write_inode(xxd_ino, 0, xxd_rvx, truncate=True)

    # tail - show last 10 lines of file
    p_tail = Program(entry=0x1000_0000)
    tail_usage = p_tail.db(b"usage: tail <file>\n")
    tail_openfail = p_tail.db(b"open failed\n")
    p_tail.align_data(8)
    tail_buf = p_tail.db(b"\x00" * 4096)
    p_tail.label("_start")
    p_tail.li(rvlib.T0, 2)
    p_tail.blt(rvlib.A0, rvlib.T0, "tail_usage")
    p_tail.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_tail, path_reg=rvlib.A0)
    p_tail.blt(rvlib.A0, rvlib.ZERO, "tail_openfail")
    p_tail.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = fd
    # Read entire file into buffer
    p_tail.li(rvlib.S1, 0)  # S1 = total bytes read
    p_tail.label("tail_read")
    p_tail.li(rvlib.A1, tail_buf)
    p_tail.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    p_tail.li(rvlib.T0, 4096)
    p_tail.emit(rvasm.sub(rvlib.T0, rvlib.T0, rvlib.S1))
    p_tail.beq(rvlib.T0, rvlib.ZERO, "tail_count")
    rvlib.sys_read_reg(p_tail, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count_reg=rvlib.T0)
    p_tail.beq(rvlib.A0, rvlib.ZERO, "tail_count")
    p_tail.blt(rvlib.A0, rvlib.ZERO, "tail_count")
    p_tail.emit(rvasm.add(rvlib.S1, rvlib.S1, rvlib.A0))
    p_tail.jal(rvlib.ZERO, "tail_read")
    p_tail.label("tail_count")
    rvlib.sys_close(p_tail, fd_reg=rvlib.S0)
    # Count newlines from end
    p_tail.li(rvlib.S2, 0)  # S2 = newline count
    p_tail.emit(rvasm.addi(rvlib.S3, rvlib.S1, -1))  # S3 = cursor
    p_tail.label("tail_count_loop")
    p_tail.blt(rvlib.S3, rvlib.ZERO, "tail_output")
    p_tail.li(rvlib.A1, tail_buf)
    p_tail.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S3))
    p_tail.emit(rvasm.lbu(rvlib.T0, rvlib.A1, 0))
    p_tail.li(rvlib.T1, 10)
    p_tail.bne(rvlib.T0, rvlib.T1, "tail_count_next")
    p_tail.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_tail.li(rvlib.T0, 10)
    p_tail.beq(rvlib.S2, rvlib.T0, "tail_found")
    p_tail.label("tail_count_next")
    p_tail.emit(rvasm.addi(rvlib.S3, rvlib.S3, -1))
    p_tail.jal(rvlib.ZERO, "tail_count_loop")
    p_tail.label("tail_found")
    p_tail.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_tail.label("tail_output")
    p_tail.li(rvlib.A1, tail_buf)
    p_tail.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S3))
    p_tail.emit(rvasm.sub(rvlib.T0, rvlib.S1, rvlib.S3))
    rvlib.sys_write_fd_reg_reg(p_tail, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.T0)
    rvlib.sys_exit(p_tail, 0)
    p_tail.label("tail_usage")
    rvlib.sys_write(p_tail, fd=1, buf=tail_usage, count=len(b"usage: tail <file>\n"))
    rvlib.sys_exit(p_tail, 1)
    p_tail.label("tail_openfail")
    rvlib.sys_write(p_tail, fd=1, buf=tail_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_tail, 1)
    tail_rvx = p_tail.build_rvx()
    tail_ino = fs.create_file("/bin/tail")
    fs.write_inode(tail_ino, 0, tail_rvx, truncate=True)

    # ===== TIER 3: Text Processing =====

    # grep - simple substring search
    p_grep = Program(entry=0x1000_0000)
    grep_usage = p_grep.db(b"usage: grep <pattern> <file>\n")
    grep_openfail = p_grep.db(b"open failed\n")
    p_grep.align_data(8)
    grep_line = p_grep.db(b"\x00" * 256)
    p_grep.label("_start")
    p_grep.li(rvlib.T0, 3)
    p_grep.blt(rvlib.A0, rvlib.T0, "grep_usage")
    p_grep.emit(rvasm.ld(rvlib.S4, rvlib.A1, 8))   # S4 = pattern
    p_grep.emit(rvasm.ld(rvlib.A0, rvlib.A1, 16))  # file path
    rvlib.sys_open_ro_reg(p_grep, path_reg=rvlib.A0)
    p_grep.blt(rvlib.A0, rvlib.ZERO, "grep_openfail")
    p_grep.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = fd
    p_grep.label("grep_readline")
    p_grep.li(rvlib.S1, 0)  # line length
    p_grep.label("grep_readchar")
    p_grep.li(rvlib.T0, 255)
    p_grep.bge(rvlib.S1, rvlib.T0, "grep_search")
    p_grep.li(rvlib.A1, grep_line)
    p_grep.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    rvlib.sys_read_reg_reg_cnt(p_grep, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=1)
    p_grep.beq(rvlib.A0, rvlib.ZERO, "grep_eof")
    p_grep.blt(rvlib.A0, rvlib.ZERO, "grep_close")
    p_grep.li(rvlib.A1, grep_line)
    p_grep.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S1))
    p_grep.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_grep.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_grep.li(rvlib.T2, 10)
    p_grep.beq(rvlib.T1, rvlib.T2, "grep_search")
    p_grep.jal(rvlib.ZERO, "grep_readchar")
    p_grep.label("grep_eof")
    p_grep.beq(rvlib.S1, rvlib.ZERO, "grep_close")
    p_grep.label("grep_search")
    # Search for pattern in line
    p_grep.li(rvlib.S2, 0)  # line position
    p_grep.label("grep_search_pos")
    p_grep.beq(rvlib.S2, rvlib.S1, "grep_readline")
    p_grep.li(rvlib.S3, 0)  # pattern position
    p_grep.label("grep_match")
    p_grep.emit(rvasm.add(rvlib.T0, rvlib.S4, rvlib.S3))
    p_grep.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_grep.beq(rvlib.T1, rvlib.ZERO, "grep_found")
    p_grep.emit(rvasm.add(rvlib.T2, rvlib.S2, rvlib.S3))
    p_grep.bge(rvlib.T2, rvlib.S1, "grep_next_pos")
    p_grep.li(rvlib.A1, grep_line)
    p_grep.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T2))
    p_grep.emit(rvasm.lbu(rvlib.T2, rvlib.T0, 0))
    p_grep.bne(rvlib.T1, rvlib.T2, "grep_next_pos")
    p_grep.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_grep.jal(rvlib.ZERO, "grep_match")
    p_grep.label("grep_next_pos")
    p_grep.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_grep.jal(rvlib.ZERO, "grep_search_pos")
    p_grep.label("grep_found")
    p_grep.li(rvlib.A1, grep_line)
    rvlib.sys_write_fd_reg_reg(p_grep, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.S1)
    p_grep.jal(rvlib.ZERO, "grep_readline")
    p_grep.label("grep_close")
    rvlib.sys_close(p_grep, fd_reg=rvlib.S0)
    rvlib.sys_exit(p_grep, 0)
    p_grep.label("grep_usage")
    rvlib.sys_write(p_grep, fd=1, buf=grep_usage, count=len(b"usage: grep <pattern> <file>\n"))
    rvlib.sys_exit(p_grep, 1)
    p_grep.label("grep_openfail")
    rvlib.sys_write(p_grep, fd=1, buf=grep_openfail, count=len(b"open failed\n"))
    rvlib.sys_exit(p_grep, 1)
    grep_rvx = p_grep.build_rvx()
    grep_ino = fs.create_file("/bin/grep")
    fs.write_inode(grep_ino, 0, grep_rvx, truncate=True)

    # tr - translate characters
    p_tr = Program(entry=0x1000_0000)
    tr_usage = p_tr.db(b"usage: tr <set1> <set2>\n")
    p_tr.align_data(8)
    tr_buf = p_tr.db(b"\x00" * 1)
    p_tr.label("_start")
    p_tr.li(rvlib.T0, 3)
    p_tr.blt(rvlib.A0, rvlib.T0, "tr_usage")
    p_tr.emit(rvasm.ld(rvlib.S0, rvlib.A1, 8))   # S0 = set1
    p_tr.emit(rvasm.ld(rvlib.S1, rvlib.A1, 16))  # S1 = set2
    p_tr.label("tr_loop")
    p_tr.li(rvlib.A1, tr_buf)
    rvlib.sys_read_fd_reg_cnt(p_tr, fd=0, buf_reg=rvlib.A1, count=1)
    p_tr.beq(rvlib.A0, rvlib.ZERO, "tr_done")
    p_tr.blt(rvlib.A0, rvlib.ZERO, "tr_done")
    p_tr.li(rvlib.A1, tr_buf)
    p_tr.emit(rvasm.lbu(rvlib.S2, rvlib.A1, 0))  # S2 = char
    # Search in set1
    p_tr.li(rvlib.S3, 0)  # index
    p_tr.label("tr_search")
    p_tr.emit(rvasm.add(rvlib.T0, rvlib.S0, rvlib.S3))
    p_tr.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_tr.beq(rvlib.T1, rvlib.ZERO, "tr_output")
    p_tr.bne(rvlib.T1, rvlib.S2, "tr_next")
    # Found - get replacement from set2
    p_tr.emit(rvasm.add(rvlib.T0, rvlib.S1, rvlib.S3))
    p_tr.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_tr.beq(rvlib.T1, rvlib.ZERO, "tr_output")
    p_tr.emit(rvasm.addi(rvlib.S2, rvlib.T1, 0))
    p_tr.jal(rvlib.ZERO, "tr_output")
    p_tr.label("tr_next")
    p_tr.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_tr.jal(rvlib.ZERO, "tr_search")
    p_tr.label("tr_output")
    p_tr.li(rvlib.A1, tr_buf)
    p_tr.emit(rvasm.sb(rvlib.S2, rvlib.A1, 0))
    rvlib.sys_write_fd_reg_cnt(p_tr, fd=1, buf_reg=rvlib.A1, count=1)
    p_tr.jal(rvlib.ZERO, "tr_loop")
    p_tr.label("tr_done")
    rvlib.sys_exit(p_tr, 0)
    p_tr.label("tr_usage")
    rvlib.sys_write(p_tr, fd=1, buf=tr_usage, count=len(b"usage: tr <set1> <set2>\n"))
    rvlib.sys_exit(p_tr, 1)
    tr_rvx = p_tr.build_rvx()
    tr_ino = fs.create_file("/bin/tr")
    fs.write_inode(tr_ino, 0, tr_rvx, truncate=True)

    # cut - cut fields from lines (cut -d<delim> -f<field>)
    p_cut = Program(entry=0x1000_0000)
    cut_usage = p_cut.db(b"usage: cut -d<delim> -f<field>\n")
    p_cut.align_data(8)
    cut_buf = p_cut.db(b"\x00" * 256)
    p_cut.label("_start")
    p_cut.li(rvlib.T0, 3)
    p_cut.blt(rvlib.A0, rvlib.T0, "cut_usage")
    # Parse -d<delim> from argv[1]
    p_cut.emit(rvasm.ld(rvlib.T0, rvlib.A1, 8))
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_cut.li(rvlib.T2, 45)  # '-'
    p_cut.bne(rvlib.T1, rvlib.T2, "cut_usage")
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 1))
    p_cut.li(rvlib.T2, 100)  # 'd'
    p_cut.bne(rvlib.T1, rvlib.T2, "cut_usage")
    p_cut.emit(rvasm.lbu(rvlib.S0, rvlib.T0, 2))  # S0 = delimiter
    # Parse -f<field> from argv[2]
    p_cut.emit(rvasm.ld(rvlib.T0, rvlib.A1, 16))
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_cut.li(rvlib.T2, 45)  # '-'
    p_cut.bne(rvlib.T1, rvlib.T2, "cut_usage")
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 1))
    p_cut.li(rvlib.T2, 102)  # 'f'
    p_cut.bne(rvlib.T1, rvlib.T2, "cut_usage")
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 2))
    p_cut.emit(rvasm.addi(rvlib.S1, rvlib.T1, -48))  # S1 = field (1-based)
    p_cut.label("cut_readline")
    p_cut.li(rvlib.S2, 0)  # line length
    p_cut.label("cut_readchar")
    p_cut.li(rvlib.T0, 255)
    p_cut.bge(rvlib.S2, rvlib.T0, "cut_process")
    p_cut.li(rvlib.A1, cut_buf)
    p_cut.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S2))
    rvlib.sys_read_fd_reg_cnt(p_cut, fd=0, buf_reg=rvlib.A1, count=1)
    p_cut.beq(rvlib.A0, rvlib.ZERO, "cut_eof")
    p_cut.blt(rvlib.A0, rvlib.ZERO, "cut_done")
    p_cut.li(rvlib.A1, cut_buf)
    p_cut.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S2))
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_cut.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_cut.li(rvlib.T2, 10)
    p_cut.beq(rvlib.T1, rvlib.T2, "cut_process")
    p_cut.jal(rvlib.ZERO, "cut_readchar")
    p_cut.label("cut_eof")
    p_cut.beq(rvlib.S2, rvlib.ZERO, "cut_done")
    p_cut.label("cut_process")
    # Find field S1 (1-based)
    p_cut.li(rvlib.S3, 0)  # cursor
    p_cut.li(rvlib.S4, 1)  # current field
    p_cut.emit(rvasm.addi(rvlib.S5, rvlib.S3, 0))  # field start
    p_cut.label("cut_scan")
    p_cut.bge(rvlib.S3, rvlib.S2, "cut_output")
    p_cut.li(rvlib.A1, cut_buf)
    p_cut.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S3))
    p_cut.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_cut.li(rvlib.T2, 10)
    p_cut.beq(rvlib.T1, rvlib.T2, "cut_output")
    p_cut.bne(rvlib.T1, rvlib.S0, "cut_scan_next")
    # Found delimiter
    p_cut.beq(rvlib.S4, rvlib.S1, "cut_output")
    p_cut.emit(rvasm.addi(rvlib.S4, rvlib.S4, 1))
    p_cut.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_cut.emit(rvasm.addi(rvlib.S5, rvlib.S3, 0))
    p_cut.jal(rvlib.ZERO, "cut_scan")
    p_cut.label("cut_scan_next")
    p_cut.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_cut.jal(rvlib.ZERO, "cut_scan")
    p_cut.label("cut_output")
    p_cut.bne(rvlib.S4, rvlib.S1, "cut_readline")
    p_cut.emit(rvasm.sub(rvlib.T0, rvlib.S3, rvlib.S5))
    p_cut.li(rvlib.A1, cut_buf)
    p_cut.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S5))
    rvlib.sys_write_fd_reg_reg(p_cut, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.T0)
    # Print newline
    p_cut.li(rvlib.A1, cut_buf)
    p_cut.li(rvlib.T0, 10)
    p_cut.emit(rvasm.sb(rvlib.T0, rvlib.A1, 0))
    rvlib.sys_write_fd_reg_cnt(p_cut, fd=1, buf_reg=rvlib.A1, count=1)
    p_cut.jal(rvlib.ZERO, "cut_readline")
    p_cut.label("cut_done")
    rvlib.sys_exit(p_cut, 0)
    p_cut.label("cut_usage")
    rvlib.sys_write(p_cut, fd=1, buf=cut_usage, count=len(b"usage: cut -d<delim> -f<field>\n"))
    rvlib.sys_exit(p_cut, 1)
    cut_rvx = p_cut.build_rvx()
    cut_ino = fs.create_file("/bin/cut")
    fs.write_inode(cut_ino, 0, cut_rvx, truncate=True)

    # sort - sort lines (simple bubble sort)
    p_sort = Program(entry=0x1000_0000)
    p_sort.align_data(8)
    sort_buf = p_sort.db(b"\x00" * 2048)
    p_sort.align_data(8)
    sort_lines = p_sort.db(b"\x00" * (8 * 64))  # up to 64 line pointers
    p_sort.align_data(8)
    sort_lens = p_sort.db(b"\x00" * (8 * 64))   # line lengths
    p_sort.label("_start")
    # Check if file argument provided
    p_sort.li(rvlib.T0, 2)
    p_sort.blt(rvlib.A0, rvlib.T0, "sort_stdin")
    # Open file from argv[1]
    p_sort.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_sort, path_reg=rvlib.A0)
    p_sort.blt(rvlib.A0, rvlib.ZERO, "sort_done")
    p_sort.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))
    p_sort.jal(rvlib.ZERO, "sort_start")
    p_sort.label("sort_stdin")
    p_sort.li(rvlib.S0, 0)  # fd = stdin
    p_sort.label("sort_start")
    p_sort.li(rvlib.S1, 0)  # buffer offset
    p_sort.li(rvlib.S2, 0)  # line count
    p_sort.label("sort_readline")
    p_sort.li(rvlib.T0, 64)
    p_sort.bge(rvlib.S2, rvlib.T0, "sort_do_sort")
    # Store line start
    p_sort.li(rvlib.A1, sort_lines)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S2, 3))
    p_sort.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.T0))
    p_sort.li(rvlib.T1, sort_buf)
    p_sort.emit(rvasm.add(rvlib.T1, rvlib.T1, rvlib.S1))
    p_sort.emit(rvasm.sd(rvlib.T1, rvlib.A1, 0))
    p_sort.li(rvlib.S3, 0)  # line length
    p_sort.label("sort_readchar")
    p_sort.li(rvlib.T0, 2048)
    p_sort.bge(rvlib.S1, rvlib.T0, "sort_do_sort")
    p_sort.li(rvlib.A1, sort_buf)
    p_sort.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S1))
    rvlib.sys_read_reg_reg_cnt(p_sort, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=1)
    p_sort.beq(rvlib.A0, rvlib.ZERO, "sort_eof")
    p_sort.blt(rvlib.A0, rvlib.ZERO, "sort_do_sort")
    p_sort.li(rvlib.A1, sort_buf)
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.S1))
    p_sort.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_sort.emit(rvasm.addi(rvlib.S1, rvlib.S1, 1))
    p_sort.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_sort.li(rvlib.T2, 10)
    p_sort.bne(rvlib.T1, rvlib.T2, "sort_readchar")
    # Store line length
    p_sort.li(rvlib.A1, sort_lens)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S2, 3))
    p_sort.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.sd(rvlib.S3, rvlib.A1, 0))
    p_sort.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_sort.jal(rvlib.ZERO, "sort_readline")
    p_sort.label("sort_eof")
    p_sort.beq(rvlib.S3, rvlib.ZERO, "sort_do_sort")
    # Store last line length
    p_sort.li(rvlib.A1, sort_lens)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S2, 3))
    p_sort.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.sd(rvlib.S3, rvlib.A1, 0))
    p_sort.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_sort.label("sort_do_sort")
    # Bubble sort
    p_sort.li(rvlib.S3, 0)  # i
    p_sort.label("sort_outer")
    p_sort.emit(rvasm.addi(rvlib.T0, rvlib.S2, -1))
    p_sort.bge(rvlib.S3, rvlib.T0, "sort_output")
    p_sort.emit(rvasm.addi(rvlib.S4, rvlib.S3, 1))  # j
    p_sort.label("sort_inner")
    p_sort.bge(rvlib.S4, rvlib.S2, "sort_next_i")
    # Compare lines[i] and lines[j]
    p_sort.li(rvlib.A1, sort_lines)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S3, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.ld(rvlib.S5, rvlib.T0, 0))  # S5 = lines[i]
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S4, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.ld(rvlib.S6, rvlib.T0, 0))  # S6 = lines[j]
    # String compare
    p_sort.li(rvlib.T0, 0)
    p_sort.label("sort_cmp")
    p_sort.emit(rvasm.add(rvlib.T1, rvlib.S5, rvlib.T0))
    p_sort.emit(rvasm.lbu(rvlib.T2, rvlib.T1, 0))
    p_sort.emit(rvasm.add(rvlib.T1, rvlib.S6, rvlib.T0))
    p_sort.emit(rvasm.lbu(rvlib.T3, rvlib.T1, 0))
    p_sort.li(rvlib.T4, 10)
    p_sort.beq(rvlib.T2, rvlib.T4, "sort_next_j")
    p_sort.beq(rvlib.T3, rvlib.T4, "sort_swap")
    p_sort.blt(rvlib.T2, rvlib.T3, "sort_next_j")
    p_sort.blt(rvlib.T3, rvlib.T2, "sort_swap")
    p_sort.emit(rvasm.addi(rvlib.T0, rvlib.T0, 1))
    p_sort.jal(rvlib.ZERO, "sort_cmp")
    p_sort.label("sort_swap")
    # Swap lines[i] and lines[j]
    p_sort.li(rvlib.A1, sort_lines)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S3, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.sd(rvlib.S6, rvlib.T0, 0))
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S4, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.sd(rvlib.S5, rvlib.T0, 0))
    # Swap lens[i] and lens[j]
    p_sort.li(rvlib.A1, sort_lens)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S3, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.ld(rvlib.T1, rvlib.T0, 0))
    p_sort.emit(rvasm.slli(rvlib.T2, rvlib.S4, 3))
    p_sort.emit(rvasm.add(rvlib.T2, rvlib.A1, rvlib.T2))
    p_sort.emit(rvasm.ld(rvlib.T3, rvlib.T2, 0))
    p_sort.emit(rvasm.sd(rvlib.T3, rvlib.T0, 0))
    p_sort.emit(rvasm.sd(rvlib.T1, rvlib.T2, 0))
    p_sort.label("sort_next_j")
    p_sort.emit(rvasm.addi(rvlib.S4, rvlib.S4, 1))
    p_sort.jal(rvlib.ZERO, "sort_inner")
    p_sort.label("sort_next_i")
    p_sort.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_sort.jal(rvlib.ZERO, "sort_outer")
    p_sort.label("sort_output")
    p_sort.li(rvlib.S3, 0)
    p_sort.label("sort_print")
    p_sort.bge(rvlib.S3, rvlib.S2, "sort_done")
    p_sort.li(rvlib.A1, sort_lines)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S3, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A1, rvlib.T0))
    p_sort.emit(rvasm.ld(rvlib.A1, rvlib.T0, 0))
    # Get line length from sort_lens
    p_sort.li(rvlib.A2, sort_lens)
    p_sort.emit(rvasm.slli(rvlib.T0, rvlib.S3, 3))
    p_sort.emit(rvasm.add(rvlib.T0, rvlib.A2, rvlib.T0))
    p_sort.emit(rvasm.ld(rvlib.A2, rvlib.T0, 0))
    # Write line to stdout
    rvlib.sys_write_fd_reg_reg(p_sort, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.A2)
    p_sort.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_sort.jal(rvlib.ZERO, "sort_print")
    p_sort.label("sort_done")
    rvlib.sys_exit(p_sort, 0)
    sort_rvx = p_sort.build_rvx()
    sort_ino = fs.create_file("/bin/sort")
    fs.write_inode(sort_ino, 0, sort_rvx, truncate=True)

    # sleep - sleep for N seconds (busy-wait using GETTIMEOFDAY)
    p_sleep = Program(entry=0x1000_0000)
    sleep_usage = p_sleep.db(b"usage: sleep <seconds>\n")
    p_sleep.align_data(8)
    sleep_tv = p_sleep.db(b"\x00" * 16)  # timeval struct (8 bytes sec, 8 bytes usec)
    p_sleep.label("_start")
    # Check argc
    p_sleep.li(rvlib.T0, 2)
    p_sleep.blt(rvlib.A0, rvlib.T0, "sleep_usage")
    # Get argv[1]
    p_sleep.emit(rvasm.ld(rvlib.S0, rvlib.A1, 8))  # S0 = argv[1]
    # Parse number from argv[1]
    p_sleep.li(rvlib.S1, 0)  # S1 = seconds
    p_sleep.label("sleep_parse")
    p_sleep.emit(rvasm.lbu(rvlib.T0, rvlib.S0, 0))
    p_sleep.beq(rvlib.T0, rvlib.ZERO, "sleep_start")
    p_sleep.li(rvlib.T1, 48)
    p_sleep.emit(rvasm.sub(rvlib.T0, rvlib.T0, rvlib.T1))
    # S1 = S1 * 10 = S1 * 8 + S1 * 2
    p_sleep.emit(rvasm.slli(rvlib.T1, rvlib.S1, 3))  # T1 = S1 * 8
    p_sleep.emit(rvasm.slli(rvlib.T2, rvlib.S1, 1))  # T2 = S1 * 2
    p_sleep.emit(rvasm.add(rvlib.S1, rvlib.T1, rvlib.T2))  # S1 = T1 + T2
    p_sleep.emit(rvasm.add(rvlib.S1, rvlib.S1, rvlib.T0))
    p_sleep.emit(rvasm.addi(rvlib.S0, rvlib.S0, 1))
    p_sleep.jal(rvlib.ZERO, "sleep_parse")
    p_sleep.label("sleep_start")
    # Get start time: gettimeofday(sleep_tv, NULL)
    p_sleep.li(rvlib.A0, sleep_tv)
    p_sleep.li(rvlib.A1, 0)
    p_sleep.li(rvlib.A7, int(Sysno.GETTIMEOFDAY))
    rvlib.ecall(p_sleep)
    # S2 = start seconds
    p_sleep.li(rvlib.T0, sleep_tv)
    p_sleep.emit(rvasm.ld(rvlib.S2, rvlib.T0, 0))
    p_sleep.label("sleep_loop")
    # Get current time
    p_sleep.li(rvlib.A0, sleep_tv)
    p_sleep.li(rvlib.A1, 0)
    p_sleep.li(rvlib.A7, int(Sysno.GETTIMEOFDAY))
    rvlib.ecall(p_sleep)
    # T0 = current seconds
    p_sleep.li(rvlib.T0, sleep_tv)
    p_sleep.emit(rvasm.ld(rvlib.T0, rvlib.T0, 0))
    # T1 = elapsed = current - start
    p_sleep.emit(rvasm.sub(rvlib.T1, rvlib.T0, rvlib.S2))
    # If elapsed < seconds, loop
    p_sleep.blt(rvlib.T1, rvlib.S1, "sleep_loop")
    p_sleep.label("sleep_done")
    rvlib.sys_exit(p_sleep, 0)
    p_sleep.label("sleep_usage")
    p_sleep.li(rvlib.A0, 1)
    p_sleep.li(rvlib.A1, sleep_usage)
    p_sleep.li(rvlib.A2, 23)
    p_sleep.li(rvlib.A7, int(Sysno.WRITE))
    rvlib.ecall(p_sleep)
    rvlib.sys_exit(p_sleep, 1)
    sleep_rvx = p_sleep.build_rvx()
    sleep_ino = fs.create_file("/bin/sleep")
    fs.write_inode(sleep_ino, 0, sleep_rvx, truncate=True)

    # whoami - print current user
    p_whoami = Program(entry=0x1000_0000)
    whoami_str = p_whoami.db(b"root\n")
    p_whoami.label("_start")
    rvlib.sys_write(p_whoami, fd=1, buf=whoami_str, count=5)
    rvlib.sys_exit(p_whoami, 0)
    whoami_rvx = p_whoami.build_rvx()
    whoami_ino = fs.create_file("/bin/whoami")
    fs.write_inode(whoami_ino, 0, whoami_rvx, truncate=True)

    # hostname - print system hostname
    p_hostname = Program(entry=0x1000_0000)
    hostname_str = p_hostname.db(b"simmach\n")
    p_hostname.label("_start")
    rvlib.sys_write(p_hostname, fd=1, buf=hostname_str, count=8)
    rvlib.sys_exit(p_hostname, 0)
    hostname_rvx = p_hostname.build_rvx()
    hostname_ino = fs.create_file("/bin/hostname")
    fs.write_inode(hostname_ino, 0, hostname_rvx, truncate=True)

    # date - print current timestamp (simplified)
    p_date = Program(entry=0x1000_0000)
    date_msg = p_date.db(b"SimMach OS - use 'date' for time\n")
    p_date.label("_start")
    rvlib.sys_write(p_date, fd=1, buf=date_msg, count=33)
    rvlib.sys_exit(p_date, 0)
    date_rvx = p_date.build_rvx()
    date_ino = fs.create_file("/bin/date")
    fs.write_inode(date_ino, 0, date_rvx, truncate=True)

    # tac - print file in reverse line order
    p_tac = Program(entry=0x1000_0000)
    tac_usage = p_tac.db(b"usage: tac <file>\n")
    p_tac.align_data(8)
    tac_buf = p_tac.db(b"\x00" * 4096)
    p_tac.align_data(8)
    tac_lines = p_tac.db(b"\x00" * (8 * 128))  # line start offsets
    p_tac.label("_start")
    p_tac.li(rvlib.T0, 2)
    p_tac.blt(rvlib.A0, rvlib.T0, "tac_usage")
    # Open file
    p_tac.emit(rvasm.ld(rvlib.A0, rvlib.A1, 8))
    rvlib.sys_open_ro_reg(p_tac, path_reg=rvlib.A0)
    p_tac.blt(rvlib.A0, rvlib.ZERO, "tac_done")
    p_tac.emit(rvasm.addi(rvlib.S0, rvlib.A0, 0))  # S0 = fd
    # Read entire file
    p_tac.li(rvlib.A1, tac_buf)
    rvlib.sys_read_reg_reg_cnt(p_tac, fd_reg=rvlib.S0, buf_reg=rvlib.A1, count=4096)
    p_tac.blt(rvlib.A0, rvlib.ZERO, "tac_close")
    p_tac.emit(rvasm.addi(rvlib.S1, rvlib.A0, 0))  # S1 = bytes read
    rvlib.sys_close(p_tac, fd_reg=rvlib.S0)
    # Find line starts
    p_tac.li(rvlib.S2, 0)  # line count
    p_tac.li(rvlib.S3, 0)  # current offset
    # First line starts at 0
    p_tac.li(rvlib.T0, tac_lines)
    p_tac.li(rvlib.T1, 0)
    p_tac.emit(rvasm.sd(rvlib.T1, rvlib.T0, 0))
    p_tac.li(rvlib.S2, 1)
    # Scan for newlines
    p_tac.label("tac_scan")
    p_tac.bge(rvlib.S3, rvlib.S1, "tac_print")
    p_tac.li(rvlib.T0, tac_buf)
    p_tac.emit(rvasm.add(rvlib.T0, rvlib.T0, rvlib.S3))
    p_tac.emit(rvasm.lbu(rvlib.T1, rvlib.T0, 0))
    p_tac.emit(rvasm.addi(rvlib.S3, rvlib.S3, 1))
    p_tac.li(rvlib.T2, 10)
    p_tac.bne(rvlib.T1, rvlib.T2, "tac_scan")
    # Found newline, store next line start
    p_tac.li(rvlib.T0, 128)
    p_tac.bge(rvlib.S2, rvlib.T0, "tac_print")
    p_tac.li(rvlib.T0, tac_lines)
    p_tac.emit(rvasm.slli(rvlib.T1, rvlib.S2, 3))
    p_tac.emit(rvasm.add(rvlib.T0, rvlib.T0, rvlib.T1))
    p_tac.emit(rvasm.sd(rvlib.S3, rvlib.T0, 0))
    p_tac.emit(rvasm.addi(rvlib.S2, rvlib.S2, 1))
    p_tac.jal(rvlib.ZERO, "tac_scan")
    # Print lines in reverse
    p_tac.label("tac_print")
    p_tac.emit(rvasm.addi(rvlib.S2, rvlib.S2, -1))
    p_tac.blt(rvlib.S2, rvlib.ZERO, "tac_done")
    # Get line start
    p_tac.li(rvlib.T0, tac_lines)
    p_tac.emit(rvasm.slli(rvlib.T1, rvlib.S2, 3))
    p_tac.emit(rvasm.add(rvlib.T0, rvlib.T0, rvlib.T1))
    p_tac.emit(rvasm.ld(rvlib.S3, rvlib.T0, 0))  # S3 = line start
    # Get next line start or end of file
    p_tac.emit(rvasm.addi(rvlib.T2, rvlib.S2, 1))
    p_tac.li(rvlib.T3, tac_lines)
    p_tac.emit(rvasm.slli(rvlib.T4, rvlib.T2, 3))
    p_tac.emit(rvasm.add(rvlib.T3, rvlib.T3, rvlib.T4))
    p_tac.emit(rvasm.ld(rvlib.S4, rvlib.T3, 0))  # S4 = next line start
    # Calculate line length
    p_tac.emit(rvasm.sub(rvlib.A2, rvlib.S4, rvlib.S3))
    # Print line
    p_tac.li(rvlib.A1, tac_buf)
    p_tac.emit(rvasm.add(rvlib.A1, rvlib.A1, rvlib.S3))
    rvlib.sys_write_fd_reg_reg(p_tac, fd=1, buf_reg=rvlib.A1, count_reg=rvlib.A2)
    p_tac.jal(rvlib.ZERO, "tac_print")
    p_tac.label("tac_close")
    rvlib.sys_close(p_tac, fd_reg=rvlib.S0)
    p_tac.label("tac_done")
    rvlib.sys_exit(p_tac, 0)
    p_tac.label("tac_usage")
    rvlib.sys_write(p_tac, fd=1, buf=tac_usage, count=18)
    rvlib.sys_exit(p_tac, 1)
    tac_rvx = p_tac.build_rvx()
    tac_ino = fs.create_file("/bin/tac")
    fs.write_inode(tac_ino, 0, tac_rvx, truncate=True)

    # env - print environment variables (simulated)
    p_env = Program(entry=0x1000_0000)
    env_str = p_env.db(b"PATH=/bin\nHOME=/\nUSER=root\nSHELL=/bin/sh\n")
    p_env.label("_start")
    rvlib.sys_write(p_env, fd=1, buf=env_str, count=42)
    rvlib.sys_exit(p_env, 0)
    env_rvx = p_env.build_rvx()
    env_ino = fs.create_file("/bin/env")
    fs.write_inode(env_ino, 0, env_rvx, truncate=True)

    # tty - print terminal name
    p_tty = Program(entry=0x1000_0000)
    tty_str = p_tty.db(b"/dev/console\n")
    p_tty.label("_start")
    rvlib.sys_write(p_tty, fd=1, buf=tty_str, count=13)
    rvlib.sys_exit(p_tty, 0)
    tty_rvx = p_tty.build_rvx()
    tty_ino = fs.create_file("/bin/tty")
    fs.write_inode(tty_ino, 0, tty_rvx, truncate=True)

    # groups - print group memberships
    p_groups = Program(entry=0x1000_0000)
    groups_str = p_groups.db(b"root\n")
    p_groups.label("_start")
    rvlib.sys_write(p_groups, fd=1, buf=groups_str, count=5)
    rvlib.sys_exit(p_groups, 0)
    groups_rvx = p_groups.build_rvx()
    groups_ino = fs.create_file("/bin/groups")
    fs.write_inode(groups_ino, 0, groups_rvx, truncate=True)

    # arch - print machine architecture
    p_arch = Program(entry=0x1000_0000)
    arch_str = p_arch.db(b"riscv64\n")
    p_arch.label("_start")
    rvlib.sys_write(p_arch, fd=1, buf=arch_str, count=8)
    rvlib.sys_exit(p_arch, 0)
    arch_rvx = p_arch.build_rvx()
    arch_ino = fs.create_file("/bin/arch")
    fs.write_inode(arch_ino, 0, arch_rvx, truncate=True)

    sh = Program(entry=0x1000_0000)

    prompt = sh.db(b"sh$ ")
    nl = sh.db(b"\n")
    cr = sh.db(b"\r")
    clreol = sh.db(b"\x1b[K")
    bsseq = sh.db(b"\b \b")
    sp = sh.db(b" ")
    helpmsg = sh.db(b"builtins: help exit echo cat ls cd pwd status set unset export mkdir rm mv touch stat sleep pid ppid\n")
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
    mkdir_usage = sh.db(b"usage: mkdir <path>\n")
    mkdir_fail = sh.db(b"mkdir failed\n")
    rm_usage = sh.db(b"usage: rm <path>\n")
    rm_fail = sh.db(b"rm failed\n")
    mv_usage = sh.db(b"usage: mv <old> <new>\n")
    mv_fail = sh.db(b"mv failed\n")
    touch_usage = sh.db(b"usage: touch <file>\n")
    touch_fail = sh.db(b"touch failed\n")
    stat_usage = sh.db(b"usage: stat <path>\n")
    stat_fail = sh.db(b"stat failed\n")
    stat_type = sh.db(b"type: ")
    stat_file = sh.db(b"file\n")
    stat_dir = sh.db(b"dir\n")
    stat_inum = sh.db(b"inum: ")
    stat_size = sh.db(b"size: ")
    sleep_usage = sh.db(b"usage: sleep <ms>\n")
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
    cmd_set = sh.db(b"set\x00")
    cmd_unset = sh.db(b"unset\x00")
    cmd_export = sh.db(b"export\x00")
    cmd_mkdir = sh.db(b"mkdir\x00")
    cmd_rm = sh.db(b"rm\x00")
    cmd_mv = sh.db(b"mv\x00")
    cmd_touch = sh.db(b"touch\x00")
    cmd_stat = sh.db(b"stat\x00")
    cmd_sleep = sh.db(b"sleep\x00")
    cmd_pid = sh.db(b"pid\x00")
    cmd_ppid = sh.db(b"ppid\x00")
    var_equals = sh.db(b"=")
    var_nl = sh.db(b"\n")

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
    statbuf = sh.db(b"\x00" * 16)
    sh.align_data(8)
    statusbuf = sh.db(b"\x00" * 8)
    # Variable system storage
    sh.align_data(8)
    varcount = sh.db(b"\x00" * 8)  # Number of variables
    sh.align_data(8)
    varnames = sh.db(b"\x00" * (32 * 32))  # 32 variable names, 32 bytes each
    sh.align_data(8)
    varvalues = sh.db(b"\x00" * (128 * 32))  # 32 variable values, 128 bytes each
    sh.align_data(8)
    expbuf = sh.db(b"\x00" * 512)  # Expansion buffer for variable substitution

    A0 = rvlib.A0
    A1 = rvlib.A1
    A2 = rvlib.A2
    A3 = rvlib.A3
    A7 = rvlib.A7
    T0 = rvlib.T0
    T1 = rvlib.T1
    T2 = rvlib.T2
    T3 = rvlib.T3
    T4 = rvlib.T4
    T5 = rvlib.T5
    S0 = rvlib.S0
    S1 = rvlib.S1
    S2 = rvlib.S2
    S3 = rvlib.S3
    S4 = rvlib.S4
    S5 = rvlib.S5
    S6 = rvlib.S6

    # Register assignments for shell state
    REG_IOBUF = rvlib.S7
    REG_DIRENTBUF = rvlib.S8
    REG_CWDBUF = rvlib.S9
    REG_LAST_STATUS = rvlib.S10
    REG_BIN_PREFIX = rvlib.S11
    REG_PATH_SCRATCH = rvlib.T3
    REG_PIPEBUF_ADDR = rvlib.T4
    REG_REDIR_META_ADDR = rvlib.T5
    REG_PREV_PIPE_READ = rvlib.T6
    REG_CURRENT_STAGE = rvlib.A5
    REG_STAGE_COUNT = rvlib.A6
    REG_TOK_COUNT = rvlib.S4
    REG_CMD_NAME = rvlib.S5

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
        reg_hist_idx=rvlib.A4,
        reg_line_len=rvlib.A5,
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
        expbuf=expbuf,
        varcount=varcount,
        varnames=varnames,
        varvalues=varvalues,
    )

    _gen_sh_exec(
        sh,
        stageargvbuf=stageargvbuf,
        stagepathbuf=stagepathbuf,
        pipebuf_reg=REG_PIPEBUF_ADDR,
        statusbuf=statusbuf,
        reg_status_addr=rvlib.S3,
        redirmeta_reg=REG_REDIR_META_ADDR,
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
        cmd_set=cmd_set,
        cmd_unset=cmd_unset,
        cmd_export=cmd_export,
        cmd_mkdir=cmd_mkdir,
        cmd_rm=cmd_rm,
        cmd_mv=cmd_mv,
        cmd_touch=cmd_touch,
        cmd_stat=cmd_stat,
        cmd_sleep=cmd_sleep,
        cmd_pid=cmd_pid,
        cmd_ppid=cmd_ppid,
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
        varcount=varcount,
        varnames=varnames,
        varvalues=varvalues,
        var_equals=var_equals,
        mkdir_usage=mkdir_usage,
        mkdir_fail=mkdir_fail,
        rm_usage=rm_usage,
        rm_fail=rm_fail,
        mv_usage=mv_usage,
        mv_fail=mv_fail,
        touch_usage=touch_usage,
        touch_fail=touch_fail,
        stat_usage=stat_usage,
        stat_fail=stat_fail,
        stat_type=stat_type,
        stat_file=stat_file,
        stat_dir=stat_dir,
        stat_inum=stat_inum,
        stat_size=stat_size,
        statbuf=statbuf,
        sleep_usage=sleep_usage,
    )

    _gen_sh_utils(sh, iobuf_reg=REG_IOBUF)

    sh_rvx = sh.build_rvx()
    sh_ino = fs.create_file("/bin/sh")
    fs.write_inode(sh_ino, 0, sh_rvx, truncate=True)
