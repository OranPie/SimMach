from __future__ import annotations

from typing import Optional

from constants import O_APPEND, O_CREAT, O_TRUNC, Sysno
from simmach import rvasm
from simmach.rvprog import Program


A0 = 10
A1 = 11
A2 = 12
A3 = 13
A4 = 14
A5 = 15
A6 = 16
A7 = 17

S0 = 8
S1 = 9
S2 = 18
S3 = 19
S4 = 20
S5 = 21
S6 = 22
S7 = 23
S8 = 24
S9 = 25
S10 = 26
S11 = 27

T0 = 5
T1 = 6
T2 = 7
T3 = 28
T4 = 29
T5 = 30
T6 = 31

GP = 3
TP = 4
RA = 1
SP = 2
ZERO = 0


def ecall(p: Program) -> None:
    p.emit(rvasm.ecall())


def sys_write_reg(p: Program, *, fd_reg: int, buf_reg: int, count_reg: int) -> None:
    if fd_reg != A0:
        p.emit(rvasm.addi(A0, fd_reg, 0))
    if buf_reg != A1:
        p.emit(rvasm.addi(A1, buf_reg, 0))
    if count_reg != A2:
        p.emit(rvasm.addi(A2, count_reg, 0))
    p.li(A7, int(Sysno.WRITE))
    ecall(p)


def sys_read_reg(p: Program, *, fd_reg: int, buf_reg: int, count_reg: int) -> None:
    if fd_reg != A0:
        p.emit(rvasm.addi(A0, fd_reg, 0))
    if buf_reg != A1:
        p.emit(rvasm.addi(A1, buf_reg, 0))
    if count_reg != A2:
        p.emit(rvasm.addi(A2, count_reg, 0))
    p.li(A7, int(Sysno.READ))
    ecall(p)


def sys_chdir_reg(p: Program, *, path_reg: int) -> None:
    if path_reg != A0:
        p.emit(rvasm.addi(A0, path_reg, 0))
    p.li(A7, int(Sysno.CHDIR))
    ecall(p)


def sys_getcwd_reg(p: Program, *, buf_reg: int, size_reg: int) -> None:
    if buf_reg != A0:
        p.emit(rvasm.addi(A0, buf_reg, 0))
    if size_reg != A1:
        p.emit(rvasm.addi(A1, size_reg, 0))
    p.li(A7, int(Sysno.GETCWD))
    ecall(p)


def sys_exit(p: Program, code: int) -> None:
    p.li(A0, code)
    p.li(A7, int(Sysno.EXIT))
    ecall(p)


def sys_open(p: Program, *, path_addr: int, flags: int) -> None:
    p.li(A0, path_addr)
    p.li(A1, flags)
    p.li(A2, 0)
    p.li(A7, int(Sysno.OPEN))
    ecall(p)


def sys_open_ro(p: Program, *, path_addr: int) -> None:
    sys_open(p, path_addr=path_addr, flags=0)


def sys_open_create_trunc(p: Program, *, path_addr: int) -> None:
    sys_open(p, path_addr=path_addr, flags=int(O_CREAT | O_TRUNC))


def sys_open_append(p: Program, *, path_addr: int, create: bool = False) -> None:
    flags = int(O_APPEND | (O_CREAT if create else 0))
    sys_open(p, path_addr=path_addr, flags=flags)


def sys_open_reg(p: Program, *, path_reg: int, flags: int) -> None:
    if path_reg != A0:
        p.emit(rvasm.addi(A0, path_reg, 0))
    p.li(A1, int(flags))
    p.li(A2, 0)
    p.li(A7, int(Sysno.OPEN))
    ecall(p)


def sys_open_ro_reg(p: Program, *, path_reg: int) -> None:
    sys_open_reg(p, path_reg=path_reg, flags=0)


def sys_open_create_trunc_reg(p: Program, *, path_reg: int) -> None:
    sys_open_reg(p, path_reg=path_reg, flags=int(O_CREAT | O_TRUNC))


def sys_open_append_reg(p: Program, *, path_reg: int, create: bool = False) -> None:
    flags = int(O_APPEND | (O_CREAT if create else 0))
    sys_open_reg(p, path_reg=path_reg, flags=flags)


def sys_execve_reg(p: Program, *, path_reg: int, argv_reg: int, envp_reg: Optional[int] = None) -> None:
    if path_reg != A0:
        p.emit(rvasm.addi(A0, path_reg, 0))
    if argv_reg != A1:
        p.emit(rvasm.addi(A1, argv_reg, 0))
    if envp_reg is None:
        p.li(A2, 0)
    elif envp_reg != A2:
        p.emit(rvasm.addi(A2, envp_reg, 0))
    p.li(A7, int(Sysno.EXECVE))
    ecall(p)


def sys_close(p: Program, *, fd_reg: int = A0) -> None:
    if fd_reg != A0:
        p.emit(rvasm.addi(A0, fd_reg, 0))
    p.li(A7, int(Sysno.CLOSE))
    ecall(p)


def sys_waitpid(p: Program, *, child_pid_reg: int, status_addr: int) -> None:
    if child_pid_reg != A0:
        p.emit(rvasm.addi(A0, child_pid_reg, 0))
    p.li(A1, status_addr)
    p.li(A7, int(Sysno.WAITPID))
    ecall(p)


def sys_pipe(p: Program, *, pipefd_addr: int) -> None:
    p.li(A0, pipefd_addr)
    p.li(A7, int(Sysno.PIPE))
    ecall(p)


def sys_dup2(p: Program, *, oldfd_reg: int, newfd: int) -> None:
    if oldfd_reg != A0:
        p.emit(rvasm.addi(A0, oldfd_reg, 0))
    p.li(A1, int(newfd))
    p.li(A7, int(Sysno.DUP2))
    ecall(p)


def sys_fork(p: Program) -> None:
    p.li(A7, int(Sysno.FORK))
    ecall(p)


def sys_mmap(p: Program, *, length: int, prot: int, flags: int, fd_reg: int, file_off: int = 0) -> None:
    p.li(A0, 0)
    p.li(A1, int(length))
    p.li(A2, int(prot))
    p.li(A3, int(flags))
    if fd_reg != A4:
        p.emit(rvasm.addi(A4, fd_reg, 0))
    p.li(A5, int(file_off))
    p.li(A7, int(Sysno.MMAP))
    ecall(p)


def sys_unlink_reg(p: Program, *, path_reg: int) -> None:
    if path_reg != A0:
        p.emit(rvasm.addi(A0, path_reg, 0))
    p.li(A7, int(Sysno.UNLINK))
    ecall(p)


def sys_rename_reg(p: Program, *, old_reg: int, new_reg: int) -> None:
    if old_reg != A0:
        p.emit(rvasm.addi(A0, old_reg, 0))
    if new_reg != A1:
        p.emit(rvasm.addi(A1, new_reg, 0))
    p.li(A7, int(Sysno.RENAME))
    ecall(p)


def sys_mkdir_reg(p: Program, *, path_reg: int) -> None:
    if path_reg != A0:
        p.emit(rvasm.addi(A0, path_reg, 0))
    p.li(A7, int(Sysno.MKDIR))
    ecall(p)


