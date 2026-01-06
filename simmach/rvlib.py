from __future__ import annotations

from constants import O_APPEND, O_CREAT, O_TRUNC, Sysno
from simmach import rvasm
from simmach.rvprog import Program


A0 = 10
A1 = 11
A2 = 12
A3 = 13
A4 = 14
A5 = 15
A7 = 17

S0 = 8
S1 = 9
T0 = 5
T1 = 6
T2 = 7


def ecall(p: Program) -> None:
    p.emit(rvasm.ecall())


def sys_write(p: Program, *, fd: int, buf: int, count: int) -> None:
    p.li(A0, fd)
    p.li(A1, buf)
    p.li(A2, count)
    p.li(A7, int(Sysno.WRITE))
    ecall(p)


def sys_read(p: Program, *, fd: int, buf: int, count: int) -> None:
    p.li(A0, fd)
    p.li(A1, buf)
    p.li(A2, count)
    p.li(A7, int(Sysno.READ))
    ecall(p)


def sys_readkey(p: Program) -> None:
    p.li(A7, int(Sysno.READKEY))
    ecall(p)


def sys_chdir(p: Program, *, path_addr: int) -> None:
    p.li(A0, path_addr)
    p.li(A7, int(Sysno.CHDIR))
    ecall(p)


def sys_getcwd(p: Program, *, buf_addr: int, size: int) -> None:
    p.li(A0, buf_addr)
    p.li(A1, int(size))
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


def sys_munmap(p: Program, *, addr_reg: int, length: int) -> None:
    if addr_reg != A0:
        p.emit(rvasm.addi(A0, addr_reg, 0))
    p.li(A1, int(length))
    p.li(A7, int(Sysno.MUNMAP))
    ecall(p)
