from __future__ import annotations

from typing import TYPE_CHECKING

from constants import O_APPEND, O_CREAT, O_TRUNC, MAP_ANON, MAP_FILE, MAP_SHARED, PROT_READ, PROT_WRITE, Sysno
from simmach import rvasm
from .regalloc import A0, A1, A2, A3, A4, A5, A7, SP

if TYPE_CHECKING:
    from simmach.rvprog import Program


# Each builtin is a function: (p: Program, arg_regs: list[int], dest_reg: int) -> None
# arg_regs: registers already holding evaluated argument values
# dest_reg: register to put the return value into (may equal A0)

def _ecall(p: "Program") -> None:
    p.emit(rvasm.ecall())


def _mov(p: "Program", dst: int, src: int) -> None:
    if dst != src:
        p.emit(rvasm.addi(dst, src, 0))


def _syscall1(p: "Program", sysno: Sysno, arg_regs: list, dest: int) -> None:
    _mov(p, A0, arg_regs[0])
    p.li(A7, int(sysno))
    _ecall(p)
    _mov(p, dest, A0)


def _syscall2(p: "Program", sysno: Sysno, arg_regs: list, dest: int) -> None:
    # Must be careful: moving to A0/A1 might clobber args already in A1/A0
    # Load in reverse arg order if needed, or use temps already in arg_regs.
    # Since arg_regs are caller-provided (t-regs or s-regs), just copy in order.
    _mov(p, A1, arg_regs[1])
    _mov(p, A0, arg_regs[0])
    p.li(A7, int(sysno))
    _ecall(p)
    _mov(p, dest, A0)


def _syscall3(p: "Program", sysno: Sysno, arg_regs: list, dest: int) -> None:
    _mov(p, A2, arg_regs[2])
    _mov(p, A1, arg_regs[1])
    _mov(p, A0, arg_regs[0])
    p.li(A7, int(sysno))
    _ecall(p)
    _mov(p, dest, A0)


def _syscall6(p: "Program", sysno: Sysno, arg_regs: list, dest: int) -> None:
    _mov(p, A5, arg_regs[5])
    _mov(p, A4, arg_regs[4])
    _mov(p, A3, arg_regs[3])
    _mov(p, A2, arg_regs[2])
    _mov(p, A1, arg_regs[1])
    _mov(p, A0, arg_regs[0])
    p.li(A7, int(sysno))
    _ecall(p)
    _mov(p, dest, A0)


# ── Built-in implementations ─────────────────────────────────────────────────

def emit_write(p: "Program", arg_regs: list, dest: int) -> None:
    """write(fd, buf, n) -> int"""
    _syscall3(p, Sysno.WRITE, arg_regs, dest)


def emit_read(p: "Program", arg_regs: list, dest: int) -> None:
    """read(fd, buf, n) -> int"""
    _syscall3(p, Sysno.READ, arg_regs, dest)


def emit_open(p: "Program", arg_regs: list, dest: int) -> None:
    """open(path, flags) -> fd"""
    p.li(A2, 0)          # mode=0
    _mov(p, A1, arg_regs[1])
    _mov(p, A0, arg_regs[0])
    p.li(A7, int(Sysno.OPEN))
    _ecall(p)
    _mov(p, dest, A0)


def emit_close(p: "Program", arg_regs: list, dest: int) -> None:
    """close(fd) -> int"""
    _syscall1(p, Sysno.CLOSE, arg_regs, dest)


def emit_exit(p: "Program", arg_regs: list, dest: int) -> None:
    """exit(code) -> never"""
    _mov(p, A0, arg_regs[0])
    p.li(A7, int(Sysno.EXIT))
    _ecall(p)


def emit_fork(p: "Program", arg_regs: list, dest: int) -> None:
    """fork() -> pid"""
    p.li(A7, int(Sysno.FORK))
    _ecall(p)
    _mov(p, dest, A0)


def emit_waitpid(p: "Program", arg_regs: list, dest: int) -> None:
    """waitpid(pid, status_ptr) -> int"""
    _syscall2(p, Sysno.WAITPID, arg_regs, dest)


def emit_mmap(p: "Program", arg_regs: list, dest: int) -> None:
    """mmap(addr, len, prot, flags, fd, off) -> ptr"""
    _syscall6(p, Sysno.MMAP, arg_regs, dest)


def emit_munmap(p: "Program", arg_regs: list, dest: int) -> None:
    """munmap(addr, len) -> int"""
    _syscall2(p, Sysno.MUNMAP, arg_regs, dest)


def emit_getpid(p: "Program", arg_regs: list, dest: int) -> None:
    p.li(A7, int(Sysno.GETPID))
    _ecall(p)
    _mov(p, dest, A0)


def emit_getppid(p: "Program", arg_regs: list, dest: int) -> None:
    p.li(A7, int(Sysno.GETPPID))
    _ecall(p)
    _mov(p, dest, A0)


def emit_alloca(p: "Program", arg_regs: list, dest: int) -> None:
    """alloca(n) -> ptr  — bumps sp down by n bytes, returns new sp"""
    # sub sp, sp, n   (addi sp, sp, -n — only works for small n)
    # For arbitrary n we need to negate and add.  Use a temp.
    tmp = arg_regs[0]  # n is already in this reg
    # sp = sp - n
    p.emit(rvasm.sub(SP, SP, tmp))
    _mov(p, dest, SP)


def emit_deref64(p: "Program", arg_regs: list, dest: int) -> None:
    """deref64(addr) -> value  — load 8 bytes"""
    p.emit(rvasm.ld(dest, arg_regs[0], 0))


def emit_store64(p: "Program", arg_regs: list, dest: int) -> None:
    """store64(addr, val) — store 8 bytes, returns 0"""
    p.emit(rvasm.sd(arg_regs[1], arg_regs[0], 0))
    if dest != 0:
        p.emit(rvasm.addi(dest, 0, 0))


def emit_deref8(p: "Program", arg_regs: list, dest: int) -> None:
    """deref8(addr) -> value  — load 1 byte (zero-extended)"""
    p.emit(rvasm.lbu(dest, arg_regs[0], 0))


def emit_store8(p: "Program", arg_regs: list, dest: int) -> None:
    """store8(addr, val) — store low byte, returns 0"""
    p.emit(rvasm.sb(arg_regs[1], arg_regs[0], 0))
    if dest != 0:
        p.emit(rvasm.addi(dest, 0, 0))


def emit_println(p: "Program", arg_regs: list, dest: int, str_len: int) -> None:
    """println(str_literal) — write to fd=1, auto-computed length.
    str_len must be pre-computed by the codegen from the StrLit node."""
    p.li(A0, 1)
    _mov(p, A1, arg_regs[0])
    p.li(A2, str_len)
    p.li(A7, int(Sysno.WRITE))
    _ecall(p)
    if dest != A0:
        _mov(p, dest, A0)


# ── Registry ─────────────────────────────────────────────────────────────────

# Maps builtin name → (emit_fn, expected_arg_count)
# println is handled specially in codegen (needs str_len)
BUILTINS: dict = {
    "write":    (emit_write,   3),
    "read":     (emit_read,    3),
    "open":     (emit_open,    2),
    "close":    (emit_close,   1),
    "exit":     (emit_exit,    1),
    "fork":     (emit_fork,    0),
    "waitpid":  (emit_waitpid, 2),
    "mmap":     (emit_mmap,    6),
    "munmap":   (emit_munmap,  2),
    "getpid":   (emit_getpid,  0),
    "getppid":  (emit_getppid, 0),
    "alloca":   (emit_alloca,  1),
    "deref64":  (emit_deref64, 1),
    "store64":  (emit_store64, 2),
    "deref8":   (emit_deref8,  1),
    "store8":   (emit_store8,  2),
    "println":  (None,         1),   # handled specially
}
