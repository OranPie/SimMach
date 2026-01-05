from __future__ import annotations

from enum import IntEnum

PAGE_SIZE = 4096

LITTLE_ENDIAN = "<"

# mmap ABI (minimal)
PROT_READ = 1 << 0
PROT_WRITE = 1 << 1
PROT_EXEC = 1 << 2

MAP_ANON = 1 << 0
MAP_FIXED = 1 << 1
MAP_FILE = 1 << 2
MAP_SHARED = 1 << 3

OBJECT_HEADER_SIZE = 16
HANDLE_RECORD_SIZE = 32
STRING_BODY_SIZE = 48
STRING_OBJECT_SIZE = 64
HANDLE_TABLE_HEADER_SIZE = 64

MAGIC_OBJECT_HEADER = 0x4F424A01
MAGIC_HANDLE_TABLE_HEADER = 0x48444C45

HANDLE_TABLE_VERSION = 1
HANDLE_RECORD_VERSION = 1


class HandleType(IntEnum):
    Int64 = 1
    Bytes = 2
    String = 3
    Inode = 4


class Errno(IntEnum):
    ENOENT = -2
    ECHILD = -10
    EAGAIN = -11
    EBADF = -9
    ENOMEM = -12
    EACCES = -13
    EFAULT = -14
    EINVAL = -22


class Sysno(IntEnum):
    EXIT = 1
    WRITE = 2
    READ = 3
    OPEN = 4
    CLOSE = 5
    MMAP = 6
    MUNMAP = 7
    BRK = 8
    GETTIMEOFDAY = 9
    YIELD = 10
    CALC = 11
    FORK = 12
    EXECVE = 13
    WAITPID = 14
    READKEY = 15
    CHDIR = 16
    GETCWD = 17
    PIPE = 18
    DUP2 = 19


class CalcOp(IntEnum):
    ADD = 1
    SUB = 2
    MUL = 3
    DIV = 4
    AND = 5
    OR = 6
    XOR = 7
    SHL = 8
    SHR = 9
    CMP = 10


class CalcFlags(IntEnum):
    SIGNED = 1 << 0
    TRAP_OVERFLOW = 1 << 1
