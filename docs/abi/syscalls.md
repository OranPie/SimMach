# SimMach Syscall ABI (MVP)

## Calling Convention
- `a7` (`TrapFrame.rax`): syscall number (`constants.Sysno`).
- `a0..a5` (`TrapFrame.rdi/rsi/rdx/r10/r8/r9`): syscall arguments.
- return in `a0` as signed integer (`>=0` success, `<0` errno).

## Core Process/Execution
- `EXIT(code)` -> `0` and marks process zombie.
- `FORK()` -> child pid in parent, `0` in child.
- `EXECVE(path_ptr, argv_ptr, envp_ptr)` -> entry point or `-errno`.
- `WAITPID(pid|-1, status_ptr)` -> child pid, `-EAGAIN`, or `-ECHILD`.

## Core IO
- `OPEN(path_ptr, flags, mode)` -> fd or `-errno`.
- `READ(fd, buf_ptr, count)` -> bytes read or `-errno`.
- `WRITE(fd, buf_ptr, count)` -> bytes written or `-errno`.
- `CLOSE(fd)` -> `0` or `-errno`.
- `PIPE(pipefd_ptr)` -> `0` or `-errno` (`pipefd_ptr` gets two u64 fds).
- `DUP2(oldfd, newfd)` -> `newfd` or `-errno`.

## Memory
- `MMAP(addr, len, prot, flags, fd, off)` -> mapped address or `-errno`.
- `MUNMAP(addr, len)` -> `0` or `-errno`.
- `MPROTECT(addr, len, prot)` -> `0` or `-errno`.

## Error Mapping
- Invalid/unmapped user pointers -> `-EFAULT`.
- Invalid arguments/unsupported modes -> `-EINVAL`.
- Address-space/resource exhaustion -> `-ENOMEM`.
