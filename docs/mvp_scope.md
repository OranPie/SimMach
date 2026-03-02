# SimMach MVP Scope (8-12 Weeks)

## In Scope
- Educational Unix-like kernel model with stable SimMach syscall ABI.
- Process lifecycle (`fork`, `execve`, `waitpid`, `exit`) correctness.
- Virtual memory and user-pointer safety (`mmap`, `munmap`, user copy helpers).
- Filesystem + fd + pipe semantics for local workloads.
- SimScript as primary userland language targeting RVX1 binaries.
- Executable conformance suite as release gate.

## Out of Scope
- Networking stack (sockets/TCP/UDP).
- Multi-core SMP scheduling.
- Dynamic linking / full ELF compatibility as primary executable path.
- Tick-preemptive scheduling (MVP stays cooperative).

## Compatibility Target
- Freeze current `constants.Sysno` numeric ABI as the MVP public interface.
- Preserve return-value semantics based on `constants.Errno`.
