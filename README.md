# SimMach

SimMach is a small educational OS + machine simulator written in Python.

It models:

- A per-process virtual memory system (Sv39-style 3-level page table)
- A minimal kernel with syscalls (process, file, and memory primitives)
- A writable toy filesystem (BetterFS) backed by a block device
- A RISC-V RV64 interpreter capable of running small user programs
- A simple executable format (RVX1) and an `execve` loader

The project is intentionally minimal, but the components are wired end-to-end so you can:

- Build a user program as an RVX1 executable
- Store it into the filesystem
- `execve` it from user memory
- Run it via the RV64 interpreter
- Use syscalls like `fork`, `waitpid`, `mmap`, `open/read/write/close`

## Layout

- `simmach/`
  - `kernel.py`: kernel + syscall handlers + loaders + RV64 runner
  - `mem.py`: physical memory, frame allocator, address spaces, Sv39-style page table, TLB + page faults
  - `fs.py`: `TinyFS` (read-only) and `BetterFS` (writable)
  - `riscv.py`: RV64 interpreter (RV64I subset)
  - `rvexe.py`: RVX1 executable format (header + PT_LOAD segments)
  - `proc.py`: process structures (`Process`, `OpenFile`, mmap bookkeeping)
- `demos/`: runnable demos / smoke tests

## Kernel model (high level)

- **Processes**
  - Each process owns an `AddressSpace` (its own page table), backed by shared `PhysMem` + `FrameAllocator`.
  - Process lifecycle includes `exit` cleanup, zombie tracking, and `waitpid` reaping.

- **Virtual memory**
  - Sv39-style 3-level page table
  - User permissions are enforced for `user=True` memory operations.
  - A minimal TLB is used to cache `walk()` results.
  - Faults are raised as `PageFault` (inherits `InvalidAddress`) with reason fields.

- **Filesystem**
  - `TinyFS`: read-only and contiguous allocation
  - `BetterFS`: writable with inode table + bitmap block allocator + directory hierarchy

- **Executable + ISA**
  - RVX1 executable loader maps PT_LOAD segments into the process address space, then builds the initial user stack.
  - RV64 interpreter supports a useful RV64I subset; W-instructions for RV64 are included (`ADDIW/ADDW/...`).

## Syscalls (selected)

- **Process**: `exit`, `fork`, `execve`, `waitpid`
- **Files**: `open`, `read`, `write`, `close`
  - `open` flags: `flags&1` = create, `flags&2` = append
- **Memory**: `mmap`, `munmap`
  - File mapping supports `MAP_FILE` and `MAP_SHARED` writeback on `munmap/exit/execve`

## Running demos

Run from the project root:

```bash
python3 -m demos.m11_rvx_exec_demo
python3 -m demos.m12_rv_abi_callret_demo
python3 -m demos.m13_execve_argv_envp_demo
python3 -m demos.m14_rv_w_demo
python3 -m demos.m15_init_v1_demo
python3 -m demos.m15_init_v1_newapi_demo
```

Other demos are also available in `demos/`.

## Notable demos

- `demos.m11_rvx_exec_demo`
  - Writes `/bin/init` as an RVX1 executable and runs it.

- `demos.m12_rv_abi_callret_demo`
  - Verifies the RV64 user ABI (stack layout + a0/a1/a2) and CALL/RET sequences.

- `demos.m13_execve_argv_envp_demo`
  - Verifies `execve(path, argv, envp)` argument passing and stack reconstruction.

- `demos.m14_rv_w_demo`
  - Verifies RV64 W-instruction semantics (32-bit ops + sign-extension).

- `demos.m15_init_v1_demo`
  - A userland init smoke test: `fork/wait`, writes `/tmp/init.log`, and `mmap(MAP_SHARED)` file writeback.

## Convenience layers (for writing RVX1 programs)

- `simmach/rvasm.py`
  - RISC-V instruction encoders (emit a 32-bit instruction word).
  - Intended to replace per-demo `_enc_*` helpers.

- `simmach/rvprog.py`
  - `Program` builder:
    - Label + fixup support for branches/jumps
    - Helpers like `li()` and `db()`
    - Builds an RVX1 executable via `build_rvx()`

- `simmach/rvlib.py`
  - Small userland "lib" for syscall snippets (write/open/mmap/fork/wait/exit) targeting the RV syscall ABI.

The demo `demos.m15_init_v1_newapi_demo` is a reference showing how to write a non-trivial RVX1 program using these helpers.
