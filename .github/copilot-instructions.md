# SimMach Copilot Instructions

SimMach is an educational OS + machine simulator written in Python. It models virtual memory (Sv39-style), a minimal kernel with syscalls, a toy filesystem (BetterFS), and a RISC-V RV64 interpreter — all wired end-to-end.

## Running demos (the test suite)

Run from the project root. There is no dedicated test framework; demos serve as smoke tests.

```bash
# Run any demo
python3 -m demos.m15_init_v1_newapi_demo

# Run the SimScript demos (m17+)
python3 -m demos.m17_simscript_demo
python3 -m demos.m18_simscript_init_demo

# Run the interactive shell
python3 -m simos

# Run a single demo (replace mXX with the milestone number)
python3 -m demos.m11_rvx_exec_demo
```

## Architecture

### Two main layers

**`simmach/`** — hardware + kernel simulation:
- `mem.py` — `PhysMem`, `FrameAllocator`, `AddressSpace`, Sv39 page table, TLB, `PageFlags`
- `kernel.py` — `Kernel` class, syscall dispatch, process lifecycle, RVX1 loader
- `riscv.py` — `RiscVCPU`, RV64I interpreter
- `fs.py` — `TinyFS` (read-only) and `BetterFS` (writable, inode + bitmap allocator)
- `proc.py` — `Process`, `Thread`, `OpenFile`, mmap bookkeeping
- `rvexe.py` — RVX1 executable format parser/builder
- `rvprog.py` — `Program` builder (labels, fixups, `build_rvx()`); `li()` supports 32-bit immediates only
- `rvasm.py` — RV64 instruction encoders (emit 32-bit instruction words); includes RV64M (`mul`/`div`/`rem`) and pseudo-instructions (`seqz`/`snez`)
- `rvlib.py` — userland syscall snippets (write, open, fork, wait, mmap, exit) targeting the RV syscall ABI
- `simscript/` — **SimScript compiler** (high-level Python-like language → RVX1); see below
- `alu.py` — `MemoryALU`, memory-descriptor-based 64-bit arithmetic with overflow capture
- `handle.py` — `HandleManager` for String/Bytes/Int64 objects
- `syscall.py` — `TrapFrame`, `SyscallTable`
- `errors.py` — `SimMachError`, `OOMError`, `InvalidAddress`, `PageFault`
- `block.py` — `BlockDevice`
- `io.py` — `ConsoleDevice`
- `path.py` — `norm_path`

**`simos/`** — OS shell layer (runs on top of `simmach`):
- `shell_env.py` — `ShellEnv`, errno name helper
- `shell_host.py` — `repl` (interactive shell loop)
- `shell_bins.py` — built-in shell commands
- `shell_runtime.py`, `shell_gen.py` — runtime and codegen helpers
- `__main__.py` — entry point (`python3 -m simos`)

**`demos/`** — milestone demos (m0–m16), numbered by implementation stage per `PLAN.md`.

**Top-level shared modules:**
- `constants.py` — all shared enums and constants: `Errno`, `Sysno`, `HandleType`, `CalcOp`, `CalcFlags`, mmap flags (`MAP_ANON/FILE/SHARED/FIXED`), open flags (`O_CREAT/O_APPEND/O_TRUNC`), layout sizes
- `structs.py` — binary-serializable dataclasses: `ObjectHeader`, `HandleTableHeader`, `HandleRecord`, `StringBody`, `Stat`, and range validators

## Key conventions

### Binary structs
All on-wire structs follow this pattern — frozen dataclass with a class-level `_STRUCT` and `to_bytes()`/`from_bytes()`:

```python
@dataclass(frozen=True, slots=True)
class HandleRecord:
    version: int = HANDLE_RECORD_VERSION
    ...
    _STRUCT: ClassVar[struct.Struct] = struct.Struct(f"{LITTLE_ENDIAN}IHHIIQII")

    def to_bytes(self) -> bytes: ...
    @classmethod
    def from_bytes(cls, data: bytes) -> "HandleRecord": ...
```

Range-checking helpers `_u8`, `_u16`, `_u32`, `_u64` are defined in `structs.py` and used inside `to_bytes()`.

### Constants and enums
- All magic numbers, layout sizes, flags, errno values, and syscall numbers go in `constants.py`
- `VirtAddr: TypeAlias = int` is defined in `structs.py`; use it for all virtual address parameters

### Writing RVX1 user programs (in demos)
**Preferred (new):** Use SimScript — `simmach/simscript/`:

```python
from simmach.simscript import compile as simscript_compile

src = """
def main():
    write(1, "hello\\n")
    x = 6 * 7
    if x == 42:
        write(1, "ok\\n")
    exit(0)
"""
rvx = simscript_compile(src)
```

**Lower-level:** Use `rvprog.Program` + `rvasm.*` + `rvlib.*` directly (needed for demos predating m17):

```python
p = Program(entry=0x1000_0000, text_vaddr=0x1000_0000, data_vaddr=0x1000_4000)
msg = p.db(b"hello\n")
p.label("start")
rvlib.sys_write(p, fd=1, buf=msg, count=6)
rvlib.sys_exit(p, code=0)
exe = p.build_rvx()
```

### SimScript language (`simmach/simscript/`)
Pipeline: `src → lexer.py → parser.py → codegen.py → Program → build_rvx()`.

- **Types:** single type `i64` (also used as pointer); string literals → data segment address
- **Variables:** auto-allocated to callee-saved regs `s0`–`s11`; spill to stack beyond 12
- **Builtins:** `write(fd, buf[, n])`, `read`, `open(path, flags)`, `close`, `exit`, `fork`, `waitpid`, `mmap`, `munmap`, `getpid`, `getppid`, `alloca`, `deref64`, `store64`, `println`
- `write(fd, "str")` with 2 args auto-computes string length
- String literals are 8-byte aligned in the data segment (required for `deref64`)
- `p.li()` only supports 32-bit immediates; use `deref64("...")` to load larger values from the data segment

### Syscall ABI (RV64 user programs)
- Syscall number in `a7` (register 17), arguments in `a0`–`a5`
- Return value in `a0`: `>= 0` success, `< 0` errno (e.g., `-12` = ENOMEM)
- Syscall numbers are defined as `Sysno` in `constants.py`

### Error hierarchy
- `OOMError` — frame/heap allocation failed
- `InvalidAddress` — unmapped or bad virtual address
- `PageFault(InvalidAddress)` — page table miss with `virt_addr` field

### Memory layout (user address space)
- Text segment: `0x1000_0000` (typical)
- Data segment: `0x1000_4000` (typical)
- Stack: high user address, grown down
- `PAGE_SIZE = 4096`; all mappings are page-aligned

### Filesystem
- `open` flags: `O_CREAT=1`, `O_APPEND=2`, `O_TRUNC=4`
- `BetterFS` supports directories, inodes, bitmap allocator, and `MAP_SHARED` writeback on `munmap`/`exit`/`execve`
