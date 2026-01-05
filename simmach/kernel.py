from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import struct
from typing import Deque, Dict, Optional

from constants import MAP_ANON, MAP_FILE, MAP_FIXED, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE, Errno, Sysno
from simmach.errors import InvalidAddress
from simmach.exe import PF_R, PF_W, PF_X, PT_LOAD, parse_exe_v1
from simmach.exe import REG_REF_MASK
from simmach.fs import TinyFS
from simmach.io import ConsoleDevice
from simmach.alu import MemoryALU
from simmach.mem import AddressSpace, PageFlags
from simmach.proc import MmapFileMapping, OpenFile, Process, Thread
from simmach.riscv import RiscVCPU
from simmach.rvexe import MAGIC_RVEX_V1, PF_R as RV_PF_R, PF_W as RV_PF_W, PF_X as RV_PF_X, PT_LOAD as RV_PT_LOAD, parse_rvexe_v1
from simmach.syscall import SyscallTable, TrapFrame


@dataclass(slots=True)
class KernelConfig:
    stdout_fd: int = 1
    stderr_fd: int = 2


@dataclass(slots=True)
class Pipe:
    buf: bytearray
    read_off: int
    readers: int
    writers: int


@dataclass(slots=True)
class PipeEnd:
    pipe_id: int
    is_read: bool


class Kernel:
    def __init__(self, aspace: AddressSpace, *, config: Optional[KernelConfig] = None):
        # Kernel-global context: provides access to the shared PhysMem + FrameAllocator.
        # Each process will get its own AddressSpace (separate PageTable) backed by
        # the same underlying PhysMem + FrameAllocator.
        self.kernel_aspace = aspace
        self.config = config or KernelConfig()

        self.console = ConsoleDevice()
        self.fs: Optional[TinyFS] = None

        self.syscalls = SyscallTable()
        self._install_syscalls()

        self._next_pid = 1
        self._next_tid = 1
        self.processes: Dict[int, Process] = {}
        self.threads: Dict[int, Thread] = {}
        self.runq: Deque[int] = deque()

        self._next_pipe_id = 1
        self._pipes: Dict[int, Pipe] = {}

    @staticmethod
    def _norm_path(path: str) -> str:
        if not path:
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

    def _resolve_path(self, pid: int, path: str) -> str:
        if not path:
            return self._proc(pid).cwd
        if path.startswith("/"):
            return self._norm_path(path)
        base = self._proc(pid).cwd
        if not base.endswith("/"):
            base += "/"
        return self._norm_path(base + path)

    def _proc(self, pid: int) -> Process:
        return self.processes[pid]

    def create_process(self, *, parent_pid: int = 0) -> int:
        pid = self._next_pid
        self._next_pid += 1

        proc_aspace = AddressSpace(self.kernel_aspace.physmem, self.kernel_aspace.frame_allocator)
        p = Process(
            pid=pid,
            aspace=proc_aspace,
            parent_pid=int(parent_pid),
            fds={0: "console", self.config.stdout_fd: "console", self.config.stderr_fd: "console"},
        )
        self.processes[pid] = p

        if parent_pid:
            parent = self.processes.get(int(parent_pid))
            if parent is not None:
                parent.children.append(pid)
        return pid

    def _free_user_pages(self, aspace: AddressSpace) -> None:
        # Free all USER mappings in the address space.
        for virt_page_base, _, flags in list(aspace.pagetable.dump_mappings()):
            if not (flags & PageFlags.USER):
                continue
            try:
                aspace.unmap_page(virt_page_base, free_frame=True)
            except Exception:
                pass

    def _reap_process(self, pid: int) -> None:
        # Remove process and any threads.
        for tid, t in list(self.threads.items()):
            if t.pid == pid:
                del self.threads[tid]
        self.processes.pop(pid, None)

    def _mark_zombie(self, pid: int) -> None:
        p = self.processes.get(pid)
        if p is None:
            return
        parent_pid = int(p.parent_pid)
        if parent_pid:
            parent = self.processes.get(parent_pid)
            if parent is not None and pid not in parent.zombie_children:
                parent.zombie_children.append(pid)

    def create_thread(self, pid: int, script: list[tuple[int, int, int, int]]) -> int:
        tid = self._next_tid
        self._next_tid += 1
        t = Thread(tid=tid, pid=pid, script=list(script))
        self.threads[tid] = t
        self.runq.append(tid)
        return tid

    def copy_from_user(self, pid: int, user_ptr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        return self._proc(pid).aspace.read(user_ptr, size, user=True)

    def copy_to_user(self, pid: int, user_ptr: int, data: bytes) -> None:
        self._proc(pid).aspace.write(user_ptr, data, user=True)

    def read_cstring_from_user(self, pid: int, user_ptr: int, *, max_len: int = 4096) -> str:
        buf = bytearray()
        aspace = self._proc(pid).aspace
        for i in range(max_len):
            b = aspace.read(user_ptr + i, 1, user=True)
            if b == b"\x00":
                return buf.decode("utf-8")
            buf += b
        raise InvalidAddress("unterminated cstring")

    def set_fs(self, fs) -> None:
        self.fs = fs

    def _read_user_ptr_array(self, pid: int, user_ptr: int, *, max_elems: int = 64) -> list[int]:
        if user_ptr == 0:
            return []
        out: list[int] = []
        for i in range(int(max_elems)):
            try:
                raw = self.copy_from_user(pid, int(user_ptr) + i * 8, 8)
            except InvalidAddress:
                raise
            (p,) = struct.unpack("<Q", raw)
            if int(p) == 0:
                return out
            out.append(int(p))
        raise ValueError("ptr array too long")

    def _read_user_str_list(self, pid: int, user_ptr: int, *, max_elems: int = 64, max_total_bytes: int = 4096) -> list[str]:
        ptrs = self._read_user_ptr_array(pid, user_ptr, max_elems=max_elems)
        out: list[str] = []
        total = 0
        for p in ptrs:
            s = self.read_cstring_from_user(pid, int(p), max_len=max_total_bytes)
            total += len(s) + 1
            if total > int(max_total_bytes):
                raise ValueError("argv/envp too large")
            out.append(s)
        return out

    def _build_rv_initial_stack(self, pid: int, *, argv: list[str], envp: list[str]) -> None:
        p = self._proc(pid)
        aspace = p.aspace

        stack_top = 0x4000_0000
        stack_pages = 8
        stack_base = stack_top - stack_pages * 4096
        stack_flags = PageFlags.USER | PageFlags.R | PageFlags.W
        for page_base in range(stack_base, stack_top, 4096):
            aspace.map_page(page_base, stack_flags)

        sp = int(stack_top)

        def _push_bytes(b: bytes) -> int:
            nonlocal sp
            sp -= len(b)
            aspace.write(sp, b, user=True)
            return int(sp)

        def _align_down(align: int) -> None:
            nonlocal sp
            sp &= ~(int(align) - 1)

        argv_addrs: list[int] = []
        envp_addrs: list[int] = []

        for s in reversed(envp):
            addr = _push_bytes(s.encode("utf-8") + b"\x00")
            envp_addrs.append(addr)
        envp_addrs.reverse()

        for s in reversed(argv):
            addr = _push_bytes(s.encode("utf-8") + b"\x00")
            argv_addrs.append(addr)
        argv_addrs.reverse()

        _align_down(16)

        argc = len(argv_addrs)
        argv_ptrs = argv_addrs + [0]
        envp_ptrs = envp_addrs + [0]

        frame_words = 1 + len(argv_ptrs) + len(envp_ptrs)
        frame_size = frame_words * 8
        sp -= frame_size
        sp &= ~0xF

        buf = bytearray()
        buf += struct.pack("<Q", int(argc))
        for a in argv_ptrs:
            buf += struct.pack("<Q", int(a))
        for a in envp_ptrs:
            buf += struct.pack("<Q", int(a))

        aspace.write(int(sp), bytes(buf), user=True)

        p.start_rsp = int(sp)
        p.start_a0 = int(argc)
        p.start_a1 = int(sp + 8)
        p.start_a2 = int(sp + 8 + len(argv_ptrs) * 8)

    def load_executable(self, pid: int, blob: bytes, *, argv: Optional[list[str]] = None, envp: Optional[list[str]] = None) -> int:
        """Load an EXE blob into a process AddressSpace (user mappings) and return entry RIP."""
        p = self._proc(pid)
        aspace = p.aspace
        hdr, phs = parse_exe_v1(blob)
        for ph in phs:
            if ph.type != PT_LOAD:
                continue
            if ph.mem_size < ph.file_size:
                raise ValueError("bad segment sizes")

            final_flags = PageFlags.USER
            if ph.flags & PF_R:
                final_flags |= PageFlags.R
            if ph.flags & PF_W:
                final_flags |= PageFlags.W
            if ph.flags & PF_X:
                final_flags |= PageFlags.X

            # During load we need write permission to copy/zero.
            load_flags = final_flags | PageFlags.W

            seg_start = ph.vaddr
            seg_end = ph.vaddr + ph.mem_size
            page_start = seg_start - (seg_start % 4096)
            page_end = (seg_end + 4095) & ~4095

            for page_base in range(page_start, page_end, 4096):
                aspace.map_page(page_base, load_flags)

            file_data = blob[ph.file_off : ph.file_off + ph.file_size]
            if file_data:
                aspace.write(ph.vaddr, file_data, user=True)
            if ph.mem_size > ph.file_size:
                aspace.write(
                    ph.vaddr + ph.file_size,
                    b"\x00" * (ph.mem_size - ph.file_size),
                    user=True,
                )

            # Downgrade to final permissions.
            for page_base in range(page_start, page_end, 4096):
                aspace.pagetable.protect_page(page_base, final_flags)

        argv = argv or []
        envp = envp or []
        self._build_rv_initial_stack(pid, argv=argv, envp=envp)
        p.start_rip = int(hdr.entry)
        return int(hdr.entry)

    def load_rv_executable(self, pid: int, blob: bytes, *, argv: Optional[list[str]] = None, envp: Optional[list[str]] = None) -> int:
        p = self._proc(pid)
        aspace = p.aspace
        hdr, phs = parse_rvexe_v1(blob)
        for ph in phs:
            if ph.type != RV_PT_LOAD:
                continue
            if ph.mem_size < ph.file_size:
                raise ValueError("bad segment sizes")

            final_flags = PageFlags.USER
            if ph.flags & RV_PF_R:
                final_flags |= PageFlags.R
            if ph.flags & RV_PF_W:
                final_flags |= PageFlags.W
            if ph.flags & RV_PF_X:
                final_flags |= PageFlags.X

            load_flags = final_flags | PageFlags.W

            seg_start = ph.vaddr
            seg_end = ph.vaddr + ph.mem_size
            page_start = seg_start - (seg_start % 4096)
            page_end = (seg_end + 4095) & ~4095

            for page_base in range(page_start, page_end, 4096):
                aspace.map_page(page_base, load_flags)

            file_data = blob[ph.file_off : ph.file_off + ph.file_size]
            if file_data:
                aspace.write(ph.vaddr, file_data, user=True)
            if ph.mem_size > ph.file_size:
                aspace.write(
                    ph.vaddr + ph.file_size,
                    b"\x00" * (ph.mem_size - ph.file_size),
                    user=True,
                )

            for page_base in range(page_start, page_end, 4096):
                aspace.pagetable.protect_page(page_base, final_flags)

        argv = argv or []
        envp = envp or []
        self._build_rv_initial_stack(pid, argv=argv, envp=envp)
        p.start_rip = int(hdr.entry)
        return int(hdr.entry)

    def run_user_script(self, pid: int, entry: int, *, max_ops: int = 10_000) -> None:
        """Interpret the user script bytecode at entry.

        Instruction format in user memory: 4x u64 (sysno, a1, a2, a3)
        """
        # regs[0] is the implicit return register (last syscall return value)
        # regs[1].. are general-purpose and can be used to supply extra syscall args
        # mapped as: r10=regs[1], r8=regs[2], r9=regs[3].
        p = self._proc(pid)
        regs: list[int] = [0] * 8
        ip = int(entry)
        for _ in range(max_ops):
            raw = p.aspace.read(ip, 32, user=True)
            sysno = int.from_bytes(raw[0:8], "little", signed=False)
            a1 = int.from_bytes(raw[8:16], "little", signed=False)
            a2 = int.from_bytes(raw[16:24], "little", signed=False)
            a3 = int.from_bytes(raw[24:32], "little", signed=False)

            # Pseudo-instruction: MOVI
            # (0, reg_index, imm, 0)
            if sysno == 0:
                reg_index = int(a1)
                if reg_index < 0 or reg_index >= len(regs):
                    raise RuntimeError("bad reg index")
                regs[reg_index] = int(a2)
                ip += 32
                continue

            def _resolve(v: int) -> int:
                if v & REG_REF_MASK:
                    idx = int(v & 0xFF)
                    return int(regs[idx])
                return int(v)

            tf = TrapFrame(
                rax=int(sysno),
                rdi=_resolve(a1),
                rsi=_resolve(a2),
                rdx=_resolve(a3),
                r10=int(regs[1]),
                r8=int(regs[2]),
                r9=int(regs[3]),
            )
            ret = int(self.syscalls.dispatch(self, pid, tf))
            regs[0] = ret

            if sysno == int(Sysno.EXIT) and self.processes[pid].exit_status is not None:
                return
            ip += 32

        raise RuntimeError("script did not exit")

    class _RvExit(Exception):
        pass

    def run_user_rv64(self, pid: int, entry: int, *, max_steps: int = 200_000) -> None:
        p = self._proc(pid)
        cpu = RiscVCPU(p.aspace, pc=int(entry))
        if p.start_rsp is not None:
            cpu.regs[2] = int(p.start_rsp)
        if p.start_a0 is not None:
            cpu.regs[10] = int(p.start_a0)
        if p.start_a1 is not None:
            cpu.regs[11] = int(p.start_a1)
        if p.start_a2 is not None:
            cpu.regs[12] = int(p.start_a2)

        def _syscall(cpu: RiscVCPU) -> None:
            regs_before = list(cpu.regs)
            a0 = int(cpu.regs[10])
            a1 = int(cpu.regs[11])
            a2 = int(cpu.regs[12])
            a3 = int(cpu.regs[13])
            a4 = int(cpu.regs[14])
            a5 = int(cpu.regs[15])
            a7 = int(cpu.regs[17])

            tf = TrapFrame(
                rax=int(a7),
                rdi=int(a0),
                rsi=int(a1),
                rdx=int(a2),
                r10=int(a3),
                r8=int(a4),
                r9=int(a5),
            )
            ret = int(self.syscalls.dispatch(self, pid, tf))
            cpu.regs[10] = int(ret)

            # execve replaces the process AddressSpace; the CPU must switch to it.
            # Note: the RV interpreter increments PC by +4 after this callback returns,
            # so we set pc=(entry-4) here to land exactly on entry.
            if a7 == int(Sysno.EXECVE) and ret > 0:
                np = self._proc(pid)
                cpu.aspace = np.aspace
                if np.start_rsp is not None:
                    cpu.regs[2] = int(np.start_rsp)
                if np.start_a0 is not None:
                    cpu.regs[10] = int(np.start_a0)
                if np.start_a1 is not None:
                    cpu.regs[11] = int(np.start_a1)
                if np.start_a2 is not None:
                    cpu.regs[12] = int(np.start_a2)
                cpu.pc = int(ret) - 4

            if a7 == int(Sysno.FORK) and ret > 0:
                child_pid = int(ret)
                child_proc = self._proc(child_pid)
                child_cpu = RiscVCPU(child_proc.aspace, pc=int(cpu.pc + 4))
                child_cpu.regs = list(regs_before)
                child_cpu.regs[10] = 0
                if child_proc.start_rsp is not None:
                    child_cpu.regs[2] = int(child_proc.start_rsp)

                def _child_syscall(child_cpu: RiscVCPU) -> None:
                    ca0 = int(child_cpu.regs[10])
                    ca1 = int(child_cpu.regs[11])
                    ca2 = int(child_cpu.regs[12])
                    ca3 = int(child_cpu.regs[13])
                    ca4 = int(child_cpu.regs[14])
                    ca5 = int(child_cpu.regs[15])
                    ca7 = int(child_cpu.regs[17])
                    ctf = TrapFrame(
                        rax=int(ca7),
                        rdi=int(ca0),
                        rsi=int(ca1),
                        rdx=int(ca2),
                        r10=int(ca3),
                        r8=int(ca4),
                        r9=int(ca5),
                    )
                    cret = int(self.syscalls.dispatch(self, child_pid, ctf))
                    child_cpu.regs[10] = int(cret)

                    if ca7 == int(Sysno.EXECVE) and cret > 0:
                        cp = self._proc(child_pid)
                        child_cpu.aspace = cp.aspace
                        if cp.start_rsp is not None:
                            child_cpu.regs[2] = int(cp.start_rsp)
                        if cp.start_a0 is not None:
                            child_cpu.regs[10] = int(cp.start_a0)
                        if cp.start_a1 is not None:
                            child_cpu.regs[11] = int(cp.start_a1)
                        if cp.start_a2 is not None:
                            child_cpu.regs[12] = int(cp.start_a2)
                        child_cpu.pc = int(cret) - 4

                    if ca7 == int(Sysno.EXIT) and self.processes[child_pid].exit_status is not None:
                        raise Kernel._RvExit()

                try:
                    child_cpu.run(_child_syscall, max_steps=max_steps)
                except Kernel._RvExit:
                    pass
            if a7 == int(Sysno.EXIT) and self.processes[pid].exit_status is not None:
                raise Kernel._RvExit()

        try:
            cpu.run(_syscall, max_steps=max_steps)
        except Kernel._RvExit:
            return

    def _install_syscalls(self) -> None:
        self.syscalls.register(int(Sysno.EXIT), Kernel._sys_exit)
        self.syscalls.register(int(Sysno.YIELD), Kernel._sys_yield)
        self.syscalls.register(int(Sysno.WRITE), Kernel._sys_write)
        self.syscalls.register(int(Sysno.OPEN), Kernel._sys_open)
        self.syscalls.register(int(Sysno.READ), Kernel._sys_read)
        self.syscalls.register(int(Sysno.CLOSE), Kernel._sys_close)
        self.syscalls.register(int(Sysno.MMAP), Kernel._sys_mmap)
        self.syscalls.register(int(Sysno.MUNMAP), Kernel._sys_munmap)
        self.syscalls.register(int(Sysno.CALC), Kernel._sys_calc)
        self.syscalls.register(int(Sysno.FORK), Kernel._sys_fork)
        self.syscalls.register(int(Sysno.EXECVE), Kernel._sys_execve)
        self.syscalls.register(int(Sysno.WAITPID), Kernel._sys_waitpid)
        self.syscalls.register(int(Sysno.READKEY), Kernel._sys_readkey)
        self.syscalls.register(int(Sysno.CHDIR), Kernel._sys_chdir)
        self.syscalls.register(int(Sysno.GETCWD), Kernel._sys_getcwd)
        self.syscalls.register(int(Sysno.PIPE), Kernel._sys_pipe)
        self.syscalls.register(int(Sysno.DUP2), Kernel._sys_dup2)

    def _pipe(self, pipe_id: int) -> Pipe:
        return self._pipes[pipe_id]

    def _pipe_incref(self, pe: PipeEnd) -> None:
        p = self._pipe(int(pe.pipe_id))
        if pe.is_read:
            p.readers += 1
        else:
            p.writers += 1

    def _pipe_decref(self, pe: PipeEnd) -> None:
        p = self._pipe(int(pe.pipe_id))
        if pe.is_read:
            p.readers -= 1
        else:
            p.writers -= 1
        if p.readers <= 0 and p.writers <= 0:
            self._pipes.pop(int(pe.pipe_id), None)

    def _sys_chdir(self, pid: int, tf: TrapFrame) -> int:
        if self.fs is None:
            return int(Errno.EINVAL)
        path_ptr = int(tf.rdi)
        try:
            path_raw = self.read_cstring_from_user(pid, path_ptr)
        except InvalidAddress:
            return int(Errno.EFAULT)
        try:
            path = self._resolve_path(pid, path_raw)
        except ValueError:
            return int(Errno.EINVAL)

        try:
            inode = self.fs.lookup(path)
        except Exception:
            return int(Errno.EINVAL)
        if inode is None:
            return int(Errno.ENOENT)
        if not getattr(inode, "is_dir", False):
            return int(Errno.EINVAL)

        self._proc(pid).cwd = str(path)
        return 0

    def _sys_getcwd(self, pid: int, tf: TrapFrame) -> int:
        # rdi: buf_ptr, rsi: size
        buf_ptr = int(tf.rdi)
        size = int(tf.rsi)
        if size <= 0:
            return int(Errno.EINVAL)
        cwd = self._proc(pid).cwd
        data = cwd.encode("utf-8") + b"\x00"
        if len(data) > size:
            return int(Errno.EINVAL)
        try:
            self.copy_to_user(pid, buf_ptr, data)
        except InvalidAddress:
            return int(Errno.EFAULT)
        return int(len(data))

    def _sys_readkey(self, pid: int, tf: TrapFrame) -> int:
        # Block until we can decode one key.
        # Returns: 1 up,2 down,3 left,4 right,5 restart('r'),6 quit('q').
        # Any other input is ignored.
        def _read1() -> int:
            b = self.console.read(1)
            if not b:
                return -1
            return int(b[0])

        while True:
            c = _read1()
            if c < 0:
                continue
            if c == ord('q'):
                return 6
            if c == ord('r'):
                return 5

            # ANSI arrow keys: ESC [ A/B/C/D
            if c != 0x1B:
                continue
            c2 = _read1()
            if c2 != ord('['):
                continue
            c3 = _read1()
            if c3 == ord('A'):
                return 1
            if c3 == ord('B'):
                return 2
            if c3 == ord('D'):
                return 3
            if c3 == ord('C'):
                return 4

    def _sys_calc(self, pid: int, tf: TrapFrame) -> int:
        desc_ptr = int(tf.rdi)
        alu = MemoryALU(self._proc(pid).aspace)
        try:
            desc = alu.read_desc_user(desc_ptr)
            alu.exec(desc)
            return 0
        except InvalidAddress:
            return int(Errno.EFAULT)
        except ZeroDivisionError:
            return int(Errno.EINVAL)
        except OverflowError:
            return int(Errno.EINVAL)
        except ValueError:
            return int(Errno.EINVAL)

    def _sys_exit(self, pid: int, tf: TrapFrame) -> int:
        code = int(tf.rdi)
        p = self._proc(pid)
        p.exit_status = code

        # Release resources eagerly, but keep the Process until it is waited.
        try:
            for entry in list(p.fds.values()):
                if isinstance(entry, PipeEnd):
                    try:
                        self._pipe_decref(entry)
                    except Exception:
                        pass
            p.fds.clear()
        except Exception:
            pass

        self._writeback_shared_mmaps(p, start=None, end=None)
        p.mmap_regions.clear()
        p.mmap_files.clear()
        self._free_user_pages(p.aspace)
        self._mark_zombie(pid)
        return 0

    def _sys_waitpid(self, pid: int, tf: TrapFrame) -> int:
        # Non-blocking waitpid.
        # rdi: target pid (-1 for any)
        # rsi: status_ptr (user pointer, 0 to ignore)
        target = int(tf.rdi)
        status_ptr = int(tf.rsi)

        p = self._proc(pid)
        if not p.children and not p.zombie_children:
            return int(Errno.ECHILD)

        candidate: int | None = None
        if target == -1:
            if p.zombie_children:
                candidate = int(p.zombie_children[0])
        else:
            if target in p.zombie_children:
                candidate = int(target)

        if candidate is None:
            return int(Errno.EAGAIN)

        child = self.processes.get(candidate)
        if child is None:
            # stale
            try:
                p.zombie_children.remove(candidate)
            except ValueError:
                pass
            return int(Errno.EAGAIN)

        status = int(child.exit_status) if child.exit_status is not None else 0
        if status_ptr != 0:
            try:
                self.copy_to_user(pid, status_ptr, struct.pack("<q", status))
            except InvalidAddress:
                return int(Errno.EFAULT)

        try:
            p.zombie_children.remove(candidate)
        except ValueError:
            pass
        try:
            p.children.remove(candidate)
        except ValueError:
            pass

        self._reap_process(candidate)
        return int(candidate)

    def _sys_fork(self, pid: int, tf: TrapFrame) -> int:
        parent = self._proc(pid)
        child_pid = self.create_process(parent_pid=pid)
        child = self._proc(child_pid)

        child.cwd = str(parent.cwd)

        # Inherit fds (copy OpenFile records).
        child.next_fd = int(parent.next_fd)
        child.fds.clear()
        for fd, entry in parent.fds.items():
            if entry == "console":
                child.fds[int(fd)] = "console"
            elif isinstance(entry, OpenFile):
                child.fds[int(fd)] = OpenFile(inode=entry.inode, offset=int(entry.offset))
            elif isinstance(entry, PipeEnd):
                pe = PipeEnd(pipe_id=int(entry.pipe_id), is_read=bool(entry.is_read))
                child.fds[int(fd)] = pe
                self._pipe_incref(pe)
            else:
                child.fds[int(fd)] = entry

        # Copy address space mappings & data (USER pages).
        for virt_page_base, _, flags in parent.aspace.pagetable.dump_mappings():
            if not (flags & PageFlags.USER):
                continue
            child.aspace.map_page(int(virt_page_base), PageFlags(flags))
            page = parent.aspace.read(int(virt_page_base), 4096, user=False)
            child.aspace.write(int(virt_page_base), page, user=False)

        # Copy bookkeeping.
        child.mmap_base = int(parent.mmap_base)
        child.mmap_end = int(parent.mmap_end)
        child.mmap_regions = list(parent.mmap_regions)
        child.mmap_files = {
            int(base): MmapFileMapping(
                base=int(m.base),
                length=int(m.length),
                inode=m.inode,
                file_off=int(m.file_off),
                shared=bool(m.shared),
            )
            for base, m in parent.mmap_files.items()
        }
        child.start_rip = parent.start_rip
        child.start_rsp = parent.start_rsp
        return int(child_pid)

    def _sys_execve(self, pid: int, tf: TrapFrame) -> int:
        # rdi: path_ptr
        if self.fs is None:
            return int(Errno.EINVAL)

        path_ptr = int(tf.rdi)
        argv_ptr = int(tf.rsi)
        envp_ptr = int(tf.rdx)
        try:
            path_raw = self.read_cstring_from_user(pid, path_ptr)
        except InvalidAddress:
            return int(Errno.EFAULT)

        try:
            path = self._resolve_path(pid, path_raw)
        except ValueError:
            return int(Errno.EINVAL)

        try:
            argv = self._read_user_str_list(pid, argv_ptr)
            envp = self._read_user_str_list(pid, envp_ptr)
        except InvalidAddress:
            return int(Errno.EFAULT)
        except ValueError:
            return int(Errno.EINVAL)

        try:
            inode = self.fs.lookup(path)
        except Exception:
            return int(Errno.EINVAL)
        if inode is None:
            return int(Errno.ENOENT)

        blob = self.fs.read_inode(inode, 0, int(inode.size_bytes))

        p = self._proc(pid)
        # Free old memory before replacing the page table.
        self._writeback_shared_mmaps(p, start=None, end=None)
        self._free_user_pages(p.aspace)
        p.mmap_regions.clear()
        p.mmap_files.clear()

        p.aspace = AddressSpace(self.kernel_aspace.physmem, self.kernel_aspace.frame_allocator)
        try:
            if blob[:4] == MAGIC_RVEX_V1:
                entry = self.load_rv_executable(pid, blob, argv=argv, envp=envp)
            else:
                entry = self.load_executable(pid, blob, argv=argv, envp=envp)
        except ValueError:
            return int(Errno.EINVAL)
        except InvalidAddress:
            return int(Errno.EFAULT)
        except Exception:
            return int(Errno.EINVAL)
        return int(entry)

    def _writeback_shared_mmaps(self, p: Process, *, start: int | None, end: int | None) -> None:
        if self.fs is None:
            return
        write_inode = getattr(self.fs, "write_inode", None)
        if write_inode is None:
            return

        for m in list(p.mmap_files.values()):
            if not m.shared:
                continue
            ms = int(m.base)
            me = int(m.base + m.length)
            if start is None or end is None:
                ov_start, ov_end = ms, me
            else:
                if me <= start or ms >= end:
                    continue
                ov_start, ov_end = max(ms, int(start)), min(me, int(end))

            cursor = ov_start
            while cursor < ov_end:
                n = min(4096, ov_end - cursor)
                data = p.aspace.read(cursor, n, user=False)
                try:
                    write_inode(m.inode, int(m.file_off) + (cursor - ms), data)
                except Exception:
                    return
                cursor += n

    def _shrink_file_mmaps(self, p: Process, start: int, end: int) -> None:
        items = list(p.mmap_files.items())
        for base, m in items:
            ms = int(m.base)
            me = int(m.base + m.length)
            if me <= start or ms >= end:
                continue
            del p.mmap_files[int(base)]

            if ms < start:
                left_len = int(start - ms)
                p.mmap_files[ms] = MmapFileMapping(
                    base=ms,
                    length=left_len,
                    inode=m.inode,
                    file_off=int(m.file_off),
                    shared=bool(m.shared),
                )
            if end < me:
                right_base = int(end)
                right_len = int(me - end)
                p.mmap_files[right_base] = MmapFileMapping(
                    base=right_base,
                    length=right_len,
                    inode=m.inode,
                    file_off=int(m.file_off) + (right_base - ms),
                    shared=bool(m.shared),
                )

    def _sys_yield(self, pid: int, tf: TrapFrame) -> int:
        return 0

    def _sys_write(self, pid: int, tf: TrapFrame) -> int:
        fd = int(tf.rdi)
        buf = int(tf.rsi)
        count = int(tf.rdx)
        if count < 0:
            return int(Errno.EINVAL)

        p = self._proc(pid)
        target = p.fds.get(fd)
        try:
            data = self.copy_from_user(pid, buf, count)
        except InvalidAddress:
            return int(Errno.EFAULT)

        if target == "console":
            return self.console.write(data)

        if isinstance(target, PipeEnd):
            if target.is_read:
                return int(Errno.EBADF)
            pipe = self._pipe(int(target.pipe_id))
            if pipe.readers <= 0:
                return int(Errno.EPIPE) if hasattr(Errno, "EPIPE") else int(Errno.EINVAL)
            pipe.buf += data
            return int(len(data))

        if isinstance(target, OpenFile):
            if self.fs is None:
                return int(Errno.EINVAL)
            write_inode = getattr(self.fs, "write_inode", None)
            if write_inode is None:
                return int(Errno.EBADF)
            try:
                n = int(write_inode(target.inode, int(target.offset), data))
            except Exception:
                return int(Errno.EINVAL)
            target.offset += n
            return n

        return int(Errno.EBADF)

    def _sys_open(self, pid: int, tf: TrapFrame) -> int:
        if self.fs is None:
            return int(Errno.EINVAL)

        path_ptr = int(tf.rdi)
        flags = int(tf.rsi)
        try:
            path_raw = self.read_cstring_from_user(pid, path_ptr)
        except InvalidAddress:
            return int(Errno.EFAULT)

        try:
            path = self._resolve_path(pid, path_raw)
        except ValueError:
            return int(Errno.EINVAL)

        try:
            inode = self.fs.lookup(path)
        except Exception:
            return int(Errno.EINVAL)
        if inode is None:
            if flags & 1:
                create_file = getattr(self.fs, "create_file", None)
                if create_file is None:
                    return int(Errno.ENOENT)
                try:
                    inode = create_file(path)
                except Exception:
                    return int(Errno.EINVAL)
            else:
                return int(Errno.ENOENT)

        if (flags & 4) and not (flags & 2):
            # Truncate to 0 on open (like O_TRUNC), unless appending.
            truncate_inode = getattr(self.fs, "truncate_inode", None)
            if truncate_inode is not None:
                try:
                    truncate_inode(inode, 0)
                except Exception:
                    return int(Errno.EINVAL)

        p = self._proc(pid)
        fd = p.next_fd
        p.next_fd += 1
        off = 0
        if flags & 2:
            off = int(getattr(inode, "size_bytes", 0))
        p.fds[fd] = OpenFile(inode=inode, offset=off)
        return fd

    def _sys_read(self, pid: int, tf: TrapFrame) -> int:
        fd = int(tf.rdi)
        buf_ptr = int(tf.rsi)
        count = int(tf.rdx)
        if count < 0:
            return int(Errno.EINVAL)

        p = self._proc(pid)
        target = p.fds.get(fd)
        if target == "console":
            data = self.console.read(count)
        elif isinstance(target, PipeEnd):
            if not target.is_read:
                return int(Errno.EBADF)
            pipe = self._pipe(int(target.pipe_id))
            if not pipe.buf or pipe.read_off >= len(pipe.buf):
                if pipe.writers <= 0:
                    data = b""
                else:
                    data = b""
            else:
                end = min(int(pipe.read_off) + int(count), len(pipe.buf))
                data = bytes(pipe.buf[int(pipe.read_off) : int(end)])
                pipe.read_off = int(end)
                if pipe.read_off >= len(pipe.buf):
                    pipe.buf = bytearray()
                    pipe.read_off = 0
        elif isinstance(target, OpenFile):
            if self.fs is None:
                return int(Errno.EINVAL)
            data = self.fs.read_inode(target.inode, target.offset, count)
            target.offset += len(data)
        else:
            return int(Errno.EBADF)

        try:
            self.copy_to_user(pid, buf_ptr, data)
        except InvalidAddress:
            return int(Errno.EFAULT)

        return len(data)

    def _sys_close(self, pid: int, tf: TrapFrame) -> int:
        fd = int(tf.rdi)
        p = self._proc(pid)
        if fd not in p.fds or fd in (self.config.stdout_fd, self.config.stderr_fd):
            return int(Errno.EBADF)
        entry = p.fds.get(fd)
        if isinstance(entry, PipeEnd):
            self._pipe_decref(entry)
        del p.fds[fd]
        return 0

    def _sys_pipe(self, pid: int, tf: TrapFrame) -> int:
        pipefd_ptr = int(tf.rdi)
        if pipefd_ptr == 0:
            return int(Errno.EFAULT)

        p = self._proc(pid)
        pipe_id = int(self._next_pipe_id)
        self._next_pipe_id += 1
        self._pipes[pipe_id] = Pipe(buf=bytearray(), read_off=0, readers=1, writers=1)

        rfd = int(p.next_fd)
        wfd = int(p.next_fd + 1)
        p.next_fd += 2

        p.fds[rfd] = PipeEnd(pipe_id=pipe_id, is_read=True)
        p.fds[wfd] = PipeEnd(pipe_id=pipe_id, is_read=False)

        try:
            self.copy_to_user(pid, pipefd_ptr, struct.pack("<QQ", int(rfd), int(wfd)))
        except InvalidAddress:
            self._pipe_decref(PipeEnd(pipe_id=pipe_id, is_read=True))
            self._pipe_decref(PipeEnd(pipe_id=pipe_id, is_read=False))
            p.fds.pop(rfd, None)
            p.fds.pop(wfd, None)
            return int(Errno.EFAULT)
        return 0

    def _sys_dup2(self, pid: int, tf: TrapFrame) -> int:
        oldfd = int(tf.rdi)
        newfd = int(tf.rsi)
        if newfd < 0:
            return int(Errno.EINVAL)
        p = self._proc(pid)
        if oldfd not in p.fds:
            return int(Errno.EBADF)
        if oldfd == newfd:
            return int(newfd)

        if newfd in p.fds:
            old_entry = p.fds.get(newfd)
            if isinstance(old_entry, PipeEnd):
                self._pipe_decref(old_entry)
            p.fds.pop(newfd, None)

        entry = p.fds.get(oldfd)
        if isinstance(entry, PipeEnd):
            pe = PipeEnd(pipe_id=int(entry.pipe_id), is_read=bool(entry.is_read))
            p.fds[newfd] = pe
            self._pipe_incref(pe)
        else:
            p.fds[newfd] = entry
        if newfd >= p.next_fd:
            p.next_fd = int(newfd + 1)
        return int(newfd)

    @staticmethod
    def _page_align_down(x: int) -> int:
        return x & ~4095

    @staticmethod
    def _page_align_up(x: int) -> int:
        return (x + 4095) & ~4095

    def _coalesce_mmap(self, p: Process) -> None:
        if not p.mmap_regions:
            return
        regs = sorted(p.mmap_regions)
        out: list[tuple[int, int]] = []
        cs, cl = regs[0]
        ce = cs + cl
        for s, l in regs[1:]:
            e = s + l
            if s == ce:
                ce = e
                continue
            out.append((cs, ce - cs))
            cs, ce = s, e
        out.append((cs, ce - cs))
        p.mmap_regions = out

    def _overlaps_any(self, p: Process, start: int, length: int) -> bool:
        end = start + length
        for s, l in p.mmap_regions:
            e = s + l
            if not (end <= s or start >= e):
                return True
        return False

    def _munmap_overlaps(self, p: Process, start: int, end: int) -> int:
        # Unmap any pages that overlap [start, end) and subtract those ranges from
        # existing regions. Does not require full coverage.
        regs = sorted(p.mmap_regions)
        new_regs: list[tuple[int, int]] = []

        for s, l in regs:
            e = s + l
            if e <= start or s >= end:
                new_regs.append((s, l))
                continue

            ov_start = max(s, start)
            ov_end = min(e, end)
            for page_base in range(ov_start, ov_end, 4096):
                try:
                    p.aspace.unmap_page(page_base, free_frame=True)
                except InvalidAddress:
                    return int(Errno.EFAULT)

            if s < ov_start:
                new_regs.append((s, ov_start - s))
            if ov_end < e:
                new_regs.append((ov_end, e - ov_end))

        p.mmap_regions = new_regs
        self._coalesce_mmap(p)
        return 0

    def _munmap_covered_range(self, p: Process, start: int, end: int) -> int:
        # Unmap pages in [start, end) and update regions.
        regs = sorted(p.mmap_regions)
        new_regs: list[tuple[int, int]] = []

        cursor = start
        for s, l in regs:
            e = s + l
            if e <= start or s >= end:
                new_regs.append((s, l))
                continue

            if s > cursor:
                return int(Errno.EINVAL)

            ov_start = max(s, start)
            ov_end = min(e, end)
            for page_base in range(ov_start, ov_end, 4096):
                try:
                    p.aspace.unmap_page(page_base, free_frame=True)
                except InvalidAddress:
                    return int(Errno.EFAULT)

            if s < ov_start:
                new_regs.append((s, ov_start - s))
            if ov_end < e:
                new_regs.append((ov_end, e - ov_end))

            cursor = max(cursor, ov_end)

        if cursor < end:
            return int(Errno.EINVAL)

        p.mmap_regions = new_regs
        self._coalesce_mmap(p)
        return 0

    def _alloc_mmap_range(self, p: Process, length: int, *, hint: int = 0) -> int:
        length = self._page_align_up(length)
        if length <= 0:
            raise InvalidAddress("bad length")

        # Try hint first if provided.
        if hint != 0:
            hint = self._page_align_down(hint)
            if hint < p.mmap_base or hint + length > p.mmap_end:
                raise InvalidAddress("hint out of mmap range")
            if not self._overlaps_any(p, hint, length):
                p.mmap_regions.append((hint, length))
                self._coalesce_mmap(p)
                return hint

        addr = p.mmap_base
        regs = sorted(p.mmap_regions)
        for s, l in regs:
            if addr + length <= s:
                p.mmap_regions.append((addr, length))
                self._coalesce_mmap(p)
                return addr
            addr = max(addr, s + l)
            addr = self._page_align_up(addr)

        if addr + length <= p.mmap_end:
            p.mmap_regions.append((addr, length))
            self._coalesce_mmap(p)
            return addr

        raise InvalidAddress("mmap region exhausted")

    def _sys_mmap(self, pid: int, tf: TrapFrame) -> int:
        # ABI: mmap(addr, length, prot, flags, fd, offset)
        addr_hint = int(tf.rdi)
        length = int(tf.rsi)
        prot = int(tf.rdx)
        flags = int(tf.r10)
        fd = int(tf.r8)

        if length <= 0:
            return int(Errno.EINVAL)
        if addr_hint != 0 and (addr_hint % 4096) != 0:
            return int(Errno.EINVAL)

        if (flags & MAP_ANON) and (flags & MAP_FILE):
            return int(Errno.EINVAL)
        if not (flags & MAP_ANON) and not (flags & MAP_FILE):
            return int(Errno.EINVAL)
        if (flags & MAP_SHARED) and not (flags & MAP_FILE):
            return int(Errno.EINVAL)
        if (flags & MAP_SHARED) and (flags & MAP_ANON):
            return int(Errno.EINVAL)

        page_flags = PageFlags.USER
        if prot & PROT_READ:
            page_flags |= PageFlags.R
        if prot & PROT_WRITE:
            page_flags |= PageFlags.W
        if prot & PROT_EXEC:
            page_flags |= PageFlags.X
        if prot != 0 and not (page_flags & PageFlags.R):
            page_flags |= PageFlags.R

        p = self._proc(pid)
        length_aligned = self._page_align_up(length)

        if flags & MAP_FIXED:
            if addr_hint == 0:
                return int(Errno.EINVAL)
            base = self._page_align_down(addr_hint)
            if base < p.mmap_base or base + length_aligned > p.mmap_end:
                return int(Errno.EINVAL)

            self._writeback_shared_mmaps(p, start=base, end=base + length_aligned)
            r = self._munmap_overlaps(p, base, base + length_aligned)
            if r != 0:
                return r
            self._shrink_file_mmaps(p, base, base + length_aligned)
            p.mmap_regions.append((base, length_aligned))
            self._coalesce_mmap(p)
        else:
            try:
                base = self._alloc_mmap_range(p, length, hint=addr_hint)
            except InvalidAddress:
                return int(Errno.ENOMEM)

        try:
            for page_base in range(base, base + length_aligned, 4096):
                p.aspace.map_page(page_base, page_flags)
        except Exception:
            # Best-effort rollback
            for page_base in range(base, base + length_aligned, 4096):
                try:
                    p.aspace.unmap_page(page_base, free_frame=True)
                except Exception:
                    pass
            p.mmap_regions = [(s, l) for (s, l) in p.mmap_regions if s != base]
            return int(Errno.ENOMEM)

        # MAP_FILE: copy in file data (MAP_PRIVATE semantics)
        if flags & MAP_FILE:
            if self.fs is None:
                return int(Errno.EINVAL)
            of = p.fds.get(fd)
            if not isinstance(of, OpenFile):
                return int(Errno.EBADF)
            file_off = int(tf.r9)
            if file_off < 0 or (file_off % 4096) != 0:
                return int(Errno.EINVAL)

            remaining = length_aligned
            cursor = 0
            while remaining > 0:
                chunk = self.fs.read_inode(of.inode, file_off + cursor, min(4096, remaining))
                if len(chunk) < 4096:
                    chunk = chunk + b"\x00" * (4096 - len(chunk))
                # kernel write: bypass user perms (PROT_NONE)
                p.aspace.write(base + cursor, chunk, user=False)
                cursor += 4096
                remaining -= 4096

            if flags & MAP_SHARED:
                p.mmap_files[int(base)] = MmapFileMapping(
                    base=int(base),
                    length=int(length_aligned),
                    inode=of.inode,
                    file_off=int(file_off),
                    shared=True,
                )

        return base

    def _sys_munmap(self, pid: int, tf: TrapFrame) -> int:
        addr = int(tf.rdi)
        length = int(tf.rsi)
        if length <= 0:
            return int(Errno.EINVAL)
        if (addr % 4096) != 0:
            return int(Errno.EINVAL)

        length_aligned = self._page_align_up(length)
        unmap_start = addr
        unmap_end = addr + length_aligned

        p = self._proc(pid)

        self._writeback_shared_mmaps(p, start=unmap_start, end=unmap_end)
        r = self._munmap_covered_range(p, unmap_start, unmap_end)
        if r == 0:
            self._shrink_file_mmaps(p, unmap_start, unmap_end)
        return r

    def run(self, *, max_steps: int = 10_000) -> None:
        steps = 0
        while self.runq and steps < max_steps:
            tid = self.runq.popleft()
            t = self.threads[tid]
            if not t.runnable:
                steps += 1
                continue

            p = self._proc(t.pid)
            if p.exit_status is not None:
                t.runnable = False
                steps += 1
                continue

            op = t.next_op()
            if op is None:
                t.runnable = False
                steps += 1
                continue

            sysno, a1, a2, a3 = op
            tf = TrapFrame(rax=sysno, rdi=a1, rsi=a2, rdx=a3)
            ret = self.syscalls.dispatch(self, t.pid, tf)

            if sysno == int(Sysno.EXIT) and p.exit_status is not None:
                t.runnable = False
            else:
                self.runq.append(tid)

            _ = ret
            steps += 1
