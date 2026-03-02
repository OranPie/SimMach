from __future__ import annotations

import struct
import unittest

from constants import MAP_FILE, MAP_SHARED, PROT_READ, PROT_WRITE, Errno, O_CREAT, PAGE_SIZE, Sysno
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.proc import OpenFile
from simmach.simscript import compile as simscript_compile
from simmach.syscall import TrapFrame


def _new_kernel(*, with_fs: bool) -> tuple[Kernel, BetterFS | None]:
    physmem = PhysMem(size_bytes=4096 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)
    kernel = Kernel(kas)
    if not with_fs:
        return kernel, None
    dev = BlockDevice(block_size=512, num_blocks=2048)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()
    kernel.set_fs(fs)
    return kernel, fs


def _dispatch(kernel: Kernel, pid: int, tf: TrapFrame) -> int:
    return int(kernel.syscalls.dispatch(kernel, pid, tf))


class ConformanceSuite(unittest.TestCase):
    def test_write_cross_page_fault_returns_efault(self) -> None:
        kernel, _ = _new_kernel(with_fs=False)
        pid = kernel.create_process()
        aspace = kernel.processes[pid].aspace
        base = 0x2000_0000
        aspace.map_page(base, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.write(base + PAGE_SIZE - 2, b"AB", user=True)

        rc = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=base + PAGE_SIZE - 2, rdx=8),
        )
        self.assertEqual(int(Errno.EFAULT), rc)

    def test_open_tracks_path_handle_and_close_releases_it(self) -> None:
        kernel, _ = _new_kernel(with_fs=True)
        pid = kernel.create_process()
        proc = kernel.processes[pid]
        aspace = proc.aspace
        base = 0x2000_0000
        aspace.map_page(base, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.write(base, b"/tmp/handles.txt\x00", user=True)

        fd = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.OPEN), rdi=base, rsi=int(O_CREAT), rdx=0),
        )
        self.assertGreaterEqual(fd, 3)
        entry = proc.fds.get(fd)
        self.assertIsInstance(entry, OpenFile)
        assert isinstance(entry, OpenFile)
        self.assertGreater(entry.path_handle, 0)
        self.assertIn(entry.path_handle, proc.owned_handles)

        hm = kernel.handle_manager
        self.assertIsNotNone(hm)
        assert hm is not None
        self.assertEqual("/tmp/handles.txt", hm.get_typed(entry.path_handle))
        path_handle = int(entry.path_handle)

        rc = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=fd))
        self.assertEqual(0, rc)
        self.assertNotIn(fd, proc.fds)
        self.assertNotIn(path_handle, proc.owned_handles)
        with self.assertRaises(Exception):
            hm.get_typed(path_handle)

    def test_fork_waitpid_reaps_child_and_writes_status(self) -> None:
        kernel, _ = _new_kernel(with_fs=False)
        pid = kernel.create_process()
        aspace = kernel.processes[pid].aspace
        status_ptr = 0x2000_0000
        aspace.map_page(status_ptr, PageFlags.USER | PageFlags.R | PageFlags.W)

        child_pid = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.FORK)))
        self.assertGreater(child_pid, 0)
        rc_wait_running = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.WAITPID), rdi=child_pid, rsi=status_ptr),
        )
        self.assertEqual(int(Errno.EAGAIN), rc_wait_running)

        rc_exit = _dispatch(kernel, child_pid, TrapFrame(rax=int(Sysno.EXIT), rdi=7))
        self.assertEqual(0, rc_exit)
        rc_wait_done = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.WAITPID), rdi=child_pid, rsi=status_ptr),
        )
        self.assertEqual(child_pid, rc_wait_done)
        self.assertEqual(7, struct.unpack("<q", aspace.read(status_ptr, 8, user=True))[0])
        self.assertNotIn(child_pid, kernel.processes)

    def test_pipe_write_read_eof(self) -> None:
        kernel, _ = _new_kernel(with_fs=False)
        pid = kernel.create_process()
        aspace = kernel.processes[pid].aspace
        pipefd_ptr = 0x2000_0000
        data_ptr = 0x2000_1000
        out_ptr = 0x2000_2000
        for addr in (pipefd_ptr, data_ptr, out_ptr):
            aspace.map_page(addr, PageFlags.USER | PageFlags.R | PageFlags.W)

        rc_pipe = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.PIPE), rdi=pipefd_ptr))
        self.assertEqual(0, rc_pipe)
        rfd, wfd = struct.unpack("<QQ", aspace.read(pipefd_ptr, 16, user=True))

        aspace.write(data_ptr, b"abc", user=True)
        rc_write = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.WRITE), rdi=int(wfd), rsi=data_ptr, rdx=3),
        )
        self.assertEqual(3, rc_write)

        rc_close_w = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(wfd)))
        self.assertEqual(0, rc_close_w)

        rc_read = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.READ), rdi=int(rfd), rsi=out_ptr, rdx=3),
        )
        self.assertEqual(3, rc_read)
        self.assertEqual(b"abc", aspace.read(out_ptr, 3, user=True))

        rc_eof = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.READ), rdi=int(rfd), rsi=out_ptr, rdx=3),
        )
        self.assertEqual(0, rc_eof)

    def test_simscript_execve_flow(self) -> None:
        kernel, fs = _new_kernel(with_fs=True)
        assert fs is not None

        src = """\
def main():
    fd = open("/tmp/conformance.txt", 1)
    write(fd, "ok\\n")
    close(fd)
    exit(0)
"""
        rvx = simscript_compile(src)
        inode = fs.create_file("/bin/conformance")
        fs.write_inode(inode, 0, rvx, truncate=True)

        pid = kernel.create_process()
        aspace = kernel.processes[pid].aspace
        user_base = 0x2000_0000
        aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.write(user_base, b"/bin/conformance\x00", user=True)

        entry = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base, rsi=0, rdx=0),
        )
        self.assertGreater(entry, 0)
        kernel.run_user_rv64(pid, entry)

        out = fs.lookup("/tmp/conformance.txt")
        self.assertIsNotNone(out)
        assert out is not None
        self.assertTrue(fs.read_inode(out, 0, 16).startswith(b"ok\n"))

    def test_mmap_shared_partial_writeback(self) -> None:
        kernel, fs = _new_kernel(with_fs=True)
        assert fs is not None
        inode = fs.create_file("/tmp/shared.bin")
        fs.write_inode(inode, 0, b"\x00" * 8192, truncate=True)

        pid = kernel.create_process()
        proc = kernel.processes[pid]
        aspace = proc.aspace
        path_ptr = 0x1800_0000
        aspace.map_page(path_ptr, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.write(path_ptr, b"/tmp/shared.bin\x00", user=True)

        fd = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=path_ptr, rsi=0, rdx=0))
        self.assertGreaterEqual(fd, 3)
        map_addr = _dispatch(
            kernel,
            pid,
            TrapFrame(
                rax=int(Sysno.MMAP),
                rdi=0,
                rsi=8192,
                rdx=int(PROT_READ | PROT_WRITE),
                r10=int(MAP_FILE | MAP_SHARED),
                r8=fd,
                r9=0,
            ),
        )
        self.assertGreater(map_addr, 0)

        aspace.write(map_addr + 10, b"F1", user=False)
        aspace.write(map_addr + 4096 + 3, b"S2", user=False)

        rc_unmap_second = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.MUNMAP), rdi=map_addr + 4096, rsi=4096),
        )
        self.assertEqual(0, rc_unmap_second)
        raw_mid = fs.read_inode(inode, 4096, 16)
        self.assertEqual(b"S2", raw_mid[3:5])
        raw_start = fs.read_inode(inode, 0, 16)
        self.assertEqual(b"\x00\x00", raw_start[10:12])

        rc_unmap_first = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.MUNMAP), rdi=map_addr, rsi=4096),
        )
        self.assertEqual(0, rc_unmap_first)
        raw_start_after = fs.read_inode(inode, 0, 16)
        self.assertEqual(b"F1", raw_start_after[10:12])

    def test_execve_flushes_shared_mmap(self) -> None:
        kernel, fs = _new_kernel(with_fs=True)
        assert fs is not None
        file_inode = fs.create_file("/tmp/execflush.bin")
        fs.write_inode(file_inode, 0, b"\x00" * 4096, truncate=True)
        rvx = simscript_compile(
            """\
def main():
    exit(0)
"""
        )
        prog_inode = fs.create_file("/bin/noop")
        fs.write_inode(prog_inode, 0, rvx, truncate=True)

        pid = kernel.create_process()
        proc = kernel.processes[pid]
        aspace = proc.aspace
        user_base = 0x1801_0000
        aspace.map_page(user_base, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.map_page(user_base + PAGE_SIZE, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.write(user_base, b"/tmp/execflush.bin\x00", user=True)
        aspace.write(user_base + 256, b"/bin/noop\x00", user=True)

        fd = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.OPEN), rdi=user_base, rsi=0, rdx=0))
        self.assertGreaterEqual(fd, 3)
        map_addr = _dispatch(
            kernel,
            pid,
            TrapFrame(
                rax=int(Sysno.MMAP),
                rdi=0,
                rsi=4096,
                rdx=int(PROT_READ | PROT_WRITE),
                r10=int(MAP_FILE | MAP_SHARED),
                r8=fd,
                r9=0,
            ),
        )
        self.assertGreater(map_addr, 0)
        aspace.write(map_addr + 100, b"ZZ", user=False)

        entry = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.EXECVE), rdi=user_base + 256, rsi=0, rdx=0),
        )
        self.assertGreater(entry, 0)
        self.assertEqual(b"ZZ", fs.read_inode(file_inode, 100, 2))


if __name__ == "__main__":
    unittest.main()
