from __future__ import annotations

import struct
import unittest

from constants import PAGE_SIZE, Sysno
from simmach.kernel import Kernel, PipeEnd
from simmach.mem import AddressSpace, FrameAllocator, PageFlags, PhysMem
from simmach.syscall import TrapFrame


def _new_kernel() -> Kernel:
    physmem = PhysMem(size_bytes=1024 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)
    return Kernel(kas)


def _dispatch(kernel: Kernel, pid: int, tf: TrapFrame) -> int:
    return int(kernel.syscalls.dispatch(kernel, pid, tf))


class ShellPipelineRegression(unittest.TestCase):
    def test_pipeline_style_dup2_stdout_to_pipe(self) -> None:
        kernel = _new_kernel()
        pid = kernel.create_process()
        proc = kernel.processes[pid]
        aspace = proc.aspace
        pipefd_ptr = 0x2000_0000
        in_ptr = 0x2000_1000
        out_ptr = 0x2000_2000
        for addr in (pipefd_ptr, in_ptr, out_ptr):
            aspace.map_page(addr, PageFlags.USER | PageFlags.R | PageFlags.W)

        rc_pipe = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.PIPE), rdi=pipefd_ptr))
        self.assertEqual(0, rc_pipe)
        rfd, wfd = struct.unpack("<QQ", aspace.read(pipefd_ptr, 16, user=True))

        rc_dup2 = _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.DUP2), rdi=int(wfd), rsi=1))
        self.assertEqual(1, rc_dup2)
        self.assertIsInstance(proc.fds.get(1), PipeEnd)

        aspace.write(in_ptr, b"pipe-data", user=True)
        rc_write = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.WRITE), rdi=1, rsi=in_ptr, rdx=len(b"pipe-data")),
        )
        self.assertEqual(len(b"pipe-data"), rc_write)

        rc_read = _dispatch(
            kernel,
            pid,
            TrapFrame(rax=int(Sysno.READ), rdi=int(rfd), rsi=out_ptr, rdx=len(b"pipe-data")),
        )
        self.assertEqual(len(b"pipe-data"), rc_read)
        self.assertEqual(b"pipe-data", aspace.read(out_ptr, len(b"pipe-data"), user=True))

    def test_pipeline_rewire_releases_old_pipe(self) -> None:
        kernel = _new_kernel()
        pid = kernel.create_process()
        proc = kernel.processes[pid]
        aspace = proc.aspace
        pipe1_ptr = 0x2000_0000
        pipe2_ptr = 0x2000_1000
        aspace.map_page(pipe1_ptr, PageFlags.USER | PageFlags.R | PageFlags.W)
        aspace.map_page(pipe2_ptr, PageFlags.USER | PageFlags.R | PageFlags.W)

        self.assertEqual(0, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.PIPE), rdi=pipe1_ptr)))
        r1, w1 = struct.unpack("<QQ", aspace.read(pipe1_ptr, 16, user=True))
        self.assertEqual(1, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.DUP2), rdi=int(w1), rsi=1)))
        entry1 = proc.fds.get(1)
        assert isinstance(entry1, PipeEnd)
        pipe1_id = int(entry1.pipe_id)
        self.assertEqual(0, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(w1))))

        self.assertEqual(0, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.PIPE), rdi=pipe2_ptr)))
        r2, w2 = struct.unpack("<QQ", aspace.read(pipe2_ptr, 16, user=True))
        self.assertEqual(1, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.DUP2), rdi=int(w2), rsi=1)))
        entry2 = proc.fds.get(1)
        self.assertIsInstance(entry2, PipeEnd)
        assert isinstance(entry2, PipeEnd)
        self.assertNotEqual(pipe1_id, int(entry2.pipe_id))

        self.assertEqual(0, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(r1))))
        self.assertNotIn(pipe1_id, kernel._pipes)

        self.assertEqual(0, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(w2))))
        self.assertEqual(0, _dispatch(kernel, pid, TrapFrame(rax=int(Sysno.CLOSE), rdi=int(r2))))


if __name__ == "__main__":
    unittest.main()
