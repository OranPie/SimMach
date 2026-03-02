#!/usr/bin/env python3
from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from constants import PAGE_SIZE
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.simscript import compile as simscript_compile


@dataclass(slots=True)
class Workload:
    name: str
    source: str
    max_steps: int


def _mk_spill_src(*, nvars: int, loops: int) -> str:
    lines = ["def main():"]
    for i in range(nvars):
        lines.append(f"    v{i} = {i}")
    lines.append("    i = 0")
    lines.append(f"    while i < {loops}:")
    for i in range(nvars):
        lines.append(f"        v{i} = v{i} + i")
    lines.append("        i = i + 1")
    lines.append("    return v0")
    return "\n".join(lines) + "\n"


def _run_rvx_once(blob: bytes, *, max_steps: int) -> float:
    physmem = PhysMem(size_bytes=4096 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)
    kernel = Kernel(kas)
    pid = kernel.create_process()
    entry = kernel.load_rv_executable(pid, blob)
    t0 = time.perf_counter()
    kernel.run_user_rv64(pid, entry, max_steps=max_steps)
    return time.perf_counter() - t0


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark simmach core RV64 simulation speed.")
    parser.add_argument("--repeats", type=int, default=3, help="Measured runs per workload.")
    parser.add_argument("--warmups", type=int, default=1, help="Warmup runs per workload.")
    args = parser.parse_args()

    workloads = [
        Workload(
            name="arith_loop_50k",
            source="""\
def main():
    i = 0
    s = 0
    while i < 50000:
        s = s + i
        s = s ^ (i << 1)
        s = s - (i & 7)
        i = i + 1
    return s
""",
            max_steps=4_000_000,
        ),
        Workload(
            name="spill_loop_24vars_10k",
            source=_mk_spill_src(nvars=24, loops=10_000),
            max_steps=4_000_000,
        ),
    ]

    print("workload,run_s,avg_s,min_s,max_s,stdev_s")
    for w in workloads:
        blob = simscript_compile(w.source)
        for _ in range(max(0, args.warmups)):
            _run_rvx_once(blob, max_steps=w.max_steps)

        runs = [_run_rvx_once(blob, max_steps=w.max_steps) for _ in range(max(1, args.repeats))]
        avg = statistics.fmean(runs)
        stdev = statistics.pstdev(runs) if len(runs) > 1 else 0.0
        run_s = ";".join(f"{x:.6f}" for x in runs)
        print(f"{w.name},{run_s},{avg:.6f},{min(runs):.6f},{max(runs):.6f},{stdev:.6f}")


if __name__ == "__main__":
    main()
