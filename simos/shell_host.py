from __future__ import annotations

import shlex
import time
from typing import Sequence

from constants import PAGE_SIZE
from simmach.block import BlockDevice
from simmach.fs import BetterFS
from simmach.kernel import Kernel
from simmach.mem import AddressSpace, FrameAllocator, PhysMem
from simmach.path import norm_path

from simos.shell_bins import _install_base_bins
from simos.shell_env import ShellEnv, _errno_name
from simos.shell_runtime import _run_program

try:
    import readline  # type: ignore
except Exception:
    readline = None

def _cmd_help() -> None:
    print("commands:")
    print("  help")
    print("  exit")
    print("  pwd")
    print("  cd [path]")
    print("  ls [path]")
    print("  stat <path>")
    print("  cat <path>")
    print("  hexdump <path>")
    print("  mkdir <path>")
    print("  touch <path>")
    print("  write <path> <text...>")
    print("  append <path> <text...>")
    print("  echo [text...]")
    print("  run <path|cmd> [args...]")
    print("  sleep <ms>")

def _resolve_path(env: ShellEnv, path: str) -> str:
    if path.startswith("/"):
        return norm_path(path)
    base = env.cwd
    if not base.endswith("/"):
        base += "/"
    return norm_path(base + path)

def _resolve_cmd(env: ShellEnv, cmd: str) -> str:
    if "/" in cmd:
        return _resolve_path(env, cmd)
    p = f"/bin/{cmd}"
    return p

def _cmd_ls(env: ShellEnv, path: str) -> None:
    try:
        ap = _resolve_path(env, path)
        names = env.fs.listdir(ap)
    except Exception as e:
        print(f"ls: {e}")
        return
    for n in names:
        print(n)

def _cmd_cat(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        data = env.fs.read_file(ap)
        try:
            sys.stdout.write(data.decode("utf-8", errors="replace"))
        except Exception:
            sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.write("\n")
    except Exception as e:
        print(f"cat: {e}")

def _cmd_stat(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    ino = env.fs.lookup(ap)
    if ino is None:
        print("stat: no such file")
        return
    typ = "dir" if ino.is_dir else "file"
    print(f"path: {ap}")
    print(f"type: {typ}")
    print(f"size: {int(ino.size_bytes)}")
    if not ino.is_dir:
        print(f"blocks: {len(ino.direct)}")

def _cmd_mkdir(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        env.fs.mkdir(ap)
    except Exception as e:
        print(f"mkdir: {e}")

def _cmd_touch(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        if not env.fs.exists(ap):
            env.fs.create_file(ap)
    except Exception as e:
        print(f"touch: {e}")

def _cmd_write(env: ShellEnv, path: str, text: str, *, append: bool) -> None:
    ap = _resolve_path(env, path)
    data = text.encode("utf-8")
    try:
        env.fs.write_file(ap, data, create=True, truncate=not append, append=append)
    except Exception as e:
        print(f"write: {e}")

def _cmd_hexdump(env: ShellEnv, path: str) -> None:
    ap = _resolve_path(env, path)
    try:
        data = env.fs.read_file(ap)
        width = 16
        for i in range(0, len(data), width):
            chunk = data[i : i + width]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{i:08x}  {hx:<47}  |{asc}|")
    except Exception as e:
        print(f"hexdump: {e}")

def _make_env() -> ShellEnv:
    physmem = PhysMem(size_bytes=2048 * PAGE_SIZE)
    frame_alloc = FrameAllocator(physmem)
    kas = AddressSpace(physmem, frame_alloc)

    dev = BlockDevice(block_size=512, num_blocks=4096)
    fs = BetterFS(dev)
    fs.format_and_mount(create_default_dirs=True)
    fs.mount()
    _install_base_bins(fs)

    k = Kernel(kas)
    k.set_fs(fs)
    return ShellEnv(k=k, fs=fs, kas=kas)

def _read_host_line() -> str | None:
    try:
        return input("simos$ ")
    except EOFError:
        print()
        return None
    except KeyboardInterrupt:
        print()
        return ""

def _parse_host_line(line: str) -> list[str] | None:
    line = line.strip()
    if not line:
        return []
    try:
        return list(shlex.split(line))
    except ValueError as e:
        print(f"parse error: {e}")
        return None

def _dispatch_host_command(env: ShellEnv, parts: Sequence[str]) -> bool:
    if not parts:
        return True
    cmd, *args = parts

    if cmd in ("exit", "quit"):
        return False
    if cmd == "help":
        _cmd_help()
        return True
    if cmd == "pwd":
        print(env.cwd)
        return True
    if cmd == "cd":
        target = args[0] if args else "/"
        ap = _resolve_path(env, target)
        ino = env.fs.lookup(ap)
        if ino is None or not ino.is_dir:
            print("cd: not a directory")
            return True
        env.cwd = ap
        return True
    if cmd == "ls":
        _cmd_ls(env, args[0] if args else env.cwd)
        return True
    if cmd == "stat":
        if not args:
            print("stat: missing path")
            return True
        _cmd_stat(env, args[0])
        return True
    if cmd == "cat":
        if not args:
            print("cat: missing path")
            return True
        _cmd_cat(env, args[0])
        return True
    if cmd == "hexdump":
        if not args:
            print("hexdump: missing path")
            return True
        _cmd_hexdump(env, args[0])
        return True
    if cmd == "mkdir":
        if not args:
            print("mkdir: missing path")
            return True
        _cmd_mkdir(env, args[0])
        return True
    if cmd == "touch":
        if not args:
            print("touch: missing path")
            return True
        _cmd_touch(env, args[0])
        return True
    if cmd == "write":
        if len(args) < 2:
            print("write: usage: write <path> <text...>")
            return True
        _cmd_write(env, args[0], " ".join(args[1:]), append=False)
        return True
    if cmd == "append":
        if len(args) < 2:
            print("append: usage: append <path> <text...>")
            return True
        _cmd_write(env, args[0], " ".join(args[1:]), append=True)
        return True
    if cmd == "echo":
        print(" ".join(args))
        return True
    if cmd == "run":
        if not args:
            print("run: missing path")
            return True
        path = _resolve_cmd(env, args[0])
        argv = [path, *args[1:]]
        rc = _run_program(env, path, argv)
        if rc != 0:
            name = _errno_name(rc)
            if name is None:
                print(f"run: execve failed: {rc}")
            else:
                print(f"run: execve failed: {name} ({rc})")
        return True
    if cmd == "sleep":
        if not args:
            print("sleep: missing ms")
            return True
        try:
            ms = float(args[0])
            if ms < 0:
                raise ValueError("negative")
        except Exception:
            print("sleep: invalid ms")
            return True
        time.sleep(ms / 1000.0)
        return True

    print("unknown command")
    return True

def repl() -> None:
    env = _make_env()
    _cmd_help()

    while True:
        line = _read_host_line()
        if line is None:
            return
        parts = _parse_host_line(line)
        if parts is None:
            continue
        if parts == []:
            continue
        if not _dispatch_host_command(env, parts):
            return
