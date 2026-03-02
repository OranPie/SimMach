# SimMach FS + FD Semantics (MVP)

## Path Resolution
- Absolute paths are used as-is.
- Relative paths are resolved against per-process `cwd`.
- `.` and `..` normalization is handled by `simmach.path.norm_path`.

## open/read/write/close
- `open` supports `O_CREAT`, `O_APPEND`, `O_TRUNC`.
- `read`/`write` operate on current file offset for regular files.
- `close` releases fd entry; pipes adjust reader/writer refs.

## Pipe Semantics
- `pipe` returns read/write fds.
- Writing to a pipe with no readers returns `-EPIPE`.
- Reading from an empty pipe with no writers returns EOF (`0` bytes).

## Handle Integration
- Kernel allocates a typed string handle per opened path.
- Handle ownership is tracked per process and released on close/exit/reap.
