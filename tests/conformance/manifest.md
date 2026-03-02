# Conformance Manifest

This suite validates MVP behavior in executable scenarios:

- VM/user-pointer fault handling (`-EFAULT` on invalid user buffers).
- Process lifecycle (`fork`, `waitpid`, zombie reap + status writeback).
- Pipe behavior (`pipe`, `write`, `close`, EOF on drained reads).
- Handle integration for open-file path metadata lifecycle.
- Shared `mmap` writeback edge cases (partial `munmap`, `execve` flush).
- Shell pipeline syscall patterns (`pipe` + `dup2` rewiring regressions).
- Shell runtime integration (`run` path, argv passing, missing-binary errno).
- SimScript compile + RVX1 exec + filesystem side effects.

Primary test entrypoint:

```bash
python3 -m unittest tests.test_conformance_suite tests.test_shell_pipeline_regression tests.test_shell_runtime_integration
```
