# SimOS Shell Runtime Notes

## Runtime Model
- `simos.shell_runtime._run_program` creates a fresh process for each `run`.
- Arguments are marshaled as user-space C strings and `argv[]` pointers.
- Program execution happens through `execve` + RV64 runner.
- Processes are always reaped by runtime cleanup on both success and exec failure.

## Error Surface
- Missing binary returns `Errno.ENOENT` from `run`.
- Other syscall failures flow back as negative errno values.

## Pipeline Dependencies
- Shell pipeline execution relies on kernel `pipe` + `dup2` semantics.
- Regression coverage ensures stdout rewiring and stale-pipe cleanup behavior.
