# SimMach Memory ABI Notes (MVP)

## User Pointer Contract
- Kernel must access user buffers only through:
  - `Kernel.copy_from_user`
  - `Kernel.copy_to_user`
  - `Kernel.read_cstring_from_user`
- Negative pointers and unmapped pages are faults.
- Syscalls must surface pointer failures as `-EFAULT`.

## Address Space Model
- Each process has an independent `AddressSpace` and page table.
- User mappings require `PageFlags.USER`.
- `PageFlags.R/W/X` gate read/write/execute checks in `PageTable.walk`.

## mmap/munmap Rules
- `mmap` length must be positive; addresses page-aligned when specified.
- `MAP_FILE` and `MAP_ANON` are mutually exclusive.
- `MAP_SHARED` valid only for file-backed mappings.
- `munmap` requires page-aligned start and positive length.
