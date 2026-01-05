下面补上你说的两份：**可执行装载格式（简化版）**与**用户态地址空间布局表**。依旧是最终规范风格、全面但保持最小可落地。

---

# 11) 可执行装载格式简化规范（SimMach-EXE v1）

## 11.1 设计目标

* 足够简单：便于 `Kernel.load_executable()` 快速实现
* 可支持 text/data/bss/stack、参数与环境变量
* 支持最小权限：RX（代码）、RW（数据）、RW（栈）
* 与“虚拟地址指针 + 页表”体系相容

## 11.2 文件整体结构（固定头 + 段表 + 段数据）

### 11.2.1 `ExeHeaderV1`（固定 64 bytes）

全部字段 Little-Endian。

| 偏移 | 长度 | 字段         | 类型  | 说明                      |
| -: | -: | ---------- | --- | ----------------------- |
|  0 |  4 | magic      | u32 | `0x534D5845`（"SMXE" 示例） |
|  4 |  2 | version    | u16 | 1                       |
|  6 |  2 | endian     | u16 | 1=LE，2=BE（本规范默认 1）      |
|  8 |  2 | arch       | u16 | 1=x86_64（示例）            |
| 10 |  2 | abi        | u16 | 1=SimMach ABI v1        |
| 12 |  4 | flags      | u32 | 可执行特性位（可选）              |
| 16 |  8 | entry      | u64 | 用户入口点（VirtAddr）         |
| 24 |  8 | phoff      | u64 | 段表（program header）文件偏移  |
| 32 |  4 | phnum      | u32 | 段表数量                    |
| 36 |  4 | phentsize  | u32 | 每个段表项大小（建议 56 bytes）    |
| 40 |  8 | file_size  | u64 | 文件总大小（可用于校验）            |
| 48 |  8 | image_base | u64 | 建议装载基址（可为 0 表示由内核决定）    |
| 56 |  8 | reserved   | u64 | 置 0                     |

**校验规则**

* magic/version/endianness/arch/abi 必须匹配，否则 `-EINVAL`
* `phoff + phnum*phentsize <= file_size`，否则 `-EINVAL`
* `entry` 必须落在某个 PT_LOAD 段的映射范围内，否则 `-EINVAL`

---

### 11.2.2 `ProgramHeaderV1`（每项建议 56 bytes）

| 偏移 | 长度 | 字段       | 类型  | 说明                       |
| -: | -: | -------- | --- | ------------------------ |
|  0 |  4 | p_type   | u32 | 段类型（见下）                  |
|  4 |  4 | p_flags  | u32 | 权限与属性（见下）                |
|  8 |  8 | p_offset | u64 | 段数据在文件内偏移                |
| 16 |  8 | p_vaddr  | u64 | 段装载到的用户虚拟地址              |
| 24 |  8 | p_filesz | u64 | 文件中段数据大小                 |
| 32 |  8 | p_memsz  | u64 | 内存中段大小（>= filesz，可含 bss） |
| 40 |  8 | p_align  | u64 | 对齐（通常 4096）              |
| 48 |  8 | p_resv   | u64 | 保留                       |

#### 段类型 `p_type`

* `0 = PT_NULL`：忽略
* `1 = PT_LOAD`：需要装载并映射的段
* `2 = PT_STACK`：可选，声明栈大小（否则用默认）
* `3 = PT_TLS`：可选（可不实现）
* `4 = PT_NOTE`：可选

#### 权限与属性 `p_flags`（bitflags）

* bit0 `PF_X`：可执行
* bit1 `PF_W`：可写
* bit2 `PF_R`：可读
* bit3 `PF_GROWSDOWN`：栈向下增长（仅 PT_STACK）
* bit4 `PF_ZERO`：要求把 memsz 全部清零（通常 data+bss 会需要）

---

## 11.3 装载语义（Kernel.load_executable 的规范流程）

### 11.3.1 基本流程

1. `open(path)` → 读取 `ExeHeaderV1`
2. 校验 header
3. 读取 `phnum` 个 `ProgramHeaderV1`
4. 创建用户 AddressSpace + PageTable（分配 root frame）
5. 对每个 `PT_LOAD`：

   * `p_vaddr` 与 `p_align` 页对齐（或要求文件保证）
   * 为 `[p_vaddr, p_vaddr+p_memsz)` 分配页并映射物理帧
   * 从文件读取 `p_filesz` bytes 写入内存
   * 若 `p_memsz > p_filesz`，把剩余部分清零（bss）
   * 权限：由 `p_flags` 设置页表权限（R/W/X）
6. 栈：

   * 若存在 `PT_STACK`：按其 `p_memsz` 分配栈
   * 否则用默认栈大小（见 12.2）
7. 构造初始用户栈（argv/envp/auxv 可选简化）
8. 初始化线程寄存器：

   * `RIP = entry`
   * `RSP = user_stack_top`
9. 进程表登记 pid/tid，返回

### 11.3.2 关键错误映射

* 文件结构错误：`-EINVAL`
* 找不到文件：`-ENOENT`
* 分配页帧失败：`-ENOMEM`
* 地址冲突/不在用户区：`-EINVAL`
* 访问用户区/内核区混淆：`-EFAULT` 或 `-EINVAL`（建议 `-EINVAL`）

---

## 11.4 初始栈布局（最小可用版本）

> 为了快实现，建议先用 “Linux 风格简化版”，但可以不实现 auxv。

在栈顶向下放置：

1. `argv strings`（以 `\0` 结尾）
2. `env strings`
3. 对齐到 16 bytes
4. `argv pointers[]`（指向字符串）
5. `envp pointers[]`
6. `argc`（u64 或 u32 均可，建议 u64）

**对齐要求**

* 进入用户态前：RSP 必须 16-byte 对齐（或 8-byte，取决于你模拟的 ABI；推荐 16）

---

# 12) 用户态地址空间布局表（User VA Layout v1）

## 12.1 设计目标

* 与 `mmap/brk/stack` 兼容
* 避免和内核高半区冲突
* 虚拟地址区间固定，便于 `PageAllocator` 管理与调试

> 假设：用户空间使用低半区（canonical lower half），内核使用高半区。

---

## 12.2 用户空间区域划分（推荐）

| 区域          | 虚拟范围（示例）                                          | 权限  | 说明                           |
| ----------- | ------------------------------------------------- | --- | ---------------------------- |
| Null Guard  | `0x0000_0000_0000_0000` ~ `0x0000_0000_0000_1000` | --- | 保护页，捕捉空指针                    |
| Text（代码）    | `0x0000_0000_0040_0000` ~ `0x0000_0000_2000_0000` | R-X | PT_LOAD 映射的 RX 段（默认从 4MB 开始） |
| Data/BSS    | `0x0000_0000_2000_0000` ~ `0x0000_0000_4000_0000` | RW- | RW 段、bss                     |
| Heap（brk）   | `0x0000_0000_4000_0000` ~ `0x0000_0000_6000_0000` | RW- | 传统堆（brk 增长）                  |
| mmap 区      | `0x0000_0000_6000_0000` ~ `0x0000_0000_7F00_0000` | 可变  | 匿名/文件映射区域（由 mmap 分配）         |
| Stack Guard | `0x0000_0000_7F00_0000` ~ `0x0000_0000_7F10_0000` | --- | 栈保护区（可选）                     |
| User Stack  | `0x0000_0000_7F10_0000` ~ `0x0000_0000_8000_0000` | RW- | 用户栈（向下增长，默认 15MB）            |

> 这些范围只是示例。关键在于：
>
> * stack 在高地址向下增长
> * heap 从固定 base 向上增长
> * mmap 在中间按需分配，避免与 heap/stack 冲突

---

## 12.3 默认大小建议

* 默认用户栈：8MB 或 16MB（文档示例 15MB）
* 默认 brk heap 初始：从 `0x4000_0000` 开始，初始 0 页，按需扩展
* mmap 分配粒度：页对齐（4KB）

---

## 12.4 地址合法性规则（用户/内核隔离）

* **用户指针**必须落在用户空间范围内（例如 `< 0x0000_8000_0000_0000`，以你的 canonical 规则为准）
* 用户不可映射内核高半区
* 内核 copy_from_user/copy_to_user 必须检查：

  * 是否在用户区
  * 是否映射存在
  * 是否权限正确

---

# 13) 装载与运行时序图补充（可执行格式 + 用户布局）

## 13.1 `load_executable` 关键时序（含段映射）

```
User        Kernel        FS         ExeParser    UserAS/PT     FrameAlloc      PhysMem
 |            |           |             |            |              |             |
 | load_exe   |           | lookup      |            |              |             |
 |----------->|---------->|-----------> |            |              |             |
 |            | read file |             |            |              |             |
 |            |---------->|-----------> |            |              |             |
 |            | parse hdr |-----------> | validate   |              |             |
 |            | parse ph  |-----------> | segments   |              |             |
 |            | create AS/PT           |            | create root   | alloc_frame |
 |            |------------------------------------->|<-------------|             |
 |            | for each PT_LOAD: map pages          | walk/map      | alloc_frame |
 |            |------------------------------------->|------------->|-----------> |
 |            | copy file bytes to mapped pages      | translate     |             |
 |            |--------------------------------------------------------------->   |
 |            | zero bss                             | translate     |             |
 |            |--------------------------------------------------------------->   |
 |            | setup stack                          | map stack     | alloc_frame |
 |            |------------------------------------->|------------->|-----------> |
 |            | set RIP/RSP return pid/tid           |              |             |
 |<-----------|                                       |              |             |
```

---

# 14) 与现有规范的接合点（你实现时最关键的几条）

1. **String SSO 的 heap_ptr 是 VirtAddr**

   * heap_ptr 指向“外部 UTF-8 bytes”的起始地址
   * 推荐复用 Bytes 对象的 payload：`heap_ptr = bytes_obj_ptr + 16`

2. **HandleRecord.obj_ptr 是 VirtAddr**

   * 指向对象头（ObjectHeader 起始）或 inode_no（若 InodeRef 选择 inode_no 策略）
   * 若 InodeRef 用 inode_no，则必须在 codec 中明确“obj_ptr 存的是 inode_no 而不是地址”

3. **load_executable** 必须保证：

   * PT_LOAD 的映射范围落在用户布局的合法区间
   * 权限按 flags 设置（RX/RW）
   * 栈按用户布局固定区间分配

4. **所有用户指针**都必须经过 copy_*_user 逐页检查，否则 EFAULT

---

如果你希望把这份最终文档再“出版级”整理（统一编号、术语表、字段常量表、HandleType 数值分配表、syscall 号表等），我也可以继续把它变成一份完整的 `SPEC.md` 形式（仍不写实现代码）。
