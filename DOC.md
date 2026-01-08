# SimMach 编程与架构指南 (Comprehensive Programming & Architecture Guide)

本文档旨在为 SimMach 模拟机系统的开发者和用户提供深入的架构分析、指令集参考、内存布局及系统调用接口说明。SimMach 是一个基于 Python 实现的高性能 RISC-V 兼容模拟环境，包含完整的内存管理、文件系统、进程管理以及自定义的 ALU 加速引擎。

---

## 1. 系统概览 (System Overview)

SimMach 是一个分层架构的模拟系统，从底层的位操作到高层的操作系统外壳（Shell），每一层都经过精心设计以模拟真实的计算机行为。

### 1.1 核心组件
- **MemoryALU**: 基于内存描述符的计算引擎，支持 64 位有符号/无符号运算及溢出捕获。
- **RiscVCPU**: 兼容 RV64I 指令集的模拟 CPU 核心，支持 RV64I 基础指令集及部分 64 位扩展指令。
- **AddressSpace / PageTable**: 提供三级页表（Sv39 风格）映射的虚拟内存管理，支持读、写、执行权限控制。
- **TinyFS / BetterFS**: 两种不同复杂度的模拟文件系统，BetterFS 支持目录树、位图管理及随机读写。
- **Kernel**: 核心管理模块，负责进程调度、系统调用分发、信号/异常处理及资源回收。
- **HandleManager**: 结构化对象（String, Bytes, Int64）的句柄管理系统，支持对象的序列化与生命周期管理。

---

## 2. 内存架构 (Memory Architecture)

SimMach 采用了经典的页表映射机制，模拟了现代处理器的 MMU 行为。

### 2.1 物理内存 (PhysMem)
物理内存由一个连续的 `bytearray` 组成，所有访问都必须通过物理地址。
- **PAGE_SIZE**: 4096 字节 (4KB)。
- **LITTLE_ENDIAN**: 所有的数值存储均遵循小端序（`<`）。

### 2.2 页表结构 (PageTable)
采用 Sv39 风格的三级页表：
- **VPN2 (Level 2)**: 位 30-38，指向二级页表。
- **VPN1 (Level 1)**: 位 21-29，指向一级页表。
- **VPN0 (Level 0)**: 位 12-20，指向物理页帧。
- **Offset**: 位 0-11，页内偏移。

### 2.3 访问权限 (PageFlags)
| 标志位 | 值 | 说明 |
| :--- | :--- | :--- |
| `PageFlags.R` | 0x1 | 可读 (Read) |
| `PageFlags.W` | 0x2 | 可写 (Write) |
| `PageFlags.X` | 0x4 | 可执行 (Execute) |
| `PageFlags.USER` | 0x8 | 用户模式可访问 (User Mode) |

---

## 3. 核心数据结构与查找表 (Core Structures & Lookup Tables)

### 3.1 对象存储结构

#### 对象头 (ObjectHeader)
所有在堆上分配的对象（如句柄背后的实体）都以此开头。
- **Size**: 16 字节
- **Magic**: `0x4F424A01`
- **结构定义**: `[u32 magic][u16 type][u16 flags][u32 byte_len][u32 byte_cap]`

#### 句柄记录 (HandleRecord)
用于描述一个句柄所指向的资源。
- **Size**: 32 字节
- **结构定义**: `[u32 version][u16 type][u16 state][u32 owner_pid][u32 refcnt][u64 obj_ptr][u32 obj_len][u32 obj_cap]`

### 3.2 句柄类型 (HandleType)
句柄用于跨进程共享和安全访问结构化数据。

| 类型名 | 枚举值 | 说明 |
| :--- | :--- | :--- |
| `Int64` | 1 | 64位有符号整数，存储在 8 字节 Payload 中。 |
| `Bytes` | 2 | 原始字节流，支持动态扩容。 |
| `String` | 3 | 字符串对象，采用 SSO (Small String Optimization) 优化。 |
| `Inode` | 4 | 文件系统索引节点，用于文件描述符。 |

### 3.3 系统调用查找表 (Syscall Table)
用户态程序通过 `ecall` 指令触发系统调用。寄存器映射：`a7` (Sysno), `a0-a5` (Args), `a0` (Return Value)。

| 名称 | 编号 (Sysno) | a0 参数 | a1 参数 | a2 参数 | 说明 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `EXIT` | 1 | `exit_code` | - | - | 退出当前进程 |
| `WRITE` | 2 | `fd` | `buf_ptr` | `count` | 写入文件/控制台 |
| `READ` | 3 | `fd` | `buf_ptr` | `count` | 读取文件/控制台 |
| `OPEN` | 4 | `path_ptr` | `flags` | - | 打开文件 |
| `CLOSE` | 5 | `fd` | - | - | 关闭文件 |
| `MMAP` | 6 | `addr` | `length` | `prot` | 内存映射 |
| `MUNMAP` | 7 | `addr` | `length` | - | 取消内存映射 |
| `BRK` | 8 | `new_brk` | - | - | 改变堆大小 |
| `CALC` | 11 | `desc_ptr` | - | - | 硬件加速计算 (ALU) |
| `FORK` | 12 | - | - | - | 克隆当前进程 |
| `EXECVE` | 13 | `path_ptr` | `argv_ptr` | `envp_ptr` | 加载新程序 |
| `WAITPID` | 14 | `pid` | `status_ptr`| - | 等待子进程退出 |
| `PIPE` | 18 | `fds_ptr` | - | - | 创建管道 |
| `DUP2` | 19 | `oldfd` | `newfd` | - | 复制文件描述符 |

---

## 4. MemoryALU 运算规范

MemoryALU 是一个独立的硬件模拟加速单元，允许用户通过内存描述符进行复杂的 64 位运算。

### 4.1 计算描述符 (CalcDesc)
用户需要先在内存中构建此结构，然后将其地址传递给 `sys_calc`。
- **Size**: 32 字节
- **结构**: `[u32 op][u32 flags][u64 a_ptr][u64 b_ptr][u64 out_ptr]`

### 4.2 算术操作码 (CalcOp)
| 操作码 | 枚举值 | 说明 |
| :--- | :--- | :--- |
| `ADD` | 1 | `*out = *a + *b` |
| `SUB` | 2 | `*out = *a - *b` |
| `MUL` | 3 | `*out = *a * *b` |
| `DIV` | 4 | `*out = *a / *b` (b=0 时抛出异常) |
| `AND` | 5 | 按位与 |
| `OR` | 6 | 按位或 |
| `XOR` | 7 | 按位异或 |
| `SHL` | 8 | 逻辑左移 |
| `SHR` | 9 | 算术右移 (SIGNED=1) 或逻辑右移 (SIGNED=0) |
| `CMP` | 10 | 比较: a<b -> -1, a==b -> 0, a>b -> 1 |

---

## 5. RISC-V 指令集实现 (RV64I)

SimMach 实现了 RV64I 的核心子集，支持 64 位整数运算和内存访问。

### 5.1 基础整数指令 (Opcode: 0x13, 0x33)
- **ADDI / ADD**: 整数加法。
- **SLTI / SLT**: 设置小于则为 1 (Signed)。
- **SLTIU / SLTU**: 设置小于则为 1 (Unsigned)。
- **ANDI / AND**: 按位与。
- **ORI / OR**: 按位或。
- **XORI / XOR**: 按位异或。
- **SLLI / SLL**: 逻辑左移。
- **SRLI / SRL**: 逻辑右移。
- **SRAI / SRA**: 算术右移。

### 5.2 64位扩展指令 (Opcode: 0x1B, 0x3B)
这些指令处理 32 位操作数并对结果进行符号扩展。
- **ADDIW / ADDW**: 32位加法并符号扩展。
- **SUBW**: 32位减法。
- **SLLIW / SLLW**: 32位左移。
- **SRLIW / SRLW**: 32位逻辑右移。
- **SRAIW / SRAW**: 32位算术右移。

### 5.3 内存与跳转
- **LOAD (0x03)**: LB, LH, LW, LD, LBU, LHU, LWU。支持字节到双字的加载。
- **STORE (0x23)**: SB, SH, SW, SD。
- **BRANCH (0x63)**: BEQ, BNE, BLT, BGE, BLTU, BGEU。
- **JAL / JALR**: 实现函数调用和间接跳转。

---

## 6. 文件系统架构 (TinyFS & BetterFS)

### 6.1 BetterFS 磁盘布局
BetterFS 是一个基于块设备的日志结构友好型文件系统。
- **Block 0**: 超级块 (Superblock)，存储 FS 魔法数字、块大小、Inode 区域位置。
- **Inode Table**: 存储 `BetterInode` 结构，支持 12 个直接块指针。
- **Bitmap**: 数据块分配位图，用于追踪空闲块。
- **Data Blocks**: 实际存储文件内容和目录项的区域。

### 6.2 目录项 (Directory Entry)
目录文件内容是由 `DENT` 结构组成的列表。
- **Size**: 64 字节
- **结构**: `[48s name][u32 inum][12s reserved]`

---

## 7. 句柄系统与字符串优化 (SSO)

SimMach 的字符串处理非常高效，主要归功于 `StringBody` 的 SSO 实现。

### 7.1 StringBody 布局
- **Mode 0 (SSO)**:
  - `byte_len`: 实际长度 (<= 24)。
  - `sso_bytes`: 直接存储 24 字节以内的内容，无需额外堆分配。
- **Mode 1 (Heap)**:
  - `heap_ptr`: 指向外部分配的字节数组。
  - `heap_len`: 字符串长度。
  - `heap_cap`: 堆空间容量。

---

## 8. 进程与线程管理

### 8.1 进程控制块 (Process)
每个进程拥有独立的：
- **AddressSpace**: 独立的页表映射。
- **File Descriptor Table**: 映射整数 FD 到 `OpenFile` 或 `PipeEnd`。
- **CWD**: 当前工作目录。
- **Mmap Bookkeeping**: 记录 `mmap_regions` 及其对应的文件映射。

### 8.2 可执行文件格式 (SMX1 / RVEX1)
支持两种格式：
1. **SMX1 (Script-based)**: 基于自定义脚本指令序列，用于快速测试系统调用。
2. **RVEX1 (RISC-V)**: 真正的 RISC-V 二进制镜像，包含段信息（PT_LOAD）和入口点（Entry）。

---

## 9. 编程最佳实践

### 9.1 内存安全
- **页对齐**: 使用 `mmap` 或映射内存时，地址必须是 4096 的倍数。
- **用户权限**: 在内核态编写模拟逻辑时，使用 `user=True` 参数调用 `read/write` 以确保不越权访问内核内存。

### 9.2 计算优化
- 频繁的大数据量计算应优先使用 `sys_calc` 而非 RISC-V 原生循环，以利用 Python 底层的 `struct` 处理能力。

---

## 10. 异常与错误码参考 (Lookup Table)

| 错误名 (Errno) | 值 | 说明 |
| :--- | :--- | :--- |
| `ENOENT` | -2 | 文件或路径不存在。 |
| `EBADF` | -9 | 提供的文件描述符无效。 |
| `ECHILD` | -10 | waitpid 等待的子进程不存在。 |
| `EAGAIN` | -11 | 资源暂时不可用（通常见于非阻塞等待）。 |
| `ENOMEM` | -12 | 物理内存或虚拟堆空间耗尽。 |
| `EACCES` | -13 | 试图访问受保护的内存或文件。 |
| `EFAULT` | -14 | 用户提供的指针指向未映射或非法的地址。 |
| `EINVAL` | -22 | 参数错误（如除以零、未对齐的地址）。 |

---

## 11. 深入架构分析 (Deep Architecture Analysis)

### 11.1 虚拟内存管理细节 (Virtual Memory Internals)

SimMach 的虚拟内存系统不仅模拟了地址转换，还实现了复杂的内存分配策略。

#### 11.1.1 三级页表转换流程 (Walk Logic)
当 CPU 或内核访问一个虚拟地址时，`PageTable.walk` 执行以下步骤：
1. **VPN 分离**: 从 64 位虚拟地址中提取 `vpn2`, `vpn1`, `vpn0` 以及 12 位页内偏移。
2. **多级查找**:
   - 访问 `root[vpn2]` 获取二级页表。
   - 访问 `level2[vpn1]` 获取一级页表。
   - 访问 `level1[vpn0]` 获取 `PageMapping`。
3. **权限检查**: 如果 `user=True`，则检查 `PageFlags.USER` 位。如果是写入操作，检查 `PageFlags.W` 位；如果是执行操作，检查 `PageFlags.X` 位。
4. **TLB 缓存**: 为了加速转换，系统实现了一个简单的 TLB 字典，缓存 `(virt_page_base, write, execute, user)` 到 `(phys_addr, flags)` 的映射。

#### 11.1.2 堆分配器 (Heap Allocators)
系统提供两种堆分配器：
- **PageAllocator**: 以页为单位进行大块分配，主要用于句柄表等内核数据结构。采用简单的 Free-list 跨度管理，并支持自动页映射。
- **ValueHeapAllocator**: 提供细粒度的块分配（类似于 `malloc`）。
  - **空闲链表管理**: 使用 `_coalesce_spans` 合并相邻的空闲空间，减少内存碎片。
  - **BRK 机制**: 维护一个 `_brk` 指针，当空闲链表无法满足需求时，自动向上扩展堆空间并映射新物理页。

### 11.2 BetterFS 深度解析 (BetterFS Internals)

BetterFS 模拟了一个相对完整的 Unix 风格文件系统。

#### 11.2.1 索引节点 (BetterInode)
每个 Inode 包含：
- `inum`: 唯一的节点编号。
- `is_dir`: 是否为目录标志。
- `size_bytes`: 文件或目录的大小。
- `direct`: 包含最多 12 个直接块指针的列表。这限制了 BetterFS 单个文件的最大大小为 `12 * block_size`。

#### 11.2.2 目录结构实现
目录在 BetterFS 中只是一个 `is_dir=True` 的特殊文件。其数据块内容为一系列连续的 `DENT` (Directory Entry) 结构。
- **查找过程**: `lookup` 函数通过 `/` 分割路径，逐级读取目录文件的数据块，解析 `DENT` 列表以获取下一级 Inode 编号。
- **创建过程**: `_create_child` 分配新 Inode，更新父目录的数据块（添加新的 `DENT`），并增加目录的大小。

#### 11.2.3 位图与块管理
- **Data Bitmap**: 存储在磁盘的固定区域。每个 bit 代表一个数据块的占用状态。
- **分配策略**: `_alloc_block` 线性扫描位图寻找第一个为 0 的 bit，将其设为 1 并写回磁盘，同时对该块进行清零。

### 11.3 进程间通信：管道 (Pipes)

SimMach 支持基于系统调用的匿名管道。

#### 11.3.1 管道生命周期
- **创建**: `sys_pipe` 分配一个新的 `Pipe` 对象（内核态缓冲区）和两个 `PipeEnd`（读端和写端）。
- **引用计数**: 每个 `Pipe` 维护 `readers` 和 `writers` 计数。`fork` 时，子进程继承 `PipeEnd` 并增加引用计数。
- **关闭**: 当最后一个读者或写者关闭文件描述符时，内核释放管道占用的资源。

### 11.4 句柄管理与序列化

句柄系统是 SimMach 处理复杂对象的关键抽象。

#### 11.4.1 Codec 机制
每个 `HandleType` 对应一个 `Codec` 实现：
- **Int64Codec**: 使用 `struct.pack("<q", value)` 将 64 位整数序列化。
- **BytesCodec**: 管理变长字节数组，支持指数增长的扩容策略。
- **StringCodec**: 负责 SSO (Small String Optimization) 逻辑，协调 `StringBody` 和 `BytesCodec`。

#### 11.4.2 内存安全性
句柄访问始终是受控的。`HandleManager` 通过 `HandleTable` 查找 `HandleRecord`，然后根据 `type_id` 调用对应的 `Codec`。由于 `obj_ptr` 存储在内核管理的 `HandleRecord` 中，用户态程序无法伪造或直接篡改对象地址。

---

## 12. 系统调用深度参考手册 (Deep Syscall Reference)

### 12.1 进程管理 (Process Management)

#### `sys_fork (12)`
- **操作**: 深度克隆当前进程。
- **内存拷贝**: 遍历父进程页表，为子进程分配新页帧并拷贝内容。
- **FD 拷贝**: 复制文件描述符表，增加 Inode 或管道端的引用计数。
- **返回值**: 父进程获得子进程 PID，子进程获得 0。

#### `sys_execve (13)`
- **操作**: 用新程序替换当前进程镜像。
- **流程**:
  1. 读取并校验新程序（ELF/RVEX）。
  2. 释放旧的页表和内存映射。
  3. 创建新页表，加载程序段。
  4. 建立新的用户栈，压入 `argv` 和 `envp`。
  5. 重置 CPU 的 PC 指针。

### 12.2 内存映射 (Memory Mapping)

#### `sys_mmap (6)`
- **参数**: `rdi=addr`, `rsi=len`, `rdx=prot`, `r10=flags`, `r8=fd`, `r9=off`
- **支持类型**:
  - `MAP_ANON`: 分配零初始化的私有内存。
  - `MAP_SHARED`: 映射文件到内存。SimMach 支持写回（Writeback）机制，当进程退出或显式取消映射时，修改的内容会同步回文件系统。

### 12.3 硬件加速 (ALU Acceleration)

#### `sys_calc (11)`
这是 SimMach 的一个独特系统调用，用于弥补 RISC-V 模拟器在执行复杂数学运算时的性能损失。它直接调用内核态的高性能 `MemoryALU`。

---

## 13. 开发者调试指南

### 13.1 控制台设备 (ConsoleDevice)
内核集成了一个模拟控制台，支持 ANSI 转义序列。通过 `sys_readkey` 可以读取方向键、退出键等。

### 13.2 错误追踪
当发生 `PageFault` 或 `InvalidAddress` 时，模拟器会打印详细的错误现场，包括：
- 触发异常的虚拟地址。
- 访问类型（Read/Write/Execute）。
- 当前 PC 指针。

---

## 14. 查找表摘要 (Comprehensive Lookup Tables)

### 14.1 寄存器别名 (RV64 ABI)
| 寄存器 | 别名 | 用途 |
| :--- | :--- | :--- |
| `x0` | `zero` | 常数 0 |
| `x1` | `ra` | 返回地址 |
| `x2` | `sp` | 栈指针 |
| `x8` | `s0/fp` | 保存寄存器/帧指针 |
| `x10-x11` | `a0-a1` | 函数参数/返回值 |
| `x12-x17` | `a2-a7` | 函数参数 |
| `x17` | - | 系统调用号 (a7) |

### 14.2 文件权限标志 (O_FLAGS)
- `O_CREAT (1)`: 不存在则创建。
- `O_APPEND (2)`: 追加模式。
- `O_TRUNC (4)`: 截断到 0 长度。

### 14.3 计算标志位 (CalcFlags)
- `SIGNED (0x1)`: 开启补码有符号运算。
- `TRAP_OVERFLOW (0x2)`: 溢出时立即中止。

---

## 15. 总结

SimMach 不仅仅是一个简单的指令集模拟器，它通过句柄系统、复杂的文件系统实现和内存加速引擎，构建了一个可以运行小型多任务系统的完备环境。深入理解其页表转换、堆分配策略和系统调用分发机制，对于开发高效的模拟程序至关重要。

## 16. 关键算法实现细节分析 (Algorithm Implementation Details)

### 16.1 页表遍历 (Page Table Walking) 算法

`PageTable.walk` 是整个模拟器中被调用最频繁的函数之一。其实现通过递归或迭代方式模拟了 MMU 的三级查找过程。

#### 16.1.1 核心逻辑 (simmach/mem.py)
```python
def walk(self, virt_addr: int, *, write: bool = False, execute: bool = False, user: bool = False) -> Tuple[int, PageFlags]:
    virt_page_base = _align_down(virt_addr)
    # TLB 快速查找
    if user:
        cached = self._tlb.get((int(virt_page_base), bool(write), bool(execute), True))
        if cached is not None:
            phys_addr, flags = cached
            offset = virt_addr - virt_page_base
            return int(phys_addr + offset), PageFlags(flags)

    # 逐级查找逻辑
    # ... 从 self._l2 开始分级查找 vpn2, vpn1, vpn0
```
该算法保证了虚拟地址到物理地址转换的 O(1) 复杂度（三层嵌套字典查找），并通过 TLB 显著提升了重复访问同一页面的效率。

### 16.2 内存 ALU (MemoryALU) 执行流

`MemoryALU.exec` 的实现体现了对 64 位算术运算的精确控制，特别是在 Python 的变长整数环境下模拟固定位宽的溢出行为。

#### 16.2.1 溢出处理与补码转换
```python
def _mask_u64(x: int) -> int:
    return x & 0xFFFF_FFFF_FFFF_FFFF

def _to_i64(x: int) -> int:
    x = _mask_u64(x)
    return x - (1 << 64) if (x >> 63) else x

def _from_i64(x: int) -> int:
    return _mask_u64(x)
```
- **SIGNED 模式**: 运算前将 U64 原始字节转换为有符号整数，执行 Python 级运算后，再检查是否超出 `[-2^63, 2^63-1]` 范围。
- **TRAP_OVERFLOW**: 若设置此标志且发生越界，系统将抛出 `OverflowError`，最终反映为系统调用返回 `EINVAL`。

### 16.3 BetterFS 目录项查找算法

在 `BetterFS.lookup` 中，路径解析采用迭代遍历目录树的方式。

#### 16.3.1 路径解析伪代码
1. 输入路径 `path = "/bin/ls"`。
2. 调用 `_split_path` 得到 `['bin', 'ls']`。
3. 从 `root_inum` (1) 开始。
4. 在当前 Inode 的数据块中读取所有 `DENT` 结构。
5. 遍历 `DENT` 列表，匹配名字 `"bin"`，获取其 `inum`。
6. 跳转到步骤 4，直到解析完所有路径部分或遇到缺失项。

### 16.4 RISC-V 指令解码与执行循环

`RiscVCPU.step` 是 CPU 模拟的核心，采用了基于操作码分发的“取指-译码-执行”循环。

#### 16.4.1 指令解码宏 (simmach/riscv.py)
```python
def _get_bits(x: int, lo: int, hi: int) -> int:
    mask = (1 << (hi - lo + 1)) - 1
    return (int(x) >> lo) & mask

def _imm_i(insn: int) -> int:
    return _sign_extend(_get_bits(insn, 20, 31), 12)
```
系统通过位偏移和掩码操作，高效地从 32 位指令编码中提取 `rd`, `rs1`, `rs2`, `funct3`, `funct7` 以及各类立即数（I-type, S-type, B-type, U-type, J-type）。

### 16.5 管道 (Pipe) 缓冲与同步机制

管道的实现依赖于内核态的 `bytearray`。

#### 16.5.1 阻塞与引用计数
虽然目前的 `sys_read/sys_write` 对管道是非阻塞的，但内核通过引用计数 `readers/writers` 管理其生命周期。
- 如果 `writers == 0`，对管道的 `read` 将立即返回 0（EOF）。
- 如果 `readers == 0`，对管道的 `write` 将导致错误。

## 17. 引导加载程序 (Loader) 与进程启动

### 17.1 RVEX1 文件加载过程

加载器 `load_rv_executable` 负责将二进制镜像加载进进程的虚拟地址空间：
1. **解析头部**: 读取 `MAGIC_RVEX_V1` 并验证版本。
2. **段映射**: 遍历 `ProgramHeader` (PT_LOAD)，计算所需的页数。
3. **内存分配**: 在进程页表中映射虚拟页面，设置初始权限为 `W` (写)。
4. **数据拷贝**: 将文件中的段内容拷贝到对应的虚拟地址。
5. **权限降级**: 根据段头部的 `flags` (PF_R, PF_W, PF_X)，将页面权限调整为最终状态。
6. **栈初始化**: 调用 `_build_rv_initial_stack` 在高地址（如 `0x4000_0000`）分配栈空间，并压入 `argc`, `argv`, `envp`。

### 17.2 初始寄存器设置
在进程切换到用户态运行前，内核会设置 CPU 寄存器：
- `sp (x2)`: 设置为初始化后的栈指针位置。
- `a0 (x10)`: 设置为 `argc`。
- `a1 (x11)`: 设置为 `argv` 数组的指针。
- `a2 (x12)`: 设置为 `envp` 数组的指针。
- `pc`: 设置为程序入口点 (Entry Point)。

## 18. 系统扩展与自定义

### 18.1 添加新的系统调用
开发者可以通过以下步骤向 SimMach 添加新功能：
1. 在 `constants.py` 的 `Sysno` 枚举中定义新编号。
2. 在 `kernel.py` 中编写对应的 `_sys_xxx` 成员方法。
3. 在 `_install_syscalls` 中注册该方法。
4. 如果是复杂的对象操作，考虑在 `handle.py` 中增加新的 `Codec`。

### 18.2 添加自定义 ALU 指令
MemoryALU 的架构允许轻松扩展运算指令：
1. 在 `CalcOp` 枚举中定义新操作码。
2. 修改 `alu.py` 中的 `exec` 方法，加入新的算术处理分支。

---

## 19. 性能分析与局限性 (Analysis & Limitations)

### 19.1 性能特性
- **优点**: 内存管理非常轻量化；ALU 加速显著减少了模拟开销；Python 的动态特性使得文件系统调试非常直观。
- **缺点**: 相比于 C 编写的模拟器，纯解释执行的指令流速度较慢（约 1-10 MIPS）；不支持多核心 SMP 模拟。

### 19.2 未来改进方向
- **JIT 编译**: 引入简单的动态翻译技术，将 RISC-V 指令块转换为 Python 字节码。
- **异步 I/O**: 基于 `asyncio` 重新实现 I/O 层，以支持真正的并发网络设备模拟。

---

## 20. 结语与致谢

SimMach 是一个极具教学价值和研究潜力的微型模拟机系统。它完整地重现了现代操作系统与硬件之间的交互边界，是学习操作系统原理、编译器后端设计以及计算机体系结构的理想实验平台。

(文档结束)

