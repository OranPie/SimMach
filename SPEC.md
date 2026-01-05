下面是你要的**最终全面规范文档**（虚构 `simmach` 体系，采用：**虚拟地址指针（VirtAddr）+ SSO**）。
内容覆盖：总体分层、内核内存布局、对象编码（Int64/String/HandleRecord）、HandleType→Codec 映射、最小系统调用 ABI、用户指针拷贝规则、关键错误映射、引导与运行时序图。

---

# SimMach（虚构）底层模拟机器：最终规范文档

**版本**：1.0
**默认字节序**：Little-Endian（LE）
**指针语义**：虚拟地址指针（VirtAddr，64-bit）

---

## 目录

1. 总体原则与分层
2. 内核虚拟内存布局表（固定区间）
3. 基础编码与通用规则（对齐/大小端/布尔/版本）
4. 值对象编码规范（Int64 / Bytes / String SSO）
5. 句柄系统规范（HandleTable / HandleRecord / 生命周期）
6. HandleType → Codec 映射表
7. 最小系统调用 ABI（编号/签名/语义/错误）
8. 用户指针访问与拷贝规范（copy_from_user/copy_to_user）
9. 错误与 errno 映射表
10. 时序图（引导、装载、运行、关机）

---

# 1. 总体原则与分层

## 1.1 终极资源与 limit 生效路径

* 唯一终极资源池：`PhysMem(size_bytes)`（连续 Byte array）
* 所有上层资源都必须可追溯到 PhysMem 的消耗：

  * `FrameAllocator` 分配页帧 → OOM 由 `PhysMem` 决定
  * `PageAllocator` 分配虚拟堆页 → 需要 `FrameAllocator.alloc_frame()`
  * `HandleTable` 记录区 + `ValueHeap` 值对象区 → 必须来自 `PageAllocator` 的映射页
  * 任何“对象状态”（Int64/String/Bytes/HandleRecord）必须落在 **内核可计量 Bytes** 上，禁止只存在于宿主语言对象中

## 1.2 分层模块（建议）

* `simmach.hw`：Machine/CPU/Bus/INTC/Clock
* `simmach.mem`：PhysMem/FrameAllocator/AddressSpace/PageTable/PageAllocator
* `simmach.io`：ConsoleDevice（MMIO）
* `simmach.fs`：BlockDevice/SuperBlock/Inode
* `simmach.handle`：HandleTable/HandleRecord/HandleType/Codecs
* `simmach.kernel`：Kernel/ProcessTable/SyscallTable/Loader/Scheduler-loop
* `simmach.errors`：OOMError/ResourceLimitError/InvalidAddress

---

# 2. 内核虚拟内存布局表（固定区间，VirtAddr 稳定）

> 目标：**虚拟地址指针稳定**。因此内核关键区间必须固定，且不搬迁或提供重定位（本规范默认不搬迁）。

## 2.1 高半区建议布局（x86-64 风格示例）

| 区域              | 虚拟范围（64-bit）                                      | 权限     | backed    | 说明                         |
| --------------- | ------------------------------------------------- | ------ | --------- | -------------------------- |
| Kernel Text     | `0xFFFF_8000_0000_0000` ~ `0xFFFF_8000_0040_0000` | R-X    | Mapped    | 内核代码（示例 4MB）               |
| Kernel ROData   | `0xFFFF_8000_0040_0000` ~ `0xFFFF_8000_0060_0000` | R--    | Mapped    | 只读常量                       |
| Kernel Data/BSS | `0xFFFF_8000_0060_0000` ~ `0xFFFF_8000_0080_0000` | RW-    | Mapped    | 全局数据                       |
| Per-CPU         | `0xFFFF_8100_0000_0000` ~ `0xFFFF_8100_0100_0000` | RW-    | Mapped    | 每 CPU 数据                   |
| Kernel Heap     | `0xFFFF_9000_0000_0000` ~ `0xFFFF_9000_1000_0000` | RW-    | On-demand | PageAllocator 管理（示例 256MB） |
| HandleTable     | `0xFFFF_9000_1000_0000` ~ `0xFFFF_9000_1100_0000` | RW-    | On-demand | 句柄记录区（示例 16MB）             |
| ValueHeap       | `0xFFFF_9000_1100_0000` ~ `0xFFFF_9000_2000_0000` | RW-    | On-demand | 值对象堆（示例 240MB）             |
| Kernel Stacks   | `0xFFFF_A000_0000_0000` ~ `0xFFFF_A000_1000_0000` | RW-    | Mapped    | 内核线程栈                      |
| MMIO Window     | `0xFFFF_F000_0000_0000` ~ `0xFFFF_F000_1000_0000` | RW- UC | Mapped    | MMIO（不可缓存）                 |
| Direct Map（可选）  | `0xFFFF_C000_0000_0000` ~ `0xFFFF_E000_0000_0000` | RW-    | Mapped    | 物理内存线性映射                   |

**关键约束**

* `HandleRecord.obj_ptr` 指向的对象必须在 `ValueHeap` 或其他稳定区间内
* `HandleTable` 记录区必须在 `HandleTable` 区间内
* 如果实现会重映射/压缩堆，需要同时“修复虚拟指针”；本规范默认不做

---

# 3. 基础编码与通用规则

## 3.1 大小端

* 默认 **Little-Endian**（LE）
* 所有整数、长度、指针字段均按 LE 编码

## 3.2 对齐

* `u64/i64`：8 对齐
* `u32/i32`：4 对齐
* `HandleRecord`：记录起始建议 16 对齐（强烈建议）
* `ObjectHeader`：16 bytes，起始建议 16 对齐

## 3.3 布尔

* `bool` = `u8`：`0x00=false`，`0x01=true`（建议只使用 0/1）

## 3.4 版本与 magic

* 可持久/可调试结构建议包含：

  * `magic`（可选但推荐）
  * `version`（必选）
  * `size`/`cap`（必选）

---

# 4. 值对象编码规范（ValueHeap）

ValueHeap 对象统一建议使用对象头，便于调试、回收、一致性验证。

## 4.1 统一对象头 `ObjectHeader`（推荐）

**ObjectHeader（16 bytes）**

| 偏移 | 长度 | 字段       | 类型  | 说明                       |
| -: | -: | -------- | --- | ------------------------ |
|  0 |  4 | magic    | u32 | `0x4F424A01`（示例）         |
|  4 |  2 | type     | u16 | 对齐 HandleType id         |
|  6 |  2 | flags    | u16 | bitflags（SSO/readonly/…） |
|  8 |  4 | byte_len | u32 | payload 有效长度             |
| 12 |  4 | byte_cap | u32 | payload 容量               |

> 后续 payload 紧随其后：`payload_ptr = obj_ptr + 16`

---

## 4.2 `Int64` 对象（HandleType.Int64）

**对象布局**

* `[ObjectHeader(16)] + [i64(8)] + [padding(0..7)]`
* `byte_len = 8`，`byte_cap >= 8`

**payload**

| 偏移（相对 payload） | 长度 | 字段                 |
| -------------: | -: | ------------------ |
|              0 |  8 | `value_i64`（LE 补码） |

---

## 4.3 `Bytes` 对象（HandleType.Bytes）

**对象布局**

* `[ObjectHeader(16)] + [raw bytes (byte_cap bytes)]`

**规则**

* `byte_len <= byte_cap`
* `set` 写入长度可变，超过 cap 必须扩容（重新分配新对象块并更新 HandleRecord）

---

## 4.4 `String` 对象（HandleType.String，SSO + 虚拟指针）

### 4.4.1 StringObject 固定大小（推荐实现版本）

**总大小**：64 bytes（固定）
**布局**：`[ObjectHeader(16)] + [StringBody(48)]`

### 4.4.2 `StringBody`（48 bytes）布局

| 偏移（相对 body） | 长度 | 字段        | 类型        | 说明                          |
| ----------: | -: | --------- | --------- | --------------------------- |
|           0 |  1 | mode      | u8        | 0=SSO, 1=HEAP               |
|           1 |  1 | reserved  | u8        | 扩展                          |
|           2 |  2 | reserved2 | u16       | 扩展                          |
|           4 |  4 | byte_len  | u32       | UTF-8 字节长度                  |
|           8 |  8 | heap_ptr  | u64       | **VirtAddr**（mode=HEAP 时有效） |
|          16 |  4 | heap_cap  | u32       | 外部容量                        |
|          20 |  4 | heap_len  | u32       | 外部有效长度                      |
|          24 | 24 | sso_bytes | bytes[24] | SSO 内联最多 24 bytes           |

### 4.4.3 行为规则

* 若 `byte_len <= 24`：

  * `mode=SSO`
  * 写入 `sso_bytes[0:byte_len]`
  * 清零其余部分（可选但推荐）
  * `heap_ptr/cap/len` 可清零
* 若 `byte_len > 24`：

  * `mode=HEAP`
  * `heap_ptr` 指向**外部 raw UTF-8 bytes 的起始地址**（推荐指向 Bytes 对象 payload，或直接一块裸 bytes，二选一但必须统一）
  * `heap_len=byte_len`
  * `heap_cap>=heap_len`（可按增长策略）
  * `sso_bytes` 可不使用/清零

> 推荐外部数据块复用 `Bytes` 对象：`heap_ptr = bytes_obj_ptr + 16`（payload 起始）。这样 string 只需读写 raw bytes，扩容交给 BytesCodec。

---

# 5. 句柄系统规范（HandleTable / HandleRecord）

## 5.1 HandleTable 区域与表头

HandleTable 区域必须来自内核内存（PageAllocator+FrameAllocator），不得是宿主 dict。

### 5.1.1 `HandleTableHeader`（建议 64 bytes）

| 偏移 | 长度 | 字段          | 类型    | 说明                    |
| -: | -: | ----------- | ----- | --------------------- |
|  0 |  4 | magic       | u32   | `0x48444C45` ("HDLE") |
|  4 |  4 | version     | u32   | 1                     |
|  8 |  4 | record_size | u32   | 32                    |
| 12 |  4 | max_handles | u32   | N                     |
| 16 |  4 | next_id     | u32   | 递增 id                 |
| 20 |  4 | free_head   | i32   | 空闲链表头（-1 无）           |
| 24 | 40 | reserved    | bytes | 扩展                    |

---

## 5.2 HandleRecord（32 bytes）

| 偏移 | 长度 | 字段        | 类型  | 说明                   |
| -: | -: | --------- | --- | -------------------- |
|  0 |  4 | version   | u32 | 1                    |
|  4 |  2 | type      | u16 | HandleType id        |
|  6 |  2 | state     | u16 | VALID/CLOSED 等       |
|  8 |  4 | owner_pid | u32 | 0=kernel/none        |
| 12 |  4 | refcnt    | u32 | 最小实现可固定 1            |
| 16 |  8 | obj_ptr   | u64 | **VirtAddr**（对象起始地址） |
| 24 |  4 | obj_len   | u32 | 语义由 codec 定义         |
| 28 |  4 | obj_cap   | u32 | 语义由 codec 定义         |

### state 推荐位定义

* bit0 `VALID`
* bit1 `CLOSED`
* bit2 `BUSY`（可选）
* bit3 `READONLY`（可选）

---

## 5.3 句柄生命周期（最小语义）

* `create_handle / alloc_typed`：

  * 分配 record（free list 或 next_id）
  * 写 record 字段
  * 若值类型：从 ValueHeap 分配对象块，并把 `obj_ptr` 写入 record
* `free(handle)`：

  * 若 `refcnt > 1`：`refcnt--` 后返回
  * 否则：调用 codec.free(obj_ptr, obj_cap)（值类型）
  * 清空 record，加入 free list

---

# 6. HandleType → Codec 映射表

## 6.1 HandleType（推荐最小集合）

* `Int64`
* `String`
* `Bytes`
* `Inode`
* `Custom(name: str)`（可选扩展）

## 6.2 Codec 责任与统一接口（文档级）

每个 codec 最少提供：

* `decode(obj_ptr: VirtAddr, record: HandleRecord) -> Any`
* `encode(obj_ptr: VirtAddr, record: HandleRecord, value: Any) -> None`
* `ensure_capacity(record: HandleRecord, new_len: int) -> None`（String/Bytes 需要）
* `free(obj_ptr: VirtAddr, record: HandleRecord) -> None`

## 6.3 映射表（摘要）

| HandleType | Codec            | obj_ptr 指向                     | obj_len/obj_cap 语义             |
| ---------- | ---------------- | ------------------------------ | ------------------------------ |
| Int64      | Int64Codec       | Int64 对象头（ObjectHeader 起始）     | len=8，cap>=8                   |
| Bytes      | BytesCodec       | Bytes 对象头                      | len=有效 bytes，cap=容量            |
| String     | StringCodec(SSO) | StringObject 头                 | len=UTF-8 bytes，cap=64（或 body） |
| Inode      | InodeRefCodec    | inode_no（推荐）或 inode struct ptr | 自定义（例如 obj_ptr=inode_no）       |
| Custom     | RegistryCodec    | 由注册表决定                         | 由 codec 定义                     |

---

# 7. 系统调用 ABI（最小集合）

## 7.1 通用 ABI

* `RAX=sysno`
* `RDI, RSI, RDX, R10, R8, R9` 传参
* 返回：

  * 成功：`RAX >= 0`
  * 失败：`RAX = -errno`

## 7.2 errno（最小建议）

* `ENOMEM=-12`
* `EBADF=-9`
* `EFAULT=-14`
* `ENOENT=-2`
* `EINVAL=-22`
* `EACCES=-13`

## 7.3 最小 syscalls（10 个）

### (1) `exit(code: int) -> never`

* sysno=1，RDI=code

### (2) `write(fd: int, buf: VirtAddr, count: int) -> int`

* sysno=2
* 从用户内存拷贝数据（见第 8 节）
* fd → HandleId → HandleType(Inode/Console/Bytes) → 写入
* 返回写入字节数或负 errno

### (3) `read(fd: int, buf: VirtAddr, count: int) -> int`

* sysno=3

### (4) `open(path: VirtAddr, flags: int, mode: int) -> int`

* sysno=4（最小可忽略 dirfd）
* 从用户读取路径字符串
* VFS lookup inode
* create_handle(type=InodeRef)
* 分配 fd，绑定

### (5) `close(fd: int) -> int`

* sysno=5
* 解绑 fd
* handle refcnt--，到 0 则 free

### (6) `mmap(addr: VirtAddr, length: int, prot: int, flags: int, fd: int, offset: int) -> VirtAddr`

* sysno=6
* 最小先支持匿名映射：fd=-1
* 返回新映射起始地址或负 errno

### (7) `munmap(addr: VirtAddr, length: int) -> int`

* sysno=7

### (8) `brk(new_end: VirtAddr) -> VirtAddr`

* sysno=8（可选实现；若已实现 mmap，也可不实现 brk）

### (9) `gettimeofday(out: VirtAddr) -> int`

* sysno=9
* 写结构体到用户内存（需 copy_to_user）

### (10) `yield() -> int`

* sysno=10
* 主动让出 CPU

---

# 8. 用户指针访问与拷贝规范（copy_from_user / copy_to_user）

## 8.1 目标

对用户虚拟地址访问必须：

1. 验证映射存在
2. 验证权限（读/写）
3. 支持跨页复制（逐页校验）
4. 任何失败返回 `-EFAULT`

## 8.2 规范接口（文档级）

* `copy_from_user(dst_kernel_ptr: VirtAddr, src_user_ptr: VirtAddr, size: int) -> int`

  * 返回 0 成功，失败返回 -EFAULT 或 -ENOMEM（若内部临时缓冲分配失败）
* `copy_to_user(dst_user_ptr: VirtAddr, src_kernel_ptr: VirtAddr, size: int) -> int`

## 8.3 跨页规则

* 对每一页：

  * `PageTable.walk(user_virt_page)` 必须存在
  * `prot` 必须允许访问（read 或 write）
  * 计算本页可用字节数，分段复制

---

# 9. 错误与 errno 映射表

| 内核异常/错误                         |                 errno | 场景                        |
| ------------------------------- | --------------------: | ------------------------- |
| OOMError                        |               -ENOMEM | 页帧不足/堆扩容失败/ValueHeap 分配失败 |
| InvalidAddress                  |               -EFAULT | 用户指针无效/越界/未映射             |
| ResourceLimitError(Handle full) | -ENOMEM 或 -EMFILE(可选) | 句柄表满                      |
| ResourceLimitError(Permission)  |               -EACCES | 不允许读写/覆盖                  |
| FileNotFound                    |               -ENOENT | open/lookup 找不到           |
| InvalidArg                      |               -EINVAL | mmap 参数等不合法               |
| BadFD                           |                -EBADF | fd 无效或未绑定                 |

---

# 10. 时序图（全面）

## 10.1 引导：`power_on → build_kernel → mount_fs`

```
User        Machine     FrameAlloc     AddrSpace/PT     PageAlloc      Console/Block      FS(SB)      HandleTable     Kernel
 |            |             |              |               |                |                |             |             |
 | power_on() |             |              |               |                |                |             |             |
 |----------->| init hw      |              |               |                |                |             |             |
 |            | attach frame | attach(...)  |               |                |                |             |             |
 |            |------------->|--------------|               |                |                |             |             |
 |            | create aspace|              | create+rootPT |                |                |             |             |
 |            |------------------------------------------->|                |                |             |             |
 |            | map kernel   |              | map identities|                |                |             |             |
 |            |------------------------------------------->|                |                |             |             |
 |            | reserve heap |              | reserve_range | attach         |                |             |             |
 |            |-------------------------------------------->|-------------->|                |             |             |
 |            | mmio console |              | map mmio      |                | from_mmio      |             |             |
 |            |------------------------------------------------------------>|----------------|             |             |
 |            | mmio block   |              | map mmio      |                | from_mmio      |             |             |
 |            |------------------------------------------------------------>|----------------|             |             |
 |            | format/mount |              |               |                |                | format      |             |
 |            |-------------------------------------------------------------------------------->|----------->|             |
 |            | attach HT    |              |               | alloc pages     |                |             | attach bytes|
 |            |-------------------------------------------->|---------------->|                |             |             |
 |            | Kernel(...)  |              |               |                |                |             |             |
 |            |---------------------------------------------------------------------------------------------------------->|
```

## 10.2 运行：`load_executable → bind fd → run_for_ticks → exit`

```
User     Kernel      FS        FrameAlloc   UserAS/PT     HandleTable    ProcTable     Console
 |         |         |            |            |              |             |            |
 | load_exe|         | lookup     |            |              |             |            |
 |-------->|-------->|----------->|            |              |             |            |
 |         | read    | read blocks|            |              |             |            |
 |         |-------->|----------->|            |              |             |            |
 |         | create user PT       | alloc_frame| create maps  |             |            |
 |         |--------------------->|----------->|------------->|             |            |
 |         | alloc pid/tid        |            |              |             | alloc       |
 |         |--------------------------------------------------------------->|------------|
 | bind fd | lookup /dev/console  |            |              | create_handle| set_fd      |
 |-------->|-------->|----------->|            |              |------------->|------------|
 | run     | tick loop/syscalls   |            |              |             |            |
 |-------->|  write(fd,buf,n) -> copy_from_user -> resolve fd->handle->inode->console.write_bytes
 |         | process exit         |            |              |             | set status  |
 |         |--------------------------------------------------------------->|------------|
```
