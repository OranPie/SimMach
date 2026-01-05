下面给一份**实现计划 + 阶段目标**（按你这套规范：VirtAddr 指针、String SSO、HandleTable+ValueHeap、最小 syscall ABI、简化 EXE 格式）。我按“能尽快跑起来、每阶段都有可验证成果”的方式拆分，并标出每阶段的验收标准与风险点。

---

# 实现计划总览（从可运行到可扩展）

## 总里程碑

* **M0**：内存与页表可用（能映射、能读写、能触发 OOM）
* **M1**：内核堆 + ValueHeap + HandleTable（Int64/Bytes/String SSO）可用
* **M2**：进程/线程最小模型 + `write/exit/yield` syscalls 打通
* **M3**：FS + `open/read/close` + Console 设备 I/O 完整闭环
* **M4**：装载器（SimMach-EXE v1）+ 用户态跑起来
* **M5**：`mmap/munmap`（或 brk）+ 用户态内存管理与稳定性
* **M6**：完善：权限/错误码/测试矩阵/调试工具（dump/trace）

---

# 阶段 0：工程脚手架与规范冻结（建议 0.5–1 天）

## 目标

* 目录结构与模块边界确定
* 常量、结构体布局、errno、HandleType id 分配表冻结
* 核心数据结构用“规范字段名”统一

## 交付物

* `SPEC.md`（你当前规范的最终版落地到仓库）
* `constants.py`（magic/version/errno/sysno/HandleType id）
* `structs.py`（ObjectHeader/HandleRecord/StringBody 的 pack/unpack 接口，先空实现也行）

## 验收

* 所有字段偏移、大小、对齐、端序在文档与常量中一致

---

# 阶段 1（M0）：PhysMem → FrameAllocator → PageTable/AddressSpace（底层可用）

## 目标

实现最底层“资源池+映射系统”，让 OOM/InvalidAddress 能真实触发。

## 必做内容

1. `PhysMem`

* bytearray 存储
* `read/write`（边界检查）

2. `FrameAllocator`

* 以 4K 页为单位管理 free bitmap 或 free list
* 支持 reserved_ranges
* `alloc_frame/free_frame/available_frames`
* 无帧时抛 `OOMError`

3. `PageTable` + `AddressSpace`

* 最小 4K 页映射
* `map/unmap/walk`
* 页表层级可先简化成“单级页表”（模拟用 dict 也可以），但必须保证：

  * `walk` 是唯一翻译入口
  * 权限检查可先占位（后续补）

4. 内核地址空间固定区间

* 实现 `reserve_range`（仅记录，不映射）
* 实现 `map_range_identity`（映射一段连续范围）

## 验收标准

* 能映射一段虚拟地址到物理页帧并读写一致
* 能在物理帧耗尽时抛 `OOMError`
* 能访问未映射地址时抛 `InvalidAddress`
* 能 dump 一个映射表（调试输出即可）

## 风险点

* 页表权限标志设计：建议现在就把 flags 结构定下来（R/W/X/User）

---

# 阶段 2（M1）：Kernel Heap（PageAllocator）+ ValueHeap 分配器

## 目标

内核堆能按页扩展；ValueHeap 能分配对象块（ObjectHeader+payload）；支持扩容与释放。

## 必做内容

1. `PageAllocator`

* 给定 heap_virt_base/heap_size_bytes
* `alloc_pages/free_pages`
* 内部必须：每分配页 → `FrameAllocator.alloc_frame()` → `PageTable.map()`

2. `ValueHeapAllocator`（建议新增组件，挂在 kernel 里）

* 在 `ValueHeap` 区间做 **对象块分配**
* 最小实现建议：

  * bump allocator（线性分配）+ 不回收（先跑通）
  * 或 freelist（支持 free）
* 必须返回 **VirtAddr（对象头起始）**
* 需要记录 obj_cap 以便 free/resize

3. `ObjectHeader` pack/unpack

* 真实写入内核内存（通过虚拟地址翻译到 physmem）

## 验收标准

* 能 allocate 一个对象（VirtAddr 指针）
* 能写入 ObjectHeader 并读回一致
* 能触发 ValueHeap OOM（通过 pageallocator 申请不到页或超过区间）

## 风险点

* bump allocator 后续加 free 会复杂：建议从一开始就选 “slab/size-class freelist” 的方向（但可以先简化）

---

# 阶段 3（M1 延续）：HandleTable + Codecs（Int64/Bytes/String SSO）

## 目标

句柄表记录区落地到 HandleTable 区间，记录也以 Bytes 形式存在；typed 值通过 codec 读写 ValueHeap。

## 必做内容

1. `HandleTable.attach`

* 在 HandleTable 区间分配 header+records 所需 pages
* 写 `HandleTableHeader`
* 初始化 free list 或 next_id

2. `HandleRecord` pack/unpack

* 所有 create/free/get 都实际读写内核 bytes（不能只在 dict 存状态）

3. Codecs

* `Int64Codec`：ObjectHeader + 8 bytes payload
* `BytesCodec`：ObjectHeader + payload，支持 `ensure_capacity`（可先用“重新分配+拷贝”）
* `StringCodec(SSO)`：固定 64B StringObject

  * SSO ≤24 bytes 内联
  * HEAP >24 bytes：分配 Bytes 对象外部数据块，并让 heap_ptr 指向 payload 起始（bytes_obj_ptr+16）

4. HandleType → Codec 映射表（registry）

* `type_id -> codec` 查表

## 验收标准

* `alloc_typed(Int64, 42)` → `get_typed` 返回 42 → `set_typed` 更新
* `alloc_typed(String, "hi")`（SSO）读写正确
* `alloc_typed(String, "A"*100)`（HEAP）读写正确，扩容正确
* HandleTable 满时抛 `ResourceLimitError`
* free 后句柄记录可复用（free list 生效）

## 风险点

* String HEAP 指向 Bytes payload：要保证 heap_ptr 的翻译/权限路径正确
* 记录区与值堆区的越界检查要严格，否则后续 bug 难查

---

# 阶段 4（M2）：最小内核循环 + 进程/线程模型 + 3 个 syscalls 打通

## 目标

先让“用户程序”不用真正装载器也能触发 syscall，建立 OS 闭环：`write/exit/yield`

## 必做内容

1. `ProcessTable`

* pid 分配
* fd 表（fd->handle_id）
* exit_status

2. `SyscallTable`

* 注册 sysno handler
* syscall 分发入口：`syscall_dispatch(trapframe)`

3. 用户指针拷贝（最小 copy_from_user）

* 逐页 walk 校验
* 权限检查（至少要区分 user page 与 kernel page）
* 返回 -EFAULT

4. syscalls：

* `exit(code)`
* `yield()`
* `write(fd, buf, count)`：

  * 解析 fd→handle→inode/console
  * 把用户缓冲拷贝到内核临时 buffer（或分段写入）

## 验收标准

* 一个“伪用户线程”调用 write 能在 console 输出
* exit 能正确设置进程退出码并停止调度该线程
* yield 会切换到另一个 runnable 线程（哪怕是轮转）

## 风险点

* 用户/内核地址空间隔离与权限位设计必须靠谱，否则 copy_* 会混乱

---

# 阶段 5（M3）：FS 最小闭环（BlockDevice + SuperBlock/Inode）+ open/read/close

## 目标

实现 `open/read/close`，能从磁盘（模拟块设备）读取文件内容，并通过 write 输出到 console。

## 必做内容

1. `BlockDevice`：read_block/write_block
2. 最小 FS（可以极简）

* SuperBlock.format_and_mount
* lookup(path)
* Inode.read_bytes/write_bytes（可先只支持顺序文件）

3. syscalls：

* `open(path, flags, mode)`（读取用户路径字符串）
* `read(fd, buf, count)`
* `close(fd)`

## 验收标准

* 用户程序：

  * open("/etc/demo.conf")
  * read → write 到 stdout
* 路径不存在返回 -ENOENT
* fd 无效返回 -EBADF

## 风险点

* 先做“内存 FS”虽然快，但会绕开 BlockDevice；建议至少把块读写走通，哪怕 FS 很简陋

---

# 阶段 6（M4）：装载器（SimMach-EXE v1）+ 用户态真正跑起来

## 目标

`Kernel.load_executable` 能读取 EXE 头与段表，映射 PT_LOAD 段、设置 RIP/RSP。

## 必做内容

1. ExeParser

* ExeHeaderV1 + ProgramHeaderV1 解析与校验

2. User AddressSpace + User PageAllocator（或在 kernel 中专门管理 user mappings）
3. PT_LOAD 装载

* map pages
* copy file bytes
* zero bss
* 权限按 PF_R/PF_W/PF_X

4. 栈构造（argv/env）
5. 初始 TrapFrame 设置

## 验收标准

* 能加载一个最小 demo_app（哪怕只是几条 syscall 的字节码/解释执行也行）
* demo_app 能 write 输出并 exit
* 错误输入 EXE 能返回 -EINVAL

## 风险点

* 你如果没有真实指令执行器，可以用“模拟用户程序：解释执行 syscall 脚本”来过渡；关键是装载与地址空间要真实

---

# 阶段 7（M5）：用户内存管理（mmap/munmap 或 brk）+ 稳定性

## 目标

实现匿名映射 + 释放，保证用户程序能动态申请内存，并通过 copy_* 访问。

## 必做内容

* `mmap(fd=-1)`：在 mmap 区挑选空闲区间，映射 pages
* `munmap`：unmap 并 free frames
* 可选 `brk`：管理 heap_end 并扩展/收缩映射

## 验收标准

* 用户程序 mmap 一块内存写入，再 write 输出验证
* munmap 后访问该区域触发 -EFAULT（通过页表检查）

---

# 阶段 8（M6）：完善与工程化（权限、调试、测试矩阵）

## 目标

把系统从“能跑”变成“可靠可扩展”。

## 建议补齐

* 权限：User/RW/X 全面检查（页表 flags + syscall）
* Handle 权限位（read/write/overwrite/频率）若你要恢复此前设想
* 调试工具：

  * `dump_pagetable(pid)`
  * `dump_handles(pid)`
  * `hexdump(virtaddr, len)`
* 测试矩阵（强烈建议）

  * OOM：frame 耗尽、ValueHeap 耗尽、HandleTable 满
  * EFAULT：跨页、未映射、只读页写入
  * String：SSO/HEAP 边界（24、25、扩容、缩短回 SSO）
  * FD：close 后再用 EBADF

---

# 每阶段“最小可运行 Demo”建议（强验收）

* **M0 Demo**：映射一个页面，写入 bytes，再读出比对；耗尽帧触发 OOM
* **M1 Demo**：alloc_typed Int64/String(SSO/HEAP) 并 set/get；handle full 触发限制
* **M2 Demo**：伪用户线程 sys_write → console 输出；exit 后进程状态正确
* **M3 Demo**：open/read/write/close 读文件到控制台
* **M4 Demo**：load_executable(demo_app) → demo_app write+exit
* **M5 Demo**：demo_app mmap 内存、写入、write 输出、munmap 后访问 EFAULT

---

# 关键技术决策（你现在就该锁定的 6 个点）

1. 页表实现：先 dict 模拟 vs 真正多级页表（建议先 dict，保证语义正确）
2. ValueHeap 分配：bump-only（快） vs freelist（可回收）（建议：先 bump，尽快跑通，再加 freelist）
3. String HEAP 外部块：复用 Bytes 对象 payload（推荐）
4. InodeRef：`obj_ptr=inode_no`（推荐稳定） vs 指针（快但脆）
5. 用户程序执行：真实 ISA 模拟 vs “syscall 脚本解释器”（建议先脚本解释器，先把 OS 路径打通）
6. mmap/brk：先 mmap（更通用）还是先 brk（更传统）（建议先 mmap anonymous）

---

如果你愿意，我可以按这个计划再输出两样更落地的东西（仍不写库实现）：

1. **每阶段的接口清单**（你需要先写哪些类/方法的最小签名）
2. **测试用例清单**（按验收标准逐条列出输入/期望输出/错误码）
