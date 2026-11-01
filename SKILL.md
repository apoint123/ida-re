---
name: ida-re
description: 使用本机 IDA Pro 9.5 (idalib) 环境进行逆向工程分析。直接导入 ida_session 模块进行编排，访问完整原生 IDAPython 能力。
---

# idalib Runtime & IDAPython Primitives

本机已就绪 IDA 9.5 64位无头环境（`idalib`）与 Hex-Rays 反编译引擎。可在任何 Python 脚本中直接导入 `ida_session`。

## 运行约束

- **主线程**：idalib 只能在主线程调用；在工作线程中打开会抛出 `RuntimeError: Function can be called from the main thread only`。
- **单库**：同一进程同一时间只能打开一个数据库；嵌套 `IDASession` 会失败（`code: -1`），多目标请顺序处理。
- **会话生命周期**：所有方法与数据库元数据属性只能在 `with` 块内使用；关闭后调用会抛出 `RuntimeError`。
- **数据库损坏与恢复（Internal Error 1228）**：运行时可能随机遭遇 `FATAL ERROR: Oops! internal error 1228 occurred.` 内部故障，诱发原因未知。该故障会导致 IDA 的 `.i64` 等数据库文件损坏。
  - **恢复方案**：发生后必须删除已损坏的旧数据库文件并重新载入原始二进制重建。
  - **备份策略**：若目标二进制体积较大（自动分析耗时漫长），生成数据库后应先行备份数据库文件（如 `.i64`），避免突发损坏后重复消耗重建时间。

## 模块导入与环境就绪

```python
from ida_session import (
    IDASession,  # 数据库生命周期与原子原语上下文管理器
    FuncRef,     # func_at / xrefs_with_owner 返回的命名元组
    OwnedXref,   # xrefs_with_owner 返回的命名元组
    # 原生 IDAPython 模块直通：
    ida_auto,
    ida_bytes,
    ida_funcs,
    ida_hexrays,
    ida_ida,
    ida_idaapi,
    ida_name,
    ida_typeinf,
    idautils,
    idc,
)
```

## 核心原子原语

### `IDASession(target_path: str | os.PathLike[str], save: bool = True, auto_analysis: bool = None)`
- **生命周期管理**：自动调度 `idapro.open_database`（`run_auto_analysis=True` 时自身会同步等待分析完成）、`ida_hexrays.init_hexrays_plugin()` 与安全关闭。
- **参数行为**：
  - `target_path`: 原始二进制（.exe/.dll/.elf 等）或已生成的 IDA 数据库（.i64/.idb）。
  - `auto_analysis`: 默认为智能判定（原始二进制自动触发并等待分析；`.i64` 直接挂载；`.idb` 由 IDA 9 自动转换为同目录 `.i64`，会产生落盘文件）。
  - `save`: 退出时是否落盘，默认 `True`；上下文内抛出异常时不落盘。`save=False` 不阻止内存修改。
- **核心原子方法**：
  - `session.decompile(target: int | str) -> ida_hexrays.cfuncptr_t`: 反编译指定地址或符号，返回原始 Hex-Rays AST 对象（通过 `str(cfunc)` 获取伪代码，通过 `cfunc.get_lvars()` 访问原始局部变量，通过 `cfunc.body` 访问 Ctree）。失败时抛出 `RuntimeError`，消息包含 Hex-Rays 的 `desc()` 与错误码。
  - `session.to_ea(target: int | str) -> int`: 解析顺序为「符号名 → 十六进制（`0x` 前缀可选）→ 报错」。纯数字字符串按十六进制解析；十进制请直接传 `int`。结果必须落在当前数据库的映射范围内，否则抛出 `ValueError`。
  - `session.name(target: int | str) -> str`: 获取符号或函数名；函数内部地址回退为所属函数名。
  - `session.rename(target: int | str, new_name: str) -> bool`: 仅在名称精确生效时返回 `True`；名称冲突或非法时返回 `False` 且不改动，不会自动追加后缀或清洗字符。
  - `session.set_comment(target: int | str, comment: str, repeatable: bool = False) -> bool`: 设置注释。
  - `session.xrefs_to(target: int | str, flags: int = 0) -> Iterator[xref]`: 返回指向目标的所有原生交叉引用迭代器；`flags` 透传给 `idautils.XrefsTo`。
  - `session.xrefs_from(target: int | str, flags: int = 0) -> Iterator[xref]`: 返回源自目标的所有原生交叉引用迭代器；`flags` 透传给 `idautils.XrefsFrom`。
  - `session.func_at(target: int | str) -> FuncRef | None`: 返回地址所属函数；不在任何函数内（如 `.rdata` 数据）时返回 `None`。`FuncRef` 为命名元组 `(start_ea, name, size)`：`size` 由 IDA 原生 `calc_func_size` 系列计算（计入 tail 碎片）。需要 `func_t` 本体（flags、frame、tail 链）时直接调用 `ida_funcs.get_func(ea)`。
  - `session.names_like(pattern: str | re.Pattern[str]) -> Iterator[tuple[int, str]]`: 按 `re.search` 语义筛选符号名，逐项产出 `(ea, name)`；`"add"` 会命中 `smoke_add`，精确匹配请用 `^...$` 锚定。顺序沿用 IDA 名称表。
  - `session.xrefs_with_owner(target: int | str, flags: int = 0) -> Iterator[OwnedXref]`: 指向目标的交叉引用与其来源地址所属函数一并产出。`OwnedXref` 为命名元组 `(xref, owner)`：`xref` 是原生 xref 对象，`owner` 为 `FuncRef` 或 `None`（来源位于函数之外，如数据引用）。
  - `session.functions() -> Iterator[int]`: 遍历全库函数入口地址。
  - `session.strings() -> idautils.Strings`: 返回原生 `idautils.Strings` 可迭代对象（元素为 `StringItem`）。
  - `session.min_ea`, `session.max_ea`, `session.proc_name`, `session.hexrays_available`: 数据库元数据属性。

所有接受 `target: int | str` 的方法都经 `to_ea` 解析。无法解析或未映射时会抛出 `ValueError`。

## FLIRT 签名

IDA 9.x 扩展签名位于 `%APPDATA%\Hex-Rays\IDA Pro\signatures-bundles\`（配对 `.sig` 与 `.metadata`，无 `.til`）。匹配后仅重命名未命名函数（`sub_*`）并置 `FUNC_LIB`，函数原型仍靠调用点推断。IDA 默认不自动加载该目录，需手动或脚本引入。

---

### 1. 签名选择

归属以 `.metadata` 的 `Variables` 字段为准（`package` / `arch` / `version` 等），包内版本可能滞后于最新工具链。

| 目标      | 路径模式                                                                 | 选择策略                                               |
| --------- | ------------------------------------------------------------------------ | ------------------------------------------------------ |
| **Rust**  | `rust/<triple>/rust_<ver>_<triple>.sig`、`rust/rust_bundle_<triple>.sig` | 首选精确版本；次选合并包（仅部分 triple 支持）。       |
| **Go**    | `golang/stdlibs/golang_std_<arch>_<ABI>.sig`                             | 多版本合并包（含 `runtime` 与 std），按架构与 ABI 选。 |
| **MSVC**  | `windows/vs-channels/<pkg>/Microsoft.<pkg>_<arch>.sig`                   | 按库类型（CRT/MFC/ATL）与架构选。                      |
| **Linux** | `linux/<distro>/<distro>-<pkg>-<arch>.sig`                               | 按发行版、包名与架构选。                               |

> **Rust 版本定位**：从二进制字符串提取 `/rustc/<40位 commit>/library/...`，在 Rust 仓库执行 `git tag --contains <commit>` 确认版本。无精确签名时选邻近版本。

---

### 2. 脚本应用示例

```python
import ida_auto, ida_funcs

before = ida_funcs.get_idasgn_qty()
ida_funcs.plan_to_apply_idasgn(r"C:\path\to\target.sig")
ida_auto.auto_wait()

for i in range(before, ida_funcs.get_idasgn_qty()):
    path, optlibs, matches = ida_funcs.get_idasgn_desc_with_matches(i)
    print(f"{path} -> {matches} matches")
```

## 典型编排范式

### 上下文管理器与原子查询（Ad-hoc 脚本）

```powershell
& {
@'
import json
from ida_session import IDASession

with IDASession("target.exe.i64") as session:
    # 1. 反编译函数
    cfunc = session.decompile("main")
    print(str(cfunc))

    # 2. 交叉引用分析
    target_ea = session.to_ea("target_symbol")
    callers = [hex(x.frm) for x in session.xrefs_to(target_ea)]
    print(json.dumps({"symbol": "target_symbol", "callers": callers}))

    # 3. 引用方宿主函数（名称 + 含 tail 碎片的函数大小）
    for item in session.xrefs_with_owner(target_ea):
        owner = item.owner
        site = owner.name if owner else "<outside any function>"
        size = owner.size if owner else 0
        print(hex(item.xref.frm), item.xref.type, site, size)

    # 4. 按正则枚举符号
    for ea, name in session.names_like(r"^sub_[0-9A-F]+$"):
        print(hex(ea), name, session.func_at(ea))
'@ | python -
}
```

这些方法只做「地址 → 结构」的导航：`OwnedXref` 保留未经改动的原生 xref 对象，函数大小取自 IDA 原生计算（含 tail 碎片），不裁剪字段。
