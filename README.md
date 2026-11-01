# ida-re: IDA Pro (idalib) Agent Primitives

基于 IDA Pro 9.0+ (`idalib`) 的原生 IDAPython 运行时与原子化基础原语个人自用库，专为 AI Agent 逆向工程分析设计。

## 为什么会有这个项目？

当前针对 IDA Pro 的主流 AI 接入方案（例如社区 [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) 和 [官方 MCP](https://github.com/HexRaysSA/ida-mcp) 等）普遍倾向于在 IDAPython 之上构建一套庞大、复杂且脆弱的高层抽象接口（例如专用搜索函数、预设格式的代码摘要提取器等）。在真实的 AI 逆向场景中，这种过度封装暴露出明显的结构性缺陷：

1. **抽象脆弱且维护成本高**：逆向分析场景千变万化，预设的高层 API 难以穷尽复杂的分析需求，封装层本身容易引入边界异常与版本兼容 Bug。
2. **割裂预训练知识，徒增 Token 消耗**：主流大模型在预训练阶段已经吸收了海量官方 IDAPython、Hex-Rays SDK 源码及工业界逆向脚本。强行引入一套私有的高层封装，不仅无法发挥大模型优秀的逆向工程素养，反倒迫使 Agent 把上下文与 Token 浪费在理解、试错陌生抽象上。
3. **数据过早裁剪，扼杀推理链条**：传统封装为了排版整洁，往往会将反编译或分析结果简化为预过滤的字符串或裁剪后的 JSON，丢弃了完整的 AST 语法树、局部变量元数据以及精细的交叉引用结构，致使 Agent 无法通过编写脚本发挥编程式逆向的优势。

**ida-re 采取截然相反的设计理念——回归原子原语与原生直通**：
- **原子化生命周期**：仅解决无头驱动挂载（`idalib`）、环境准备（Hex-Rays 就绪）与数据库事务安全管理。
- **数据零损耗保真**：全面保留 Hex-Rays 原生 `cfuncptr_t` 对象（底层 `cfunc_t`、AST、Ctree、局部变量）、原生 xref 迭代器与原始字节，由 Agent 自行决定数据清洗与筛选策略。
- **IDAPython 原生直通**：再导出常用 `ida_*` 模块，其余模块在 `idapro` 初始化后同样可直接 import，让 Agent 自由编排原生 Python 脚本，释放 Agent 资深逆向工程师级别的推理潜能。

---

## 环境要求

- **IDA Pro**：9.0 或更高版本（需自带 `idalib` 64 位无头支持，例如 IDA Pro 9.5），并确保 `idapro` 能定位本机 IDA（安装器的 idalib 激活选项、`IDADIR` 环境变量或 `py-activate-idalib.py`）
- **Python**：>= 3.10
- **操作系统**：Windows / Linux / macOS

---

## 安装与配置

你可以通过本地可编辑模式安装本包：

```bash
pip install -e .
```

或者直接将项目所在的 `src` 目录路径写入 Python `site-packages` 下的 `.pth` 文件（例如 `ida_session.pth`），实现全局免安装直通。

---

## 快速开始

```python
from ida_session import IDASession

with IDASession("target.exe.i64") as session:
    ea = session.to_ea("main")
    print(str(session.decompile(ea)))
    print([hex(x.frm) for x in session.xrefs_to(ea)])
```

完整 API、运行约束与 `save` 语义见 [`SKILL.md`](./SKILL.md)。

---

## 验证

```bash
python tests/smoke_test.py
```

测试会用本机 `clang` 编译 [`tests/fixtures/sample.c`](./tests/fixtures/sample.c)，再用 `IDASession` 验证符号解析、反编译、字符串交叉引用、重命名/注释、失败诊断与 `save` 语义。需要本机可用 `clang`。

---

## 架构契约与设计原则

本项目的一切维护与扩展严格遵守 [`AGENTS.md`](./AGENTS.md) 契约。面向 Agent 的 API 与运行约束见 [`SKILL.md`](./SKILL.md)。

---

## License

[MIT](./LICENSE)
