# AGENTS.md: ida-re 设计原则与协作契约

本项目为 AI Agent 提供基于 IDA Pro 9.0+ (`idalib`) 的原生 IDAPython 运行时与原子化基础原语。任何对本仓库的维护、重构与扩展必须严格遵守以下设计原则。

---

## 核心设计原则

### 1. 优先提供原子化原语，鼓励自主组合 (Atomic Primitives & Autonomous Composition)
- **定义**：仅提供标准、通用且职责单一的基础原语。
- **执行规范**：
  - **严禁面向具体场景封装高层 API / 专用 CLI**：例如禁止开发 `find_password_functions()` 或 `search_and_dump_xrefs()` 这类带业务假设的复合接口。
  - **由 Agent 自主编排**：复杂分析逻辑由调用的 Agent 在其自身脚本中利用 Python 原生语法（列表推导、生成器、`dataclass`、字典映射）自主组装。
  - **最小化私有认知成本**：Agent 的推理资源应聚焦于目标二进制的逆向分析，而非消耗在理解本项目的私有抽象上。

### 2. 保持数据原始度，避免过早裁剪 (Raw Data Fidelity & Zero Premature Pruning)
- **定义**：向 Agent 返回的接口必须保持数据完备度与元数据丰富性，严禁为了“排版简洁”或“精简字段”在底层做前置过滤。
- **执行规范**：
  - **透传原生数据结构**：例如反编译接口 `session.decompile()` 必须返回原始 Hex-Rays `cfuncptr_t` 对象（底层持有 `cfunc_t`），保留完整的 AST 节点、局部变量列表（`get_lvars()`）与伪代码结构，由消费方自行决定需要提取的属性。
  - **完整保留上下文**：交叉引用生成器保留完整的 `frm`, `to`, `type` 等原生属性。
  - **决策权后置**：筛选、清洗与异常推导是 Agent 核心推理能力的体现，前置裁剪会破坏 Agent 进行跨维度关联与边缘情况验证所需的关键线索。

### 3. 默认 Agent 具备充分的语义理解力 (Assume Semantic Competence)
- **定义**：将 Agent 视为精通计算机体系结构、编译原理与 IDAPython 的资深逆向工程师，杜绝任何面向初学者的人类防呆注释与说教。
- **执行规范**：
  - **高密度技术契约**：`SKILL.md` 与代码文档只陈述环境特征、API 签名、类型约束与正向行为规范。
  - **拒绝流程绑架**：严禁在 Prompt 或文档中强加“第一步先查字符串、第二步反编译...”等僵化工作流；Agent 会根据具体的二进制特征动态采取最优策略。
  - **正向目标驱动**：避免冗长的负向防御（如“不要混淆 32 位与 64 位”），直接表述正向契约即可。

---

## 架构红线与开发契约

1. **导入绝对前置**：任何涉及 IDA API 的模块，必须在导入任何 `ida_*` 模块之前 `import idapro`。
2. **生命周期原子化**：数据库生命周期统一通过 `IDASession` 管理（默认落盘 `save=True`；内存中的符号/注释修改在关闭时写回。上下文内抛出异常时不落盘）。
3. **IDAPython 原生直通**：保持 `ida_session` 对底层 IDAPython 模块（`ida_auto`, `ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_ida`, `ida_idaapi`, `ida_name`, `ida_typeinf`, `idautils`, `idc`）的完全透明导出，不建立阻隔层。
