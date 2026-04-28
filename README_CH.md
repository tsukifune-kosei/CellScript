# CellScript

<p align="center">
  <img src="assets/cellscript-logo.png" alt="CellScript" width="560">
</p>

[![CellScript CI](https://github.com/tsukifune-kosei/CellScript/actions/workflows/ci.yml/badge.svg)](https://github.com/tsukifune-kosei/CellScript/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)
[![Targets: CKB](https://img.shields.io/badge/targets-CKB-2f6f4e.svg)](#target-profiles)
[![Package Workflow: Local First](https://img.shields.io/badge/package%20workflow-local%20first-2f6f4e.svg)](#包工作流)
[![LSP: Local Tooling](https://img.shields.io/badge/LSP-local%20tooling-2f6f4e.svg)](#编辑器支持)
[![Wiki Tutorials](https://img.shields.io/badge/wiki-tutorials-6f42c1.svg)](https://github.com/tsukifune-kosei/CellScript/wiki)

[English](README.md) | [中文](README_CH.md)

**用你思考 Cell 合约的方式来写 Cell 合约——而不是按线格式的方式来写。**

CellScript 是面向 CKB 的 Cell 模型智能合约 DSL。它把 `.cell`
源码编译为 ckb-vm RISC-V assembly 或 ELF 产物，并同时输出可用于审计、
策略检查、schema 绑定和调度感知执行的类型化 metadata。

在这份 README 中，metadata 指编译器输出的机器可读语义事实：schema layout、
Cell effects、access summaries、source hashes、verifier obligations、
runtime requirements 和 target-profile policy flags。

CellScript 是刻意收窄的语言：它不是新的 VM，也不是账户存储合约语言。
它为协议作者提供一种类型化方式来描述资产、共享 Cell 状态、receipt、
生命周期转换、lock 和交易形状的效果——同时仍然直接映射到 CKB
使用的 Cell 模型。

---

## 为什么需要 CellScript

CKB 暴露了强大的 Cell 执行模型，但手写脚本会迫使作者靠近线
格式工作：

- 手动解析 witness bytes
- 按 index 跟踪 inputs、CellDeps、outputs 和 output data
- 把类型化状态编码进原始 byte arrays
- 用 RISC-V C 或汇编直接调用 syscall 编号
- 依靠约定而不是编译器维护线性资产语义

CellScript 把这些工作提升为显式语言构造：`resource`、`shared`、
`receipt`、`action`、`lock`、`consume`、`create`、`read_ref`、
`transfer`、`destroy`、`claim` 和 `settle`。这些构造不是隐喻——它们会
直接 lower 到目标链已经执行的 Cell 交易形状。

## 当前状态

CellScript 目前处于 CKB-focused alpha / stabilization 阶段。

它适合用于：
- 试验 CKB Cell-contract authoring；
- 编译并检查内置示例；
- 探索类型化 Cell effects、metadata、constraints 和 CKB target-profile
  checks；
- 试用本地 VS Code 扩展和 LSP tooling。

它尚不建议在没有人工审查和审计的情况下直接用于 mainnet 部署。当前重点是
developer-readiness、diagnostics、ProofPlan / metadata visibility，以及
CKB target-profile stability。

## 快速开始

从仓库安装：

```bash
cd cellscript
cargo install --path .
```

编译你的第一个合约：

```bash
# 仅做类型检查
cellc examples/token.cell

# 输出 CKB 的 RISC-V ELF
cellc examples/token.cell --target riscv64-elf --target-profile ckb

# 输出 CKB 的 RISC-V ELF，指定入口 action
cellc examples/nft.cell --target riscv64-elf --target-profile ckb --entry-action transfer
```

创建包：

```bash
cellc init token-package
cd token-package
cellc add shared-types --path ../shared-types
cellc build --target riscv64-elf --target-profile ckb
```

运行 CKB profile 检查：

```bash
cellc check --target-profile ckb
```

检查编译器能解释的 token 示例信息：

```bash
cellc metadata examples/token.cell --target-profile ckb --json
cellc constraints examples/token.cell --target-profile ckb
cellc scheduler-plan examples/token.cell --target-profile ckb
```

这些命令展示编译器认为协议会 read、write、create、consume、assume 什么，
以及它向 CKB-facing policy tooling 暴露了什么。

> **下一步：** 阅读[语言模型](#核心模型)、[完整示例](#示例)，或深入了解[架构](#架构)。

---

## 示例

一个 module 包含 schema 声明和可执行入口。持久值用 `resource`、`shared`
或 `receipt` 声明；可执行逻辑用 `action` 或 `lock` 声明；效果用显式生命
周期操作表达。

**声明：**

```cellscript
module cellscript::example

struct Config {
    threshold: u64
}

resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}

shared Pool has store {
    token_reserve: u64
    ckb_reserve: u64
}

receipt VestingGrant has store, claim {
    beneficiary: Address
    amount: u64
    unlock_epoch: u64
}

struct Wallet {
    owner: Address
}

lock owner_only(wallet: &Wallet, signer: Address) -> bool {
    wallet.owner == signer
}
```

**效果：**

```cellscript
action move_token(token: Token, to: Address) -> Token {
    assert_invariant(token.amount > 0, "empty token")

    consume token

    create Token {
        amount: token.amount,
        symbol: token.symbol
    } with_lock(to)
}
```

编译器把 `consume`、`create`、`transfer`、`destroy`、`claim`、`settle` 和
`read_ref` 当作 **Cell effect**，而不是普通函数调用。这些 effect 会反映到
metadata 中，使 CKB admission policy、schema decoding 和
artifact verification 都能审计生成脚本。

**完整的 fungible-token 示例：**

```cellscript
module cellscript::fungible_token

resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}

resource MintAuthority has store {
    token_symbol: [u8; 8]
    max_supply: u64
    minted: u64
}

action mint(auth: &mut MintAuthority, to: Address, amount: u64) -> Token {
    assert_invariant(auth.minted + amount <= auth.max_supply, "exceeds max supply")

    auth.minted = auth.minted + amount

    create Token {
        amount: amount,
        symbol: auth.token_symbol
    } with_lock(to)
}

action transfer_token(token: Token, to: Address) -> Token {
    consume token

    create Token {
        amount: token.amount,
        symbol: token.symbol
    } with_lock(to)
}

action burn(token: Token) {
    assert_invariant(token.amount > 0, "cannot burn zero")
    destroy token
}
```

**内置协议示例：**

| 示例 | 展示内容 |
|---|---|
| `examples/token.cell` | Mint、transfer、burn，带同 symbol guard 的 token merge |
| `examples/timelock.cell` | 时间门控状态转换、延迟 claim 路径 |
| `examples/multisig.cell` | 授权阈值、签名导向的 lock 逻辑 |
| `examples/nft.cell` | 唯一资产、metadata、所有权转移 |
| `examples/vesting.cell` | Receipt-style grants 和 claim lifecycle |
| `examples/amm_pool.cell` | Shared pool state、swap/liquidity effects |
| `examples/launch.cell` | Launch/pool composition patterns |

---

## 编辑器支持

CellScript 为早期用户提供 production-style 的本地语言工具：

- **In-process LSP** — 诊断、补全、hover、go-to-definition、引用、重命名、
  格式化和 metadata-oriented code actions。编译器 crate 暴露 `LspServer`；
  `cellc --lsp` 提供完整的 `tower-lsp` JSON-RPC stdio 传输。
- **VS Code 扩展** — 语法高亮、snippets、on-save 诊断、compiler-backed
  格式化、scratch compile、metadata/constraints/production report、
  CKB target-profile 参数和状态栏反馈。它调用 `cellc`（或 `cargo run` 回退），
  所以编辑器行为和 CLI/CI 保持一致。

- [VS Code 扩展](https://github.com/tsukifune-kosei/CellScript/tree/main/editors/vscode-cellscript)
- [运行时错误码](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md)
- [Entry witness ABI](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_ENTRY_WITNESS_ABI.md)
- [Collections 支持矩阵](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md)
- [Mutate 与 replacement output](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_MUTATE_AND_REPLACEMENT_OUTPUTS.md)
- [CKB target profile tutorial](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/wiki/Tutorial-05-CKB-Target-Profiles.md)
- [CKB deployment manifest](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_CKB_DEPLOYMENT_MANIFEST.md)
- [Capacity 与 builder contract](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md)
- [线性所有权](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_LINEAR_OWNERSHIP.md)
- [Scheduler hints](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_SCHEDULER_HINTS.md)
- [Metadata verification and production gates](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md)
- [CKB hashing workflow 示例](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/ckb_hashing.md)
- [Collections matrix 示例](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/collections_matrix.md)
- [Deployment manifest 示例](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/deployment_manifest.md)
- [Mutate append 示例](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/mutate_append.md)
- [0.13 roadmap](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_0_13_ROADMAP.md)
- [0.14 roadmap](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_0_14_ROADMAP.md)
- [0.14 release notes draft](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/CELLSCRIPT_0_14_RELEASE_NOTES_DRAFT.md)

## Target Profiles

CellScript 现在只支持 CKB 这一个 target profile：

| Profile | 何时使用 | 你得到什么 |
|---|---|---|
| `ckb` | CKB mainnet 产物 | BLAKE2b/Molecule 约定、CKB syscall profile |

> `ckb` profile 已按 bundled CellScript suite 进入 production-gated 状态。
> 它输出原生 CKB ckb-vm artifact，使用 CKB syscall
> 与 Molecule/BLAKE2b 约定，并通过正常 target-profile policy 拒绝未支持形状。

```bash
cellc examples/token.cell --target riscv64-elf --target-profile ckb
cellc check --target-profile ckb
```

## 核心模型

CellScript 程序围绕 Cell 生命周期操作书写：

| 概念 | 编译到什么 |
|---|---|
| `resource T { ... }` | 线性的 Cell-backed 资产（`CellOutput` + `outputs_data[i]`） |
| `shared T { ... }` | 共享状态 Cell，通过 `CellDep` 读取，或通过 consume + create 更新 |
| `receipt T { ... }` | 一次性证明 Cell（deposit、vesting、vote、liquidity） |
| `consume value` | 花费一个 transaction input |
| `create T { ... }` | 创建新的 output Cell 和类型化数据 |
| `read_ref T` | 加载只读 CellDep-backed 值 |
| `action` | Type-script 状态转换逻辑 → 编译为 RISC-V |
| `lock` | Lock-script 授权逻辑 → 编译为 RISC-V |
| 本地 `let` 值 | 交易局部计算；不会成为持久存储 |

> **关键规则：** 只有 `create` 会物化持久状态。普通本地值不会变成 Cell，
> 除非被显式创建为 `resource`、`shared` 或 `receipt`。

## 语言特性

- **Cell 原生资源** — `resource` 值是线性的，不能复制、静默丢弃或藏进
  普通值。每个 resource 都必须被 consume、transfer、return、claim、
  settle 或 destroy。
- **显式共享状态** — `shared` 标记池、注册表、配置 Cell 等争用敏感协议
  状态。读写保持对 metadata 和工具可见。
- **Receipt 作为有状态证明** — `receipt` 是一次性 Cell，证明某个操作已经
  发生，并可在之后被 claim 或 settle。
- **Capability 守门** — `has store, transfer, destroy` 让资产权限显式化。
- **生命周期规则** — `#[lifecycle(...)]` 让 Cell-backed 值描述状态机，
  例如 `Granted -> Claimable -> FullyClaimed`。
- **Effect 推断** — `action` 会根据 Cell 操作被分类为 `Pure`、`ReadOnly`、
  `Mutating`、`Creating` 或 `Destroying`。
- **调度感知 metadata** — CKB target 可以暴露 access summary 和 shared
  touch domain，让区块构建器判断哪些工作可以独立处理。
- **类型化 schema metadata** — Cell data layout、type identity、source hash、
  runtime access 和 verifier obligation 都会作为机器可读 metadata 输出。
- **RISC-V 输出** — 可执行目标是 ckb-vm 兼容 RISC-V assembly 或 ELF。
  CellScript 不引入独立 VM。
- **包感知编译** — 支持 `Cell.toml`、本地模块、source roots 和本地 path
  dependencies。
- **策略门禁** — build、check、metadata 和 artifact verification 命令可以按
  目标 profile 或部署策略拒绝不合规产物。

## 对比

CellScript 为什么围绕 typed Cells、线性资源、显式交易 effect 和 ckb-vm
artifact 设计——而不是围绕账户存储或单链专用 VM：

| 维度 | CellScript | Solidity | Move | Sway |
|---|---|---|---|---|
| 执行目标 | ckb-vm 上 RISC-V ELF/asm | EVM bytecode | Move bytecode | FuelVM bytecode |
| 状态模型 | 类型化 Cells，显式 inputs/deps/outputs | 账户存储槽 | 全局存储中的 resources | UTXO + 原生资产 |
| 资产模型 | 原生 `resource`、生命周期、receipt、shared Cells | 手写 token contracts | 原生 resources | 原生资产 |
| 线性所有权 | 编译器强制 | 无 | 通过 abilities | 无通用用户定义 |
| 共享状态 | 显式 `shared` Cells | 隐式 contract storage | 部分 Move 链的 shared objects | 无 shared Cell 对应物 |
| 重入 | 无 callback 风格重入 | 常见风险面 | 设计上较低 | predicate 风险较低 |
| 调度 metadata | CKB 原生支持 | 无 | 非 GhostDAG 导向 | predicate 级 |
| CKB 兼容性 | 面向 bundled Cell suite 的 production-gated CKB ckb-vm artifact profile | 需要不同 VM | 需要不同 VM | 需要 FuelVM |

与手写 CKB 脚本相比，CellScript 保留同一个 runtime substrate，
但用类型化 Cell 操作、线性检查、schema metadata 和可被策略验证的产物取代
原始 byte/syscall 编程。

---

## 架构

CellScript 是一个多遍编译器，把 `.cell` 源码通过五个定义明确的阶段 lower，
然后输出 RISC-V 产物、类型化 metadata 和 profile 感知策略检查。下面列出的
每个模块都位于单一 Rust crate（`cellscript`）中，在 `src/` 下有自己的
`mod.rs` 入口。

```mermaid
graph LR
    Source["Source (.cell)"] --> Lexer
    Lexer --> Parser
    Parser --> TypeCheck["Type Checker\n+ Lifecycle"]
    TypeCheck --> IRLower["IR Lowering\n+ Optimize"]
    IRLower --> Codegen["Codegen (RISC-V)"]
    IRLower --> Metadata["Metadata (JSON)"]
    Codegen --> Artifact[".s / .elf Artifact"]
```

### 编译流水线

**1. 词法分析**（`lexer/`）
扫描 `.cell` 源码生成类型化 token 流。处理 CellScript 关键字、运算符、
字面量和字符串插值。每个 token 携带行/列 span 用于诊断。

**2. 语法解析**（`parser/`）
从 token 流构建 AST。AST 建模完整 CellScript 表面语法：`resource`、
`shared`、`receipt`、`struct`、`enum`、`action`、`lock`、`function`、
`use`、`const`、capability gates、lifecycle 注解，以及所有语句/表达式形式。

**3. 语义分析**（`types/` + `lifecycle/`）
- *类型检查* — 强制线性资源语义：每个 `resource`/`receipt` 值在 action
  体退出前必须被 consume、transfer、destroy、claim 或 settle。同时验证
  shared-state 可变性规则、capability gates、effect 分类（`Pure` /
  `ReadOnly` / `Mutating` / `Creating` / `Destroying`）和调用签名。
- *生命周期检查* — 验证 receipt 上的 `#[lifecycle(...)]` 状态机：合法
  状态转换、整数 state-field 类型和静态 create-site 检查。

**4. IR 降低**（`ir/` + `optimize/` + `resolve/`）
- *`resolve/`* — 构建每模块符号表，解析跨包 `use` 导入。
- *`ir/`* — 将类型化 AST 降低为扁平的、面向 RISC-V 的中间表示
  （`IrAction`、`IrLock`、`IrPureFn`、`IrTypeDef`），带显式 Cell-effect
  指令（`IrConsume`、`IrCreate`、`IrReadRef`、`IrTransfer`、`IrDestroy`、
  `IrClaim`、`IrSettle`）、witness/layout 槽位分配和 verifier obligations。
- *`optimize/`* — 在 `-O1+` 时做语法局部常量折叠和死分支裁剪。刻意保守
  以保留资源语义。

**5. 代码生成**（`codegen/`）
输出 ckb-vm 兼容 RISC-V assembly（`.s`）或 ELF（`.elf`）：
- Syscall wrapper：`ckb_load_cell_data`、`ckb_load_witness`、
  `ckb_load_header_by_field`、`ckb_load_input_by_field`。
- Cell input/output/dep 索引映射、witness ABI 帧、运行时 scratch buffer
  和每入口点 trampoline。
- Profile 切换的 syscall ABI — CKB 使用特定的 syscall 编号表和
  source-flag 约定。

### Metadata 与策略

编译器输出单个 JSON metadata sidecar（`.elf.meta.json` / `.s.meta.json`），
涵盖链调度器、审计工具和策略门禁所需的一切——无需重新解析源码：

| 内容 | 产生者 | 消费者 |
|---|---|---|
| Schema 布局、type ID、字段偏移 | `ir/` | Schema 解码器、索引器 |
| Effect 分类、资源摘要 | `types/` | 调度器、审计工具 |
| Scheduler witness ABI 与访问域 | `codegen/`（CKB） | CKB 区块构建器、并行调度器 |
| 源码哈希、artifact CKB Blake2b | `lib.rs` | `cellc verify-artifact`、CI |
| Verifier obligations、pool invariants | `ir/` | 链上 verifier、策略检查器 |
| Target-profile 策略违规 | `lib.rs` | `cellc check`、CI |

`cellc constraints` 输出关注生产就绪性的可读子集：ABI slot 用量、寄存器/
stack-spill 布局、witness byte bounds、CKB cycle/capacity 估算。

### 运行时与标准库

| 模块 | 作用 |
|---|---|
| **Stdlib**（`stdlib/`） | 降低到 ckb-vm syscall 和小型运行时 helper 的内置函数：`syscall_load_tx_hash`、`syscall_load_script_hash`、`syscall_load_cell`、`syscall_load_header`、cycle/time helper 和 math helper。模块注入，不单独链接。 |
| **Collections**（`stdlib/collections.rs`） | 类 vector 操作（push、length、get），降低到 Cell output data 区域写入/读取并带边界检查。 |

### 工具面

| 工具 | 模块 | 工作方式 |
|---|---|---|
| **CLI** | `cli/` + `main.rs` | `cellc` 二进制，包含所有子命令 |
| **LSP** | `lsp/` + `lsp/server.rs` | In-process `LspServer` + `tower-lsp` JSON-RPC over stdio（`cellc --lsp`） |
| **VS Code** | `editors/vscode-cellscript/` | 调用 `cellc` 实现高亮、诊断、报告 |
| **Formatter** | `fmt/` | 幂等格式化器，服务于 `cellc fmt` 和 LSP |
| **Doc 生成器** | `docgen/` | 从 AST + metadata 生成 HTML/Markdown/JSON 文档 |
| **模拟器** | `simulate.rs` | 符号求值器——输出 `TraceEvent` 日志，无需 ckb-vm |
| **REPL** | `repl.rs` | 交互式 read-eval-print loop |

### 包与构建系统

| 模块 | 作用 |
|---|---|
| **包工作流**（`package/`） | `Cell.toml` 解析、本地 path 依赖解析、传递 `Cell.lock` 可复现性、`cellc init`/`add`/`remove`/`install --path`/`update`/`info`。Registry publish 与 registry 依赖解析已具形状但 fail-closed。 |
| **增量编译器**（`incremental/`） | 依赖图感知构建缓存——输入未变时跳过重编译。 |
| **构建集成**（`lib.rs`） | 解析 `Cell.toml` → `CellBuildConfig`，合并 CLI + manifest 选项，选择入口 scope，运行策略门禁，写入 artifact + metadata。 |

### CKB Target Profile

CKB profile 不是最后一步的打包开关。它是一层贯穿语义分析、代码生成、
metadata 输出和发布证据的策略层。目标是在 artifact 被认为可部署之前，把
CKB 假设暴露出来。

```mermaid
flowchart TB
    Source[".cell source + Cell.toml\n--target-profile ckb"] --> Frontend["Lexer + parser\n稳定 source span"]
    Frontend --> Semantics["Type + lifecycle checks\n线性资源、lock-only require、\nprotected/witness/lock_args 分类"]
    Semantics --> Policy["CKB policy gate\n对不支持的 runtime 或状态形状 fail closed"]

    subgraph Rules["CKB profile rules"]
        R1["CKB syscall ABI\nsource flags + syscall numbers"]
        R2["Molecule-facing schema\nentry witness + lock args ABI"]
        R3["CKB Blake2b\nartifact + deployment hashes"]
        R4["hash_type / CellDep / DepGroup policy"]
        R5["capacity policy\nwith_capacity_floor、occupied_capacity、\ntx-size 与 cycle evidence"]
    end

    Rules --> Policy
    Policy --> IR["IR lowering + optimizer\nCell effects、entry ABI、\nverifier obligations"]
    IR --> Metadata["metadata sidecar\nschema、ABI、runtime errors、\nconstraints、CKB policy"]
    IR --> Codegen["RISC-V codegen\nCKB syscalls、raw ELF、\nper-entry trampolines"]
    Codegen --> Artifact["CKB artifact\n.s / .elf"]

    Artifact --> Verify["cellc verify-artifact\nprofile、source hash、\nartifact hash、policy flags"]
    Metadata --> Verify

    Artifact --> Builder["builder workflow\ninputs、outputs、outputs_data、\nwitness、cell_deps、capacity floors"]
    Metadata --> Builder
    Builder --> Acceptance["CKB acceptance gate\ndry-run、commit、cycles、\ntx size、occupied capacity、\nvalid/invalid lock matrix"]
```

这里分成三条边界：

- **编译器边界** — parse、type/lifecycle checks、CKB policy rejection、IR、
  codegen 和 metadata；
- **artifact 边界** — `cellc verify-artifact` 证明 artifact、sidecar、源码
  hash、target profile 和选定 policy flags 一致；
- **链上证据边界** — builder 和 acceptance 脚本证明具体 CKB 交易形状、
  capacity、cycles、tx size，以及 lock/action 行为。

这个 profile 里的 capacity 分成两层：`with_capacity_floor(shannons)` 声明
某个类型输出的最低容量，并进入 metadata 和 constraints；
`occupied_capacity("TypeName")` 继续提供运行时可见的 capacity 检查。二者都
不替代 builder 证据：最终交易仍然要测量 occupied capacity，确保 output
capacity 足够，并保留 tx-size evidence。

### Wasm 门禁

`wasm/` 是一个 **fail-closed** 审计脚手架：它参与编译和测试，但显式拒绝
可执行 CellScript 入口，因为 CellScript 没有生产级 Wasm 后端。仅类型的
IR 模块输出审计报告；其他入口返回
`WasmSupportStatus::UnsupportedProgram`。该模块的存在是为了防止隐藏的
过时后端偏离当前 IR。

---

## 参考

### Manifest

`Cell.toml` 设置包入口、source roots、target profile 和策略默认值：

```toml
[package]
name = "token"
version = "0.15.0"
entry = "src/main.cell"
source_roots = ["src"]

[build]
target = "riscv64-elf"
target_profile = "ckb"

[policy]
production = true
deny_fail_closed = true
deny_ckb_runtime = false
deny_runtime_obligations = false
```

命令行 flags 可以在构建或 CI 中进一步收紧策略检查。

### 包工作流

CellScript 在 `cellc` 中提供本地优先的包工作流。本地包、source roots、
path dependencies、lockfile 刷新，以及 package build/check/doc/fmt 流程
已经按生产式工作流收口。Registry publish 和 registry 依赖解析仍是实验性
能力，并保持 fail-closed。

**当前支持：**

- `cellc init` — 创建带 `Cell.toml` 的应用包或 library package
- `cellc build` / `check` / `doc` / `fmt` — 操作当前 package
- 顶层 `cellc <input>` 和报告类命令在支持输入参数时接受 `.cell` 文件、
  package 目录或 `Cell.toml` manifest
- `cellc add --path` — 把本地 path 依赖写入 `Cell.toml`
- `cellc install --path` 与 `cellc update` — 解析本地 path 依赖图并刷新
  `Cell.lock`
- 本地 path dependencies 会递归解析，参与 module loading、source hashing
  和 metadata
- `Cell.lock` — 记录直接和传递依赖的解析身份，用于可复现检查
- `cellc info --json` — 为 CI 和工具输出 package metadata

**实验性 / fail-closed：**

- Registry `publish`、registry package install/resolution 和 `login` 已有命令
  形状，但在 registry backend 和 trust model 定稿前会 fail closed
- Git dependencies 是显式 remote source fetch；应当作为需要审查的输入，
  而不是 registry 生产路径

### CLI 命令

| 命令 | 用途 |
|---|---|
| `cellc <input>` | 编译 `.cell` 文件、包目录或 `Cell.toml` |
| `cellc build` | 编译包，写入 artifact + metadata |
| `cellc check` | 类型检查和 lowering，不写入 artifact |
| `cellc metadata` | 输出 lowering、runtime、scheduler、source 和 schema metadata |
| `cellc constraints` | 输出 profile-aware 生产约束 |
| `cellc abi` | 说明 action 或 lock 的 `_cellscript_entry` witness ABI 布局 |
| `cellc entry-witness` | 编码 `_cellscript_entry` witness 字节 |
| `cellc scheduler-plan` | 消费 scheduler hints，输出串行/冲突策略报告 |
| `cellc ckb-hash` | 为 builder 和 release evidence 计算 CKB 默认 Blake2b-256 hash |
| `cellc opt-report` | 对比 O0..O3 的 artifact size 和 constraints status |
| `cellc verify-artifact` | 用 metadata sidecar 校验 artifact |
| `cellc test` | 运行编译器/policy 测试（非可信 runtime 执行） |
| `cellc doc` | 生成 API 和审计文档 |
| `cellc fmt` | 格式化 `.cell` 源码或检查格式 |
| `cellc init` | 创建 package skeleton |
| `cellc add` / `remove` | 修改本地包依赖 |
| `cellc install --path` / `update` | 解析本地 path 依赖并刷新 `Cell.lock` |
| `cellc info` | 输出 manifest 和 package 信息 |
| `cellc repl` | 启动交互式 REPL |
| `cellc run` | 通过 VM runner 或 simulator 运行 ELF 入口 |
| `cellc publish` / registry `install` / registry-backed `update` / `login` | 实验性 registry 流程，fail-closed |

### CLI 选项

| 选项 | 用途 |
|---|---|
| `--target riscv64-asm` | 输出 RISC-V assembly |
| `--target riscv64-elf` | 输出 RISC-V ELF artifact |
| `--target-profile ckb` | 使用 CKB profile |
| `--entry-action <ACTION>` | 将单个 action 编译为 artifact entrypoint |
| `--entry-lock <LOCK>` | 将单个 lock 编译为 artifact entrypoint |
| `--json` | 在支持的命令中输出机器可读 summary |
| `--production` | 启用 production-oriented metadata policy checks |
| `--deny-fail-closed` | 拒绝 fail-closed runtime features 或 obligations |
| `--deny-ckb-runtime` | 拒绝 CKB transaction/syscall runtime requirements |
| `--deny-runtime-obligations` | 拒绝 runtime-required verifier obligations |

---

## 项目结构

```text
cellscript/
├── src/                 # compiler, parser, type checker, lowering, codegen, CLI
├── examples/            # example contracts and protocol patterns
├── tests/               # compiler and CLI tests
└── editors/
    └── vscode-cellscript/
```

## License

License metadata 在 [`Cargo.toml`](Cargo.toml) 中声明。仓库包含
[`LICENSE-MIT`](LICENSE-MIT)。
