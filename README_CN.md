# CellScript

[![CellScript CI](https://github.com/tsukifune-kosei/CellScript/actions/workflows/ci.yml/badge.svg)](https://github.com/tsukifune-kosei/CellScript/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)
[![Language: Rust](https://img.shields.io/badge/language-Rust-b7410e.svg)](https://www.rust-lang.org/)
[![Targets: Spora and CKB](https://img.shields.io/badge/targets-Spora%20%7C%20CKB-2f6f4e.svg)](#target-profiles)
[![Package Manager: Beta](https://img.shields.io/badge/package%20manager-beta-f0ad4e.svg)](#包管理器-beta)
[![LSP: Available](https://img.shields.io/badge/LSP-available-4c78a8.svg)](#编辑器支持)
[![Wiki Tutorials](https://img.shields.io/badge/wiki-tutorials-6f42c1.svg)](docs/wiki/Home.md)

[English](README.md) | [中文](README_CN.md)

独立仓库：<https://github.com/tsukifune-kosei/CellScript>

CellScript 是面向 Spora 和 CKB 的 Cell 模型智能合约 DSL。它把 `.cell`
源码编译为 ckb-vm RISC-V assembly 或 ELF 产物，并同时输出可用于审计、
策略检查、schema 绑定和调度感知执行的类型化 metadata。

CellScript 是刻意收窄的语言。它不是新的 VM，也不是账户存储合约语言。
它为协议作者提供一种类型化方式来描述资产、共享 Cell 状态、receipt、
生命周期转换、lock 和交易形状的效果，同时仍然直接映射到 Spora 和 CKB
使用的 Cell 模型。

## 为什么需要 CellScript

Spora 和 CKB 都暴露了强大的 Cell 执行模型，但手写脚本会迫使作者靠近线
格式工作：

- 手动解析 witness bytes；
- 按 index 跟踪 inputs、CellDeps、outputs 和 output data；
- 把类型化状态编码进原始 byte arrays；
- 用 RISC-V C 或汇编直接调用 syscall 编号；
- 依靠约定而不是编译器维护线性资产语义。

CellScript 把这些工作提升为显式语言构造：`resource`、`shared`、
`receipt`、`action`、`lock`、`consume`、`create`、`read_ref`、
`transfer`、`destroy`、`claim` 和 `settle`。这些构造不是隐喻；它们会
lower 到目标链已经执行的 Cell 交易形状。

## Target Profiles

CellScript 通过 `--target-profile` 支持多个 Cell 兼容目标。

| Profile | 适用场景 | 目标形状 |
|---|---|---|
| `spora` | Spora 原生产物 | Spora CellTx 约定、domain-separated BLAKE3 metadata、Spora DAG header ABI、Spora scheduler witness metadata，以及 ELF 产物中的 Spora ABI trailer。 |
| `ckb` | 受支持纯净子集的 CKB 产物 | CKB mainnet syscall profile、CKB Molecule/BLAKE2b 约定、CKB header ABI、无 Spora ABI trailer、无 Spora scheduler witness ABI。 |
| `portable-cell` | 源码可移植性检查 | 用于检查代码是否保持在 Spora/CKB 共享 Cell 子集内；生成产物时使用 `spora` 或 `ckb`。 |

v1 的 `ckb` profile 是有边界的 artifact profile。它只承诺通过 CKB
portability gate 的源码可以按 CKB profile 生成产物；它不承诺任意
stateful CellScript 程序或任意手写 CKB 合约可以完整互换。未覆盖的
CKB/runtime/stateful 形状会被策略拒绝，或保留为 post-v1 工作。

示例：

```bash
cellc examples/token.cell --target riscv64-elf --target-profile spora
cellc examples/token.cell --target riscv64-elf --target-profile ckb
cellc check --target-profile portable-cell
```

## 核心模型

CellScript 程序围绕 Cell 生命周期操作书写。

| CellScript 概念 | Cell 交易映射 |
|---|---|
| `resource T { ... }` | 线性的 Cell-backed 资产，表示为 `CellOutput` 加 `outputs_data[i]`。 |
| `shared T { ... }` | 共享状态 Cell；通过 `CellDep` 读取，或通过消费 input 并创建替代 output 来更新。 |
| `receipt T { ... }` | 一次性证明 Cell，可表达 deposit、vesting grant、vote 或 liquidity position 等操作结果。 |
| `consume value` | 花费一个 transaction input，线性值随后不可再用。 |
| `create T { ... }` | 创建新的 output Cell 和类型化 output data。 |
| `read_ref T` | 加载只读 CellDep-backed 值。 |
| `action` | 编译为 RISC-V 的 type-script 风格状态转换逻辑。 |
| `lock` | 编译为 RISC-V 的 lock-script 风格授权逻辑。 |
| 本地 `let` 值 | 交易局部计算或 witness 派生值；它们自身不会成为持久存储。 |

只有 `create` 会物化持久状态。普通本地值不会变成 Cell，除非它们被显式
创建为 `resource`、`shared` 或 `receipt`。

## 语言特性

- **Cell 原生资源**：`resource` 值是线性的，不能复制、静默丢弃或藏进
  普通值。每个 resource 都必须被 consume、transfer、return、claim、
  settle 或 destroy。
- **显式共享状态**：`shared` 标记池、注册表、配置 Cell 等争用敏感协议
  状态。读写会保持对 metadata 和工具可见。
- **Receipt 作为有状态证明**：`receipt` 表示一次性 Cell，证明某个操作已经
  发生，并可在之后被 claim 或 settle。
- **Capability 守门**：`has store, transfer, destroy` 这类声明让资产权限
  显式化。
- **生命周期规则**：`#[lifecycle(...)]` 让 Cell-backed 值描述状态机，例如
  `Granted -> Claimable -> FullyClaimed`。
- **Effect 推断**：`action` 会根据 Cell 操作被分类为 `Pure`、`ReadOnly`、
  `Mutating`、`Creating` 或 `Destroying`。
- **调度感知 metadata**：Spora target 可以暴露 access summary 和 shared
  touch domain，让区块构建器和执行流水线判断哪些工作可以独立处理。
- **类型化 schema metadata**：Cell data layout、type identity、output 字段
  provenance、source hash、runtime access 和 verifier obligation 都会作为机
  器可读 metadata 输出。
- **RISC-V 输出**：可执行目标是 ckb-vm 兼容 RISC-V assembly 或 ELF。
  CellScript 不引入独立 VM。
- **包感知编译**：支持 `Cell.toml`、本地模块、配置化 source roots 和本地
  path dependencies。
- **策略门禁**：build、check、metadata 和 artifact verification 命令可以按
  目标 profile 或部署策略拒绝不合规产物。

## 示例

CellScript 语法刻意贴近 Cell 交易形状。一个 module 包含 schema 声明和可
执行入口。持久值用 `resource`、`shared` 或 `receipt` 声明；可执行逻辑用
`action` 或 `lock` 声明；交易效果用显式生命周期操作表达。

常见声明形式：

```cellscript
module spora::example

struct Config {
    threshold: u64
}

resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}

shared Pool has store {
    token_reserve: u64
    spora_reserve: u64
}

receipt VestingGrant has store, claim {
    beneficiary: Address
    amount: u64
    unlock_epoch: u64
}

lock owner_only(owner: Address, signature: Signature) {
    assert_invariant(verify_signature(owner, signature), "invalid signature")
}
```

常见语句和效果形式：

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
`read_ref` 当作 Cell effect，而不是普通函数调用。这些 effect 会反映到
metadata 中，使 Spora 调度、CKB admission policy、schema decoding 和
artifact verification 都能审计生成脚本。

完整的 fungible-token 示例：

```cellscript
module spora::fungible_token

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

仓库还包含以下 bundled protocol examples：

| Example | 展示内容 |
|---|---|
| `examples/token.cell` | Mint、transfer、burn，以及带同 symbol guard 的 token merge。 |
| `examples/timelock.cell` | 时间门控状态转换和延迟 claim 路径。 |
| `examples/multisig.cell` | 授权阈值和签名导向的 lock 逻辑。 |
| `examples/nft.cell` | 唯一资产、metadata 和所有权转移。 |
| `examples/vesting.cell` | Receipt-style grants 和 claim lifecycle。 |
| `examples/amm_pool.cell` | Shared pool state、swap 和 liquidity effects。 |
| `examples/launch.cell` | Launch/pool composition patterns。 |

## 对比

下面的对比总结了 CellScript 为什么围绕 typed Cells、线性资源、显式交易
effect 和 ckb-vm artifact 设计，而不是围绕账户存储或单链专用 VM 设计。

| 维度 | CellScript | Solidity | Move | Sway |
|---|---|---|---|---|
| 执行目标 | ckb-vm 上的 RISC-V ELF 或 assembly | EVM bytecode | Move bytecode | FuelVM bytecode |
| 状态模型 | 类型化 Cells，显式 inputs/deps/outputs | 账户存储槽 | 全局存储中的 resources | UTXO 加原生资产 |
| 资产模型 | 原生 `resource`、生命周期、receipt 和 shared Cell 模式 | 手写 token contracts | 原生 resources | 原生资产，但 type-script 概念较少 |
| 线性所有权 | 对 Cell-backed 值做编译器强制 | 无 | 通过 abilities 支持 | 无通用用户定义线性 resource |
| 共享状态 | 显式 `shared` Cells | 隐式 contract storage | 部分 Move 链中的 shared objects | 无通用 shared Cell 对应物 |
| 重入形态 | 没有账户存储 callback 风格重入 | 常见风险面 | 设计上较低 | predicate 风险较低 |
| 调度 metadata | Spora target 原生支持 | 无 | 非 GhostDAG 导向 | predicate 级独立性 |
| CKB 兼容性 | 对受支持 Cell 子集提供有边界的 ckb-vm artifact profile | 需要不同 VM | 需要不同 VM | 需要 FuelVM |

与手写 CKB 或 Spora 脚本相比，CellScript 保留同一个 runtime substrate，
但用类型化 Cell 操作、线性检查、schema metadata 和可被策略验证的产物取代
原始 byte/syscall 编程。

## 快速开始

从仓库安装：

```bash
cd cellscript
cargo install --path .
```

编译单文件：

```bash
cellc examples/token.cell
cellc examples/token.cell --target riscv64-elf
cellc examples/token.cell --target riscv64-elf --target-profile ckb
```

编译或检查包：

```bash
cellc build --target-profile spora
cellc check --target-profile ckb
cellc check --target-profile portable-cell
```

初始化和维护包：

```bash
cellc init token-package
cd token-package
cellc add shared-types --path ../shared-types
cellc info
cellc build --target riscv64-elf --target-profile spora
```

输出 metadata：

```bash
cellc metadata examples/token.cell --target riscv64-elf --target-profile spora
cellc examples/token.cell --target riscv64-elf --target-profile spora
cellc verify-artifact examples/token.elf --metadata examples/token.elf.meta.json
```

## Manifest

`Cell.toml` 可以设置包入口、source roots、target profile 和 policy 默认值。

```toml
[package]
name = "token"
version = "0.1.0"
entry = "src/main.cell"
source_roots = ["src"]

[build]
target = "riscv64-elf"
target_profile = "spora"

[policy]
production = true
deny_fail_closed = true
deny_symbolic_runtime = false
deny_ckb_runtime = false
deny_runtime_obligations = false
```

命令行 flags 可以在构建或 CI 中进一步收紧策略检查。

## 包管理器 Beta

CellScript 在 `cellc` 中提供 beta 包管理器。当前设计刻意保持本地优先和
fail-closed；registry protocol 仍属于 post-v1 工作。

当前支持：

- `cellc init` 创建带 `Cell.toml` 的应用包或 library package。
- `cellc build`、`cellc check`、`cellc metadata` 和 `cellc test` 可以接受包
  目录或 manifest 作为输入。
- `cellc add --path` 和 `cellc add --git` 会把依赖写入 `Cell.toml`。
- 本地 path dependencies 会递归解析，并参与 module loading、source
  hashing 和 metadata。
- `Cell.lock` 记录解析后的依赖身份，用于可复现检查。
- `cellc info --json` 为 CI 和工具输出 package metadata。

仍处于 beta：

- Registry `publish`、`install`、`update` 和 `login` 已有命令形状，但在
  registry backend 和 trust model 定稿前会 fail closed。
- Package name、lockfile 字段和 registry authentication 还不是稳定生产接口。

## CLI Reference

| Command | 用途 |
|---|---|
| `cellc <input>` | 编译 `.cell` 文件、包目录或 `Cell.toml`。 |
| `cellc build` | 编译包并写入 artifact 和 metadata。 |
| `cellc check` | 类型检查和 lowering，不写入 artifact。 |
| `cellc metadata` | 输出 lowering、runtime、scheduler、source 和 schema metadata。 |
| `cellc verify-artifact` | 用 metadata sidecar 和可选 source hashes 校验 artifact。 |
| `cellc test` | 运行 `.cell` 源码和注释驱动诊断的编译器测试。 |
| `cellc doc` | 生成 API 和 audit 文档。 |
| `cellc fmt` | 格式化 `.cell` 源码或检查格式。 |
| `cellc init` | 创建 package skeleton。 |
| `cellc add` / `cellc remove` | 修改本地包依赖。 |
| `cellc publish` / `cellc install` / `cellc update` / `cellc login` | Beta registry-shaped commands；registry-backed operation 仍会 fail closed。 |
| `cellc info` | 输出 manifest 和 package 信息。 |
| `cellc repl` | 启动交互式 REPL。 |
| `cellc run` | 通过可选 VM runner 或 simulator 路径运行支持的 ELF entrypoints。 |

常用选项：

| Option | 用途 |
|---|---|
| `--target riscv64-asm` | 输出 RISC-V assembly。 |
| `--target riscv64-elf` | 输出 RISC-V ELF artifact。 |
| `--target-profile spora` | 使用 Spora profile。 |
| `--target-profile ckb` | 使用 CKB profile。 |
| `--target-profile portable-cell` | 检查 Cell profile 间的源码可移植性。 |
| `--json` | 在支持的命令中输出机器可读 summary。 |
| `--production` | 启用 production-oriented metadata policy checks。 |
| `--deny-fail-closed` | 拒绝 fail-closed runtime features 或 obligations。 |
| `--deny-symbolic-runtime` | 拒绝 symbolic Cell/runtime requirements。 |
| `--deny-ckb-runtime` | 拒绝 CKB transaction/syscall runtime requirements。 |
| `--deny-runtime-obligations` | 拒绝 runtime-required verifier obligations。 |

## 编辑器支持

CellScript 包含 beta 语言工具：

- 编译器 crate 暴露 in-process LSP service，覆盖 diagnostics、completions、
  hover、definition、references、rename、formatting 和 metadata-oriented code
  actions。
- 仓库包含一个 VS Code 扩展，支持 `.cell` 语法高亮、语言配置、snippets、
  open/save diagnostics，以及 compiler-backed formatting/validation hooks。
- 编辑器集成仍处于 beta。它适合本地编写和获取编译器反馈，但
  language-server transport 和 extension packaging 后续仍可能演进。

- [`editors/vscode-cellscript`](editors/vscode-cellscript)

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
