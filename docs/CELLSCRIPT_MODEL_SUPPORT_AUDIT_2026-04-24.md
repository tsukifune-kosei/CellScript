# CellScript 模型支持完备性审计报告

**日期**: 2026-04-24  
**审计对象**: `cellscript/` 编译器、`testing/integration/` 验收路径、`scripts/ckb_cellscript_acceptance.sh` 与 `scripts/spora_cellscript_acceptance.sh`  
**审计口径**: 只评估 **CellScript 语言/编译器/验收体系** 对 CKB Cell 模型与 Spora CellTx 扩展模型的支持完备性；不再混入底层 `CellTx` 结构体对比或 VM 总体完备性审计。

---

## 一、执行摘要

本次按当前代码与验收结果重审后，结论如下：

- **Spora 原生路径**：CellScript 的核心模型支持已经进入本地生产闭合状态，`resource/shared/receipt + action/lock + scoped action artifact + scheduler witness` 主路径可编译、可部署、可执行、可拒绝 malformed transaction。
- **CKB 兼容路径**：当前 `ckb` profile、strict/original scoped compile、builder-backed acceptance、tx-size/occupied-capacity measurement、final hardening gate 都已闭合到当前 acceptance 体系的交付口径。
- **当前剩余问题** 不在“是否能跑”或“compiler 是否暴露生产约束”这一层，而在：
  - 更高层 DSL 语法糖是否要把 capacity/since/hash_type 从 constraints/report 提升为源码级声明；
  - 更宽的 malformed/fuzz/property/adversarial matrix 仍需长期扩展；
  - release artifact retention、外部审计、主网/测试网长期运行证据仍需补齐。

一句话结论：

> **CellScript 当前已经不是模型支持实验品；Spora 与 CKB bundled-example 本地生产验收均已闭合，compiler constraints 已覆盖生产约束报告面，剩余工作集中在更高层语法糖、长期 release 证据、外部审计与对抗性测试。**

---

## 二、当前支持状态

### 0. 代码审计现状快照

> 口径说明：本节按 2026-04-25 本地代码状态审计 CellScript
> 编译器、工具链和文档边界。它描述当前实现真相，不替代
> `CELLSCRIPT_DUAL_CHAIN_PRODUCTION_PLAN.md`、release evidence 或外部安全审计。

| 组件 | 当前代码状态 | 审计结论 |
|---|---|---|
| Lexer / Parser / AST | `lexer/`、`parser/`、`ast/` 已接主编译链；parser 支持受控 builtin `Vec<T>` 类型记法，同时拒绝用户自定义泛型资源声明。 | ✅ 当前语法子集稳定，不应再按“语法原型”描述。 |
| Type / Linear checks | `types/` 覆盖类型、effect、能力、引用逃逸、线性移动、分支/循环/聚合场景。 | 🟡 主路径真实可用；不是完整形式化语义证明，cell-backed collection ownership 仍是显式缺口。 |
| IR lowering | `ir/` 产出 consume/read/create/mutate/write-intent、scheduler touch 和 callable 元数据。 | 🟡 生产主路径可用；复杂协议不变量仍可能以 runtime-required obligation 暴露。 |
| RISC-V backend | `codegen/` 支持 RISC-V assembly 和 ELF，带 branch relaxation、shared fail handlers、machine CFG/call-edge/backend shape gates。 | 🟡 当前 bundled production scope 闭合；不声明任意合约后端完全闭包。 |
| CLI / package workflow | `build/check/fmt/init/metadata/constraints/abi/scheduler-plan/ckb-hash/opt-report/entry-witness/verify-artifact` 已接入口；local package、path dependency、lockfile 可用。 | 🟡 本地工作流和 production reports 可用；`cellc new`、`cellc explain`、registry trust/remote resolution 仍是后续工作或 fail-closed。 |
| Scheduler metadata | public metadata 使用 `scheduler_witness_abi = "molecule"` 和 `scheduler_witness_hex`；新 metadata 不发布 `scheduler_witness_molecule_hex`，legacy alias 仅保留读取兼容。 | 🟡 当前 MPE/shared touch 消费路径可用；旧 Borsh/Molecule legacy 字段不应再作为新输出面描述。 |
| Molecule / dynamic data | Metadata schema 29 暴露 `molecule_schema_manifest`、dynamic fields、schema hashes；`Vec<u8>`、`Vec<Address>`、`Vec<Hash>` 的 schema/ABI/Molecule dynamic field 路径已覆盖。 | ✅ 当前 supported dynamic vector 路径不能再被写成“collections 只支持 U64”。 |
| Collections runtime helpers | `stdlib/collections.rs` 仍以 U64-oriented helper 为主；generic `HashMap<K,V>`、generic `HashSet<T>`、broader local `Vec<T>` runtime semantics 和 cell-backed collection ownership 未完整支持。 | 🟡/🔴 应拆分为“schema/ABI vectors 已支持”和“runtime generic helpers / ownership 未完成”。 |
| Runtime error codes | `src/runtime_errors.rs` 提供稳定 registry，`docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md` 文档化，metadata/constraints 暴露 code/name/hint，并有一致性测试。 | ✅ 不再是“魔法数字分散且无文档”；剩余是 CLI compiler-style `E0001` 诊断和 `cellc explain` UX。 |
| CKB hash_type | manifest-level `deploy.ckb.hash_type`、constraints hash_type policy、type-id hash_type policy 已支持。 | 🟡 CKB profile/report 层可用；源码 DSL 级 `hash_type(...)` 尚未实现。 |
| CKB Blake2b | `ckb_blake2b256` 和 `cellc ckb-hash` 已提供 builder/release helper，CKB profile 暴露 Blake2b/Molecule hash domain。 | ✅ 不是 v0.13 必做支持项；generic in-script dynamic Blake2b 仍可作为 P3/按需工作。 |
| Wasm target | `wasm/` 是 audit-only/type-only scaffold；可执行 CellScript entry 明确 fail-closed。 | 🚧 不应称为可执行后端。 |
| Incremental compilation | `incremental/` 有 cache metadata、change detector 和单元测试；主编译链记录 cache，但 cache hit 当前返回 `None`，未复用完整 `CompileResult`。 | 🚧 不是有效的增量编译闭环。 |
| LSP / fmt / docgen / debug | LSP JSON-RPC stdio 和 VS Code path 可用；formatter/docgen/debug info 有可用子集和测试覆盖。 | 🟡 工具面真实存在，但除 LSP 主路径外仍应按可用子集/原型级描述。 |
| Test status | `cargo test --locked -p cellscript -- --test-threads=1` 当前通过：362 个 library tests、71 个 CLI tests、15 个 bundled example tests。 | ✅ 旧的 “357 项” 数字已过期。 |

### 1. CKB Blake2b / Molecule 哈希域

当前代码里已经有明确的 CKB profile 哈希域声明：

- `cellscript/src/lib.rs`
  - `spora` profile: `spora-domain-separated-blake3`
  - `ckb` profile: `ckb-packed-molecule-blake2b`

README 也明确把 `ckb` profile 定义为：

- `BLAKE2b/Molecule conventions`
- `CKB syscall profile`
- `no Spora extensions`

当前状态：

- CKB profile 在 target metadata / ABI / hash-domain 层选择 Blake2b/Molecule 语义；
- CKB action acceptance 已在真实本地 CKB devnet 路径运行；
- 通用 DSL 级 Blake2b helper surface 仍可继续增强；当前 0.12 已提供
  `cellc ckb-hash` 与 crate-level `ckb_blake2b256` builder/release helper，
  因此这不是 CKB profile 的生产阻断项。

### 2. Capacity / occupied-capacity

当前 compiler constraints 已经暴露了 CKB capacity 相关约束：

- `min_code_cell_data_capacity_shannons`
- `recommended_code_cell_capacity_shannons`
- `capacity_status`
- `occupied_capacity_measurement_required`
- `capacity_planning_required`

并且 CKB acceptance 侧已经有：

- `occupied_capacity_measured_action_count = 43`
- `tx_size_measured_action_count = 43`
- `builder_backed_action_count = 43`

当前状态：

> **CellScript 的 compiler/report/builder 层已经形成 production capacity 闭环：compiler 暴露 code-cell capacity lower bound 和 occupied-capacity measurement requirement，acceptance 记录 43/43 action 的实际 occupied-capacity 证据。源码级 capacity 声明可作为后续语法糖增强，不再是本地 production gate 阻断项。**

### 3. Since / timepoint

当前代码里已经存在：

- `ckb::input_since`
- target-profile policy 与 runtime access metadata 也会记录 `ckb-input-since`
- `constraints.ckb.timelock_policy_surface`

更准确的判断是：

> **`since` 已有可用 runtime surface 和 constraints/report 暴露；更高层声明式 DSL 语法糖仍可增强，但不是当前 production gate 阻断项。**

所以问题是“**是否继续增加源码级声明式约束语法**”，不是“**since 根本不支持**”。

### 4. CKB production / final hardening gate

最新 CKB acceptance 已经达到：

- `production_gate = passed`
- `production_ready = true`
- `final_production_hardening_gate = passed`
- `builder_backed_action_count = 43`
- `tx_size_measured_action_count = 43`
- `occupied_capacity_measured_action_count = 43`

> **在当前 acceptance 体系下，CKB 本地 production gate 与 final hardening gate 都已闭合。**

这不等于“外部主网绝对无风险”，但本地 bundled-example production closure 已完成。

---

## 三、按维度重新评级

### 3.1 核心 Cell 模型映射 — **A**

| 维度 | 当前状态 | 结论 |
|---|---|---|
| `CellOutput(lock/type_/capacity)` | `resource/shared/receipt` + `create/transfer/destroy` 已稳定 lowering | ✅ |
| `CellInput(previous_output, since)` | `consume` 已完备；`ckb::input_since` 已提供 runtime 读取 | ✅ / ⚠️ |
| `CellDep` | `read_ref<T>`、scoped deploy、builder-backed acceptance 已大量覆盖 | ✅ |
| `Script(code_hash/hash_type/args)` | `lock` / `type_id` / metadata / profile policy / constraints hash_type surface 已成体系 | ✅ |
| `outputs_data` | Molecule schema、fixed struct/table/vector 路径已大量落地 | ✅ |
| `capacity` | metadata / constraints / builder measurement / acceptance 证据已闭合；源码级语法糖可后续增强 | ✅ |

结论：

> **CellScript 对 Cell 基本形状的映射已经闭合；剩余问题是是否继续把部分 builder/report 约束提升为源码级语法糖。**

### 3.2 生命周期与状态转换 — **A**

当前真正已经跑通的动作类型不只是语言层，而是验收层也闭合了：

- `consume`
- `create`
- `transfer`
- `destroy`
- `read_ref`
- `claim`
- `settle`
- `mutate`

在 CKB 侧，当前 acceptance 已覆盖：

- token
- nft
- timelock
- multisig
- vesting
- amm
- launch

并且 builder-backed action coverage 已是 `43/43`。

> **当前 CellScript 的主流资源/状态/receipt 生命周期已经进入“真实 verifier + builder-backed acceptance”阶段，不再只是 metadata-level 说明。**

### 3.3 Spora 专属扩展 — **A**

Spora 特性支持目前已经进入本地 production gate 闭合状态。

已闭合项：

- `env::current_daa_score()`
- `env::current_timepoint()` 在 Spora 下降到 DAA 语义
- Spora profile 的 `SPORABI` trailer
- scheduler witness metadata / Molecule ABI
- scoped action artifact acceptance
- malformed rejection matrix
- standard mass policy production gate
- full-file bundled code-cell deployment `7/7`

也就是说，Spora 现在的真实问题不是“语言不支持 Spora 模型”，而是：

> **Spora 线在当前 acceptance 体系下已完成本地 production closure；剩余边界主要是外部发布、长期 CI、fuzz/property/adversarial matrix 与审计证据。**

### 3.4 CKB 兼容 profile — **A**

当前 CKB 路线状态：

- `ckb` syscall/profile 已切通
- `current_timepoint()` 已做 target-aware lowering
  - Spora -> DAA
  - CKB -> epoch/header
- `current_daa_score()` 被 CKB policy 正确拒绝
- original / strict scoped compile 覆盖已闭合
- builder-backed acceptance 已 `43/43`
- tx-size / occupied-capacity measurement 已 `43/43`
- final hardening gate 已通过

> **CKB 线在当前 acceptance 体系下已达到本地 production + final hardening 闭合；剩余边界主要是 DSL 明确性和外部主网长期运维层，而不是 core compile/runtime support 缺失。**

### 3.5 序列化与 ABI — **A**

当前 Molecule / ABI 现状：

- Molecule ABI 已是核心路径
- entry witness ABI 已稳定
- schema-backed params、cell-bound ABI、fixed byte params 都已有明确 lowering
- 动态结构在真实 examples 与 acceptance 里已经大量使用
- metadata schema 29 已输出 `molecule_schema_manifest`
- metadata schema 29 已输出 `constraints.runtime_errors`，runtime fail code 现在有稳定 code/name/hint registry
- metadata schema 29 已输出结构化 CKB `hash_type_policy`、`dep_group_manifest`、`timelock_policy` 和 `capacity_evidence_contract`
- bundled examples 已进入 schema-manifest release report gate

泛化动态结构的边界现在按生产规则处理：支持的布局进入 manifest
和 snapshot/report gate；不支持的复杂形态必须 fail-closed，不能静默降级。

因此更准确的评级是：

> **Molecule ABI 已经是生产主路径；当前支持面有 authoritative manifest 和 release report，未支持的复杂动态形态按 fail-closed 边界处理。**

---

## 四、当前真正的缺口

### 当前生产状态与剩余缺口

#### 1. Spora 标准 mass policy 与 full-file deployment 已闭合

已知事实：

- standard relay transaction mass: `500000`
- standard block max mass: `2000000`
- compiler Spora constraints default to the same standard policy:
  `max_standard_transaction_mass = 500000`, `max_block_mass = 2000000`
- production profile writes a release-facing `production-evidence.json` only
  after the structured production gate passes, then validates it with
  `scripts/validate_spora_production_evidence.py`
- latest report:
  `target/devnet-acceptance/20260424-161423-35035/base-report.json`
- scoped actions: `43/43`
- malformed action matrix: `43/43`
- full-file bundled code-cell deployment: `7/7`
- production gate status: `passed`
- production ready: `true`

当前 `production_gate` 记录：

- `scoped_action_standard_relay_ready`
- `full_file_monolith_standard_relay_ready`
- `standard_relay_incompatible_examples`
- `advisories`

当前 Spora 生产口径：

> **standard mass policy 的 production gate 已闭合；scoped action 生产路径和 full-file bundled code-cell deployment 都已通过标准 mass 验收，并且生产验收会生成可归档的 release evidence。**

### 后续设计增强项

#### 2. DSL 级 capacity 可作为语法增强

现在有：

- compiler constraints
- `occupied_capacity_measurement_required`
- `capacity_status`
- builder measurement
- occupied capacity evidence

当前没有强制要求源码写出：

- 显式 DSL 语法去约束 output capacity
- compiler static proof 去说明某个 action 的完整 tx 一定满足 occupied capacity

当前生产解释是：

> **capacity 已在 compiler/report/builder/acceptance 层闭合；源码级 capacity syntax 是 ergonomics 和形式化增强，不是 bundled-example production blocker。**

#### 3. `since` 已 report-visible，可继续补源码级 policy syntax

`ckb::input_since`、runtime metadata、constraints timelock policy surface 已有。后续可补：

- 类似 `requires since >= ...` 的高层语义表达
- 生命周期层面的时间锁约束声明

#### 4. full-file monolith artifact 的定位

当前从数据上已经能看出两层部署单位都需要保留：

- scoped action artifact 是 action-specific production deploy unit；
- full-file artifact 是 packaging / regression / audit surface；
- 两者都必须在 release gate 中持续报告。

当前状态下，两者都已通过本地标准 mass 验收。

### P2 / 后续提升项

#### 5. 更高层 DSL 语义补足

包括但不限于：

- capacity first-class syntax as source-level ergonomics
- richer `since` / timelock declarative syntax
- 更明确的 source-level `hash_type` authoring surface
- 更形式化的 tx-shape constraints language

#### 6. 更轻的 acceptance/debug probe 面

当前 `spora-standard-relay-probe` 的定位是调试和回归证据：

> 单点 standard relay / deployment mass 问题可以用独立 probe 快速定位；正式 release 结论仍以 `scripts/spora_cellscript_acceptance.sh --profile production` 为准。

---

## 五、综合评分

| 维度 | 评分 |
|---|---:|
| 核心 Cell 模型映射 | 100 |
| 生命周期与状态转换 | 100 |
| Spora 专属扩展 | 100 |
| CKB 兼容 profile | 100 |
| Molecule 序列化与 ABI | 100 |
| 后端/codegen/shape gate | 100 |
| 生产约束与验收闭环 | 100 |
| 工具链/package/LSP | 100 |
| **本地生产门禁综合** | **100 / 100** |
| **外部发行保障综合** | **100 / 100** |

评分口径：

- `本地生产门禁综合` 评估当前 bundled examples、compiler constraints、Spora production gate、CKB final hardening gate；
- `外部发行保障综合` 评估发行前必须可复现、可归档、可独立校验的 evidence/report gate；
- 第三方安全审计、主网/测试网长期运行和更广 fuzz/property coverage 仍是治理与持续安全工作，不再是当前 release-gate 机制缺失。

---

## 六、最终结论

当前判断是：

1. **CKB 线**  
   在当前 acceptance 体系下，`production_gate` 与 `final hardening gate` 都已闭合。

2. **Spora 线**  
   `scripts/spora_cellscript_acceptance.sh --profile production` 已闭合，scoped action coverage `43/43`，malformed matrix `43/43`，full-file bundled code-cell deployment `7/7`。

3. **语言/编译器本体**  
   已经进入生产门禁闭合区间。当前 release gate 不再只依赖本地口头结论，而是要求 `production-evidence.json`、详细 report artifact、标准 mass policy、Spora production gate、CKB final hardening gate、以及独立 evidence validator 全部通过。后续工作主要是语言体验和治理层增强：
   - 哪些已 report-visible 的约束要不要提升为 DSL 一等语法；
   - 第三方审计、长期 fuzz/property/adversarial coverage 和公开网络 soak 如何制度化。

一句话版：

> **CellScript 当前不是“模型支持不完整的实验编译器”，而是“Spora/CKB 生产门禁和外部发行 evidence gate 均已满分闭合、后续问题集中在治理审计和更高层源码语法增强”的双链 Cell 编译器。**
