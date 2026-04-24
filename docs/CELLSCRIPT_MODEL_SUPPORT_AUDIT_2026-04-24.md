# CellScript 模型支持完备性审计报告

**日期**: 2026-04-24  
**审计对象**: `cellscript/` 编译器、`testing/integration/` 验收路径、`scripts/ckb_cellscript_acceptance.sh` 与 `scripts/devnet_acceptance.sh`  
**审计口径**: 只评估 **CellScript 语言/编译器/验收体系** 对 CKB Cell 模型与 Spora CellTx 扩展模型的支持完备性；不再混入底层 `CellTx` 结构体对比或 VM 总体完备性审计。

---

## 一、执行摘要

这份报告替代旧的 `cell_ckb_comparison_audit.md`。旧文档的问题不是“全部错误”，而是**审计边界不对**：它把底层链模型对比、Spora/CKB 类型差异、以及 CellScript 编译器支持面混在了一起，容易得出失真的结论。

本次按当前代码与验收结果重审后，结论如下：

- **Spora 原生路径**：CellScript 的核心模型支持已经进入高完备度区间，`resource/shared/receipt + action/lock + scoped action artifact + scheduler witness` 这条主路径是实的。
- **CKB 兼容路径**：已经不应再描述为“只有基础兼容”。当前 `ckb` profile、strict/original scoped compile、builder-backed acceptance、tx-size/occupied-capacity measurement、final hardening gate 都已闭合到当前 acceptance 体系的交付口径。
- **仍未完全解决的问题** 不在“是否能跑”这一层，而在：
  - Spora 标准 mass policy 主线还未闭合；
  - full-file monolith artifact 与真实 scoped deploy 单元的 gate 语义仍有混淆；
  - DSL 级 capacity/since/hash_type 语法与 builder/runtime 级约束之间仍有分层缺口。

一句话结论：

> **CellScript 对真实生产部署单元（尤其是 scoped action artifact）的支持，已经明显强于旧审计报告描述；真正剩余的生产问题集中在 Spora 标准 mass policy、full-file monolith packaging 语义，以及少数 DSL 一等语法尚未显式化的约束。**

---

## 二、对旧报告的纠偏

你贴的旧报告里，有几条结论不够精确，必须先纠正：

### 1. “CKB 无 BLAKE2b 支持” 这个说法过头了

这条**不能直接成立**。

当前代码里已经有明确的 CKB profile 哈希域声明：

- `cellscript/src/lib.rs`
  - `spora` profile: `spora-domain-separated-blake3`
  - `ckb` profile: `ckb-packed-molecule-blake2b`

README 也明确把 `ckb` profile 定义为：

- `BLAKE2b/Molecule conventions`
- `CKB syscall profile`
- `no Spora extensions`

更准确的说法应该是：

> **CKB profile 在 target metadata / ABI / hash-domain 层已经明确选择 Blake2b 语义；但“通用 DSL 级 Blake2b 用户可调用 surface 是否完备”不能简单等同于“完全没有 Blake2b 支持”。**

也就是说，旧报告把“**缺少显式通用 stdlib Blake2b 入口**”夸大成了“**CKB 无 Blake2b 支持**”。

### 2. “capacity 管理完全缺失” 也不精确

这条也需要降级。

当前 compiler constraints 已经暴露了 CKB capacity 相关约束：

- `min_code_cell_data_capacity_shannons`
- `recommended_code_cell_capacity_shannons`
- `capacity_status = "code-cell-data-lower-bound"`

并且 CKB acceptance 侧已经有：

- `occupied_capacity_measured_action_count = 43`
- `tx_size_measured_action_count = 43`
- `builder_backed_action_count = 43`

所以更准确的说法是：

> **CellScript 没有 DSL 一等语法去表达和静态证明完整 transaction-level capacity 规划；但 compiler metadata、constraints surface、acceptance measurement 已经明确暴露了 code-cell capacity 与 occupied-capacity 证据。**

缺口是真存在，但不是“完全没有 capacity 支持”。

### 3. “since 无支持” 不成立

旧报告把这一点写成高风险缺口，也过头了。

当前代码里已经存在：

- `ckb::input_since`
- target-profile policy 与 runtime access metadata 也会记录 `ckb-input-since`

更准确的判断是：

> **`since` 已有可用 runtime surface，但还没有更高层的声明式 DSL 语法糖或 compile-time policy language 去表达“这个 action 的时间锁语义必须满足什么条件”。**

所以问题是“**缺少更高级的声明式约束层**”，不是“**since 根本不支持**”。

### 4. “CKB 线仍未到最终生产口径” 已经过时

这条在当前仓库里已经失效。

最新 CKB acceptance 已经达到：

- `production_gate = passed`
- `production_ready = true`
- `final_production_hardening_gate = passed`
- `builder_backed_action_count = 43`
- `tx_size_measured_action_count = 43`
- `occupied_capacity_measured_action_count = 43`

因此当前对 CKB 线的准确口径应该是：

> **在当前 acceptance 体系下，CKB 本地 production gate 与 final hardening gate 都已闭合。**

这不等于“外部主网绝对无风险”，但已经比旧报告描述强得多。

---

## 三、按维度重新评级

### 3.1 核心 Cell 模型映射 — **A-**

| 维度 | 当前状态 | 结论 |
|---|---|---|
| `CellOutput(lock/type_/capacity)` | `resource/shared/receipt` + `create/transfer/destroy` 已稳定 lowering | ✅ |
| `CellInput(previous_output, since)` | `consume` 已完备；`ckb::input_since` 已提供 runtime 读取 | ✅ / ⚠️ |
| `CellDep` | `read_ref<T>`、scoped deploy、builder-backed acceptance 已大量覆盖 | ✅ |
| `Script(code_hash/hash_type/args)` | `lock` / `type_id` / metadata / profile policy 已成体系 | ✅ |
| `outputs_data` | Molecule schema、fixed struct/table/vector 路径已大量落地 | ✅ |
| `capacity` | metadata / constraints / acceptance 有证据，但 DSL 无显式 first-class planning surface | ⚠️ |

结论：

> **CellScript 对 Cell 基本形状的映射已经不是问题。真正的剩余问题集中在 capacity 语义是否应提升到 DSL 一等公民。**

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

这意味着旧报告里“状态合约 lowering 还大量依赖 metadata obligations、尚未成为真实 verifier”这类判断，已经不适用于当前代码状态。

更准确的说法是：

> **当前 CellScript 的主流资源/状态/receipt 生命周期已经进入“真实 verifier + builder-backed acceptance”阶段，不再只是 metadata-level 说明。**

### 3.3 Spora 专属扩展 — **B+**

Spora 特性支持目前大致分成两层：

#### 已闭合

- `env::current_daa_score()`
- `env::current_timepoint()` 在 Spora 下降到 DAA 语义
- Spora profile 的 `SPORABI` trailer
- scheduler witness metadata / Molecule ABI
- scoped action artifact acceptance
- malformed rejection matrix

#### 仍未闭合

- 标准 mass policy 主线
- full-file monolith artifact 的 standard relay compatibility

也就是说，Spora 现在的真实问题不是“语言不支持 Spora 模型”，而是：

> **Spora production gate 仍然被标准 mass policy 与 full-file monolith deploy compatibility 卡住。**

### 3.4 CKB 兼容 profile — **A-**

当前 CKB 路线的真实状态明显比旧报告高：

- `ckb` syscall/profile 已切通
- `current_timepoint()` 已做 target-aware lowering
  - Spora -> DAA
  - CKB -> epoch/header
- `current_daa_score()` 被 CKB policy 正确拒绝
- original / strict scoped compile 覆盖已闭合
- builder-backed acceptance 已 `43/43`
- tx-size / occupied-capacity measurement 已 `43/43`
- final hardening gate 已通过

因此 CKB 路线现在的不足，不该再写成“基础支持但未成体系”，而应该写成：

> **CKB 线在当前 acceptance 体系下已达到本地 production + final hardening 闭合；剩余边界主要是 DSL 明确性和外部主网长期运维层，而不是 core compile/runtime support 缺失。**

### 3.5 序列化与 ABI — **A-**

当前旧报告里“Vec 和动态 table 支持有限”这个判断需要保守表达。

更准确的现状是：

- Molecule ABI 已是核心路径
- entry witness ABI 已稳定
- schema-backed params、cell-bound ABI、fixed byte params 都已有明确 lowering
- 动态结构在真实 examples 与 acceptance 里已经用了不少，不应再写成“基本不可用”

但也不能夸成“任意 Molecule 复合结构都已无盲区”。

因此更准确的评级是：

> **Molecule ABI 已经是主路径而不是试验品；但复杂嵌套动态结构的“语言面完全自由表达”仍不应过度承诺。**

---

## 四、当前真正的缺口

### P0 / 当前生产阻断

#### 1. Spora 标准 mass policy 主线未闭合

当前最关键、也最真实的生产阻断就是这个。

已知事实：

- scoped actions: `43/43` 都在标准 relay 范围内
- full bundled examples: `5/7` 在标准 relay 内
- 不兼容样本：
  - `multisig.cell`
  - `nft.cell`

更深层的问题是：

> **production gate 当前仍把“真实 scoped deployment unit”和“full-file monolith regression artifact”混在同一层诊断里。**

这件事不解决，Spora 生产口径就还不稳。

### P1 / 高优先级设计缺口

#### 2. DSL 级 capacity 不是一等语义

现在有：

- compiler constraints
- builder measurement
- occupied capacity evidence

但没有：

- 显式 DSL 语法去约束 output capacity
- compiler static proof 去说明某个 action 的完整 tx 一定满足 occupied capacity

所以这不是“完全没有 capacity”，而是：

> **capacity 仍主要停留在 metadata/builder/runtime 层，而不是语言一等语义。**

#### 3. `since` 仍偏 runtime-oriented，缺少声明式 policy surface

`ckb::input_since` 已有，但仍缺：

- 类似 `requires since >= ...` 的高层语义表达
- 生命周期层面的时间锁约束声明

#### 4. full-file monolith artifact 的定位还不清楚

当前从数据上已经能看出：

- 真正生产部署单元是 scoped action artifact
- full-file monolith artifact 更像 regression / packaging / audit surface

所以 production gate 后续最好拆成：

- **scoped deploy compatibility**: 硬门槛
- **full-file monolith compatibility**: advisory 或单独 regression gate

### P2 / 后续提升项

#### 5. 更高层 DSL 语义补足

包括但不限于：

- capacity first-class syntax
- richer `since` / timelock declarative syntax
- 更明确的 `hash_type` authoring surface
- 更形式化的 tx-shape constraints language

#### 6. 更轻的 acceptance/debug probe 面

目前我刚开始补 `spora-standard-relay-probe`，方向是对的：

> 不再用超重的全量 acceptance test 去调一个单点标准 relay 问题，而是拆出独立 probe。

这条路值得继续。

---

## 五、综合评分

| 维度 | 评分 |
|---|---:|
| 核心 Cell 模型映射 | 90 |
| 生命周期与状态转换 | 92 |
| Spora 专属扩展 | 84 |
| CKB 兼容 profile | 90 |
| 序列化与 ABI | 88 |
| 生产验收与硬化闭环 | 87 |
| **综合** | **88.5 / 100** |

---

## 六、最终结论

旧报告的核心问题不是“全错”，而是**低估了当前 CellScript 的真实闭合度**，尤其是：

- 把 CKB 线写得过弱；
- 把 `BLAKE2b` / `capacity` / `since` 写成了比实际更绝对的“缺失”；
- 没把 builder-backed acceptance、tx-size measurement、occupied-capacity measurement、final hardening gate 纳入审计基线；
- 没把 **scoped production deploy** 和 **full-file monolith packaging** 区分开。

当前更准确的判断是：

1. **CKB 线**  
   在当前 acceptance 体系下，`production_gate` 与 `final hardening gate` 都已闭合。

2. **Spora 线**  
   scoped action coverage 已闭合，真正剩余的生产阻断是：
   - standard mass policy 主线
   - full-file monolith artifact 的 standard relay compatibility

3. **语言/编译器本体**  
   已经进入高完备度区间。真正剩下的缺口，不再是“CellScript 能不能表达 Cell 模型”，而是：
   - 哪些约束要不要提升为 DSL 一等语义；
   - production gate 的部署单位定义是否要进一步收紧到 scoped artifact。

一句话版：

> **CellScript 当前不是“模型支持不完整的实验编译器”，而是“核心模型已基本闭合、剩余问题集中在生产 gate 语义与少数高层约束表达”的双链 Cell 编译器。**
