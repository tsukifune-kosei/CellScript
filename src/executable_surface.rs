//! Compiler-owned inventory of the typed IR surface and its executable status.
//!
//! The generated Markdown and JSON matrices are checked by `cellscript-tools`.
//! Keep entries conservative: `complete` means the operation has no
//! compiler-recognized fail-closed shape; `shape-gated` means production
//! compilation accepts only shapes for which the metadata classifier reports
//! no fail-closed feature.

use crate::error::{CompileError, Result};
use crate::ir::{IrBody, IrInstruction, IrItem, IrModule, IrTerminator, IrType};
use serde::Serialize;

pub const EXECUTABLE_SURFACE_SCHEMA: &str = "cellscript-executable-surface-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExecutableSurfaceEntry {
    pub id: &'static str,
    pub layer: &'static str,
    pub status: &'static str,
    pub production_policy: &'static str,
    pub conditions: &'static str,
    pub fail_closed_features: &'static [&'static str],
}

const ACCEPT: &str = "accepted";
const ACCEPT_WHEN_CLOSED: &str = "accepted only when the shape classifier reports no fail-closed feature";
const FRONTEND_ONLY: &str = "not materialized as a runtime value";

macro_rules! entry {
    ($id:literal, $layer:literal, $status:literal, $policy:expr, $conditions:literal) => {
        ExecutableSurfaceEntry {
            id: $id,
            layer: $layer,
            status: $status,
            production_policy: $policy,
            conditions: $conditions,
            fail_closed_features: &[],
        }
    };
    ($id:literal, $layer:literal, $status:literal, $policy:expr, $conditions:literal, [$($feature:literal),+ $(,)?]) => {
        ExecutableSurfaceEntry {
            id: $id,
            layer: $layer,
            status: $status,
            production_policy: $policy,
            conditions: $conditions,
            fail_closed_features: &[$($feature),+],
        }
    };
}

pub static EXECUTABLE_SURFACE: &[ExecutableSurfaceEntry] = &[
    entry!(
        "runtime:gather-hash-arguments", "runtime", "shape-gated", ACCEPT_WHEN_CLOSED,
        "Experimental gathered hashes require proven local byte/offset vectors and checked transaction span bounds.",
        ["gather-hash-materialization"]
    ),
    entry!(
        "runtime:spawn-hex4-arguments", "runtime", "shape-gated", ACCEPT_WHEN_CLOSED,
        "Experimental returning four-argument hex SPAWN/WAIT requires a proven local Vec<u8>; the external child verifier remains separately unresolved.",
        ["spawn-argv-materialization"]
    ),
    entry!(
        "runtime:exec-hex4-arguments", "runtime", "shape-gated", ACCEPT_WHEN_CLOSED,
        "Experimental four-argument hex EXEC requires a proven local Vec<u8>; external-verifier delegation remains separately unresolved.",
        ["exec-argv-materialization"]
    ),
    entry!(
        "runtime:trusted-external-delegation", "runtime", "bounded", ACCEPT_WHEN_CLOSED,
        "EXEC or SPAWN/WAIT is admitted only through a trusted_* intrinsic with a compile-time 32-byte DATA_HASH, an exact versioned Cell.toml declaration, an emitted pre-delegation identity check, and a trusted-external evidence record that never claims to prove the verifier's internals."
    ),
    entry!("type:u8", "type", "complete", ACCEPT, "One-byte unsigned scalar with checked source representability."),
    entry!("type:u16", "type", "complete", ACCEPT, "Two-byte little-endian unsigned scalar."),
    entry!("type:u32", "type", "complete", ACCEPT, "Four-byte little-endian unsigned scalar."),
    entry!("type:i32", "type", "complete", ACCEPT, "Four-byte signed scalar with signed comparison, division, and remainder."),
    entry!("type:u64", "type", "complete", ACCEPT, "Eight-byte little-endian unsigned scalar."),
    entry!(
        "type:u128",
        "type",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Sixteen-byte value with full-range decimal literals plus checked add, subtract, multiply, divide, remainder, comparison, casts, calls, parameters, and returns."
    ),
    entry!("type:bool", "type", "complete", ACCEPT, "Canonical boolean scalar."),
    entry!("type:unit", "type", "compile-time-only", FRONTEND_ONLY, "Control-flow and no-value result marker."),
    entry!("type:Address", "type", "complete", ACCEPT, "Fixed 32-byte address value."),
    entry!("type:Hash", "type", "complete", ACCEPT, "Fixed 32-byte hash value."),
    entry!("type:Array", "type", "bounded", ACCEPT_WHEN_CLOSED, "Compile-time length and recursively fixed element layout."),
    entry!(
        "type:GenericValue",
        "type",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Struct, enum, and function templates monomorphize before IR under explicit value abilities, deterministic budgets, and hidden-Cell rejection."
    ),
    entry!(
        "type:Option",
        "type",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Built-in Option<T> uses the ordinary fixed-width generic enum and tagged-union lowering path."
    ),
    entry!("type:Tuple", "type", "bounded", ACCEPT_WHEN_CLOSED, "Non-recursive aggregate with deterministic field offsets."),
    entry!("type:Named", "type", "shape-gated", ACCEPT_WHEN_CLOSED, "Concrete struct, enum, or Cell schema with a deterministic metadata layout."),
    entry!(
        "type:Ref",
        "type",
        "compile-time-only",
        FRONTEND_ONLY,
        "Read-only view with field-path, canonical-root reborrow, lifecycle-crossing, and non-escape checks before lowering."
    ),
    entry!("type:MutRef", "type", "reserved", "rejected by current semantic checks", "No executable general mutable-reference ABI."),
    entry!(
        "semantic:value-pattern",
        "semantic",
        "bounded",
        ACCEPT,
        "Recursive fixed enum, tuple, and struct patterns plus binding-free or-patterns with exhaustiveness and linear wildcard checks."
    ),
    entry!(
        "semantic:borrow-region",
        "semantic",
        "compile-time-only",
        FRONTEND_ONLY,
        "Field-path and reborrow regions retain one canonical Cell root and cannot materialize, escape, or cross a lifecycle operation."
    ),
    entry!(
        "semantic:loop-control",
        "semantic",
        "complete",
        ACCEPT,
        "Nearest and labeled break/continue targets lower to explicit CFG jumps after compile-time target validation."
    ),
    entry!("ir-item:type-def", "ir-item", "bounded", ACCEPT_WHEN_CLOSED, "Concrete fixed-layout type definition."),
    entry!("ir-item:invariant", "ir-item", "compile-time-only", FRONTEND_ONLY, "Proof-planning invariant record."),
    entry!("ir-item:action", "ir-item", "bounded", ACCEPT_WHEN_CLOSED, "Executable transaction action entry."),
    entry!("ir-item:pure-fn", "ir-item", "bounded", ACCEPT_WHEN_CLOSED, "Resolved helper callable."),
    entry!("ir-item:lock", "ir-item", "bounded", ACCEPT_WHEN_CLOSED, "Executable lock predicate entry."),
    entry!("ir-terminator:return", "terminator", "complete", ACCEPT, "Typed return with an optional value."),
    entry!("ir-terminator:jump", "terminator", "complete", ACCEPT, "Validated direct CFG edge."),
    entry!("ir-terminator:branch", "terminator", "complete", ACCEPT, "Validated boolean conditional CFG edge."),
    entry!("ir:load-const", "instruction", "complete", ACCEPT, "Materializes supported scalar and fixed-byte constants."),
    entry!("ir:load-var", "instruction", "complete", ACCEPT, "Loads a checked local binding."),
    entry!("ir:store-var", "instruction", "complete", ACCEPT, "Stores a checked local binding without changing Cell authority."),
    entry!(
        "ir:binary",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Scalar arithmetic, bitwise, shifts, and complete u128 operators execute directly; dynamic shifts have width guards and fixed-byte equality requires addressable operands.",
        ["fixed-byte-comparison"]
    ),
    entry!("ir:unary", "instruction", "bounded", ACCEPT, "Boolean not, scalar negation, and compile-time reference conversions."),
    entry!(
        "ir:field-access",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Requires a fixed schema, aggregate pointer, or tuple-call-return layout.",
        ["field-access"]
    ),
    entry!(
        "ir:index",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Fixed aggregates and bounded stack collections with known element layout.",
        ["index-access"]
    ),
    entry!(
        "ir:length",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Static lengths or validated bounded collection length words.",
        ["dynamic-length"]
    ),
    entry!(
        "ir:type-hash",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Schema parameter or verified output Type Script hash.",
        ["type-hash"]
    ),
    entry!(
        "ir:collection-new",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack buffer or verifier-covered create-output vector.",
        ["collection-new"]
    ),
    entry!(
        "ir:collection-capacity",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection; hidden Cell ownership is rejected.",
        ["collection-capacity", "cell-backed-collection-capacity"]
    ),
    entry!(
        "ir:collection-push",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Fixed-width bounded value or verified output-vector construction.",
        ["collection-push", "cell-backed-collection-push"]
    ),
    entry!(
        "ir:collection-extend",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded fixed-width stack collection or verified output vector.",
        ["collection-extend", "cell-backed-collection-extend"]
    ),
    entry!(
        "ir:collection-clear",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection only.",
        ["collection-clear", "cell-backed-collection-clear"]
    ),
    entry!(
        "ir:collection-contains",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with comparable fixed-width elements.",
        ["collection-contains", "cell-backed-collection-contains"]
    ),
    entry!(
        "ir:collection-remove",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with fixed-width elements.",
        ["collection-remove", "cell-backed-collection-remove"]
    ),
    entry!(
        "ir:collection-insert",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with checked capacity and index.",
        ["collection-insert", "cell-backed-collection-insert"]
    ),
    entry!(
        "ir:collection-set",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with checked index.",
        ["collection-set", "cell-backed-collection-set"]
    ),
    entry!(
        "ir:collection-pop",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with fixed-width result.",
        ["collection-pop", "cell-backed-collection-pop"]
    ),
    entry!(
        "ir:collection-reverse",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with fixed-width elements.",
        ["collection-reverse", "cell-backed-collection-reverse"]
    ),
    entry!(
        "ir:collection-truncate",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with checked target length.",
        ["collection-truncate", "cell-backed-collection-truncate"]
    ),
    entry!(
        "ir:collection-swap",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Bounded stack collection with checked indexes.",
        ["collection-swap", "cell-backed-collection-swap"]
    ),
    entry!(
        "ir:bounded-cell-load",
        "instruction",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Exact current Type Script group input scan with runtime cardinality, identity, role, and fixed-width decode checks."
    ),
    entry!(
        "ir:bounded-plan-load",
        "instruction",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Canonical bounded-output-plan-v1 Molecule FixVec decoding with exact length and runtime cardinality checks."
    ),
    entry!(
        "ir:bounded-output-verify",
        "instruction",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Plan-relative GroupOutput data, lock, Type Script role, and declared capacity-floor verification."
    ),
    entry!(
        "ir:bounded-output-end",
        "instruction",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Exact plan-count to current Type Script GroupOutput-count correspondence."
    ),
    entry!("ir:call", "instruction", "bounded", ACCEPT_WHEN_CLOSED, "Resolved typed callable with a closed ABI and effect summary."),
    entry!(
        "artifact:ckb-sighash-all",
        "artifact-policy",
        "reserved",
        "rejected by production policy",
        "Canonical transaction sighash construction is deferred. Audit artifacts unconditionally exit with runtime error 66 when called, including discarded results and helper calls.",
        ["ckb-sighash-all-deferred"]
    ),
    entry!("ir:read-ref", "instruction", "bounded", ACCEPT, "Explicit Input or CellDep read-only Cell view."),
    entry!("ir:move", "instruction", "complete", ACCEPT, "Typed local move; ownership validity is checked before lowering."),
    entry!("ir:tuple", "instruction", "bounded", ACCEPT_WHEN_CLOSED, "Deterministic fixed aggregate construction."),
    entry!(
        "ir:enum-construct",
        "instruction",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "Concrete fixed-width payload enum construction, including pre-IR generic enum monomorphizations."
    ),
    entry!("ir:enum-tag", "instruction", "bounded", ACCEPT_WHEN_CLOSED, "Validated concrete payload enum tag."),
    entry!("ir:enum-payload", "instruction", "bounded", ACCEPT_WHEN_CLOSED, "Fixed-width concrete enum payload field."),
    entry!(
        "ir:consume",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Explicit Cell-backed input consumption.",
        ["consume-expression", "non-cell-consume"]
    ),
    entry!("ir:create", "instruction", "bounded", ACCEPT_WHEN_CLOSED, "Output construction covered by create-set verification."),
    entry!(
        "ir:transfer",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Verifier-covered output construction and lock replacement.",
        ["transfer-expression"]
    ),
    entry!(
        "ir:destroy",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Explicit destructible Cell-backed operand.",
        ["destroy-expression"]
    ),
    entry!(
        "ir:claim",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Verifier-covered receipt claim output.",
        ["claim-expression"]
    ),
    entry!(
        "ir:settle",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Verifier-covered settlement output.",
        ["settle-expression"]
    ),
    entry!(
        "ir:create-unique",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Verifier-covered output plus executable identity policy.",
        ["create-unique-expression"]
    ),
    entry!(
        "ir:replace-unique",
        "instruction",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "Verifier-covered replacement plus executable identity policy.",
        ["replace-unique-expression"]
    ),
    entry!("ir:cell-metadata-equality", "instruction", "complete", ACCEPT, "Lock-hash or capacity equality over validated Cell views."),
    entry!(
        "artifact:create-output-verification",
        "artifact-policy",
        "shape-gated",
        ACCEPT_WHEN_CLOSED,
        "All constructed output fields and output lock must be materializable by the verifier.",
        ["output-verification-incomplete", "output-lock-verification-incomplete"]
    ),
    entry!(
        "artifact:cell-backed-collection-return",
        "artifact-policy",
        "reserved",
        "rejected by production policy",
        "Returning a hidden Cell-backed collection has no linear ownership ABI.",
        ["cell-backed-collection-return"]
    ),
    entry!(
        "artifact:bounded-consume-each-runtime",
        "artifact-policy",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "The bounded-type-group-inputs-v1 fixed-width shape is executable; all other BoundedCellSet sources and element shapes remain fail-closed.",
        ["bounded-consume-each-runtime"]
    ),
    entry!(
        "artifact:bounded-create-each-runtime",
        "artifact-policy",
        "bounded",
        ACCEPT_WHEN_CLOSED,
        "The bounded-output-plan-v1 fixed-width shape is executable when the output has a complete create template, explicit lock, no custom identity, and a declared capacity floor; all other shapes remain fail-closed.",
        ["bounded-create-each-runtime"]
    ),
];

pub fn validate_ir_module(module: &IrModule) -> Result<()> {
    module.validate_entry_selection()?;
    for external in &module.external_type_defs {
        require_registered("ir-item:type-def")?;
        for field in &external.fields {
            validate_ir_type(&field.ty)?;
        }
        if let Some(claim_output) = &external.claim_output {
            validate_ir_type(claim_output)?;
        }
    }
    for item in &module.items {
        require_registered(ir_item_surface_id(item))?;
        match item {
            IrItem::TypeDef(definition) => {
                for field in &definition.fields {
                    validate_ir_type(&field.ty)?;
                }
                if let Some(claim_output) = &definition.claim_output {
                    validate_ir_type(claim_output)?;
                }
            }
            IrItem::Action(action) => {
                validate_params_and_return(&action.params, action.return_type.as_ref())?;
                validate_body(&action.body)?;
            }
            IrItem::PureFn(function) => {
                validate_params_and_return(&function.params, function.return_type.as_ref())?;
                validate_body(&function.body)?;
            }
            IrItem::Lock(lock) => {
                validate_params_and_return(&lock.params, Some(&IrType::Bool))?;
                validate_body(&lock.body)?;
            }
            IrItem::Invariant(_) => {}
        }
    }
    Ok(())
}

pub fn validate_fail_closed_features<'a>(features: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let registered = EXECUTABLE_SURFACE
        .iter()
        .flat_map(|entry| entry.fail_closed_features.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    let unknown = features.into_iter().filter(|feature| !registered.contains(feature)).collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(CompileError::without_span(format!(
            "executable surface reported unregistered fail-closed feature(s): {}",
            unknown.join(", ")
        ))
        .with_code("E2105"))
    }
}

fn validate_params_and_return(params: &[crate::ir::IrParam], return_type: Option<&IrType>) -> Result<()> {
    for param in params {
        validate_ir_type(&param.ty)?;
    }
    if let Some(return_type) = return_type {
        validate_ir_type(return_type)?;
    }
    Ok(())
}

fn validate_body(body: &IrBody) -> Result<()> {
    for block in &body.blocks {
        for instruction in &block.instructions {
            require_registered(ir_instruction_surface_id(instruction))?;
        }
        require_registered(ir_terminator_surface_id(&block.terminator))?;
    }
    Ok(())
}

fn validate_ir_type(ty: &IrType) -> Result<()> {
    require_registered(ir_type_surface_id(ty))?;
    match ty {
        IrType::Array(inner, _) | IrType::Ref(inner) | IrType::MutRef(inner) => validate_ir_type(inner),
        IrType::Tuple(items) => {
            for item in items {
                validate_ir_type(item)?;
            }
            Ok(())
        }
        IrType::U8
        | IrType::U16
        | IrType::U32
        | IrType::I32
        | IrType::U64
        | IrType::U128
        | IrType::Bool
        | IrType::Unit
        | IrType::Address
        | IrType::Hash
        | IrType::Named(_) => Ok(()),
    }
}

fn require_registered(id: &str) -> Result<()> {
    if EXECUTABLE_SURFACE.iter().any(|entry| entry.id == id) {
        Ok(())
    } else {
        Err(CompileError::without_span(format!("IR surface classifier emitted unregistered ID '{id}'")).with_code("E2105"))
    }
}

fn ir_item_surface_id(item: &IrItem) -> &'static str {
    match item {
        IrItem::TypeDef(_) => "ir-item:type-def",
        IrItem::Invariant(_) => "ir-item:invariant",
        IrItem::Action(_) => "ir-item:action",
        IrItem::PureFn(_) => "ir-item:pure-fn",
        IrItem::Lock(_) => "ir-item:lock",
    }
}

fn ir_type_surface_id(ty: &IrType) -> &'static str {
    match ty {
        IrType::U8 => "type:u8",
        IrType::U16 => "type:u16",
        IrType::U32 => "type:u32",
        IrType::I32 => "type:i32",
        IrType::U64 => "type:u64",
        IrType::U128 => "type:u128",
        IrType::Bool => "type:bool",
        IrType::Unit => "type:unit",
        IrType::Address => "type:Address",
        IrType::Hash => "type:Hash",
        IrType::Array(_, _) => "type:Array",
        IrType::Tuple(_) => "type:Tuple",
        IrType::Named(_) => "type:Named",
        IrType::Ref(_) => "type:Ref",
        IrType::MutRef(_) => "type:MutRef",
    }
}

fn ir_instruction_surface_id(instruction: &IrInstruction) -> &'static str {
    match instruction {
        IrInstruction::LoadConst { .. } => "ir:load-const",
        IrInstruction::LoadVar { .. } => "ir:load-var",
        IrInstruction::StoreVar { .. } => "ir:store-var",
        IrInstruction::Binary { .. } => "ir:binary",
        IrInstruction::Unary { .. } => "ir:unary",
        IrInstruction::FieldAccess { .. } => "ir:field-access",
        IrInstruction::Index { .. } => "ir:index",
        IrInstruction::Length { .. } => "ir:length",
        IrInstruction::TypeHash { .. } => "ir:type-hash",
        IrInstruction::CollectionNew { .. } => "ir:collection-new",
        IrInstruction::CollectionCapacity { .. } => "ir:collection-capacity",
        IrInstruction::CollectionPush { .. } => "ir:collection-push",
        IrInstruction::CollectionExtend { .. } => "ir:collection-extend",
        IrInstruction::CollectionClear { .. } => "ir:collection-clear",
        IrInstruction::CollectionContains { .. } => "ir:collection-contains",
        IrInstruction::CollectionRemove { .. } => "ir:collection-remove",
        IrInstruction::CollectionInsert { .. } => "ir:collection-insert",
        IrInstruction::CollectionSet { .. } => "ir:collection-set",
        IrInstruction::CollectionPop { .. } => "ir:collection-pop",
        IrInstruction::CollectionReverse { .. } => "ir:collection-reverse",
        IrInstruction::CollectionTruncate { .. } => "ir:collection-truncate",
        IrInstruction::CollectionSwap { .. } => "ir:collection-swap",
        IrInstruction::BoundedCellLoad { .. } => "ir:bounded-cell-load",
        IrInstruction::BoundedPlanLoad { .. } => "ir:bounded-plan-load",
        IrInstruction::BoundedOutputVerify { .. } => "ir:bounded-output-verify",
        IrInstruction::BoundedOutputEnd { .. } => "ir:bounded-output-end",
        IrInstruction::Call { .. } => "ir:call",
        IrInstruction::ReadRef { .. } => "ir:read-ref",
        IrInstruction::Move { .. } => "ir:move",
        IrInstruction::Tuple { .. } => "ir:tuple",
        IrInstruction::EnumConstruct { .. } => "ir:enum-construct",
        IrInstruction::EnumTag { .. } => "ir:enum-tag",
        IrInstruction::EnumPayload { .. } => "ir:enum-payload",
        IrInstruction::Consume { .. } => "ir:consume",
        IrInstruction::Create { .. } => "ir:create",
        IrInstruction::Transfer { .. } => "ir:transfer",
        IrInstruction::Destroy { .. } => "ir:destroy",
        IrInstruction::Claim { .. } => "ir:claim",
        IrInstruction::Settle { .. } => "ir:settle",
        IrInstruction::CreateUnique { .. } => "ir:create-unique",
        IrInstruction::ReplaceUnique { .. } => "ir:replace-unique",
        IrInstruction::CellMetadataEquality { .. } => "ir:cell-metadata-equality",
    }
}

fn ir_terminator_surface_id(terminator: &IrTerminator) -> &'static str {
    match terminator {
        IrTerminator::Return(_) => "ir-terminator:return",
        IrTerminator::Jump(_) => "ir-terminator:jump",
        IrTerminator::Branch { .. } => "ir-terminator:branch",
    }
}

pub fn executable_surface_json() -> String {
    let value = serde_json::json!({
        "schema": EXECUTABLE_SURFACE_SCHEMA,
        "entries": EXECUTABLE_SURFACE,
    });
    let mut rendered = serde_json::to_string_pretty(&value).expect("static executable surface serializes");
    rendered.push('\n');
    rendered
}

pub fn executable_surface_markdown() -> String {
    let mut rendered = String::from(
        "# CellScript Executable Surface Matrix\n\n\
**Status**: generated from the compiler-owned 0.26 executable-surface registry\n\n\
This file is generated. Run `cellscript-tools check-executable-surface --write` after changing the registry.\n\n\
Production compilation means `--production` or `--deny-fail-closed`; both stop before codegen when a selected shape reports any listed fail-closed feature. Metadata-only compilation remains available for diagnostics and Playground inspection.\n\n\
| ID | Layer | Status | Production policy | Conditions | Fail-closed features |\n\
|---|---|---|---|---|---|\n",
    );
    for entry in EXECUTABLE_SURFACE {
        let features = if entry.fail_closed_features.is_empty() { "none".to_string() } else { entry.fail_closed_features.join(", ") };
        rendered.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | `{}` |\n",
            entry.id, entry.layer, entry.status, entry.production_policy, entry.conditions, features
        ));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::{validate_fail_closed_features, EXECUTABLE_SURFACE};
    use std::collections::BTreeSet;

    #[test]
    fn registry_ids_and_fail_closed_features_are_stable_and_unique() {
        let mut ids = BTreeSet::new();
        let mut features = BTreeSet::new();
        for entry in EXECUTABLE_SURFACE {
            assert!(ids.insert(entry.id), "duplicate executable-surface ID: {}", entry.id);
            for feature in entry.fail_closed_features {
                assert!(features.insert(*feature), "fail-closed feature appears under multiple surface entries: {feature}");
                assert!(
                    feature.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-'),
                    "fail-closed feature must be lowercase kebab-case: {feature}"
                );
            }
        }
    }

    #[test]
    fn unregistered_fail_closed_features_are_rejected_even_before_policy_selection() {
        let error = validate_fail_closed_features(["new-unclassified-runtime-shape"]).unwrap_err();
        assert_eq!(error.code.as_deref(), Some("E2105"));
        assert!(error.message.contains("unregistered"));
    }
}
