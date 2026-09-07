//! Covenant ProofPlan metadata for CKB trigger/scope/coverage auditing.

pub mod soundness;

use crate::aggregate_lowering::{
    aggregate_group_amount_endpoint, fungible_type_group_v1_conservation_type, xudt_group_amount_conservation_type,
    FUNGIBLE_TYPE_GROUP_V1_METADATA_HELPER, XUDT_GROUP_AMOUNT_CONSERVED_METADATA_HELPER,
};
use crate::ast::{AggregateInvariantKind, AggregateRelation, AggregateTarget, BoundedQuantifierKind, ParamSource, SourceView};
use crate::ir::{self, IrInstruction};
use crate::{CkbRuntimeAccessMetadata, PoolPrimitiveMetadata, VerifierObligationMetadata};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanSourceSpanMetadata {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanDiagnosticMetadata {
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceTier {
    CheckedStatic,
    CheckedRuntime,
    TrustedExternal,
    RuntimeHelperRequired,
    BuilderEvidenceRequired,
    #[default]
    MetadataOnly,
    ChainEvidenceRequired,
}

impl EvidenceTier {
    pub const ALL: [Self; 7] = [
        Self::CheckedStatic,
        Self::CheckedRuntime,
        Self::TrustedExternal,
        Self::RuntimeHelperRequired,
        Self::BuilderEvidenceRequired,
        Self::MetadataOnly,
        Self::ChainEvidenceRequired,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheckedStatic => "checked-static",
            Self::CheckedRuntime => "checked-runtime",
            Self::TrustedExternal => "trusted-external",
            Self::RuntimeHelperRequired => "runtime-helper-required",
            Self::BuilderEvidenceRequired => "builder-evidence-required",
            Self::MetadataOnly => "metadata-only",
            Self::ChainEvidenceRequired => "chain-evidence-required",
        }
    }

    pub const fn is_checked(self) -> bool {
        matches!(self, Self::CheckedStatic | Self::CheckedRuntime | Self::TrustedExternal)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanMetadata {
    pub name: String,
    pub origin: String,
    pub category: String,
    pub feature: String,
    #[serde(default)]
    pub evidence_tier: EvidenceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<ProofPlanSourceSpanMetadata>,
    pub trigger: String,
    pub scope: String,
    pub reads: Vec<String>,
    pub coverage: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_output_relation_checks: Vec<String>,
    pub group_cardinality: String,
    pub identity_lifecycle_policy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_args_fields: Vec<String>,
    pub on_chain_checked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub on_chain_checked_obligations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builder_assumptions: Vec<String>,
    pub codegen_coverage_status: String,
    pub status: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<ProofPlanDiagnosticMetadata>,
}

pub fn build_for_body(
    scope_kind: &str,
    name: &str,
    body: &ir::IrBody,
    params: &[ir::IrParam],
    obligations: &[VerifierObligationMetadata],
    runtime_accesses: &[CkbRuntimeAccessMetadata],
    pool_primitives: &[PoolPrimitiveMetadata],
) -> Vec<ProofPlanMetadata> {
    let origin = format!("{}:{}", scope_kind, name);
    let body_reads = body_reads(body, params, runtime_accesses);
    let body_coverage = body_coverage(scope_kind, name, body);
    let preserved_fields = preserved_fields(body);
    let witness_fields = witness_fields(params, runtime_accesses);
    let lock_args_fields = lock_args_fields(params, runtime_accesses);
    let mut plans = Vec::new();
    let mut seen = BTreeSet::new();

    for obligation in obligations {
        let key = (obligation.scope.clone(), obligation.category.clone(), obligation.feature.clone(), obligation.status.clone());
        if seen.insert(key) {
            plans.push(plan_from_obligation(
                scope_kind,
                &origin,
                obligation,
                &body_reads,
                &body_coverage,
                &preserved_fields,
                &witness_fields,
                &lock_args_fields,
                pool_primitives,
            ));
        }
    }

    for primitive in pool_primitives {
        let key = (primitive.scope.clone(), "pool-primitive".to_string(), primitive.feature.clone(), primitive.status.clone());
        if seen.insert(key) {
            let obligation = VerifierObligationMetadata {
                scope: primitive.scope.clone(),
                category: "pool-primitive".to_string(),
                feature: primitive.feature.clone(),
                status: primitive.status.clone(),
                detail: format!(
                    "Pool primitive {}:{} checked components [{}]; runtime-required components [{}]",
                    primitive.operation,
                    primitive.ty,
                    primitive.checked_components.join(", "),
                    primitive.runtime_required_components.join(", ")
                ),
            };
            plans.push(plan_from_obligation(
                scope_kind,
                &origin,
                &obligation,
                &body_reads,
                &body_coverage,
                &preserved_fields,
                &witness_fields,
                &lock_args_fields,
                pool_primitives,
            ));
        }
    }

    plans.extend(
        body.bounded_collection_ops
            .iter()
            .enumerate()
            .map(|(index, operation)| plan_for_bounded_collection(scope_kind, name, index, operation)),
    );
    plans
        .extend(body.borrow_regions.iter().enumerate().map(|(index, region)| plan_for_borrow_region(scope_kind, name, index, region)));
    plans.extend(exact_script_handle_plans(scope_kind, name, body));

    plans
}

fn exact_script_handle_plans(scope_kind: &str, scope_name: &str, body: &ir::IrBody) -> Vec<ProofPlanMetadata> {
    let mut plans = Vec::new();
    for (block_index, block) in body.blocks.iter().enumerate() {
        for (operation_index, instruction) in block.instructions.iter().enumerate() {
            let IrInstruction::Call { func, args, .. } = instruction else {
                continue;
            };
            let (role, identity) = match func.as_str() {
                "__ckb_require_cell_lock_exact_handle" => ("lock", "complete-script-hash"),
                "__ckb_require_cell_type_exact_handle" => ("type", "complete-script-hash"),
                "__ckb_require_cell_dep_exact_verifier_handle" => ("spawned-verifier", "cell-dep-data-hash"),
                _ => continue,
            };
            let handle_hash = match args.get(2) {
                Some(ir::IrOperand::Const(ir::IrConst::Hash(hash))) => hex::encode(hash),
                _ => "invalid-non-constant-handle-hash".to_string(),
            };
            let feature = format!("{role}:{handle_hash}");
            plans.push(ProofPlanMetadata {
                name: format!("{}#exact-script-handle-{}-{}", scope_name, block_index, operation_index),
                origin: format!("{}:{}#exact-script-handle:{}:{}", scope_kind, scope_name, block_index, operation_index),
                category: "exact-script-handle".to_string(),
                feature: feature.clone(),
                evidence_tier: EvidenceTier::CheckedRuntime,
                source_span: None,
                trigger: trigger_for_scope_kind(scope_kind).to_string(),
                scope: "selected-ckb-source-view".to_string(),
                reads: vec![
                    "source-view".to_string(),
                    "witness".to_string(),
                    "ExactScriptHandle".to_string(),
                    "handle-hash-literal".to_string(),
                ],
                coverage: vec![
                    "encoding:CSHDLv1-fixed-202".to_string(),
                    "magic:CSHDLv1\\0".to_string(),
                    format!("class-and-role:{role}"),
                    format!("handle-hash:{handle_hash}"),
                    "receipt-commitment:bound-by-full-handle-hash".to_string(),
                    format!("identity:{identity}"),
                ],
                input_output_relation_checks: Vec::new(),
                group_cardinality: "one-selected-source-view".to_string(),
                identity_lifecycle_policy: "read-only exact artifact identity check; grants no Cell lifecycle authority".to_string(),
                preserved_fields: Vec::new(),
                witness_fields: vec!["ExactScriptHandle".to_string()],
                lock_args_fields: Vec::new(),
                on_chain_checked: true,
                on_chain_checked_obligations: vec![
                    format!("exact-script-handle:{feature}=checked-runtime"),
                    "the complete fixed-width handle, class, role, receipt commitment, and selected CKB identity are checked"
                        .to_string(),
                ],
                builder_assumptions: Vec::new(),
                codegen_coverage_status: "covered".to_string(),
                status: "checked-runtime".to_string(),
                detail: format!(
                    "{func} binds the selected CKB value to an exact {role} handle committed by full handle hash 0x{handle_hash}"
                ),
                diagnostics: vec![ProofPlanDiagnosticMetadata {
                    severity: "info".to_string(),
                    message:
                        "exact handles are non-linear fixed values; the runtime check does not authorize Cell consumption or creation"
                            .to_string(),
                }],
            });
        }
    }
    plans
}

fn plan_for_borrow_region(scope_kind: &str, scope_name: &str, index: usize, region: &ir::IrBorrowRegion) -> ProofPlanMetadata {
    let feature = format!("View<{}>:{}->{}", region.root_type, region.root, region.binding);
    ProofPlanMetadata {
        name: format!("{}#borrow-region{}", scope_name, index),
        origin: format!("{}:{}#borrow-region:{}", scope_kind, scope_name, index),
        category: "borrow-region".to_string(),
        feature: feature.clone(),
        evidence_tier: EvidenceTier::CheckedStatic,
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: region.span.start,
            end: region.span.end,
            line: region.span.line,
            column: region.span.column,
        }),
        trigger: trigger_for_scope_kind(scope_kind).to_string(),
        scope: "lexical-block-with-flow-sensitive-checks".to_string(),
        reads: vec![region.root.clone()],
        coverage: vec![
            format!("root:{}:{}", region.root, region.root_type),
            format!("view:{}", region.binding),
            "storage:none".to_string(),
            "abi:none".to_string(),
            "allowed-effects:Pure,ReadOnly".to_string(),
            "lifecycle-crossing:rejected".to_string(),
            "escape:return,aggregate,assignment,generic-call-rejected".to_string(),
        ],
        input_output_relation_checks: Vec::new(),
        group_cardinality: "single-linear-root".to_string(),
        identity_lifecycle_policy: "borrow preserves root Cell identity and cannot consume, destroy, transfer, claim, or settle it"
            .to_string(),
        preserved_fields: Vec::new(),
        witness_fields: Vec::new(),
        lock_args_fields: Vec::new(),
        on_chain_checked: true,
        on_chain_checked_obligations: vec![
            format!("borrow-region:{}=checked-static", feature),
            "compiler rejects borrow escape, lifecycle crossing, and effect-incompatible calls before codegen".to_string(),
        ],
        builder_assumptions: Vec::new(),
        codegen_coverage_status: "covered".to_string(),
        status: "checked-static".to_string(),
        detail: format!(
            "borrowed view '{}' of linear root '{}' is erased after static region, escape, lifecycle, and callee-effect checks",
            region.binding, region.root
        ),
        diagnostics: vec![ProofPlanDiagnosticMetadata {
            severity: "info".to_string(),
            message: "borrow region is a compiler marker and emits no serializable value or callable ABI slot".to_string(),
        }],
    }
}

fn plan_for_bounded_collection(
    scope_kind: &str,
    scope_name: &str,
    index: usize,
    operation: &ir::IrBoundedCollectionOp,
) -> ProofPlanMetadata {
    let source = match operation.source {
        ParamSource::Default => "default",
        ParamSource::Input => "input",
        ParamSource::Output => "output",
        ParamSource::Protected => "protected",
        ParamSource::Witness => "witness",
        ParamSource::LockArgs => "lock_args",
    };
    let is_create = operation.operation == "create_each";
    let runtime_checked = operation.runtime_contract.is_some();
    let helper = operation.runtime_contract.as_deref().unwrap_or(if is_create {
        "__cellscript_bounded_create_each"
    } else {
        "__cellscript_bounded_consume_each"
    });
    let evidence_tier = if runtime_checked {
        EvidenceTier::CheckedRuntime
    } else if is_create {
        EvidenceTier::BuilderEvidenceRequired
    } else {
        EvidenceTier::RuntimeHelperRequired
    };
    let status = if runtime_checked {
        "checked-runtime"
    } else if is_create {
        "builder-evidence-required"
    } else {
        "runtime-required"
    };
    let codegen_coverage_status = if runtime_checked {
        "covered"
    } else if is_create {
        "gap:builder-evidence-required"
    } else {
        "gap:runtime-helper-required"
    };
    let mut reads = vec![source.to_string()];
    if runtime_checked {
        reads.extend([if is_create { "group_output" } else { "group_input" }.to_string(), "current_script".to_string()]);
    }
    if is_create && source == "witness" {
        reads.push("witness".to_string());
    }
    dedup(&mut reads);
    let mut coverage = vec![
        format!("operation:{}", operation.operation),
        format!("collection:{}", operation.collection_type),
        format!("element:{}", operation.element_type),
        format!("source:{source}"),
        format!("maximum_cardinality:{}", operation.max_elements),
        if runtime_checked {
            "actual_scanned_cardinality:runtime-observed".to_string()
        } else {
            "actual_scanned_cardinality:not-observed-no-runtime-lowering".to_string()
        },
        "vacuous:true-when-cardinality-zero".to_string(),
        format!("runtime_helper:{helper}"),
    ];
    coverage.extend(operation.predicates.iter().map(|predicate| {
        if runtime_checked {
            format!("predicate-executed-once-per-element:{predicate}")
        } else {
            format!("predicate-retained-not-executed:{predicate}")
        }
    }));
    coverage.extend(operation.accumulator_updates.iter().map(|update| {
        if runtime_checked {
            format!("outer-numeric-accumulator-updated-once-per-element:{update}")
        } else {
            format!("outer-numeric-accumulator-retained-not-executed:{update}")
        }
    }));
    if runtime_checked && is_create {
        coverage.extend([
            "witness_codec:CSBPLv1-Molecule-FixVec".to_string(),
            "source_selection:exact-current-type-group-outputs".to_string(),
            "script_role:type-only".to_string(),
            "script_identity:current-script-hash".to_string(),
            "output_correspondence:plan-index-equals-group-output-index".to_string(),
            "output_decode:fixed-width-exact-size".to_string(),
            "lock_policy:exact-create-template-lock-hash".to_string(),
            "capacity_policy:declared-type-floor-checked-on-chain".to_string(),
            format!("plan_element_width_bytes:{}", operation.element_width.unwrap_or_default()),
        ]);
    } else if runtime_checked {
        coverage.extend([
            "source_selection:exact-current-type-group-inputs".to_string(),
            "script_role:type-only".to_string(),
            "script_identity:current-script-hash".to_string(),
            "element_decode:fixed-width-exact-size".to_string(),
            "lifecycle:every-selected-input-discharged".to_string(),
            format!("element_width_bytes:{}", operation.element_width.unwrap_or_default()),
        ]);
    }
    let mut builder_assumptions =
        if runtime_checked { Vec::new() } else { vec![format!("declared(runtime-helper-required:{helper})")] };
    if is_create {
        coverage.extend([
            format!("output_cardinality_max:{}", operation.max_elements),
            format!("capacity_builder_evidence_required:{}", !runtime_checked),
            format!("output_type:{}", operation.output_type.as_deref().unwrap_or("unknown")),
        ]);
        if !runtime_checked {
            builder_assumptions.extend([
                "declared(builder must provide exactly one output per plan element)".to_string(),
                "declared(builder must prove aggregate output capacity and occupied-capacity floors)".to_string(),
            ]);
        }
        if let Some(template) = &operation.create_template {
            coverage.push(format!("create_template_output_type:{}", template.output_type));
            coverage.extend(template.fields.iter().map(|(field, value)| format!("create_template_field:{field}={value}")));
            coverage.push(format!("create_template_lock:{}", template.lock.as_deref().unwrap_or("not-specified")));
        }
    }
    let feature = format!("{}:{}:{}", operation.operation, operation.collection_binding, operation.collection_type);
    let on_chain_checked_obligations = if runtime_checked {
        let mut obligations = vec![
            format!("bounded-cell-collection:{feature}={status}"),
            "type-only Script role".to_string(),
            "current Script hash identity".to_string(),
            "runtime cardinality bound".to_string(),
            "exact fixed-width decode".to_string(),
            "exactly-once predicate coverage".to_string(),
        ];
        if is_create {
            obligations.extend([
                "canonical witness plan codec".to_string(),
                "one plan element per GroupOutput".to_string(),
                "exact output lock hash".to_string(),
                "declared output capacity floor".to_string(),
            ]);
        }
        obligations
    } else {
        Vec::new()
    };
    ProofPlanMetadata {
        name: format!("{}#bounded-collection{}", scope_name, index),
        origin: format!("{}:{}#bounded-collection:{}", scope_kind, scope_name, index),
        category: "bounded-cell-collection".to_string(),
        feature,
        evidence_tier,
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: operation.span.start,
            end: operation.span.end,
            line: operation.span.line,
            column: operation.span.column,
        }),
        trigger: trigger_for_scope_kind(scope_kind).to_string(),
        scope: if is_create { "transaction".to_string() } else { "selected_cells".to_string() },
        reads: reads.clone(),
        coverage,
        input_output_relation_checks: if runtime_checked {
            vec![if is_create {
                format!("plan_count=group_output_count<={}", operation.max_elements)
            } else {
                format!("group_input_count<={}", operation.max_elements)
            }]
        } else {
            Vec::new()
        },
        group_cardinality: if runtime_checked {
            format!("runtime-observed:0..={}", operation.max_elements)
        } else {
            format!("declared-maximum:0..={}; actual:not-observed-no-runtime-lowering", operation.max_elements)
        },
        identity_lifecycle_policy: if is_create && runtime_checked {
            "checked on chain: each canonical plan element binds exactly one current-Type-Script GroupOutput at the same relative index, with exact data and lock policy"
                .to_string()
        } else if is_create {
            "required but not enforced: define fresh-output identity, output ordering, and one-output-per-plan correspondence"
                .to_string()
        } else if runtime_checked {
            "checked on chain: exact current Type Script group inputs are decoded once, predicates execute once, and every selected input is linearly discharged"
                .to_string()
        } else {
            "checked statically only: the collection binding is linearly discharged; runtime Cell selection and per-element consumption are not emitted"
                .to_string()
        },
        preserved_fields: Vec::new(),
        witness_fields: if source == "witness" { vec![format!("witness.{}", operation.collection_binding)] } else { Vec::new() },
        lock_args_fields: Vec::new(),
        on_chain_checked: runtime_checked,
        on_chain_checked_obligations,
        builder_assumptions,
        codegen_coverage_status: codegen_coverage_status.to_string(),
        status: status.to_string(),
        detail: if runtime_checked && is_create {
            format!(
                "bounded create_each over '{}' is lowered by the '{}' consensus runtime contract",
                operation.collection_binding, helper
            )
        } else if runtime_checked {
            format!(
                "bounded consume_each over '{}' is lowered by the '{}' consensus runtime contract",
                operation.collection_binding, helper
            )
        } else if is_create {
            format!(
                "bounded create_each over witness plan '{}' requires runtime iteration plus output-count and capacity builder evidence",
                operation.collection_binding
            )
        } else {
            format!(
                "bounded consume_each over input Cell set '{}' requires emitted source iteration coverage",
                operation.collection_binding
            )
        },
        diagnostics: vec![ProofPlanDiagnosticMetadata {
            severity: if runtime_checked { "info" } else { "warning" }.to_string(),
            message: if runtime_checked && is_create {
                "bounded create_each is enforced by the versioned Molecule plan codec, exact GroupOutput correspondence, output data/lock checks, and the declared capacity floor"
                    .to_string()
            } else if runtime_checked {
                "bounded consume_each is enforced by exact Type Script group selection, runtime count, exact decode, and per-element predicate machine blocks"
                    .to_string()
            } else if is_create {
                "bounded create_each is non-deployable until a canonical witness codec, output correspondence/order, identity, capacity, and runtime predicate contract are implemented"
                    .to_string()
            } else {
                format!(
                    "bounded consume_each is non-deployable: {helper} is only a planned helper name; source selection, decoding, cardinality, and per-element predicate execution are not emitted"
                )
            },
        }],
    }
}

pub fn build_for_invariant(invariant: &ir::IrInvariant, runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<ProofPlanMetadata> {
    let mut plans = vec![summary_plan_for_invariant(invariant, runtime_accesses)];
    plans.extend(
        invariant
            .aggregates
            .iter()
            .enumerate()
            .map(|(index, aggregate)| plan_for_aggregate_invariant(invariant, index, aggregate, runtime_accesses)),
    );
    plans.extend(
        invariant.quantifiers.iter().enumerate().map(|(index, quantifier)| plan_for_bounded_quantifier(invariant, index, quantifier)),
    );
    plans
}

pub fn build_for_type_validity(
    type_def: &ir::IrTypeDef,
    create_paths_selected: usize,
    create_paths_checked: usize,
    update_paths_selected: usize,
) -> Vec<ProofPlanMetadata> {
    let mut plans = Vec::new();
    for (index, predicate) in type_def.validity_predicates.iter().enumerate() {
        let feature = format!("{}#{}:{}", type_def.name, index, predicate.rendered);
        let all_create_paths_checked = create_paths_selected > 0 && create_paths_checked == create_paths_selected;
        let (evidence_tier, status, codegen_coverage_status, on_chain_checked, create_status) = match predicate.evidence {
            ir::IrValidityEvidence::CheckedStatic => {
                (EvidenceTier::CheckedStatic, "checked-static", "covered", true, "checked-static")
            }
            ir::IrValidityEvidence::CheckedRuntime if all_create_paths_checked => {
                (EvidenceTier::CheckedRuntime, "checked-runtime", "covered", true, "checked-runtime")
            }
            ir::IrValidityEvidence::CheckedRuntime if create_paths_selected == 0 => (
                EvidenceTier::RuntimeHelperRequired,
                "runtime-required",
                "gap:runtime-helper-required",
                false,
                "not-selected-runtime-helper-required",
            ),
            ir::IrValidityEvidence::CheckedRuntime if create_paths_checked == 0 => (
                EvidenceTier::RuntimeHelperRequired,
                "runtime-required",
                "gap:runtime-helper-required",
                false,
                "selected-runtime-helper-required",
            ),
            ir::IrValidityEvidence::CheckedRuntime => (
                EvidenceTier::RuntimeHelperRequired,
                "runtime-required",
                "gap:runtime-helper-required",
                false,
                "partial-runtime-helper-required",
            ),
            ir::IrValidityEvidence::BuilderEvidenceRequired => (
                EvidenceTier::BuilderEvidenceRequired,
                "builder-evidence-required",
                "gap:builder-evidence-required",
                false,
                "builder-header-evidence-required",
            ),
        };
        let mut reads = Vec::new();
        if predicate.dependencies.iter().any(|dependency| dependency.starts_with("field:")) {
            reads.push("output".to_string());
        }
        if predicate.dependencies.iter().any(|dependency| dependency.starts_with("environment:")) {
            reads.push("header_dep".to_string());
        }
        dedup(&mut reads);
        let mut coverage = vec![
            format!("predicate:{}", predicate.rendered),
            format!("create_path:{create_status}"),
            format!("create_paths_selected:{create_paths_selected}"),
            format!(
                "create_paths_checked:{}",
                if predicate.evidence == ir::IrValidityEvidence::BuilderEvidenceRequired { 0 } else { create_paths_checked }
            ),
            format!("runtime_checked_on_create:{}", predicate.runtime_checked_on_create && all_create_paths_checked),
        ];
        coverage.extend(predicate.dependencies.iter().map(|dependency| format!("dependency:{dependency}")));
        let mut builder_assumptions = Vec::new();
        if predicate.evidence == ir::IrValidityEvidence::BuilderEvidenceRequired {
            builder_assumptions.extend([
                "declared(builder-evidence-required:header-dep-block-number-evidence)".to_string(),
                "declared(env::block_number is not a CKB-VM ambient tip-height syscall)".to_string(),
            ]);
        } else if predicate.evidence == ir::IrValidityEvidence::CheckedRuntime && !all_create_paths_checked {
            builder_assumptions.push(format!(
                "declared(runtime-helper-required:create paths checked {create_paths_checked}/{create_paths_selected})"
            ));
        }
        let category = "type-validity".to_string();
        let on_chain_checked_obligations = if on_chain_checked { vec![format!("{category}:{feature}={status}")] } else { Vec::new() };
        plans.push(ProofPlanMetadata {
            name: format!("{}#validity{}", type_def.name, index),
            origin: format!("validity:{}#predicate:{}", type_def.name, index),
            category,
            feature,
            evidence_tier,
            source_span: Some(ProofPlanSourceSpanMetadata {
                start: predicate.span.start,
                end: predicate.span.end,
                line: predicate.span.line,
                column: predicate.span.column,
            }),
            trigger: "type_script_output_validation".to_string(),
            scope: "selected_cells".to_string(),
            reads: reads.clone(),
            coverage,
            input_output_relation_checks: vec![format!("valid({})={create_status}", type_def.name)],
            group_cardinality: "each-created-output-of-declared-type".to_string(),
            identity_lifecycle_policy: "predicate observes proposed field values; it grants no consume/create authority".to_string(),
            preserved_fields: Vec::new(),
            witness_fields: Vec::new(),
            lock_args_fields: Vec::new(),
            on_chain_checked,
            on_chain_checked_obligations,
            builder_assumptions,
            codegen_coverage_status: codegen_coverage_status.to_string(),
            status: status.to_string(),
            detail: format!("type validity predicate for '{}' create path", type_def.name),
            diagnostics: vec![ProofPlanDiagnosticMetadata {
                severity: if on_chain_checked { "info".to_string() } else { "warning".to_string() },
                message: if predicate.evidence == ir::IrValidityEvidence::BuilderEvidenceRequired {
                    "env::block_number requires explicit builder/header evidence and is not emitted as an ambient CKB-VM syscall"
                        .to_string()
                } else if on_chain_checked {
                    "validity predicate is discharged before every selected output create instruction".to_string()
                } else if create_paths_selected == 0 {
                    "validity predicate has no selected create path in this module and remains a runtime-helper obligation"
                        .to_string()
                } else {
                    format!(
                        "validity predicate is checked on {create_paths_checked}/{create_paths_selected} selected create paths and remains a runtime-helper obligation"
                    )
                },
            }],
        });

        if predicate.evidence == ir::IrValidityEvidence::CheckedRuntime && update_paths_selected > 0 {
            plans.push(ProofPlanMetadata {
                name: format!("{}#validity{}#update", type_def.name, index),
                origin: format!("validity:{}#predicate:{}#update", type_def.name, index),
                category: "type-validity-update-path".to_string(),
                feature: format!("{}#{}:update", type_def.name, index),
                evidence_tier: EvidenceTier::RuntimeHelperRequired,
                source_span: Some(ProofPlanSourceSpanMetadata {
                    start: predicate.span.start,
                    end: predicate.span.end,
                    line: predicate.span.line,
                    column: predicate.span.column,
                }),
                trigger: "type_script_output_validation".to_string(),
                scope: "selected_cells".to_string(),
                reads: vec!["input".to_string(), "output".to_string()],
                coverage: vec![
                    format!("predicate:{}", predicate.rendered),
                    format!("update_paths_selected:{update_paths_selected}"),
                    "update_path:runtime-helper-required".to_string(),
                ],
                input_output_relation_checks: vec![format!("valid({})_after_update=runtime-helper-required", type_def.name)],
                group_cardinality: "each-mutated-output-of-declared-type".to_string(),
                identity_lifecycle_policy: "update must preserve Cell identity while validating final output fields".to_string(),
                preserved_fields: Vec::new(),
                witness_fields: Vec::new(),
                lock_args_fields: Vec::new(),
                on_chain_checked: false,
                on_chain_checked_obligations: Vec::new(),
                builder_assumptions: vec!["declared(runtime-helper-required:final mutated output validity check)".to_string()],
                codegen_coverage_status: "gap:runtime-helper-required".to_string(),
                status: "runtime-required".to_string(),
                detail: format!(
                    "type validity predicate for '{}' has a selected mutate path without final-field lowering",
                    type_def.name
                ),
                diagnostics: vec![ProofPlanDiagnosticMetadata {
                    severity: "warning".to_string(),
                    message: "selected mutate path records a fail-closed validity gap until final-field output checking is emitted"
                        .to_string(),
                }],
            });
        }
    }
    plans
}

fn summary_plan_for_invariant(invariant: &ir::IrInvariant, runtime_accesses: &[CkbRuntimeAccessMetadata]) -> ProofPlanMetadata {
    let trigger = invariant.trigger.clone().unwrap_or_else(|| "explicit_entry".to_string());
    let scope = invariant.scope.clone().unwrap_or_else(|| "selected_cells".to_string());
    let mut coverage = vec![format!("declared_invariant_assertions:{}", invariant.assert_count)];
    coverage.extend(invariant.aggregates.iter().map(aggregate_coverage_label));
    coverage.extend(invariant.quantifiers.iter().map(bounded_quantifier_coverage_label));
    let aggregate_evidence = invariant
        .aggregates
        .iter()
        .map(|aggregate| aggregate_lowering_evidence(invariant, aggregate, runtime_accesses))
        .collect::<Vec<_>>();
    for evidence in &aggregate_evidence {
        if let Some(helper) = evidence.helper() {
            coverage.push(format!("runtime_helper:{helper}"));
        }
        if let AggregateLoweringEvidence::RuntimeHelperChecked(helper) = evidence {
            coverage.push(format!("runtime_helper_checked:{helper}"));
        }
    }
    coverage.extend(coverage_notes(&trigger, &scope));
    dedup(&mut coverage);

    let mut reads = invariant.reads.iter().map(ToString::to_string).collect::<Vec<_>>();
    for aggregate in &invariant.aggregates {
        reads.extend(aggregate_reads(aggregate));
    }
    for quantifier in &invariant.quantifiers {
        reads.extend(reads_from_aggregate_target(&quantifier.range));
    }
    dedup(&mut reads);

    let mut input_output_relation_checks = invariant
        .aggregates
        .iter()
        .zip(aggregate_evidence.iter().copied())
        .map(|(aggregate, evidence)| aggregate_relation_check_label(aggregate, evidence))
        .collect::<Vec<_>>();
    dedup(&mut input_output_relation_checks);

    let all_aggregates_runtime_helper_backed =
        !aggregate_evidence.is_empty() && aggregate_evidence.iter().all(AggregateLoweringEvidence::is_runtime_helper_backed);
    let all_aggregates_runtime_helper_checked =
        !aggregate_evidence.is_empty() && aggregate_evidence.iter().all(AggregateLoweringEvidence::is_checked);
    let has_helper_backed_feature = !invariant.aggregates.is_empty() || !invariant.quantifiers.is_empty();
    let all_non_assert_features_helper_backed = invariant.assert_count == 0
        && has_helper_backed_feature
        && (invariant.aggregates.is_empty() || all_aggregates_runtime_helper_backed);
    let executable_by_runtime_helper =
        all_aggregates_runtime_helper_checked && invariant.quantifiers.is_empty() && invariant.assert_count == 0;
    let runtime_helper_required = all_non_assert_features_helper_backed && !executable_by_runtime_helper;
    let mut builder_assumptions = if executable_by_runtime_helper {
        let mut assumptions = aggregate_evidence
            .iter()
            .filter_map(AggregateLoweringEvidence::helper)
            .map(|helper| format!("declared(runtime-helper-checked:{helper})"))
            .collect::<Vec<_>>();
        assumptions.push(format!("declared(assert_invariant_count:{})", invariant.assert_count));
        assumptions
    } else if runtime_helper_required {
        let mut assumptions = invariant
            .aggregates
            .iter()
            .flat_map(|aggregate| aggregate_group_amount_runtime_helpers(invariant, aggregate))
            .map(|helper| format!("declared(runtime-helper-required:{helper})"))
            .collect::<Vec<_>>();
        assumptions.extend(invariant.quantifiers.iter().map(|quantifier| {
            format!(
                "declared(runtime-helper-required:{})",
                if quantifier.kind == BoundedQuantifierKind::ForAll {
                    "__cellscript_bounded_forall"
                } else {
                    "__cellscript_bounded_count"
                }
            )
        }));
        assumptions.push(format!("declared(assert_invariant_count:{})", invariant.assert_count));
        assumptions.push(format!("declared(bounded_quantifier_count:{})", invariant.quantifiers.len()));
        assumptions
    } else {
        vec![
            "declared(metadata-only invariant not yet lowered to executable verifier code)".to_string(),
            format!("declared(assert_invariant_count:{})", invariant.assert_count),
        ]
    };
    if !invariant.aggregates.is_empty() {
        builder_assumptions.push(format!("declared(aggregate_invariant_count:{})", invariant.aggregates.len()));
    }
    if !invariant.quantifiers.is_empty() {
        builder_assumptions.push(format!("declared(bounded_quantifier_count:{})", invariant.quantifiers.len()));
    }
    if trigger == "lock_group" && scope == "transaction" {
        builder_assumptions.push(
            "declared(lock transaction scan only protects the lock group unless the builder constrains every relevant cell)"
                .to_string(),
        );
    }
    dedup(&mut builder_assumptions);

    let mut diagnostics = if executable_by_runtime_helper {
        vec![ProofPlanDiagnosticMetadata {
            severity: "info".to_string(),
            message: "declared xUDT group amount invariant is discharged by matching generated runtime helper coverage".to_string(),
        }]
    } else if runtime_helper_required {
        vec![ProofPlanDiagnosticMetadata {
            severity: "info".to_string(),
            message: "declared invariant has a known runtime-helper contract; selected entries must emit matching coverage before claiming checked-runtime evidence"
                .to_string(),
        }]
    } else {
        vec![ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message: "declared invariant is metadata-only until executable lowering covers it".to_string(),
        }]
    };
    if trigger == "lock_group" && scope == "transaction" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message:
                "transaction scans from a lock do not imply type-group conservation; only inputs sharing the lock trigger this verifier"
                    .to_string(),
        });
    }

    let status = if executable_by_runtime_helper { "checked-runtime" } else { "runtime-required" };
    let evidence_tier = if executable_by_runtime_helper {
        EvidenceTier::CheckedRuntime
    } else if runtime_helper_required {
        EvidenceTier::RuntimeHelperRequired
    } else {
        EvidenceTier::MetadataOnly
    };
    let on_chain_checked_obligations =
        if executable_by_runtime_helper { vec![format!("declared-invariant:{}={status}", invariant.name)] } else { Vec::new() };

    ProofPlanMetadata {
        name: invariant.name.clone(),
        origin: format!("invariant:{}", invariant.name),
        category: "declared-invariant".to_string(),
        feature: invariant.name.clone(),
        evidence_tier,
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: invariant.span.start,
            end: invariant.span.end,
            line: invariant.span.line,
            column: invariant.span.column,
        }),
        trigger,
        scope,
        reads: reads.clone(),
        coverage,
        input_output_relation_checks,
        group_cardinality: declared_group_cardinality(invariant).to_string(),
        identity_lifecycle_policy: declared_identity_lifecycle_policy(invariant).to_string(),
        preserved_fields: Vec::new(),
        witness_fields: declared_witness_fields(&reads),
        lock_args_fields: declared_lock_args_fields(&reads),
        on_chain_checked: executable_by_runtime_helper,
        on_chain_checked_obligations,
        builder_assumptions,
        codegen_coverage_status: if executable_by_runtime_helper {
            "covered".to_string()
        } else if runtime_helper_required {
            "gap:runtime-helper-required".to_string()
        } else {
            "gap:metadata-only".to_string()
        },
        status: status.to_string(),
        detail: format!(
            "explicit source invariant declaration captured for ProofPlan auditing; aggregate_primitives={}; bounded_quantifiers={}",
            invariant.aggregates.len(),
            invariant.quantifiers.len()
        ),
        diagnostics,
    }
}

fn plan_for_aggregate_invariant(
    invariant: &ir::IrInvariant,
    index: usize,
    aggregate: &ir::IrAggregateInvariant,
    runtime_accesses: &[CkbRuntimeAccessMetadata],
) -> ProofPlanMetadata {
    let trigger = invariant.trigger.clone().unwrap_or_else(|| "explicit_entry".to_string());
    let scope = aggregate.scope.clone();
    let reads = aggregate_reads(aggregate);
    let evidence = aggregate_lowering_evidence(invariant, aggregate, runtime_accesses);
    let relation_check = aggregate_relation_check_label(aggregate, evidence);
    let mut coverage = vec![aggregate_coverage_label(aggregate)];
    if let Some(helper) = evidence.helper() {
        coverage.push(format!("runtime_helper:{helper}"));
    }
    if let AggregateLoweringEvidence::RuntimeHelperChecked(helper) = evidence {
        coverage.push(format!("runtime_helper_checked:{helper}"));
    }
    coverage.extend(coverage_notes(&trigger, &scope));
    dedup(&mut coverage);
    let mut builder_assumptions = match evidence {
        AggregateLoweringEvidence::RuntimeHelperChecked(helper) => {
            vec![format!("declared(runtime-helper-checked:{helper})"), format!("declared(parent_invariant:{})", invariant.name)]
        }
        AggregateLoweringEvidence::RuntimeHelperRequired(helper) => {
            vec![format!("declared(runtime-helper-required:{helper})"), format!("declared(parent_invariant:{})", invariant.name)]
        }
        AggregateLoweringEvidence::MetadataOnly => vec![
            "declared(metadata-only aggregate invariant not yet lowered to executable verifier code)".to_string(),
            format!("declared(parent_invariant:{})", invariant.name),
        ],
    };
    if trigger == "lock_group" && scope == "transaction" {
        builder_assumptions.push(
            "declared(lock transaction scan only protects the lock group unless the builder constrains every relevant cell)"
                .to_string(),
        );
    }
    dedup(&mut builder_assumptions);

    let mut diagnostics = match evidence {
        AggregateLoweringEvidence::RuntimeHelperChecked(helper) => vec![ProofPlanDiagnosticMetadata {
            severity: "info".to_string(),
            message: format!("aggregate invariant is discharged by generated {helper} runtime helper coverage"),
        }],
        AggregateLoweringEvidence::RuntimeHelperRequired(helper) => vec![ProofPlanDiagnosticMetadata {
            severity: "info".to_string(),
            message: format!("aggregate invariant requires {helper} runtime helper coverage"),
        }],
        AggregateLoweringEvidence::MetadataOnly => vec![ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message: "aggregate invariant primitive is metadata-only until executable lowering covers it".to_string(),
        }],
    };
    if trigger == "lock_group" && scope == "transaction" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message:
                "transaction scans from a lock do not imply type-group conservation; only inputs sharing the lock trigger this verifier"
                    .to_string(),
        });
    }

    let feature = aggregate_feature_label(aggregate);
    let status = if evidence.is_checked() { "checked-runtime" } else { "runtime-required" };
    let evidence_tier = match evidence {
        AggregateLoweringEvidence::RuntimeHelperChecked(_) => EvidenceTier::CheckedRuntime,
        AggregateLoweringEvidence::RuntimeHelperRequired(_) => EvidenceTier::RuntimeHelperRequired,
        AggregateLoweringEvidence::MetadataOnly => EvidenceTier::MetadataOnly,
    };
    let on_chain_checked_obligations =
        if evidence.is_checked() { vec![format!("aggregate-invariant:{feature}={status}")] } else { Vec::new() };

    ProofPlanMetadata {
        name: format!("{}#aggregate{}", invariant.name, index),
        origin: format!("invariant:{}#aggregate:{}", invariant.name, index),
        category: "aggregate-invariant".to_string(),
        feature,
        evidence_tier,
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: aggregate.span.start,
            end: aggregate.span.end,
            line: aggregate.span.line,
            column: aggregate.span.column,
        }),
        trigger,
        scope,
        reads: reads.clone(),
        coverage,
        input_output_relation_checks: vec![relation_check],
        group_cardinality: aggregate_group_cardinality(aggregate).to_string(),
        identity_lifecycle_policy: aggregate_identity_lifecycle_policy(aggregate).to_string(),
        preserved_fields: Vec::new(),
        witness_fields: declared_witness_fields(&reads),
        lock_args_fields: declared_lock_args_fields(&reads),
        on_chain_checked: evidence.is_checked(),
        on_chain_checked_obligations,
        builder_assumptions,
        codegen_coverage_status: evidence.codegen_coverage_status().to_string(),
        status: status.to_string(),
        detail: format!("aggregate invariant primitive declared under invariant '{}'", invariant.name),
        diagnostics,
    }
}

fn plan_for_bounded_quantifier(
    invariant: &ir::IrInvariant,
    index: usize,
    quantifier: &crate::ast::BoundedQuantifier,
) -> ProofPlanMetadata {
    let trigger = invariant.trigger.clone().unwrap_or_else(|| "explicit_entry".to_string());
    let scope = bounded_quantifier_scope(quantifier).to_string();
    let kind = match quantifier.kind {
        BoundedQuantifierKind::ForAll => "forall",
        BoundedQuantifierKind::Count => "count",
    };
    let helper = match quantifier.kind {
        BoundedQuantifierKind::ForAll => "__cellscript_bounded_forall",
        BoundedQuantifierKind::Count => "__cellscript_bounded_count",
    };
    let predicates = quantifier.predicates.iter().map(crate::fmt::format_expression).collect::<Vec<_>>();
    let declared_field_reads = invariant
        .reads
        .iter()
        .filter(|read| read.source == quantifier.range.source && read.type_name == quantifier.range.type_name)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut reads = reads_from_aggregate_target(&quantifier.range);
    reads.extend(declared_field_reads.iter().cloned());
    dedup(&mut reads);
    let mut coverage = vec![
        format!("bounded_quantifier:{kind}"),
        format!("range:{}", quantifier.range),
        format!("source:{}", quantifier.range.source.as_str()),
        format!("complexity:O({})", quantifier.range.source.as_str()),
        format!("scan:one Source::{} scan", quantifier.range.source.as_str()),
        "source_view_cap:ckb-consensus-bounded".to_string(),
        "actual_scanned_cardinality:runtime-recorded".to_string(),
        "cycle_estimate:base-plus-per-cell-predicate".to_string(),
        format!("runtime_helper:{helper}"),
    ];
    coverage.extend(predicates.iter().map(|predicate| format!("predicate:{predicate}")));
    coverage.extend(declared_field_reads.iter().map(|read| format!("field_read:{read}")));
    match quantifier.kind {
        BoundedQuantifierKind::ForAll => {
            coverage.push("vacuous:true-when-cardinality-zero".to_string());
            coverage.push("cardinality_zero_audit:required".to_string());
        }
        BoundedQuantifierKind::Count => {
            coverage.push("accumulator_width:u64".to_string());
            coverage.push("overflow_policy:fail-closed".to_string());
        }
    }
    dedup(&mut coverage);
    let relation = match quantifier.kind {
        BoundedQuantifierKind::ForAll => format!("forall({})=runtime-helper-required:{helper}", quantifier.range),
        BoundedQuantifierKind::Count => format!(
            "count({}){}{}=runtime-helper-required:{helper}",
            quantifier.range,
            quantifier.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            quantifier.expected.as_ref().map(crate::fmt::format_expression).unwrap_or_else(|| "?".to_string())
        ),
    };
    let feature = bounded_quantifier_feature_label(quantifier);
    ProofPlanMetadata {
        name: format!("{}#quantifier{}", invariant.name, index),
        origin: format!("invariant:{}#quantifier:{}", invariant.name, index),
        category: "bounded-source-quantifier".to_string(),
        feature,
        evidence_tier: EvidenceTier::RuntimeHelperRequired,
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: quantifier.span.start,
            end: quantifier.span.end,
            line: quantifier.span.line,
            column: quantifier.span.column,
        }),
        trigger,
        scope,
        reads: reads.clone(),
        coverage,
        input_output_relation_checks: vec![relation],
        group_cardinality: bounded_quantifier_cardinality(quantifier).to_string(),
        identity_lifecycle_policy: "read-only bounded transaction-view scan; no lifecycle authority".to_string(),
        preserved_fields: Vec::new(),
        witness_fields: declared_witness_fields(&reads),
        lock_args_fields: declared_lock_args_fields(&reads),
        on_chain_checked: false,
        on_chain_checked_obligations: Vec::new(),
        builder_assumptions: vec![
            format!("declared(runtime-helper-required:{helper})"),
            "declared(actual cardinality and vacuous status are runtime evidence)".to_string(),
        ],
        codegen_coverage_status: "gap:runtime-helper-required".to_string(),
        status: "runtime-required".to_string(),
        detail: format!(
            "bounded {kind} over {}; predicates={}; accumulator={}",
            quantifier.range,
            predicates.len(),
            if quantifier.kind == BoundedQuantifierKind::Count { "u64/fail-closed-overflow" } else { "not-applicable" }
        ),
        diagnostics: vec![ProofPlanDiagnosticMetadata {
            severity: "info".to_string(),
            message: format!("bounded {kind} has a known {helper} contract but no emitted helper for this selected entry"),
        }],
    }
}

fn plan_from_obligation(
    scope_kind: &str,
    origin: &str,
    obligation: &VerifierObligationMetadata,
    body_reads: &[String],
    body_coverage: &[String],
    preserved_fields: &[String],
    witness_fields: &[String],
    lock_args_fields: &[String],
    pool_primitives: &[PoolPrimitiveMetadata],
) -> ProofPlanMetadata {
    let trigger = trigger_for_scope_kind(scope_kind).to_string();
    let scope = proof_scope(scope_kind, obligation, body_reads).to_string();
    let reads = reads_for_obligation(obligation, body_reads);
    let mut coverage = body_coverage.to_vec();
    coverage.extend(coverage_notes(&trigger, &scope));
    coverage.extend(macro_expansion_provenance(obligation));
    dedup(&mut coverage);
    let on_chain_checked = on_chain_checked(&obligation.status);
    let input_output_relation_checks = input_output_relation_checks(obligation, pool_primitives);
    let on_chain_checked_obligations =
        if on_chain_checked { checked_obligation_labels(obligation, &input_output_relation_checks) } else { Vec::new() };
    let builder_assumptions = builder_assumptions(obligation, &trigger, &scope, on_chain_checked);
    let diagnostics = diagnostics_for_plan(&trigger, &scope, obligation, &builder_assumptions);
    let evidence_tier = evidence_tier_for_obligation(obligation, on_chain_checked, &builder_assumptions);

    ProofPlanMetadata {
        name: obligation.feature.clone(),
        origin: origin.to_string(),
        category: obligation.category.clone(),
        feature: obligation.feature.clone(),
        evidence_tier,
        source_span: None,
        trigger,
        scope,
        reads,
        coverage,
        input_output_relation_checks,
        group_cardinality: group_cardinality(obligation, scope_kind).to_string(),
        identity_lifecycle_policy: identity_lifecycle_policy(obligation).to_string(),
        preserved_fields: preserved_fields.to_vec(),
        witness_fields: witness_fields.to_vec(),
        lock_args_fields: lock_args_fields.to_vec(),
        on_chain_checked,
        on_chain_checked_obligations,
        builder_assumptions,
        codegen_coverage_status: codegen_coverage_status(&obligation.status, on_chain_checked).to_string(),
        status: obligation.status.clone(),
        detail: obligation.detail.clone(),
        diagnostics,
    }
}

fn evidence_tier_for_obligation(
    obligation: &VerifierObligationMetadata,
    on_chain_checked: bool,
    builder_assumptions: &[String],
) -> EvidenceTier {
    if on_chain_checked {
        return if obligation.status == "checked-static" { EvidenceTier::CheckedStatic } else { EvidenceTier::CheckedRuntime };
    }

    if obligation.status == "metadata-only" || obligation.detail.to_ascii_lowercase().contains("metadata-only") {
        return EvidenceTier::MetadataOnly;
    }
    if obligation.status == "chain-evidence-required"
        || obligation.feature.contains("capacity")
        || obligation.feature.contains("dry-run")
        || obligation.feature.contains("tx-pool")
        || obligation.feature.contains("commit")
        || obligation.feature.contains("cycle")
    {
        return EvidenceTier::ChainEvidenceRequired;
    }
    if obligation.status == "builder-evidence-required"
        || obligation.status == "builder-required"
        || builder_assumptions.iter().any(|assumption| {
            let assumption = assumption.to_ascii_lowercase();
            assumption.contains("builder") || assumption.contains("indexer") || assumption.contains("cell selection")
        })
    {
        return EvidenceTier::BuilderEvidenceRequired;
    }
    if obligation.status == "runtime-helper-required" || obligation.status == "runtime-required" {
        return EvidenceTier::RuntimeHelperRequired;
    }

    EvidenceTier::MetadataOnly
}

fn trigger_for_scope_kind(scope_kind: &str) -> &'static str {
    match scope_kind {
        "lock" => "lock_group",
        _ => "explicit_entry",
    }
}

fn proof_scope<'a>(scope_kind: &str, obligation: &'a VerifierObligationMetadata, reads: &'a [String]) -> &'static str {
    if obligation.category == "transaction-invariant"
        || obligation.feature.contains("transfer-output")
        || obligation.feature.contains("claim-output")
        || obligation.feature.contains("settle-output")
        || obligation.feature.contains("destroy-output-scan")
        || obligation.feature.contains("resource-conservation")
    {
        "transaction"
    } else if reads.iter().any(|read| read.starts_with("group_")) || scope_kind == "lock" {
        "group"
    } else {
        "selected_cells"
    }
}

fn body_reads(body: &ir::IrBody, params: &[ir::IrParam], runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<String> {
    let mut reads = BTreeSet::new();
    for access in runtime_accesses {
        for read in reads_for_source(&access.source) {
            reads.insert(read.to_string());
        }
        if access.source == "Witness" || access.operation.contains("witness") || access.binding.starts_with("witness::") {
            reads.insert("witness".to_string());
        }
    }
    if !body.consume_set.is_empty() {
        reads.insert("input".to_string());
    }
    if !body.create_set.is_empty() {
        reads.insert("output".to_string());
    }
    if !body.read_refs.is_empty() {
        reads.insert("cell_dep".to_string());
    }
    if !body.mutate_set.is_empty() {
        reads.insert("input".to_string());
        reads.insert("output".to_string());
    }
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                IrInstruction::Transfer { .. } | IrInstruction::Claim { .. } | IrInstruction::Settle { .. } => {
                    reads.insert("input".to_string());
                    reads.insert("output".to_string());
                }
                IrInstruction::Destroy { .. } => {
                    reads.insert("input".to_string());
                    reads.insert("output".to_string());
                }
                _ => {}
            }
        }
    }
    for param in params {
        match param.source {
            ParamSource::Protected => {
                reads.insert("group_input".to_string());
            }
            ParamSource::Witness => {
                reads.insert("witness".to_string());
            }
            ParamSource::LockArgs => {
                reads.insert("lock_args".to_string());
            }
            ParamSource::Input => {
                reads.insert("input".to_string());
            }
            ParamSource::Output => {
                reads.insert("output".to_string());
            }
            ParamSource::Default => {}
        }
    }
    reads.into_iter().collect()
}

fn reads_for_source(source: &str) -> &'static [&'static str] {
    match source {
        "Transaction" => &["transaction"],
        "Input" => &["input"],
        "Output" => &["output"],
        "GroupInput" => &["group_input"],
        "GroupOutput" => &["group_output"],
        "Input/GroupInput" => &["input", "group_input"],
        "GroupInput/GroupOutput" => &["group_input", "group_output"],
        "CurrentScript/Input/GroupInput/GroupOutput" => &["current_script", "input", "group_input", "group_output"],
        "Input/Output" => &["input", "output", "source_view"],
        "Input/HeaderDep" => &["input", "header_dep"],
        "CellDep" => &["cell_dep"],
        "HeaderDep" => &["header_dep"],
        "Witness" => &["witness"],
        "ScriptArgs" => &["lock_args"],
        "SourceView" => &["source_view"],
        _ => &[],
    }
}

fn reads_for_obligation(obligation: &VerifierObligationMetadata, body_reads: &[String]) -> Vec<String> {
    let mut reads = body_reads.to_vec();
    if obligation.category == "cell-access"
        && let Some(source) = obligation.feature.split(':').nth(1).and_then(|source| source.split('#').next())
    {
        for read in reads_for_source(source) {
            reads.push(read.to_string());
        }
    }
    if obligation.detail.contains("witness") || obligation.feature.contains("witness") {
        reads.push("witness".to_string());
    }
    if obligation.detail.contains("header") || obligation.feature.contains("header") {
        reads.push("header_dep".to_string());
    }
    dedup(&mut reads);
    reads
}

fn body_coverage(scope_kind: &str, name: &str, body: &ir::IrBody) -> Vec<String> {
    let mut coverage = vec![format!("entry:{}:{}", scope_kind, name)];
    if !body.consume_set.is_empty() {
        coverage.push(format!(
            "covered_cells(inputs:{})",
            body.consume_set.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    if !body.create_set.is_empty() {
        coverage.push(format!(
            "covered_cells(outputs:{})",
            body.create_set.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    if !body.read_refs.is_empty() {
        coverage.push(format!(
            "observed_cells(cell_deps:{})",
            body.read_refs.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    if !body.mutate_set.is_empty() {
        coverage.push(format!(
            "covered_cells(replacements:{})",
            body.mutate_set.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    coverage
}

fn coverage_notes(trigger: &str, scope: &str) -> Vec<String> {
    match (trigger, scope) {
        ("lock_group", "transaction") => vec![
            "only inputs sharing this lock script trigger the verifier".to_string(),
            "transaction scans from a lock do not imply type-group conservation".to_string(),
        ],
        ("lock_group", _) => vec!["lock ScriptGroup coverage: inputs sharing this lock script".to_string()],
        ("type_group", _) => vec!["type ScriptGroup coverage: cells sharing this type script".to_string()],
        (_, "transaction") => vec!["transaction-scoped relation over explicit input/output views".to_string()],
        (_, "selected_cells") => vec!["selected cell coverage from explicit consume/read_ref/create/mutate summaries".to_string()],
        _ => Vec::new(),
    }
}

fn preserved_fields(body: &ir::IrBody) -> Vec<String> {
    let mut fields = Vec::new();
    for pattern in &body.mutate_set {
        for field in &pattern.preserved_fields {
            fields.push(format!("{}.{}", pattern.binding, field));
        }
        if pattern.preserve_type_hash {
            fields.push(format!("{}.type_script_hash", pattern.binding));
        }
        if pattern.preserve_lock_hash {
            fields.push(format!("{}.lock_script_hash", pattern.binding));
        }
    }
    dedup(&mut fields);
    fields
}

fn witness_fields(params: &[ir::IrParam], runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<String> {
    let mut fields = Vec::new();
    for param in params {
        match param.source {
            ParamSource::Witness => fields.push(format!("witness.{}", param.name)),
            ParamSource::Default | ParamSource::Protected | ParamSource::LockArgs | ParamSource::Input | ParamSource::Output => {}
        }
    }
    for access in runtime_accesses {
        if access.source == "Witness" || access.operation.contains("witness") {
            fields.push(format!("{}#{}:{}", access.source, access.index, access.binding));
        }
    }
    dedup(&mut fields);
    fields
}

fn lock_args_fields(params: &[ir::IrParam], runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<String> {
    let mut fields = Vec::new();
    for param in params {
        if param.source == ParamSource::LockArgs {
            fields.push(format!("lock_args.{}", param.name));
        }
    }
    for access in runtime_accesses {
        if access.source == "ScriptArgs" || access.operation.contains("lock-args") {
            fields.push(format!("{}#{}:{}", access.source, access.index, access.binding));
        }
    }
    dedup(&mut fields);
    fields
}

fn on_chain_checked(status: &str) -> bool {
    matches!(status, "checked-runtime" | "checked-static" | "ckb-runtime")
}

fn input_output_relation_checks(obligation: &VerifierObligationMetadata, pool_primitives: &[PoolPrimitiveMetadata]) -> Vec<String> {
    let mut checks = checked_runtime_subconditions(&obligation.detail);
    if obligation.category == "transaction-invariant" && obligation.status == "checked-runtime" {
        checks.push(format!("{}=checked-runtime", obligation.feature));
    }
    for primitive in pool_primitives.iter().filter(|primitive| primitive.feature == obligation.feature) {
        checks.extend(primitive.checked_components.iter().cloned());
        checks.extend(primitive.runtime_required_components.iter().map(|component| format!("{}=runtime-required", component)));
    }
    dedup(&mut checks);
    checks
}

fn macro_expansion_provenance(obligation: &VerifierObligationMetadata) -> Vec<String> {
    if obligation.feature.starts_with("transfer-output:") || obligation.feature.starts_with("transfer-input:") {
        vec!["macro_expansion:transfer=consume-input+create-output".to_string()]
    } else if obligation.feature.starts_with("create-output:") {
        vec!["macro_expansion:create=create-output".to_string()]
    } else if obligation.feature.starts_with("create-unique-output:") || obligation.feature.starts_with("create-unique-identity:") {
        vec!["macro_expansion:create_unique=create-output+identity-anchor".to_string()]
    } else if obligation.feature.starts_with("replace-unique-output:")
        || obligation.feature.starts_with("replace-unique-input:")
        || obligation.feature.starts_with("replace-unique-identity:")
        || obligation.feature.starts_with("replace_unique-input:")
    {
        vec!["macro_expansion:replace_unique=consume-input+create-output+preserve-identity".to_string()]
    } else if obligation.feature.starts_with("claim-output:") || obligation.feature.starts_with("claim-input:") {
        vec!["macro_expansion:claim=consume-receipt+create-output".to_string()]
    } else if obligation.feature.starts_with("settle-output:") || obligation.feature.starts_with("settle-input:") {
        vec!["macro_expansion:settle=consume-pending+create-output".to_string()]
    } else if obligation.feature.starts_with("consume-input:") {
        vec!["macro_expansion:consume=consume-input".to_string()]
    } else if obligation.feature.starts_with("destroy-input:") {
        vec!["macro_expansion:destroy=consume-input+no-output".to_string()]
    } else if obligation.feature.starts_with("pool-create:") {
        vec!["macro_expansion:pool-create=shared-cell-create+pool-protocol-metadata".to_string()]
    } else if obligation.feature.starts_with("pool-mutation-invariants:") {
        vec!["macro_expansion:pool-mutation=shared-cell-mutate+invariant-metadata".to_string()]
    } else if obligation.feature.starts_with("pool-composition:") {
        vec!["macro_expansion:pool-composition=cross-call+pool-protocol-metadata".to_string()]
    } else {
        Vec::new()
    }
}

fn checked_runtime_subconditions(detail: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in detail.split([',', ';']) {
        let trimmed = segment.trim();
        if let Some((prefix, _)) = trimmed.split_once("=checked-runtime") {
            let label = prefix.split_whitespace().last().unwrap_or(prefix).trim_matches(['.', ':']);
            if !label.is_empty() {
                out.push(label.to_string());
            }
        }
        if let Some((prefix, _)) = trimmed.split_once("=checked-static") {
            let label = prefix.split_whitespace().last().unwrap_or(prefix).trim_matches(['.', ':']);
            if !label.is_empty() {
                out.push(label.to_string());
            }
        }
    }
    dedup(&mut out);
    out
}

fn checked_obligation_labels(obligation: &VerifierObligationMetadata, relation_checks: &[String]) -> Vec<String> {
    let mut labels = vec![format!("{}:{}={}", obligation.category, obligation.feature, obligation.status)];
    labels.extend(relation_checks.iter().cloned());
    dedup(&mut labels);
    labels
}

fn builder_assumptions(obligation: &VerifierObligationMetadata, trigger: &str, scope: &str, on_chain_checked: bool) -> Vec<String> {
    let mut assumptions = Vec::new();
    if !on_chain_checked {
        assumptions.push(format!("declared({}: {})", obligation.status, obligation.detail));
    }
    if trigger == "lock_group" && scope == "transaction" {
        assumptions.push(
            "declared(lock transaction scan only protects the lock group unless the builder constrains every relevant cell)"
                .to_string(),
        );
    }
    assumptions
}

fn diagnostics_for_plan(
    trigger: &str,
    scope: &str,
    obligation: &VerifierObligationMetadata,
    builder_assumptions: &[String],
) -> Vec<ProofPlanDiagnosticMetadata> {
    let mut diagnostics = Vec::new();
    if trigger == "lock_group" && scope == "transaction" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message:
                "transaction scans from a lock do not imply type-group conservation; only inputs sharing the lock trigger this verifier"
                    .to_string(),
        });
    }
    if obligation.status == "runtime-required" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message: "obligation is not fully covered by generated on-chain code".to_string(),
        });
    }
    if !builder_assumptions.is_empty() && obligation.status == "fail-closed" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "error".to_string(),
            message: "generated code fail-closes this obligation instead of accepting a metadata-only proof".to_string(),
        });
    }
    diagnostics
}

fn group_cardinality(obligation: &VerifierObligationMetadata, scope_kind: &str) -> &'static str {
    let text = format!("{} {}", obligation.feature, obligation.detail).to_ascii_lowercase();
    if text.contains("type_id") || text.contains("type-id") {
        "ckb_type_id: at-most-one-input-and-one-output"
    } else if scope_kind == "lock" {
        "ckb lock ScriptGroup cardinality"
    } else if text.contains("group") {
        "ckb ScriptGroup cardinality"
    } else {
        "not a script-group cardinality obligation"
    }
}

fn identity_lifecycle_policy(obligation: &VerifierObligationMetadata) -> &'static str {
    let text = format!("{} {}", obligation.feature, obligation.detail).to_ascii_lowercase();
    if text.contains("identity field(") || text.contains("field identity") {
        "identity field"
    } else if text.contains("script_args") || text.contains("script args") {
        "identity script_args"
    } else if text.contains("singleton_type") || text.contains("singleton type") {
        "identity singleton_type"
    } else if text.contains("type_id") || text.contains("type-id") {
        "identity ckb_type_id"
    } else if text.contains("destroy-output-scan") || text.contains("same type") || text.contains("typehash absence") {
        "destroy_singleton_type compatibility policy"
    } else if text.contains("destroy") {
        "explicit destruction policy required"
    } else if text.contains("lifecycle") || text.contains("settle-finalization") {
        "identity lifecycle transition policy"
    } else if text.contains("transfer") || text.contains("preserve") || text.contains("replacement") {
        "preserve_identity(input, output)"
    } else {
        "none"
    }
}

fn codegen_coverage_status(status: &str, on_chain_checked: bool) -> &str {
    if on_chain_checked {
        "covered"
    } else if status == "runtime-required" {
        "gap:runtime-required"
    } else if status == "fail-closed" {
        "fail-closed"
    } else {
        status
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateLoweringEvidence {
    MetadataOnly,
    RuntimeHelperRequired(&'static str),
    RuntimeHelperChecked(&'static str),
}

impl AggregateLoweringEvidence {
    fn helper(&self) -> Option<&'static str> {
        match *self {
            Self::MetadataOnly => None,
            Self::RuntimeHelperRequired(helper) | Self::RuntimeHelperChecked(helper) => Some(helper),
        }
    }

    fn is_runtime_helper_backed(&self) -> bool {
        !matches!(self, Self::MetadataOnly)
    }

    fn is_checked(&self) -> bool {
        matches!(self, Self::RuntimeHelperChecked(_))
    }

    fn relation_status(&self) -> String {
        match *self {
            Self::MetadataOnly => "metadata-only".to_string(),
            Self::RuntimeHelperRequired(helper) => format!("runtime-helper-required:{helper}"),
            Self::RuntimeHelperChecked(helper) => format!("checked-runtime:{helper}"),
        }
    }

    fn codegen_coverage_status(&self) -> &'static str {
        match *self {
            Self::MetadataOnly => "gap:metadata-only",
            Self::RuntimeHelperRequired(_) => "gap:runtime-helper-required",
            Self::RuntimeHelperChecked(_) => "covered",
        }
    }
}

fn aggregate_coverage_label(aggregate: &ir::IrAggregateInvariant) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "aggregate_assertion:{}{}{} scope={}",
            aggregate.target,
            aggregate.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            aggregate.rhs.as_ref().map(ToString::to_string).unwrap_or_else(|| "?".to_string()),
            aggregate.scope
        ),
        AggregateInvariantKind::Conserved => format!("aggregate_assertion:conserved({}) scope={}", aggregate.target, aggregate.scope),
        AggregateInvariantKind::Delta => format!(
            "aggregate_assertion:delta({},{}) scope={}",
            aggregate.target,
            aggregate.argument.as_deref().unwrap_or("?"),
            aggregate.scope
        ),
        AggregateInvariantKind::Distinct => format!("aggregate_assertion:distinct({}) scope={}", aggregate.target, aggregate.scope),
        AggregateInvariantKind::Singleton => format!("aggregate_assertion:singleton({}) scope={}", aggregate.target, aggregate.scope),
    }
}

fn bounded_quantifier_coverage_label(quantifier: &crate::ast::BoundedQuantifier) -> String {
    format!("bounded_quantifier:{}", bounded_quantifier_feature_label(quantifier))
}

fn bounded_quantifier_feature_label(quantifier: &crate::ast::BoundedQuantifier) -> String {
    match quantifier.kind {
        BoundedQuantifierKind::ForAll => format!("forall:{}", quantifier.range),
        BoundedQuantifierKind::Count => format!(
            "count:{}{}{}",
            quantifier.range,
            quantifier.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            quantifier.expected.as_ref().map(crate::fmt::format_expression).unwrap_or_else(|| "?".to_string())
        ),
    }
}

fn bounded_quantifier_scope(quantifier: &crate::ast::BoundedQuantifier) -> &'static str {
    match quantifier.range.source {
        SourceView::GroupInput | SourceView::GroupOutput => "group",
        SourceView::Input | SourceView::Output | SourceView::CellDep => "transaction",
        SourceView::SelectedCells => "selected_cells",
        _ => "unsupported",
    }
}

fn bounded_quantifier_cardinality(quantifier: &crate::ast::BoundedQuantifier) -> &'static str {
    match quantifier.range.source {
        SourceView::GroupInput | SourceView::GroupOutput => {
            "ckb ScriptGroup cardinality; actual scanned cardinality recorded at runtime"
        }
        SourceView::Input | SourceView::Output | SourceView::CellDep => {
            "transaction source cardinality; actual scanned cardinality recorded at runtime"
        }
        SourceView::SelectedCells => "selected cell-set cardinality; actual scanned cardinality recorded at runtime",
        _ => "unsupported quantifier cardinality",
    }
}

fn aggregate_relation_check_label(aggregate: &ir::IrAggregateInvariant, evidence: AggregateLoweringEvidence) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "assert_sum:{}{}{}={}",
            aggregate.target,
            aggregate.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            aggregate.rhs.as_ref().map(ToString::to_string).unwrap_or_else(|| "?".to_string()),
            evidence.relation_status()
        ),
        AggregateInvariantKind::Conserved => format!("assert_conserved:{}=metadata-only", aggregate.target),
        AggregateInvariantKind::Delta => format!(
            "assert_delta:{}:{}={}",
            aggregate.target,
            aggregate.argument.as_deref().unwrap_or("?"),
            evidence.relation_status()
        ),
        AggregateInvariantKind::Distinct => format!("assert_distinct:{}=metadata-only", aggregate.target),
        AggregateInvariantKind::Singleton => format!("assert_singleton:{}=metadata-only", aggregate.target),
    }
}

fn aggregate_feature_label(aggregate: &ir::IrAggregateInvariant) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "assert_sum:{}{}{}",
            aggregate.target,
            aggregate.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            aggregate.rhs.as_ref().map(ToString::to_string).unwrap_or_else(|| "?".to_string())
        ),
        AggregateInvariantKind::Conserved => format!("assert_conserved:{}", aggregate.target),
        AggregateInvariantKind::Delta => format!("assert_delta:{}:{}", aggregate.target, aggregate.argument.as_deref().unwrap_or("?")),
        AggregateInvariantKind::Distinct => format!("assert_distinct:{}", aggregate.target),
        AggregateInvariantKind::Singleton => format!("assert_singleton:{}", aggregate.target),
    }
}

fn aggregate_reads(aggregate: &ir::IrAggregateInvariant) -> Vec<String> {
    let mut reads = Vec::new();
    reads.extend(reads_from_aggregate_target(&aggregate.target));
    if let Some(rhs) = &aggregate.rhs {
        reads.extend(reads_from_aggregate_target(rhs));
    }
    if reads.is_empty() {
        match aggregate.scope.as_str() {
            "group" => {
                reads.push("group_input".to_string());
                reads.push("group_output".to_string());
            }
            "transaction" => {
                reads.push("input".to_string());
                reads.push("output".to_string());
            }
            _ => {}
        }
    }
    dedup(&mut reads);
    reads
}

fn reads_from_aggregate_target(target: &AggregateTarget) -> Vec<String> {
    target.source.proof_plan_read().map(str::to_string).into_iter().collect()
}

fn aggregate_group_cardinality(aggregate: &ir::IrAggregateInvariant) -> &'static str {
    match aggregate.scope.as_str() {
        "group" => "ckb ScriptGroup cardinality",
        "transaction" => "transaction input/output cardinality",
        "selected_cells" => "selected cell-set cardinality",
        _ => "not a script-group cardinality obligation",
    }
}

fn aggregate_identity_lifecycle_policy(aggregate: &ir::IrAggregateInvariant) -> &'static str {
    match aggregate.kind {
        AggregateInvariantKind::Conserved => "aggregate conservation policy",
        AggregateInvariantKind::Delta => "aggregate delta policy",
        AggregateInvariantKind::Distinct => "aggregate uniqueness policy",
        AggregateInvariantKind::Singleton => "aggregate singleton policy",
        AggregateInvariantKind::Sum => "aggregate sum relation policy",
    }
}

fn aggregate_relation_symbol(relation: AggregateRelation) -> &'static str {
    match relation {
        AggregateRelation::Lt => "<",
        AggregateRelation::Le => "<=",
        AggregateRelation::Eq => "==",
        AggregateRelation::Ge => ">=",
        AggregateRelation::Gt => ">",
    }
}

fn aggregate_lowering_evidence(
    invariant: &ir::IrInvariant,
    aggregate: &ir::IrAggregateInvariant,
    runtime_accesses: &[CkbRuntimeAccessMetadata],
) -> AggregateLoweringEvidence {
    let helpers = aggregate_group_amount_runtime_helpers(invariant, aggregate);
    if helpers.is_empty() {
        return AggregateLoweringEvidence::MetadataOnly;
    }
    if let Some(helper) = helpers.iter().copied().find(|helper| runtime_helper_access_is_available(runtime_accesses, helper)) {
        return AggregateLoweringEvidence::RuntimeHelperChecked(helper);
    }
    AggregateLoweringEvidence::RuntimeHelperRequired(helpers[0])
}

fn runtime_helper_access_is_available(runtime_accesses: &[CkbRuntimeAccessMetadata], helper: &str) -> bool {
    runtime_accesses.iter().any(|access| {
        access.binding == helper
            && (access.source == "GroupInput/GroupOutput"
                || (helper == FUNGIBLE_TYPE_GROUP_V1_METADATA_HELPER && access.source == "CurrentScript/Input/GroupInput/GroupOutput"))
    })
}

fn aggregate_group_amount_runtime_helpers(invariant: &ir::IrInvariant, aggregate: &ir::IrAggregateInvariant) -> Vec<&'static str> {
    if invariant.trigger.as_deref() != Some("type_group") || aggregate.scope != "group" {
        return Vec::new();
    }
    match aggregate.kind {
        AggregateInvariantKind::Sum if aggregate.relation == Some(AggregateRelation::Eq) => {
            let mut helpers = Vec::new();
            if xudt_group_amount_conservation_type(invariant, aggregate).is_some() {
                helpers.push(XUDT_GROUP_AMOUNT_CONSERVED_METADATA_HELPER);
            }
            if fungible_type_group_v1_conservation_type(invariant, aggregate).is_some() {
                helpers.push(FUNGIBLE_TYPE_GROUP_V1_METADATA_HELPER);
            }
            helpers
        }
        AggregateInvariantKind::Delta => {
            let Some((source, _type_name)) = aggregate_group_amount_endpoint(&aggregate.target) else {
                return Vec::new();
            };
            let Some(argument) = aggregate.argument.as_deref() else {
                return Vec::new();
            };
            if argument.is_empty() {
                return Vec::new();
            }
            match source {
                SourceView::GroupOutput => vec!["xudt::require_group_amount_minted"],
                SourceView::GroupInput => vec!["xudt::require_group_amount_burned"],
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

fn declared_group_cardinality(invariant: &ir::IrInvariant) -> &'static str {
    match invariant.trigger.as_deref() {
        Some("type_group") => "ckb type ScriptGroup cardinality",
        Some("lock_group") => "ckb lock ScriptGroup cardinality",
        _ if invariant.scope.as_deref() == Some("group") => "ckb ScriptGroup cardinality",
        _ => "not a script-group cardinality obligation",
    }
}

fn declared_identity_lifecycle_policy(invariant: &ir::IrInvariant) -> &'static str {
    if invariant.aggregates.iter().any(|aggregate| {
        matches!(aggregate.kind, AggregateInvariantKind::Conserved | AggregateInvariantKind::Delta | AggregateInvariantKind::Singleton)
    }) {
        "aggregate invariant policy"
    } else {
        "declared invariant policy"
    }
}

fn declared_witness_fields(reads: &[String]) -> Vec<String> {
    let mut fields = reads.iter().filter(|read| read.starts_with("witness")).cloned().collect::<Vec<_>>();
    dedup(&mut fields);
    fields
}

fn declared_lock_args_fields(reads: &[String]) -> Vec<String> {
    let mut fields = reads.iter().filter(|read| read.starts_with("lock_args")).cloned().collect::<Vec<_>>();
    dedup(&mut fields);
    fields
}

fn dedup(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::EvidenceTier;
    use std::collections::BTreeSet;

    #[test]
    fn evidence_tier_registry_is_complete_and_unique() {
        let names = EvidenceTier::ALL.into_iter().map(EvidenceTier::as_str).collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "checked-static",
                "checked-runtime",
                "trusted-external",
                "runtime-helper-required",
                "builder-evidence-required",
                "metadata-only",
                "chain-evidence-required",
            ]
        );
        assert_eq!(names.iter().copied().collect::<BTreeSet<_>>().len(), names.len());
    }
}
