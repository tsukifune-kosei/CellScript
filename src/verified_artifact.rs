use crate::ast;
use crate::codegen::{MachineEdgeKindEvidence, MachineLayoutEvidence, MachineTerminatorEvidence};
use crate::error::{CompileError, Result, Span};
use crate::{CompileMetadata, ParamMetadata};
use cellscript_artifact_checker::{
    canonical_hash, check_bundle_values, domain_hash_bytes, parse_elf, CheckerBudgets, CompatibilityProfileIdentity, EdgeKind,
    EntryKind, LoweringBlock, LoweringEdge, LoweringEntry, MachineRange, MachineTerminator, ProofRecord, RuntimeErrorExit,
    SemanticSourceMapping, SourceArtifactMap, SourceMapCoverageClaim, SourceMapInterval, StorageClass, SyscallSite, TypedBlockBinding,
    TypedParameter, VerificationClaim, VerifiedArtifactMetadata, VerifiedArtifactState, VerifiedLoweringRecord, CHECKER_POLICY_SCHEMA,
    CHECKER_VERSION, LOWERING_RECORD_SCHEMA, LOWERING_RECORD_VERSION, SOURCE_MAP_SCHEMA, SOURCE_MAP_VERSION,
    VERIFIED_ARTIFACT_BOUNDARY_SCHEMA,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) struct VerifiedArtifactDraft {
    pub machine_layout: MachineLayoutEvidence,
    pub source_spans: BTreeMap<String, Span>,
    pub disposition_spans: BTreeMap<String, Span>,
    pub claim_spans: BTreeMap<String, Span>,
}

impl VerifiedArtifactDraft {
    pub(crate) fn new(machine_layout: MachineLayoutEvidence, module: &ast::Module, ir: &crate::ir::IrModule) -> Self {
        let source_spans = module
            .items
            .iter()
            .filter_map(|item| match item {
                ast::Item::Action(action) => Some((action.name.clone(), action.span)),
                ast::Item::Function(function) => Some((function.name.clone(), function.span)),
                ast::Item::Lock(lock) => Some((lock.name.clone(), lock.span)),
                _ => None,
            })
            .collect();
        let mut claim_spans: BTreeMap<String, Span> = ir
            .items
            .iter()
            .filter_map(|item| match item {
                crate::ir::IrItem::Action(entry) => Some((format!("action:{}", entry.name), &entry.body)),
                crate::ir::IrItem::Lock(entry) => Some((format!("lock:{}", entry.name), &entry.body)),
                crate::ir::IrItem::PureFn(entry) => Some((format!("helper:{}", entry.name), &entry.body)),
                crate::ir::IrItem::TypeDef(_) | crate::ir::IrItem::Invariant(_) => None,
            })
            .flat_map(|(entry_id, body)| {
                body.enforced_claims
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, claim)| (format!("claim:{entry_id}:enforced:{ordinal:05}"), claim.span))
            })
            .collect();
        for item in &ir.items {
            let (entry_id, audits) = match item {
                crate::ir::IrItem::Action(entry) => (format!("action:{}", entry.name), entry.audit_claims.as_slice()),
                crate::ir::IrItem::Lock(entry) => (format!("lock:{}", entry.name), entry.audit_claims.as_slice()),
                crate::ir::IrItem::TypeDef(_) | crate::ir::IrItem::Invariant(_) | crate::ir::IrItem::PureFn(_) => continue,
            };
            for audit in audits {
                claim_spans.insert(format!("claim:{entry_id}:audit:{}", audit.name), audit.span);
            }
        }
        let disposition_spans = ir
            .items
            .iter()
            .filter_map(|item| match item {
                crate::ir::IrItem::Action(entry) => Some((format!("action:{}", entry.name), entry.source_dispositions.as_slice())),
                _ => None,
            })
            .flat_map(|(entry_id, dispositions)| {
                dispositions
                    .iter()
                    .map(move |disposition| (crate::ir::source_disposition_id(&entry_id, disposition), disposition.span))
            })
            .collect();
        Self { machine_layout, source_spans, disposition_spans, claim_spans }
    }
}

pub(crate) fn build_verified_artifact_boundary(
    artifact: &[u8],
    metadata: &CompileMetadata,
    draft: &VerifiedArtifactDraft,
) -> Result<(VerifiedLoweringRecord, SourceArtifactMap, VerifiedArtifactMetadata)> {
    let budgets = CheckerBudgets::default();
    let elf = parse_elf(artifact, budgets.instructions).map_err(|error| boundary_error(error.to_string()))?;
    let compatibility_profile = compatibility_profile_identity(metadata);
    let compatibility_profile_hash = canonical_hash("cellscript-compatibility-profile-identity-v1", &compatibility_profile)
        .map_err(|error| boundary_error(error.to_string()))?;
    let source_identity = metadata
        .source_content_hash
        .clone()
        .ok_or_else(|| boundary_error("verified artifact boundary requires source_content_hash before emission"))?;

    let owners = block_owners(&draft.machine_layout)?;
    let frame_sizes = complete_frame_sizes(&draft.machine_layout, &elf, &owners)?;
    let mut entries = build_entries(metadata, &frame_sizes, &owners)?;
    let owner_ids = entries.iter().map(|entry| (entry.name.clone(), entry.id.clone())).collect::<BTreeMap<_, _>>();
    let entry_proofs = build_proof_records(metadata, &owner_ids);
    let proof_ids_by_entry = entry_proofs.iter().fold(BTreeMap::<String, Vec<String>>::new(), |mut map, proof| {
        map.entry(proof.entry_id.clone()).or_default().push(proof.id.clone());
        map
    });
    for entry in &mut entries {
        entry.proof_ids = proof_ids_by_entry.get(&entry.id).cloned().unwrap_or_default();
    }

    let mut blocks = Vec::with_capacity(draft.machine_layout.blocks.len());
    for (index, machine) in draft.machine_layout.blocks.iter().enumerate() {
        let owner_name = owners.get(index).ok_or_else(|| boundary_error("machine block owner map is incomplete"))?;
        let owner_entry = owner_ids
            .get(owner_name)
            .cloned()
            .ok_or_else(|| boundary_error(format!("machine owner '{owner_name}' has no lowering entry")))?;
        let range = MachineRange { start: machine.start, end: machine.end };
        let machine_bytes = elf.bytes_for_range(artifact, range).map_err(|error| boundary_error(error.to_string()))?;
        let frame_size_bytes = frame_sizes.get(owner_name).copied().unwrap_or(0);
        let proof_ids = proof_ids_by_entry.get(&owner_entry).cloned().unwrap_or_default();
        let entry_effect = entries
            .iter()
            .find(|entry| entry.id == owner_entry)
            .map(|entry| entry.effect.clone())
            .unwrap_or_else(|| "runtime".to_string());
        let lowering_block_id = lowering_block_id(machine.label.as_deref(), owner_name);
        let typed_block_hash = lowering_block_id
            .and_then(|block_id| {
                metadata
                    .typed_semantics
                    .entries
                    .iter()
                    .find(|entry| entry.id == owner_entry)
                    .and_then(|entry| entry.blocks.iter().find(|block| block.id == block_id))
            })
            .map(|block| canonical_hash("cellscript-typed-block-v1", block))
            .transpose()
            .map_err(|error| boundary_error(error.to_string()))?;
        blocks.push(LoweringBlock {
            id: machine_block_id(index),
            owner_entry,
            reachable: true,
            lowering_block_id,
            typed_block_hash,
            machine_label: machine.label.clone(),
            terminator: match machine.terminator {
                MachineTerminatorEvidence::Fallthrough => MachineTerminator::Fallthrough,
                MachineTerminatorEvidence::Jump => MachineTerminator::Jump,
                MachineTerminatorEvidence::ConditionalBranch => MachineTerminator::ConditionalBranch,
                MachineTerminatorEvidence::Return => MachineTerminator::Return,
            },
            range,
            byte_digest: domain_hash_bytes("cellscript-machine-block-v1", machine_bytes),
            frame_size_bytes,
            outgoing_argument_bytes: entries
                .iter()
                .find(|entry| entry.name == *owner_name)
                .map(|entry| entry.outgoing_argument_bytes)
                .unwrap_or(0),
            stack_slots: Vec::new(),
            scratch_register_avoid: Vec::new(),
            effect: entry_effect,
            capabilities: Vec::new(),
            proof_ids,
        });
    }

    let mut edges = draft
        .machine_layout
        .edges
        .iter()
        .map(|edge| LoweringEdge {
            from: machine_block_id(edge.from),
            to: machine_block_id(edge.to),
            kind: match edge.kind {
                MachineEdgeKindEvidence::Fallthrough => EdgeKind::Fallthrough,
                MachineEdgeKindEvidence::Jump => EdgeKind::Jump,
                MachineEdgeKindEvidence::ConditionalTaken => EdgeKind::ConditionalTaken,
                MachineEdgeKindEvidence::ConditionalFallthrough => EdgeKind::ConditionalFallthrough,
                MachineEdgeKindEvidence::Call => EdgeKind::Call,
            },
        })
        .collect::<Vec<_>>();
    edges.sort_by(|a, b| (&a.from, &a.kind, &a.to).cmp(&(&b.from, &b.kind, &b.to)));
    bind_typed_blocks(&mut entries, &blocks, metadata)?;
    mark_reachable_blocks(&entries, &mut blocks, &edges);

    let syscall_sites = elf
        .syscall_addresses
        .iter()
        .copied()
        .filter(|address| draft.machine_layout.text_start <= *address && *address < draft.machine_layout.text_end)
        .map(|address| {
            let block = blocks
                .iter()
                .find(|block| block.range.contains(address))
                .ok_or_else(|| boundary_error(format!("decoded syscall {address:#x} is outside machine blocks")))?;
            let header_contract = match block.owner_entry.as_str() {
                "runtime:__ckb_header_dep_epoch_number" => {
                    Some((crate::ckb_abi::syscall::LOAD_HEADER_BY_FIELD, "ckb-header-dep-epoch-number-v1", 8))
                }
                "runtime:__ckb_header_dep_epoch_start_block_number" => {
                    Some((crate::ckb_abi::syscall::LOAD_HEADER_BY_FIELD, "ckb-header-dep-epoch-start-block-number-v1", 8))
                }
                "runtime:__ckb_header_dep_epoch_length" => {
                    Some((crate::ckb_abi::syscall::LOAD_HEADER_BY_FIELD, "ckb-header-dep-epoch-length-v1", 8))
                }
                "runtime:__ckb_header_dep_block_number" => {
                    Some((crate::ckb_abi::syscall::LOAD_HEADER, "ckb-header-dep-block-number-v1", 208))
                }
                "runtime:__ckb_header_dep_timestamp_millis" => {
                    Some((crate::ckb_abi::syscall::LOAD_HEADER, "ckb-header-dep-timestamp-millis-v1", 208))
                }
                _ => None,
            };
            let (syscall_number, contract, source_domain, index_domain, buffer_limit_bytes) =
                if let Some((syscall_number, contract, buffer_limit_bytes)) = header_contract {
                    (
                        Some(syscall_number),
                        contract.to_string(),
                        "HeaderDepView/source=HeaderDep".to_string(),
                        "u32-source-view".to_string(),
                        buffer_limit_bytes,
                    )
                } else {
                    (
                        None,
                        "ckb-vm-ecall-a7-v1".to_string(),
                        "entry-runtime-metadata".to_string(),
                        "entry-runtime-metadata".to_string(),
                        block.frame_size_bytes.max(1),
                    )
                };
            Ok(SyscallSite {
                block_id: block.id.clone(),
                address,
                syscall_number,
                contract,
                source_domain,
                index_domain,
                return_code_checked: true,
                buffer_limit_bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let runtime_error_exits = runtime_error_exits(&draft.machine_layout, &blocks);
    let verifier_failure_exits = verifier_failure_exits(&draft.machine_layout, &blocks)?;

    let mut record = VerifiedLoweringRecord {
        schema: LOWERING_RECORD_SCHEMA.to_string(),
        version: LOWERING_RECORD_VERSION,
        compiler_version: metadata.compiler_version.clone(),
        module: metadata.module.clone(),
        edition: metadata.edition.as_str().to_string(),
        target_profile: metadata.target_profile.name.clone(),
        compatibility_profile,
        compatibility_profile_hash,
        source_set_hash: source_identity.clone(),
        source_content_hash: source_identity.clone(),
        artifact_format: metadata.artifact_format.clone(),
        artifact_hash: metadata.artifact_hash.clone().ok_or_else(|| boundary_error("metadata artifact hash is missing"))?,
        artifact_size_bytes: artifact.len() as u64,
        typed_semantics: metadata.typed_semantics.clone(),
        typed_semantics_hash: metadata.typed_semantics_hash.clone(),
        text_range: MachineRange { start: draft.machine_layout.text_start, end: draft.machine_layout.text_end },
        entries,
        blocks,
        edges,
        proof_records: entry_proofs,
        syscall_sites,
        runtime_error_exits,
        verifier_failure_exits,
        limits: budgets.as_declared_limits(),
        claim: VerificationClaim {
            lowering_record: "binding-verified".to_string(),
            machine_code: "structurally-verified".to_string(),
            semantic_equivalence: false,
        },
    };
    record.canonicalize();
    let record_hash = canonical_hash(LOWERING_RECORD_SCHEMA, &record).map_err(|error| boundary_error(error.to_string()))?;

    let source_path = stable_entry_source_path(metadata);
    let mut intervals = record
        .blocks
        .iter()
        .filter_map(|block| {
            let lowering_block_id = block.lowering_block_id?;
            let entry = record.entries.iter().find(|entry| entry.id == block.owner_entry)?;
            let span = draft.source_spans.get(&entry.name).copied().unwrap_or_default();
            let runtime_error_codes =
                record.runtime_error_exits.iter().filter(|exit| exit.block_id == block.id).map(|exit| exit.code).collect();
            Some(SourceMapInterval {
                source_path: source_path.clone(),
                source_start: u32::try_from(span.start).unwrap_or(u32::MAX),
                source_end: u32::try_from(span.end).unwrap_or(u32::MAX),
                entry_id: block.owner_entry.clone(),
                block_id: block.id.clone(),
                lowering_block_id: Some(lowering_block_id),
                machine_range: block.range,
                proof_ids: block.proof_ids.clone(),
                runtime_error_codes,
            })
        })
        .collect::<Vec<_>>();
    intervals.sort_by_key(|interval| interval.machine_range.start);
    let mut source_map = SourceArtifactMap {
        schema: SOURCE_MAP_SCHEMA.to_string(),
        version: SOURCE_MAP_VERSION,
        module: metadata.module.clone(),
        artifact_hash: record.artifact_hash.clone(),
        lowering_record_hash: record_hash.clone(),
        source_set_hash: source_identity,
        source_digest: record.source_content_hash.clone(),
        text_range: record.text_range,
        intervals,
        semantic_mappings: semantic_source_mappings(metadata, draft, &source_path),
        coverage_claim: SourceMapCoverageClaim {
            mapped_instruction_ranges_only: true,
            complete_text_coverage: false,
            source_semantic_equivalence: false,
        },
    };
    source_map.canonicalize();
    let source_map_hash = canonical_hash(SOURCE_MAP_SCHEMA, &source_map).map_err(|error| boundary_error(error.to_string()))?;
    let identities = &metadata.typed_semantics.foundation.identities;
    let deployable_artifact_id = record.artifact_hash.clone();
    let verified_bundle_id = canonical_hash(
        "cellscript-verified-bundle-id-v1",
        &(
            deployable_artifact_id.as_str(),
            metadata.typed_semantics_hash.as_str(),
            record.compatibility_profile_hash.as_str(),
            record_hash.as_str(),
            source_map_hash.as_str(),
            source_map.source_digest.as_str(),
        ),
    )
    .map_err(|error| boundary_error(error.to_string()))?;
    let boundary_metadata = VerifiedArtifactMetadata {
        boundary_schema: VERIFIED_ARTIFACT_BOUNDARY_SCHEMA.to_string(),
        state: VerifiedArtifactState::Emitted,
        checker_name: "cellscript-artifact-checker".to_string(),
        checker_version: CHECKER_VERSION.to_string(),
        checker_policy_schema: CHECKER_POLICY_SCHEMA.to_string(),
        lowering_record_schema: LOWERING_RECORD_SCHEMA.to_string(),
        lowering_record_hash: Some(record_hash),
        source_map_schema: SOURCE_MAP_SCHEMA.to_string(),
        source_map_hash: Some(source_map_hash),
        source_digest: Some(source_map.source_digest.clone()),
        core_semantic_id: Some(identities.core_semantic_id.clone()),
        entry_contract_id: Some(identities.entry_contract_id.clone()),
        artifact_contract_id: Some(identities.artifact_contract_id.clone()),
        deployable_artifact_id: Some(deployable_artifact_id),
        verified_bundle_id: Some(verified_bundle_id),
        claim: "binding-verified+structurally-verified;semantic-equivalence-not-claimed".to_string(),
    };
    Ok((record, source_map, boundary_metadata))
}

fn semantic_source_mappings(
    metadata: &CompileMetadata,
    draft: &VerifiedArtifactDraft,
    source_path: &str,
) -> Vec<SemanticSourceMapping> {
    let foundation = &metadata.typed_semantics.foundation;
    let mut mappings = Vec::new();
    let mut push = |semantic_node_id: &str, entry_id: &str, exact_span: Option<Span>| {
        let entry_name = entry_id.split_once(':').map_or(entry_id, |(_, name)| name);
        let span = exact_span.or_else(|| draft.source_spans.get(entry_name).copied()).unwrap_or_default();
        mappings.push(SemanticSourceMapping {
            semantic_node_id: semantic_node_id.to_string(),
            source_path: source_path.to_string(),
            source_start: u32::try_from(span.start).unwrap_or(u32::MAX),
            source_end: u32::try_from(span.end).unwrap_or(u32::MAX),
        });
    };
    push(&foundation.entry_contract.semantic_node_id, &foundation.entry_contract.exact_entry, None);
    for role in &foundation.roles {
        push(&role.semantic_node_id, &role.entry_id, None);
    }
    for disposition in &foundation.dispositions {
        let disposition_span = draft.disposition_spans.get(&disposition.id).copied().filter(|span| span.end > span.start);
        push(&disposition.semantic_node_id, &disposition.entry_id, disposition_span);
    }
    for claim in &foundation.claims {
        let claim_span = draft.claim_spans.get(&claim.id).copied().filter(|span| span.end > span.start);
        push(&claim.semantic_node_id, &claim.entry_id, claim_span);
    }
    for legacy in &foundation.legacy_nodes {
        let mut segments = legacy.id.strip_prefix("legacy:disposition:").unwrap_or_default().split(':');
        let entry_id = match (segments.next(), segments.next()) {
            (Some(kind), Some(name)) => format!("{kind}:{name}"),
            _ => String::new(),
        };
        push(&legacy.semantic_node_id, &entry_id, None);
    }
    for binding in &foundation.provenance.bindings {
        push(&binding.node_id, &binding.entry_id, None);
    }
    for node in &foundation.provenance.nodes {
        push(&node.id, &foundation.entry_contract.exact_entry, None);
    }
    mappings
}

fn mark_reachable_blocks(entries: &[LoweringEntry], blocks: &mut [LoweringBlock], edges: &[LoweringEdge]) {
    let mut reachable = BTreeSet::new();
    let mut pending = entries.iter().map(|entry| entry.entry_block.as_str()).collect::<Vec<_>>();
    while let Some(block_id) = pending.pop() {
        if !reachable.insert(block_id) {
            continue;
        }
        pending.extend(edges.iter().filter(|edge| edge.from == block_id).map(|edge| edge.to.as_str()));
    }
    for block in blocks {
        block.reachable = reachable.contains(block.id.as_str());
    }
}

pub(crate) fn validate_boundary_values(
    artifact: &[u8],
    metadata: &CompileMetadata,
    record: &VerifiedLoweringRecord,
    source_map: &SourceArtifactMap,
) -> Result<()> {
    let metadata_value = serde_json::to_value(metadata)
        .map_err(|error| boundary_error(format!("failed to serialize metadata for checker: {error}")))?;
    check_bundle_values(artifact, &metadata_value, record, source_map, &CheckerBudgets::default())
        .map_err(|error| boundary_error(error.to_string()))?;
    Ok(())
}

fn build_entries(metadata: &CompileMetadata, frame_sizes: &BTreeMap<String, u32>, owners: &[String]) -> Result<Vec<LoweringEntry>> {
    let first_block_by_owner = owners.iter().enumerate().fold(BTreeMap::<String, usize>::new(), |mut map, (index, owner)| {
        map.entry(owner.clone()).or_insert(index);
        map
    });
    let mut entries = Vec::new();
    for owner in first_block_by_owner.keys() {
        let (kind, params, return_type, effect) = if let Some(action) = metadata.actions.iter().find(|entry| entry.name == *owner) {
            (
                EntryKind::Action,
                action.params.as_slice(),
                action.return_type.clone().unwrap_or_else(|| "unit".to_string()),
                action.effect_class.clone(),
            )
        } else if let Some(lock) = metadata.locks.iter().find(|entry| entry.name == *owner) {
            (EntryKind::Lock, lock.params.as_slice(), "bool".to_string(), "lock-predicate".to_string())
        } else if let Some(function) = metadata.functions.iter().find(|entry| entry.name == *owner) {
            (
                EntryKind::Helper,
                function.params.as_slice(),
                function.return_type.clone().unwrap_or_else(|| "unit".to_string()),
                function.effect_class.clone(),
            )
        } else if owner == "_cellscript_entry" {
            (EntryKind::Wrapper, &[][..], "i32".to_string(), "entry-wrapper".to_string())
        } else {
            (EntryKind::Runtime, &[][..], "i32".to_string(), "runtime-helper".to_string())
        };
        let id = entry_id(kind, owner);
        let frame_size_bytes = frame_sizes.get(owner).copied().unwrap_or(0);
        let outgoing_argument_bytes = u32::try_from(params.len().saturating_sub(8).saturating_mul(8)).unwrap_or(u32::MAX);
        if outgoing_argument_bytes > frame_size_bytes && frame_size_bytes != 0 {
            return Err(boundary_error(format!("entry '{owner}' outgoing ABI exceeds its captured frame")));
        }
        entries.push(LoweringEntry {
            id,
            kind,
            name: owner.clone(),
            entry_block: machine_block_id(first_block_by_owner[owner]),
            params: params.iter().enumerate().map(|(index, param)| typed_parameter(index, param)).collect(),
            return_type,
            effect,
            capabilities: Vec::new(),
            proof_ids: Vec::new(),
            frame_size_bytes,
            outgoing_argument_bytes: outgoing_argument_bytes.min(frame_size_bytes),
            typed_blocks: Vec::new(),
        });
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(entries)
}

fn bind_typed_blocks(entries: &mut [LoweringEntry], blocks: &[LoweringBlock], metadata: &CompileMetadata) -> Result<()> {
    for entry in entries {
        let Some(typed_entry) = metadata.typed_semantics.entries.iter().find(|typed| typed.id == entry.id) else {
            continue;
        };
        entry.typed_blocks = typed_entry
            .blocks
            .iter()
            .map(|typed_block| {
                let hash =
                    canonical_hash("cellscript-typed-block-v1", typed_block).map_err(|error| boundary_error(error.to_string()))?;
                let machine_block_ids = blocks
                    .iter()
                    .filter(|block| block.owner_entry == entry.id && block.lowering_block_id == Some(typed_block.id))
                    .map(|block| block.id.clone())
                    .collect();
                Ok(TypedBlockBinding { id: typed_block.id, hash, machine_block_ids })
            })
            .collect::<Result<Vec<_>>>()?;
    }
    Ok(())
}

fn complete_frame_sizes(
    layout: &MachineLayoutEvidence,
    elf: &cellscript_artifact_checker::ParsedElf,
    owners: &[String],
) -> Result<BTreeMap<String, u32>> {
    let mut sizes = layout.entry_frame_sizes.clone();
    let mut negative_adjustments = BTreeMap::<String, u64>::new();
    for (index, block) in layout.blocks.iter().enumerate() {
        let owner = owners.get(index).ok_or_else(|| boundary_error("machine block owner map is incomplete"))?;
        let total = elf
            .stack_adjustments
            .iter()
            .filter(|adjustment| block.start <= adjustment.address && adjustment.address < block.end && adjustment.delta < 0)
            .try_fold(0_u64, |total, adjustment| total.checked_add(adjustment.delta.unsigned_abs()))
            .ok_or_else(|| boundary_error(format!("captured frame size for '{owner}' overflows u64")))?;
        let accumulated = negative_adjustments.entry(owner.clone()).or_default();
        *accumulated = accumulated
            .checked_add(total)
            .ok_or_else(|| boundary_error(format!("captured frame size for '{owner}' overflows u64")))?;
    }
    for (owner, inferred) in negative_adjustments {
        let inferred =
            u32::try_from(inferred).map_err(|_| boundary_error(format!("captured frame size for '{owner}' exceeds u32")))?;
        sizes.entry(owner).and_modify(|size| *size = (*size).max(inferred)).or_insert(inferred);
    }
    Ok(sizes)
}

fn build_proof_records(metadata: &CompileMetadata, owner_ids: &BTreeMap<String, String>) -> Vec<ProofRecord> {
    let mut records = Vec::new();
    for action in &metadata.actions {
        append_entry_proofs(&mut records, owner_ids.get(&action.name), &action.proof_plan);
    }
    for lock in &metadata.locks {
        append_entry_proofs(&mut records, owner_ids.get(&lock.name), &lock.proof_plan);
    }
    for function in &metadata.functions {
        append_entry_proofs(&mut records, owner_ids.get(&function.name), &function.proof_plan);
    }
    records.sort_by(|a, b| a.id.cmp(&b.id));
    records
}

fn append_entry_proofs(output: &mut Vec<ProofRecord>, entry_id: Option<&String>, plans: &[crate::ProofPlanMetadata]) {
    let Some(entry_id) = entry_id else {
        return;
    };
    for (index, plan) in plans.iter().enumerate() {
        output.push(ProofRecord {
            id: format!("proof:{entry_id}:{index:05}"),
            entry_id: entry_id.clone(),
            obligation: format!("{}:{}:{}", plan.name, plan.category, plan.status),
            evidence_tier: plan.evidence_tier.as_str().to_string(),
        });
    }
}

fn block_owners(layout: &MachineLayoutEvidence) -> Result<Vec<String>> {
    let text_globals = layout.globals.iter().filter(|name| layout.symbols.contains_key(*name)).cloned().collect::<BTreeSet<_>>();
    let mut current = None::<String>;
    let mut owners = Vec::with_capacity(layout.blocks.len());
    for block in &layout.blocks {
        if let Some(label) = block.label.as_ref().filter(|label| text_globals.contains(*label)) {
            current = Some(label.clone());
        }
        let owner = current
            .clone()
            .ok_or_else(|| boundary_error(format!("machine block {} precedes every global entry label", block.index)))?;
        owners.push(owner);
    }
    Ok(owners)
}

fn runtime_error_exits(layout: &MachineLayoutEvidence, blocks: &[LoweringBlock]) -> Vec<RuntimeErrorExit> {
    let mut exits = layout
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(index, machine)| {
            machine.runtime_error_codes.iter().filter_map(move |code| {
                let raw_code = *code;
                let code = i32::try_from(raw_code).ok()?;
                let block = blocks.get(index)?;
                let error = crate::runtime_errors::CellScriptRuntimeError::from_code(raw_code)?;
                Some(RuntimeErrorExit { block_id: block.id.clone(), address: block.range.start, code, name: error.name().to_string() })
            })
        })
        .chain(layout.symbols.iter().filter_map(|(label, address)| {
            let (_, code) = label.rsplit_once("_fail_")?;
            let code = code.parse::<i32>().ok()?;
            let block = blocks.iter().find(|block| block.range.contains(*address))?;
            Some(RuntimeErrorExit {
                block_id: block.id.clone(),
                address: *address,
                code,
                name: format!("cellscript-runtime-error-{code}"),
            })
        }))
        .collect::<Vec<_>>();
    exits.sort_by(|a, b| (&a.block_id, a.code, a.address).cmp(&(&b.block_id, b.code, b.address)));
    exits.dedup_by(|a, b| a.block_id == b.block_id && a.code == b.code && a.address == b.address);
    exits
}

fn verifier_failure_exits(layout: &MachineLayoutEvidence, blocks: &[LoweringBlock]) -> Result<Vec<RuntimeErrorExit>> {
    let mut exits = Vec::new();
    for (label, address) in &layout.symbols {
        let Some(suffix) = label.strip_prefix(".Lverifier_failure_") else { continue };
        let code = suffix
            .split('_')
            .next()
            .and_then(|code| code.parse::<u64>().ok())
            .ok_or_else(|| boundary_error("invalid terminal verifier failure label"))?;
        let error = crate::runtime_errors::CellScriptRuntimeError::from_code(code)
            .ok_or_else(|| boundary_error("unknown terminal verifier failure code"))?;
        let block = blocks
            .iter()
            .find(|block| block.range.contains(*address))
            .ok_or_else(|| boundary_error("terminal verifier failure lies outside machine coverage"))?;
        exits.push(RuntimeErrorExit {
            block_id: block.id.clone(),
            address: *address,
            code: code as i32,
            name: error.name().to_string(),
        });
    }
    exits.sort_by_key(|exit| exit.address);
    Ok(exits)
}

fn compatibility_profile_identity(metadata: &CompileMetadata) -> CompatibilityProfileIdentity {
    let profile = &metadata.compatibility_profile;
    CompatibilityProfileIdentity {
        schema: profile.schema.clone(),
        id: profile.id.clone(),
        edition: profile.edition.as_str().to_string(),
        source_semantics: profile.source_semantics.clone(),
        target_profile: profile.target_profile.clone(),
        primitive_assurance: profile.primitive_assurance.clone(),
        metadata_schema_version: profile.metadata_schema_version,
        source_metadata_schema_version: profile.source_metadata_schema_version,
        artifact_metadata_schema_version: profile.artifact_metadata_schema_version,
        constraints_metadata_schema_version: profile.constraints_metadata_schema_version,
        entry_witness_payload_abi: profile.entry_witness_payload_abi.clone(),
        entry_witness_placement_abi: profile.entry_witness_placement_abi.clone(),
        entry_witness_placement_field: profile.entry_witness_placement_field.clone(),
        entry_witness_placement_source: profile.entry_witness_placement_source.clone(),
        raw_entry_witness_payload_compatible: profile.raw_entry_witness_payload_compatible,
    }
}

fn typed_parameter(index: usize, param: &ParamMetadata) -> TypedParameter {
    let (storage, width_bytes, alignment_bytes) = parameter_storage(param);
    TypedParameter {
        index: u32::try_from(index).unwrap_or(u32::MAX),
        name: param.name.clone(),
        ty: param.ty.clone(),
        storage,
        width_bytes,
        alignment_bytes,
    }
}

fn parameter_storage(param: &ParamMetadata) -> (StorageClass, u32, u32) {
    if param.schema_pointer_abi {
        return (StorageClass::SchemaPointer, 8, 8);
    }
    if param.is_ref {
        return (StorageClass::Reference, 8, 8);
    }
    if param.fixed_byte_pointer_abi {
        let width = u32::try_from(param.fixed_byte_len.unwrap_or(8)).unwrap_or(u32::MAX);
        return (StorageClass::FixedBytes, width.max(1), width.next_power_of_two().min(16));
    }
    let width = match param.ty.as_str() {
        "u8" | "bool" => 1,
        "u16" => 2,
        "u32" | "i32" => 4,
        "u128" => 16,
        "address" | "hash" => 32,
        _ => 8,
    };
    let storage = if width > 8 { StorageClass::FixedBytes } else { StorageClass::Scalar };
    (storage, width, width.next_power_of_two().min(16))
}

fn entry_id(kind: EntryKind, name: &str) -> String {
    let prefix = match kind {
        EntryKind::Action => "action",
        EntryKind::Lock => "lock",
        EntryKind::Helper => "helper",
        EntryKind::Runtime => "runtime",
        EntryKind::Wrapper => "wrapper",
    };
    format!("{prefix}:{name}")
}

fn machine_block_id(index: usize) -> String {
    format!("mb{index:06}")
}

fn lowering_block_id(label: Option<&str>, owner: &str) -> Option<u32> {
    let prefix = format!(".L{owner}_block_");
    label?.strip_prefix(&prefix)?.parse().ok()
}

fn stable_entry_source_path(metadata: &CompileMetadata) -> String {
    let unit = metadata
        .source_units
        .iter()
        .find(|unit| matches!(unit.role.as_str(), "entry" | "memory"))
        .or_else(|| metadata.source_units.first());
    let Some(unit) = unit else {
        return "<memory>".to_string();
    };
    if unit.path == "<memory>" {
        return unit.path.clone();
    }
    let file_name = unit.path.rsplit(['/', '\\']).next().filter(|name| !name.is_empty()).unwrap_or("module.cell");
    format!("source/{file_name}")
}

fn boundary_error(message: impl Into<String>) -> CompileError {
    CompileError::without_span(format!("verified artifact boundary: {}", message.into())).with_code("E2400")
}
