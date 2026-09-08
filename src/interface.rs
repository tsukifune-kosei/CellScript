//! Canonical public package interfaces and deterministic compatibility reports.
//!
//! This module intentionally depends on source AST plus already-checked compile
//! metadata. It does not infer authority from names: exported signatures,
//! layouts, effects, Cell capabilities, builder inputs, and deployment ABI are
//! recorded as separate compatibility dimensions.

use crate::ast::{self, Item, TypeParam};
use crate::error::{CompileError, Result};
use crate::{ckb_blake2b256, CompileMetadata};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const INTERFACE_SCHEMA: &str = "cellscript-package-interface-v3";
pub const INTERFACE_SCHEMA_VERSION: u32 = 3;
pub const COMPATIBILITY_SCHEMA: &str = "cellscript-interface-compatibility-v1";
pub const TEMPORAL_INTERFACE_SCHEMA: &str = "cellscript-ckb-temporal-interface-v1";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageInterface {
    pub schema: String,
    pub version: u32,
    pub module: String,
    pub module_identity: String,
    pub edition: String,
    pub visibility_default: String,
    pub types: Vec<InterfaceType>,
    pub constants: Vec<InterfaceConstant>,
    pub callables: Vec<InterfaceCallable>,
    pub runtime_contract: InterfaceRuntimeContract,
    pub builder_contract_hash: String,
    pub deployment_contract_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceType {
    pub identity: String,
    pub name: String,
    pub kind: String,
    pub visibility: String,
    pub type_parameters: Vec<InterfaceTypeParameter>,
    pub value_abilities: Vec<String>,
    pub cell_capabilities: Vec<String>,
    pub fields: Vec<InterfaceField>,
    pub variants: Vec<InterfaceVariant>,
    pub layout_identity: String,
    pub type_identity: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceTypeParameter {
    pub name: String,
    pub phantom: bool,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceField {
    pub name: String,
    pub r#type: String,
    pub offset: Option<usize>,
    pub encoded_size: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceVariant {
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceConstant {
    pub identity: String,
    pub name: String,
    pub visibility: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceCallable {
    pub identity: String,
    pub name: String,
    pub kind: String,
    pub visibility: String,
    pub type_parameters: Vec<InterfaceTypeParameter>,
    pub params: Vec<InterfaceParam>,
    pub return_type: Option<String>,
    pub outputs: Vec<InterfaceParam>,
    pub effect: String,
    pub entry_witness_abi: Option<String>,
    pub builder_contract_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceParam {
    pub name: String,
    pub r#type: String,
    pub source: String,
    pub mutable: bool,
    pub reference: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceRuntimeContract {
    pub target_profile: String,
    pub vm_abi: String,
    pub witness_abi: String,
    pub lock_args_abi: String,
    pub source_encoding: String,
    pub spawn_ipc_abi: String,
    pub compatibility_profile_id: String,
    #[serde(default)]
    pub temporal: InterfaceTemporalContract,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceTemporalContract {
    pub schema: String,
    pub wire_representation: String,
    pub since_abi: String,
    pub constructors: Vec<String>,
    pub decoder: String,
    pub domains: Vec<String>,
    pub migration: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceCompatibilityReport {
    pub schema: String,
    pub version: u32,
    pub old_interface_hash: String,
    pub new_interface_hash: String,
    pub compatible: bool,
    pub dimensions: Vec<CompatibilityDimension>,
    pub changes: Vec<CompatibilityChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityDimension {
    pub dimension: String,
    pub classification: String,
    pub breaking_changes: usize,
    pub compatible_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityChange {
    pub code: String,
    pub dimension: String,
    pub classification: String,
    pub item: String,
    pub detail: String,
}

pub fn build(ast: &ast::Module, metadata: &CompileMetadata) -> PackageInterface {
    let metadata_types = metadata.types.iter().map(|ty| (ty.name.as_str(), ty)).collect::<BTreeMap<_, _>>();
    let action_metadata = metadata.actions.iter().map(|item| (item.name.as_str(), item)).collect::<BTreeMap<_, _>>();
    let function_metadata = metadata.functions.iter().map(|item| (item.name.as_str(), item)).collect::<BTreeMap<_, _>>();
    let lock_metadata = metadata.locks.iter().map(|item| (item.name.as_str(), item)).collect::<BTreeMap<_, _>>();

    let mut types = Vec::new();
    let mut constants = Vec::new();
    let mut callables = Vec::new();
    let items = ast.items.iter().chain(ast.interface_templates.iter());
    for item in items {
        let Some(name) = item.name() else { continue };
        if crate::generics::decode_monomorph_name(name).is_some() {
            continue;
        }
        let visibility = ast.visibility_of(name);
        if !visibility.is_exported() {
            continue;
        }
        let identity = canonical_item_identity(&ast.name, name);
        match item {
            Item::Resource(def) => types.push(interface_structural_type(
                &identity,
                name,
                "resource",
                visibility.as_str(),
                &[],
                &[],
                &def.capabilities.iter().map(|item| item.as_str().to_string()).collect::<Vec<_>>(),
                &def.fields,
                &[],
                def.type_id.as_ref().map(|item| item.value.clone()),
                metadata_types.get(name).copied(),
            )),
            Item::Shared(def) => types.push(interface_structural_type(
                &identity,
                name,
                "shared",
                visibility.as_str(),
                &[],
                &[],
                &def.capabilities.iter().map(|item| item.as_str().to_string()).collect::<Vec<_>>(),
                &def.fields,
                &[],
                def.type_id.as_ref().map(|item| item.value.clone()),
                metadata_types.get(name).copied(),
            )),
            Item::Receipt(def) => types.push(interface_structural_type(
                &identity,
                name,
                "receipt",
                visibility.as_str(),
                &[],
                &[],
                &def.capabilities.iter().map(|item| item.as_str().to_string()).collect::<Vec<_>>(),
                &def.fields,
                &[],
                def.type_id.as_ref().map(|item| item.value.clone()),
                metadata_types.get(name).copied(),
            )),
            Item::Struct(def) => types.push(interface_structural_type(
                &identity,
                name,
                "struct",
                visibility.as_str(),
                &def.type_params,
                &def.abilities.iter().map(|item| item.as_str().to_string()).collect::<Vec<_>>(),
                &[],
                &def.fields,
                &[],
                def.type_id.as_ref().map(|item| item.value.clone()),
                metadata_types.get(name).copied(),
            )),
            Item::Enum(def) => {
                let variants = def
                    .variants
                    .iter()
                    .map(|variant| InterfaceVariant {
                        name: variant.name.clone(),
                        fields: variant.fields.iter().map(crate::generics::render_source_type).collect(),
                    })
                    .collect::<Vec<_>>();
                types.push(interface_structural_type(
                    &identity,
                    name,
                    "enum",
                    visibility.as_str(),
                    &def.type_params,
                    &def.abilities.iter().map(|item| item.as_str().to_string()).collect::<Vec<_>>(),
                    &[],
                    &[],
                    &variants,
                    None,
                    metadata_types.get(name).copied(),
                ));
            }
            Item::Const(def) => constants.push(InterfaceConstant {
                identity,
                name: name.to_string(),
                visibility: visibility.as_str().to_string(),
                r#type: crate::generics::render_source_type(&def.ty),
            }),
            Item::Action(def) => {
                let params = source_params(&def.params);
                let outputs = def
                    .outputs
                    .iter()
                    .map(|output| InterfaceParam {
                        name: output.name.clone(),
                        r#type: crate::generics::render_source_type(&output.ty),
                        source: "output".to_string(),
                        mutable: false,
                        reference: false,
                    })
                    .collect::<Vec<_>>();
                let builder_contract_hash = action_metadata
                    .get(name)
                    .map(|item| hash_serializable(&(item.params.clone(), item.transaction_runtime_input_requirements.clone())))
                    .unwrap_or_else(|| hash_serializable(&(params.clone(), outputs.clone())));
                callables.push(InterfaceCallable {
                    identity,
                    name: name.to_string(),
                    kind: "action".to_string(),
                    visibility: visibility.as_str().to_string(),
                    type_parameters: Vec::new(),
                    params,
                    return_type: def.return_type.as_ref().map(crate::generics::render_source_type),
                    outputs,
                    effect: format!("{:?}", def.effect),
                    entry_witness_abi: Some(metadata.target_profile.witness_abi.clone()),
                    builder_contract_hash,
                });
            }
            Item::Function(def) => {
                let params = source_params(&def.params);
                let builder_contract_hash = function_metadata
                    .get(name)
                    .map(|item| hash_serializable(&(item.params.clone(), item.transaction_runtime_input_requirements.clone())))
                    .unwrap_or_else(|| hash_serializable(&params));
                callables.push(InterfaceCallable {
                    identity,
                    name: name.to_string(),
                    kind: "function".to_string(),
                    visibility: visibility.as_str().to_string(),
                    type_parameters: type_parameters(&def.type_params),
                    params,
                    return_type: def.return_type.as_ref().map(crate::generics::render_source_type),
                    outputs: Vec::new(),
                    effect: format!("{:?}", def.effect),
                    entry_witness_abi: None,
                    builder_contract_hash,
                });
            }
            Item::Lock(def) => {
                let params = source_params(&def.params);
                let builder_contract_hash = lock_metadata
                    .get(name)
                    .map(|item| hash_serializable(&(item.params.clone(), item.transaction_runtime_input_requirements.clone())))
                    .unwrap_or_else(|| hash_serializable(&params));
                callables.push(InterfaceCallable {
                    identity,
                    name: name.to_string(),
                    kind: "lock".to_string(),
                    visibility: visibility.as_str().to_string(),
                    type_parameters: Vec::new(),
                    params,
                    return_type: Some(crate::generics::render_source_type(&def.return_type)),
                    outputs: Vec::new(),
                    effect: "ReadOnly".to_string(),
                    entry_witness_abi: Some(metadata.target_profile.witness_abi.clone()),
                    builder_contract_hash,
                });
            }
            Item::Flow(_) | Item::Invariant(_) | Item::Use(_) => {}
        }
    }

    types.sort_by(|left, right| left.identity.cmp(&right.identity));
    types.dedup_by(|left, right| left.identity == right.identity);
    constants.sort_by(|left, right| left.identity.cmp(&right.identity));
    callables.sort_by(|left, right| left.identity.cmp(&right.identity));
    callables.dedup_by(|left, right| left.identity == right.identity);

    let runtime_contract = InterfaceRuntimeContract {
        target_profile: metadata.target_profile.name.clone(),
        vm_abi: metadata.target_profile.vm_abi.clone(),
        witness_abi: metadata.target_profile.witness_abi.clone(),
        lock_args_abi: metadata.target_profile.lock_args_abi.clone(),
        source_encoding: metadata.target_profile.source_encoding.clone(),
        spawn_ipc_abi: metadata.target_profile.spawn_ipc_abi.clone(),
        compatibility_profile_id: metadata.compatibility_profile.id.clone(),
        temporal: temporal_contract(&metadata.target_profile.since_abi),
    };
    let builder_contract_hash =
        hash_serializable(&callables.iter().map(|item| (&item.identity, &item.builder_contract_hash)).collect::<Vec<_>>());
    let deployment_contract_hash = hash_serializable(&runtime_contract);
    PackageInterface {
        schema: INTERFACE_SCHEMA.to_string(),
        version: INTERFACE_SCHEMA_VERSION,
        module: ast.name.clone(),
        module_identity: module_identity(&ast.name),
        edition: metadata.edition.to_string(),
        visibility_default: "legacy-public (Edition 2026 compatibility)".to_string(),
        types,
        constants,
        callables,
        runtime_contract,
        builder_contract_hash,
        deployment_contract_hash,
    }
}

pub fn temporal_contract(since_abi: &str) -> InterfaceTemporalContract {
    InterfaceTemporalContract {
        schema: TEMPORAL_INTERFACE_SCHEMA.to_string(),
        wire_representation: "fixed-u64-register-and-little-endian-wire".to_string(),
        since_abi: since_abi.to_string(),
        constructors: vec![
            "ckb::since_absolute_block(u64)->AbsoluteBlockSince".to_string(),
            "ckb::since_absolute_epoch(u64,u64,u64)->AbsoluteEpochSince".to_string(),
            "ckb::since_absolute_timestamp(u64-seconds)->AbsoluteTimestampSince".to_string(),
            "ckb::since_relative_block(u64)->RelativeBlockSince".to_string(),
            "ckb::since_relative_epoch(u64,u64,u64)->RelativeEpochSince".to_string(),
            "ckb::since_relative_timestamp(u64-seconds)->RelativeTimestampSince".to_string(),
        ],
        decoder: "ckb::since_decode(EncodedSince)->DecodedSince;ckb::since_from_raw_checked(u64)->DecodedSince".to_string(),
        domains: vec![
            "EpochNumber".to_string(),
            "EpochDuration".to_string(),
            "BlockNumber".to_string(),
            "EpochLength".to_string(),
            "TimestampMillis".to_string(),
            "EncodedSince".to_string(),
            "DecodedSince".to_string(),
            "AbsoluteBlockSince".to_string(),
            "AbsoluteEpochSince".to_string(),
            "AbsoluteTimestampSince".to_string(),
            "RelativeBlockSince".to_string(),
            "RelativeEpochSince".to_string(),
            "RelativeTimestampSince".to_string(),
        ],
        migration: "legacy-raw-ckb-temporal-to-explicit-typed-v1".to_string(),
    }
}

pub fn hash(interface: &PackageInterface) -> String {
    hash_serializable(interface)
}

/// Validate the dependency-facing generic portion of a canonical package
/// interface without consulting source AST or monomorphized compiler state.
///
/// Version 2 remains readable for historical diffs. Version 3 records the
/// selected public-value-generic boundary in expanded machine form, so every
/// consumer can enforce the same closed ability vocabulary and layout rules.
pub fn validate(interface: &PackageInterface) -> Result<()> {
    if interface.schema == "cellscript-package-interface-v2" && interface.version == 2 {
        return Ok(());
    }
    if interface.schema != INTERFACE_SCHEMA || interface.version != INTERFACE_SCHEMA_VERSION {
        return Err(invalid_interface(format!("unsupported public interface schema '{}'/{}", interface.schema, interface.version)));
    }

    validate_sorted_unique_identities(interface.types.iter().map(|item| item.identity.as_str()), "type")?;
    validate_sorted_unique_identities(interface.constants.iter().map(|item| item.identity.as_str()), "constant")?;
    validate_sorted_unique_identities(interface.callables.iter().map(|item| item.identity.as_str()), "callable")?;
    for item in &interface.types {
        validate_interface_type_parameters(&item.type_parameters, &format!("{}.type_parameters", item.identity), true)?;
        validate_interface_abilities(&item.value_abilities, &format!("{}.value_abilities", item.identity))?;
    }
    for item in &interface.callables {
        validate_interface_type_parameters(&item.type_parameters, &format!("{}.type_parameters", item.identity), false)?;
    }
    Ok(())
}

fn validate_sorted_unique_identities<'a>(identities: impl Iterator<Item = &'a str>, kind: &str) -> Result<()> {
    let mut previous = None::<&str>;
    for identity in identities {
        if identity.is_empty() || previous.is_some_and(|previous| previous >= identity) {
            return Err(invalid_interface(format!(
                "public interface {kind} identities must be non-empty, unique, and canonically ordered"
            )));
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_interface_type_parameters(params: &[InterfaceTypeParameter], label: &str, layout_type: bool) -> Result<()> {
    let mut names = BTreeSet::new();
    for param in params {
        let valid_name = !param.name.is_empty()
            && param.name.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            && param.name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !valid_name || !names.insert(param.name.as_str()) {
            return Err(invalid_interface(format!("{label} has an invalid or duplicate parameter '{}'", param.name)));
        }
        validate_interface_abilities(&param.constraints, &format!("{label}.{}.constraints", param.name))?;
        if layout_type
            && !param.phantom
            && ["fixed", "serializable", "non_linear"]
                .into_iter()
                .any(|required| !param.constraints.iter().any(|constraint| constraint == required))
        {
            return Err(invalid_interface(format!(
                "{label}.{} must preserve the fixed, serializable, non_linear public layout boundary",
                param.name
            )));
        }
    }
    Ok(())
}

fn validate_interface_abilities(abilities: &[String], label: &str) -> Result<()> {
    let canonical = ast::ValueAbility::ALL
        .into_iter()
        .filter(|ability| abilities.iter().any(|candidate| candidate == ability.as_str()))
        .map(|ability| ability.as_str())
        .collect::<Vec<_>>();
    if canonical.len() != abilities.len() || !abilities.iter().map(String::as_str).eq(canonical) {
        return Err(invalid_interface(format!("{label} must contain unique, known value abilities in canonical order")));
    }
    if abilities.iter().any(|ability| ability == "cell") && abilities.iter().any(|ability| ability == "non_linear") {
        return Err(invalid_interface(format!("{label} cannot combine cell and non_linear")));
    }
    Ok(())
}

fn invalid_interface(message: impl Into<String>) -> CompileError {
    CompileError::without_span(message)
}

pub fn compare(old: &PackageInterface, new: &PackageInterface) -> InterfaceCompatibilityReport {
    const DIMENSIONS: [&str; 6] = ["source_api", "serialized_layout", "runtime_abi", "effects_capabilities", "builder", "deployment"];
    let mut changes = Vec::new();
    compare_types(old, new, &mut changes);
    compare_callables(old, new, &mut changes);
    compare_constants(old, new, &mut changes);
    if old.runtime_contract != new.runtime_contract {
        push_breaking(
            &mut changes,
            "ICOMP3001",
            "runtime_abi",
            &new.module_identity,
            "target profile or versioned runtime ABI changed",
        );
    }
    if old.builder_contract_hash != new.builder_contract_hash && !changes.iter().any(|change| change.dimension == "builder") {
        push_breaking(&mut changes, "ICOMP5001", "builder", &new.module_identity, "generated builder contract changed");
    }
    if old.deployment_contract_hash != new.deployment_contract_hash {
        push_breaking(&mut changes, "ICOMP6001", "deployment", &new.module_identity, "deployment identity contract changed");
    }
    changes.sort_by(|left, right| {
        left.dimension.cmp(&right.dimension).then_with(|| left.item.cmp(&right.item)).then_with(|| left.code.cmp(&right.code))
    });
    let dimensions = DIMENSIONS
        .into_iter()
        .map(|dimension| {
            let breaking_changes =
                changes.iter().filter(|change| change.dimension == dimension && change.classification == "breaking").count();
            let compatible_changes =
                changes.iter().filter(|change| change.dimension == dimension && change.classification == "compatible").count();
            CompatibilityDimension {
                dimension: dimension.to_string(),
                classification: if breaking_changes == 0 { "compatible" } else { "breaking" }.to_string(),
                breaking_changes,
                compatible_changes,
            }
        })
        .collect::<Vec<_>>();
    InterfaceCompatibilityReport {
        schema: COMPATIBILITY_SCHEMA.to_string(),
        version: 1,
        old_interface_hash: hash(old),
        new_interface_hash: hash(new),
        compatible: dimensions.iter().all(|dimension| dimension.classification == "compatible"),
        dimensions,
        changes,
    }
}

#[allow(clippy::too_many_arguments)] // Mirrors the audited, canonical InterfaceType field set.
fn interface_structural_type(
    identity: &str,
    name: &str,
    kind: &str,
    visibility: &str,
    params: &[TypeParam],
    value_abilities: &[String],
    cell_capabilities: &[String],
    fields: &[ast::Field],
    variants: &[InterfaceVariant],
    type_identity: Option<String>,
    metadata: Option<&crate::TypeMetadata>,
) -> InterfaceType {
    let fields = fields
        .iter()
        .map(|field| {
            let layout = metadata.and_then(|metadata| metadata.fields.iter().find(|candidate| candidate.name == field.name));
            InterfaceField {
                name: field.name.clone(),
                r#type: crate::generics::render_source_type(&field.ty),
                offset: layout.map(|layout| layout.offset),
                encoded_size: layout.and_then(|layout| layout.encoded_size),
            }
        })
        .collect::<Vec<_>>();
    let layout_identity = hash_serializable(&(kind, &fields, variants));
    InterfaceType {
        identity: identity.to_string(),
        name: name.to_string(),
        kind: kind.to_string(),
        visibility: visibility.to_string(),
        type_parameters: type_parameters(params),
        value_abilities: value_abilities.to_vec(),
        cell_capabilities: cell_capabilities.to_vec(),
        fields,
        variants: variants.to_vec(),
        layout_identity,
        type_identity,
    }
}

fn type_parameters(params: &[TypeParam]) -> Vec<InterfaceTypeParameter> {
    params
        .iter()
        .map(|param| InterfaceTypeParameter {
            name: param.name.clone(),
            phantom: param.phantom,
            constraints: param.constraints.iter().map(|item| item.as_str().to_string()).collect(),
        })
        .collect()
}

fn source_params(params: &[ast::Param]) -> Vec<InterfaceParam> {
    params
        .iter()
        .map(|param| InterfaceParam {
            name: param.name.clone(),
            r#type: crate::generics::render_source_type(&param.ty),
            source: match param.source {
                ast::ParamSource::Default => "default",
                ast::ParamSource::Witness => "witness",
                ast::ParamSource::LockArgs => "lock_args",
                ast::ParamSource::Input => "input",
                ast::ParamSource::Output => "output",
                ast::ParamSource::Protected => "protected",
            }
            .to_string(),
            mutable: param.is_mut,
            reference: param.is_ref || param.is_read_ref,
        })
        .collect()
}

fn canonical_item_identity(module: &str, name: &str) -> String {
    format!("{}::{}", module, name)
}

fn module_identity(module: &str) -> String {
    let mut bytes = b"cellscript-module-identity-v1\0".to_vec();
    bytes.extend_from_slice(module.as_bytes());
    format!("blake2b:{}", hex::encode(ckb_blake2b256(&bytes)))
}

fn hash_serializable(value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("interface records are serializable");
    let canonical = crate::package::registry::canonical_json_value(&value);
    let bytes = serde_json::to_vec(&canonical).expect("canonical interface JSON is serializable");
    hex::encode(ckb_blake2b256(&bytes))
}

fn compare_types(old: &PackageInterface, new: &PackageInterface, changes: &mut Vec<CompatibilityChange>) {
    let old_types = old.types.iter().map(|item| (item.identity.as_str(), item)).collect::<BTreeMap<_, _>>();
    let new_types = new.types.iter().map(|item| (item.identity.as_str(), item)).collect::<BTreeMap<_, _>>();
    for (identity, old_type) in &old_types {
        let Some(new_type) = new_types.get(identity) else {
            push_breaking(changes, "ICOMP1001", "source_api", identity, "exported type was removed or made non-public");
            continue;
        };
        if old_type.kind != new_type.kind {
            push_breaking(changes, "ICOMP1002", "source_api", identity, "exported type kind changed");
        }
        match compare_type_parameters(&old_type.type_parameters, &new_type.type_parameters) {
            TypeParameterChange::Same => {}
            TypeParameterChange::Relaxed => push_compatible(
                changes,
                "ICOMP1104",
                "source_api",
                identity,
                "generic constraints were relaxed while the remaining interface contract stayed independently checked",
            ),
            TypeParameterChange::Breaking => push_breaking(
                changes,
                "ICOMP1002",
                "source_api",
                identity,
                "generic parameter shape or constraints changed incompatibly",
            ),
        }
        if old_type.layout_identity != new_type.layout_identity || old_type.type_identity != new_type.type_identity {
            push_breaking(
                changes,
                "ICOMP2001",
                "serialized_layout",
                identity,
                "serialized fields, variants, offsets, or type identity changed",
            );
        }
        if old_type.value_abilities != new_type.value_abilities || old_type.cell_capabilities != new_type.cell_capabilities {
            push_breaking(
                changes,
                "ICOMP4001",
                "effects_capabilities",
                identity,
                "value abilities or Cell lifecycle capabilities changed",
            );
        }
    }
    for identity in new_types.keys().filter(|identity| !old_types.contains_key(*identity)) {
        push_compatible(changes, "ICOMP1101", "source_api", identity, "exported type was added");
    }
}

fn compare_callables(old: &PackageInterface, new: &PackageInterface, changes: &mut Vec<CompatibilityChange>) {
    let old_items = old.callables.iter().map(|item| (item.identity.as_str(), item)).collect::<BTreeMap<_, _>>();
    let new_items = new.callables.iter().map(|item| (item.identity.as_str(), item)).collect::<BTreeMap<_, _>>();
    for (identity, old_item) in &old_items {
        let Some(new_item) = new_items.get(identity) else {
            push_breaking(changes, "ICOMP1003", "source_api", identity, "exported callable was removed or made non-public");
            continue;
        };
        if old_item.kind != new_item.kind
            || old_item.params != new_item.params
            || old_item.return_type != new_item.return_type
            || old_item.outputs != new_item.outputs
        {
            push_breaking(changes, "ICOMP1004", "source_api", identity, "callable signature changed");
            push_breaking(changes, "ICOMP3002", "runtime_abi", identity, "entry or call ABI changed");
        }
        match compare_type_parameters(&old_item.type_parameters, &new_item.type_parameters) {
            TypeParameterChange::Same => {}
            TypeParameterChange::Relaxed => push_compatible(
                changes,
                "ICOMP1104",
                "source_api",
                identity,
                "generic constraints were relaxed while the remaining interface contract stayed independently checked",
            ),
            TypeParameterChange::Breaking => {
                push_breaking(changes, "ICOMP1004", "source_api", identity, "generic callable parameters changed incompatibly");
                push_breaking(changes, "ICOMP3002", "runtime_abi", identity, "generic call contract changed incompatibly");
            }
        }
        if old_item.entry_witness_abi != new_item.entry_witness_abi {
            push_breaking(changes, "ICOMP3003", "runtime_abi", identity, "entry witness ABI changed");
        }
        if old_item.effect != new_item.effect {
            push_breaking(changes, "ICOMP4002", "effects_capabilities", identity, "declared or inferred effect changed");
        }
        if old_item.builder_contract_hash != new_item.builder_contract_hash {
            push_breaking(changes, "ICOMP5002", "builder", identity, "builder inputs or transaction requirements changed");
        }
    }
    for identity in new_items.keys().filter(|identity| !old_items.contains_key(*identity)) {
        push_compatible(changes, "ICOMP1102", "source_api", identity, "exported callable was added");
        push_compatible(changes, "ICOMP5101", "builder", identity, "builder for a new exported callable was added");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeParameterChange {
    Same,
    Relaxed,
    Breaking,
}

fn compare_type_parameters(old: &[InterfaceTypeParameter], new: &[InterfaceTypeParameter]) -> TypeParameterChange {
    if old.len() != new.len() {
        return TypeParameterChange::Breaking;
    }
    let mut relaxed = false;
    for (old, new) in old.iter().zip(new) {
        if old.name != new.name || old.phantom != new.phantom {
            return TypeParameterChange::Breaking;
        }
        let old_constraints = old.constraints.iter().map(String::as_str).collect::<BTreeSet<_>>();
        let new_constraints = new.constraints.iter().map(String::as_str).collect::<BTreeSet<_>>();
        if !new_constraints.is_subset(&old_constraints) {
            return TypeParameterChange::Breaking;
        }
        relaxed |= old_constraints != new_constraints;
    }
    if relaxed {
        TypeParameterChange::Relaxed
    } else {
        TypeParameterChange::Same
    }
}

fn compare_constants(old: &PackageInterface, new: &PackageInterface, changes: &mut Vec<CompatibilityChange>) {
    let old_items = old.constants.iter().map(|item| (item.identity.as_str(), item)).collect::<BTreeMap<_, _>>();
    let new_items = new.constants.iter().map(|item| (item.identity.as_str(), item)).collect::<BTreeMap<_, _>>();
    let identities = old_items.keys().chain(new_items.keys()).copied().collect::<BTreeSet<_>>();
    for identity in identities {
        match (old_items.get(identity), new_items.get(identity)) {
            (Some(_), None) => {
                push_breaking(changes, "ICOMP1005", "source_api", identity, "exported constant was removed or made non-public")
            }
            (Some(old_item), Some(new_item)) if old_item.r#type != new_item.r#type => {
                push_breaking(changes, "ICOMP1006", "source_api", identity, "exported constant type changed")
            }
            (None, Some(_)) => push_compatible(changes, "ICOMP1103", "source_api", identity, "exported constant was added"),
            _ => {}
        }
    }
}

fn push_breaking(changes: &mut Vec<CompatibilityChange>, code: &str, dimension: &str, item: &str, detail: &str) {
    changes.push(CompatibilityChange {
        code: code.to_string(),
        dimension: dimension.to_string(),
        classification: "breaking".to_string(),
        item: item.to_string(),
        detail: detail.to_string(),
    });
}

fn push_compatible(changes: &mut Vec<CompatibilityChange>, code: &str, dimension: &str, item: &str, detail: &str) {
    changes.push(CompatibilityChange {
        code: code.to_string(),
        dimension: dimension.to_string(),
        classification: "compatible".to_string(),
        item: item.to_string(),
        detail: detail.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile_metadata, lexer, parser, CellScriptEdition};

    fn interface_for_edition(source: &str, edition: CellScriptEdition) -> PackageInterface {
        let ast = if edition == CellScriptEdition::Edition2026 {
            let tokens = lexer::lex(source).unwrap();
            parser::parse(&tokens).unwrap()
        } else {
            crate::frontend::parse(source, edition).unwrap()
        };
        let monomorphized = crate::generics::monomorphize(&ast).unwrap();
        let metadata = compile_metadata(source, edition, None).unwrap();
        build(&monomorphized, &metadata)
    }

    fn interface(source: &str) -> PackageInterface {
        interface_for_edition(source, CellScriptEdition::Edition2026)
    }

    #[test]
    fn visibility_and_interface_hash_are_deterministic() {
        let source = r#"
module api
private struct Hidden { value: u64, }
public struct Box<T: copy + drop + store + fixed + serializable + non_linear> has copy, drop, store, fixed, serializable, non_linear { value: T, }
public fn id<T: copy + drop>(value: T) -> T { return value }
fn use_it() -> u64 { return id<u64>(7) }
"#;
        let first = interface(source);
        let second = interface(source);
        assert_eq!(hash(&first), hash(&second));
        assert!(first.types.iter().all(|item| item.name != "Hidden"));
        assert!(first.types.iter().any(|item| item.name == "Box" && !item.type_parameters.is_empty()));
    }

    #[test]
    fn fixed_value_profile_and_expanded_spelling_share_one_interface_identity() {
        let compact = interface(
            r#"
module api
public struct Pair<T: fixed_value> { left: T, right: T }
public fn first<T: fixed_value>(pair: Pair<T>) -> T { pair.left }
"#,
        );
        let expanded = interface(
            r#"
module api
public struct Pair<T: non_linear + fixed + serializable + copy + store + drop>
    has copy, drop, store, fixed, serializable, non_linear { left: T, right: T }
public fn first<T: copy + drop + store + fixed + serializable + non_linear>(pair: Pair<T>) -> T { pair.left }
"#,
        );
        assert_eq!(compact, expanded);
        assert_eq!(hash(&compact), hash(&expanded));
        let fixed_value = ["copy", "drop", "store", "fixed", "serializable", "non_linear"].map(str::to_string);
        assert_eq!(compact.types[0].type_parameters[0].constraints, fixed_value);
        assert_eq!(compact.types[0].value_abilities, fixed_value);
        validate(&compact).unwrap();
    }

    #[test]
    fn public_interface_validation_rejects_noncanonical_or_unsafe_generic_shapes() {
        let interface = interface("module api\npublic struct Pair<T: fixed_value> { left: T, right: T }\n");

        let mut reordered = interface.clone();
        reordered.types[0].type_parameters[0].constraints.swap(0, 1);
        assert!(validate(&reordered).unwrap_err().message.contains("canonical order"));

        let mut unsafe_layout = interface;
        unsafe_layout.types[0].type_parameters[0].constraints.pop();
        assert!(validate(&unsafe_layout).unwrap_err().message.contains("public layout boundary"));
    }

    #[test]
    fn generic_constraint_diffs_distinguish_relaxing_from_tightening() {
        let baseline = interface("module api\npublic fn id<T: fixed_value>(value: T) -> T { value }\n");
        let mut relaxed = baseline.clone();
        relaxed.callables[0].type_parameters[0].constraints.pop();
        let relaxed_report = compare(&baseline, &relaxed);
        assert!(relaxed_report.compatible);
        assert!(relaxed_report.changes.iter().any(|change| change.code == "ICOMP1104" && change.classification == "compatible"));

        let mut tightened = relaxed.clone();
        tightened.callables[0].type_parameters[0].constraints.push("non_linear".to_string());
        let tightened_report = compare(&relaxed, &tightened);
        assert!(!tightened_report.compatible);
        assert!(tightened_report.changes.iter().any(|change| change.code == "ICOMP1004" && change.dimension == "source_api"));
    }

    #[test]
    fn compatibility_report_separates_additive_and_layout_changes() {
        let old = interface("module api\npublic struct Value { amount: u64, }\n");
        let additive = interface("module api\npublic struct Value { amount: u64, }\npublic fn read() -> u64 { return 1 }\n");
        assert!(compare(&old, &additive).compatible);

        let changed = interface("module api\npublic struct Value { amount: u128, }\n");
        let report = compare(&old, &changed);
        assert!(!report.compatible);
        assert!(report
            .dimensions
            .iter()
            .any(|dimension| dimension.dimension == "serialized_layout" && dimension.classification == "breaking"));
    }

    #[test]
    fn private_monomorphization_use_sites_do_not_change_the_public_interface() {
        let with_private_use = interface(
            r#"
module api
public struct Pair<T: copy + drop + store + fixed + serializable + non_linear>
    has copy, drop, store, fixed, serializable, non_linear { left: T, right: T, }
private fn implementation() -> u64 {
    let pair: Pair<u64> = Pair<u64> { left: 20, right: 22 }
    return pair.left + pair.right
}
"#,
        );
        let without_private_use = interface(
            r#"
module api
public struct Pair<T: copy + drop + store + fixed + serializable + non_linear>
    has copy, drop, store, fixed, serializable, non_linear { left: T, right: T, }
private fn implementation() -> u64 { return 42 }
"#,
        );
        assert_eq!(with_private_use, without_private_use);
        assert!(compare(&with_private_use, &without_private_use).compatible);
    }

    #[test]
    fn temporal_contract_and_typed_signature_changes_are_explicitly_breaking() {
        let raw = interface("module api\npublic fn deadline() -> u64 { return ckb::since_epoch_absolute(1, 0, 1) }\n");
        let typed = interface_for_edition(
            "module api\npublic fn deadline() -> AbsoluteEpochSince { return ckb::since_absolute_epoch(1, 0, 1) }\n",
            CellScriptEdition::Edition2027,
        );
        assert_eq!(typed.schema, INTERFACE_SCHEMA);
        assert_eq!(typed.version, INTERFACE_SCHEMA_VERSION);
        assert_eq!(typed.runtime_contract.temporal.schema, TEMPORAL_INTERFACE_SCHEMA);
        assert_eq!(typed.runtime_contract.temporal.since_abi, "ckb-since-rfc0017-typed-v1");
        assert!(typed.runtime_contract.temporal.constructors.iter().any(|constructor| constructor.contains("AbsoluteEpochSince")));
        assert!(typed.runtime_contract.temporal.decoder.contains("since_decode"));
        assert!(typed.runtime_contract.temporal.domains.contains(&"TimestampMillis".to_string()));

        let report = compare(&raw, &typed);
        assert!(!report.compatible);
        assert!(report.changes.iter().any(|change| change.code == "ICOMP1004" && change.dimension == "source_api"));

        let mut legacy_value = serde_json::to_value(&typed).unwrap();
        legacy_value["schema"] = serde_json::json!("cellscript-package-interface-v2");
        legacy_value["version"] = serde_json::json!(2);
        legacy_value["runtime_contract"].as_object_mut().unwrap().remove("temporal");
        let legacy: PackageInterface = serde_json::from_value(legacy_value).expect("v2 interface remains readable");
        assert_eq!(legacy.runtime_contract.temporal, InterfaceTemporalContract::default());
        let report = compare(&legacy, &typed);
        assert!(!report.compatible);
        assert!(report.changes.iter().any(|change| change.code == "ICOMP3001" && change.dimension == "runtime_abi"));
    }
}
