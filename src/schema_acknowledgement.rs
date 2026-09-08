//! Focused review receipts for `same except` schema evolution.
//!
//! A receipt is off-chain review evidence. It binds one old/new schema pair
//! and one canonical authoring relation, but it does not authorize a package,
//! deployment, or on-chain migration. Newly added fields must be assigned
//! explicitly before an acknowledgement can be created; implicit preservation
//! remains a blocking migration decision.

use crate::ast::{ActionDef, Expr, Item, ReplaceDataTreatment, ReplaceRelation, Stmt, Type};
use crate::error::{CompileError, Result};
use crate::CompileResult;
use cellscript_artifact_checker::canonical_hash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA_CHANGE_PLAN_SCHEMA: &str = "cellscript-schema-change-plan-v1";
pub const SCHEMA_ACKNOWLEDGEMENT_SCHEMA: &str = "cellscript-schema-acknowledgement-v1";
const SCHEMA_IDENTITY_DOMAIN: &str = "cellscript-authoring-schema-identity-v1";
const RELATION_IDENTITY_DOMAIN: &str = "cellscript-authoring-relation-identity-v1";
const PLAN_HASH_DOMAIN: &str = "cellscript-schema-change-plan-hash-v1";
const ACKNOWLEDGEMENT_HASH_DOMAIN: &str = "cellscript-schema-acknowledgement-hash-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaRelationSelector {
    pub action: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaFieldPolicy {
    pub treatment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaFieldChange {
    pub field: String,
    pub classification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_policy: Option<SchemaFieldPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_policy: Option<SchemaFieldPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaAcknowledgementBlocker {
    pub code: String,
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaChangePlan {
    pub schema: String,
    pub version: u32,
    pub module: String,
    pub selector: SchemaRelationSelector,
    pub resource_type: String,
    pub old_interface_hash: String,
    pub new_interface_hash: String,
    pub old_schema_identity: String,
    pub new_schema_identity: String,
    pub old_relation_identity: String,
    pub new_relation_identity: String,
    pub requires_acknowledgement: bool,
    pub state_migration_required: bool,
    pub field_changes: Vec<SchemaFieldChange>,
    pub blockers: Vec<SchemaAcknowledgementBlocker>,
    pub plan_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaAcknowledgementReceipt {
    pub schema: String,
    pub version: u32,
    pub plan_hash: String,
    pub module: String,
    pub selector: SchemaRelationSelector,
    pub resource_type: String,
    pub old_schema_identity: String,
    pub new_schema_identity: String,
    pub old_relation_identity: String,
    pub new_relation_identity: String,
    pub review_policy: String,
    pub reviewer: String,
    pub rationale: String,
    pub field_changes: Vec<SchemaFieldChange>,
    pub acknowledgement_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaIdentity<'a> {
    resource_type: &'a str,
    encoded_size: Option<u32>,
    fields: Vec<SchemaIdentityField<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaIdentityField<'a> {
    name: &'a str,
    ty: &'a str,
    offset: u32,
    width_bytes: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct RelationIdentity<'a> {
    before: &'a str,
    after: &'a str,
    data: &'static str,
    fields: &'a BTreeMap<String, SchemaFieldPolicy>,
    lock: String,
    capacity: &'static str,
    identity: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PlanHashPayload<'a> {
    schema: &'a str,
    version: u32,
    module: &'a str,
    selector: &'a SchemaRelationSelector,
    resource_type: &'a str,
    old_interface_hash: &'a str,
    new_interface_hash: &'a str,
    old_schema_identity: &'a str,
    new_schema_identity: &'a str,
    old_relation_identity: &'a str,
    new_relation_identity: &'a str,
    requires_acknowledgement: bool,
    state_migration_required: bool,
    field_changes: &'a [SchemaFieldChange],
    blockers: &'a [SchemaAcknowledgementBlocker],
}

#[derive(Debug, Clone, Serialize)]
struct AcknowledgementHashPayload<'a> {
    schema: &'a str,
    version: u32,
    plan_hash: &'a str,
    module: &'a str,
    selector: &'a SchemaRelationSelector,
    resource_type: &'a str,
    old_schema_identity: &'a str,
    new_schema_identity: &'a str,
    old_relation_identity: &'a str,
    new_relation_identity: &'a str,
    review_policy: &'a str,
    reviewer: &'a str,
    rationale: &'a str,
    field_changes: &'a [SchemaFieldChange],
}

pub fn build_schema_change_plan(
    old: &CompileResult,
    new: &CompileResult,
    selector: SchemaRelationSelector,
) -> Result<SchemaChangePlan> {
    if old.metadata.module != new.metadata.module {
        return Err(CompileError::without_span(format!(
            "schema acknowledgement compares one module identity; old '{}' differs from new '{}'",
            old.metadata.module, new.metadata.module
        )));
    }
    let old_action = find_action(&old.ast, &selector.action, "old")?;
    let new_action = find_action(&new.ast, &selector.action, "new")?;
    let old_relation = find_relation(old_action, &selector, "old")?;
    let new_relation = find_relation(new_action, &selector, "new")?;
    let old_resource = relation_resource_type(old_action, &selector, "old")?;
    let new_resource = relation_resource_type(new_action, &selector, "new")?;
    if old_resource != new_resource {
        return Err(CompileError::without_span(format!(
            "schema acknowledgement relation resource changed from '{old_resource}' to '{new_resource}'"
        )));
    }

    let old_schema = typed_schema(old, &old_resource, "old")?;
    let new_schema = typed_schema(new, &new_resource, "new")?;
    let old_schema_identity = hash_schema_identity(&old_resource, old_schema)?;
    let new_schema_identity = hash_schema_identity(&new_resource, new_schema)?;
    let old_policies = relation_policies(old_relation, old_schema)?;
    let new_policies = relation_policies(new_relation, new_schema)?;
    let old_relation_identity = hash_relation_identity(old_relation, &old_policies)?;
    let new_relation_identity = hash_relation_identity(new_relation, &new_policies)?;

    let old_types = old_schema.fields.iter().map(|field| (field.name.as_str(), field.ty.as_str())).collect::<BTreeMap<_, _>>();
    let new_types = new_schema.fields.iter().map(|field| (field.name.as_str(), field.ty.as_str())).collect::<BTreeMap<_, _>>();
    let names = old_types.keys().chain(new_types.keys()).copied().collect::<BTreeSet<_>>();
    let mut field_changes = Vec::new();
    let mut blockers = Vec::new();
    for name in names {
        let old_type = old_types.get(name).copied();
        let new_type = new_types.get(name).copied();
        let old_policy = old_policies.get(name);
        let new_policy = new_policies.get(name);
        let classification = match (old_type, new_type) {
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(old), Some(new)) if old != new => "type-changed",
            _ if old_policy != new_policy => "policy-changed",
            _ => continue,
        };
        if classification == "added" && new_policy.is_some_and(|policy| policy.treatment == "preserve") {
            blockers.push(SchemaAcknowledgementBlocker {
                code: "SACK1001".to_string(),
                field: name.to_string(),
                message: format!(
                    "new field '{name}' is implicitly preserved by `same except`; assign it explicitly before acknowledging the schema change"
                ),
            });
        }
        field_changes.push(SchemaFieldChange {
            field: name.to_string(),
            classification: classification.to_string(),
            old_type: old_type.map(str::to_string),
            new_type: new_type.map(str::to_string),
            old_policy: old_policy.cloned(),
            new_policy: new_policy.cloned(),
        });
    }
    blockers.sort_by(|left, right| left.field.cmp(&right.field).then(left.code.cmp(&right.code)));
    let requires_acknowledgement = old_schema_identity != new_schema_identity;
    let state_migration_required = requires_acknowledgement;
    let mut plan = SchemaChangePlan {
        schema: SCHEMA_CHANGE_PLAN_SCHEMA.to_string(),
        version: 1,
        module: old.metadata.module.clone(),
        selector,
        resource_type: old_resource,
        old_interface_hash: old.metadata.interface_hash.clone(),
        new_interface_hash: new.metadata.interface_hash.clone(),
        old_schema_identity,
        new_schema_identity,
        old_relation_identity,
        new_relation_identity,
        requires_acknowledgement,
        state_migration_required,
        field_changes,
        blockers,
        plan_hash: String::new(),
    };
    plan.plan_hash = plan_hash(&plan)?;
    Ok(plan)
}

pub fn acknowledge_schema_change(
    plan: &SchemaChangePlan,
    reviewer: impl Into<String>,
    rationale: impl Into<String>,
) -> Result<SchemaAcknowledgementReceipt> {
    validate_plan(plan)?;
    if !plan.requires_acknowledgement {
        return Err(CompileError::without_span("schema-change plan does not require an acknowledgement"));
    }
    if !plan.blockers.is_empty() {
        return Err(CompileError::without_span(format!(
            "schema-change plan has blocking field treatments: {}",
            plan.blockers.iter().map(|blocker| format!("{} {}", blocker.code, blocker.field)).collect::<Vec<_>>().join(", ")
        )));
    }
    let reviewer = reviewer.into().trim().to_string();
    let rationale = rationale.into().trim().to_string();
    if reviewer.is_empty() || rationale.is_empty() {
        return Err(CompileError::without_span("schema acknowledgement requires a non-empty reviewer and rationale"));
    }
    let mut receipt = SchemaAcknowledgementReceipt {
        schema: SCHEMA_ACKNOWLEDGEMENT_SCHEMA.to_string(),
        version: 1,
        plan_hash: plan.plan_hash.clone(),
        module: plan.module.clone(),
        selector: plan.selector.clone(),
        resource_type: plan.resource_type.clone(),
        old_schema_identity: plan.old_schema_identity.clone(),
        new_schema_identity: plan.new_schema_identity.clone(),
        old_relation_identity: plan.old_relation_identity.clone(),
        new_relation_identity: plan.new_relation_identity.clone(),
        review_policy: "reviewed-explicit-field-treatment-delta-v1".to_string(),
        reviewer,
        rationale,
        field_changes: plan.field_changes.clone(),
        acknowledgement_hash: String::new(),
    };
    receipt.acknowledgement_hash = acknowledgement_hash(&receipt)?;
    Ok(receipt)
}

pub fn verify_schema_acknowledgement(plan: &SchemaChangePlan, receipt: &SchemaAcknowledgementReceipt) -> Result<()> {
    validate_plan(plan)?;
    if !plan.requires_acknowledgement || !plan.blockers.is_empty() {
        return Err(CompileError::without_span("current schema-change plan is not eligible for acknowledgement"));
    }
    if receipt.schema != SCHEMA_ACKNOWLEDGEMENT_SCHEMA
        || receipt.version != 1
        || receipt.review_policy != "reviewed-explicit-field-treatment-delta-v1"
    {
        return Err(CompileError::without_span("unsupported schema acknowledgement schema/version/review policy"));
    }
    if receipt.reviewer.trim().is_empty() || receipt.rationale.trim().is_empty() {
        return Err(CompileError::without_span("schema acknowledgement reviewer and rationale must remain non-empty"));
    }
    let expected_hash = acknowledgement_hash(receipt)?;
    if receipt.acknowledgement_hash != expected_hash {
        return Err(CompileError::without_span("schema acknowledgement hash does not match its contents"));
    }
    if receipt.plan_hash != plan.plan_hash
        || receipt.module != plan.module
        || receipt.selector != plan.selector
        || receipt.resource_type != plan.resource_type
        || receipt.old_schema_identity != plan.old_schema_identity
        || receipt.new_schema_identity != plan.new_schema_identity
        || receipt.old_relation_identity != plan.old_relation_identity
        || receipt.new_relation_identity != plan.new_relation_identity
        || receipt.field_changes != plan.field_changes
    {
        return Err(CompileError::without_span("schema acknowledgement is stale or belongs to a different schema/relation change"));
    }
    Ok(())
}

pub fn validate_plan(plan: &SchemaChangePlan) -> Result<()> {
    if plan.schema != SCHEMA_CHANGE_PLAN_SCHEMA || plan.version != 1 {
        return Err(CompileError::without_span("unsupported schema-change plan schema/version"));
    }
    if plan.module.is_empty()
        || plan.selector.action.is_empty()
        || plan.selector.before.is_empty()
        || plan.selector.after.is_empty()
        || plan.resource_type.is_empty()
    {
        return Err(CompileError::without_span("schema-change plan contains an empty identity field"));
    }
    if plan.requires_acknowledgement != (plan.old_schema_identity != plan.new_schema_identity)
        || plan.state_migration_required != plan.requires_acknowledgement
    {
        return Err(CompileError::without_span("schema-change plan flags do not match the bound schema identities"));
    }
    let expected = plan_hash(plan)?;
    if plan.plan_hash != expected {
        return Err(CompileError::without_span("schema-change plan hash does not match its contents"));
    }
    Ok(())
}

fn find_action<'a>(module: &'a crate::ast::Module, name: &str, label: &str) -> Result<&'a ActionDef> {
    module
        .items
        .iter()
        .find_map(|item| match item {
            Item::Action(action) if action.name == name => Some(action),
            _ => None,
        })
        .ok_or_else(|| CompileError::without_span(format!("{label} module has no action '{name}'")))
}

fn find_relation<'a>(action: &'a ActionDef, selector: &SchemaRelationSelector, label: &str) -> Result<&'a ReplaceRelation> {
    let mut relations = Vec::new();
    collect_relations(&action.body, &mut relations);
    let matches = relations
        .into_iter()
        .filter(|relation| relation.before == selector.before && relation.after == selector.after)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [relation] => Ok(relation),
        [] => Err(CompileError::without_span(format!(
            "{label} action '{}' has no `replace {} -> {}` relation",
            selector.action, selector.before, selector.after
        ))),
        _ => Err(CompileError::without_span(format!(
            "{label} action '{}' has multiple `replace {} -> {}` relations; acknowledgement selectors must be unique",
            selector.action, selector.before, selector.after
        ))),
    }
}

fn collect_relations<'a>(statements: &'a [Stmt], out: &mut Vec<&'a ReplaceRelation>) {
    for statement in statements {
        match statement {
            Stmt::Expr(expr) => collect_relations_expr(expr, out),
            Stmt::Let(statement) => collect_relations_expr(&statement.value, out),
            Stmt::Return(statement) => {
                if let Some(value) = &statement.value {
                    collect_relations_expr(value, out);
                }
            }
            Stmt::If(statement) => {
                collect_relations_expr(&statement.condition, out);
                collect_relations(&statement.then_branch, out);
                if let Some(branch) = &statement.else_branch {
                    collect_relations(branch, out);
                }
            }
            Stmt::For(statement) => {
                collect_relations_expr(&statement.iterable, out);
                collect_relations(&statement.body, out);
            }
            Stmt::While(statement) => {
                collect_relations_expr(&statement.condition, out);
                collect_relations(&statement.body, out);
            }
            Stmt::Borrow(statement) => collect_relations(&statement.body, out),
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }
}

fn collect_relations_expr<'a>(expr: &'a Expr, out: &mut Vec<&'a ReplaceRelation>) {
    match expr {
        Expr::ReplaceRelation(relation) => out.push(relation),
        Expr::Block(statements) => collect_relations(statements, out),
        Expr::If(expr) => {
            collect_relations_expr(&expr.condition, out);
            collect_relations_expr(&expr.then_branch, out);
            collect_relations_expr(&expr.else_branch, out);
        }
        Expr::Match(expr) => {
            collect_relations_expr(&expr.expr, out);
            for arm in &expr.arms {
                collect_relations_expr(&arm.value, out);
            }
        }
        _ => {}
    }
}

fn relation_resource_type(action: &ActionDef, selector: &SchemaRelationSelector, label: &str) -> Result<String> {
    let before = action.params.iter().find(|param| param.name == selector.before).map(|param| &param.ty).ok_or_else(|| {
        CompileError::without_span(format!("{label} relation predecessor '{}' is not an action parameter", selector.before))
    })?;
    let after = action
        .outputs
        .iter()
        .find(|output| output.name == selector.after)
        .map(|output| &output.ty)
        .or_else(|| action.params.iter().find(|param| param.name == selector.after).map(|param| &param.ty))
        .ok_or_else(|| {
            CompileError::without_span(format!("{label} relation successor '{}' is not an action output", selector.after))
        })?;
    let (Type::Named(before), Type::Named(after)) = (before, after) else {
        return Err(CompileError::without_span("schema acknowledgement requires concrete named Cell resource roles"));
    };
    if before != after {
        return Err(CompileError::without_span(format!("{label} relation changes resource type from '{before}' to '{after}'")));
    }
    Ok(before.clone())
}

fn typed_schema<'a>(
    result: &'a CompileResult,
    resource_type: &str,
    label: &str,
) -> Result<&'a cellscript_artifact_checker::TypedSemanticType> {
    result
        .metadata
        .typed_semantics
        .types
        .iter()
        .find(|schema| schema.name == resource_type && schema.kind == "resource")
        .ok_or_else(|| CompileError::without_span(format!("{label} metadata has no concrete resource schema '{resource_type}'")))
}

fn hash_schema_identity(resource_type: &str, schema: &cellscript_artifact_checker::TypedSemanticType) -> Result<String> {
    let fields = schema
        .fields
        .iter()
        .map(|field| SchemaIdentityField {
            name: field.name.as_str(),
            ty: field.ty.as_str(),
            offset: field.offset,
            width_bytes: field.width_bytes,
        })
        .collect();
    canonical_hash(SCHEMA_IDENTITY_DOMAIN, &SchemaIdentity { resource_type, encoded_size: schema.encoded_size, fields })
        .map_err(|error| CompileError::without_span(format!("failed to hash schema identity: {error}")))
}

fn relation_policies(
    relation: &ReplaceRelation,
    schema: &cellscript_artifact_checker::TypedSemanticType,
) -> Result<BTreeMap<String, SchemaFieldPolicy>> {
    let ReplaceDataTreatment::SameExcept(assignments) = &relation.data else {
        return Err(CompileError::without_span("schema acknowledgement is defined only for `data = same except { ... }` relations"));
    };
    let assigned = assignments.iter().map(|(field, value)| (field.as_str(), value)).collect::<BTreeMap<_, _>>();
    let mut policies = BTreeMap::new();
    for field in &schema.fields {
        let policy = if let Some(value) = assigned.get(field.name.as_str()) {
            SchemaFieldPolicy { treatment: "assign".to_string(), expression: Some(crate::fmt::format_expression(value)) }
        } else {
            SchemaFieldPolicy { treatment: "preserve".to_string(), expression: None }
        };
        policies.insert(field.name.clone(), policy);
    }
    Ok(policies)
}

fn hash_relation_identity(relation: &ReplaceRelation, fields: &BTreeMap<String, SchemaFieldPolicy>) -> Result<String> {
    let lock = match &relation.lock {
        crate::ast::ReplaceLockTreatment::Same => "same".to_string(),
        crate::ast::ReplaceLockTreatment::Exact(value) => format!("exact({})", crate::fmt::format_expression(value)),
        crate::ast::ReplaceLockTreatment::ExactHash(value) => format!("exact_hash({})", crate::fmt::format_expression(value)),
    };
    canonical_hash(
        RELATION_IDENTITY_DOMAIN,
        &RelationIdentity {
            before: &relation.before,
            after: &relation.after,
            data: "same-except",
            fields,
            lock,
            capacity: "same",
            identity: "same",
        },
    )
    .map_err(|error| CompileError::without_span(format!("failed to hash relation identity: {error}")))
}

fn plan_hash(plan: &SchemaChangePlan) -> Result<String> {
    canonical_hash(
        PLAN_HASH_DOMAIN,
        &PlanHashPayload {
            schema: &plan.schema,
            version: plan.version,
            module: &plan.module,
            selector: &plan.selector,
            resource_type: &plan.resource_type,
            old_interface_hash: &plan.old_interface_hash,
            new_interface_hash: &plan.new_interface_hash,
            old_schema_identity: &plan.old_schema_identity,
            new_schema_identity: &plan.new_schema_identity,
            old_relation_identity: &plan.old_relation_identity,
            new_relation_identity: &plan.new_relation_identity,
            requires_acknowledgement: plan.requires_acknowledgement,
            state_migration_required: plan.state_migration_required,
            field_changes: &plan.field_changes,
            blockers: &plan.blockers,
        },
    )
    .map_err(|error| CompileError::without_span(format!("failed to hash schema-change plan: {error}")))
}

fn acknowledgement_hash(receipt: &SchemaAcknowledgementReceipt) -> Result<String> {
    canonical_hash(
        ACKNOWLEDGEMENT_HASH_DOMAIN,
        &AcknowledgementHashPayload {
            schema: &receipt.schema,
            version: receipt.version,
            plan_hash: &receipt.plan_hash,
            module: &receipt.module,
            selector: &receipt.selector,
            resource_type: &receipt.resource_type,
            old_schema_identity: &receipt.old_schema_identity,
            new_schema_identity: &receipt.new_schema_identity,
            old_relation_identity: &receipt.old_relation_identity,
            new_relation_identity: &receipt.new_relation_identity,
            review_policy: &receipt.review_policy,
            reviewer: &receipt.reviewer,
            rationale: &receipt.rationale,
            field_changes: &receipt.field_changes,
        },
    )
    .map_err(|error| CompileError::without_span(format!("failed to hash schema acknowledgement: {error}")))
}
