use cellscript::schema_acknowledgement::{
    acknowledge_schema_change, build_schema_change_plan, verify_schema_acknowledgement, SchemaRelationSelector,
};
use cellscript::{compile_with_executable_surface_policy, CellScriptEdition, CompileOptions, CompileResult, ExecutableSurfacePolicy};

fn compile(source: &str) -> CompileResult {
    compile_with_executable_surface_policy(
        source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..CompileOptions::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_or_else(|error| panic!("schema fixture must compile: {error}\n{source}"))
}

fn selector() -> SchemaRelationSelector {
    SchemaRelationSelector { action: "transfer".to_string(), before: "token".to_string(), after: "next".to_string() }
}

const OLD: &str = r#"
module schema_ack::token
resource Token has store, replace, relock { owner: Address, amount: u64 }

action transfer(input token: Token) -> next: Token {
    replace token -> next {
        data = same except { }
        lock = same
        capacity = same
        identity = same
    }
}
"#;

const ADDED_IMPLICIT: &str = r#"
module schema_ack::token
resource Token has store, replace, relock { owner: Address, amount: u64, approval_nonce: u64 }

action transfer(input token: Token) -> next: Token {
    replace token -> next {
        data = same except { }
        lock = same
        capacity = same
        identity = same
    }
}
"#;

const ADDED_RESET: &str = r#"
module schema_ack::token
resource Token has store, replace, relock { owner: Address, amount: u64, approval_nonce: u64 }

action transfer(input token: Token) -> next: Token {
    replace token -> next {
        data = same except {
            approval_nonce = 0
        }
        lock = same
        capacity = same
        identity = same
    }
}
"#;

#[test]
fn added_field_must_be_explicit_before_acknowledgement() {
    let plan = build_schema_change_plan(&compile(OLD), &compile(ADDED_IMPLICIT), selector()).unwrap();
    assert!(plan.requires_acknowledgement);
    assert!(plan.state_migration_required);
    assert_eq!(plan.blockers.len(), 1);
    assert_eq!(plan.blockers[0].code, "SACK1001");
    assert_eq!(plan.blockers[0].field, "approval_nonce");
    assert!(acknowledge_schema_change(&plan, "Arthur", "reviewed reset policy").is_err());
}

#[test]
fn explicit_reset_produces_a_bound_receipt_and_stale_changes_reject() {
    let old = compile(OLD);
    let candidate = compile(ADDED_RESET);
    let plan = build_schema_change_plan(&old, &candidate, selector()).unwrap();
    assert!(plan.blockers.is_empty());
    let added = plan.field_changes.iter().find(|change| change.field == "approval_nonce").unwrap();
    assert_eq!(added.classification, "added");
    assert_eq!(added.new_policy.as_ref().unwrap().treatment, "assign");
    assert_eq!(added.new_policy.as_ref().unwrap().expression.as_deref(), Some("0"));

    let receipt = acknowledge_schema_change(&plan, "Arthur", "approval nonce resets on every transfer").unwrap();
    verify_schema_acknowledgement(&plan, &receipt).unwrap();

    let mut tampered = receipt.clone();
    tampered.rationale = "different review".to_string();
    let error = verify_schema_acknowledgement(&plan, &tampered).unwrap_err().to_string();
    assert!(error.contains("hash"), "{error}");

    let mut receipt_json = serde_json::to_value(&receipt).unwrap();
    receipt_json["unbound_extension"] = serde_json::json!(true);
    assert!(serde_json::from_value::<cellscript::schema_acknowledgement::SchemaAcknowledgementReceipt>(receipt_json).is_err());

    let changed = compile(&ADDED_RESET.replace("approval_nonce = 0", "approval_nonce = token.approval_nonce + 1"));
    let changed_plan = build_schema_change_plan(&old, &changed, selector()).unwrap();
    let error = verify_schema_acknowledgement(&changed_plan, &receipt).unwrap_err().to_string();
    assert!(error.contains("stale"), "{error}");
}

#[test]
fn formatting_changes_do_not_change_the_plan_identity() {
    let old = compile(OLD);
    let candidate = compile(ADDED_RESET);
    let reformatted = compile(&cellscript::fmt::format_default(&candidate.ast).unwrap());
    let first = build_schema_change_plan(&old, &candidate, selector()).unwrap();
    let second = build_schema_change_plan(&old, &reformatted, selector()).unwrap();
    assert_eq!(first.plan_hash, second.plan_hash);
    assert_eq!(first.new_relation_identity, second.new_relation_identity);
}

#[test]
fn an_unchanged_schema_is_a_baseline_and_needs_no_receipt() {
    let old = compile(OLD);
    let plan = build_schema_change_plan(&old, &old, selector()).unwrap();
    assert!(!plan.requires_acknowledgement);
    assert!(!plan.state_migration_required);
    assert!(plan.field_changes.is_empty());
    assert!(acknowledge_schema_change(&plan, "Arthur", "not needed").is_err());
}
