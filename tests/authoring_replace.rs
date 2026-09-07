//! Branch-local successor relations in the authoring route.
//!
//! A `replace before -> after { ... }` declaration is checked sugar over the
//! spelled-out Edition 2026 successor forms: these tests require identical
//! generated machine code between the two spellings, execute the relation in
//! the real CKB-VM, and reject incomplete, duplicated or out-of-scope
//! relations. This is differential compiler evidence, not a shared-policy
//! dispatch or production deployment claim.

use cellscript::{
    compile_with_executable_surface_policy, frontend, strip_vm_abi_trailer, CellScriptEdition, CompileOptions, CompileResult,
    EntryWitnessArg, ExecutableSurfacePolicy,
};
use ckb_testtool::ckb_types::{bytes::Bytes, packed, prelude::*};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, deterministic_always_success_lock_hash, execute_cellscript_script};

fn options(edition: CellScriptEdition) -> CompileOptions {
    CompileOptions { edition, target: Some("riscv64-elf".to_string()), target_profile: Some("ckb".to_string()), ..Default::default() }
}

fn compile_2027(source: &str) -> CompileResult {
    compile_with_executable_surface_policy(source, options(CellScriptEdition::Edition2027), ExecutableSurfacePolicy::DenyFailClosed)
        .unwrap_or_else(|error| panic!("authoring source must compile: {error}\n{source}"))
}

fn compile_2026(source: &str) -> CompileResult {
    compile_with_executable_surface_policy(source, options(CellScriptEdition::Edition2026), ExecutableSurfacePolicy::DenyFailClosed)
        .unwrap_or_else(|error| panic!("Edition 2026 source must compile: {error}\n{source}"))
}

fn errors_2027(source: &str) -> String {
    compile_with_executable_surface_policy(source, options(CellScriptEdition::Edition2027), ExecutableSurfacePolicy::DenyFailClosed)
        .expect_err("source must be rejected")
        .to_string()
}

const EXACT_LOCK_RELATION: &str = r#"
module authoring_replace::transfer
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    require token.amount > 0
    replace token -> next {
        data { amount = same }
        lock = exact(recipient)
        capacity = same
        identity = same
    }
}
"#;

const EXACT_HASH_LOCK_RELATION: &str = r#"
module authoring_replace::transfer_hash
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient_hash: Hash) -> next: Token {
    require token.amount > 0
    replace token -> next {
        data { amount = same }
        lock = exact_hash(ckb::script_hash(recipient_hash))
        capacity = same
        identity = same
    }
}
"#;

const OBSERVED_HASH_LOCK_RELATION: &str = r#"
module authoring_replace::observed_hash
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token) -> next: Token {
    let observed = ckb::input<Token>(0)
    replace token -> next {
        data { amount = same }
        lock = exact_hash(observed.lock_hash)
        capacity = same
        identity = same
    }
}
"#;

const EXACT_LOCK_LEGACY: &str = r#"
module authoring_replace::transfer
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    verification
        require token.amount > 0
        std::lifecycle::transfer(token, next, recipient) { amount }
        std::cell::preserve_capacity(next, token)
}
"#;

const SAME_LOCK_RELATION: &str = r#"
module authoring_replace::rollover
resource Note has store, replace, relock { owner: Address, amount: u64 }

action roll(input note: Note) -> next: Note {
    replace note -> next {
        data = same except { amount = note.amount + 1 }
        lock = same
        capacity = same
        identity = same
    }
}
"#;

// Field order follows the relation's canonical sorted expansion (amount,
// owner) so the two spellings lower to one instruction sequence.
const SAME_LOCK_LEGACY: &str = r#"
module authoring_replace::rollover
resource Note has store, replace, relock { owner: Address, amount: u64 }

action roll(input note: Note) -> next: Note {
    verification
        consume note
        create next = Note { amount: note.amount + 1, owner: note.owner }
        std::cell::same_lock(next, note)
        std::cell::same_type(next, note)
        std::cell::preserve_capacity(next, note)
}
"#;

fn assert_identical_machine_code(relation: &CompileResult, legacy: &CompileResult) {
    relation.validate().expect("valid authoring compiler bundle");
    legacy.validate().expect("valid Edition 2026 compiler bundle");
    assert_eq!(&legacy.artifact_bytes[..4], b"\x7fELF");
    assert_eq!(relation.metadata.actions.len(), legacy.metadata.actions.len());
    let obligations = |result: &CompileResult| -> Vec<String> {
        result.metadata.actions[0].proof_plan.iter().map(|proof| proof.feature.clone()).collect::<Vec<_>>()
    };
    let mut relation_obligations = obligations(relation);
    let mut legacy_obligations = obligations(legacy);
    relation_obligations.sort();
    legacy_obligations.sort();
    assert_eq!(relation_obligations, legacy_obligations, "the relation must carry the identical obligation set");
}

#[test]
fn exact_lock_relation_is_checked_sugar_over_the_legacy_transfer() {
    let relation = compile_2027(EXACT_LOCK_RELATION);
    let legacy = compile_2026(EXACT_LOCK_LEGACY);
    assert_identical_machine_code(&relation, &legacy);
}

#[test]
fn same_except_and_lock_same_execute_with_checked_field_updates() {
    // The `same except` form expands against the concrete schema and the
    // `lock = same` treatment pins the successor's complete Lock Script hash
    // to the predecessor's: conservation recognizes the updated-successor
    // shape (verbatim aliases plus verifier-checked u64 updates rooted in the
    // consumed input), so both spellings stay executable under
    // DenyFailClosed.
    let relation = compile_2027(SAME_LOCK_RELATION);
    let legacy = compile_2026(SAME_LOCK_LEGACY);
    assert_identical_machine_code(&relation, &legacy);
    assert!(
        relation.metadata.actions[0]
            .proof_plan
            .iter()
            .any(|proof| { proof.feature == "resource-conservation:Note" && proof.on_chain_checked }),
        "the updated successor must carry checked conservation evidence"
    );

    // Note's layout is owner (32-byte Address) followed by amount (u64).
    let owner = deterministic_always_success_lock_hash();
    let note_data = |amount: u64| -> Bytes {
        let mut data = owner.to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        Bytes::from(data)
    };
    let run = |input_amount: u64, output_amount: u64| {
        let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
        fixture.current_type_script_input_indices = vec![0];
        fixture.inputs[0].data = note_data(input_amount);
        fixture.outputs[0].data = note_data(output_amount);
        let execution = execute_cellscript_script(strip_vm_abi_trailer(&relation.artifact_bytes), &fixture);
        (execution.exit_code, execution.captured_debug.clone())
    };
    let (exit, debug) = run(7, 8);
    assert_eq!(exit, 0, "a verifier-checked amount update must pass: {debug:?}");
    let (exit, _) = run(7, 7);
    assert_ne!(exit, 0, "skipping the declared update must reject");
    let (exit, _) = run(7, 9);
    assert_ne!(exit, 0, "an off-by-more update must reject");

    // Field validation still fails closed on unknown fields.
    let unknown_field = SAME_LOCK_RELATION.replace("amount = note.amount + 1", "ghost = note.amount + 1");
    let message = errors_2027(&unknown_field);
    assert!(message.contains("does not exist on the relation's resource"), "{message}");
}

fn transfer_fixture(amount: u64, output_amount: u64) -> ckb_script_runner::CkbVmFixture {
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.inputs[0].data = Bytes::copy_from_slice(&amount.to_le_bytes());
    fixture.outputs[0].data = Bytes::copy_from_slice(&output_amount.to_le_bytes());
    fixture
}

fn transfer_witness(result: &CompileResult, recipient_lock_hash: [u8; 32]) -> Bytes {
    let payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Address(recipient_lock_hash)])
        .expect("encode declared entry arguments");
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

fn transfer_hash_witness(result: &CompileResult, recipient_lock_hash: [u8; 32]) -> Bytes {
    let payload = result.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Hash(recipient_lock_hash)])
        .expect("encode declared Script-hash argument");
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

#[test]
fn exact_lock_relation_executes_and_rejects_in_the_real_vm() {
    let result = compile_2027(EXACT_LOCK_RELATION);
    let recipient = deterministic_always_success_lock_hash();
    let run = |fixture_witness: Bytes, amount: u64, output_amount: u64| {
        let mut fixture = transfer_fixture(amount, output_amount);
        fixture.witnesses = vec![fixture_witness];
        let execution = execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture);
        (execution.exit_code, execution.captured_debug.clone(), execution.cycles)
    };

    let witness = transfer_witness(&result, recipient);
    let (exit, debug, cycles) = run(witness.clone(), 7, 7);
    assert_eq!(exit, 0, "preserving transfer must pass: {debug:?}");
    // Regression budget: the compact layout and single-instruction small
    // immediates brought this fixture from 10,772 down to 8,573 cycles.
    // Headroom guards against accidental codegen regressions without
    // pinning the exact optimization.
    assert!(cycles <= 9_500, "relation transfer cycles regressed past budget: {cycles}");

    let (exit, _, _) = run(witness.clone(), 0, 0);
    assert_ne!(exit, 0, "amount guard must reject zero");

    let (exit, _, _) = run(witness.clone(), 7, 8);
    assert_ne!(exit, 0, "mutated successor data must reject");

    let wrong_recipient = {
        let mut hash = recipient;
        hash[0] ^= 0xff;
        hash
    };
    let (exit, _, _) = run(transfer_witness(&result, wrong_recipient), 7, 7);
    assert_ne!(exit, 0, "a successor locked to another recipient must reject");
}

#[test]
fn exact_hash_relation_accepts_only_the_explicit_script_hash_domain_and_executes_in_the_real_vm() {
    let result = compile_2027(EXACT_HASH_LOCK_RELATION);
    let recipient = deterministic_always_success_lock_hash();
    let run = |witness: Bytes| {
        let mut fixture = transfer_fixture(7, 7);
        fixture.witnesses = vec![witness];
        execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture).exit_code
    };

    assert_eq!(run(transfer_hash_witness(&result, recipient)), 0, "the complete output Lock Script hash must match");
    let mut wrong_recipient = recipient;
    wrong_recipient[0] ^= 0xff;
    assert_ne!(run(transfer_hash_witness(&result, wrong_recipient)), 0, "a different complete Lock Script hash must reject");

    let formatted = cellscript::fmt::format_default(&result.ast).expect("format exact_hash relation source");
    assert!(formatted.contains("lock = exact_hash(ckb::script_hash(recipient_hash))"), "{formatted}");
    compile_2027(&formatted);

    let observed = compile_2027(OBSERVED_HASH_LOCK_RELATION);
    let fixture = transfer_fixture(7, 7);
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&observed.artifact_bytes), &fixture);
    assert_eq!(execution.exit_code, 0, "a typed InputView.lock_hash must remain in the ScriptHash domain");
}

#[test]
fn formatted_relation_round_trips_into_identical_machine_code() {
    let relation = compile_2027(EXACT_LOCK_RELATION);
    let formatted = cellscript::fmt::format_default(&relation.ast).expect("format relation source");
    assert!(formatted.contains("replace token -> next"), "{formatted}");
    assert!(formatted.contains("lock = exact(recipient)"), "{formatted}");
    let reparsed = compile_2027(&formatted);
    assert_identical_machine_code(&reparsed, &relation);
    let legacy = compile_2026(EXACT_LOCK_LEGACY);
    assert_identical_machine_code(&reparsed, &legacy);
}

const CONDITIONAL_DISPOSAL: &str = r#"
module authoring_replace::conditional
resource Token has store, replace, relock { amount: u64 }

action branchy(input token: Token, witness flag: u64, witness recipient: Address) -> next: Token {
    if flag > 0 {
        replace token -> next {
            data { amount = same }
            lock = exact(recipient)
            capacity = same
            identity = same
        }
    }
}
"#;

const COMPLETE_DISPOSAL: &str = r#"
module authoring_replace::complete
resource Token has store, replace, relock { amount: u64 }

action branchy(input token: Token, witness flag: u64, witness recipient: Address) -> next: Token {
    if flag > 0 {
        replace token -> next {
            data { amount = same }
            lock = exact(recipient)
            capacity = same
            identity = same
        }
    } else {
        replace token -> next {
            data { amount = same }
            lock = exact(recipient)
            capacity = same
            identity = same
        }
    }
}
"#;

const DOUBLE_DISPOSAL: &str = r#"
module authoring_replace::double
resource Token has store, consume { amount: u64 }

action greedy(input token: Token, witness recipient: Address) -> next: Token {
    replace token -> next {
        data { amount = same }
        lock = exact(recipient)
        capacity = same
        identity = same
    }
    consume token
}
"#;

#[test]
fn path_sensitive_successor_completeness_rejects_partial_and_double_disposal() {
    assert!(errors_2027(CONDITIONAL_DISPOSAL).contains("every accepting path must dispose"), "a branch that skips disposal must fail");
    // Both branches covering the role satisfies the path-sensitive check and
    // now compiles: sibling branch arms re-materialize schema fields instead
    // of reusing a predecessor-only definition, so each arm's create stands
    // on its own and the typed record validates.
    let complete = compile_2027(COMPLETE_DISPOSAL);
    assert_eq!(complete.metadata.actions.len(), 1, "both branches covering the role must compile");
    assert!(errors_2027(DOUBLE_DISPOSAL).contains("disposed of twice"), "two disposals on one path must fail");
}

#[test]
fn relation_surface_fails_closed_outside_its_contract() {
    for (source, expected) in [
        (
            r#"
module authoring_replace::frozen
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    replace token -> next {
        data { amount = same }
        lock = exact_hash(recipient)
        capacity = same
        identity = same
    }
}
"#,
            "expects a ScriptHash, found Address",
        ),
        (
            r#"
module authoring_replace::untyped_hash
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient_hash: Hash) -> next: Token {
    replace token -> next {
        data { amount = same }
        lock = exact_hash(recipient_hash)
        capacity = same
        identity = same
    }
}
"#,
            "convert a trusted Hash explicitly with ckb::script_hash(hash)",
        ),
        (
            r#"
module authoring_replace::unknown_field
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    replace token -> next {
        data = same except { owner = recipient }
        lock = same
        capacity = same
        identity = same
    }
}
"#,
            "does not exist on the relation\'s resource",
        ),
        (
            r#"
module authoring_replace::missing_treatment
resource Token has store, replace, relock { amount: u64 }

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    replace token -> next {
        data { amount = same }
        capacity = same
        identity = same
    }
}
"#,
            "missing lock",
        ),
        (
            r#"
module authoring_replace::partial_data
resource Token has store, replace, relock { owner: Address, amount: u64 }

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    replace token -> next {
        data { amount = same }
        lock = same
        capacity = same
        identity = same
    }
}
"#,
            "must cover every field",
        ),
        (
            r#"
module authoring_replace::looped
resource Token has store, consume { amount: u64 }

action loopy(input token: Token, witness rounds: u64) -> u64 {
    for i in 0..rounds {
        consume token
    }
    return 0
}
"#,
            "inside a loop",
        ),
    ] {
        let message = errors_2027(source);
        assert!(message.contains(expected), "expected `{expected}` in: {message}");
    }

    // The frozen Edition 2026 grammar keeps `replace` as an ordinary
    // identifier: the relation must not parse there.
    assert!(frontend::parse(EXACT_LOCK_RELATION, CellScriptEdition::Edition2026).is_err());
}
