//! Differential CKB-VM evidence for the bounded zero-lock sighash domain.

use cellscript::{
    compile_with_executable_surface_policy, strip_vm_abi_trailer, CellScriptEdition, CompileOptions, ExecutableSurfacePolicy,
};
use ckb_sdk::{types::ScriptGroup, unlock::generate_message};
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionView, packed, prelude::*};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{
    build_simple_fixture, execute_cellscript_script, execute_cellscript_script_with_transaction_transform, CkbVmFixture,
};

const SOURCE: &str = r#"
module signing::zero_lock

action inspect() -> u64 {
    verification
        let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
        let expected = witness::args(0).lock
        require Hash::from_sighash_all(digest) == expected
        return 0
}
"#;

const HELPER_SOURCE: &str = r#"
module signing::zero_lock_helper

fn signing_message_matches(expected: Hash) -> bool {
    let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
    return Hash::from_sighash_all(digest) == expected
}

action inspect() -> u64 {
    verification
        let expected = witness::args(0).lock
        require signing_message_matches(expected)
        return 0
}
"#;

fn compile(source: &str) -> cellscript::CompileResult {
    compile_at(source, 0)
}

fn compile_at(source: &str, opt_level: u8) -> cellscript::CompileResult {
    compile_with_executable_surface_policy(
        source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            opt_level,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_or_else(|error| panic!("bounded zero-lock sighash source must compile: {error}\n{source}"))
}

fn fixture() -> CkbVmFixture {
    let first = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 32])).pack())
        .input_type(Some(Bytes::from_static(b"domain-owned-entry")).pack())
        .build()
        .as_bytes();
    let mut fixture = build_simple_fixture(Bytes::default(), 3, 1);
    fixture.current_type_script_input_indices = vec![0, 2];
    fixture.witnesses = vec![
        first,
        Bytes::from_static(b"unrelated-input-witness-excluded"),
        Bytes::from_static(b"second-current-group-witness"),
        Bytes::from_static(b"extra-witness-after-inputs"),
    ];
    fixture
}

fn install_sdk_message(tx: TransactionView, script: packed::Script) -> TransactionView {
    let mut group = ScriptGroup::from_type_script(&script);
    group.input_indices = vec![0, 2];
    let message = generate_message(&tx, &group, Bytes::from(vec![0u8; 32])).expect("ckb-sdk-rust generate_message");
    let first =
        packed::WitnessArgs::from_slice(tx.witnesses().get(0).expect("first witness").raw_data().as_ref()).expect("first WitnessArgs");
    let first = first.as_builder().lock(Some(message).pack()).build();
    let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    witnesses[0] = first.as_bytes().pack();
    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

#[test]
fn bounded_zero_lock_digest_matches_ckb_sdk_and_binds_metadata() {
    for opt_level in 0..=3 {
        let result = compile_at(SOURCE, opt_level);
        let execution = execute_cellscript_script_with_transaction_transform(
            strip_vm_abi_trailer(&result.artifact_bytes),
            &fixture(),
            install_sdk_message,
        );
        assert_eq!(
            execution.exit_code, 0,
            "CellScript digest must equal ckb-sdk-rust generate_message at O{opt_level}: {:?}",
            execution.captured_debug
        );
    }

    let result = compile(SOURCE);

    assert!(result.metadata.runtime.fail_closed_runtime_features.is_empty());
    assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-sighash-all-zero-lock-v1".to_string()));
    let domain = result.metadata.runtime.signing_message_domains.first().expect("signing domain metadata");
    assert_eq!(domain.contract, cellscript::CKB_SIGHASH_ALL_ZERO_LOCK_CONTRACT);
    assert_eq!(domain.digest_type, "SighashAllDigest");
    assert_eq!(domain.max_group_inputs, 4);
    assert_eq!(domain.max_inputs, 8);
    assert_eq!(domain.max_extra_witnesses, 4);
    assert_eq!(domain.max_witness_bytes, 4096);
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "sighash-all-zero-lock-v1"
            && access.syscall == "CKB_SIGHASH_ALL_ZERO_LOCK_V1"
            && access.source == "GroupInput"
            && access.provenance.index.max_inclusive == Some(3)
            && access.provenance.range.length.max_inclusive == Some(4096)
    }));

    let mut tampered = result.metadata.clone();
    tampered.runtime.signing_message_domains[0].max_inputs = 9;
    let error = cellscript::validate_compile_metadata(&tampered, result.artifact_format)
        .expect_err("compile metadata limits must remain bound to the typed call");
    assert!(error.message.contains("typed bounded sighash call"), "{error}");
}

#[test]
fn zero_lock_digest_can_be_verified_inside_a_helper_call() {
    let result = compile(HELPER_SOURCE);
    let execution = execute_cellscript_script_with_transaction_transform(
        strip_vm_abi_trailer(&result.artifact_bytes),
        &fixture(),
        install_sdk_message,
    );
    assert_eq!(execution.exit_code, 0, "helper-local signing digest must retain its bytes: {:?}", execution.captured_debug);
    let domain = result.metadata.runtime.signing_message_domains.first().expect("helper signing domain metadata");
    assert_eq!(domain.scope_kind, "function");
    assert_eq!(domain.scope_name, "signing_message_matches");
}

#[test]
fn zero_lock_digest_is_accepted_directly_by_the_explicit_bip340_boundary() {
    let source = r#"
module signing::zero_lock_bip340

action verify(
    witness verifier_data_hash: Hash,
    witness xonly_pubkey: [u8; 32],
    witness signature: [u8; 64],
) -> u64 {
    verification
        let verifier_dep = source::cell_dep(0)
        ckb::require_cell_data_hash(verifier_dep, verifier_data_hash)
        let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
        verifier::btc::bip340::require_signature_from_cell_dep(
            0,
            digest,
            xonly_pubkey,
            signature,
        )
        return 0
}
"#;
    let result = compile_with_executable_surface_policy(
        source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-asm".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .expect("the signing-domain digest must feed the explicit BIP340 verifier");
    assert!(result.metadata.runtime.fail_closed_runtime_features.is_empty());
    let assembly = String::from_utf8(result.artifact_bytes).unwrap();
    assert!(assembly.contains("call __ckb_sighash_all_zero_lock"), "{assembly}");
    assert!(assembly.contains("# cellscript abi: novaseal bip340 ipc word 0"), "{assembly}");
}

#[test]
fn post_message_witness_mutation_and_declared_bounds_fail_closed() {
    let result = compile(SOURCE);
    let execution = execute_cellscript_script_with_transaction_transform(
        strip_vm_abi_trailer(&result.artifact_bytes),
        &fixture(),
        |tx, script| {
            let signed = install_sdk_message(tx, script);
            let mut witnesses: Vec<packed::Bytes> = signed.witnesses().into_iter().collect();
            witnesses[3] = Bytes::from_static(b"mutated-after-message-construction").pack();
            signed.as_advanced_builder().set_witnesses(witnesses).build()
        },
    );
    assert_ne!(execution.exit_code, 0, "an extra witness mutation must change the committed message");

    for source in [
        SOURCE.replace("(4, 8, 4, 4096)", "(1, 8, 4, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(2, 2, 4, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(4, 8, 0, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(4, 8, 4, 32)"),
    ] {
        let bounded = compile(&source);
        let execution = execute_cellscript_script(strip_vm_abi_trailer(&bounded.artifact_bytes), &fixture());
        assert_eq!(
            execution.exit_code,
            cellscript::runtime_errors::CellScriptRuntimeError::SighashBoundExceeded.code() as i64,
            "the declared signing-message bounds must fail closed"
        );
    }

    let malformed = compile(SOURCE);
    let mut malformed_fixture = fixture();
    malformed_fixture.witnesses[0] = Bytes::from_static(b"not-a-WitnessArgs");
    let execution = execute_cellscript_script(strip_vm_abi_trailer(&malformed.artifact_bytes), &malformed_fixture);
    assert_eq!(
        execution.exit_code,
        cellscript::runtime_errors::CellScriptRuntimeError::WitnessMalformed.code() as i64,
        "the first signing witness must be a canonical WitnessArgs"
    );
}

#[test]
fn zero_lock_domain_requires_literal_supported_bounds_and_distinct_digest_type() {
    for source in [
        SOURCE.replace("(4, 8, 4, 4096)", "(0, 8, 4, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(65, 65, 4, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(4, 257, 4, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(4, 8, 65, 4096)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(4, 8, 4, 65537)"),
        SOURCE.replace("(4, 8, 4, 4096)", "(8, 4, 4, 4096)"),
        SOURCE
            .replace("action inspect() -> u64 {", "action inspect(witness maximum: u64) -> u64 {")
            .replace("(4, 8, 4, 4096)", "(4, 8, 4, maximum)"),
    ] {
        let error = compile_with_executable_surface_policy(
            &source,
            CompileOptions {
                edition: CellScriptEdition::Edition2027,
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..Default::default()
            },
            ExecutableSurfacePolicy::DenyFailClosed,
        )
        .expect_err("invalid zero-lock bound must be rejected statically");
        assert!(error.message.contains("sighash_all_zero_lock"), "unexpected diagnostic: {error}");
    }

    let confused = SOURCE.replace(
        "let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)",
        "let digest: Hash = env::sighash_all_zero_lock(4, 8, 4, 4096)",
    );
    let error = compile_with_executable_surface_policy(
        &confused,
        CompileOptions { edition: CellScriptEdition::Edition2027, ..Default::default() },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .expect_err("a signing-domain digest must not silently become a generic Hash");
    assert!(error.message.contains("type mismatch"), "unexpected digest-domain diagnostic: {error}");
}
