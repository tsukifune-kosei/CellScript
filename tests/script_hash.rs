//! Canonical source-level CKB Script construction and hash evidence.

use cellscript::{
    compile_with_executable_surface_policy, strip_vm_abi_trailer, CellScriptEdition, CompileOptions, EntryWitnessArg,
    ExecutableSurfacePolicy,
};
use ckb_testtool::ckb_types::{bytes::Bytes, core::ScriptHashType, packed, prelude::*};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, execute_cellscript_script};

fn byte_string(bytes: &[u8]) -> String {
    let mut out = String::from("b\"");
    for byte in bytes {
        out.push_str(&format!("\\x{byte:02x}"));
    }
    out.push('"');
    out
}

fn source(code_hash: [u8; 32], hash_type: &str, args: &[u8]) -> String {
    let args = if args.is_empty() {
        "script::args_empty()".to_string()
    } else if args.len() == 32 {
        format!("script::args(Hash::from_bytes({}))", byte_string(args))
    } else {
        format!("script::args({})", byte_string(args))
    };
    format!(
        r#"
module script_hash::canonical

action verify(witness expected: ScriptHash) -> u64 {{
    let code_hash = Hash::from_bytes({})
    let value = script::new(code_hash, script::{hash_type}(), {args})
    let complete: ScriptHash = script::hash(value)
    require complete == expected
    return 0
}}
"#,
        byte_string(&code_hash)
    )
}

fn compile(source: &str) -> cellscript::CompileResult {
    compile_with_executable_surface_policy(
        source,
        CompileOptions {
            edition: CellScriptEdition::Edition2027,
            target: Some("riscv64-elf".to_string()),
            target_profile: Some("ckb".to_string()),
            ..Default::default()
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_or_else(|error| panic!("canonical Script source must compile: {error}\n{source}"))
}

fn witness(result: &cellscript::CompileResult, expected: [u8; 32]) -> Bytes {
    let payload =
        result.metadata.actions[0].entry_witness_args(&[EntryWitnessArg::Hash(expected)]).expect("encode expected Script hash");
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

fn execute(result: &cellscript::CompileResult, expected: [u8; 32]) -> i64 {
    let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
    fixture.current_type_script_input_indices = vec![0];
    fixture.witnesses = vec![witness(result, expected)];
    execute_cellscript_script(strip_vm_abi_trailer(&result.artifact_bytes), &fixture).exit_code
}

#[test]
fn canonical_script_hash_matches_ckb_types_for_all_hash_types_and_bounds() {
    let code_hash = [0x5au8; 32];
    let cases = [
        (ScriptHashType::Data, "hash_type_data", Vec::new()),
        (ScriptHashType::Type, "hash_type_type", vec![0x11; 20]),
        (ScriptHashType::Data1, "hash_type_data1", vec![0x22; 32]),
        (ScriptHashType::Data2, "hash_type_data2", vec![0x33; cellscript::CKB_SCRIPT_HASH_MAX_ARGS_BYTES]),
    ];

    for (hash_type, helper, args) in cases {
        let packed_script = packed::Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(hash_type)
            .args(Bytes::copy_from_slice(&args).pack())
            .build();
        let expected: [u8; 32] = packed_script.calc_script_hash().unpack();
        let result = compile(&source(code_hash, helper, &args));

        assert_eq!(execute(&result, expected), 0, "{helper} with {} args bytes must match ckb-types", args.len());
        let mut wrong = expected;
        wrong[0] ^= 0x80;
        assert_ne!(execute(&result, wrong), 0, "a substituted complete Script hash must reject");

        let access = result
            .metadata
            .runtime
            .ckb_runtime_accesses
            .iter()
            .find(|access| access.operation == "script-hash-v1")
            .expect("canonical Script hash runtime access");
        assert_eq!(access.syscall, "CKB_BLAKE2B");
        assert_eq!(access.source, "Script");
        assert_eq!(access.binding, "script::hash");
        assert_eq!(access.provenance.source.origin, "constructed-script");
        assert_eq!(access.provenance.range.length.value, Some((53 + args.len()) as u64));
        assert!(result.metadata.typed_semantics.entries.iter().any(|entry| {
            entry.blocks.iter().any(|block| {
                block.operations.iter().any(|operation| operation.call.as_ref().is_some_and(|call| call.target == "__ckb_script_hash"))
            })
        }));
    }
}

#[test]
fn script_hash_rejects_wrong_domains_oversized_args_and_dynamic_invalid_hash_type() {
    for invalid in [
        r#"
module script_hash::wrong_domain
action verify() -> u64 {
    let value = script::hash(Hash::zero())
    return 0
}
"#
        .to_string(),
        source([0x44; 32], "hash_type_data", &vec![0x55; cellscript::CKB_SCRIPT_HASH_MAX_ARGS_BYTES + 1]),
    ] {
        let error = compile_with_executable_surface_policy(
            &invalid,
            CompileOptions {
                edition: CellScriptEdition::Edition2027,
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..Default::default()
            },
            ExecutableSurfacePolicy::DenyFailClosed,
        )
        .expect_err("invalid Script hash source must reject")
        .to_string();
        assert!(
            error.contains("expects a Script constructed with script::new")
                || error.contains("exceeds the bounded maximum of 459 bytes"),
            "unexpected diagnostic: {error}"
        );
    }

    let dynamic_invalid = r#"
module script_hash::invalid_hash_type
action verify(witness expected: Hash) -> u64 {
    let invalid_hash_type = 3
    let value = script::new(Hash::zero(), invalid_hash_type, script::args_empty())
    let complete = script::hash(value)
    require complete == ckb::script_hash(expected)
    return 0
}
"#;
    let result = compile(dynamic_invalid);
    assert_eq!(execute(&result, [0; 32]), cellscript::runtime_errors::CellScriptRuntimeError::ScriptConstructionInvalid.code() as i64);
}
