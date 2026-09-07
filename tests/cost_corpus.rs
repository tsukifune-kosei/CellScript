//! Matched cost corpus: CellScript scenarios versus hand-written Rust CKB
//! references with the same checked scope, plus the deployed sizes of real
//! on-chain system scripts as context.
//!
//! This is cost evidence for named samples, not an equivalence proof or a
//! production release gate. Each Rust binary mirrors exactly the checks of
//! its CellScript counterpart under the audited build profile (no_std,
//! ckb-std 1.1.0, opt-level z, thin LTO, one codegen unit, aborting panics,
//! llvm-strip). Real system-script sizes are reported for context only:
//! their feature sets differ from every scenario here.

use std::{env, fs, path::PathBuf, process::Command};

use cellscript::{
    compile_with_executable_surface_policy, strip_vm_abi_trailer, CellScriptEdition, CompileOptions, CompileResult, EntryWitnessArg,
    ExecutableSurfacePolicy,
};
use ckb_testtool::{
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed, prelude::*},
    context::Context,
};

#[path = "support/ckb_script_runner.rs"]
#[allow(dead_code)]
mod ckb_script_runner;

use ckb_script_runner::{build_simple_fixture, deterministic_always_success_lock_hash, execute_cellscript_script};

const RUST_CKB_TARGET: &str = "riscv64imac-unknown-none-elf";
const PARITY_BUDGET_PERCENT: u64 = 100;

const NFT_LOCK: &str = include_str!("fixtures/cost_corpus/nft_lock.cell");
const POOL_MERGE: &str = include_str!("fixtures/cost_corpus/pool_merge.cell");
const SCHEMA_ROLL: &str = include_str!("fixtures/cost_corpus/schema_roll.cell");

fn options() -> CompileOptions {
    CompileOptions {
        edition: CellScriptEdition::Edition2027,
        opt_level: 3,
        target: Some("riscv64-elf".to_string()),
        target_profile: Some("ckb".to_string()),
        ..Default::default()
    }
}

fn compile_cellscript(source: &str) -> CompileResult {
    compile_with_executable_surface_policy(source, options(), ExecutableSurfacePolicy::DenyFailClosed)
        .unwrap_or_else(|error| panic!("corpus source must compile: {error}\n{source}"))
}

fn maybe_dump_cellscript_assembly(scenario: &str, source: &str) {
    if env::var_os("CELLSCRIPT_COST_CORPUS_DUMP_ASM").is_none() {
        return;
    }
    let mut assembly_options = options();
    assembly_options.target = Some("riscv64-asm".to_string());
    let result = compile_with_executable_surface_policy(source, assembly_options, ExecutableSurfacePolicy::DenyFailClosed)
        .unwrap_or_else(|error| panic!("corpus assembly must compile: {error}\n{source}"));
    let assembly = String::from_utf8(result.artifact_bytes).expect("generated assembly is UTF-8");
    eprintln!("[cost-corpus-asm-begin] {scenario}");
    eprintln!("{assembly}");
    eprintln!("[cost-corpus-asm-end] {scenario}");
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_riscv_target_is_installed() -> bool {
    let Ok(output) = Command::new("rustup").args(["target", "list", "--installed"]).output() else {
        return true;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).lines().any(|line| line.trim() == RUST_CKB_TARGET)
}

fn command_is_available(command: &str) -> bool {
    Command::new(command).arg("--version").output().is_ok()
}

fn build_rust_reference(repo: &std::path::Path, temp_root: &std::path::Path, bin: &str) -> PathBuf {
    let manifest = repo.join("tests/fixtures/cost_corpus/Cargo.toml");
    let target_dir = temp_root.join("rust-target");
    let cargo = env::var_os("CARGO").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("cargo"));
    let output = Command::new(cargo)
        .args([
            "build",
            "--locked",
            "--manifest-path",
            manifest.to_str().expect("manifest path"),
            "--release",
            "--target",
            RUST_CKB_TARGET,
            "--bin",
            bin,
        ])
        .env("CARGO_TARGET_DIR", &target_dir)
        .output()
        .expect("run cargo build for the corpus Rust reference");
    assert!(
        output.status.success(),
        "corpus Rust reference build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let binary = target_dir.join(RUST_CKB_TARGET).join("release").join(bin);
    let stripped = temp_root.join(format!("{bin}.stripped"));
    fs::copy(&binary, &stripped).expect("copy for stripping");
    let status = Command::new("llvm-strip").arg(&stripped).status().expect("run llvm-strip");
    assert!(status.success(), "llvm-strip should succeed for {}", stripped.display());
    stripped
}

fn assert_byte_parity(scenario: &str, cellscript: &CompileResult, rust_stripped: &PathBuf) -> (u64, u64) {
    let cellscript_bytes = strip_vm_abi_trailer(&cellscript.artifact_bytes).len() as u64;
    let rust_bytes = fs::metadata(rust_stripped).expect("stripped metadata").len();
    eprintln!(
        "[cost-corpus] {scenario}: cellscript={cellscript_bytes}B rust_stripped={rust_bytes}B (ratio {:.2})",
        cellscript_bytes as f64 / rust_bytes as f64
    );
    assert!(
        cellscript_bytes * 100 <= rust_bytes * PARITY_BUDGET_PERCENT,
        "{scenario} artifact exceeds the matched stripped Rust reference: {cellscript_bytes} vs {rust_bytes} bytes"
    );
    (cellscript_bytes, rust_bytes)
}

fn witness_for(result: &CompileResult, args: &[EntryWitnessArg]) -> Bytes {
    let payload = if result.metadata.actions.is_empty() {
        result.metadata.locks[0].entry_witness_args(args)
    } else {
        result.metadata.actions[0].entry_witness_args(args)
    }
    .expect("encode declared entry arguments");
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

fn token_data(amount: u64) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes())
}

fn note_data(owner: [u8; 32], amount: u64) -> Bytes {
    let mut data = owner.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    Bytes::from(data)
}

#[test]
fn matched_cost_corpus_compiles_runs_and_stays_within_budget() {
    if !rust_riscv_target_is_installed() || !command_is_available("llvm-strip") {
        eprintln!("skipping cost corpus because {RUST_CKB_TARGET} or llvm-strip is unavailable");
        return;
    }
    let repo = repo_root();
    let temp = tempfile::tempdir().expect("tempdir");

    // --- Pool merge (two inputs, checked sum, output lock binding) ---
    let merge = compile_cellscript(POOL_MERGE);
    maybe_dump_cellscript_assembly("pool-merge", POOL_MERGE);
    let merge_rust = build_rust_reference(&repo, temp.path(), "pool-merge");
    assert_byte_parity("pool-merge", &merge, &merge_rust);
    let merge_rust_elf = fs::read(&merge_rust).expect("read rust ref");
    let recipient = deterministic_always_success_lock_hash();
    let merge_witness = witness_for(&merge, &[EntryWitnessArg::Address(recipient)]);
    for (amounts, output, expected_ok) in [(&[3u64, 4][..], 7, true), (&[3, 4][..], 8, false), (&[0, 4][..], 4, false)] {
        let mut fixture = build_simple_fixture(Bytes::default(), 2, 1);
        fixture.current_type_script_input_indices = vec![0, 1];
        fixture.witnesses = vec![merge_witness.clone()];
        for (input, amount) in fixture.inputs.iter_mut().zip(amounts) {
            input.data = token_data(*amount);
        }
        fixture.outputs[0].data = token_data(output);
        let cs = execute_cellscript_script(strip_vm_abi_trailer(&merge.artifact_bytes), &fixture);
        let rust = execute_cellscript_script(&merge_rust_elf, &fixture);
        assert_eq!(cs.exit_code == 0, expected_ok, "cellscript merge {amounts:?}->{output}");
        assert_eq!(rust.exit_code == 0, expected_ok, "rust merge {amounts:?}->{output}");
        if expected_ok {
            eprintln!("[cost-corpus] pool-merge positive cycles: cellscript={} rust={}", cs.cycles, rust.cycles);
            assert!(cs.cycles <= rust.cycles, "pool-merge cycles exceed matched Rust: {} vs {}", cs.cycles, rust.cycles);
        }
    }

    // --- Schema roll (two-field successor with one updated field) ---
    let roll = compile_cellscript(SCHEMA_ROLL);
    maybe_dump_cellscript_assembly("schema-roll", SCHEMA_ROLL);
    let roll_rust = build_rust_reference(&repo, temp.path(), "schema-roll");
    assert_byte_parity("schema-roll", &roll, &roll_rust);
    let roll_rust_elf = fs::read(&roll_rust).expect("read rust ref");
    let owner = deterministic_always_success_lock_hash();
    for (input_amount, output_amount, expected_ok) in [(7u64, 8, true), (7, 7, false), (7, 9, false)] {
        let mut fixture = build_simple_fixture(Bytes::default(), 1, 1);
        fixture.current_type_script_input_indices = vec![0];
        fixture.inputs[0].data = note_data(owner, input_amount);
        fixture.outputs[0].data = note_data(owner, output_amount);
        let cs = execute_cellscript_script(strip_vm_abi_trailer(&roll.artifact_bytes), &fixture);
        let rust = execute_cellscript_script(&roll_rust_elf, &fixture);
        assert_eq!(cs.exit_code == 0, expected_ok, "cellscript roll {input_amount}->{output_amount}");
        assert_eq!(rust.exit_code == 0, expected_ok, "rust roll {input_amount}->{output_amount}");
        if expected_ok {
            eprintln!("[cost-corpus] schema-roll positive cycles: cellscript={} rust={}", cs.cycles, rust.cycles);
            assert!(cs.cycles <= rust.cycles, "schema-roll cycles exceed matched Rust: {} vs {}", cs.cycles, rust.cycles);
        }
    }

    // --- NFT ownership lock (script args, data owner, witness claim) ---
    let nft = compile_cellscript(NFT_LOCK);
    maybe_dump_cellscript_assembly("nft-lock", NFT_LOCK);
    let nft_rust = build_rust_reference(&repo, temp.path(), "nft-lock");
    assert_byte_parity("nft-lock", &nft, &nft_rust);
    let nft_rust_elf = fs::read(&nft_rust).expect("read rust ref");
    let run_lock_pair = |data_owner: [u8; 32], elf: &[u8], witness: &Bytes| {
        let mut context = Context::new_with_deterministic_rng();
        let code = context.deploy_cell(Bytes::copy_from_slice(elf));
        let script = context
            .build_script_with_hash_type(&code, ckb_testtool::ckb_types::core::ScriptHashType::Data2, Bytes::default())
            .expect("build lock script");
        let cell = packed::CellOutput::new_builder().capacity::<packed::Uint64>(100_000_000_000u64.pack()).lock(script).build();
        let input = context.create_cell(cell.clone(), Bytes::copy_from_slice(&data_owner));
        let transaction = TransactionBuilder::default()
            .input(packed::CellInput::new_builder().previous_output(input).build())
            .output(cell)
            .output_data(Bytes::copy_from_slice(&data_owner).pack())
            .witness(witness.clone().pack())
            .build();
        let completed = context.complete_tx(transaction);
        context.verify_tx(&completed, 20_000_000)
    };
    for (data_owner, claimed, expected_ok) in [
        (owner, owner, true),
        (
            {
                let mut wrong = owner;
                wrong[0] ^= 0xff;
                wrong
            },
            owner,
            false,
        ),
        (
            owner,
            {
                let mut wrong = owner;
                wrong[1] ^= 0xff;
                wrong
            },
            false,
        ),
    ] {
        let nft_witness = witness_for(&nft, &[EntryWitnessArg::Address(claimed)]);
        let cs = run_lock_pair(data_owner, strip_vm_abi_trailer(&nft.artifact_bytes), &nft_witness);
        let rust_witness = packed::WitnessArgs::new_builder()
            .input_type(
                Some({
                    // The molecule field supplies its own 4-byte length framing;
                    // the content is exactly the CSARGv1 payload.
                    let mut payload = b"CSARGv1\0".to_vec();
                    payload.extend_from_slice(&claimed);
                    Bytes::from(payload)
                })
                .pack(),
            )
            .build()
            .as_bytes();
        let rust = run_lock_pair(data_owner, &nft_rust_elf, &rust_witness);
        assert_eq!(cs.is_ok(), expected_ok, "cellscript nft lock outcome");
        assert_eq!(rust.is_ok(), expected_ok, "rust nft lock outcome");
        if expected_ok {
            let cs_cycles = cs.expect("positive CellScript lock cycles");
            let rust_cycles = rust.expect("positive Rust lock cycles");
            eprintln!("[cost-corpus] nft-lock positive cycles: cellscript={cs_cycles} rust={rust_cycles}");
            assert!(cs_cycles <= rust_cycles, "nft-lock cycles exceed matched Rust: {cs_cycles} vs {rust_cycles}");
        }
    }

    // --- Real on-chain system scripts, deployed sizes for context only ---
    let registry = home_registry_path();
    for (name, relative) in [
        ("dao (mainnet system script)", "ckb-system-scripts-0.6.0/specs/cells/dao"),
        ("secp256k1_blake160_sighash_all", "ckb-system-scripts-0.6.0/specs/cells/secp256k1_blake160_sighash_all"),
        ("secp256k1_data", "ckb-system-scripts-0.6.0/specs/cells/secp256k1_data"),
    ] {
        if let Ok(meta) = fs::metadata(registry.join(relative)) {
            eprintln!("[cost-corpus] deployed context: {name} = {} bytes", meta.len());
        }
    }
    if let Ok(meta) = fs::metadata(repo.join("tests/benchmarks/ickb_diff/original_binaries/xudt")) {
        eprintln!("[cost-corpus] deployed context: xudt (iCKB corpus original) = {} bytes", meta.len());
    }
    eprintln!(
        "[cost-corpus] note: DAO/secp/xUDT have different feature scopes from every scenario above; sizes are context, not matched comparisons."
    );
}

fn home_registry_path() -> PathBuf {
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".cargo/registry/src/index.crates.io-1949cf8c6b5b557f")
}
