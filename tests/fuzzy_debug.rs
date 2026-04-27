use cellscript::lsp::{LspServer, Position, Range, TextDocumentContentChangeEvent};
use cellscript::{
    compile, decode_scheduler_witness_hex, encode_entry_witness_args_for_params, validate_compile_metadata, ArtifactFormat,
    CompileOptions, EntryWitnessArg, ParamMetadata,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;

const ENTRY_WITNESS_ABI_MAGIC: &[u8; 8] = b"CSARGv1\0";

#[derive(Clone)]
struct Rng64 {
    state: u64,
}

impl Rng64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn usize(&mut self, upper: usize) -> usize {
        if upper == 0 {
            0
        } else {
            (self.next() as usize) % upper
        }
    }
}

fn mutate_source(seed: &str, rng: &mut Rng64) -> String {
    const INSERTS: [&str; 24] = [
        "",
        "}",
        "{",
        "require ",
        "protected ",
        "witness ",
        "lock_args ",
        "source::group_input(0)",
        "witness::lock(source::group_input(0))",
        "env::sighash_all(source::group_input(0))",
        "Vec::<u64>",
        "[]",
        "with_capacity_floor(0)",
        "#[type_id(\"fuzz\")]",
        "return",
        "consume",
        "create",
        "destroy",
        "😀",
        "\0",
        "\"unterminated",
        "999999999999999999999999999999",
        "module",
        "::",
    ];

    let mut bytes = seed.as_bytes().to_vec();
    let rounds = 1 + rng.usize(10);
    for _ in 0..rounds {
        match rng.usize(5) {
            0 if !bytes.is_empty() => {
                let index = rng.usize(bytes.len());
                bytes.remove(index);
            }
            1 if !bytes.is_empty() => {
                let index = rng.usize(bytes.len());
                bytes[index] = (rng.next() & 0xff) as u8;
            }
            2 => {
                let insert = INSERTS[rng.usize(INSERTS.len())].as_bytes();
                let index = rng.usize(bytes.len() + 1);
                bytes.splice(index..index, insert.iter().copied());
            }
            3 if bytes.len() > 1 => {
                let start = rng.usize(bytes.len());
                let end = start + rng.usize(bytes.len() - start);
                bytes.drain(start..end);
            }
            _ => {
                bytes.reverse();
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn assert_compile_is_controlled(source: &str, options: CompileOptions, case: &str) {
    let outcome = catch_unwind(AssertUnwindSafe(|| compile(source, options)));
    let result = match outcome {
        Ok(result) => result,
        Err(payload) => panic!("compile panicked for {case}: {payload:?}\nsource:\n{source}"),
    };
    if let Err(err) = result {
        assert!(!err.message.trim().is_empty(), "empty compile error for {case}");
    }
}

fn assert_format_is_controlled(source: &str, case: &str) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let tokens = cellscript::lexer::lex(source)?;
        let module = cellscript::parser::parse(&tokens)?;
        cellscript::fmt::format_default(&module)
    }));
    let result = match outcome {
        Ok(result) => result,
        Err(payload) => panic!("format path panicked for {case}: {payload:?}\nsource:\n{source}"),
    };
    if let Err(err) = result {
        assert!(!err.message.trim().is_empty(), "empty format-path error for {case}");
    }
}

#[test]
fn fuzzy_mutated_sources_never_panic() {
    let seeds = [
        r#"
module cellscript::fuzz_basic

resource Token has store {
    amount: u64
}

action mint(amount: u64) -> Token {
    assert_invariant(amount > 0, "positive")
    create Token { amount }
}
"#,
        r#"
module cellscript::fuzz_lock

resource Wallet has store {
    owner: Address
}

lock owner(wallet: protected Wallet, owner: lock_args Address, claimed_owner: witness Address) -> bool {
    let input = source::group_input(0)
    let digest = env::sighash_all(input)
    let witness_lock = witness::lock(input)
    require owner == wallet.owner
    require claimed_owner == owner
    require witness_lock == digest
}
"#,
        include_str!("../examples/language/canonical_style.cell"),
        include_str!("../examples/language/v0_14_multi_step_pipeline.cell"),
    ];

    let mut rng = Rng64::new(0xC311_5C21_0014_F00D);
    for index in 0..160 {
        let seed = seeds[rng.usize(seeds.len())];
        let source = mutate_source(seed, &mut rng);
        let options = if index % 3 == 0 {
            CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }
        } else {
            CompileOptions::default()
        };
        assert_compile_is_controlled(&source, options, &format!("mutated-source-{index}"));
        assert_format_is_controlled(&source, &format!("mutated-source-{index}"));
    }
}

#[test]
fn fuzzy_lsp_incremental_edits_never_panic() {
    let uri = "file:///fuzzy.cell".to_string();
    let mut server = LspServer::new();
    let mut rng = Rng64::new(0x15F_0014_C0DE);
    let mut content = include_str!("../examples/language/canonical_style.cell").to_string();
    server.open_document(uri.clone(), content.clone());

    for index in 0..120 {
        let replacement = mutate_source("module cellscript::lsp_fuzz\n", &mut rng);
        let range = if index % 7 == 0 {
            None
        } else {
            let start = random_position(&mut rng);
            let end = if rng.usize(4) == 0 { random_position(&mut rng) } else { start };
            Some(Range { start, end })
        };
        let changes = vec![TextDocumentContentChangeEvent { range, range_length: None, text: replacement.clone() }];

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            server.update_document_incremental(&uri, changes);
            let _ = server.get_diagnostics(&uri);
            let pos = random_position(&mut rng);
            let _ = server.completion(&uri, pos);
            let _ = server.hover(&uri, pos);
            let _ = server.signature_help(&uri, pos);
            let _ = server.document_highlight(&uri, pos);
            let _ = server.selection_range(&uri, pos);
            let _ = server.folding_range(&uri);
            let _ = server.format_document(&uri);
        }));
        if let Err(payload) = outcome {
            panic!("LSP incremental edit path panicked at iteration {index}: {payload:?}");
        }

        if index % 11 == 0 {
            content = mutate_source(&content, &mut rng);
            let outcome = catch_unwind(AssertUnwindSafe(|| server.update_document(uri.clone(), content.clone())));
            if let Err(payload) = outcome {
                panic!("LSP full update path panicked at iteration {index}: {payload:?}");
            }
        }
    }
}

fn random_position(rng: &mut Rng64) -> Position {
    Position { line: rng.usize(32) as u32, character: rng.usize(96) as u32 }
}

#[test]
fn fuzzy_entry_witness_encoding_never_panics() {
    let result = compile(
        r#"
module cellscript::fuzz_entry_witness

resource Token has store {
    owner: Address
    amount: u64
}

action spend(owner: Address, amount: u64, active: bool, memo: [u8; 4]) -> u64 {
    assert_invariant(active, "active")
    return amount
}

lock owner_lock(token: protected Token, owner: lock_args Address, claimed_owner: witness Address) -> bool {
    require owner == token.owner
    require claimed_owner == owner
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let action = result.metadata.actions.iter().find(|action| action.name == "spend").expect("spend metadata");
    let lock = result.metadata.locks.iter().find(|lock| lock.name == "owner_lock").expect("owner_lock metadata");

    let mut rng = Rng64::new(0xAB1_000E_5717_5514);
    for index in 0..128 {
        let args = random_entry_args(&mut rng);
        let action_outcome = catch_unwind(AssertUnwindSafe(|| action.entry_witness_args(&args)));
        let action_result = action_outcome
            .unwrap_or_else(|payload| panic!("action entry witness panicked at iteration {index}: {payload:?}; args={args:?}"));
        if let Ok(bytes) = action_result {
            assert!(bytes.starts_with(ENTRY_WITNESS_ABI_MAGIC));
        }

        let lock_outcome = catch_unwind(AssertUnwindSafe(|| lock.entry_witness_args(&args)));
        let lock_result = lock_outcome
            .unwrap_or_else(|payload| panic!("lock entry witness panicked at iteration {index}: {payload:?}; args={args:?}"));
        if let Ok(bytes) = lock_result {
            assert!(bytes.starts_with(ENTRY_WITNESS_ABI_MAGIC));
        }
    }
}

fn random_entry_args(rng: &mut Rng64) -> Vec<EntryWitnessArg> {
    let count = rng.usize(8);
    (0..count)
        .map(|_| match rng.usize(9) {
            0 => EntryWitnessArg::Unit,
            1 => EntryWitnessArg::Bool(rng.next() & 1 == 1),
            2 => EntryWitnessArg::U8(rng.next() as u8),
            3 => EntryWitnessArg::U16(rng.next() as u16),
            4 => EntryWitnessArg::U32(rng.next() as u32),
            5 => EntryWitnessArg::U64(rng.next()),
            6 => EntryWitnessArg::U128(((rng.next() as u128) << 64) | rng.next() as u128),
            7 => EntryWitnessArg::Address(random_fixed_32(rng)),
            _ => {
                let len = rng.usize(48);
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push(rng.next() as u8);
                }
                EntryWitnessArg::Bytes(bytes)
            }
        })
        .collect()
}

fn random_fixed_32(rng: &mut Rng64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        *byte = rng.next() as u8;
    }
    bytes
}

#[test]
fn fuzzy_metadata_tampering_never_panics() {
    let result = compile(
        include_str!("../examples/language/v0_14_ckb_type_id_create.cell"),
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let mut rng = Rng64::new(0x0A11_DA7A_0014_0001);

    for index in 0..96 {
        let mut metadata = result.metadata.clone();
        match rng.usize(10) {
            0 => metadata.metadata_schema_version = rng.next() as u32,
            1 => metadata.compiler_version.push_str("-fuzz"),
            2 => metadata.artifact_format = "fuzz-format".to_string(),
            3 => metadata.target_profile.lock_args_abi.push_str("-fuzz"),
            4 => metadata.target_profile.output_data_abi.clear(),
            5 => metadata.runtime.vm_abi.version ^= rng.next() as u16,
            6 => metadata.runtime.vm_abi.format = "fuzz".to_string(),
            7 => metadata.molecule_schema_manifest.manifest_hash.push_str("00"),
            8 => {
                if let Some(action) = metadata.actions.first_mut() {
                    if let Some(binding) = action.create_set.first_mut().and_then(|create| create.ckb_output_data.as_mut()) {
                        binding.output_data_index = binding.output_data_index.saturating_add(1);
                    }
                }
            }
            _ => {
                if let Some(ty) = metadata.types.first_mut() {
                    if let Some(schema) = ty.molecule_schema.as_mut() {
                        schema.schema_hash.push_str("ff");
                    }
                }
            }
        }

        let outcome = catch_unwind(AssertUnwindSafe(|| validate_compile_metadata(&metadata, ArtifactFormat::RiscvAssembly)));
        let validation = outcome.unwrap_or_else(|payload| panic!("metadata validation panicked at iteration {index}: {payload:?}"));
        if let Err(err) = validation {
            assert!(!err.message.trim().is_empty());
        }
    }
}

#[test]
fn fuzzy_unicode_hex_inputs_are_controlled_errors() {
    for (index, input) in ["😀", "é0", "0é", "１２", "ab💥"].iter().enumerate() {
        let outcome = catch_unwind(AssertUnwindSafe(|| decode_scheduler_witness_hex(input)));
        let result = outcome.unwrap_or_else(|payload| panic!("scheduler hex decoder panicked at case {index}: {payload:?}"));
        let err = result.expect_err("unicode scheduler witness hex should be rejected");
        assert!(!err.message.trim().is_empty());
    }

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
name = "fuzzy_cli_hex"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module fuzzy_cli_hex::main

action owned(owner: Address) -> u64 {
    return 0
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("entry-witness")
        .arg("--action")
        .arg("owned")
        .arg("--arg")
        .arg("😀")
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success(), "unicode hex input should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "CLI hex decoder panicked instead of returning a diagnostic: {stderr}");
    assert!(stderr.contains("invalid hex byte"), "unexpected stderr: {stderr}");
}

#[test]
fn fuzzy_oversized_static_widths_are_controlled_errors() {
    let oversized = ParamMetadata {
        name: "oversized".to_string(),
        ty: "[u8; huge]".to_string(),
        is_mut: false,
        is_ref: false,
        source: "default".to_string(),
        protected_spend_surface: false,
        witness_data_source: false,
        lock_args_data_source: false,
        cell_bound_abi: false,
        schema_pointer_abi: false,
        schema_length_abi: false,
        fixed_byte_pointer_abi: false,
        fixed_byte_length_abi: false,
        fixed_byte_len: Some(usize::MAX),
        type_hash_pointer_abi: false,
        type_hash_length_abi: false,
        type_hash_len: None,
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| encode_entry_witness_args_for_params(&[oversized], &[])));
    let result = outcome.unwrap_or_else(|payload| panic!("oversized entry witness metadata panicked: {payload:?}"));
    let err = result.expect_err("oversized entry witness metadata should be rejected");
    assert!(err.message.contains("payload length"), "unexpected error: {}", err.message);

    let huge_array_source = r#"
module cellscript::huge_width_fuzz

struct Huge {
    data: [u8; 18446744073709551615],
}

action inspect(value: Huge) -> u64 {
    return 0
}
"#;
    assert_compile_is_controlled(huge_array_source, CompileOptions::default(), "huge-static-array-width");
}
