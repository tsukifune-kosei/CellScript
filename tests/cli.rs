mod common;

use base64::Engine as _;
use common::cellc_command;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;
use unicode_width::UnicodeWidthStr;

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_json_for_test<T: serde::Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap();
    hex_lower(&cellscript::ckb_blake2b256(&bytes))
}

fn lock_package(root: &std::path::Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("lock").output().unwrap();
    assert!(output.status.success(), "lock failed: {}", String::from_utf8_lossy(&output.stderr));
}

fn ckb_script_hash_for_test(code_hash: &str, hash_type: &str, args: &str) -> String {
    let code_hash_bytes = hex::decode(code_hash.trim_start_matches("0x")).unwrap();
    let hash_type_byte = match hash_type {
        "data" => 0u8,
        "type" => 1u8,
        "data1" => 2u8,
        "data2" => 4u8,
        other => panic!("unknown hash_type: {other}"),
    };
    let args_bytes = hex::decode(args.trim_start_matches("0x")).unwrap();
    let mut args_molecule = Vec::with_capacity(4 + args_bytes.len());
    args_molecule.extend_from_slice(&(args_bytes.len() as u32).to_le_bytes());
    args_molecule.extend_from_slice(&args_bytes);

    let header_size = 4 + 4 * 3;
    let field_sizes = [32usize, 1usize, args_molecule.len()];
    let mut cursor = header_size;
    let mut offsets = Vec::with_capacity(3);
    for size in field_sizes {
        offsets.push(cursor);
        cursor += size;
    }

    let mut serialized = Vec::with_capacity(cursor);
    serialized.extend_from_slice(&(cursor as u32).to_le_bytes());
    for offset in offsets {
        serialized.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    serialized.extend_from_slice(&code_hash_bytes);
    serialized.push(hash_type_byte);
    serialized.extend_from_slice(&args_molecule);

    format!("0x{}", hex_lower(&cellscript::ckb_blake2b256(&serialized)))
}

fn run_mcp_messages(messages: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cellscript-mcp"))
        .env("CELLSCRIPT_CELLC", env!("CARGO_BIN_EXE_cellc"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cellscript-mcp");

    {
        let stdin = child.stdin.as_mut().expect("mcp stdin");
        for message in messages {
            writeln!(stdin, "{}", serde_json::to_string(&message).unwrap()).unwrap();
        }
    }
    drop(child.stdin.take());

    let mut stdout = String::new();
    child.stdout.as_mut().expect("mcp stdout").read_to_string(&mut stdout).unwrap();
    let output = child.wait_with_output().expect("wait for cellscript-mcp");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

#[test]
fn cellc_top_level_help_shows_commands_and_direct_source_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("--help").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cellc <COMMAND> [OPTIONS]"), "unexpected help: {stdout}");
    assert!(stdout.contains("Direct source mode:"), "unexpected help: {stdout}");
    assert!(stdout.contains("build"), "unexpected help: {stdout}");
    assert!(stdout.contains("verify-artifact"), "unexpected help: {stdout}");
    assert!(stdout.contains("tx"), "unexpected help: {stdout}");
    assert!(stdout.contains("protocol"), "unexpected help: {stdout}");
    assert!(stdout.contains("deploy"), "unexpected help: {stdout}");
    assert!(!stdout.contains("validate-tx"), "legacy tx alias should be hidden from top-level help: {stdout}");
    assert!(!stdout.contains("deploy-plan"), "legacy deploy alias should be hidden from top-level help: {stdout}");
    assert!(stdout.contains("--explain <CODE>"), "unexpected help: {stdout}");
    assert!(stdout.contains("--json"), "unexpected help: {stdout}");
    assert!(!stdout.contains("--message-format"), "deprecated flag should be hidden: {stdout}");
    assert!(stdout.contains("--color <WHEN>"), "unexpected help: {stdout}");
    assert!(stdout.contains("Run `cellc <command> --help`"), "unexpected help: {stdout}");
}

#[test]
fn cellc_short_and_long_version_flags_share_one_output() {
    let short = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("-V").output().unwrap();
    let long = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("--version").output().unwrap();
    assert!(short.status.success());
    assert!(long.status.success());
    assert_eq!(short.stdout, long.stdout);
    assert_eq!(String::from_utf8_lossy(&long.stdout).lines().count(), 1);
}

#[test]
fn cellc_top_level_explain_matches_explain_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["--explain", "E0001"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CellScript runtime error E0001"), "unexpected explain output: {stdout}");
    assert!(stdout.contains("syscall-failed"), "unexpected explain output: {stdout}");
}

#[test]
fn cellc_list_reports_package_commands_without_direct_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("--list").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Installed cellc commands"), "unexpected list: {stdout}");
    assert!(stdout.contains("build"), "unexpected list: {stdout}");
    assert!(stdout.contains("tx"), "unexpected list: {stdout}");
    assert!(stdout.contains("protocol"), "unexpected list: {stdout}");
    assert!(stdout.contains("deploy"), "unexpected list: {stdout}");
    assert!(stdout.contains("registry"), "unexpected list: {stdout}");
    assert!(stdout.contains("receipt"), "unexpected list: {stdout}");
    assert!(stdout.contains("sign-receipt"), "unexpected list: {stdout}");
    assert!(stdout.contains("verify-receipt"), "unexpected list: {stdout}");
    assert!(stdout.contains("certify"), "unexpected list: {stdout}");
    assert!(!stdout.contains("validate-tx"), "legacy tx alias should be hidden from command list: {stdout}");
    assert!(!stdout.contains("deploy-plan"), "legacy deploy alias should be hidden from command list: {stdout}");
    assert!(!stdout.contains("registry-verify"), "legacy registry alias should be hidden from command list: {stdout}");
    assert!(!stdout.contains("package-verify"), "legacy package alias should be hidden from command list: {stdout}");
    assert!(!stdout.contains("--target-profile"), "unexpected direct flag in command list: {stdout}");
}

#[test]
fn cellc_auth_help_hides_legacy_login_alias() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["auth", "--help"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("capability"), "unexpected auth help: {stdout}");
    assert!(stdout.contains("reproducer"), "unexpected auth help: {stdout}");
    assert!(!stdout.contains("login"), "legacy auth login alias should be hidden from auth help: {stdout}");
}

#[test]
fn cellc_help_subcommand_delegates_to_package_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["help", "build"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compile the current package"), "unexpected help: {stdout}");
    assert!(stdout.contains("Usage: cellc build [OPTIONS]"), "unexpected help: {stdout}");
}

#[test]
fn cellc_help_reports_canonical_nested_021_groups() {
    let explain = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["help", "explain"]).output().unwrap();
    assert!(explain.status.success(), "{}", String::from_utf8_lossy(&explain.stderr));
    let explain_stdout = String::from_utf8_lossy(&explain.stdout);
    assert!(explain_stdout.contains("profile"), "unexpected explain help: {explain_stdout}");
    assert!(explain_stdout.contains("proof"), "unexpected explain help: {explain_stdout}");
    assert!(explain_stdout.contains("assumptions"), "unexpected explain help: {explain_stdout}");
    assert!(explain_stdout.contains("generics"), "unexpected explain help: {explain_stdout}");
    assert!(explain_stdout.contains("graph"), "unexpected explain help: {explain_stdout}");

    let tx = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["help", "tx"]).output().unwrap();
    assert!(tx.status.success(), "{}", String::from_utf8_lossy(&tx.stderr));
    let tx_stdout = String::from_utf8_lossy(&tx.stdout);
    assert!(tx_stdout.contains("Validate, solve, and trace transaction evidence"), "unexpected tx help: {tx_stdout}");
    assert!(tx_stdout.contains("validate"), "unexpected tx help: {tx_stdout}");
    assert!(tx_stdout.contains("solve"), "unexpected tx help: {tx_stdout}");
    assert!(tx_stdout.contains("trace"), "unexpected tx help: {tx_stdout}");

    let deploy = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["help", "deploy"]).output().unwrap();
    assert!(deploy.status.success(), "{}", String::from_utf8_lossy(&deploy.stderr));
    let deploy_stdout = String::from_utf8_lossy(&deploy.stdout);
    assert!(deploy_stdout.contains("Plan, verify, diff, and lock deployment evidence"), "unexpected deploy help: {deploy_stdout}");
    assert!(deploy_stdout.contains("plan"), "unexpected deploy help: {deploy_stdout}");
    assert!(deploy_stdout.contains("verify"), "unexpected deploy help: {deploy_stdout}");
    assert!(deploy_stdout.contains("lock-deps"), "unexpected deploy help: {deploy_stdout}");
}

#[test]
fn cellscript_mcp_lists_read_only_tools() {
    let responses = run_mcp_messages(vec![
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "clientInfo": { "name": "cellscript-test", "version": "0" },
                "capabilities": {}
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "cellscript_command_tree",
                "arguments": {}
            }
        }),
    ]);

    assert_eq!(responses.len(), 3, "unexpected MCP responses: {responses:?}");
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "cellscript-mcp");
    let tools = responses[1]["result"]["tools"].as_array().expect("tools array");
    let names = tools.iter().filter_map(|tool| tool["name"].as_str()).collect::<Vec<_>>();
    assert!(names.contains(&"cellscript_check"), "missing check tool: {names:?}");
    assert!(names.contains(&"cellscript_protocol_graph"), "missing graph tool: {names:?}");
    assert!(names.contains(&"cellscript_evidence_levels"), "missing evidence tool: {names:?}");
    assert!(!names.iter().any(|name| name.contains("sign") || name.contains("submit") || name.contains("publish")), "{names:?}");

    let command_tree = &responses[2]["result"]["structuredContent"];
    assert_eq!(command_tree["source"], "cellscript::cli::commands::CliParser::command");
    let commands = command_tree["commands"].as_array().expect("commands array");
    assert!(commands.iter().any(|command| command["name"] == "explain"), "missing explain group: {command_tree}");
    assert!(commands.iter().any(|command| command["name"] == "tx"), "missing tx group: {command_tree}");
    assert!(commands.iter().any(|command| command["name"] == "deploy"), "missing deploy group: {command_tree}");
    assert!(command_tree["legacy_aliases"]
        .as_array()
        .is_some_and(|aliases| aliases.iter().any(|alias| alias["legacy"] == "validate-tx" && alias["canonical"] == "tx validate")));
}

#[test]
fn cellscript_mcp_reads_the_diagnostics_topic() {
    let responses = run_mcp_messages(vec![serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "cellscript_docs_topic",
            "arguments": { "topic": "diagnostics" }
        }
    })]);

    let result = &responses[0]["result"];
    assert_eq!(result["isError"], false, "unexpected MCP result: {result}");
    let documents = result["structuredContent"]["documents"].as_array().expect("diagnostics documents");
    assert!(documents.iter().any(|document| {
        document["path"].as_str().is_some_and(|path| path.ends_with("Tutorial-13-Agentic-Loops-and-cellscript-mcp.md"))
    }));
}

#[test]
fn cellscript_mcp_reads_the_022_language_and_fiber_topics() {
    for (topic, expected_path) in [
        ("language-0.22", "docs/releases/CELLSCRIPT_0_22_RELEASE_NOTES.md"),
        ("fiber-interop", "examples/fiber/README.md"),
        ("release-0.22", "docs/releases/CELLSCRIPT_0_22_RELEASE_NOTES.md"),
    ] {
        let responses = run_mcp_messages(vec![serde_json::json!({
            "jsonrpc": "2.0",
            "id": topic,
            "method": "tools/call",
            "params": {
                "name": "cellscript_docs_topic",
                "arguments": { "topic": topic }
            }
        })]);
        let result = &responses[0]["result"];
        let documents = result["structuredContent"]["documents"].as_array().expect("0.22 topic documents");
        assert!(
            documents.iter().any(|document| document["path"] == expected_path),
            "missing {expected_path} from {topic}: {documents:?}"
        );
    }
}

#[test]
fn cellscript_mcp_check_tool_preserves_structured_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "mcp-demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src/main.cell"),
        r#"
module demo::main

resource Token has store {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let responses = run_mcp_messages(vec![
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "cellscript_check",
                "arguments": {
                    "cwd": root.display().to_string(),
                    "target_profile": "ckb"
                }
            }
        }),
    ]);

    let result = &responses[1]["result"];
    assert_eq!(result["isError"], false, "unexpected MCP result: {result}");
    let structured = &result["structuredContent"];
    assert_eq!(structured["status"], "ok", "unexpected tool status: {structured}");
    assert_eq!(structured["evidence_level"], "compile-only");
    assert_eq!(structured["writes"], false);
    assert!(structured["stderr"].as_str().is_some(), "stderr boundary missing: {structured}");
    let stdout = structured["stdout"].as_str().expect("stdout");
    let check_json: serde_json::Value = serde_json::from_str(stdout).unwrap();
    assert_eq!(check_json["status"], "ok", "unexpected check JSON: {check_json}");
}

#[test]
fn cellc_explain_profile_canonical_group_matches_legacy_alias() {
    let canonical = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "profile", "ckb", "--json"]).output().unwrap();
    assert!(canonical.status.success(), "{}", String::from_utf8_lossy(&canonical.stderr));

    let legacy = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain-profile", "ckb", "--json"]).output().unwrap();
    assert!(legacy.status.success(), "{}", String::from_utf8_lossy(&legacy.stderr));

    assert_eq!(canonical.stdout, legacy.stdout);
}

fn protocol_graph_pool_source() -> String {
    r#"
module test

resource Pool has store {
    reserve: u64
}

action swap(input pool: Pool) -> output: Pool {
    transition pool -> output
    verification
        require output.reserve == pool.reserve
}
"#
    .to_string()
}

fn protocol_graph_explicit_role_source() -> String {
    r#"
module test

enum SwapState {
    Pending,
    Claimed,
}

resource SwapLock has store {
    state: SwapState,
    participant: Address,
}

flow SwapLock.state {
    initial Pending;
    terminal Claimed;
    Pending -> Claimed;
}

action claim(input swap: SwapLock, witness participant: Address) -> output: SwapLock {
    transition swap.state: Pending -> output.state: Claimed
    verification
        require participant == swap.participant
}
"#
    .to_string()
}

fn protocol_graph_conflicting_role_source() -> String {
    r#"
module test

enum SwapState {
    Pending,
    Refunded,
}

resource SwapLock has store {
    state: SwapState,
    initiator: Address,
    participant: Address,
}

flow SwapLock.state {
    initial Pending;
    terminal Refunded;
    Pending -> Refunded;
}

action refund(input swap: SwapLock, witness initiator: Address) -> output: SwapLock {
    transition swap.state: Pending -> output.state: Refunded
    verification
        require initiator == swap.participant
}
"#
    .to_string()
}

fn protocol_graph_weak_field_role_source() -> String {
    r#"
module test

resource Vault has store {
    owner: Address,
    amount: u64,
}

action inspect(input vault: Vault) -> output: Vault {
    verification
        require output.amount == vault.amount
}
"#
    .to_string()
}

#[test]
fn cellc_explain_graph_reports_cyclic_protocol_view() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    std::fs::write(&input, protocol_graph_pool_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "graph"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(graph["schema"], "cellscript-protocol-graph-v0.22");
    assert_eq!(graph["derivation"], "derived-from-compile-metadata");
    assert_eq!(graph["consensus_checked"], false);
    assert_eq!(graph["cycle_detected"], true);
    assert!(graph["self_loop_count"].as_u64().unwrap() >= 1, "expected self-loop graph: {graph}");
    assert!(graph["edges"].as_array().unwrap().iter().any(|edge| {
        edge["action_name"] == "swap"
            && edge["source_vertex"] == "Pool"
            && edge["target_vertex"] == "Pool"
            && edge["derivation"] == "type-pattern"
    }));
    assert!(graph["role_lints"].as_array().unwrap().iter().any(|lint| lint["code"] == "PG-ROLE-MISSING"));
}

#[test]
fn cellc_explain_graph_attributes_explicit_protocol_role_without_authorization_claim() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("role.cell");
    std::fs::write(&input, protocol_graph_explicit_role_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "graph"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let edge = graph["edges"].as_array().unwrap().iter().find(|edge| edge["action_name"] == "claim").expect("claim graph edge");
    assert_eq!(edge["role"], "participant");
    assert_eq!(edge["role_source"], "verification-predicate");
    assert_eq!(edge["role_strength"], "explicit");
    assert_eq!(edge["role_status"], "attributed");
    assert_eq!(edge["role_evidence_tier"], "metadata-only");
    assert_eq!(edge["authorization_proven"], false);
    assert_eq!(edge["role_conflict"], false);
    assert_eq!(edge["role_source_used"]["actor_binding"], "participant");
    assert_eq!(edge["role_source_used"]["actor_source"], "witness");
    assert_eq!(graph["role_model"]["authorization_proven"], false);
    assert_eq!(graph["role_warning_count"], 0);
}

#[test]
fn cellc_explain_graph_lints_weak_field_role_without_overclaiming_authority() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("weak-role.cell");
    std::fs::write(&input, protocol_graph_weak_field_role_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "graph"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let edge = graph["edges"].as_array().unwrap().first().expect("Vault graph edge");
    assert_eq!(edge["role"], "owner");
    assert_eq!(edge["role_source"], "field-name");
    assert_eq!(edge["role_status"], "weak-field-inference");
    assert_eq!(edge["authorization_proven"], false);
    assert!(edge["role_warnings"].as_array().unwrap().iter().any(|warning| warning["code"] == "PG-ROLE-WEAK-FIELD"));
}

#[test]
fn cellc_explain_graph_resolves_conflicting_role_sources_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("conflicting-role.cell");
    std::fs::write(&input, protocol_graph_conflicting_role_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "graph"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let edge = graph["edges"].as_array().unwrap().iter().find(|edge| edge["action_name"] == "refund").expect("refund graph edge");
    assert_eq!(edge["role"], "participant");
    assert_eq!(edge["role_source"], "verification-predicate");
    assert_eq!(edge["role_status"], "conflicting");
    assert_eq!(edge["role_conflict"], true);
    assert!(edge["role_candidates"]
        .as_array()
        .unwrap()
        .iter()
        .any(|candidate| { candidate["role"] == "initiator" && candidate["source"] == "witness-binding" }));
    assert!(graph["role_lints"].as_array().unwrap().iter().any(|warning| warning["code"] == "PG-ROLE-CONFLICT"));
}

#[test]
fn cellc_explain_graph_mermaid_and_legacy_alias_match_json() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    std::fs::write(&input, protocol_graph_pool_source()).unwrap();

    let canonical = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "graph"]).arg(&input).arg("--json").output().unwrap();
    assert!(canonical.status.success(), "{}", String::from_utf8_lossy(&canonical.stderr));

    let legacy = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("explain-graph").arg(&input).arg("--json").output().unwrap();
    assert!(legacy.status.success(), "{}", String::from_utf8_lossy(&legacy.stderr));
    assert_eq!(canonical.stdout, legacy.stdout);

    let mermaid = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["explain", "graph"])
        .arg(&input)
        .args(["--format", "mermaid"])
        .output()
        .unwrap();
    assert!(mermaid.status.success(), "{}", String::from_utf8_lossy(&mermaid.stderr));
    let mermaid_stdout = String::from_utf8_lossy(&mermaid.stdout);
    assert!(mermaid_stdout.contains("flowchart LR"), "unexpected mermaid output: {mermaid_stdout}");
    assert!(mermaid_stdout.contains("Pool"), "unexpected mermaid output: {mermaid_stdout}");
    assert!(mermaid_stdout.contains("swap"), "unexpected mermaid output: {mermaid_stdout}");
}

#[test]
fn cellc_audit_bundle_embeds_protocol_graph() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    let output_dir = dir.path().join("audit");
    std::fs::write(&input, protocol_graph_pool_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("audit-bundle")
        .arg(&input)
        .args(["--output"])
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(output_dir.join("audit-bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["protocol_graph"]["schema"], "cellscript-protocol-graph-v0.22");
    assert_eq!(bundle["protocol_graph"]["cycle_detected"], true);
    assert_eq!(bundle["template_layouts"][0]["schema"], "cellscript-template-layout-v0.21");
    assert_eq!(bundle["template_layouts"][0]["type_name"], "Pool");
    assert_eq!(bundle["template_layouts"][0]["layout"], "Flat");
    assert_eq!(bundle["template_layouts"][0]["consensus_checked"], false);
}

/// Source whose `flow` block declares a genuine state-machine cycle (Open <-> Closed),
/// which must lower to a `RootRequired` template layout with `state_machine_acyclic = false`.
fn cyclic_flow_template_layout_source() -> String {
    r#"
module demo::cyclic_flow

resource Pool has store {
    state: u8
    reserve: u64
}

flow Pool.state {
    Open -> Closed;
    Closed -> Open;
}

action close(pool_before: Pool) -> pool_after: Pool {
    transition pool_before.state: Open -> pool_after.state: Closed
    verification
        require pool_after.reserve == pool_before.reserve
}

action reopen(pool_before: Pool) -> pool_after: Pool {
    transition pool_before.state: Closed -> pool_after.state: Open
    verification
        require pool_after.reserve == pool_before.reserve
}
"#
    .to_string()
}

/// Source whose `flow` block declares a linear (acyclic) state machine, which must
/// lower to a `PathOnlyAllowed` template layout with `state_machine_acyclic = true`.
fn acyclic_flow_template_layout_source() -> String {
    r#"
module demo::acyclic_flow

resource Grant has store {
    state: u8
    amount: u64
}

flow Grant.state {
    Granted -> Claimable;
    Claimable -> FullyClaimed;
}

action claim(grant_before: Grant) -> grant_after: Grant {
    transition grant_before.state: Claimable -> grant_after.state: FullyClaimed
    verification
        require grant_after.amount == grant_before.amount
}
"#
    .to_string()
}

#[test]
fn cellc_audit_bundle_marks_cyclic_flow_type_as_root_required() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    let output_dir = dir.path().join("audit");
    std::fs::write(&input, cyclic_flow_template_layout_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("audit-bundle")
        .arg(&input)
        .args(["--output"])
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(output_dir.join("audit-bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["protocol_graph"]["schema"], "cellscript-protocol-graph-v0.22");
    assert_eq!(bundle["protocol_graph"]["cycle_detected"], true);
    let cyclic_layout = bundle["template_layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layout| layout["type_name"] == "Pool")
        .expect("Pool template layout");
    assert_eq!(cyclic_layout["schema"], "cellscript-template-layout-v0.21");
    assert_eq!(cyclic_layout["cycle_policy"], "RootRequired", "unexpected layout: {cyclic_layout}");
    assert_eq!(cyclic_layout["state_machine_acyclic"], false);
    assert_eq!(cyclic_layout["consensus_checked"], false);
}

#[test]
fn cellc_audit_bundle_marks_acyclic_flow_type_as_path_only() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("grant.cell");
    let output_dir = dir.path().join("audit");
    std::fs::write(&input, acyclic_flow_template_layout_source()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("audit-bundle")
        .arg(&input)
        .args(["--output"])
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(output_dir.join("audit-bundle.json")).unwrap()).unwrap();
    let acyclic_layout = bundle["template_layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layout| layout["type_name"] == "Grant")
        .expect("Grant template layout");
    assert_eq!(acyclic_layout["schema"], "cellscript-template-layout-v0.21");
    assert_eq!(acyclic_layout["cycle_policy"], "PathOnlyAllowed", "unexpected layout: {acyclic_layout}");
    assert_eq!(acyclic_layout["state_machine_acyclic"], true);
}

#[test]
fn cellc_audit_bundle_template_layout_hash_distinguishes_cyclic_vs_acyclic() {
    let dir = tempfile::tempdir().unwrap();
    let cyclic_input = dir.path().join("cyclic.cell");
    let acyclic_input = dir.path().join("acyclic.cell");
    std::fs::write(&cyclic_input, cyclic_flow_template_layout_source()).unwrap();
    std::fs::write(&acyclic_input, acyclic_flow_template_layout_source()).unwrap();

    let build_cyclic =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&cyclic_input).arg("-o").arg(dir.path().join("cyclic.s")).status().unwrap();
    assert!(build_cyclic.success());
    let build_acyclic =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&acyclic_input).arg("-o").arg(dir.path().join("acyclic.s")).status().unwrap();
    assert!(build_acyclic.success());

    let cyclic_meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("cyclic.s.meta.json")).unwrap()).unwrap();
    let acyclic_meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("acyclic.s.meta.json")).unwrap()).unwrap();

    let cyclic_hash =
        cyclic_meta["template_layouts"].as_array().unwrap().iter().find(|layout| layout["type_name"] == "Pool").expect("Pool layout")
            ["template_layout_hash"]
            .as_str()
            .unwrap();
    let acyclic_hash = acyclic_meta["template_layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layout| layout["type_name"] == "Grant")
        .expect("Grant layout")["template_layout_hash"]
        .as_str()
        .unwrap();
    // The canonical hash input embeds the acyclic/cyclic marker and the cycle
    // policy, so the two layouts must produce distinct hashes.
    assert_eq!(cyclic_hash.len(), 64);
    assert_eq!(acyclic_hash.len(), 64);
    assert_ne!(cyclic_hash, acyclic_hash, "cyclic and acyclic layout hashes must differ");
}

#[test]
fn cellc_verify_artifact_rejects_template_layout_consensus_checked_true() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    let output = dir.path().join("pool.s");
    std::fs::write(&input, cyclic_flow_template_layout_source()).unwrap();
    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let metadata_path = dir.path().join("pool.s.meta.json");
    let mut metadata_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    // RC deferral: consensus-checked TemplateLayout commitments are not supported,
    // so externally-supplied metadata carrying consensus_checked=true must be rejected.
    metadata_json["template_layouts"][0]["consensus_checked"] = serde_json::json!(true);
    let tampered = dir.path().join("consensus-true.meta.json");
    std::fs::write(&tampered, serde_json::to_vec_pretty(&metadata_json).unwrap()).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--metadata")
        .arg(&tampered)
        .output()
        .unwrap();
    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(
        stderr.contains("cannot set consensus_checked=true until a backend verifier supports TemplateLayout commitments"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cellc_verify_artifact_rejects_template_layout_unsupported_cycle_policy() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    let output = dir.path().join("pool.s");
    std::fs::write(&input, cyclic_flow_template_layout_source()).unwrap();
    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let metadata_path = dir.path().join("pool.s.meta.json");
    let mut metadata_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    metadata_json["template_layouts"][0]["cycle_policy"] = serde_json::json!("Provisional");
    let tampered = dir.path().join("bad-cycle-policy.meta.json");
    std::fs::write(&tampered, serde_json::to_vec_pretty(&metadata_json).unwrap()).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--metadata")
        .arg(&tampered)
        .output()
        .unwrap();
    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("unsupported cycle_policy"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_verify_artifact_rejects_template_layout_unsupported_layout() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    let output = dir.path().join("pool.s");
    std::fs::write(&input, cyclic_flow_template_layout_source()).unwrap();
    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let metadata_path = dir.path().join("pool.s.meta.json");
    let mut metadata_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    metadata_json["template_layouts"][0]["layout"] = serde_json::json!("MerkleRoot");
    let tampered = dir.path().join("bad-layout.meta.json");
    std::fs::write(&tampered, serde_json::to_vec_pretty(&metadata_json).unwrap()).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--metadata")
        .arg(&tampered)
        .output()
        .unwrap();
    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("unsupported layout"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_unknown_bare_command_suggests_nearest_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("buil").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no such command or input: `buil`"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("similar name exists: `build`"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("pass a .cell file, package directory, or Cell.toml"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_command_typo_wins_over_an_ambiguous_extensionless_file() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("buil"), "not CellScript").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(temp.path()).arg("buil").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no such command or input: `buil`"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("similar name exists: `build`"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_structured_failures_expose_usage_and_io_exit_categories() {
    let usage = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["--json", "--not-a-cellc-option"]).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
    assert!(usage.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&usage.stderr));
    let usage_json: serde_json::Value = serde_json::from_slice(&usage.stdout).unwrap();
    assert_eq!(usage_json["category"], "usage");
    assert_eq!(usage_json["exit_code"], 2);

    let missing = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["--json", "missing.cell"]).output().unwrap();
    assert_eq!(missing.status.code(), Some(74));
    assert!(missing.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&missing.stderr));
    let missing_json: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing_json["category"], "io");
    assert_eq!(missing_json["exit_code"], 74);
    assert_eq!(missing_json["diagnostics"][0]["file"], "missing.cell");
}

#[test]
fn cellc_empty_directory_error_suggests_init_or_source_input() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(temp.path()).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error: Cell.toml not found"), "unexpected stderr: {stderr}");
    assert!(!stderr.contains("line 0"), "unexpected no-span line marker: {stderr}");
    assert!(stderr.contains("cellc init"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("pass a .cell file"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_direct_parse_error_prints_source_context() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.cell");
    std::fs::write(
        &input,
        r#"module demo::bad

resource Token {
    amount:
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("--parse").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error: expected type"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("-->"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("bad.cell:4:12") || stderr.contains("bad.cell:4:13"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("4 |     amount:"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("^ expected type"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_source_snippet_uses_terminal_width_for_unicode_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("unicode.cell");
    let bad_line = "        let 数量: u64 true";
    std::fs::write(
        &input,
        format!("module unicode_error\n\naction bad() -> bool {{\n    verification\n{bad_line}\n        return true\n}}\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("--parse").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let underline = stderr.lines().find(|line| line.contains("^ expected")).expect("unicode underline");
    let gutter_end = underline.find("| ").expect("snippet gutter") + 2;
    let caret = underline.find('^').expect("caret");
    let expected_offset = UnicodeWidthStr::width(&bad_line[..bad_line.find("true").unwrap()]);
    assert_eq!(caret - gutter_end, expected_offset, "unexpected underline: {underline}");
}

#[test]
fn cellc_parse_reports_multiple_recovered_syntax_errors() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.cell");
    std::fs::write(
        &input,
        r#"module multi_parse_errors

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("--parse").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected '=', found 'true'"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("expected '=', found integer 1"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("5 |         let first: u64 true"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("6 |         let second: bool 1"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("aborting due to 2 diagnostics"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_direct_compile_reports_multiple_recovered_syntax_errors() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.cell");
    std::fs::write(
        &input,
        r#"module multi_parse_errors

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected '=', found 'true'"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("expected '=', found integer 1"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("5 |         let first: u64 true"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("6 |         let second: bool 1"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("aborting due to 2 diagnostics"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_direct_json_reports_recovered_syntax_errors_on_stdout() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.cell");
    std::fs::write(
        &input,
        r#"module multi_parse_errors

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("--json").arg("--parse").arg(&input).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["diagnostic_count"], 2, "unexpected diagnostics: {stdout}");
    assert_eq!(stdout["error_count"], 2);
    assert_eq!(stdout["warning_count"], 0);
    let diagnostics = stdout["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected '=', found 'true'")));
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected '=', found integer 1")));
    assert!(diagnostics.iter().all(|diagnostic| diagnostic["range"]["start"]["line"].as_u64().unwrap_or_default() > 0));
    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!raw_stdout.contains("-->"), "JSON diagnostics should not include human source snippets: {raw_stdout}");
}

#[test]
fn cellc_direct_json_success_is_a_single_stdout_document() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("ok.cell");
    std::fs::write(&input, "module demo::ok\naction main() -> u64 {\n    verification\n        0\n}\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["--json", "--lex"]).arg(&input).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["mode"], "lex");
    assert!(stdout["token_count"].as_u64().unwrap_or_default() > 0);
    assert!(stdout["tokens"].is_array());
}

#[test]
fn cellc_direct_color_control_overrides_ansi_output() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.cell");
    std::fs::write(
        &input,
        r#"module demo::bad

resource Token {
    amount:
}
"#,
    )
    .unwrap();

    let always = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("--color=always").arg("--parse").arg(&input).output().unwrap();
    assert!(!always.status.success(), "unexpected success: {}", String::from_utf8_lossy(&always.stdout));
    let always_stderr = String::from_utf8_lossy(&always.stderr);
    assert!(always_stderr.contains("\u{1b}["), "expected ANSI colour when forced: {always_stderr}");

    let never = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("--color=never").arg("--parse").arg(&input).output().unwrap();
    assert!(!never.status.success(), "unexpected success: {}", String::from_utf8_lossy(&never.stdout));
    let never_stderr = String::from_utf8_lossy(&never.stderr);
    assert!(!never_stderr.contains("\u{1b}["), "unexpected ANSI colour when disabled: {never_stderr}");

    let no_color = Command::new(env!("CARGO_BIN_EXE_cellc")).env("NO_COLOR", "1").arg("--parse").arg(&input).output().unwrap();
    assert!(!no_color.status.success(), "unexpected success: {}", String::from_utf8_lossy(&no_color.stdout));
    let no_color_stderr = String::from_utf8_lossy(&no_color.stderr);
    assert!(!no_color_stderr.contains("\u{1b}["), "unexpected ANSI colour with NO_COLOR: {no_color_stderr}");
}

#[test]
fn cellc_check_multiple_diagnostics_prints_each_source_context() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "bad"
version = "0.1.0"
entry = "src/main.cell"
"#,
    )
    .unwrap();
    std::fs::create_dir_all(temp.path().join("src")).unwrap();
    std::fs::write(
        temp.path().join("src/main.cell"),
        r#"module multi_errors

action bad_one() -> u64 {
    verification
        return true
}

action bad_two() -> bool {
    verification
        return 1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("check").current_dir(temp.path()).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("return type mismatch: expected U64, found Bool"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("return type mismatch: expected Bool, found U64"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("5 |         return true"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("10 |         return 1"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("aborting due to 2 diagnostics"), "unexpected stderr: {stderr}");
    assert!(!stderr.contains("2 diagnostics:\n  -"), "unexpected collapsed diagnostics: {stderr}");
}

#[test]
fn cellc_auth_login_outputs_capability_authorisation_payload() {
    let output = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("create")
        .arg("--principal-id")
        .arg("0xjoyidprincipal")
        .arg("--capability-pubkey")
        .arg("0xcapabilitypubkey")
        .arg("--scope")
        .arg("publish:cellscript/amm")
        .arg("--expires")
        .arg("90d")
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["protocol"], "cellscript-registry-auth-v1");
    assert_eq!(payload["action"], "authorize_capability");
    assert_eq!(payload["registry_origin"], "https://api.registry.cellscript.dev");
    assert_eq!(payload["principal_type"], "joyid_ckb");
    assert_eq!(payload["principal_id"], "0xjoyidprincipal");
    assert_eq!(payload["capability_pubkey"], "0xcapabilitypubkey");
    assert_eq!(payload["requested_scopes"], serde_json::json!(["publish:cellscript/amm"]));
    assert!(payload["capability_expires_at"].as_str().is_some_and(|value| value.ends_with('Z')));
    assert!(payload["nonce"].as_str().is_some_and(|value| value.starts_with("0x")));
    assert!(payload["issued_at"].as_str().is_some());
    assert!(payload["expires_at"].as_str().is_some());
    assert!(payload["cli_version"].as_str().is_some());
}

#[test]
fn cellc_auth_capability_create_infers_only_the_exact_publish_scope() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "amm"
version = "0.1.0"
namespace = "cellscript"
"#,
    )
    .unwrap();

    let output = cellc_command()
        .args(["auth", "capability", "create"])
        .arg("--principal-id")
        .arg("0xjoyidprincipal")
        .arg("--capability-pubkey")
        .arg("0xcapabilitypubkey")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["requested_scopes"], serde_json::json!(["publish:cellscript/amm"]));
}

#[test]
fn cellc_auth_capability_create_rejects_unknown_or_duplicate_scopes() {
    for scopes in [vec!["admin:cellscript/amm"], vec!["publish:cellscript/amm", "publish:cellscript/amm"]] {
        let mut command = cellc_command();
        command
            .args(["auth", "capability", "create"])
            .arg("--principal-id")
            .arg("0xjoyidprincipal")
            .arg("--capability-pubkey")
            .arg("0xcapabilitypubkey")
            .arg("--json");
        for scope in scopes {
            command.arg("--scope").arg(scope);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
        let failure: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let message = failure["diagnostics"][0]["message"].as_str().unwrap_or_default();
        assert!(message.contains("capability scope"), "unexpected failure: {failure}");
    }
}

#[test]
fn cellc_auth_capability_create_requires_principal_id() {
    let output = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("create")
        .arg("--capability-pubkey")
        .arg("0xcapabilitypubkey")
        .arg("--scope")
        .arg("publish:cellscript/amm")
        .arg("--json")
        .output()
        .unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
    let failure: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(failure["status"], "failed");
    let message = failure["diagnostics"][0]["message"].as_str().unwrap_or_default();
    assert!(message.contains("principal id is required"), "unexpected failure: {failure}");
    assert!(message.contains("--principal-id"), "unexpected failure: {failure}");
}

#[cfg(unix)]
#[test]
fn cellc_auth_reproducer_create_keeps_private_key_out_of_public_enrollment() {
    let temp = tempfile::tempdir().unwrap();
    let private_key_path = temp.path().join("builder-private.pkcs8.b64");
    let output = cellc_command()
        .args(["auth", "reproducer", "create"])
        .arg("--builder-id")
        .arg("independent-builder-a")
        .arg("--trust-domain")
        .arg("independent-org-a")
        .arg("--private-key-output")
        .arg(&private_key_path)
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let enrollment: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(enrollment["schema"], "cellscript-reproducer-builder-enrollment-v1");
    assert_eq!(enrollment["builder_id"], "independent-builder-a");
    assert_eq!(enrollment["trust_domain"], "independent-org-a");
    assert_eq!(enrollment["policy_builder"]["builder_id"], "independent-builder-a");
    assert_eq!(enrollment["policy_builder"]["trust_domain"], "independent-org-a");
    assert_eq!(enrollment["private_key_storage"]["kind"], "pkcs8_base64_file");

    let public_key = enrollment["builder_public_key"].as_str().unwrap();
    assert!(public_key.starts_with("p256-spki:"));
    let spki = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(public_key.trim_start_matches("p256-spki:")).unwrap();
    assert_eq!(spki.len(), 91);
    let expected_key_id = format!("cap_{}", &hex::encode(Sha256::digest(public_key.as_bytes()))[..32]);
    assert_eq!(enrollment["builder_key_id"], expected_key_id);
    assert_eq!(enrollment["policy_builder"]["public_key"], public_key);

    let private_key_secret = std::fs::read_to_string(&private_key_path).unwrap();
    let private_key = base64::engine::general_purpose::STANDARD.decode(private_key_secret.trim()).unwrap();
    assert!(private_key.len() > 100);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(private_key_secret.trim()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&private_key_path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let second = cellc_command()
        .args(["auth", "reproducer", "create"])
        .arg("--builder-id")
        .arg("independent-builder-a")
        .arg("--trust-domain")
        .arg("independent-org-a")
        .arg("--private-key-output")
        .arg(&private_key_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!second.status.success(), "existing private-key file must not be overwritten");
    assert_eq!(std::fs::read_to_string(&private_key_path).unwrap(), private_key_secret);
}

#[cfg(not(unix))]
#[test]
fn cellc_auth_reproducer_create_rejects_private_key_file_without_unix_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let private_key_path = temp.path().join("builder-private.pkcs8.b64");
    let output = cellc_command()
        .args(["auth", "reproducer", "create"])
        .arg("--builder-id")
        .arg("independent-builder-a")
        .arg("--trust-domain")
        .arg("independent-org-a")
        .arg("--private-key-output")
        .arg(&private_key_path)
        .arg("--json")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires Unix mode-0600 permission semantics"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!private_key_path.exists());
}

fn write_publish_fixture_package(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "1.2.3"
namespace = "cellscript"
description = "Demo package"
license = "MIT"
repository = "https://example.com/cellscript/demo"
entry = "src/main.cell"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src/main.cell"),
        r#"
module demo::main

action identity(value: u64) -> u64 {
    verification
        value
}
"#,
    )
    .unwrap();
}

fn write_declared_artifact_fixture(root: &std::path::Path) {
    std::fs::write(
        root.join("Artifact.toml"),
        r#"schema = "cellscript-registry-artifact"
namespace = "cellscript"
name = "rust-contract"
release = "1.0.0"
kind = "deployable_contract"
language = "rust"
bundle = "artifact-bundle.json"
description = "Rust CKB contract"
repository = "https://example.com/cellscript/rust-contract"
"#,
    )
    .unwrap();
    let abi_hash = hex::encode(cellscript::ckb_blake2b256(b"abi"));
    let profile_contract = serde_json::json!({
        "schema": "cellscript-registry-profile-contract-v1",
        "artifact_kind": "deployable_contract",
        "profile": "ckb_executable",
        "build": {
            "target": "riscv64imac-unknown-none-elf",
            "toolchain": "rustc 1.97.1",
            "profile": "release",
            "source_revision": "0123456789abcdef",
            "reproducible": false
        },
        "security": { "status": "review_required" },
        "ckb": {
            "vm_version": "2",
            "script_role": "type",
            "hash_type": "data1",
            "dep_type": "code",
            "abi_hash": abi_hash
        }
    });
    let bundle = serde_json::json!({
        "schema": "cellscript-registry-bundle",
        "namespace": "cellscript",
        "name": "rust-contract",
        "release": "1.0.0",
        "profile": "ckb_executable",
        "manifest_json": cellscript::package::registry::canonical_artifact_contract_json(&profile_contract).unwrap(),
        "objects": [
            {"role":"source","content_base64":"c291cmNl"},
            {"role":"executable","content_base64":"ZWxm"},
            {"role":"abi","content_base64":"YWJp"}
        ]
    });
    std::fs::write(root.join("artifact-bundle.json"), serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
}

#[test]
fn cellc_ls_idl_validate_bind_and_bundle_preserve_raw_digest() {
    let temp = tempfile::tempdir().unwrap();
    let idl = br#"{"idl_version":"0.1","name":"demo_lock","witness":[{"name":"signature","type":"secp256k1_sig","required":true}]}"#;
    let idl_path = temp.path().join("idl.json");
    let executable_path = temp.path().join("lock");
    let bound_path = temp.path().join("lock.ls-idl");
    let source_path = temp.path().join("lock.rs");
    std::fs::write(&idl_path, idl).unwrap();
    std::fs::write(&executable_path, b"\x7fELFdemo-lock").unwrap();
    std::fs::write(&source_path, b"fn main() {}").unwrap();

    let validate = cellc_command().args(["artifact", "ls-idl", "validate", "--idl"]).arg(&idl_path).arg("--json").output().unwrap();
    assert!(validate.status.success(), "stderr: {}", String::from_utf8_lossy(&validate.stderr));

    let bind = cellc_command()
        .args(["artifact", "ls-idl", "bind", "--idl"])
        .arg(&idl_path)
        .arg("--executable")
        .arg(&executable_path)
        .arg("--output")
        .arg(&bound_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(bind.status.success(), "stderr: {}", String::from_utf8_lossy(&bind.stderr));
    let bound = std::fs::read(&bound_path).unwrap();
    let digest: [u8; 32] = Sha256::digest(idl).into();
    assert_eq!(&bound[bound.len() - 32..], digest);

    let bundle = cellc_command()
        .args(["artifact", "ls-idl", "bundle", "--idl"])
        .arg(&idl_path)
        .arg("--executable")
        .arg(&bound_path)
        .arg("--source")
        .arg(&source_path)
        .args([
            "--namespace",
            "cellscript",
            "--name",
            "demo-ls-idl-lock",
            "--release",
            "0.1.0",
            "--language",
            "rust",
            "--hash-type",
            "data1",
            "--dep-type",
            "code",
            "--toolchain",
            "rustc-1.97.1",
            "--source-revision",
            "0123456789abcdef0123456789abcdef01234567",
            "--output",
            "artifact.bundle.json",
            "--artifact-manifest-output",
            "Artifact.toml",
            "--json",
        ])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(bundle.status.success(), "stderr: {}", String::from_utf8_lossy(&bundle.stderr));

    let publish = cellc_command()
        .args(["publish", "--artifact-manifest", "Artifact.toml", "--dry-run", "--json"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(publish.status.success(), "stderr: {}", String::from_utf8_lossy(&publish.stderr));
}

#[test]
fn cellc_publish_dry_run_validates_declared_non_cellscript_artifact() {
    let temp = tempfile::tempdir().unwrap();
    write_declared_artifact_fixture(temp.path());
    let output = cellc_command()
        .arg("publish")
        .arg("--artifact-manifest")
        .arg("Artifact.toml")
        .arg("--dry-run")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "valid");
    assert_eq!(result["coordinate"], "cellscript/rust-contract@1.0.0");
    assert_eq!(result["artifact"]["kind"], "deployable_contract");
    assert_eq!(result["artifact"]["profile"], "ckb_executable");
    assert_eq!(result["artifact"]["consumption_mode"], "deployment");
    assert_eq!(result["source_hash"].as_str().unwrap().len(), 64);
}

#[test]
fn cellc_publish_default_requires_capability_inputs_without_writing_registry_json() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let output = cellc_command().arg("publish").current_dir(temp.path()).output().unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("wallet-authorised publishing key"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("cellc publish --authorise"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("--capability-key-id"), "unexpected stderr: {stderr}");
    assert!(!temp.path().join("registry.json").exists(), "default public publish must not silently write offline registry.json");
}

#[test]
fn cellc_publish_print_payload_outputs_signable_registry_publish_payload() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let output = cellc_command()
        .arg("publish")
        .arg("--capability-key-id")
        .arg("cap_test")
        .arg("--print-payload")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["endpoint"], "https://api.registry.cellscript.dev/v1/artifacts/cellscript/demo/releases");
    assert_eq!(envelope["payload"]["protocol"], "cellscript-registry-publish-v1");
    assert_eq!(envelope["payload"]["action"], "publish");
    assert_eq!(envelope["payload"]["registry_origin"], "https://api.registry.cellscript.dev");
    assert_eq!(envelope["payload"]["namespace"], "cellscript");
    assert_eq!(envelope["payload"]["name"], "demo");
    assert_eq!(envelope["payload"]["version"], "1.2.3");
    assert_eq!(envelope["payload"]["capability_key_id"], "cap_test");
    assert_eq!(envelope["payload"]["artifact"]["kind"], "source_library");
    assert_eq!(envelope["payload"]["registry_entry"]["versions"][0]["verification_status"], "pending");
    let canonical_payload = envelope["canonical_payload"].as_str().expect("canonical payload");
    let canonical_json: serde_json::Value = serde_json::from_str(canonical_payload).unwrap();
    assert_eq!(canonical_json, envelope["payload"]);
    assert!(!temp.path().join("registry.json").exists(), "payload preview must not write offline registry.json");
}

#[test]
fn cellc_publish_profile_library_preserves_the_declared_artifact_kind() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let output = cellc_command()
        .arg("publish")
        .arg("--artifact-kind")
        .arg("profile_library")
        .arg("--capability-key-id")
        .arg("cap_test")
        .arg("--print-payload")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["payload"]["artifact"]["kind"], "profile_library");
    assert_eq!(envelope["payload"]["artifact"]["profile"], "cellscript_source");
    assert_eq!(envelope["payload"]["registry_entry"]["artifact"]["kind"], "profile_library");
}

#[test]
fn cellc_publish_posts_signed_request_to_registry_api() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let (api_url, request_rx) = start_mock_registry_api_capture_request(serde_json::json!({
        "request_id": "req_test",
        "verification_status": "pending",
        "deployment_status": "not_applicable",
        "availability_status": "active",
        "direct_url": "https://registry.cellscript.dev/artifacts/cellscript/demo/releases/1.2.3.json",
        "snapshot_hash": "sha256:test",
        "verification": "queued"
    }));

    let preview = cellc_command()
        .arg("publish")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--capability-key-id")
        .arg("cap_test")
        .arg("--print-payload")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(preview.status.success(), "stderr: {}", String::from_utf8_lossy(&preview.stderr));
    let envelope: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let payload_path = temp.path().join("publish-payload.json");
    std::fs::write(&payload_path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let output = cellc_command()
        .arg("publish")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--payload")
        .arg(&payload_path)
        .arg("--capability-signature")
        .arg("0x1234")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["verification_status"], "pending");
    assert_eq!(response["deployment_status"], "not_applicable");
    let request = request_rx.recv_timeout(Duration::from_secs(5)).expect("registry API request");
    assert_eq!(request.path, "/v1/artifacts/cellscript/demo/releases");
    assert!(
        request
            .header("idempotency-key")
            .is_some_and(|value| value.starts_with("cellc-publish-") && value.len() > "cellc-publish-".len()),
        "missing or malformed Idempotency-Key header: {:?}",
        request.headers
    );
    let request = request.body;
    assert_eq!(request["payload"], envelope["payload"]);
    assert_eq!(request["capability_signature"]["algorithm"], "p256-sha256");
    assert_eq!(request["capability_signature"]["signature"], "0x1234");
    assert_eq!(request["source_snapshot"]["content_type"], "application/vnd.cellscript.source-snapshot+json");
    assert_eq!(request["source_snapshot"]["source_hash"], envelope["payload"]["source_hash"]);
    assert!(request["source_snapshot"]["content_base64"].as_str().is_some_and(|value| !value.is_empty()));
    assert!(request["source_snapshot"]["size_bytes"].as_u64().is_some_and(|value| value > 0));
    assert!(!temp.path().join("registry.json").exists(), "public publish must not write offline registry.json");
}

#[test]
fn cellc_publish_honors_explicit_idempotency_key() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let (api_url, request_rx) = start_mock_registry_api_capture_request(serde_json::json!({
        "request_id": "req_test",
        "verification_status": "pending",
        "deployment_status": "not_applicable",
        "availability_status": "active",
        "direct_url": "https://registry.cellscript.dev/artifacts/cellscript/demo/releases/1.2.3.json",
        "snapshot_hash": "sha256:test",
        "verification": "queued"
    }));

    let preview = cellc_command()
        .arg("publish")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--capability-key-id")
        .arg("cap_test")
        .arg("--print-payload")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(preview.status.success(), "stderr: {}", String::from_utf8_lossy(&preview.stderr));
    let envelope: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let payload_path = temp.path().join("publish-payload.json");
    std::fs::write(&payload_path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let output = cellc_command()
        .arg("publish")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--payload")
        .arg(&payload_path)
        .arg("--capability-signature")
        .arg("0x1234")
        .arg("--idempotency-key")
        .arg("ci-release-cellscript-demo-1.2.3")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let request = request_rx.recv_timeout(Duration::from_secs(5)).expect("registry API request");
    assert_eq!(request.header("idempotency-key"), Some("ci-release-cellscript-demo-1.2.3"));
}

#[test]
fn cellc_publish_retries_transient_registry_error_with_same_idempotency_key() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let (api_url, request_rx) = start_mock_registry_api_retry_then_success(serde_json::json!({
        "request_id": "req_retry",
        "verification_status": "pending",
        "deployment_status": "not_applicable",
        "availability_status": "active",
        "direct_url": "https://registry.cellscript.dev/artifacts/cellscript/demo/releases/1.2.3.json",
        "snapshot_hash": "sha256:test",
        "verification": "queued"
    }));

    let preview = cellc_command()
        .arg("publish")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--capability-key-id")
        .arg("cap_test")
        .arg("--print-payload")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(preview.status.success(), "stderr: {}", String::from_utf8_lossy(&preview.stderr));
    let envelope: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let payload_path = temp.path().join("publish-payload.json");
    std::fs::write(&payload_path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let output = cellc_command()
        .arg("publish")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--payload")
        .arg(&payload_path)
        .arg("--capability-signature")
        .arg("0x1234")
        .arg("--idempotency-key")
        .arg("retry-cellscript-demo-1.2.3")
        .arg("--json")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["request_id"], "req_retry");
    let first = request_rx.recv_timeout(Duration::from_secs(5)).expect("first registry API request");
    let second = request_rx.recv_timeout(Duration::from_secs(5)).expect("second registry API request");
    assert_eq!(first.header("idempotency-key"), Some("retry-cellscript-demo-1.2.3"));
    assert_eq!(second.header("idempotency-key"), Some("retry-cellscript-demo-1.2.3"));
    assert_eq!(first.body, second.body);
}

#[test]
fn cellc_auth_capability_submit_posts_ckb_wallet_signature_to_registry_api() {
    let temp = tempfile::tempdir().unwrap();
    let (api_url, request_rx) = start_mock_registry_api_expect_path(
        "/v1/capabilities",
        serde_json::json!({
            "request_id": "req_cap",
            "key_id": "cap_test",
            "status": "active"
        }),
    );
    let create = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("create")
        .arg("--registry-origin")
        .arg(&api_url)
        .arg("--principal-id")
        .arg(format!("0x{}", "11".repeat(32)))
        .arg("--principal-type")
        .arg("ckb_secp256k1")
        .arg("--capability-pubkey")
        .arg("p256-spki:test")
        .arg("--scope")
        .arg("publish:cellscript/demo")
        .arg("--json")
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", String::from_utf8_lossy(&create.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    let payload_path = temp.path().join("capability-payload.json");
    let signature_path = temp.path().join("wallet-signature.json");
    std::fs::write(&payload_path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    std::fs::write(
        &signature_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "scheme": "ckb_secp256k1",
            "challenge": serde_json::to_string(&payload).unwrap(),
            "signature": format!("0x{}", "22".repeat(65)),
            "public_key": format!("0x02{}", "33".repeat(32))
        }))
        .unwrap(),
    )
    .unwrap();

    let output = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("submit")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--payload")
        .arg(&payload_path)
        .arg("--wallet-signature")
        .arg(&signature_path)
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["status"], "active");
    let request = request_rx.recv_timeout(Duration::from_secs(5)).expect("capability request");
    assert_eq!(request["payload"], payload);
    assert_eq!(request["wallet_signature"]["scheme"], "ckb_secp256k1");
}

#[test]
fn cellc_auth_namespace_claim_posts_signed_capability_payload_to_registry_api() {
    let temp = tempfile::tempdir().unwrap();
    let (api_url, request_rx) = start_mock_registry_api_expect_path(
        "/v1/namespaces/claim",
        serde_json::json!({
            "request_id": "req_namespace",
            "namespace": "exampleorg",
            "status": "active"
        }),
    );
    let create = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("create")
        .arg("--registry-origin")
        .arg(&api_url)
        .arg("--principal-id")
        .arg("0x1111111111111111111111111111111111111111")
        .arg("--capability-pubkey")
        .arg("p256-spki:test")
        .arg("--scope")
        .arg("publish:exampleorg/demo")
        .arg("--json")
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", String::from_utf8_lossy(&create.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    let payload_path = temp.path().join("capability-payload.json");
    let signature_path = temp.path().join("joyid-signature.json");
    std::fs::write(&payload_path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    std::fs::write(
        &signature_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "challenge": serde_json::to_string(&payload).unwrap(),
            "signature": "sig",
            "message": "message",
            "pubkey": "pubkey",
            "keyType": "main_key",
            "alg": -7
        }))
        .unwrap(),
    )
    .unwrap();

    let output = cellc_command()
        .arg("auth")
        .arg("namespace")
        .arg("claim")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--namespace")
        .arg("exampleorg")
        .arg("--payload")
        .arg(&payload_path)
        .arg("--joyid-signature")
        .arg(&signature_path)
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["status"], "active");
    let request = request_rx.recv_timeout(Duration::from_secs(5)).expect("namespace claim request");
    assert_eq!(request["namespace"], "exampleorg");
    assert_eq!(request["payload"], payload);
    assert_eq!(request["wallet_signature"]["signature"], "sig");
}

#[test]
fn cellc_auth_capability_revoke_generates_payload_and_posts_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let key_id = format!("cap_{}", "a".repeat(32));
    let expected_path = format!("/v1/capabilities/{}/revoke", key_id);
    let (api_url, request_rx) = start_mock_registry_api_expect_path(
        &expected_path,
        serde_json::json!({
            "request_id": "req_revoke",
            "key_id": key_id,
            "status": "revoked",
            "revoked_at": "2026-06-23T12:00:00Z"
        }),
    );
    let create = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("revoke")
        .arg("--registry-origin")
        .arg(&api_url)
        .arg("--principal-id")
        .arg("0x1111111111111111111111111111111111111111")
        .arg("--capability-key-id")
        .arg(&key_id)
        .arg("--json")
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", String::from_utf8_lossy(&create.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(payload["action"], "revoke_capability");
    assert_eq!(payload["capability_key_id"], key_id);

    let payload_path = temp.path().join("revoke-payload.json");
    let signature_path = temp.path().join("joyid-revoke-signature.json");
    std::fs::write(&payload_path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    std::fs::write(
        &signature_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "challenge": serde_json::to_string(&payload).unwrap(),
            "signature": "sig",
            "message": "message",
            "pubkey": "pubkey",
            "keyType": "main_key",
            "alg": -7
        }))
        .unwrap(),
    )
    .unwrap();

    let output = cellc_command()
        .arg("auth")
        .arg("capability")
        .arg("revoke")
        .arg("--api-url")
        .arg(&api_url)
        .arg("--payload")
        .arg(&payload_path)
        .arg("--joyid-signature")
        .arg(&signature_path)
        .arg("--reason")
        .arg("rotated")
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["status"], "revoked");
    let request = request_rx.recv_timeout(Duration::from_secs(5)).expect("revoke request");
    assert_eq!(request["payload"], payload);
    assert_eq!(request["reason"], "rotated");
}

#[test]
fn cellc_publish_offline_writes_source_published_registry_fixture() {
    let temp = tempfile::tempdir().unwrap();
    write_publish_fixture_package(temp.path());

    let output = cellc_command().arg("publish").arg("--offline").current_dir(temp.path()).output().unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Published offline registry fixture"), "unexpected stdout: {stdout}");

    let index = cellscript::package::registry::RegistryIndex::read_from_repo(temp.path()).unwrap();
    assert_eq!(index.namespace, "cellscript");
    assert_eq!(index.name, "demo");
    let version = index.versions.iter().find(|version| version.version == "1.2.3").expect("published version");
    assert_eq!(version.status, cellscript::package::registry::RegistryEntryStatus::SourcePublished);
}

fn locked_build_from_metadata_for_test(metadata: &cellscript::CompileMetadata) -> cellscript::package::LockedBuildInfo {
    let abi = serde_json::json!({
        "edition": metadata.edition,
        "compatibility_profile": &metadata.compatibility_profile,
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": {
            "metadata": metadata.metadata_schema_version,
            "source": metadata.source_metadata_schema_version,
            "artifact": metadata.artifact_metadata_schema_version,
            "constraints": metadata.constraints_metadata_schema_version,
        },
        "target_profile": metadata.target_profile.name.as_str(),
        "types": &metadata.types,
        "actions": &metadata.actions,
        "functions": &metadata.functions,
        "locks": &metadata.locks,
        "molecule_schema_manifest": &metadata.molecule_schema_manifest,
        "cell_data_codec_manifest": &metadata.cell_data_codec_manifest,
    });
    cellscript::package::LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: hash_json_for_test(&metadata.compatibility_profile),
        compiler_version: Some(metadata.compiler_version.clone()),
        target_profile: Some(metadata.target_profile.name.clone()),
        artifact_hash: metadata.artifact_hash.clone(),
        metadata_hash: Some(hash_json_for_test(metadata)),
        schema_hash: Some(metadata.molecule_schema_manifest.manifest_hash.clone()),
        cell_data_codec_manifest_hash: Some(metadata.cell_data_codec_manifest.manifest_hash.clone()),
        abi_hash: Some(hash_json_for_test(&abi)),
        constraints_hash: Some(hash_json_for_test(&metadata.constraints)),
    }
}

fn start_mock_ckb_rpc(responses: Vec<(&'static str, serde_json::Value)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for (expected_method, result) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request_body(&mut stream);
            let request_json: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request_json["method"], expected_method);
            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_json["id"].clone(),
                "result": result,
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    format!("http://{}", addr)
}

#[derive(Debug)]
struct MockRegistryRequest {
    path: String,
    headers: Vec<(String, String)>,
    body: serde_json::Value,
}

impl MockRegistryRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }
}

fn start_mock_registry_api_capture_request(
    response_body: serde_json::Value,
) -> (String, std::sync::mpsc::Receiver<MockRegistryRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (path, headers, request) = read_http_request_path_headers_and_body(&mut stream);
        let request_json: serde_json::Value = serde_json::from_slice(&request).unwrap();
        tx.send(MockRegistryRequest { path, headers, body: request_json }).unwrap();
        let response_body = response_body.to_string();
        let response = format!(
            "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    (format!("http://{}", addr), rx)
}

fn start_mock_registry_api_retry_then_success(
    response_body: serde_json::Value,
) -> (String, std::sync::mpsc::Receiver<MockRegistryRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for status in ["503 Service Unavailable", "202 Accepted"] {
            let (mut stream, _) = listener.accept().unwrap();
            let (path, headers, request) = read_http_request_path_headers_and_body(&mut stream);
            let request_json: serde_json::Value = serde_json::from_slice(&request).unwrap();
            tx.send(MockRegistryRequest { path, headers, body: request_json }).unwrap();
            let response_body = if status.starts_with("202") {
                response_body.to_string()
            } else {
                serde_json::json!({"error": {"code": "temporary_unavailable"}}).to_string()
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (format!("http://{}", addr), rx)
}

fn start_mock_registry_api_expect_path(
    expected_path: &str,
    response_body: serde_json::Value,
) -> (String, std::sync::mpsc::Receiver<serde_json::Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_path = expected_path.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (path, request) = read_http_request_path_and_body(&mut stream);
        assert_eq!(path, expected_path);
        let request_json: serde_json::Value = serde_json::from_slice(&request).unwrap();
        tx.send(request_json).unwrap();
        let response_body = response_body.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    (format!("http://{}", addr), rx)
}

fn read_http_request_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
    read_http_request_path_and_body(stream).1
}

fn read_http_request_path_and_body(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    let (path, _headers, body) = read_http_request_path_headers_and_body(stream);
    (path, body)
}

fn read_http_request_path_headers_and_body(stream: &mut std::net::TcpStream) -> (String, Vec<(String, String)>, Vec<u8>) {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert_ne!(read, 0, "mock RPC request ended before headers");
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let path = headers.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("/").to_string();
            let parsed_headers = headers
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    Some((name.trim().to_string(), value.trim().to_string()))
                })
                .collect();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let body_start = header_end + 4;
            while request.len() < body_start + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0, "mock RPC request ended before body");
                request.extend_from_slice(&buffer[..read]);
            }
            return (path, parsed_headers, request[body_start..body_start + content_length].to_vec());
        }
    }
}

fn write_live_registry_fixture(root: &std::path::Path, data_hash: &str) {
    write_live_registry_fixture_with(root, data_hash, data_hash, "data1", None);
}

fn write_live_registry_fixture_with(root: &std::path::Path, data_hash: &str, code_hash: &str, hash_type: &str, type_id: Option<&str>) {
    let out_point = "0xaaaa:0".to_string();
    let mut lockfile = cellscript::package::Lockfile::new();
    lockfile.package = cellscript::package::LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "token".to_string(),
        version: "1.0.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some("source_hash".to_string()),
        compiler_source_hash: None,
    };
    lockfile.package_build = Some(cellscript::package::LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.20.0".to_string()),
        target_profile: Some("ckb".to_string()),
        artifact_hash: Some("artifact_hash".to_string()),
        metadata_hash: Some("metadata_hash".to_string()),
        schema_hash: Some("schema_hash".to_string()),
        cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
        abi_hash: Some("abi_hash".to_string()),
        constraints_hash: Some("constraints_hash".to_string()),
    });
    lockfile.deployment.insert(
        "aggron4".to_string(),
        cellscript::package::LockfileDeploymentRef {
            record: out_point.clone(),
            record_hash: None,
            code_hash: Some(code_hash.to_string()),
            out_point: Some(out_point.clone()),
            data_hash: Some(data_hash.to_string()),
        },
    );
    lockfile.write_to_root(root).unwrap();

    let deployed = cellscript::package::DeployedManifest {
        version: cellscript::package::DeployedManifest::CURRENT_VERSION,
        schema: cellscript::package::DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: cellscript::package::DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "token".to_string(),
            version: "1.0.0".to_string(),
            source_hash: Some("source_hash".to_string()),
        },
        build: Some(cellscript::package::DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.20.0".to_string()),
            artifact_hash: Some("artifact_hash".to_string()),
            metadata_hash: Some("metadata_hash".to_string()),
            schema_hash: Some("schema_hash".to_string()),
            cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
            abi_hash: Some("abi_hash".to_string()),
            constraints_hash: Some("constraints_hash".to_string()),
        }),
        deployments: vec![cellscript::package::DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "aggron4".to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: "0xaaaa".to_string(),
            output_index: 0,
            code_hash: code_hash.to_string(),
            hash_type: hash_type.to_string(),
            dep_type: "code".to_string(),
            data_hash: data_hash.to_string(),
            out_point,
            artifact_hash: Some("artifact_hash".to_string()),
            metadata_hash: Some("metadata_hash".to_string()),
            schema_hash: Some("schema_hash".to_string()),
            cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
            abi_hash: Some("abi_hash".to_string()),
            constraints_hash: Some("constraints_hash".to_string()),
            compiler_version: Some("0.20.0".to_string()),
            type_id: type_id.map(str::to_string),
            script_role: Some(cellscript::package::ScriptRole::Type),
            status: Some(cellscript::package::DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };
    deployed.write_to_root(root).unwrap();
}

fn live_cell_rpc_result(status: &str, data_hash: &str) -> serde_json::Value {
    live_cell_rpc_result_with_type(status, data_hash, serde_json::Value::Null)
}

fn live_cell_rpc_result_with_type(status: &str, data_hash: &str, type_script: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "cell": {
            "output": {
                "capacity": "0x0",
                "lock": {
                    "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "hash_type": "data1",
                    "args": "0x"
                },
                "type": type_script
            },
            "data": {
                "content": "0x00",
                "hash": data_hash
            }
        }
    })
}

#[test]
fn cellc_writes_requested_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        let z = x + y
        return z
}
"#;
    std::fs::write(&input, source).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();

    assert!(status.success());

    let written = std::fs::read_to_string(&output).unwrap();
    assert!(written.contains(".section .text"));
    assert!(written.contains(".global add"));

    let metadata = std::fs::read_to_string(dir.path().join("sample.s.meta.json")).unwrap();
    assert!(metadata.contains("\"actions\""));
    assert!(metadata.contains("\"add\""));
    assert!(metadata.contains("\"scheduler_witness_abi\""));
    assert!(metadata.contains("\"scheduler_witness_hex\""));
    assert!(!metadata.contains("\"scheduler_witness_molecule_hex\""));
    assert!(metadata.contains("\"metadata_schema_version\""));
    assert!(metadata.contains("\"compiler_version\""));
    assert!(metadata.contains("\"artifact_hash\""));
    assert!(metadata.contains("\"artifact_size_bytes\""));
    assert!(metadata.contains("\"source_hash\""));
    assert!(metadata.contains("\"source_content_hash\""));
    assert!(metadata.contains("\"source_units\""));
    assert!(metadata.contains("\"target_profile\""));
    assert!(metadata.contains("\"target_chain\""));
    assert!(metadata.contains("\"constraints\""));
    assert!(metadata.contains("\"entry_abi\""));
    assert!(metadata.contains("\"artifact\""));
    assert!(metadata.contains("\"runtime_errors\""));
    assert!(metadata.contains("\"source_metadata_schema_version\""));
    assert!(metadata.contains("\"artifact_metadata_schema_version\""));
    assert!(metadata.contains("\"constraints_metadata_schema_version\""));
}

#[test]
fn cellc_direct_elf_build_writes_and_reports_verified_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.elf");
    std::fs::write(
        &input,
        r#"
module test

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg(&input)
        .args(["--target", "riscv64-elf", "--json", "-o"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));

    let payload: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let lowering = dir.path().join("sample.elf.lowering.json");
    let source_map = dir.path().join("sample.elf.sourcemap.json");
    assert_eq!(payload["lowering_record"], lowering.to_string_lossy().as_ref());
    assert_eq!(payload["source_map"], source_map.to_string_lossy().as_ref());
    assert!(lowering.is_file());
    assert!(source_map.is_file());

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .args(["--expect-target-profile", "ckb", "--json"])
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
}

#[test]
fn protocol_bundle_checks_three_independent_artifacts_and_hashes_canonical_composition() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let sources = [
        (
            "order",
            r#"
module protocol::order

resource SharedRecord has store, create {
    amount: u64
}

action settle() -> bool {
    verification
        true
}
"#,
        ),
        (
            "token",
            r#"
module protocol::token

resource SharedRecord has store, create {
    amount: u64
}

action transfer() -> SharedRecord {
    verification
        create SharedRecord { amount: 1 }
}
"#,
        ),
        (
            "auth",
            r#"
module protocol::auth

resource SharedRecord has store, create {
    amount: u64
}

lock authorize(witness approved: bool) -> bool {
    verification
        approved
}
"#,
        ),
    ];

    let mut artifact_hashes = std::collections::BTreeMap::new();
    let mut metadata_values = std::collections::BTreeMap::new();
    for (name, source) in sources {
        let source_path = root.join(format!("{name}.cell"));
        let artifact_path = root.join(format!("{name}.elf"));
        std::fs::write(&source_path, source).unwrap();
        let build = Command::new(env!("CARGO_BIN_EXE_cellc"))
            .arg(&source_path)
            .args(["--target", "riscv64-elf", "-o"])
            .arg(&artifact_path)
            .output()
            .unwrap();
        assert!(build.status.success(), "{}", String::from_utf8_lossy(&build.stderr));
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("{name}.elf.meta.json"))).unwrap()).unwrap();
        artifact_hashes.insert(name, metadata["artifact_hash"].as_str().unwrap().to_string());
        metadata_values.insert(name, metadata);
    }
    for (name, action) in [("order", "settle"), ("token", "transfer")] {
        let generated = Command::new(env!("CARGO_BIN_EXE_cellc"))
            .args(["gen-builder", "--metadata"])
            .arg(root.join(format!("{name}.elf.meta.json")))
            .args(["--target", "typescript"])
            .args(["--action", action, "--output"])
            .arg(root.join(format!("{name}-builder")))
            .arg("--json")
            .output()
            .unwrap();
        assert!(generated.status.success(), "{}", String::from_utf8_lossy(&generated.stderr));
    }
    let shared_schema_hashes = metadata_values
        .values()
        .map(|metadata| {
            metadata["molecule_schema_manifest"]["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["type_name"] == "SharedRecord")
                .and_then(|entry| entry["schema_hash"].as_str())
                .unwrap()
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(shared_schema_hashes.len(), 1, "all participants must compile the identical SharedRecord schema");
    let shared_schema_hash = shared_schema_hashes.into_iter().next().unwrap();

    let network = serde_json::json!({
        "chain_id": "ckb-testnet",
        "genesis_hash": format!("0x{}", "0".repeat(64)),
    });
    let artifact = |id: &str, entry_kind: &str, entry_name: &str, role: &str, dep_byte: &str| {
        let artifact_hash = artifact_hashes[id].clone();
        let mut artifact = serde_json::json!({
            "id": id,
            "package_coordinate": format!("example/{id}@1.0.0"),
            "lock_node_id": format!("{id}@1.0.0|path:{id}|env=default|features=default"),
            "entry": { "kind": entry_kind, "name": entry_name },
            "script_role": role,
            "files": {
                "artifact": format!("{id}.elf"),
                "metadata": format!("{id}.elf.meta.json"),
                "lowering_record": format!("{id}.elf.lowering.json"),
                "source_map": format!("{id}.elf.sourcemap.json"),
            },
            "deployment": {
                "network": network.clone(),
                "artifact_hash": artifact_hash,
                "script": {
                    "code_hash": format!("0x{}", artifact_hashes[id]),
                    "hash_type": "data2",
                    "args": "0x",
                },
                "code_cell_dep": {
                    "out_point": { "tx_hash": format!("0x{}", dep_byte.repeat(64)), "index": 0 },
                    "dep_type": "code",
                },
            },
        });
        if entry_kind == "action" {
            artifact["files"]["builder_manifest"] = serde_json::json!(format!("{id}-builder/cellscript-builder-manifest.json"));
        }
        artifact
    };
    let order = artifact("order", "action", "settle", "type", "1");
    let token = artifact("token", "action", "transfer", "type", "2");
    let auth = artifact("auth", "lock", "authorize", "lock", "3");
    let order_script = order.pointer("/deployment/script").unwrap().clone();
    let token_script = token.pointer("/deployment/script").unwrap().clone();
    let auth_script = auth.pointer("/deployment/script").unwrap().clone();
    let cell_deps = [&order, &token, &auth]
        .into_iter()
        .map(|artifact| artifact.pointer("/deployment/code_cell_dep").unwrap().clone())
        .collect::<Vec<_>>();
    let cell = |commitment_byte: &str, capacity: u64, lock: serde_json::Value, ty: serde_json::Value| {
        serde_json::json!({
            "cell_commitment": format!("0x{}", commitment_byte.repeat(64)),
            "capacity": capacity,
            "lock": lock,
            "type": ty,
            "data": "0x",
        })
    };
    let mut builder_assumption_evidence = serde_json::Map::new();
    for metadata in metadata_values.values() {
        let Some(assumptions) = metadata["runtime"]["builder_assumptions"].as_array() else {
            continue;
        };
        for assumption in assumptions {
            if assumption["kind"] != "capacity_policy" {
                continue;
            }
            let assumption_id = assumption["assumption_id"].as_str().unwrap();
            builder_assumption_evidence.insert(
                assumption_id.to_string(),
                serde_json::json!({
                    "assumption_id": assumption_id,
                    "kind": assumption["kind"].clone(),
                    "origin": assumption["origin"].clone(),
                    "feature": assumption["feature"].clone(),
                    "proof_plan_status": assumption["proof_plan_status"].clone(),
                    "evidence": {
                        "outputs": [{ "index": 0, "capacity": 80_000_000_000u64 }],
                        "occupied_capacity_shannons": 80_000_000_000u64,
                        "tx_size_bytes": 1,
                        "under_capacity_output_indexes": [],
                    },
                }),
            );
        }
    }
    assert!(!builder_assumption_evidence.is_empty(), "the creating action must expose a capacity-policy assumption");
    let mut input_cell = cell("4", 100_000_000_000, auth_script.clone(), order_script.clone());
    input_cell["out_point"] = serde_json::json!({ "tx_hash": format!("0x{}", "4".repeat(64)), "index": 0 });
    input_cell["since"] = serde_json::json!(0);
    let mut manifest = serde_json::json!({
        "schema": "cellscript-protocol-bundle-input-v1",
        "network": network,
        "artifacts": [order, token, auth],
        "transaction": {
            "version": 0,
            "inputs": [input_cell],
            "outputs": [cell("5", 80_000_000_000u64, auth_script.clone(), token_script.clone())],
            "witnesses": [{}],
            "cell_deps": cell_deps.clone(),
            "header_deps": [],
            "fee_policy_hash": format!("0x{}", "6".repeat(64)),
            "change_policy_hash": format!("0x{}", "7".repeat(64)),
            "builder_assumption_evidence": builder_assumption_evidence,
        },
        "roles": [
            {
                "artifact": "order", "name": "order-input", "location": "input", "index": 0,
                "ownership": "exclusive", "expected_type": order_script,
                "cell_commitment": format!("0x{}", "4".repeat(64)), "minimum_capacity": 100_000_000_000u64,
            },
            {
                "artifact": "auth", "name": "authorization", "location": "input", "index": 0,
                "ownership": "shared-read", "expected_lock": auth_script,
            },
            {
                "artifact": "token", "name": "token-output", "location": "output", "index": 0,
                "ownership": "exclusive", "expected_type": token_script,
                "resource_identity": "SharedRecord",
                "cell_commitment": format!("0x{}", "5".repeat(64)), "exact_capacity": 80_000_000_000u64,
            },
            {
                "artifact": "order", "name": "settlement-output", "location": "output", "index": 0,
                "ownership": "shared-read", "expected_type": token_script,
                "resource_identity": "SharedRecord",
            },
            {
                "artifact": "auth", "name": "settlement-output", "location": "output", "index": 0,
                "ownership": "shared-read", "expected_type": token_script,
                "resource_identity": "SharedRecord",
            },
        ],
        "closed_roles": [{
            "schema": "cellscript-protocol-closed-role-v1",
            "role_id": "settlement-record",
            "kind": "cell",
            "schema_identity": { "type_name": "SharedRecord", "schema_hash": shared_schema_hash },
            "provider": { "artifact": "token", "claim": "token-output" },
            "consumers": [
                { "artifact": "order", "claim": "settlement-output" },
                { "artifact": "auth", "claim": "settlement-output" },
            ],
            "correspondence": "exact-physical-binding",
        }],
        "cell_deps": [
            { "artifact": "order", "name": "order-code", "index": 0, "cell_dep": cell_deps[0].clone() },
            { "artifact": "token", "name": "token-code", "index": 1, "cell_dep": cell_deps[1].clone() },
            { "artifact": "auth", "name": "auth-code", "index": 2, "cell_dep": cell_deps[2].clone() },
        ],
    });
    let manifest_path = root.join("protocol-bundle.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let first = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["protocol", "bundle", "check"])
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&first.stdout)
    );
    let (materialized, materialization) = cellscript_ckb_adapter::materialize_protocol_bundle_report(&first.stdout).unwrap();
    assert_eq!(materialized.inputs().len(), 1);
    assert_eq!(materialized.outputs().len(), 1);
    assert_eq!(materialization.state, "MaterializedProtocolBundleTx");
    assert_eq!(materialization.transaction_serialization, "verified");
    assert_eq!(materialization.script_groups.len(), 3);
    assert_eq!(materialization.live_input_expectations.len(), 1);
    assert_eq!(materialization.code_cell_dep_expectations.len(), 3);
    assert_eq!(materialization.capacity_source, "bundle-skeleton-not-live-resolved");
    assert!(materialization
        .script_groups
        .iter()
        .all(|group| group.transaction_bytes_hash == materialization.serialized_transaction_hash));
    assert!(materialization.script_groups.iter().all(|group| group.execution == "not-executed"));
    assert_eq!(materialization.fee_shannons, 20_000_000_000);
    assert_eq!(materialization.ckb_vm_execution, "not-executed");
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["status"], "ok");
    assert_eq!(first["bundle"]["artifacts"].as_array().unwrap().len(), 3);
    assert_eq!(first["bundle"]["closed_roles"].as_array().unwrap().len(), 1);
    assert_eq!(first["bundle"]["closed_roles"][0]["locality"], "closed-foreign");
    assert_eq!(first["bundle"]["closed_roles"][0]["provider"]["artifact"], "token");
    assert_eq!(first["bundle"]["closed_roles"][0]["consumers"].as_array().unwrap().len(), 2);
    assert!(first["bundle"]["closed_roles"][0]["provider"]["interface_hash"].as_str().is_some());
    assert!(first["bundle"]["closed_roles"][0]["provider"]["deployment"]["script"]["code_hash"].as_str().is_some());
    let identities = first["bundle"]["artifacts"].as_array().unwrap();
    for identity in identities {
        let identity: cellscript::protocol_bundle::ProtocolArtifactIdentity = serde_json::from_value(identity.clone()).unwrap();
        assert_eq!(identity.runtime_abi_hash, identity.exact_handle_receipt.runtime_abi_hash);
        assert_eq!(identity.interface_hash, identity.exact_handle_receipt.interface_hash);
        assert_eq!(identity.typed_semantics_hash, identity.exact_handle_receipt.typed_semantics_hash);
        assert_eq!(identity.target_profile_hash, identity.exact_handle_receipt.target_profile_hash);
        assert_eq!(identity.exact_handle.encoded.len(), 2 + cellscript::script_handle::EXACT_SCRIPT_HANDLE_BYTES * 2);
        cellscript::script_handle::validate_exact_script_handle(&identity.exact_handle_receipt, &identity.exact_handle).unwrap();
        assert_eq!(
            identity.exact_handle_hash,
            cellscript::script_handle::exact_script_handle_value_hash(&identity.exact_handle).unwrap()
        );
    }
    assert_eq!(
        first["bundle"]["closed_roles"][0]["provider"]["exact_handle"],
        identities.iter().find(|identity| identity["id"] == "token").unwrap()["exact_handle"]
    );
    assert_eq!(
        first["bundle"]["closed_roles"][0]["provider"]["exact_handle_hash"],
        identities.iter().find(|identity| identity["id"] == "token").unwrap()["exact_handle_hash"]
    );
    assert_eq!(
        first["bundle"]["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|artifact| artifact.get("builder_manifest_hash").is_some())
            .count(),
        2
    );
    assert_eq!(first["evidence"]["structural_verification"], "verified");
    assert!(first["evidence"]["metadata_transaction_validation"]
        .as_object()
        .unwrap()
        .values()
        .all(|validation| validation["status"] == "ok"));
    assert_eq!(first["evidence"]["ckb_vm_execution"], "not-executed");
    assert_eq!(first["conflicts"], serde_json::json!([]));

    manifest["artifacts"].as_array_mut().unwrap().reverse();
    manifest["roles"].as_array_mut().unwrap().reverse();
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["protocol", "bundle", "check"])
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(second.status.success(), "{}", String::from_utf8_lossy(&second.stderr));
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(first["bundle_hash"], second["bundle_hash"]);

    let valid_closed_role_schema_hash = manifest["closed_roles"][0]["schema_identity"]["schema_hash"].clone();
    manifest["closed_roles"][0]["schema_identity"]["schema_hash"] = serde_json::json!("8".repeat(64));
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let closed_role_conflict_path = root.join("protocol-closed-role-conflicts.json");
    let closed_role_conflict = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["protocol", "bundle", "check"])
        .arg(&manifest_path)
        .arg("--output")
        .arg(&closed_role_conflict_path)
        .output()
        .unwrap();
    assert!(!closed_role_conflict.status.success(), "an unknown participant schema must fail before signing");
    let closed_role_report: serde_json::Value = serde_json::from_slice(&std::fs::read(closed_role_conflict_path).unwrap()).unwrap();
    assert!(closed_role_report["conflicts"].as_array().unwrap().iter().any(|conflict| conflict["code"] == "PB213"));
    manifest["closed_roles"][0]["schema_identity"]["schema_hash"] = valid_closed_role_schema_hash;

    let valid_builder_evidence = manifest["transaction"]["builder_assumption_evidence"].clone();
    manifest["transaction"]["builder_assumption_evidence"] = serde_json::json!({});
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let validation_path = root.join("protocol-builder-validation.json");
    let validation_conflict = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["protocol", "bundle", "check"])
        .arg(&manifest_path)
        .arg("--output")
        .arg(&validation_path)
        .output()
        .unwrap();
    assert!(!validation_conflict.status.success(), "missing builder evidence must fail before signing");
    let validation_report: serde_json::Value = serde_json::from_slice(&std::fs::read(validation_path).unwrap()).unwrap();
    assert!(validation_report["conflicts"].as_array().unwrap().iter().any(|conflict| conflict["code"] == "PB212"));
    assert_eq!(validation_report["evidence"]["metadata_transaction_validation"]["token"]["status"], "failed");
    manifest["transaction"]["builder_assumption_evidence"] = valid_builder_evidence;

    let builder_manifest_path = root.join("order-builder/cellscript-builder-manifest.json");
    let mut builder_manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&builder_manifest_path).unwrap()).unwrap();
    let created_outputs = {
        let settle = builder_manifest["actions"].as_array_mut().unwrap().iter_mut().find(|action| action["name"] == "settle").unwrap();
        let created_outputs = settle["created_outputs"].clone();
        settle["created_outputs"] = serde_json::json!(created_outputs.as_u64().unwrap() + 1);
        created_outputs
    };
    std::fs::write(&builder_manifest_path, serde_json::to_vec_pretty(&builder_manifest).unwrap()).unwrap();
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let tampered_builder = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["protocol", "bundle", "check"])
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!tampered_builder.status.success(), "tampered builder projections must fail artifact admission");
    let diagnostics =
        format!("{}{}", String::from_utf8_lossy(&tampered_builder.stdout), String::from_utf8_lossy(&tampered_builder.stderr));
    assert!(diagnostics.contains("builder action 'settle' field 'created_outputs'"), "unexpected diagnostics: {diagnostics}");
    let settle = builder_manifest["actions"].as_array_mut().unwrap().iter_mut().find(|action| action["name"] == "settle").unwrap();
    settle["created_outputs"] = created_outputs;
    std::fs::write(&builder_manifest_path, serde_json::to_vec_pretty(&builder_manifest).unwrap()).unwrap();

    let authorization = manifest["roles"].as_array_mut().unwrap().iter_mut().find(|role| role["artifact"] == "auth").unwrap();
    authorization["ownership"] = serde_json::json!("exclusive");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let conflict_path = root.join("protocol-conflicts.json");
    let conflict = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .args(["protocol", "bundle", "check"])
        .arg(&manifest_path)
        .arg("--output")
        .arg(&conflict_path)
        .output()
        .unwrap();
    assert!(!conflict.status.success(), "conflicting exclusive roles must fail before signing");
    let conflict_report: serde_json::Value = serde_json::from_slice(&std::fs::read(conflict_path).unwrap()).unwrap();
    assert_eq!(conflict_report["status"], "failed");
    assert!(conflict_report["conflicts"].as_array().unwrap().iter().any(|conflict| conflict["code"] == "PB200"));
    assert_eq!(conflict_report["evidence"]["structural_verification"], "not-provided");
}

#[test]
fn cellc_verify_ckb_fixtures_accepts_standard_manifest() {
    let manifest =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("compat").join("ckb_standard").join("manifest.json");

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-ckb-fixtures").arg(&manifest).arg("--json").output().unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["manifest_schema"], "cellscript-ckb-standard-compat-v0.16");
    assert_eq!(report["execution_level"], "MODEL");
    assert_eq!(report["ckb_vm_execution"], false);
    assert_eq!(report["issue_count"], 0);
    assert!(report["fixture_count"].as_u64().unwrap() >= 14);
    assert!(report["manifest_hash"].as_str().is_some_and(|hash| hash.len() == 64));
}

#[test]
fn cellc_verify_ckb_fixtures_accepts_ickb_claim_manifest() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmarks")
        .join("ickb_diff")
        .join("claim_manifest.json");

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-ckb-fixtures").arg(&manifest).arg("--json").output().unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["manifest_schema"], "cellscript-ickb-claim-manifest-v1");
    assert_eq!(report["execution_level"], "DIFFERENTIAL_CKB_VM_MANIFEST");
    assert_eq!(report["ckb_vm_execution"], false);
    assert_eq!(report["committed_ckb_vm_evidence"], true);
    assert_eq!(report["evidence_execution_level"], "DIFFERENTIAL_CKB_VM_EXECUTED");
    assert_eq!(report["required_executable_gate"], "cargo test --locked -p cellscript --test ickb_diff");
    assert!(
        report["vm_execution_note"].as_str().is_some_and(|note| note.contains("does not execute CKB VM")),
        "{}",
        report["vm_execution_note"]
    );
    assert_eq!(report["issue_count"], 0);
    assert!(report["fixture_count"].as_u64().unwrap() >= 8);
}

#[test]
fn cellc_verify_ckb_fixtures_rejects_ickb_claim_without_matrix_row() {
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmarks")
        .join("ickb_diff")
        .join("claim_manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["families"][0]["branches"][0]["required_scenarios"] =
        serde_json::json!(["differential: missing iCKB protocol branch original vs CellScript agree"]);

    let dir = tempfile::tempdir().unwrap();
    let invalid = dir.path().join("claim_manifest.json");
    std::fs::write(&invalid, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    std::fs::copy(manifest_path.parent().unwrap().join("matrix.json"), dir.path().join("matrix.json")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-ckb-fixtures").arg(&invalid).arg("--json").output().unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    let issues = report["issues"].as_array().unwrap().iter().filter_map(|issue| issue.as_str()).collect::<Vec<_>>().join("\n");
    assert!(issues.contains("required scenario is missing"), "{issues}");
}

#[test]
fn cellc_verify_ckb_fixtures_rejects_tampered_ickb_execution_evidence() {
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmarks")
        .join("ickb_diff")
        .join("claim_manifest.json");
    let matrix_path = manifest_path.parent().unwrap().join("matrix.json");
    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut matrix: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&matrix_path).unwrap()).unwrap();

    let rows = matrix["rows"].as_array_mut().unwrap();
    let pass_row =
        rows.iter_mut().find(|row| row["result"].as_str() == Some("differential-agree-pass")).expect("at least one pass row");
    pass_row["execution"]["cellscript_cycles"] = serde_json::json!(0);

    let dir = tempfile::tempdir().unwrap();
    let invalid = dir.path().join("claim_manifest.json");
    std::fs::write(&invalid, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    std::fs::write(dir.path().join("matrix.json"), serde_json::to_vec_pretty(&matrix).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-ckb-fixtures").arg(&invalid).arg("--json").output().unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    let issues = report["issues"].as_array().unwrap().iter().filter_map(|issue| issue.as_str()).collect::<Vec<_>>().join("\n");
    assert!(issues.contains("cellscript pass must consume cycles"), "{issues}");
}

#[test]
fn cellc_verify_ckb_fixtures_rejects_invalid_manifest_claim() {
    let manifest_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("compat").join("ckb_standard").join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["schema"] = serde_json::Value::String("wrong-schema".to_string());

    let dir = tempfile::tempdir().unwrap();
    let invalid = dir.path().join("invalid-fixture-manifest.json");
    std::fs::write(&invalid, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-ckb-fixtures").arg(&invalid).arg("--json").output().unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    let issues = report["issues"].as_array().unwrap().iter().filter_map(|issue| issue.as_str()).collect::<Vec<_>>().join("\n");
    assert!(issues.contains("manifest schema must be cellscript-ckb-standard-compat-v0.16"), "{issues}");
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .is_some_and(|message| message.contains("CKB fixture manifest failed verification")));
}

#[test]
fn cellc_top_level_accepts_primitive_strict_for_kernel_effect_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("strict.cell");
    let output = dir.path().join("strict.s");
    std::fs::write(
        &input,
        r#"
module test

resource Token has store, consume, burn {
    amount: u64,
}

action burn(token: Token) {
    verification
        destroy token
}
"#,
    )
    .unwrap();

    let run = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg(&input)
        .arg("--primitive-strict")
        .arg("0.15")
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();

    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(output.exists());
}

#[test]
fn cellc_top_level_primitive_strict_rejects_legacy_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("legacy.cell");
    std::fs::write(
        &input,
        r#"
module test

resource Token has store, destroy {
    amount: u64,
}

action burn(token: Token) {
    verification
        destroy token
}
"#,
    )
    .unwrap();

    let run = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("--primitive-strict").arg("0.15").output().unwrap();

    assert!(!run.status.success(), "legacy capability should fail strict mode");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("CS0151"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("legacy capability 'destroy'"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("consume + burn"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_constraints_subcommand_surfaces_ckb_deployment_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[deploy.ckb]
hash_type = "data2"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x1111111111111111111111111111111111111111111111111111111111111111:0"
dep_type = "dep_group"
hash_type = "type"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action main(value: u64) -> u64 {
    verification
        return value
}
"#,
    )
    .unwrap();

    let run = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("constraints")
        .arg("--target-profile")
        .arg("ckb")
        .arg("--entry-action")
        .arg("main")
        .output()
        .unwrap();

    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let constraints: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    let ckb = &constraints["ckb"];
    assert_eq!(constraints["target_profile"], "ckb");
    assert_eq!(ckb["hash_type_policy"]["declared_hash_type"], "data2");
    assert_eq!(ckb["hash_type_policy"]["status"], "manifest-declared-builder-must-match");
    assert_eq!(ckb["dep_group_manifest"]["status"], "manifest-declares-dep-group-builder-must-expand-or-reference");
    let dep = &ckb["dep_group_manifest"]["declared_cell_deps"][0];
    assert_eq!(dep["name"], "secp256k1");
    assert_eq!(dep["dep_type"], "dep_group");
    assert_eq!(dep["tx_hash"], "0x1111111111111111111111111111111111111111111111111111111111111111");
    assert_eq!(dep["index"], 0);
    assert_eq!(dep["hash_type"], "type");
    assert_eq!(ckb["profile_abi_contract"]["witness_abi"], "ckb-molecule-witness-args-input-type-v2+cellscript-entry-witness-v1");
    assert_eq!(ckb["profile_abi_contract"]["lock_args_abi"], "ckb-script-args-typed-fixed-bytes");
    assert_eq!(ckb["profile_abi_contract"]["source_encoding"], "ckb-source-group-high-bit");
    assert_eq!(ckb["profile_abi_contract"]["cell_dep_abi"], "ckb-cell-dep-outpoint-and-dep-group");
    assert_eq!(ckb["profile_abi_contract"]["script_ref_abi"], "ckb-script-code-hash-hash-type-args");
    assert_eq!(ckb["profile_abi_contract"]["output_data_abi"], "ckb-outputs-and-outputs-data-index-aligned");
    assert_eq!(ckb["profile_abi_contract"]["capacity_floor_abi"], "ckb-output-capacity-floor-shannons");
    assert_eq!(ckb["profile_abi_contract"]["type_id_abi"], "ckb-type-id-v1");
    assert_eq!(ckb["capacity_evidence_contract"]["tx_size_measurement_required"], true);
}

#[test]
fn cellc_verify_artifact_accepts_matching_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-artifact").arg(&output).output().unwrap();

    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("Artifact verification succeeded"));
    assert!(stdout.contains("Metadata schema"));
    assert!(stdout.contains("Compiler"));
    assert!(stdout.contains("RISC-V assembly"));

    let verify_sources =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-artifact").arg(&output).arg("--verify-sources").output().unwrap();
    assert!(verify_sources.status.success(), "{}", String::from_utf8_lossy(&verify_sources.stderr));
    let stdout = String::from_utf8_lossy(&verify_sources.stdout);
    assert!(stdout.contains("Sources: verified 1 unit(s)"), "{}", stdout);
}

#[test]
fn cellc_receipt_sign_and_verify_binds_artifact_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("pool.cell");
    let output = dir.path().join("pool.s");
    let receipt = dir.path().join("receipt.json");
    let signed_receipt = dir.path().join("receipt.signed.json");
    let tampered_receipt = dir.path().join("receipt.tampered.json");
    let key = dir.path().join("ed25519.pkcs8");
    let source = r#"
module test

resource Pool has store {
    reserve: u64
}

action swap(input: Pool) -> output: Pool {
    verification
        require output.reserve == input.reserve
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());
    let metadata_path = dir.path().join("pool.s.meta.json");
    let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();

    let receipt_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("receipt")
        .arg(&input)
        .args(["--output"])
        .arg(&receipt)
        .arg("--json")
        .output()
        .unwrap();
    assert!(receipt_output.status.success(), "{}", String::from_utf8_lossy(&receipt_output.stderr));
    let receipt_json: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(receipt_json["schema"], "cellscript-compile-receipt-v2");
    assert_eq!(receipt_json["artifact_hash"], metadata["artifact_hash"]);
    assert!(receipt_json["template_layout_hash"].as_str().is_some_and(|hash| hash.len() == 64));

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    std::fs::write(&key, pkcs8.as_ref()).unwrap();

    let sign = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("sign-receipt")
        .arg(&receipt)
        .args(["--role", "publisher", "--key"])
        .arg(&key)
        .args(["--output"])
        .arg(&signed_receipt)
        .arg("--json")
        .output()
        .unwrap();
    assert!(sign.status.success(), "{}", String::from_utf8_lossy(&sign.stderr));
    let signed_json: serde_json::Value = serde_json::from_slice(&std::fs::read(&signed_receipt).unwrap()).unwrap();
    assert_eq!(signed_json["signatures"][0]["algorithm"], "ed25519");
    assert_eq!(signed_json["signatures"][0]["role"], "publisher");

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-receipt")
        .arg(&signed_receipt)
        .args(["--metadata"])
        .arg(&metadata_path)
        .args(["--artifact"])
        .arg(&output)
        .arg("--json")
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    let verify_json: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_json["signatures_verified"], 1);
    assert_eq!(verify_json["unsigned_advisory"], false);

    let verify_artifact = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .args(["--receipt"])
        .arg(&signed_receipt)
        .arg("--json")
        .output()
        .unwrap();
    assert!(verify_artifact.status.success(), "{}", String::from_utf8_lossy(&verify_artifact.stderr));
    let verify_artifact_json: serde_json::Value = serde_json::from_slice(&verify_artifact.stdout).unwrap();
    assert_eq!(verify_artifact_json["receipt_verified"], true);
    assert_eq!(verify_artifact_json["receipt_signatures_verified"], 1);

    let mut tampered = signed_json;
    tampered["metadata_hash"] = serde_json::json!("00".repeat(32));
    std::fs::write(&tampered_receipt, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let reject = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-receipt")
        .arg(&tampered_receipt)
        .args(["--metadata"])
        .arg(&metadata_path)
        .args(["--artifact"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!reject.status.success(), "unexpected success: {}", String::from_utf8_lossy(&reject.stdout));
    let stderr = String::from_utf8_lossy(&reject.stderr);
    assert!(stderr.contains("metadata_hash"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_verify_artifact_rejects_tampered_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());
    std::fs::write(&output, b"tampered").unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-artifact").arg(&output).output().unwrap();

    assert!(!verify.status.success());
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("metadata artifact_hash") || stderr.contains("artifact_hash"), "{}", stderr);
}

#[test]
fn cellc_verify_artifact_rejects_tampered_source_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());
    std::fs::write(
        &input,
        r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y + 1
}
"#,
    )
    .unwrap();

    let verify =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-artifact").arg(&output).arg("--verify-sources").output().unwrap();

    assert!(!verify.status.success());
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("source unit") && stderr.contains("does not match metadata"), "{}", stderr);
}

#[test]
fn cellc_verify_artifact_rejects_metadata_schema_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let tampered_metadata = dir.path().join("schema-old.meta.json");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let metadata_path = dir.path().join("sample.s.meta.json");
    let mut metadata_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    let current_schema = metadata_json["metadata_schema_version"].as_u64().unwrap();
    metadata_json["metadata_schema_version"] = serde_json::json!(current_schema - 1);
    std::fs::write(&tampered_metadata, serde_json::to_vec_pretty(&metadata_json).unwrap()).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--metadata")
        .arg(&tampered_metadata)
        .output()
        .unwrap();

    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("unsupported metadata_schema_version"), "{}", stderr);
}

#[test]
fn cellc_verify_artifact_rejects_noncanonical_source_unit_hash() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let tampered_metadata = dir.path().join("uppercase-source-hash.meta.json");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let metadata_path = dir.path().join("sample.s.meta.json");
    let mut metadata_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    let source_hash = metadata_json["source_units"][0]["hash"].as_str().unwrap().to_uppercase();
    metadata_json["source_units"][0]["hash"] = serde_json::json!(source_hash);
    std::fs::write(&tampered_metadata, serde_json::to_vec_pretty(&metadata_json).unwrap()).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--metadata")
        .arg(&tampered_metadata)
        .output()
        .unwrap();

    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("expected 64 lowercase hex characters"), "{}", stderr);
}

#[test]
fn cellc_verify_artifact_enforces_policy_flags() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let source = r#"
module test

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("verify-artifact").arg(&output).arg("--production").output().unwrap();

    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("check policy failed"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("output-verification-incomplete"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("fail-closed"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_verify_artifact_enforces_expected_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("sample.cell");
    let output = dir.path().join("sample.s");
    let source = r#"
module test

action add(x: u64, y: u64) -> u64 {
    verification
        x + y
}
"#;
    std::fs::write(&input, source).unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
    assert!(build.success());

    let metadata_path = dir.path().join("sample.s.meta.json");
    let metadata_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&metadata_path).unwrap()).unwrap();
    let artifact_hash = metadata_json["artifact_hash"].as_str().unwrap();
    let source_content_hash = metadata_json["source_content_hash"].as_str().unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--expect-artifact-hash")
        .arg(artifact_hash)
        .arg("--expect-source-content-hash")
        .arg(source_content_hash)
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("Expected hashes: verified"), "{}", stdout);

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--json")
        .arg("--expect-artifact-hash")
        .arg(artifact_hash)
        .arg("--expect-source-content-hash")
        .arg(source_content_hash)
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["artifact_hash"], artifact_hash);
    assert_eq!(stdout["source_content_hash"], source_content_hash);
    assert_eq!(stdout["expected_hashes_verified"], true);
    assert_eq!(stdout["policy_verified"], false);
    assert_eq!(stdout["sources_verified"], false);
    assert_eq!(stdout["runtime_required_verifier_obligations"], 0);
    assert_eq!(stdout["fail_closed_verifier_obligations"], 0);

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--expect-source-content-hash")
        .arg("00".repeat(32))
        .output()
        .unwrap();
    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("source_content_hash") && stderr.contains("does not match expected"), "{}", stderr);

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(&output)
        .arg("--expect-artifact-hash")
        .arg(artifact_hash.to_uppercase())
        .output()
        .unwrap();
    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("lowercase CKB Blake2b hex digest"), "{}", stderr);
}

#[test]
fn cellc_compiles_bundled_examples_to_requested_outputs() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let examples_dir = manifest_dir.join("examples");
    let output_dir = tempfile::tempdir().unwrap();

    for example in [
        "amm_pool.cell",
        "atomic_swap.cell",
        "launch.cell",
        "multi_phase_dao.cell",
        "multisig.cell",
        "nft.cell",
        "timelock.cell",
        "token.cell",
        "vesting.cell",
    ] {
        let input = examples_dir.join(example);
        let output = output_dir.path().join(example.replace(".cell", ".s"));

        let status = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&input).arg("-o").arg(&output).status().unwrap();
        assert!(status.success(), "cellc failed for {}", example);

        let written = std::fs::read_to_string(&output).unwrap();
        assert!(written.contains(".section .text"), "missing text section for {}", example);
        assert!(!written.trim().is_empty(), "empty output for {}", example);
    }
}

#[test]
fn cellc_compiles_package_with_local_path_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("dep_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();

    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "dep_pkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src").join("token.cell"),
        r#"
module dep::token

resource Token has store, replace, relock, consume, burn {
    amount: u64
}
"#,
    )
    .unwrap();

    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
    )
    .unwrap();

    let app_entry = app_root.join("src").join("main.cell");
    std::fs::write(
        &app_entry,
        r#"
module app::main

use dep::token::Token

action pass_through(token: Token) -> Token {
    verification
        token
}
"#,
    )
    .unwrap();

    lock_package(&app_root);
    let output = app_root.join("build").join("main.s");
    let status = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).status().unwrap();

    assert!(status.success());

    let written = std::fs::read_to_string(&output).unwrap();
    assert!(written.contains(".section .text"));
    assert!(written.contains(".global pass_through"));
    assert!(!app_entry.with_extension("s").exists());
}

#[test]
fn cellc_rejects_registry_dependency_without_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies]
remote = "1.2.3"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("lock").output().unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("registry dependency 'remote' requires a namespace"), "unexpected stderr: {}", stderr);
    assert!(!root.join("Cell.lock").exists());
}

#[test]
fn cellc_build_resolves_artifact_api_dependency_and_writes_lockfile() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("token");
    let app_root = root.join("app");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "token"
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src/token.cell"),
        r#"
module dep::token

resource Token has store, replace, relock, consume, burn {
    amount: u64
}
"#,
    )
    .unwrap();
    let source_hash = cellscript::package::registry::compute_source_hash(&dep_root).unwrap();
    let registry_entry = cellscript::package::registry::RegistryIndex {
        schema_version: cellscript::package::registry::RegistryIndex::CURRENT_SCHEMA_VERSION,
        name: "token".to_string(),
        namespace: "cellscript".to_string(),
        versions: vec![cellscript::package::registry::RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "0.3.0".to_string(),
            tag: "v0.3.0".to_string(),
            source_hash: source_hash.clone(),
            cellscript_version: "0.19.0".to_string(),
            dependencies: Default::default(),
            abi_index: None,
            schema_hash: None,
            license: None,
            released_at: None,
            status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            replaced_by: None,
            audit: None,
        }],
    };

    let snapshot_file = |path: &str, content: &[u8]| {
        serde_json::json!({
            "path": path,
            "blake2b256": hex_lower(&cellscript::ckb_blake2b256(content)),
            "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
        })
    };
    let manifest_bytes = std::fs::read(dep_root.join("Cell.toml")).unwrap();
    let source_bytes = std::fs::read(dep_root.join("src/token.cell")).unwrap();
    let snapshot_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "cellscript-source-snapshot-v1",
        "package": { "namespace": "cellscript", "name": "token", "version": "0.3.0" },
        "files": [
            snapshot_file("Cell.toml", &manifest_bytes),
            snapshot_file("src/token.cell", &source_bytes),
        ],
    }))
    .unwrap();
    let snapshot_digest = Sha256::digest(&snapshot_bytes);
    let snapshot_hash = format!("sha256:{}", hex_lower(&snapshot_digest));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let api_origin = format!("http://{address}");
    let snapshot_path = "/source-snapshots/cellscript/token/0.3.0/token.json";
    let api_body = serde_json::json!({
        "schema": "cellscript-registry-artifact",
        "namespace": "cellscript",
        "name": "token",
        "repository": "https://example.test/cellscript/token",
        "artifact": {
            "kind": "source_library",
            "profile": "cellscript_source",
            "consumption_mode": "dependency",
            "language": "cellscript"
        },
        "releases": [{
            "release": "0.3.0",
            "verification_status": "verified",
            "availability_status": "active",
            "registry_entry": registry_entry,
            "immutable_bundle": {
                "schema": "cellscript-registry-immutable-bundle",
                "url": format!("{api_origin}{snapshot_path}"),
                "snapshot_hash": snapshot_hash,
                "source_hash": source_hash,
                "size_bytes": snapshot_bytes.len(),
                "content_type": "application/vnd.cellscript.source-snapshot+json"
            }
        }]
    })
    .to_string();
    let served_snapshot = snapshot_bytes.clone();
    listener.set_nonblocking(true).unwrap();
    let stop_server = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server_stop = std::sync::Arc::clone(&stop_server);
    let server = std::thread::spawn(move || {
        while !server_stop.load(std::sync::atomic::Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let (path, _) = read_http_request_path_and_body(&mut stream);
                    assert!(matches!(
                        path.as_str(),
                        "/v1/artifacts/cellscript/token" | "/source-snapshots/cellscript/token/0.3.0/token.json"
                    ));
                    let (body, content_type) = if path == snapshot_path {
                        (served_snapshot.as_slice(), "application/vnd.cellscript.source-snapshot+json")
                    } else {
                        (api_body.as_bytes(), "application/json")
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(body).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("artifact API mock failed: {error}"),
            }
        }
    });

    std::fs::create_dir_all(app_root.join("src")).unwrap();
    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app"
version = "0.1.0"
namespace = "cellscript"

[dependencies.token]
version = "0.3.0"
namespace = "cellscript"
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("src/main.cell"),
        r#"
module app::main

use dep::token::Token

action pass_through(token: Token) -> Token {
    verification
        token
}
"#,
    )
    .unwrap();

    let lock = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("lock")
        .env(cellscript::package::registry::REGISTRY_API_URL_ENV, &api_origin)
        .current_dir(&app_root)
        .output()
        .unwrap();
    assert!(lock.status.success(), "stderr: {}", String::from_utf8_lossy(&lock.stderr));

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("build")
        .arg("--locked")
        .env(cellscript::package::registry::REGISTRY_API_URL_ENV, &api_origin)
        .current_dir(&app_root)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let lockfile: cellscript::package::Lockfile =
        toml::from_str(&std::fs::read_to_string(app_root.join("Cell.lock")).unwrap()).unwrap();
    assert!(lockfile.package.source_hash.is_some());
    let build = lockfile.package_build.as_ref().expect("build identity");
    assert!(build.compiler_version.is_some());
    assert!(build.target_profile.is_some());
    assert!(build.artifact_hash.is_some());
    assert!(build.metadata_hash.is_some());
    assert!(build.schema_hash.is_some());
    assert!(build.abi_hash.is_some());
    assert!(build.constraints_hash.is_some());
    let token_node = lockfile.root.dependencies.get("token").expect("locked registry root edge");
    let token = lockfile.dependencies.get(token_node).expect("locked registry dependency");
    assert_eq!(token.source_hash.as_deref(), Some(source_hash.as_str()));

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("package")
        .arg("verify")
        .env(cellscript::package::registry::REGISTRY_API_URL_ENV, &api_origin)
        .current_dir(&app_root)
        .output()
        .unwrap();
    stop_server.store(true, std::sync::atomic::Ordering::Release);
    server.join().unwrap();
    assert!(verify.status.success(), "stderr: {}", String::from_utf8_lossy(&verify.stderr));
}

#[test]
fn cellc_registry_edit_yanks_existing_version() {
    let temp = tempfile::tempdir().unwrap();
    cellscript::package::registry::RegistryIndex::append_version(
        temp.path(),
        "token",
        "cellscript",
        cellscript::package::registry::RegistryVersion {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            source_hash: "abc123".to_string(),
            cellscript_version: "0.20.0".to_string(),
            dependencies: Default::default(),
            abi_index: None,
            schema_hash: None,
            license: Some("MIT".to_string()),
            released_at: None,
            status: cellscript::package::registry::RegistryEntryStatus::VerifiedBuild,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            replaced_by: None,
            audit: None,
        },
    )
    .unwrap();

    let output = cellc_command()
        .arg("registry")
        .arg("edit")
        .arg("--yank")
        .arg("1.0.0")
        .arg("--reason")
        .arg("security advisory")
        .arg("--replaced-by")
        .arg("1.0.1")
        .arg("--yanked-at")
        .arg("2026-06-23T00:00:00Z")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let index = cellscript::package::registry::RegistryIndex::read_from_repo(temp.path()).unwrap();
    let version = index.versions.iter().find(|version| version.version == "1.0.0").unwrap();
    assert!(version.yanked);
    assert_eq!(version.yanked_at.as_deref(), Some("2026-06-23T00:00:00Z"));
    assert_eq!(version.yanked_reason.as_deref(), Some("security advisory"));
    assert_eq!(version.replaced_by.as_deref(), Some("1.0.1"));
}

#[test]
fn cellc_init_accepts_phase1_namespace_flag() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("init")
        .arg("amm_pool")
        .arg("--namespace")
        .arg("cellscript")
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let manifest = std::fs::read_to_string(temp.path().join("Cell.toml")).unwrap();
    assert!(manifest.contains("namespace = \"cellscript\""), "manifest: {}", manifest);
}

#[test]
fn cellc_registry_verify_json_fails_closed_for_missing_deployment_ref() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let mut lockfile = cellscript::package::Lockfile::new();
    lockfile.package = cellscript::package::LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "token".to_string(),
        version: "1.0.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some("source_hash".to_string()),
        compiler_source_hash: None,
    };
    lockfile.package_build = Some(cellscript::package::LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.19.0".to_string()),
        target_profile: Some("ckb".to_string()),
        artifact_hash: Some("artifact_hash".to_string()),
        metadata_hash: Some("metadata_hash".to_string()),
        schema_hash: Some("schema_hash".to_string()),
        cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
        abi_hash: Some("abi_hash".to_string()),
        constraints_hash: Some("constraints_hash".to_string()),
    });
    lockfile.write_to_root(root).unwrap();

    let deployed = cellscript::package::DeployedManifest {
        version: cellscript::package::DeployedManifest::CURRENT_VERSION,
        schema: cellscript::package::DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: cellscript::package::DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "token".to_string(),
            version: "1.0.0".to_string(),
            source_hash: Some("source_hash".to_string()),
        },
        build: Some(cellscript::package::DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.19.0".to_string()),
            artifact_hash: Some("artifact_hash".to_string()),
            metadata_hash: Some("metadata_hash".to_string()),
            schema_hash: Some("schema_hash".to_string()),
            cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
            abi_hash: Some("abi_hash".to_string()),
            constraints_hash: Some("constraints_hash".to_string()),
        }),
        deployments: vec![cellscript::package::DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "aggron4".to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: "0xaaaa".to_string(),
            output_index: 0,
            code_hash: "0xbbbb".to_string(),
            hash_type: "data1".to_string(),
            dep_type: "code".to_string(),
            data_hash: "0xcccc".to_string(),
            out_point: "0xaaaa:0".to_string(),
            artifact_hash: None,
            metadata_hash: None,
            schema_hash: None,
            cell_data_codec_manifest_hash: None,
            abi_hash: None,
            constraints_hash: None,
            compiler_version: None,
            type_id: None,
            script_role: None,
            status: None,
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };
    deployed.write_to_root(root).unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("registry").arg("verify").arg("--json").current_dir(root).output().unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert!(report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|violation| violation.as_str().unwrap_or_default().contains("missing from Cell.lock")));
}

/// Build a fully-valid offline registry verify fixture whose single deployment
/// optionally declares an `upgrade_lineage`. Used by the lineage tests.
fn write_offline_fixture_with_lineage(root: &std::path::Path, lineage: Option<&str>) {
    let out_point = "0xbbbb:0".to_string();
    let mut lockfile = cellscript::package::Lockfile::new();
    lockfile.package = cellscript::package::LockfilePackageInfo {
        edition: cellscript::CURRENT_EDITION,
        name: "token".to_string(),
        version: "1.0.0".to_string(),
        namespace: Some("cellscript".to_string()),
        source_hash: Some("source_hash".to_string()),
        compiler_source_hash: None,
    };
    lockfile.package_build = Some(cellscript::package::LockedBuildInfo {
        edition: cellscript::CURRENT_EDITION,
        compatibility_profile_hash: "test-compatibility-profile".to_string(),
        compiler_version: Some("0.20.0".to_string()),
        target_profile: Some("ckb".to_string()),
        artifact_hash: Some("artifact_hash".to_string()),
        metadata_hash: Some("metadata_hash".to_string()),
        schema_hash: Some("schema_hash".to_string()),
        cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
        abi_hash: Some("abi_hash".to_string()),
        constraints_hash: Some("constraints_hash".to_string()),
    });
    lockfile.deployment.insert(
        "aggron4".to_string(),
        cellscript::package::LockfileDeploymentRef {
            record: out_point.clone(),
            record_hash: None,
            code_hash: Some("0xbbbb".to_string()),
            out_point: Some(out_point.clone()),
            data_hash: Some("0xcccc".to_string()),
        },
    );
    lockfile.write_to_root(root).unwrap();

    let deployed = cellscript::package::DeployedManifest {
        version: cellscript::package::DeployedManifest::CURRENT_VERSION,
        schema: cellscript::package::DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: cellscript::package::DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "token".to_string(),
            version: "1.0.0".to_string(),
            source_hash: Some("source_hash".to_string()),
        },
        build: Some(cellscript::package::DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            compiler_version: Some("0.20.0".to_string()),
            artifact_hash: Some("artifact_hash".to_string()),
            metadata_hash: Some("metadata_hash".to_string()),
            schema_hash: Some("schema_hash".to_string()),
            cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
            abi_hash: Some("abi_hash".to_string()),
            constraints_hash: Some("constraints_hash".to_string()),
        }),
        deployments: vec![cellscript::package::DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: "test-compatibility-profile".to_string(),
            network: "aggron4".to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: "0xbbbb".to_string(),
            output_index: 0,
            code_hash: "0xbbbb".to_string(),
            hash_type: "data1".to_string(),
            dep_type: "code".to_string(),
            data_hash: "0xcccc".to_string(),
            out_point,
            artifact_hash: Some("artifact_hash".to_string()),
            metadata_hash: Some("metadata_hash".to_string()),
            schema_hash: Some("schema_hash".to_string()),
            cell_data_codec_manifest_hash: Some("codec_manifest_hash".to_string()),
            abi_hash: Some("abi_hash".to_string()),
            constraints_hash: Some("constraints_hash".to_string()),
            compiler_version: Some("0.20.0".to_string()),
            type_id: None,
            script_role: Some(cellscript::package::ScriptRole::Type),
            status: Some(cellscript::package::DeploymentStatus::Active),
            upgrade_lineage: lineage.map(str::to_string),
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };
    deployed.write_to_root(root).unwrap();
}

#[test]
fn cellc_registry_verify_accepts_upgrade_lineage_pointing_elsewhere() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    // Lineage points at a pruned prior deployment's out_point (not self, not empty).
    write_offline_fixture_with_lineage(root, Some("0xaaaa:0"));

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("registry").arg("verify").arg("--json").current_dir(root).output().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok", "violations: {:?}", report["violations"]);
    assert!(report["violations"].as_array().unwrap().is_empty());
}

#[test]
fn cellc_registry_verify_rejects_upgrade_lineage_pointing_at_itself() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    // Current deployment's lineage points at its own out_point.
    write_offline_fixture_with_lineage(root, Some("0xbbbb:0"));

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("registry").arg("verify").arg("--json").current_dir(root).output().unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert!(
        report["violations"].as_array().unwrap().iter().any(|v| v.as_str().unwrap_or_default().contains("own out_point")),
        "violations: {:?}",
        report["violations"]
    );
}

#[test]
fn cellc_registry_verify_live_accepts_matching_rpc_cell() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data_hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
    write_live_registry_fixture(root, data_hash);
    let rpc_url = start_mock_ckb_rpc(vec![
        ("get_blockchain_info", serde_json::json!({ "chain": "ckb_testnet" })),
        ("get_live_cell", live_cell_rpc_result("live", data_hash)),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--live")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--network")
        .arg("aggron4")
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["live"]["enabled"], true);
    assert_eq!(report["live"]["checked"], 1);
    assert_eq!(report["live"]["evidence"][0]["status"], "live-verified");
    assert_eq!(report["live"]["evidence"][0]["rpc_data_hash"], data_hash);
    assert!(report["violations"].as_array().unwrap().is_empty());
}

#[test]
fn cellc_registry_verify_live_accepts_type_hash_and_type_id() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data_hash = "0x3333333333333333333333333333333333333333333333333333333333333333";
    let type_code_hash = "0x4444444444444444444444444444444444444444444444444444444444444444";
    let type_id = "0x5555555555555555555555555555555555555555555555555555555555555555";
    let script_hash = ckb_script_hash_for_test(type_code_hash, "data1", type_id);
    write_live_registry_fixture_with(root, data_hash, &script_hash, "type", Some(type_id));
    let rpc_url = start_mock_ckb_rpc(vec![
        ("get_blockchain_info", serde_json::json!({ "chain": "ckb-testnet" })),
        (
            "get_live_cell",
            live_cell_rpc_result_with_type(
                "live",
                data_hash,
                serde_json::json!({
                    "code_hash": type_code_hash,
                    "hash_type": "data1",
                    "args": type_id
                }),
            ),
        ),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--live")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["live"]["evidence"][0]["rpc_code_hash"], script_hash);
    assert!(report["violations"].as_array().unwrap().is_empty());
}

#[test]
fn cellc_registry_verify_live_rejects_dead_rpc_cell() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data_hash = "0x2222222222222222222222222222222222222222222222222222222222222222";
    write_live_registry_fixture(root, data_hash);
    let rpc_url = start_mock_ckb_rpc(vec![
        ("get_blockchain_info", serde_json::json!({ "chain": "ckb-testnet" })),
        ("get_live_cell", live_cell_rpc_result("dead", data_hash)),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--live")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["live"]["evidence"][0]["rpc_status"], "dead");
    assert!(report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|violation| violation.as_str().unwrap_or_default().contains("is not live")));
}

#[test]
fn cellc_registry_verify_live_rejects_deprecated_deployment_status() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data_hash = "0x6666666666666666666666666666666666666666666666666666666666666666";
    write_live_registry_fixture(root, data_hash);
    let mut deployed = cellscript::package::DeployedManifest::read_from_root(root).unwrap().unwrap();
    deployed.deployments[0].status = Some(cellscript::package::DeploymentStatus::Deprecated);
    deployed.write_to_root(root).unwrap();
    let rpc_url = start_mock_ckb_rpc(vec![
        ("get_blockchain_info", serde_json::json!({ "chain": "ckb-testnet" })),
        ("get_live_cell", live_cell_rpc_result("live", data_hash)),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--live")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["live"]["evidence"][0]["status"], "failed");
    assert_eq!(report["live"]["evidence"][0]["deployment_status"], "deprecated");
    assert!(report["live"]["evidence"][0]["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|violation| violation.as_str().unwrap_or_default().contains("not active")));
}

#[test]
fn cellc_registry_verify_live_rejects_missing_deployment_status() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data_hash = "0x7777777777777777777777777777777777777777777777777777777777777777";
    write_live_registry_fixture(root, data_hash);
    let mut deployed = cellscript::package::DeployedManifest::read_from_root(root).unwrap().unwrap();
    deployed.deployments[0].status = None;
    deployed.write_to_root(root).unwrap();
    let rpc_url = start_mock_ckb_rpc(vec![
        ("get_blockchain_info", serde_json::json!({ "chain": "ckb-testnet" })),
        ("get_live_cell", live_cell_rpc_result("live", data_hash)),
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--live")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["live"]["evidence"][0]["status"], "failed");
    assert!(report["live"]["evidence"][0]["deployment_status"].is_null());
    assert!(report["live"]["evidence"][0]["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|violation| violation.as_str().unwrap_or_default().contains("has no status")));
}

#[test]
fn cellc_registry_verify_requires_trust_metadata_when_requested() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data_hash = "0x8888888888888888888888888888888888888888888888888888888888888888";
    write_live_registry_fixture(root, data_hash);

    let rejected = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--require-publisher-signature")
        .arg("--require-audit-report")
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(!rejected.status.success(), "unexpected success: {}", String::from_utf8_lossy(&rejected.stdout));
    let report: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["trust"]["enabled"], true);
    assert_eq!(report["trust"]["verification_boundary"], "metadata-presence-only");
    assert_eq!(report["trust"]["evidence"][0]["publisher_signature_status"], "missing");
    assert_eq!(report["trust"]["evidence"][0]["audit_report_hash_status"], "missing");
    assert!(report["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|violation| violation.as_str().unwrap_or_default().contains("publisher_signature")));

    let mut deployed = cellscript::package::DeployedManifest::read_from_root(root).unwrap().unwrap();
    deployed.deployments[0].publisher_signature = Some("sig:fixture".to_string());
    deployed.deployments[0].audit_report_hash = Some("0xabc".to_string());
    deployed.write_to_root(root).unwrap();

    let accepted = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("registry")
        .arg("verify")
        .arg("--require-publisher-signature")
        .arg("--require-audit-report")
        .arg("--json")
        .current_dir(root)
        .output()
        .unwrap();

    assert!(accepted.status.success(), "stderr: {}", String::from_utf8_lossy(&accepted.stderr));
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["trust"]["evidence"][0]["status"], "policy-satisfied");
    assert_eq!(report["trust"]["evidence"][0]["publisher_signature_status"], "present-unverified");
    assert_eq!(report["trust"]["evidence"][0]["audit_report_hash_status"], "present");
    assert!(report["violations"].as_array().unwrap().is_empty());
}

#[test]
fn cellc_rejects_underdeclared_effects_from_path_dependency_calls() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("dep_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();

    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "dep_pkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src").join("token.cell"),
        r#"
module dep::token

resource Token {
    amount: u64
}

action issue(amount: u64) -> Token {
    verification
        let out = create Token {
            amount: amount
        }
        return out
}
"#,
    )
    .unwrap();

    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("src").join("main.cell"),
        r#"
module app::main

use dep::token::Token
use dep::token::issue

#[effect(ReadOnly)]
action wrapper(amount: u64) -> Token {
    verification
        return issue(amount)
}
"#,
    )
    .unwrap();

    lock_package(&app_root);
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("declared effect ReadOnly is too weak"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("inferred effect is Creating"), "unexpected stderr: {}", stderr);

    std::fs::write(
        app_root.join("src").join("main.cell"),
        r#"
module app::main

use dep::token::Token

#[effect(ReadOnly)]
action wrapper(amount: u64) -> Token {
    verification
        return dep::token::issue(amount)
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("declared effect ReadOnly is too weak"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("inferred effect is Creating"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_compiles_external_dependency_function_calls() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("dep_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();

    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "dep_pkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src").join("math.cell"),
        r#"
module dep::math

fn add_one(x: u64) -> u64 {
    return x + 1
}
"#,
    )
    .unwrap();

    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("src").join("main.cell"),
        r#"
module app::main

action run(x: u64) -> u64 {
    verification
        return dep::math::add_one(x)
}
"#,
    )
    .unwrap();

    lock_package(&app_root);
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let artifact = std::fs::read_to_string(app_root.join("build").join("main.s")).unwrap();
    assert!(artifact.contains("call __cellscript_ext_dep__math__add_one"), "external call was not lowered:\n{}", artifact);
    assert!(artifact.contains("__cellscript_ext_dep__math__add_one:"), "external helper body was not merged:\n{}", artifact);
    assert!(!artifact.contains("call dep::math::add_one"), "qualified label leaked into assembly:\n{}", artifact);
}

#[test]
fn cellc_enforces_package_visibility_across_path_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("dep_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();
    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "dep_pkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src").join("math.cell"),
        r#"
module dep::math

public(package) fn package_secret(x: u64) -> u64 {
    return x + 1
}

public fn exported(x: u64) -> u64 {
    return x + 2
}
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
    )
    .unwrap();

    let app_source = app_root.join("src").join("main.cell");
    std::fs::write(
        &app_source,
        r#"
module app::main

use dep::math::package_secret as hidden

action run(x: u64) -> u64 {
    verification
        return hidden(x)
}
"#,
    )
    .unwrap();
    lock_package(&app_root);
    let aliased = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(!aliased.status.success(), "package-private alias unexpectedly compiled");
    let stderr = String::from_utf8_lossy(&aliased.stderr);
    assert!(stderr.contains("package_secret") && stderr.contains("public(package)"), "unexpected stderr: {stderr}");

    std::fs::write(
        &app_source,
        r#"
module app::main

action run(x: u64) -> u64 {
    verification
        return dep::math::package_secret(x)
}
"#,
    )
    .unwrap();
    lock_package(&app_root);
    let qualified = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(!qualified.status.success(), "qualified package-private call unexpectedly compiled");

    std::fs::write(
        app_root.join("src").join("internal.cell"),
        r#"
module app::internal

public(package) fn same_package(x: u64) -> u64 {
    return x + 3
}
"#,
    )
    .unwrap();
    std::fs::write(
        &app_source,
        r#"
module app::main

use app::internal::same_package
use dep::math::exported

action run(x: u64) -> u64 {
    verification
        return same_package(x) + exported(x)
}
"#,
    )
    .unwrap();
    lock_package(&app_root);
    let allowed = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(allowed.status.success(), "stderr: {}", String::from_utf8_lossy(&allowed.stderr));
}

#[test]
fn cellc_compiles_aliased_external_dependency_function_calls() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("dep_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();

    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "dep_pkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src").join("math.cell"),
        r#"
module dep::math

fn add_one(x: u64) -> u64 {
    return x + 1
}
"#,
    )
    .unwrap();

    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("src").join("main.cell"),
        r#"
module app::main

use dep::math::add_one as plus_one
use dep::math::add_one as inc

action run(x: u64) -> u64 {
    verification
        return plus_one(x) + inc(x)
}
"#,
    )
    .unwrap();

    lock_package(&app_root);
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let artifact = std::fs::read_to_string(app_root.join("build").join("main.s")).unwrap();
    assert!(artifact.contains("call plus_one"), "aliased external call was not lowered:\n{}", artifact);
    assert!(artifact.contains("plus_one:"), "aliased external helper body was not merged:\n{}", artifact);
    assert!(!artifact.contains("call inc"), "duplicate alias did not reuse the canonical imported label:\n{}", artifact);
    assert!(!artifact.contains("inc:"), "duplicate alias emitted a second helper body:\n{}", artifact);
    assert!(!artifact.contains("call add_one"), "alias call fell back to the dependency basename:\n{}", artifact);
}

#[test]
fn cellc_compiles_same_basename_external_dependency_function_calls_without_collision() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_a_root = root.join("dep_a_pkg");
    let dep_b_root = root.join("dep_b_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_a_root.join("src")).unwrap();
    std::fs::create_dir_all(dep_b_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();

    for (dep_root, package, module, delta) in
        [(&dep_a_root, "dep_a_pkg", "dep_a::math", 1_u64), (&dep_b_root, "dep_b_pkg", "dep_b::math", 2_u64)]
    {
        std::fs::write(
            dep_root.join("Cell.toml"),
            format!(
                r#"
[package]
edition = "2026"
name = "{package}"
version = "0.1.0"
"#
            ),
        )
        .unwrap();
        std::fs::write(
            dep_root.join("src").join("math.cell"),
            format!(
                r#"
module {module}

fn add_one(x: u64) -> u64 {{
    return x + {delta}
}}
"#
            ),
        )
        .unwrap();
    }

    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_a_pkg = { path = "../dep_a_pkg" }
dep_b_pkg = { path = "../dep_b_pkg" }
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("src").join("main.cell"),
        r#"
module app::main

action run(x: u64) -> u64 {
    verification
        return dep_a::math::add_one(x) + dep_b::math::add_one(x)
}
"#,
    )
    .unwrap();

    lock_package(&app_root);
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let artifact = std::fs::read_to_string(app_root.join("build").join("main.s")).unwrap();
    assert!(artifact.contains("call __cellscript_ext_dep_a__math__add_one"), "dep_a call was not lowered:\n{}", artifact);
    assert!(artifact.contains("call __cellscript_ext_dep_b__math__add_one"), "dep_b call was not lowered:\n{}", artifact);
    assert!(
        artifact.contains("__cellscript_ext_dep_a__math__add_one:") && artifact.contains("__cellscript_ext_dep_b__math__add_one:"),
        "same-basename external helpers were not both merged:\n{}",
        artifact
    );
    assert!(!artifact.contains("call dep_a::math::add_one"), "dep_a qualified label leaked into assembly:\n{}", artifact);
    assert!(!artifact.contains("call dep_b::math::add_one"), "dep_b qualified label leaked into assembly:\n{}", artifact);
}

#[test]
fn cellc_compiles_transitive_external_dependency_function_calls() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("dep_pkg");
    let app_root = root.join("app_pkg");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(app_root.join("src")).unwrap();

    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "dep_pkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("src").join("math.cell"),
        r#"
module dep::math

fn add_one(x: u64) -> u64 {
    return x + 1
}

fn add_two(x: u64) -> u64 {
    return add_one(x) + 1
}
"#,
    )
    .unwrap();

    std::fs::write(
        app_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
    )
    .unwrap();
    std::fs::write(
        app_root.join("src").join("main.cell"),
        r#"
module app::main

action run(x: u64) -> u64 {
    verification
        return dep::math::add_two(x)
}
"#,
    )
    .unwrap();

    lock_package(&app_root);
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(&app_root).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let artifact = std::fs::read_to_string(app_root.join("build").join("main.s")).unwrap();
    assert!(artifact.contains("call __cellscript_ext_dep__math__add_two"), "outer helper call was not lowered:\n{}", artifact);
    assert!(artifact.contains("call __cellscript_ext_dep__math__add_one"), "transitive helper call was not lowered:\n{}", artifact);
    assert!(
        artifact.contains("__cellscript_ext_dep__math__add_two:") && artifact.contains("__cellscript_ext_dep__math__add_one:"),
        "transitive external helpers were not merged:\n{}",
        artifact
    );
}

#[test]
fn cellc_uses_manifest_build_out_dir_for_package_input() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
out_dir = "artifacts"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = root.join("artifacts").join("main.s");
    let status = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(root).status().unwrap();

    assert!(status.success());

    let written = std::fs::read_to_string(&output).unwrap();
    assert!(written.contains(".section .text"));
    assert!(!root.join("build").join("main.s").exists());
}

#[test]
fn cellc_cli_target_overrides_manifest_build_target() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target = "riscv64-elf"
out_dir = "artifacts"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = root.join("artifacts").join("main.s");
    let status = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(root).arg("--target").arg("riscv64-asm").status().unwrap();

    assert!(status.success());

    let written = std::fs::read_to_string(&output).unwrap();
    assert!(written.contains(".section .text"));
    assert!(!written.trim().is_empty());
}

#[test]
fn cellc_uses_manifest_build_target_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target = "riscv64-elf"
out_dir = "artifacts"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = root.join("artifacts").join("main.elf");
    let status = Command::new(env!("CARGO_BIN_EXE_cellc")).arg(root).status().unwrap();

    assert!(status.success());

    let written = std::fs::read(&output).unwrap();
    assert!(written.starts_with(b"\x7fELF"));
    assert!(!root.join("artifacts").join("main.s").exists());
}

#[test]
fn cellc_build_and_check_subcommands_use_package_flow() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let check = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").status().unwrap();
    assert!(check.success());

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").status().unwrap();
    assert!(build.success());

    let output = root.join("build").join("main.s");
    let written = std::fs::read_to_string(output).unwrap();
    assert!(written.contains(".section .text"));
    let metadata = std::fs::read_to_string(root.join("build").join("main.s.meta.json")).unwrap();
    assert!(metadata.contains("\"module\": \"demo::main\""));
    assert!(metadata.contains("\"scheduler_witness_abi\""));
    assert!(metadata.contains("\"scheduler_witness_hex\""));
    assert!(!metadata.contains("\"scheduler_witness_molecule_hex\""));

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["artifact_format"], "RISC-V assembly");
    assert_eq!(stdout["opt_level"], 1);
    assert_eq!(stdout["target_profile"], "ckb");
    assert_eq!(stdout["policy_verified"], false);
    assert_eq!(stdout["runtime_required_verifier_obligations"], 0);
    assert_eq!(stdout["fail_closed_verifier_obligations"], 0);
    assert!(stdout["artifact"].as_str().unwrap().ends_with("build/main.s"));
    assert!(stdout["metadata"].as_str().unwrap().ends_with("build/main.s.meta.json"));
    assert!(stdout["artifact_hash"].as_str().unwrap().len() == 64);
    assert!(stdout["source_content_hash"].as_str().unwrap().len() == 64);
    assert_eq!(stdout["constraints"]["target_profile"], "ckb");
    assert_eq!(stdout["constraints"]["status"], "warn");
    assert!(stdout["constraints"]["artifact"]["artifact_size_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn cellc_check_all_targets_checks_asm_and_elf_without_writing_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target = "riscv64-elf"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--all-targets").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Check succeeded"), "unexpected stdout: {}", stdout);
    assert!(stdout.contains("riscv64-asm (RISC-V assembly)"), "unexpected stdout: {}", stdout);
    assert!(stdout.contains("riscv64-elf (RISC-V ELF)"), "unexpected stdout: {}", stdout);
    assert!(!root.join("build").join("main.s").exists());
    assert!(!root.join("build").join("main.elf").exists());
    assert!(!root.join("build").join("main.s.meta.json").exists());
    assert!(!root.join("build").join("main.elf.meta.json").exists());

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--all-targets").arg("--json").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["all_targets"], true);
    assert_eq!(stdout["policy_verified"], false);
    let checked_targets = stdout["checked_targets"].as_array().unwrap();
    assert_eq!(checked_targets.len(), 2);
    assert!(checked_targets.iter().all(|target| target["runtime_required_verifier_obligations"] == 0));
    assert!(checked_targets.iter().all(|target| target["fail_closed_verifier_obligations"] == 0));
    assert!(checked_targets.iter().all(|target| target["target_profile"] == "ckb"));
    assert!(checked_targets.iter().all(|target| target["compiled_target_profile"] == "ckb"));
    assert!(checked_targets.iter().all(|target| target["target_profile_policy_violations"].as_array().unwrap().is_empty()));
    assert!(checked_targets.iter().any(|target| target["requested_target"] == "riscv64-asm"));
    assert!(checked_targets.iter().any(|target| target["requested_target"] == "riscv64-elf"));
}

#[test]
fn cellc_check_json_reports_multiple_compile_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action bad() -> bool {
    verification
        let first: u64 = true
        let second: bool = 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    let diagnostics = stdout["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 2, "unexpected diagnostics: {stdout}");
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected U64, found Bool")));
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected Bool, found U64")));
    assert_eq!(stdout["diagnostic_count"], 2);
    assert_eq!(stdout["error_count"], 2);
    assert_eq!(stdout["warning_count"], 0);
    assert!(diagnostics.iter().all(|diagnostic| diagnostic.get("range").is_some()));
    assert!(diagnostics.iter().all(|diagnostic| diagnostic["range"]["start"]["line"].as_u64().unwrap_or_default() > 0));
}

#[test]
fn cellc_check_json_reports_multiple_parse_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["diagnostic_count"], 2);
    assert_eq!(stdout["error_count"], 2);
    assert_eq!(stdout["warning_count"], 0);
    let diagnostics = stdout["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 2, "unexpected diagnostics: {stdout}");
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected '=', found 'true'")));
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected '=', found integer 1")));
    assert!(diagnostics.iter().all(|diagnostic| diagnostic["range"]["start"]["line"].as_u64().unwrap_or_default() > 0));
}

#[test]
fn cellc_check_json_reports_diagnostics_on_stdout() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["check", "--json"]).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["diagnostic_count"], 2);
    assert_eq!(stdout["error_count"], 2);
    assert_eq!(stdout["warning_count"], 0);
    let diagnostics = stdout["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected '=', found 'true'")));
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("expected '=', found integer 1")));
    assert!(diagnostics.iter().all(|diagnostic| diagnostic["range"]["start"]["line"].as_u64().unwrap_or_default() > 0));
}

#[test]
fn cellc_json_is_global_for_package_commands_and_build_failures_use_stdout() {
    let temp = tempfile::tempdir().unwrap();
    for args in [["build", "--json"], ["--json", "build"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(temp.path()).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
        let diagnostic: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(diagnostic["status"], "failed");
        assert_eq!(diagnostic["diagnostic_count"], 1);
    }
}

#[test]
fn cellc_message_format_json_remains_a_hidden_stdout_compatibility_alias() {
    let temp = tempfile::tempdir().unwrap();
    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(temp.path()).args(["build", "--message-format=json"]).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(diagnostic["status"], "failed");
}

#[test]
fn cellc_check_json_reports_multiple_ir_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token {
    amount: u64,
}

#[effect(ReadOnly)]
action issue_one(amount: u64) -> Token {
    verification
        let out = create Token {
            amount: amount
        }
        return out
}

#[effect(ReadOnly)]
action issue_two(amount: u64) -> Token {
    verification
        let out = create Token {
            amount: amount
        }
        return out
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["diagnostic_count"], 2);
    assert_eq!(stdout["error_count"], 2);
    assert_eq!(stdout["warning_count"], 0);
    let diagnostics = stdout["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 2, "unexpected diagnostics: {stdout}");
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("action 'issue_one'")));
    assert!(diagnostics.iter().any(|diagnostic| diagnostic["message"].as_str().unwrap().contains("action 'issue_two'")));
    assert!(diagnostics.iter().all(|diagnostic| {
        diagnostic["message"].as_str().unwrap().contains("declared effect ReadOnly is too weak")
            && diagnostic["range"]["start"]["line"].as_u64().unwrap_or_default() > 0
    }));
}

#[test]
fn cellc_build_accepts_pure_ckb_target_profile_without_vm_abi_trailer() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("build")
        .arg("--target-profile")
        .arg("ckb")
        .arg("--target")
        .arg("riscv64-elf")
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["target_profile"], "ckb");
    assert_eq!(stdout["artifact_format"], "RISC-V ELF");
    let artifact_path = stdout["artifact"].as_str().unwrap();
    let artifact = std::fs::read(artifact_path).unwrap();
    assert!(artifact.starts_with(b"\x7fELF"));
    assert!(!artifact.ends_with(b"CSABITR0\x01\x80\0\0\0\0\0\0"));

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(artifact_path)
        .arg("--expect-target-profile")
        .arg("ckb")
        .arg("--json")
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    let verify_stdout: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_stdout["target_profile"], "ckb");
    assert_eq!(verify_stdout["expected_target_profile_verified"], true);

    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("verify-artifact")
        .arg(artifact_path)
        .arg("--expect-target-profile")
        .arg("unknown")
        .output()
        .unwrap();
    assert!(!verify.status.success(), "unexpected success: {}", String::from_utf8_lossy(&verify.stdout));
}

#[test]
fn cellc_check_accepts_pure_ckb_target_profile() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action add(x: u64, y: u64) -> u64 {
    verification
        return x + y
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("check")
        .arg("--target-profile")
        .arg("ckb")
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    let checked_targets = stdout["checked_targets"].as_array().unwrap();
    assert_eq!(checked_targets.len(), 1);
    assert_eq!(checked_targets[0]["target_profile"], "ckb");
    assert_eq!(checked_targets[0]["compiled_target_profile"], "ckb");
    assert!(checked_targets[0]["target_profile_policy_violations"].as_array().unwrap().is_empty());
}

#[test]
fn cellc_check_accepts_ckb_profile_timepoint() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action now() -> u64 {
    verification
        return env::current_timepoint()
}
"#,
    )
    .unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--target-profile").arg("ckb").output().unwrap();

    assert!(output.status.success(), "check should succeed with timepoint: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn cellc_check_production_rejects_fail_closed_runtime_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--production").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error[E2105]"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("stopped before codegen"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("output-verification-incomplete"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("fail-closed"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_production_rejects_bounded_collection_consensus_gaps_before_codegen() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "bounded-gap"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module bounded::gap

struct Plan { amount: u64 }
resource DynamicToken has store, consume {
    amount: u64
    memo: String
}
resource Token has store, create { amount: u64 }

action batch(input inputs: BoundedCellSet<DynamicToken, 2>, witness plans: BoundedList<Plan, 2>) -> u64 {
    verification
        consume_each token in inputs {
            require false
            require token.amount > 0
        }
        create_each plan in plans {
            require false
            create Token { amount: plan.amount }
        }
        return 0
}
"#,
    )
    .unwrap();

    let check =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--production").arg("--json").output().unwrap();
    assert!(!check.status.success(), "unexpected success: {}", String::from_utf8_lossy(&check.stdout));
    let report: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["code"], "E2105");
    assert_eq!(report["phase"], "pre-codegen");
    assert_eq!(report["consensus_gaps"].as_array().map(Vec::len), Some(2));
    assert_eq!(report["consensus_gaps"][0]["operation"], "consume_each:inputs:BoundedCellSet<DynamicToken, 2>");
    assert_eq!(report["consensus_gaps"][0]["missing_enforcement"], "gap:runtime-helper-required");
    assert_eq!(report["consensus_gaps"][1]["missing_enforcement"], "gap:builder-evidence-required");
    assert!(report["consensus_gaps"][0]["remediation"].as_str().unwrap().contains("fixed-arity"));

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--production").output().unwrap();
    assert!(!build.status.success(), "unexpected success: {}", String::from_utf8_lossy(&build.stdout));
    let stderr = String::from_utf8_lossy(&build.stderr);
    assert!(stderr.contains("error[E2105]"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("create_each") || stderr.contains("consume_each"), "unexpected stderr: {stderr}");
    assert!(!root.join("build").join("main.s").exists());
    assert!(!root.join("build").join("main.s.meta.json").exists());
}

#[test]
fn cellc_errors_include_compiler_ecode_when_surface_is_rejected_before_codegen() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action append_schema_vec(items: Vec<Address>, owner: Address) -> u64 {
    verification
        let mut values = items
        values.push(owner)
        return values.len()
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--production").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error[E2105]"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("cellc explain E2105"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("collection-push"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("stopped before codegen"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_check_production_rejects_incomplete_output_verification() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--production").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error[E2105]"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("stopped before codegen"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("output-verification-incomplete"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("fail-closed"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_check_can_reject_runtime_required_obligations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 1, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 1, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 1, "unexpected stdout: {}", stdout);
    let runtime_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(
        runtime_inputs.iter().any(|value| value
            .as_str()
            .is_some_and(|summary| { summary.contains("create-output:Fingerprint") && summary.contains("(runtime-required)") })),
        "unexpected runtime-required transaction runtime input summaries: {}",
        stdout
    );

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("check policy failed"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("runtime-required verifier obligations"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("runtime-required transaction runtime input requirements"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("runtime-required transaction runtime input blockers"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("runtime-required transaction runtime input blocker classes"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("create-output:Fingerprint"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_check_reports_transaction_invariant_checked_subconditions() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store {
    amount: u64
    owner: Address
}

receipt VestingGrant has store {
    state: u8
    beneficiary: Address
    total_amount: u64
    claimed_amount: u64
    cliff_timepoint: u64
    end_timepoint: u64
}

flow VestingGrant.state {
    Granted -> Claimable;
    Granted -> FullyClaimed;
    Claimable -> FullyClaimed;
}

action claim_vested(grant: VestingGrant) -> (tokens: Token, updated_grant: VestingGrant) {
    transition grant.state: Claimable -> updated_grant.state: FullyClaimed
    verification
        let now = env::current_timepoint()

        require now >= grant.cliff_timepoint, "cliff not reached"
        require grant.state < VestingGrant::FullyClaimed, "already fully claimed"

        let vested_total = grant.total_amount
        let claimable = vested_total - grant.claimed_amount
        require claimable > 0, "nothing to claim"

        consume grant

        let new_state: u8 = if vested_total == grant.total_amount { VestingGrant::FullyClaimed } else { VestingGrant::Claimable }

        create tokens = Token {
            amount: claimable,
            owner: grant.beneficiary
        } with_lock(grant.beneficiary)

        create updated_grant = VestingGrant {
            state: new_state,
            beneficiary: grant.beneficiary,
            total_amount: grant.total_amount,
            claimed_amount: grant.claimed_amount + claimable,
            cliff_timepoint: grant.cliff_timepoint,
            end_timepoint: grant.end_timepoint
        } with_lock(grant.beneficiary)
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["runtime_required_transaction_invariants"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_invariant_checked_subconditions"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["transaction_runtime_input_requirements"], 5, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["checked_transaction_runtime_input_requirements"], 5, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 0, "unexpected stdout: {}", stdout);
    let summaries = target["runtime_required_transaction_invariant_checked_subcondition_summaries"]
        .as_array()
        .expect("transaction invariant summaries array");
    assert!(summaries.is_empty(), "claim guards should be checked-runtime now: {}", stdout);
    let runtime_inputs =
        target["transaction_runtime_input_requirement_summaries"].as_array().expect("transaction runtime input summaries array");
    assert!(
        runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("consume-input:VestingGrant:grant:consume-input-data=Input:grant.data")
                && summary.contains("consume-load-cell-input")
        })),
        "unexpected transaction runtime input summaries: {}",
        stdout
    );
    let checked_runtime_inputs = target["checked_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("checked transaction runtime input summaries array");
    assert!(
        checked_runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("consume-input:VestingGrant:grant:consume-input-data=Input:grant.data")
                && summary.contains("consume-load-cell-input")
                && summary.contains("(checked-runtime)")
                && !summary.contains("blocker=")
                && !summary.contains("blocker_class=")
        })),
        "unexpected checked transaction runtime input summaries: {}",
        stdout
    );
    assert!(
        checked_runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("create-output:Token:tokens:create-output-fields=Output:tokens.fields")
                && summary.contains("create-output-field-verifier")
                && summary.contains("(checked-runtime)")
                && !summary.contains("blocker=")
                && !summary.contains("blocker_class=")
        })),
        "unexpected checked transaction runtime input summaries: {}",
        stdout
    );
    assert!(
        checked_runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("create-output:VestingGrant:updated_grant:create-output-lock=Output:updated_grant.lock_hash")
                && summary.contains("create-output-lock-hash-32[32]")
                && summary.contains("(checked-runtime)")
                && !summary.contains("blocker=")
                && !summary.contains("blocker_class=")
        })),
        "unexpected checked transaction runtime input summaries: {}",
        stdout
    );
    let runtime_required_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(runtime_required_inputs.is_empty(), "claim input requirements should be checked-runtime now: {}", stdout);
    let runtime_input_blockers = target["runtime_required_transaction_runtime_input_blocker_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input blocker summaries array");
    assert!(runtime_input_blockers.is_empty(), "claim blockers should be checked-runtime now: {}", stdout);
    let runtime_input_blocker_classes = target["runtime_required_transaction_runtime_input_blocker_class_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input blocker class summaries array");
    assert!(runtime_input_blocker_classes.is_empty(), "claim blocker classes should be checked-runtime now: {}", stdout);

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(
        output.status.success(),
        "checked obligations should satisfy deny-runtime-obligations: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cellc_check_reports_resource_conservation_blocker_class() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store {
    amount: u64
}

action withdraw(token: Token, fee: u64) -> Token {
    verification
        let amount = token.amount
        let remaining = amount - fee
        consume token
        let out = create Token {
            amount: remaining
        }
        return out
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 1, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 1, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 1, "unexpected stdout: {}", stdout);

    let runtime_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(
        runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("resource-conservation:Token:resource-conservation-proof=Transaction:Token.input-output-conservation")
                && summary.contains("resource-conservation-consume-create-accounting")
                && summary.contains("(runtime-required)")
                && summary.contains("blocker=resource conservation is not fully lowered for this consumed-input/created-output shape")
                && summary.contains("blocker_class=resource-conservation-proof-gap")
        })),
        "unexpected runtime-required transaction runtime input summaries: {}",
        stdout
    );

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("resource-conservation:Token"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("runtime-required transaction runtime input blocker classes"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("resource-conservation-proof-gap"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_check_reports_explicit_output_binding_without_mutable_state_blockers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

shared Ledger has store {
    balance: u128,
    owner: Address,
}

action credit(ledger_before: Ledger, delta: u128) -> ledger_after: Ledger {
    verification
        require ledger_after.owner == ledger_before.owner
        require ledger_after.balance == ledger_before.balance + delta
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 0, "unexpected stdout: {}", stdout);

    let runtime_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(runtime_inputs.is_empty(), "unexpected runtime-required transaction runtime input summaries: {}", stdout);

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(
        output.status.success(),
        "explicit output requirements should not report mutable-state runtime blockers: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cellc_check_reports_settle_finalization_blocker_class() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 1, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 1, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 1, "unexpected stdout: {}", stdout);

    let runtime_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(
        runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("create-output:Fingerprint")
                && summary.contains("(runtime-required)")
                && summary.contains("blocker=create output field verifier is incomplete")
                && summary.contains("blocker_class=create-output-verification-gap")
        })),
        "unexpected runtime-required transaction runtime input summaries: {}",
        stdout
    );

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("create-output:Fingerprint"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("create-output-verification-gap"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("create output field verifier is incomplete"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_check_rejects_cell_backed_vec_with_source_aware_guidance() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource NFT {
    token_id: u64
    owner: Address
}

action batch_mint(owner: Address) -> Vec<NFT> {
    verification
        let mut nfts = Vec::new()
        let nft = create NFT {
            token_id: 1,
            owner: owner
        }
        nfts.push(nft)
        return nfts
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(!json_output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&json_output.stdout));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["diagnostic_count"], 1);
    let diagnostics = stdout["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic["message"].as_str().is_some_and(|message| {
                message.contains("type 'Vec<NFT>' cannot store a cell-backed resource")
                    && message.contains("use a source-aware BoundedCellSet<T, N> with explicit ownership")
            })
        }),
        "unexpected diagnostics: {}",
        stdout
    );
}

#[test]
fn cellc_check_accepts_u128_mutable_state_transition_with_u64_delta() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

shared Ledger has store {
    balance: u128,
    owner: Address,
}

action credit(ledger_before: Ledger, delta: u64) -> ledger_after: Ledger {
    verification
        require ledger_after.owner == ledger_before.owner
        require ledger_after.balance == ledger_before.balance + delta
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 0, "unexpected stdout: {}", stdout);

    let runtime_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(runtime_inputs.is_empty(), "unexpected runtime-required transaction runtime input summaries: {}", stdout);

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn cellc_check_rejects_undeclared_flow_edge() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // All three states are declared in the flow, but only Live -> Filled and the
    // Filled <-> Cancelled edges exist. `cancel` uses Live -> Cancelled, which is
    // not a declared edge, so the static flow-edge membership check must reject it.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store {
    state: u8
    amount: u64
}

flow Offer.state {
    Live -> Filled;
    Filled -> Cancelled;
    Cancelled -> Filled;
}

action cancel(input: Offer) -> output: Offer {
    transition input.state: Live -> output.state: Cancelled
    verification
        require input.amount == output.amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("action 'cancel' transition 'Offer.state Live -> Cancelled' is not declared in the flow"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cellc_check_accepts_declared_cyclic_flow_edge() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // Declared cyclic edges (Open <-> Closed) must be accepted by the static flow
    // membership validator; the cycle is a legitimate state machine, not an error.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Pool has store {
    state: u8
    reserve: u64
}

flow Pool.state {
    Open -> Closed;
    Closed -> Open;
}

action close(pool_before: Pool) -> pool_after: Pool {
    transition pool_before.state: Open -> pool_after.state: Closed
    verification
        require pool_after.reserve == pool_before.reserve
}

action reopen(pool_before: Pool) -> pool_after: Pool {
    transition pool_before.state: Closed -> pool_after.state: Open
    verification
        require pool_after.reserve == pool_before.reserve
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn cellc_check_accepts_declared_linear_flow_edge() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // A linear (acyclic) state machine must be accepted when every action uses a
    // declared edge. This is the positive counterpart to the undeclared-edge test.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store {
    state: u8
    amount: u64
}

flow Offer.state {
    Live -> Filled;
    Filled -> Cancelled;
    Cancelled -> Filled;
}

action fill(input: Offer) -> output: Offer {
    transition input.state: Live -> output.state: Filled
    verification
        require input.amount == output.amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn cellc_check_rejects_flow_create_missing_state_field() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store, create {
    state: u8
    amount: u64
}

flow Offer.state {
    Live -> Filled;
}

action seed(recipient: Address) -> output: Offer {
    verification
        create output = Offer { amount: 0 } with_lock(recipient)
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("create of flow type 'Offer' must set its state field"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_check_rejects_initial_flow_create_non_static_state() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // The initial create of a flow-typed cell uses a runtime-derived state value,
    // which the static flow-state contract forbids.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store, create {
    state: u8
    amount: u64
}

flow Offer.state {
    Live -> Filled;
}

action seed(dynamic_state: u8, recipient: Address) -> output: Offer {
    verification
        create output = Offer { state: dynamic_state, amount: 0 } with_lock(recipient)
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("initial create of flow type 'Offer' must use a statically known declared state"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cellc_check_rejects_flow_state_index_out_of_range() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // A statically-known state index that falls outside the declared state set
    // (two states: Live=0, Filled=1) must be rejected by the flow-state contract.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store, create {
    state: u8
    amount: u64
}

flow Offer.state {
    Live -> Filled;
}

action seed(recipient: Address) -> output: Offer {
    verification
        create output = Offer { state: 99, amount: 0 } with_lock(recipient)
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("flow state index 99 is out of range for 'Offer' with 2 states"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_check_rejects_duplicate_flow_edge() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // Declaring the same edge twice is a static error: the flow block must declare a
    // set of distinct transitions, not a multiset.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store {
    state: u8
    amount: u64
}

flow Offer.state {
    Live -> Filled;
    Live -> Filled;
    Filled -> Cancelled;
}

action fill(input: Offer) -> output: Offer {
    transition input.state: Live -> output.state: Filled
    verification
        require input.amount == output.amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("duplicate state transition 'Live -> Filled'"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_check_rejects_transition_on_type_without_flow_block() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // An action declares a state-annotated transition, but the target type has no
    // `flow` block. The compiler must reject it rather than silently accepting the
    // transition as a plain consume/create.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Offer has store {
    state: u8
    amount: u64
}

action fill(input: Offer) -> output: Offer {
    transition input.state: Live -> output.state: Filled
    verification
        require input.amount == output.amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("type 'Offer' has no declared flow"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_check_rejects_aggregate_invariant_scope_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    // The invariant declares scope: transaction but the aggregate reads group-scoped
    // endpoints (group_inputs/group_outputs). The aggregate scope must match the
    // enclosing invariant scope.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, create, consume {
    amount: u128,
}

invariant wrong_scope_conservation {
    trigger: type_group
    scope: transaction
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_sum(group_outputs<Token>.amount) == assert_sum(group_inputs<Token>.amount)
}

action transfer(input: Token) -> output: Token {
    verification
        xudt::require_group_amount_conserved()
        preserve output from input {
            amount
        }
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("aggregate invariant scope 'group' must match enclosing invariant scope 'transaction'"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cellc_check_reports_claim_source_predicate_blocker_class() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store {
    amount: u64
}

resource VestingReceipt has store {
    amount: u64
    beneficiary: Address
    cliff_timepoint: u64
}

action redeem_after_cliff(receipt: VestingReceipt) -> Token {
    verification
        let now = env::current_timepoint()
        require now >= receipt.cliff_timepoint, "cliff not reached"

        consume receipt

        create Token {
            amount: receipt.amount
        } with_lock(receipt.beneficiary)
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["transaction_runtime_input_requirements"], 3, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_requirements"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["checked_transaction_runtime_input_requirements"], 3, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blockers"], 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_transaction_runtime_input_blocker_classes"], 0, "unexpected stdout: {}", stdout);

    let runtime_inputs = target["runtime_required_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("runtime-required transaction runtime input summaries array");
    assert!(runtime_inputs.is_empty(), "unexpected runtime-required transaction runtime input summaries: {}", stdout);

    let checked_runtime_inputs = target["checked_transaction_runtime_input_requirement_summaries"]
        .as_array()
        .expect("checked transaction runtime input summaries array");
    assert!(
        checked_runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| {
            summary.contains("consume-input:VestingReceipt:receipt:consume-input-data=Input:receipt.data")
                && summary.contains("consume-load-cell-input")
                && summary.contains("(checked-runtime)")
        })),
        "unexpected checked transaction runtime input summaries: {}",
        stdout
    );
    // Using consume instead of claim, so only consume-input runtime requirements are present.
    // The checked_transaction_runtime_input_requirements count is 3:
    // 1. consume-input:VestingReceipt
    // 2. create-output:Token (fields)
    // 3. create-output:Token (lock_hash)
}

#[test]
fn cellc_check_reports_pool_invariant_policy_families() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store {
    symbol: [u8; 8]
    amount: u64
}

receipt LPReceipt has store {
    pool_id: Hash
    lp_amount: u64
    provider: Address
}

shared Pool has store {
    token_a_symbol: [u8; 8]
    token_b_symbol: [u8; 8]
    reserve_a: u64
    reserve_b: u64
    total_lp: u64
    fee_rate_bps: u16
}

action seed_pool(token_a: Token, token_b: Token, fee_rate_bps: u16, provider: Address) -> (Pool, LPReceipt) {
    verification
        require token_a.symbol != token_b.symbol, "same token"
        require token_a.amount > 0 && token_b.amount > 0, "zero liquidity"
        require fee_rate_bps <= 10000, "fee too high"
        require token_a.type_hash() != token_b.type_hash(), "same token type"

        let initial_lp: u64 = token_a.amount
        consume token_a
        consume token_b

        let pool = create Pool {
            token_a_symbol: token_a.symbol,
            token_b_symbol: token_b.symbol,
            reserve_a: token_a.amount,
            reserve_b: token_b.amount,
            total_lp: initial_lp,
            fee_rate_bps: fee_rate_bps
        }

        let receipt = create LPReceipt {
            pool_id: pool.type_hash(),
            lp_amount: initial_lp,
            provider: provider
        } with_lock(provider)

        (pool, receipt)
}
"#,
    )
    .unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert!(target["checked_pool_invariant_families"].as_u64().unwrap() > 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_pool_invariant_families"].as_u64().unwrap(), 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["pool_runtime_input_requirements"].as_u64().unwrap(), 0, "unexpected stdout: {}", stdout);
    let runtime_inputs = target["pool_runtime_input_requirement_summaries"].as_array().expect("runtime input summaries array");
    assert!(runtime_inputs.is_empty(), "checked seed_pool identity should leave no Pool runtime inputs: {}", stdout);

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(
        output.status.success(),
        "checked seed_pool identity should satisfy deny-runtime-obligations: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cellc_check_reports_amm_pool_without_runtime_blockers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let amm_source = std::fs::read_to_string(manifest_dir.join("examples").join("amm_pool.cell"))
        .unwrap()
        .replace("use cellscript::fungible_token::Token", "resource Token has store {\n    symbol: [u8; 8]\n    amount: u64\n}");

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(root.join("src").join("main.cell"), amm_source).unwrap();

    let json_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--json").output().unwrap();
    assert!(json_output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&json_output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let target = &stdout["checked_targets"][0];
    assert_eq!(target["checked_pool_invariant_families"].as_u64().unwrap(), 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_pool_invariant_families"].as_u64().unwrap(), 0, "unexpected stdout: {}", stdout);
    assert_eq!(target["runtime_required_pool_invariant_blocker_classes"].as_u64().unwrap(), 0, "unexpected stdout: {}", stdout);
    let blocker_classes = target["runtime_required_pool_invariant_blocker_class_summaries"]
        .as_array()
        .expect("runtime-required Pool invariant blocker class summaries array");
    assert!(blocker_classes.is_empty(), "AMM pool admission should not leave runtime-required blockers: {}", stdout);
    let runtime_inputs = target["pool_runtime_input_requirement_summaries"].as_array().expect("runtime input summaries array");
    assert!(
        !runtime_inputs.iter().any(|value| value.as_str().is_some_and(|summary| { summary.contains("reserve-conservation=") })),
        "AMM reserve-conservation should not appear in Pool runtime input summaries: {}",
        stdout
    );
    assert_eq!(
        target["runtime_required_transaction_runtime_input_requirements"].as_u64().unwrap(),
        0,
        "unexpected stdout: {}",
        stdout
    );
    assert_eq!(
        target["runtime_required_transaction_runtime_input_blocker_classes"].as_u64().unwrap(),
        0,
        "unexpected stdout: {}",
        stdout
    );

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(
        output.status.success(),
        "full AMM policy should satisfy deny-runtime-obligations: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cellc_check_uses_manifest_policy_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[policy]
production = true
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error[E2105]"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("stopped before codegen"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("output-verification-incomplete"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_build_uses_manifest_policy_before_writing_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[policy]
deny_ckb_runtime = true
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--target-profile").arg("ckb").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("check policy failed"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("CKB runtime features"), "unexpected stderr: {}", stderr);
    assert!(!root.join("build").join("main.s").exists());
    assert!(!root.join("build").join("main.s.meta.json").exists());
}

#[test]
fn cellc_build_production_accepts_closed_u128_modulo_lowering() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

fn mod128(left: u128, right: u128) -> u128 {
    return left % right
}

action remainder(left: u128, right: u128) -> u128 {
    verification
        return mod128(left, right)
}
"#,
    )
    .unwrap();

    let metadata = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("metadata").output().unwrap();
    assert!(metadata.status.success(), "metadata-only analysis failed: {}", String::from_utf8_lossy(&metadata.stderr));
    assert!(!String::from_utf8_lossy(&metadata.stdout).contains("u128-modulo"));

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--production").output().unwrap();
    assert!(output.status.success(), "unexpected failure: {}", String::from_utf8_lossy(&output.stderr));
    assert!(root.join("build").join("main.s").exists());
    assert!(root.join("build").join("main.s.meta.json").exists());
}

#[test]
fn cellc_test_subcommand_compiles_test_sources() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("math.cell"),
        r#"
module demo::tests::math

action adds() -> u64 {
    verification
        1 + 2
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Test compile complete"));
    assert!(stdout.contains("Compiled 1 test file(s)"));

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["test_files"], 1);
    assert_eq!(stdout["passed"], 1);
    assert_eq!(stdout["failed"], 0);
    assert_eq!(stdout["no_run"], true);
    assert_eq!(stdout["execution"], "disabled");
    let tests = stdout["tests"].as_array().unwrap();
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0]["status"], "passed");
    assert!(tests[0]["path"].as_str().unwrap().ends_with("tests/math.cell"));
}

#[test]
fn cellc_test_subcommand_supports_expected_compile_failures() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("negative.cell"),
        r#"
// cellscript-test: expect-error: declared effect Pure is too weak for function 'helper'
module demo::tests::negative

#[effect(Pure)]
fn helper() -> u64 {
    return env::current_timepoint()
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Test compile complete"));
    assert!(stdout.contains("Compiled 1 test file(s)"));
}

#[test]
fn cellc_test_subcommand_rejects_missing_expected_error_text() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("negative.cell"),
        r#"
// cellscript-test: expect-error: this text is intentionally absent
module demo::tests::negative

#[effect(Pure)]
fn helper() -> u64 {
    return env::current_timepoint()
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected error text not found"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_test_subcommand_supports_target_directive() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("elf.cell"),
        r#"
// cellscript-test: target: riscv64-elf
module demo::tests::elf

action main() -> u64 {
    verification
        0
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compiled 1 test file(s)"), "unexpected stdout: {}", stdout);
}

#[test]
fn cellc_test_subcommand_supports_policy_directives() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("policy.cell"),
        r#"
// cellscript-test: deny-runtime-obligations
// cellscript-test: expect-error: create-output:Fingerprint
module demo::tests::policy

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compiled 1 test file(s)"), "unexpected stdout: {}", stdout);
}

#[test]
fn cellc_test_subcommand_supports_runtime_metadata_directives() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("metadata.cell"),
        r#"
// cellscript-test: expect-not-standalone
// cellscript-test: expect-ckb-runtime
// cellscript-test: expect-runtime-feature: verify-output-cell
// cellscript-test: expect-no-runtime-feature: consume-expression
// cellscript-test: expect-verifier-obligation: create-output:Fingerprint
// cellscript-test: expect-no-verifier-obligation: not-present
module demo::tests::metadata

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    verification
        let dynamic_digest = pass_digest(digest)
        let token = create Fingerprint {
            digest: dynamic_digest
        }
        return token
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compiled 1 test file(s)"), "unexpected stdout: {}", stdout);
}

#[test]
fn cellc_test_subcommand_rejects_missing_runtime_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("metadata.cell"),
        r#"
// cellscript-test: expect-runtime-feature: not-present
module demo::tests::metadata

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected runtime metadata to contain 'not-present'"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_test_subcommand_supports_entrypoint_metadata_directives() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("entries.cell"),
        r#"
// cellscript-test: expect-artifact-format: RISC-V assembly
// cellscript-test: expect-action: run
// cellscript-test: expect-function: helper
// cellscript-test: expect-no-action: helper
// cellscript-test: expect-no-lock: run
module demo::tests::entries

fn helper(x: u64) -> u64 {
    x + 1
}

action run(x: u64) -> u64 {
    verification
        helper(x)
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Compiled 1 test file(s)"), "unexpected stdout: {}", stdout);
}

#[test]
fn cellc_test_subcommand_rejects_missing_entrypoint_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("entries.cell"),
        r#"
// cellscript-test: expect-function: missing_helper
module demo::tests::entries

action run(x: u64) -> u64 {
    verification
        x
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected function metadata to contain 'missing_helper'"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_test_subcommand_rejects_unknown_directives() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("typo.cell"),
        r#"
// cellscript-test: expect-eror: typo should not be ignored
module demo::tests::typo

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown cellscript-test directive"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("expect-eror"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_test_subcommand_rejects_conflicting_expectations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("tests").join("conflict.cell"),
        r#"
// cellscript-test: expect-success
// cellscript-test: expect-fail
module demo::tests::conflict

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("test").arg("--no-run").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("conflicting cellscript-test directives"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_doc_subcommand_generates_markdown_docs() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action ping() -> u64 {
    verification
        1
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("doc")
        .arg("--format")
        .arg("markdown")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["format"], "markdown");
    assert!(summary["output"].as_str().unwrap().ends_with("docs/cellscript-api.md"));
    assert!(summary["output_size_bytes"].as_u64().unwrap() > 0);

    let docs = std::fs::read_to_string(root.join("docs").join("cellscript-api.md")).unwrap();
    assert!(docs.contains("## Module `demo::main`"));
    assert!(docs.contains("### action `ping`"));
    assert!(docs.contains("## Lowering Audit Report"));
    assert!(docs.contains("### Verifier Obligations"));
}

#[test]
fn cellc_init_subcommand_supports_json_summary() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("demo_pkg");

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("init").arg("demo").arg(&root).arg("--lib").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["kind"], "library");
    assert_eq!(summary["package"], "demo");
    assert!(summary["manifest"].as_str().unwrap().ends_with("demo_pkg/Cell.toml"));
    assert_eq!(summary["entry"], "src/lib.cell");
    assert!(root.join("Cell.toml").exists());
    assert!(root.join("src").join("lib.cell").exists());
    assert!(!root.join("src").join("main.cell").exists());

    let manifest: toml::Value = std::fs::read_to_string(root.join("Cell.toml")).unwrap().parse().unwrap();
    assert_eq!(manifest["package"]["entry"].as_str(), Some("src/lib.cell"));
}

#[test]
fn cellc_new_subcommand_supports_json_summary_and_vcs_none() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("demo_pkg");

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("new")
        .arg("demo")
        .arg("--path")
        .arg(&root)
        .arg("--lib")
        .arg("--vcs")
        .arg("none")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["command"], "new");
    assert_eq!(summary["kind"], "library");
    assert_eq!(summary["package"], "demo");
    assert_eq!(summary["vcs"], "none");
    assert_eq!(summary["git_initialized"], false);
    assert!(summary["manifest"].as_str().unwrap().ends_with("demo_pkg/Cell.toml"));
    assert_eq!(summary["entry"], "src/lib.cell");
    assert!(root.join("Cell.toml").exists());
    assert!(root.join("src").join("lib.cell").exists());
    assert!(!root.join("src").join("main.cell").exists());
    assert!(!root.join(".git").exists());

    let manifest: toml::Value = std::fs::read_to_string(root.join("Cell.toml")).unwrap().parse().unwrap();
    assert_eq!(manifest["package"]["entry"].as_str(), Some("src/lib.cell"));
}

#[test]
fn cellc_new_subcommand_initializes_git_by_default() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("git_pkg");

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("new").arg("git_demo").arg("--path").arg(&root).arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["command"], "new");
    assert_eq!(summary["kind"], "binary");
    assert_eq!(summary["package"], "git_demo");
    assert_eq!(summary["vcs"], "git");
    assert_eq!(summary["git_initialized"], true);
    assert_eq!(summary["entry"], "src/main.cell");
    assert!(root.join(".git").exists());
    assert!(root.join("src").join("main.cell").exists());
}

#[test]
fn cellc_schema_ack_creates_and_verifies_a_focused_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let old = temp.path().join("old");
    let new = temp.path().join("new");
    for root in [&old, &new] {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "schema-ack-demo"
version = "0.1.0"
edition = "2027"
entry = "src/main.cell"

[build]
target_profile = "ckb"
"#,
        )
        .unwrap();
    }
    std::fs::write(
        old.join("src/main.cell"),
        r#"
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
"#,
    )
    .unwrap();
    let candidate = r#"
module schema_ack::token
resource Token has store, replace, relock { owner: Address, amount: u64, approval_nonce: u64 }
action transfer(input token: Token) -> next: Token {
    replace token -> next {
        data = same except { approval_nonce = 0 }
        lock = same
        capacity = same
        identity = same
    }
}
"#;
    std::fs::write(new.join("src/main.cell"), candidate).unwrap();

    let selector_args = ["--action", "transfer", "--before", "token", "--after", "next"];
    let plan = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("schema-ack")
        .arg("--old")
        .arg(&old)
        .arg("--new")
        .arg(&new)
        .args(selector_args)
        .output()
        .unwrap();
    assert!(plan.status.success(), "stderr: {}", String::from_utf8_lossy(&plan.stderr));
    let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan["schema"], "cellscript-schema-change-plan-v1");
    assert_eq!(plan["requires_acknowledgement"], true);
    assert_eq!(plan["blockers"].as_array().unwrap().len(), 0);

    let receipt_path = temp.path().join("schema-ack.json");
    let created = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("schema-ack")
        .arg("--old")
        .arg(&old)
        .arg("--new")
        .arg(&new)
        .args(selector_args)
        .args(["--acknowledge-by", "Arthur", "--rationale", "approval nonce resets on transfer", "--output"])
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(created.status.success(), "stderr: {}", String::from_utf8_lossy(&created.stderr));
    let receipt: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["schema"], "cellscript-schema-acknowledgement-v1");
    assert_eq!(receipt["reviewer"], "Arthur");

    let verified = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("schema-ack")
        .arg("--old")
        .arg(&old)
        .arg("--new")
        .arg(&new)
        .args(selector_args)
        .arg("--verify")
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(verified.status.success(), "stderr: {}", String::from_utf8_lossy(&verified.stderr));
    let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["status"], "verified");

    std::fs::write(new.join("src/main.cell"), candidate.replace("approval_nonce = 0", "approval_nonce = 1")).unwrap();
    let stale = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("schema-ack")
        .arg("--old")
        .arg(&old)
        .arg("--new")
        .arg(&new)
        .args(selector_args)
        .arg("--verify")
        .arg(&receipt_path)
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale"));
}

#[test]
fn cellc_explain_subcommand_reports_runtime_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("explain").arg("E0018").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["code"], 18);
    assert_eq!(summary["ecode"], "E0018");
    assert_eq!(summary["name"], "fixed-byte-comparison-unresolved");
    assert!(summary["description"].as_str().unwrap().contains("fixed-byte verifier comparison"));
    assert!(summary["hint"].as_str().unwrap().contains("schema-backed"));
}

#[test]
fn cellc_explain_subcommand_reports_compiler_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "E2202", "--json"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["domain"], "compiler");
    assert_eq!(summary["code"], "E2202");
    assert_eq!(summary["name"], "instruction-encoding");
    assert!(summary["description"].as_str().unwrap().contains("RISC-V instruction"));
    assert!(summary["hint"].as_str().unwrap().contains("immediate range"));
}

#[test]
fn cellc_explain_subcommand_reports_public_interface_breaking_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "E2501", "--json"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["domain"], "compiler");
    assert_eq!(summary["code"], "E2501");
    assert_eq!(summary["name"], "public-interface-breaking");
    assert!(summary["description"].as_str().unwrap().contains("public interface"));
    assert!(summary["hint"].as_str().unwrap().contains("compatibility dimension"));
}

#[test]
fn cellc_explain_profile_reports_ckb_v0_14_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "profile", "ckb", "--json"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["profile"], "ckb");
    assert_eq!(summary["witness_abi"], "ckb-molecule-witness-args-input-type-v2+cellscript-entry-witness-v1");
    assert_eq!(summary["lock_args_abi"], "ckb-script-args-typed-fixed-bytes");
    assert_eq!(summary["source_encoding"], "ckb-source-group-high-bit");
    assert_eq!(summary["spawn_ipc_abi"], "ckb-vm-v2-spawn-ipc-syscalls-2601-2608");
    assert_eq!(summary["since_abi"], "ckb-since-rfc0017-typed-v1");
    assert_eq!(summary["cell_dep_abi"], "ckb-cell-dep-outpoint-and-dep-group");
    assert_eq!(summary["script_ref_abi"], "ckb-script-code-hash-hash-type-args");
    assert_eq!(summary["output_data_abi"], "ckb-outputs-and-outputs-data-index-aligned");
    assert_eq!(summary["capacity_floor_abi"], "ckb-output-capacity-floor-shannons");
    assert_eq!(summary["type_id_abi"], "ckb-type-id-v1");
    let boundaries = summary["boundaries"].as_array().unwrap();
    assert!(
        boundaries.iter().any(|boundary| boundary.as_str().unwrap_or_default().contains("outputs and outputs_data are index-aligned")),
        "missing outputs_data boundary: {boundaries:?}"
    );
    assert!(
        boundaries.iter().any(|boundary| boundary.as_str().unwrap_or_default().contains("lock_args parameters are typed script args")),
        "missing lock_args boundary: {boundaries:?}"
    );
    assert!(
        boundaries.iter().any(|boundary| boundary.as_str().unwrap_or_default().contains("capacity floors are declared")),
        "missing capacity floor boundary: {boundaries:?}"
    );
}

#[test]
fn cellc_explain_proof_reports_covenant_proof_plan() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("token.cell");
    std::fs::write(
        &input,
        r#"
module test

resource Token has store, replace, relock, consume {
    amount: u64,
}

action transfer_token(token: Token, to: Address) -> next_token: Token {
    verification
        std::lifecycle::transfer(token, next_token, to) {
            amount
        }
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "proof"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let proof_plan = summary["proof_plan"].as_array().expect("proof_plan array");
    // std::lifecycle::transfer decomposes into consume + create proof plan records.
    let consume_plan = proof_plan
        .iter()
        .find(|plan| plan["feature"].as_str().is_some_and(|feature| feature.starts_with("consume-input:Token")))
        .expect("consume-input ProofPlan record");
    let create_plan = proof_plan
        .iter()
        .find(|plan| plan["feature"].as_str().is_some_and(|feature| feature.starts_with("create-output:Token")))
        .expect("create-output ProofPlan record");

    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["proof_plan_summary"]["record_count"].as_u64().unwrap(), proof_plan.len() as u64);
    assert!(summary["proof_plan_summary"]["macro_provenance_count"].as_u64().unwrap() > 0);
    assert_eq!(consume_plan["trigger"], "explicit_entry");
    assert_eq!(consume_plan["scope"], "transaction");
    assert_eq!(create_plan["trigger"], "explicit_entry");
    assert_eq!(create_plan["scope"], "transaction");
    assert!(consume_plan["reads"].as_array().unwrap().iter().any(|read| read == "input"));
    assert!(create_plan["reads"].as_array().unwrap().iter().any(|read| read == "output"));
    assert!(consume_plan["coverage"].as_array().unwrap().iter().any(|coverage| {
        coverage.as_str().is_some_and(|coverage| coverage.contains("transaction-scoped relation over explicit input/output views"))
    }));
    assert!(create_plan["coverage"].as_array().unwrap().iter().any(|coverage| {
        coverage.as_str().is_some_and(|coverage| coverage.contains("transaction-scoped relation over explicit input/output views"))
    }));
}

#[test]
fn cellc_explain_proof_human_reports_macro_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("token.cell");
    std::fs::write(
        &input,
        r#"
module test

resource Token has store, replace, relock, consume {
    amount: u64,
}

action transfer_token(token: Token, to: Address) -> next_token: Token {
    verification
        std::lifecycle::transfer(token, next_token, to) {
            amount
        }
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "proof"]).arg(&input).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Summary:"), "unexpected stdout: {}", stdout);
    assert!(stdout.contains("macro_provenance_records:"), "unexpected stdout: {}", stdout);
    assert!(stdout.contains("macro_provenance:"), "unexpected stdout: {}", stdout);
    // std::lifecycle::transfer decomposes; check for consume/create provenance instead of transfer.
    assert!(
        stdout.contains("macro_expansion:create=create-output") || stdout.contains("consume-input"),
        "unexpected stdout: {}",
        stdout
    );
}

#[test]
fn cellc_explain_proof_reports_declared_invariant() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("token.cell");
    std::fs::write(
        &input,
        r#"
module test

invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_conserved(Token.amount, scope = group)
    assert_invariant(true, "token amount is conserved")
}

resource Token {
    amount: u64,
}

action run() -> u64 {
    verification
        return 0
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "proof"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let proof_plan = summary["proof_plan"].as_array().expect("proof_plan array");
    let declared =
        proof_plan.iter().find(|plan| plan["origin"] == "invariant:token_conservation").expect("declared invariant ProofPlan record");

    assert_eq!(summary["status"], "ok");
    assert!(summary["proof_plan_summary"]["runtime_required_count"].as_u64().unwrap() > 0);
    assert!(summary["proof_plan_summary"]["metadata_only_gap_count"].as_u64().unwrap() > 0);
    assert_eq!(summary["proof_plan_summary"]["has_runtime_required_gaps"], true);
    assert_eq!(declared["category"], "declared-invariant");
    assert_eq!(declared["trigger"], "type_group");
    assert_eq!(declared["scope"], "group");
    assert_eq!(declared["codegen_coverage_status"], "gap:metadata-only");
    assert_eq!(declared["on_chain_checked"], false);
    assert!(declared["input_output_relation_checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check == "assert_conserved:Token.amount=metadata-only"));
}

#[test]
fn cellc_explain_proof_warns_for_lock_group_transaction_scope() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("token.cell");
    std::fs::write(
        &input,
        r#"
module test

invariant lock_scans_transaction {
    trigger: lock_group
    scope: transaction
    reads: inputs<Token>.amount, outputs<Token>.amount
    assert_sum(outputs<Token>.amount) <= assert_sum(inputs<Token>.amount)
}

resource Token {
    amount: u64,
}

action run() -> u64 {
    verification
        return 0
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "proof"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let proof_plan = summary["proof_plan"].as_array().expect("proof_plan array");
    let declared = proof_plan
        .iter()
        .find(|plan| plan["origin"] == "invariant:lock_scans_transaction")
        .expect("lock-group transaction invariant ProofPlan record");

    assert_eq!(declared["trigger"], "lock_group");
    assert_eq!(declared["scope"], "transaction");
    assert!(declared["coverage"].as_array().unwrap().iter().any(|coverage| {
        coverage.as_str().is_some_and(|coverage| coverage.contains("only inputs sharing this lock script trigger the verifier"))
    }));
    assert!(declared["diagnostics"].as_array().unwrap().iter().any(|diagnostic| {
        diagnostic["severity"] == "warning"
            && diagnostic["message"].as_str().is_some_and(|message| message.contains("do not imply type-group conservation"))
    }));
}

#[test]
fn cellc_explain_proof_summary_reports_fail_closed_diagnostics() {
    let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/language/ckb/witness_source.cell");

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).args(["explain", "proof"]).arg(&input).arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let proof_summary = &summary["proof_plan_summary"];
    assert!(proof_summary["fail_closed_count"].as_u64().unwrap() > 0, "unexpected summary: {}", summary);
    assert!(proof_summary["diagnostic_error_count"].as_u64().unwrap() > 0, "unexpected summary: {}", summary);
    assert_eq!(proof_summary["has_fail_closed_gaps"], true);
    assert_eq!(proof_summary["has_blocking_diagnostics"], true);
}

#[test]
fn cellc_check_denies_metadata_only_declared_invariant() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_invariant(true, "token amount is conserved")
}

resource Token {
    amount: u64,
}

action run() -> u64 {
    verification
        return 0
}
"#,
    )
    .unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--deny-runtime-obligations").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("runtime-required ProofPlan gaps"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("invariant:token_conservation"), "unexpected stderr: {}", stderr);
    assert!(stderr.contains("gap:metadata-only"), "unexpected stderr: {}", stderr);
}

#[test]
fn cellc_check_production_rejects_metadata_only_executable_claim() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

invariant enforce_token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_conserved(Token.amount, scope = group)
}

resource Token {
    amount: u64,
}

action run() -> u64 {
    verification
        return 0
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--production").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unresolved consensus ProofPlan enforcement"), "{stderr}");
    assert!(stderr.contains("gap:metadata-only"), "{stderr}");
    assert!(stderr.contains("invariant:enforce_token_conservation"), "{stderr}");
}

#[test]
fn cellc_clean_subcommand_supports_json_summary() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("target")).unwrap();
    std::fs::create_dir_all(root.join(".cell").join("cache")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("clean").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["removed"], 2);
    assert_eq!(summary["removed_paths"].as_array().unwrap().len(), 2);
    assert!(!root.join("target").exists());
    assert!(!root.join(".cell").join("cache").exists());
}

#[test]
fn cellc_info_subcommand_supports_json_summary() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
authors = ["Audit Bot"]
description = "demo package"
license = "MIT"
entry = "src/main.cell"

[dependencies]
math = "1"

[policy]
deny_fail_closed = true
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("info").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["manifest"], "Cell.toml");
    assert_eq!(summary["package"]["name"], "demo");
    assert_eq!(summary["package"]["authors"][0], "Audit Bot");
    assert_eq!(summary["dependencies"]["math"], "1");
    assert_eq!(summary["policy"]["deny_fail_closed"], true);
}

#[test]
fn cellc_add_and_remove_subcommands_honor_dev_path_and_json() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("math/src")).unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    std::fs::create_dir_all(root.join("shared")).unwrap();
    std::fs::write(root.join("src/main.cell"), "module demo;\n").unwrap();
    std::fs::write(
        root.join("math/Cell.toml"),
        "[package]\nedition = \"2026\"\nname = \"math\"\nversion = \"0.1.0\"\nentry = \"src/lib.cell\"\n",
    )
    .unwrap();
    std::fs::write(root.join("math/src/lib.cell"), "module math;\n").unwrap();

    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
entry = "src/main.cell"
source_roots = ["contracts", "shared"]

[build]
target = "riscv64-elf"
target_profile = "ckb"
out_dir = "artifacts"
"#,
    )
    .unwrap();

    let add_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("add")
        .arg("--dev")
        .arg("--path")
        .arg("math")
        .arg("--json")
        .arg("math")
        .output()
        .unwrap();
    assert!(
        add_output.status.success(),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&add_output.stdout),
        String::from_utf8_lossy(&add_output.stderr)
    );

    let add_summary: serde_json::Value = serde_json::from_slice(&add_output.stdout).unwrap();
    assert_eq!(add_summary["status"], "ok");
    assert_eq!(add_summary["target"], "dev-dependencies");
    assert_eq!(add_summary["added"][0], "math");
    assert_eq!(add_summary["dependency"]["path"], "math");

    let manifest: toml::Value = std::fs::read_to_string(root.join("Cell.toml")).unwrap().parse().unwrap();
    assert_eq!(manifest["package"]["source_roots"].as_array().unwrap().len(), 2);
    assert_eq!(manifest["build"]["target"].as_str().unwrap(), "riscv64-elf");
    assert_eq!(manifest["build"]["target_profile"].as_str().unwrap(), "ckb");
    assert_eq!(manifest["build"]["out_dir"].as_str().unwrap(), "artifacts");
    assert_eq!(manifest["dev_dependencies"]["math"]["path"].as_str().unwrap(), "math");
    assert!(manifest.get("dependencies").and_then(|value| value.get("math")).is_none());

    let remove_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("remove")
        .arg("--dev")
        .arg("--json")
        .arg("math")
        .output()
        .unwrap();
    assert!(remove_output.status.success(), "stderr: {}", String::from_utf8_lossy(&remove_output.stderr));

    let remove_summary: serde_json::Value = serde_json::from_slice(&remove_output.stdout).unwrap();
    assert_eq!(remove_summary["status"], "ok");
    assert_eq!(remove_summary["target"], "dev-dependencies");
    assert_eq!(remove_summary["removed"][0], "math");
    assert!(remove_summary["missing"].as_array().unwrap().is_empty());

    let manifest_after: toml::Value = std::fs::read_to_string(root.join("Cell.toml")).unwrap().parse().unwrap();
    assert_eq!(manifest_after["package"]["source_roots"].as_array().unwrap().len(), 2);
    assert_eq!(manifest_after["build"]["target"].as_str().unwrap(), "riscv64-elf");
    assert_eq!(manifest_after["build"]["target_profile"].as_str().unwrap(), "ckb");
    assert_eq!(manifest_after["build"]["out_dir"].as_str().unwrap(), "artifacts");
    assert!(manifest_after.get("dev_dependencies").and_then(|value| value.get("math")).is_none());
}

#[test]
fn cellc_install_path_updates_lockfile_and_remove_prunes_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let dep_root = root.join("math");
    let util_root = root.join("util");

    std::fs::create_dir_all(dep_root.join("src")).unwrap();
    std::fs::create_dir_all(util_root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.cell"), "module demo;\n").unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dep_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "math"
version = "0.2.0"
entry = "src/lib.cell"

[dependencies.util]
version = "0.1.0"
path = "../util"
"#,
    )
    .unwrap();
    std::fs::write(dep_root.join("src/lib.cell"), "module math;\n").unwrap();
    std::fs::write(
        util_root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "util"
version = "0.1.0"
entry = "src/lib.cell"
"#,
    )
    .unwrap();
    std::fs::write(util_root.join("src/lib.cell"), "module util;\n").unwrap();

    let install = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("install")
        .arg("math")
        .arg("--path")
        .arg("math")
        .output()
        .unwrap();
    assert!(install.status.success(), "stderr: {}", String::from_utf8_lossy(&install.stderr));

    let manifest: toml::Value = std::fs::read_to_string(root.join("Cell.toml")).unwrap().parse().unwrap();
    assert_eq!(manifest["dependencies"]["math"]["path"].as_str().unwrap(), "math");

    let lockfile: cellscript::package::Lockfile = toml::from_str(&std::fs::read_to_string(root.join("Cell.lock")).unwrap()).unwrap();
    let math_node = lockfile.root.dependencies.get("math").expect("math root edge should be locked");
    let locked = lockfile.dependencies.get(math_node).expect("math should be locked");
    assert_eq!(locked.version, "0.2.0");
    assert!(matches!(&locked.source, cellscript::package::LockedSource::Path { path } if path == "math"));
    let util_node = locked.dependencies.get("util").expect("math should have a util edge");
    let util = lockfile.dependencies.get(util_node).expect("transitive util should be locked");
    assert_eq!(util.version, "0.1.0");

    let update = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("update").output().unwrap();
    assert!(update.status.success(), "stderr: {}", String::from_utf8_lossy(&update.stderr));
    let update_stdout = String::from_utf8_lossy(&update.stdout);
    assert!(update_stdout.contains("Updated 2 dependency nodes"), "{update_stdout}");
    assert!(!update_stdout.contains("Warning: lockfile is not consistent"), "{update_stdout}");

    let remove = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("remove").arg("math").output().unwrap();
    assert!(remove.status.success(), "stderr: {}", String::from_utf8_lossy(&remove.stderr));

    let pruned: cellscript::package::Lockfile = toml::from_str(&std::fs::read_to_string(root.join("Cell.lock")).unwrap()).unwrap();
    assert!(pruned.root.dependencies.is_empty());
    assert!(pruned.dependencies.is_empty());
}

#[test]
fn cellc_build_uses_authoritative_lock_and_frozen_is_offline_and_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("math/src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies.math]
path = "math"
version = "^1.2.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src/main.cell"),
        r#"
module demo::main

action ping(value: u64) -> u64 {
    verification
        value
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("math/Cell.toml"),
        r#"
[package]
edition = "2026"
name = "math"
version = "1.2.3"
"#,
    )
    .unwrap();
    std::fs::write(root.join("math/src/lib.cell"), "module math;\n").unwrap();

    let missing = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("Cell.lock is missing"));

    let lock = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("lock").arg("--json").output().unwrap();
    assert!(lock.status.success(), "stderr: {}", String::from_utf8_lossy(&lock.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&lock.stdout).unwrap();
    assert_eq!(summary["schema"], cellscript::package::Lockfile::CURRENT_SCHEMA);
    assert_eq!(summary["dependency_nodes"], 1);

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--locked").output().unwrap();
    assert!(build.status.success(), "stderr: {}", String::from_utf8_lossy(&build.stderr));
    let before_frozen = std::fs::read(root.join("Cell.lock")).unwrap();
    let frozen =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--frozen").arg("--offline").output().unwrap();
    assert!(frozen.status.success(), "stderr: {}", String::from_utf8_lossy(&frozen.stderr));
    assert_eq!(std::fs::read(root.join("Cell.lock")).unwrap(), before_frozen);

    std::fs::write(root.join("math/src/lib.cell"), "module math;\n// source drift\n").unwrap();
    let drift = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--locked").output().unwrap();
    assert!(!drift.status.success());
    assert!(String::from_utf8_lossy(&drift.stderr).contains("source hash mismatch"));

    let update = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("update").output().unwrap();
    assert!(update.status.success(), "stderr: {}", String::from_utf8_lossy(&update.stderr));
    let rebuilt = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--locked").output().unwrap();
    assert!(rebuilt.status.success(), "stderr: {}", String::from_utf8_lossy(&rebuilt.stderr));
}

#[test]
fn bundled_scenario_basics_executes_positive_and_exact_negative_cases_on_both_backends() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/scenario_basics");
    let lock_before = std::fs::read(root.join("Cell.lock")).expect("scenario example must carry a tracked lockfile");

    let graph_only_verify =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(&root).args(["package", "verify", "--json"]).output().unwrap();
    assert!(!graph_only_verify.status.success());
    assert!(
        String::from_utf8_lossy(&graph_only_verify.stdout).contains("Cell.lock has no [package.build]")
            || String::from_utf8_lossy(&graph_only_verify.stderr).contains("Cell.lock has no [package.build]")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(&root)
        .args(["test", "--frozen", "--offline", "--backend", "all", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["scenario_files"], 2);
    assert_eq!(report["scenario_runs"], 4);
    let scenarios = report["scenarios"].as_array().expect("scenario reports");
    assert!(scenarios.iter().any(|row| {
        row["scenario"] == "bundled-positive-entry"
            && row["backend"] == "simulator"
            && row["evidence_tier"] == "development-non-consensus"
    }));
    assert!(scenarios.iter().any(|row| {
        row["scenario"] == "bundled-positive-entry" && row["backend"] == "ckb-vm" && row["evidence_tier"] == "authoritative-runtime"
    }));
    let exact_negative = scenarios.iter().filter(|row| row["scenario"] == "bundled-exact-runtime-error").collect::<Vec<_>>();
    assert_eq!(exact_negative.len(), 2, "exact-negative scenario should run once per backend");
    assert!(exact_negative.iter().all(|row| {
        row["steps"][0]["status"] == "expected-runtime-error"
            && row["steps"][0]["runtime_error"]["code"] == 5
            && row["steps"][0]["runtime_error"]["name"] == "assertion-failed"
    }));

    let build = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(&root)
        .args(["build", "--frozen", "--offline", "--json"])
        .output()
        .unwrap();
    assert!(build.status.success(), "stderr: {}", String::from_utf8_lossy(&build.stderr));
    for file in ["main.elf", "main.elf.meta.json", "main.elf.lowering.json", "main.elf.sourcemap.json"] {
        assert!(root.join("build").join(file).is_file(), "verified-artifact example should emit {file}");
    }
    let verify = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(&root)
        .args(["verify-artifact", "build/main.elf", "--verify-sources", "--json"])
        .output()
        .unwrap();
    assert!(verify.status.success(), "stderr: {}", String::from_utf8_lossy(&verify.stderr));
    let verify_report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_report["status"], "ok");
    assert_eq!(verify_report["structural_verification"], "verified");
    assert_eq!(verify_report["sources_verified"], true);
    std::fs::remove_dir_all(root.join("build")).expect("remove generated bundled-example artifacts");

    assert_eq!(
        std::fs::read(root.join("Cell.lock")).unwrap(),
        lock_before,
        "frozen scenario execution must not rewrite the tracked graph"
    );
}

#[test]
fn bundled_package_graph_exercises_alias_features_test_scope_and_ckb_environments() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/package_graph");
    let manifest = std::fs::read_to_string(root.join("Cell.toml")).expect("package graph manifest");
    for needle in [
        "package = \"canonical_math\"",
        "version = \"^1.2.0\"",
        "optional = true",
        "[dev_dependencies.test_support]",
        "auditing = [\"dep:audit\"]",
        "full = [\"auditing\"]",
        "[environments.mainnet]",
        "[environments.testnet]",
        "[dependency_overrides.testnet.contracts]",
    ] {
        assert!(manifest.contains(needle), "package graph example should contain `{needle}`");
    }

    let lock_before = std::fs::read(root.join("Cell.lock")).expect("package graph example must carry a tracked lockfile");
    let lock_text = String::from_utf8(lock_before.clone()).unwrap();
    for needle in [
        "schema = \"cellscript-lock-v0.24-graph-v1\"",
        "[environments.mainnet.dependencies]",
        "[environments.mainnet.dev_dependencies]",
        "[environments.testnet.dependencies]",
        "[environments.testnet.dev_dependencies]",
        "network_contracts@1.0.0|path:deps/contracts-mainnet|env=environment-independent:root=6d61696e6e6574",
        "network_contracts@2.0.0|path:deps/contracts-testnet|env=environment-independent:root=746573746e6574",
        "chain=636b622d6d61696e6e6574:genesis=0x1111111111111111111111111111111111111111111111111111111111111111",
        "chain=636b622d746573746e6574:genesis=0x2222222222222222222222222222222222222222222222222222222222222222",
    ] {
        assert!(lock_text.contains(needle), "package graph lock should contain `{needle}`");
    }

    let missing_environment =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(&root).args(["check", "--frozen", "--offline"]).output().unwrap();
    assert!(!missing_environment.status.success());
    assert!(String::from_utf8_lossy(&missing_environment.stderr).contains("--environment"));

    for args in [
        vec!["check", "--frozen", "--offline", "--environment", "mainnet"],
        vec!["check", "--frozen", "--offline", "--environment", "testnet", "--features", "full"],
        vec!["test", "--no-run", "--frozen", "--offline", "--environment", "testnet", "--all-features"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(&root).args(&args).output().unwrap();
        assert!(output.status.success(), "cellc {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr));
    }
    assert_eq!(
        std::fs::read(root.join("Cell.lock")).unwrap(),
        lock_before,
        "frozen package-graph commands must not rewrite the tracked graph"
    );
}

#[test]
fn cellc_metadata_subcommand_emits_lowering_runtime_json() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

shared Config {
    threshold: u64
}

resource Token has store, replace, relock, consume, burn {
    amount: u64
}

action update(amount: u64) -> u64 {
    verification
        let cfg = read_ref<Config>()
        let token = create Token { amount: amount }
        consume token
        return cfg.threshold
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("metadata").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"lowering\""));
    assert!(stdout.contains("\"runtime\""));
    assert!(stdout.contains("\"fail_closed_runtime_features\""));
    assert!(stdout.contains("\"verifier_obligations\""));
    assert!(stdout.contains("\"source\": \"Input\""));
    assert!(stdout.contains("\"source\": \"CellDep\""));
    assert!(stdout.contains("\"source\": \"Output\""));
    assert!(stdout.contains("\"elf_compatible\": true"));
    assert!(stdout.contains("\"ckb_runtime_required\": true"));
    assert!(stdout.contains("read-cell-dep"));
    assert!(stdout.contains("verify-output-cell"));
    assert!(!stdout.contains("schema-field-access"));
}

#[test]
fn cellc_metadata_reports_multiple_compile_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action bad() -> bool {
    verification
        let first: u64 = true
        let second: bool = 1
        return true
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("metadata").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("2 diagnostics"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("expected U64, found Bool"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("expected Bool, found U64"), "unexpected stderr: {stderr}");
}

#[test]
fn cellc_expand_uses_the_manifest_edition_and_emits_the_semantic_foundation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "semantic-preview"
version = "0.1.0"
"#,
    )
    .unwrap();
    let source_path = root.join("src").join("main.cell");
    std::fs::write(
        &source_path,
        r#"
module semantic_preview

action main(witness value: u64) -> u64 {
    verification
        return value
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "expand"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let foundation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(foundation["schema"], "cellscript-semantic-foundation-v3");
    assert_eq!(foundation["entry_contract"]["dispatch"]["kind"], "single-entry");
    assert!(foundation["identities"]["core_semantic_id"].as_str().is_some_and(|id| !id.is_empty()));

    std::fs::write(
        source_path,
        r#"
module semantic_preview

action main(value: u64) -> u64 {
    return value
}
"#,
    )
    .unwrap();
    let authoring = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "expand"]).output().unwrap();
    assert!(authoring.status.success(), "stderr: {}", String::from_utf8_lossy(&authoring.stderr));
    let authoring_foundation: serde_json::Value = serde_json::from_slice(&authoring.stdout).unwrap();
    assert_eq!(authoring_foundation["entry_contract"]["dispatch"]["kind"], "single-entry");
    assert_eq!(authoring_foundation["identities"]["core_semantic_id"], foundation["identities"]["core_semantic_id"]);
}

#[test]
fn cellc_expand_compiles_native_edition_2027_type_script_surface() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "native-semantic-preview"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module native_semantic_preview

resource Token has store, replace, relock {
    owner: Address,
    amount: u64,
}

type_script TokenTransfer on type_group<Token> {
    entry transfer(
        input token: Token from group_input[0],
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify {
            enforce token.amount > 0
        }

        effects {
            replace token -> next {
                data {
                    owner = same
                    amount = same
                }
                identity = same
                type_script = same
                lock_script = exact_hash(recipient)
                capacity = same
                cardinality = one_to_one
            }
        }
    }
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "expand"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let foundation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(foundation["entry_contract"]["trigger"], "type-group<Token>");
    assert_eq!(foundation["entry_contract"]["exact_entry"], "action:transfer");
    assert_eq!(foundation["dispositions"][0]["input"]["kind"], "successor");
    assert_eq!(foundation["dispositions"][0]["envelope"]["completeness"], "exhaustive");
    let enforced = foundation["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["category"] == "entry-condition")
        .expect("native enforce must emit an executable semantic claim");
    assert_eq!(enforced["statement"], "require token.amount > 0");
    assert_eq!(enforced["enforcement"], "checked-runtime");
    assert_eq!(enforced["on_chain_checked"], true);
    assert_eq!(enforced["evidence_reference"], "typed-entry:action:transfer:block:0:branch-condition");
    assert!(enforced["execution"]["condition_node_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert_eq!(enforced["execution"]["failure_error_code"], 5);

    let format = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("fmt").output().unwrap();
    assert!(format.status.success(), "stderr: {}", String::from_utf8_lossy(&format.stderr));
    let checked = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["fmt", "--check"]).output().unwrap();
    assert!(checked.status.success(), "stderr: {}", String::from_utf8_lossy(&checked.stderr));
}

#[test]
fn cellc_expand_reports_native_pool_and_metadata_only_audit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cell.toml"), "[package]\nedition = \"2027\"\nname = \"native-pool-preview\"\nversion = \"0.1.0\"\n")
        .unwrap();
    std::fs::write(
        root.join("src/main.cell"),
        r#"
module native_pool_preview
resource Token has store, create, consume { owner: Address, amount: u64 }
type_script TokenPool on type_group<Token> {
    entry merge(
        input left: Token from group_input[0],
        input right: Token from group_input[1],
        witness recipient: Address from group_witness.input_type,
        output merged: Token from group_output[0],
    ) {
        verify { enforce left.amount > 0 }
        audit settlement_policy { expected_evidence = external_policy(recipient) }
        effects {
            pool value_flow {
                inputs { left, right }
                outputs { merged }
                data { owner { merged = recipient } amount = conserve }
                identity = pooled
                type_script = same
                lock_script { merged = exact_hash(recipient) }
                capacity = builder_computed
                cardinality = declared
            }
        }
    }
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "expand"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let foundation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        foundation["dispositions"].as_array().unwrap().iter().filter(|disposition| disposition["input"]["kind"] == "pooled").count(),
        2
    );
    assert!(foundation["dispositions"].as_array().unwrap().iter().any(|disposition| disposition["output"]["kind"] == "pool-result"));
    let audit = foundation["claims"].as_array().unwrap().iter().find(|claim| claim["category"] == "audit").expect("audit claim");
    assert_eq!(audit["enforcement"], "metadata-only");
    assert_eq!(audit["on_chain_checked"], false);
    assert!(audit["execution"].is_null());
}

#[test]
fn cellc_expand_compiles_native_edition_2027_lock_script_surface() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "native-lock-preview"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module native_lock_preview

resource Vault has store {
    owner: Address,
}

lock_script VaultOwner on lock_group {
    entry unlock(
        protected vault: Vault from group_input[0],
        lock_args owner: Address from current_script.args,
        witness claimed_owner: Address from group_witness.input_type,
    ) {
        verify {
            enforce vault.owner == owner
            enforce claimed_owner == owner
        }
    }
}
"#,
    )
    .unwrap();

    let parsed = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "--parse"]).output().unwrap();
    assert!(parsed.status.success(), "stderr: {}", String::from_utf8_lossy(&parsed.stderr));

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "expand"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let foundation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(foundation["entry_contract"]["script_role"], "lock");
    assert_eq!(foundation["entry_contract"]["trigger"], "lock-group");
    assert_eq!(foundation["entry_contract"]["exact_entry"], "lock:unlock");
    assert_eq!(foundation["dispositions"][0]["input"]["kind"], "authorization-only");
    assert_eq!(foundation["dispositions"][0]["input"]["disposition_owner"], "type-script-or-explicit-transaction-policy");
    let enforced =
        foundation["claims"].as_array().unwrap().iter().filter(|claim| claim["category"] == "entry-condition").collect::<Vec<_>>();
    assert_eq!(enforced.len(), 2);
    assert_eq!(enforced[0]["statement"], "require vault.owner == owner");
    assert_eq!(enforced[1]["statement"], "require claimed_owner == owner");
    assert!(enforced.iter().all(|claim| claim["execution"]["failure_error_code"] == 5));

    let format = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("fmt").output().unwrap();
    assert!(format.status.success(), "stderr: {}", String::from_utf8_lossy(&format.stderr));
    let checked = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["fmt", "--check"]).output().unwrap();
    assert!(checked.status.success(), "stderr: {}", String::from_utf8_lossy(&checked.stderr));
}

#[test]
fn cellc_migrate_emits_only_a_differentially_verified_edition_2027_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "migration-preview"
version = "0.1.0"
"#,
    )
    .unwrap();
    let source = r#"module migration_preview

resource Token has store, replace, relock {
    owner: Address,
    amount: u64,
}

action transfer(input token: Token, witness recipient: Address) -> next: Token {
    verification
        require token.amount > 0
        std::lifecycle::transfer(token, next, recipient) { owner amount }
        std::cell::preserve_capacity(next, token)
}
"#;
    let source_path = root.join("src").join("main.cell");
    std::fs::write(&source_path, source).unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["--json", "migrate", ".", "--to", "2027"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "cellscript-source-migration-preview-v1");
    assert_eq!(report["kind"], "type-script");
    assert_eq!(report["artifact_byte_identical"], true);
    assert_eq!(report["source_edition"], "2026");
    assert_eq!(report["target_edition"], "2027");
    assert!(report["source"].as_str().unwrap().contains("action transfer("));
    assert!(!report["source"].as_str().unwrap().contains("type_script"));
    assert_eq!(std::fs::read_to_string(&source_path).unwrap(), source);

    let candidate_path = root.join("candidate.cell");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .args(["migrate", ".", "--output", candidate_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(std::fs::read_to_string(&candidate_path).unwrap().contains("require token.amount > 0"));

    std::fs::write(&source_path, source.replace("require token.amount > 0", "require token.amount > 0, \"positive\"")).unwrap();
    let rejected_path = root.join("rejected.cell");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .args(["migrate", ".", "--output", rejected_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no accepted custom-message mapping"));
    assert!(!rejected_path.exists());
}

#[test]
fn cellc_explain_generics_reports_checked_vec_instantiations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action address_helpers(owner: Address, candidate: Address) -> bool {
    verification
        let mut owners = Vec::with_capacity(2)
        owners.push(owner)
        owners.insert(0, candidate)
        owners.swap(0, 1)
        let removed = owners.remove(1)
        owners.push(removed)
        owners.truncate(1)
        owners.set(0, owner)

        if owners.contains(owner) {
            return owners.first() == owner
        }

        false

}
action hash_helpers(first: Hash, second: Hash) -> bool {
    verification
        let mut keys = Vec::new()
        keys.push(first)
        keys.push(second)
        let popped = keys.pop()
        keys.push(popped)
        keys.swap(0, 1)
        keys.reverse()

        if keys.first() == first {
            return keys.last() == second
        }

        false
}
"#,
    )
    .unwrap();

    let json_output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["explain", "generics", "--json"]).output().unwrap();
    assert!(json_output.status.success(), "stderr: {}", String::from_utf8_lossy(&json_output.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert!(summary["count"].as_u64().unwrap() >= 2);
    let instantiations = summary["collection_instantiations"].as_array().unwrap();

    let address = instantiations
        .iter()
        .find(|instantiation| instantiation["collection_ty"] == "Vec<Address>")
        .expect("Vec<Address> instantiation should be explained");
    assert_eq!(address["scope_kind"], "action");
    assert_eq!(address["scope_name"], "address_helpers");
    assert_eq!(address["element_ty"], "Address");
    assert_eq!(address["element_width_bytes"], 32);
    assert_eq!(address["max_elements"], 8);
    assert_eq!(address["backing"], "stack-fixed-buffer:256");
    assert_eq!(address["status"], "checked-runtime");
    let address_helpers = address["helpers"].as_array().unwrap();
    for helper in ["contains", "index", "insert", "push", "remove", "set", "swap", "truncate", "with_capacity"] {
        assert!(
            address_helpers.iter().any(|value| value.as_str() == Some(helper)),
            "missing Address helper {helper}: {address_helpers:?}"
        );
    }
    assert!(
        !address_helpers.iter().any(|value| value.as_str() == Some("new")),
        "Vec<Address> was constructed with Vec::with_capacity, not Vec::new: {address_helpers:?}"
    );

    let hash = instantiations
        .iter()
        .find(|instantiation| instantiation["collection_ty"] == "Vec<Hash>")
        .expect("Vec<Hash> instantiation should be explained");
    assert_eq!(hash["scope_kind"], "action");
    assert_eq!(hash["scope_name"], "hash_helpers");
    assert_eq!(hash["element_ty"], "Hash");
    assert_eq!(hash["element_width_bytes"], 32);
    assert_eq!(hash["max_elements"], 8);
    assert_eq!(hash["backing"], "stack-fixed-buffer:256");
    assert_eq!(hash["status"], "checked-runtime");
    let hash_helpers = hash["helpers"].as_array().unwrap();
    for helper in ["index", "new", "pop", "push", "reverse", "swap"] {
        assert!(hash_helpers.iter().any(|value| value.as_str() == Some(helper)), "missing Hash helper {helper}: {hash_helpers:?}");
    }

    let text_output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["explain", "generics"]).output().unwrap();
    assert!(text_output.status.success(), "stderr: {}", String::from_utf8_lossy(&text_output.stderr));
    let stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(stdout.contains("Checked bounded generic collection instantiations"), "{}", stdout);
    assert!(stdout.contains("Vec<Address> -> Address"), "{}", stdout);
    assert!(stdout.contains("Vec<Hash> -> Hash"), "{}", stdout);
    assert!(stdout.contains("with_capacity"), "{}", stdout);
}

#[test]
fn cellc_action_build_emits_builder_plan_json() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let parse = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("--json")
        .arg("--parse")
        .arg("src/main.cell")
        .output()
        .unwrap();
    assert!(parse.status.success(), "stderr: {}", String::from_utf8_lossy(&parse.stderr));
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&parse.stdout).unwrap()["status"], "ok");

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("action")
        .arg("build")
        .arg("--action")
        .arg("mint")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["status"], "ok");
    assert_eq!(plan["policy"], "cellscript-action-builder-plan-v1");
    assert_eq!(plan["headless"], true);
    assert_eq!(plan["ui_scope"], "none");
    assert_eq!(plan["action"], "mint");
    assert_eq!(plan["target_profile"], "ckb");
    assert!(plan["entry_witness_abi"]["required"].as_bool().unwrap());
    assert_eq!(plan["builder_requirements"]["created_outputs"].as_array().unwrap().len(), 1);
    assert_eq!(plan["builder_requirements"]["action_scan_selectors"], plan["action_scan_selectors"]);
    let scan_selectors = &plan["action_scan_selectors"];
    assert_eq!(scan_selectors["schema"], "cellscript-action-scan-selectors-v0.21");
    assert_eq!(scan_selectors["source"], "transaction_runtime_input_requirements");
    assert_eq!(scan_selectors["evidence_level"], "compile-only");
    assert_eq!(scan_selectors["status"], "compile-checked-runtime-selectors");
    assert_eq!(scan_selectors["runtime_required_selector_count"], 0);
    assert!(scan_selectors["selector_count"].as_u64().is_some_and(|count| count >= 1));
    assert!(scan_selectors["non_claims"].as_array().is_some_and(|items| items.iter().any(|item| item == "does-not-query-live-cells")));
    let create_selector = scan_selectors["selectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|selector| selector["feature"].as_str().is_some_and(|feature| feature.starts_with("create-output:Token")))
        .expect("create-output selector");
    assert_eq!(create_selector["ckb_source"], "Output");
    assert_eq!(create_selector["role"], "transaction-output");
    assert_eq!(create_selector["selector"]["kind"], "output-cell-selector");
    assert_eq!(create_selector["selector"]["source"], "Output");
    assert_eq!(create_selector["requirement_status"], "checked-runtime");
    assert_eq!(create_selector["scan_status"], "verifier-covered");
    assert_eq!(create_selector["resolution"]["adapter_action"], "materialize-and-preserve-verifier-covered-shape");
    assert!(plan["ckb"]["capacity_evidence_contract"]["required"].as_bool().unwrap());
    assert_eq!(plan["transaction_draft"]["format"], "cellscript-ccc-transaction-draft-v1");
    assert_eq!(plan["transaction_draft"]["state"], "ActionPlan");
    assert_eq!(plan["transaction_draft"]["ccc_compatible"], true);
    assert_eq!(plan["transaction_draft"]["can_submit"], false);
    assert_eq!(plan["transaction_draft"]["ckb_vm_execution"], false);
    assert_eq!(plan["transaction_draft"]["tx_pool_acceptance"], false);
    assert_eq!(plan["transaction_draft"]["requires_live_cell_resolution"], true);
    assert_eq!(plan["transaction_draft"]["requires_packed_materialization"], true);
    assert_eq!(plan["transaction_draft"]["packed_materialization"]["transaction"], "ckb_types::packed::Transaction");
    assert_eq!(plan["transaction_draft"]["packed_materialization"]["script"], "ckb_types::packed::Script");
    assert_eq!(plan["transaction_draft"]["packed_materialization"]["out_point"], "ckb_types::packed::OutPoint");
    assert_eq!(plan["transaction_draft"]["packed_materialization"]["realizer"], "cellscript-ckb-adapter via ckb-sdk-rust or CCC");
    assert!(plan["transaction_draft"]["required_evidence"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == "tx_pool_acceptance")));
    assert_eq!(plan["adapter_contract"]["schema"], "cellscript-ckb-adapter-contract-v0.19");
    assert_eq!(plan["adapter_contract"]["compiler_core_dependency"], "no-ckb-sdk-rust");
    assert_eq!(plan["adapter_contract"]["compiler_output_state"], "ActionPlan");
    assert_eq!(plan["adapter_contract"]["adapter_output_state"], "ResolvedActionTx");
    assert_eq!(plan["adapter_contract"]["accepted_output_state"], "AcceptedActionTx");
    assert_eq!(plan["adapter_contract"]["must_not_infer_protocol_semantics_from_action_name"], true);
    assert_eq!(plan["adapter_contract"]["witness_policy"]["entry_payload_abi"], "cellscript-entry-witness-v1");
    assert_eq!(plan["adapter_contract"]["witness_policy"]["placement_abi"], "cellscript-witnessargs-input-type-v2");
    assert_eq!(plan["adapter_contract"]["witness_policy"]["default_action_payload_field"], "input_type");
    assert_eq!(plan["adapter_contract"]["witness_policy"]["runtime_source"], "group-input-0-then-group-output-0");
    assert_eq!(plan["adapter_contract"]["witness_policy"]["raw_v1_compatible"], false);
    assert_eq!(plan["adapter_contract"]["witness_policy"]["lock_signature_policy"], "explicit-adapter-owned-do-not-overwrite");
    assert!(plan["adapter_contract"]["resolved_tx_required_fields"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == "outputs_data") && items.iter().any(|item| item == "lineage")));
    assert_eq!(plan["adapter_contract"]["acceptance_report_template"]["schema"], "cellscript-ckb-action-acceptance-report-v0.19");
    assert_eq!(plan["adapter_contract"]["acceptance_report_template"]["state"], "AcceptedActionTx");
    assert_eq!(plan["adapter_contract"]["acceptance_report_template"]["action_selector"], "mint");
    assert!(plan["adapter_contract"]["acceptance_report_template"]["metadata_hash"].as_str().is_some_and(|hash| hash.len() == 64));
    assert!(plan["adapter_contract"]["acceptance_report_template"]["known_limitations"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str().is_some_and(|text| text.contains("Template only")))));
    assert_eq!(plan["preview"]["format"], "cellscript-action-preview-v1");
    assert_eq!(plan["preview"]["action"], "mint");
    assert!(plan["preview"]["warnings"].as_array().is_some_and(|warnings| !warnings.is_empty()));
}

#[test]
fn cellc_action_build_emits_runtime_required_scan_selectors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store {
    amount: u64,
}

action withdraw(token: Token, fee: u64) -> Token {
    verification
        let amount = token.amount
        let remaining = amount - fee
        consume token
        let out = create Token {
            amount: remaining
        }
        return out
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("action")
        .arg("build")
        .arg("--action")
        .arg("withdraw")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let scan_selectors = &plan["action_scan_selectors"];
    assert_eq!(scan_selectors["schema"], "cellscript-action-scan-selectors-v0.21");
    assert_eq!(scan_selectors["status"], "requires-runtime-resolution");
    assert_eq!(scan_selectors["runtime_required_selector_count"], 1);
    let selector = scan_selectors["selectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|selector| selector["feature"] == "resource-conservation:Token")
        .expect("Token resource-conservation selector");
    assert_eq!(selector["requirement_status"], "runtime-required");
    assert_eq!(selector["scan_status"], "requires-runtime-resolution");
    assert_eq!(selector["ckb_source"], "Transaction");
    assert_eq!(selector["selector"]["kind"], "transaction-selector");
    assert_eq!(selector["resolution"]["blocker_class"], "resource-conservation-proof-gap");
    assert_eq!(selector["resolution"]["adapter_action"], "resolve-or-reject-before-signing");
}

#[test]
fn cellc_action_build_emits_cellfabric_intent_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("action")
        .arg("build")
        .arg("--action")
        .arg("mint")
        .arg("--fabric-intent")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "cellscript-cellfabric-intent-envelope-v0.20");
    assert_eq!(envelope["status"], "requires-runtime-binding");
    assert_eq!(envelope["bridge_boundary"]["kind"], "json-bridge");
    assert_eq!(envelope["bridge_boundary"]["cellscript_core_dependency"], "no-cell-fabric-rust-crate");
    assert_eq!(envelope["bridge_boundary"]["not_a_cellfabric_signed_intent"], true);
    assert_eq!(envelope["bridge_boundary"]["not_a_soft_confirmation"], true);
    assert_eq!(envelope["bridge_boundary"]["not_l1_finality"], true);

    let action_plan_hash = envelope["source"]["action_plan_hash"].as_str().expect("action plan hash");
    assert_eq!(action_plan_hash.len(), 64);
    assert_eq!(envelope["source"]["action"], "mint");
    assert_eq!(envelope["source"]["target_profile"], "ckb");
    assert_eq!(envelope["cellfabric_mapping"]["candidate_intent_action"], "App");
    assert_eq!(envelope["cellfabric_intent_template"]["domain"]["chain_id"], "ckb");
    assert_eq!(envelope["cellfabric_intent_template"]["action"]["kind"], "App");
    assert_eq!(envelope["cellfabric_intent_template"]["action"]["action"], "mint");
    assert_eq!(envelope["cellfabric_intent_template"]["action"]["payload_format"], "cellscript-action-plan-json-v1");
    assert_eq!(envelope["cellfabric_intent_template"]["action"]["payload_hash"], action_plan_hash);
    assert_eq!(envelope["cellfabric_intent_template"]["resources"]["status"], "template-only-runtime-outpoints-required");
    assert_eq!(envelope["cellfabric_intent_template"]["author"]["lock_script_hash"], serde_json::Value::Null);
    assert_eq!(envelope["cellfabric_intent_template"]["auth_mode"], "CoSignConcreteTx");
    assert!(envelope["resource_access_template"]["hard_conflicts"]["runtime_input_requirements"].as_array().is_some());
    assert!(envelope["resource_access_template"]["app_conflict_key_templates"].as_array().is_some());
    assert!(envelope["required_runtime_evidence"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == "resolved_consumed_outpoints")
            && items.iter().any(|item| item == "l1_status_observation")));
    assert!(envelope["non_claims"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str().is_some_and(|text| text.contains("does not soft-confirm")))));
    assert_eq!(envelope["action_plan"]["policy"], "cellscript-action-builder-plan-v1");
    assert_eq!(envelope["action_plan"]["transaction_draft"]["state"], "ActionPlan");
}

/// Source declaring an xUDT group-amount-conservation invariant, with the
/// action calling the matching `xudt::require_group_amount_conserved()` helper
/// so the invariant lowers to a checked runtime helper.
fn xudt_conserved_source_with_runtime_helper() -> &'static str {
    r#"
module demo::main

resource Token has store, create, consume {
    amount: u128,
}

invariant xudt_group_transfer_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_sum(group_outputs<Token>.amount) == assert_sum(group_inputs<Token>.amount)
}

action transfer(input: Token) -> output: Token {
    verification
        xudt::require_group_amount_conserved()
        preserve output from input {
            amount
        }
}
"#
}

/// Source declaring the same invariant but without the action-side helper call, so
/// the aggregate is recognised as runtime-helper-backed but not yet discharged.
fn xudt_conserved_source_without_helper_call() -> &'static str {
    r#"
module demo::main

resource Token has store, create, consume {
    amount: u128,
}

invariant xudt_group_transfer_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_sum(group_outputs<Token>.amount) == assert_sum(group_inputs<Token>.amount)
}

action transfer(input: Token) -> output: Token {
    verification
        preserve output from input {
            amount
        }
}
"#
}

fn write_xudt_package(root: &std::path::Path, source: &str) {
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(root.join("src").join("main.cell"), source).unwrap();
}

#[test]
fn cellc_check_xudt_group_amount_conserved_lowers_to_runtime_helper() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_xudt_package(root, xudt_conserved_source_with_runtime_helper());

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let metadata: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("build").join("main.s.meta.json")).unwrap()).unwrap();
    let proof_plan = metadata["runtime"]["proof_plan"].as_array().expect("proof_plan array");
    let aggregate =
        proof_plan.iter().find(|plan| plan["category"] == "aggregate-invariant").expect("aggregate-invariant ProofPlan record");

    assert_eq!(aggregate["status"], "checked-runtime", "unexpected metadata: {:?}", aggregate);
    assert_eq!(aggregate["evidence_tier"], "checked-runtime", "unexpected metadata: {:?}", aggregate);
    assert_eq!(aggregate["codegen_coverage_status"], "covered", "unexpected metadata: {:?}", aggregate);
    assert_eq!(aggregate["on_chain_checked"], true);
    assert!(
        aggregate["builder_assumptions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assumption| assumption == "declared(runtime-helper-checked:xudt::require_group_amount_conserved)"),
        "missing checked helper assumption: {:?}",
        aggregate["builder_assumptions"]
    );

    let runtime_accesses = metadata["runtime"]["ckb_runtime_accesses"].as_array().expect("ckb_runtime_accesses array");
    assert!(
        runtime_accesses.iter().any(|access| {
            access["operation"] == "xudt-group-amount-conservation" && access["binding"] == "xudt::require_group_amount_conserved"
        }),
        "missing xudt conserved runtime access: {:?}",
        runtime_accesses
    );
}

#[test]
fn cellc_check_xudt_conserved_runtime_helper_required_gap_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_xudt_package(root, xudt_conserved_source_without_helper_call());

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let metadata: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("build").join("main.s.meta.json")).unwrap()).unwrap();
    let proof_plan = metadata["runtime"]["proof_plan"].as_array().expect("proof_plan array");
    let aggregate =
        proof_plan.iter().find(|plan| plan["category"] == "aggregate-invariant").expect("aggregate-invariant ProofPlan record");

    // The invariant is recognised as runtime-helper-backed but the action does not
    // call the helper, so it must surface as a runtime-helper-required gap, not as
    // checked or as a pure metadata-only gap.
    assert_eq!(aggregate["status"], "runtime-required", "unexpected metadata: {:?}", aggregate);
    assert_eq!(aggregate["codegen_coverage_status"], "gap:runtime-helper-required", "unexpected metadata: {:?}", aggregate);
    assert_eq!(aggregate["on_chain_checked"], false);
    assert!(
        aggregate["builder_assumptions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assumption| assumption == "declared(runtime-helper-required:xudt::require_group_amount_conserved)"),
        "missing required helper assumption: {:?}",
        aggregate["builder_assumptions"]
    );
}

#[test]
fn cellc_check_primitive_strict_017_rejects_stale_xudt_helper_gap() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_xudt_package(root, xudt_conserved_source_without_helper_call());

    // The invariant is runtime-helper-required; strict 0.17 mode must fail closed
    // because the matching runtime access is missing from generated code.
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("build")
        .arg("--primitive-strict")
        .arg("0.17")
        .output()
        .unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("0.17 CKB source strict check failed"), "unexpected stderr: {stderr}");
    assert!(stderr.contains("PP0170"), "unexpected stderr: {stderr}");
    assert!(
        stderr.contains("0.17 strict mode requires matching runtime-helper-required:xudt::require_group_amount_conserved coverage"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cellc_explain_proof_plan_distinguishes_three_coverage_states() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_xudt_package(root, xudt_conserved_source_with_runtime_helper());

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["explain", "proof"]).arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let proof_plan = summary["proof_plan"].as_array().expect("proof_plan array");
    let aggregate =
        proof_plan.iter().find(|plan| plan["category"] == "aggregate-invariant").expect("aggregate-invariant ProofPlan record");

    // The same builder-assumption label surface must expose the checked-runtime
    // state distinctly from the runtime-required and metadata-only labels used by
    // the other two coverage branches.
    assert_eq!(aggregate["status"], "checked-runtime", "unexpected metadata: {:?}", aggregate);
    assert_eq!(aggregate["codegen_coverage_status"], "covered", "unexpected metadata: {:?}", aggregate);
    let assumptions = aggregate["builder_assumptions"].as_array().unwrap();
    assert!(
        assumptions.iter().any(|assumption| {
            let text = assumption.as_str().unwrap_or("");
            text.contains("runtime-helper-checked:xudt::require_group_amount_conserved")
        }),
        "expected checked helper label in assumptions: {assumptions:?}"
    );
    // The three label prefixes must be the canonical, distinguishable strings that
    // metadata consumers (registry, audit bundles) key off.
    let label = |prefix: &str| assumptions.iter().any(|assumption| assumption.as_str().is_some_and(|text| text.starts_with(prefix)));
    assert!(label("declared(runtime-helper-checked:"));
    // The other two branches use these prefixes; they must not collide with checked.
    let all_assumption_text = assumptions.iter().map(|assumption| assumption.as_str().unwrap_or("")).collect::<Vec<_>>().join("\n");
    assert!(!all_assumption_text.contains("declared(runtime-helper-required:"));
    assert!(!all_assumption_text.contains("declared(metadata-only invariant"));
}

fn atomic_swap_inline_source() -> &'static str {
    r#"
module demo::atomic_swap

resource SwapLock has store, create, consume, replace, burn, read_ref {
    swap_id: Hash,
    initiator: Address,
    participant: Address,
    hashlock: Hash,
    timeout_timepoint: u64,
    asset_type: AssetType,
    amount: u64,
    state: u8,
}

receipt PreimageClaim has create, consume, burn {
    swap_id: Hash,
    preimage: Hash,
    claimed_by: Address,
    claimed_at: u64,
}

enum AssetType {
    Native,
    Token(Hash),
}

flow SwapLock.state {
    initial Pending;
    terminal Claimed, Refunded;

    Pending -> Claimed;
    Pending -> Refunded;
}

action initiate_swap(swap_id: Hash, initiator: Address, participant: Address, hashlock: Hash, timeout_timepoint: u64, asset_type: AssetType, amount: u64) -> swap_lock: SwapLock {
    verification
        require amount > 0, "zero amount"
        require timeout_timepoint > 0, "zero timeout"
        create swap_lock = SwapLock { swap_id, initiator, participant, hashlock, timeout_timepoint, asset_type, amount, state: Pending } with_lock(initiator)

}

action claim_with_preimage(lock: SwapLock, preimage: Hash, claimed_by: Address, current_timepoint: u64) -> (claim: PreimageClaim, updated_lock: SwapLock) {
    transition lock.state: Pending -> updated_lock.state: Claimed
    verification
        require claimed_by == lock.participant, "not the participant"
        require current_timepoint < lock.timeout_timepoint, "claim window expired"
        require hash_blake2b(preimage) == lock.hashlock, "wrong preimage"
        consume lock
        create claim = PreimageClaim { swap_id: lock.swap_id, preimage, claimed_by, claimed_at: current_timepoint }
        create updated_lock = SwapLock { swap_id: lock.swap_id, initiator: lock.initiator, participant: lock.participant, hashlock: lock.hashlock, timeout_timepoint: lock.timeout_timepoint, asset_type: lock.asset_type, amount: lock.amount, state: Claimed } with_lock(lock.initiator)

}

action refund_after_timeout(lock: SwapLock, refunded_by: Address, current_timepoint: u64) -> updated_lock: SwapLock {
    transition lock.state: Pending -> updated_lock.state: Refunded
    verification
        require refunded_by == lock.initiator, "not the initiator"
        require current_timepoint >= lock.timeout_timepoint + 100, "timeout not reached"
        consume lock
        create updated_lock = SwapLock { swap_id: lock.swap_id, initiator: lock.initiator, participant: lock.participant, hashlock: lock.hashlock, timeout_timepoint: lock.timeout_timepoint, asset_type: lock.asset_type, amount: lock.amount, state: Refunded } with_lock(refunded_by)

}
"#
}

#[test]
fn cellc_atomic_swap_full_lifecycle_build_check_audit_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(root.join("src").join("main.cell"), atomic_swap_inline_source()).unwrap();

    // 1. check succeeds with the linear (acyclic) state machine.
    let check = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(check.status.success(), "check failed: {}", String::from_utf8_lossy(&check.stderr));

    // 2. build produces an artifact + metadata.
    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(build.status.success(), "build failed: {}", String::from_utf8_lossy(&build.stderr));
    let metadata: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("build").join("main.s.meta.json")).unwrap()).unwrap();
    let swap_layout = metadata["template_layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layout| layout["type_name"] == "SwapLock")
        .expect("SwapLock template layout");
    assert_eq!(swap_layout["schema"], "cellscript-template-layout-v0.21");
    // The flow is linear (Pending -> Claimed/Refunded), so the layout must be PathOnlyAllowed.
    assert_eq!(swap_layout["cycle_policy"], "PathOnlyAllowed");
    assert_eq!(swap_layout["state_machine_acyclic"], true);

    // 3. explain graph reports the action transitions + template-layout-aware protocol view.
    let graph = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["explain", "graph"]).arg("--json").output().unwrap();
    assert!(graph.status.success(), "{}", String::from_utf8_lossy(&graph.stderr));
    let graph_json: serde_json::Value = serde_json::from_slice(&graph.stdout).unwrap();
    assert_eq!(graph_json["schema"], "cellscript-protocol-graph-v0.22");
    assert_eq!(graph_json["consensus_checked"], false);
    assert!(graph_json["vertices"]
        .as_array()
        .unwrap()
        .iter()
        .any(|vertex| { vertex["id"] == "SwapLock:Pending" && vertex["initial"] == true && vertex["terminal"] == false }));
    assert!(graph_json["vertices"]
        .as_array()
        .unwrap()
        .iter()
        .any(|vertex| { vertex["id"] == "SwapLock:Claimed" && vertex["initial"] == false && vertex["terminal"] == true }));
    assert!(
        graph_json["edges"].as_array().unwrap().iter().any(|edge| {
            edge["action_name"] == "claim_with_preimage"
                && edge["source_vertex"] == "SwapLock:Pending"
                && edge["target_vertex"] == "SwapLock:Claimed"
                && edge["derivation"] == "state-transition"
        }),
        "expected claim_with_preimage state-transition edge: {graph_json}"
    );

    // 4. audit-bundle embeds both protocol_graph and template_layouts with the v0.21 schemas.
    let audit = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("audit-bundle")
        .args(["--output"])
        .arg(root.join("audit"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(audit.status.success(), "{}", String::from_utf8_lossy(&audit.stderr));
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("audit").join("audit-bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["protocol_graph"]["schema"], "cellscript-protocol-graph-v0.22");
    assert!(bundle["template_layouts"].as_array().unwrap().iter().any(|layout| {
        layout["schema"] == "cellscript-template-layout-v0.21"
            && layout["type_name"] == "SwapLock"
            && layout["consensus_checked"] == false
    }));

    // 5. action build surfaces runtime-required scan selectors for the consume/create actions.
    let action_build = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("action")
        .arg("build")
        .arg("--action")
        .arg("claim_with_preimage")
        .arg("--json")
        .output()
        .unwrap();
    assert!(action_build.status.success(), "{}", String::from_utf8_lossy(&action_build.stderr));
    let plan: serde_json::Value = serde_json::from_slice(&action_build.stdout).unwrap();
    let scan_selectors = &plan["action_scan_selectors"];
    assert_eq!(scan_selectors["schema"], "cellscript-action-scan-selectors-v0.21");
    assert!(
        scan_selectors["runtime_required_selector_count"].as_u64().unwrap() >= 1,
        "claim_with_preimage should declare at least one runtime-required selector: {scan_selectors}"
    );
}

#[test]
fn cellc_multi_phase_dao_flow_lifecycle_build_check_audit_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    // A linear Proposal state machine: Draft -> Active -> {Executed, Defeated}.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::dao

shared DaoConfig has store, create, read_ref {
    admin: Address,
    quorum_bps: u64,
}

receipt Proposal has store, create, consume {
    proposal_id: Hash,
    state: u8,
    proposer: Address,
    for_votes: u64,
    against_votes: u64,
    end_timepoint: u64,
}

receipt ExecutionRecord has create {
    proposal_id: Hash,
    executed_at: u64,
    for_votes: u64,
    against_votes: u64,
}

flow Proposal.state {
    Draft -> Active;
    Active -> Executed;
    Active -> Defeated;
}

action propose(proposer: Address, proposal_id: Hash, end_timepoint: u64) -> proposal: Proposal {
    verification
        create proposal = Proposal { proposal_id, state: Draft, proposer, for_votes: 0, against_votes: 0, end_timepoint } with_lock(proposer)

}

action activate_proposal(proposal_before: Proposal) -> proposal_after: Proposal {
    transition proposal_before.state: Draft -> proposal_after.state: Active
    verification
        let now = env::current_timepoint()
        require proposal_before.state == Proposal::Draft, "not draft"
        require now < proposal_before.end_timepoint, "activation window closed"
        preserve proposal_after from proposal_before {
            proposal_id
            proposer
            for_votes
            against_votes
            end_timepoint
        }
        consume proposal_before
        create proposal_after = Proposal { proposal_id: proposal_before.proposal_id, state: Proposal::Active, proposer: proposal_before.proposer, for_votes: proposal_before.for_votes, against_votes: proposal_before.against_votes, end_timepoint: proposal_before.end_timepoint } with_lock(proposal_before.proposer)

}

action execute_proposal(proposal_before: Proposal, read config: DaoConfig) -> (proposal_after: Proposal, record: ExecutionRecord) {
    transition proposal_before.state: Active -> proposal_after.state: Executed
    verification
        let now = env::current_timepoint()
        require proposal_before.state == Proposal::Active, "not active"
        require now >= proposal_before.end_timepoint, "voting not closed"
        require proposal_before.for_votes > proposal_before.against_votes, "not enough for-votes"
        consume proposal_before
        create proposal_after = Proposal { proposal_id: proposal_before.proposal_id, state: Proposal::Executed, proposer: proposal_before.proposer, for_votes: proposal_before.for_votes, against_votes: proposal_before.against_votes, end_timepoint: proposal_before.end_timepoint } with_lock(proposal_before.proposer)
        create record = ExecutionRecord { proposal_id: proposal_before.proposal_id, executed_at: now, for_votes: proposal_before.for_votes, against_votes: proposal_before.against_votes }

}
"#,
    )
    .unwrap();

    let check = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(check.status.success(), "check failed: {}", String::from_utf8_lossy(&check.stderr));

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(build.status.success(), "build failed: {}", String::from_utf8_lossy(&build.stderr));
    let metadata: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("build").join("main.s.meta.json")).unwrap()).unwrap();
    let proposal_layout = metadata["template_layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layout| layout["type_name"] == "Proposal")
        .expect("Proposal template layout");
    assert_eq!(proposal_layout["schema"], "cellscript-template-layout-v0.21");
    // Linear flow => PathOnlyAllowed + acyclic.
    assert_eq!(proposal_layout["cycle_policy"], "PathOnlyAllowed");
    assert_eq!(proposal_layout["state_machine_acyclic"], true);

    let audit = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("audit-bundle")
        .args(["--output"])
        .arg(root.join("audit"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(audit.status.success(), "{}", String::from_utf8_lossy(&audit.stderr));
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("audit").join("audit-bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["protocol_graph"]["schema"], "cellscript-protocol-graph-v0.22");
    // The audit bundle must carry the Active -> Executed and Active -> Defeated edges.
    let edges = bundle["protocol_graph"]["edges"].as_array().unwrap();
    assert!(
        edges.iter().any(|edge| { edge["action_name"] == "execute_proposal" && edge["derivation"] == "state-transition" }),
        "expected execute_proposal state-transition edge: {bundle}"
    );

    // The DAO exposes three entry actions, so action build for each must succeed and
    // surface scan selectors under the v0.21 schema.
    for action in ["propose", "activate_proposal", "execute_proposal"] {
        let action_build = Command::new(env!("CARGO_BIN_EXE_cellc"))
            .current_dir(root)
            .arg("action")
            .arg("build")
            .arg("--action")
            .arg(action)
            .arg("--json")
            .output()
            .unwrap();
        assert!(action_build.status.success(), "{action} build failed: {}", String::from_utf8_lossy(&action_build.stderr));
        let plan: serde_json::Value = serde_json::from_slice(&action_build.stdout).unwrap();
        assert_eq!(plan["action_scan_selectors"]["schema"], "cellscript-action-scan-selectors-v0.21", "{action} selector schema");
    }
}

#[test]
fn cellc_multi_phase_dao_rejects_undeclared_state_transition() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    // The flow declares Draft -> Active and Active -> {Executed, Defeated}, but the
    // action tries Draft -> Executed, which is not a declared edge. The static flow
    // membership validator must reject it.
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::dao_bad

receipt Proposal has store, create, consume {
    proposal_id: Hash,
    state: u8,
    proposer: Address,
}

flow Proposal.state {
    Draft -> Active;
    Active -> Executed;
    Active -> Defeated;
}

action fast_track(proposal_before: Proposal) -> proposal_after: Proposal {
    transition proposal_before.state: Draft -> proposal_after.state: Executed
    verification
        require proposal_after.proposer == proposal_before.proposer
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").output().unwrap();
    assert!(!output.status.success(), "unexpected success: {}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("action 'fast_track' transition 'Proposal.state Draft -> Executed' is not declared in the flow"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cellc_cross_module_launch_composition_distributes_correctly() {
    // The bundled launch example composes token minting with AMM seeding and a 4-way
    // distribution; compile it from the repository root so cross-module stdlib imports
    // (cellscript::fungible_token, cellscript::amm_pool) resolve, then assert the full
    // audit lifecycle and the eight-output distribution shape.
    let launch_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join("launch");

    let lock_before = std::fs::read(launch_path.join("Cell.lock")).expect("bundled launch package must carry a tracked lockfile");
    let build = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(&launch_path)
        .arg("build")
        .arg("--frozen")
        .arg("--offline")
        .output()
        .unwrap();
    assert!(build.status.success(), "build failed: {}", String::from_utf8_lossy(&build.stderr));

    let metadata: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(launch_path.join("build").join("main.s.meta.json")).unwrap()).unwrap();
    // The build writes into the example package directory; remove the generated build
    // output so the test leaves no artifacts behind (the directory is gitignored, but
    // we keep the working tree clean regardless).
    let _ = std::fs::remove_dir_all(launch_path.join("build"));
    // The launch_token action must expose eight create outputs (auth + 4 distributions +
    // pool + lp_receipt + change).
    let launch_action =
        metadata["actions"].as_array().unwrap().iter().find(|action| action["name"] == "launch_token").expect("launch_token action");
    assert_eq!(
        launch_action["create_set"].as_array().map(|create_set| create_set.len()).unwrap_or(0),
        8,
        "expected launch_token with eight create outputs: {launch_action}"
    );

    let audit_dir = tempfile::tempdir().unwrap();
    let audit = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .arg("audit-bundle")
        .arg(&launch_path)
        .args(["--output"])
        .arg(audit_dir.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(audit.status.success(), "{}", String::from_utf8_lossy(&audit.stderr));
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit_dir.path().join("audit-bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["protocol_graph"]["schema"], "cellscript-protocol-graph-v0.22");
    assert_eq!(
        std::fs::read(launch_path.join("Cell.lock")).unwrap(),
        lock_before,
        "frozen/offline build and audit must not rewrite the tracked dependency graph"
    );
}

#[test]
fn cellc_gen_builder_typescript_emits_package_scaffold() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64, owner: Address) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("mint.meta.json");
    let metadata = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata.stderr));

    let output_dir = root.join("generated-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(&output_dir)
        .arg("--package-name")
        .arg("@demo/token-builder")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["schema"], "cellscript-generated-builder-summary-v0.20");
    assert_eq!(summary["target"], "typescript");
    assert_eq!(summary["package_name"], "@demo/token-builder");
    assert_eq!(summary["action_count"], 1);
    assert_eq!(summary["actions"][0], "mint");
    assert!(summary["metadata_hash"].as_str().is_some_and(|hash| hash.len() == 64));
    assert_eq!(summary["cell_data_codec_abi"], "molecule");
    assert_eq!(summary["raw_cell_data_required"], false);
    assert_eq!(summary["protocol_bundle_api_schema"], "cellscript-protocol-bundle-v1");
    assert_eq!(summary["protocol_bundle_artifact_binding_schema"], "cellscript-protocol-bundle-artifact-binding-v1");
    assert_eq!(summary["exact_script_handle_receipt_schema"], "cellscript-exact-script-handle-receipt-v1");
    assert_eq!(summary["exact_script_handle_value_schema"], "cellscript-exact-script-handle-value-v1");
    assert_eq!(summary["exact_script_handle_encoding"], "CSHDLv1-fixed-202");
    assert_eq!(summary["protocol_bundle_closed_role_schema"], "cellscript-protocol-closed-role-v1");
    assert_eq!(summary["resumable_external_signing"], true);
    assert_eq!(summary["private_keys_in_generated_api"], false);

    let package_json: serde_json::Value = serde_json::from_slice(&std::fs::read(output_dir.join("package.json")).unwrap()).unwrap();
    assert_eq!(package_json["name"], "@demo/token-builder");
    assert_eq!(package_json["type"], "module");
    assert_eq!(package_json["scripts"]["build"], "tsc -p tsconfig.json");
    assert_eq!(package_json["scripts"]["test"], "npm run build && node --test test/*.test.mjs");

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema"], "cellscript-generated-action-builder-v0.23-edition-2026");
    assert_eq!(manifest["target"], "typescript");
    assert_eq!(manifest["actions"][0]["name"], "mint");
    assert_eq!(manifest["cell_data_codec_manifest"]["schema"], "cellscript-cell-data-codec-manifest-v1");
    assert_eq!(manifest["cell_data_codec_manifest"]["abi"], "molecule");
    assert_eq!(manifest["cell_data_codec_manifest"]["raw_bytes_required"], false);
    assert_eq!(
        manifest["cell_data_codec_manifest"]["molecule_schema_manifest_hash"],
        manifest["molecule_schema_manifest"]["manifest_hash"]
    );
    assert_eq!(manifest["runtime_contract"]["requires_live_cell_resolution"], true);
    assert_eq!(manifest["runtime_contract"]["requires_dry_run_before_submit"], true);
    assert_eq!(manifest["runtime_contract"]["requires_cell_data_codec_materialization"], true);
    assert_eq!(manifest["runtime_contract"]["requires_external_cell_data_codec_adapter"], false);
    assert_eq!(manifest["runtime_contract"]["cell_data_codec_abi"], "molecule");
    assert_eq!(manifest["runtime_contract"]["must_not_infer_protocol_semantics_from_action_name"], true);
    assert_eq!(manifest["runtime_contract"]["action_scan_selectors_schema"], "cellscript-action-scan-selectors-v0.21");
    assert_eq!(manifest["runtime_contract"]["action_scan_selector_source"], "transaction_runtime_input_requirements");
    assert_eq!(manifest["actions"][0]["action_scan_selectors"]["schema"], "cellscript-action-scan-selectors-v0.21");
    assert_eq!(manifest["actions"][0]["action_scan_selectors"]["source"], "transaction_runtime_input_requirements");
    assert_eq!(manifest["protocol_bundle_contract"]["schema"], "cellscript-protocol-bundle-v1");
    assert_eq!(manifest["protocol_bundle_contract"]["closed_role_schema"], "cellscript-protocol-closed-role-v1");
    assert_eq!(manifest["protocol_bundle_contract"]["exact_handle_receipt_schema"], "cellscript-exact-script-handle-receipt-v1");
    assert_eq!(manifest["protocol_bundle_contract"]["exact_handle_value_schema"], "cellscript-exact-script-handle-value-v1");
    assert_eq!(manifest["protocol_bundle_contract"]["exact_handle_encoding"], "CSHDLv1-fixed-202");
    assert_eq!(manifest["protocol_bundle_contract"]["exact_handle_hash_algorithm"], "ckb-blake2b-256");
    assert_eq!(manifest["protocol_bundle_contract"]["exact_handle_hash_personalization"], "ckb-default-hash");
    assert!(manifest["runtime_abi_hash"].as_str().is_some());
    assert!(manifest["target_profile_hash"].as_str().is_some());
    assert_eq!(manifest["protocol_bundle_contract"]["runtime_adapter"], "cellscript-ckb-adapter");
    assert_eq!(manifest["protocol_bundle_contract"]["private_keys"], "never-in-bundle-or-evidence");
    assert_eq!(manifest["protocol_bundle_contract"]["states"].as_array().unwrap().len(), 9);
    assert_eq!(manifest["protocol_bundle_contract"]["states"][8], "ConfirmedProtocolBundleTx");
    assert_eq!(
        manifest["actions"][0]["action_scan_selectors"]["selector_count"],
        manifest["actions"][0]["runtime_input_requirements"]
    );
    assert!(manifest["runtime_error_catalog"]
        .as_array()
        .is_some_and(|errors| errors.iter().any(|error| { error["code"] == 25 && error["name"] == "entry-witness-abi-invalid" })));

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("ACTION_SCAN_SELECTORS_SCHEMA"), "{index_ts}");
    assert!(index_ts.contains("actionScanSelectors"), "{index_ts}");
    assert!(index_ts.contains("scanSelectorEvidence"), "{index_ts}");
    assert!(index_ts.contains("assertScanSelectorEvidence"), "{index_ts}");
    assert!(index_ts.contains("duplicate selector_index"), "{index_ts}");
    assert!(index_ts.contains("seenEvidenceIndexes"), "{index_ts}");
    assert!(index_ts.contains("missing for selector"), "{index_ts}");
    assert!(index_ts.contains("unexpected for selector"), "{index_ts}");
    assert!(index_ts.contains("export interface MintParams"), "{index_ts}");
    assert!(index_ts.contains("amount: bigint | number | string;"), "{index_ts}");
    assert!(index_ts.contains("owner: HexString | Uint8Array;"), "{index_ts}");
    assert!(index_ts.contains("export function planMint"), "{index_ts}");
    assert!(index_ts.contains("createActionBuilder"), "{index_ts}");
    assert!(index_ts.contains("ActionBuilderResult"), "{index_ts}");
    assert!(index_ts.contains("submittedTxHashFromRuntime"), "{index_ts}");
    assert!(index_ts.contains("CellScript builder runtime missing dryRun adapter"), "{index_ts}");
    assert!(index_ts.contains("runtimeErrorCatalog"), "{index_ts}");
    assert!(index_ts.contains("explainCellScriptRuntimeError"), "{index_ts}");
    assert!(index_ts.contains("runtimeErrorContextForAction"), "{index_ts}");
    assert!(index_ts.contains("deployment record has no status"), "{index_ts}");
    assert!(index_ts.contains("deployment status is"), "{index_ts}");
    assert!(index_ts.contains("validateCellScriptDeploymentTrust"), "{index_ts}");
    assert!(index_ts.contains("publisher_signature required by trust policy"), "{index_ts}");
    assert!(index_ts.contains("live deployment evidence deployment_status"), "{index_ts}");
    assert!(index_ts.contains("canSubmit: false"), "{index_ts}");
    assert!(index_ts.contains("live_cell_availability"), "{index_ts}");
    assert!(index_ts.contains("export const cellDataCodecManifest"), "{index_ts}");
    assert!(index_ts.contains("cellDataCodecManifest,"), "{index_ts}");
    assert!(index_ts.contains("cell_data_codec_materialization"), "{index_ts}");
    assert!(index_ts.contains("export const metadata = {"), "{index_ts}");
    assert!(!index_ts.contains("import metadataJson"), "{index_ts}");
    assert!(index_ts.contains("PROTOCOL_BUNDLE_ARTIFACT_BINDING_SCHEMA"), "{index_ts}");
    assert!(index_ts.contains("bindProtocolBundleArtifact"), "{index_ts}");
    assert!(index_ts.contains("PROTOCOL_CLOSED_ROLE_SCHEMA"), "{index_ts}");
    assert!(index_ts.contains("bindClosedProtocolRole"), "{index_ts}");
    assert!(index_ts.contains("schemaContracts"), "{index_ts}");
    assert!(index_ts.contains("EXACT_SCRIPT_HANDLE_RECEIPT_SCHEMA"), "{index_ts}");
    assert!(index_ts.contains("bindCheckedExactScriptHandle"), "{index_ts}");
    assert!(index_ts.contains("exactScriptHandleFromCheckedBundle"), "{index_ts}");
    assert!(index_ts.contains("deploymentLineHandleFromCheckedBundle"), "{index_ts}");
    assert!(index_ts.contains("deploymentLineHandleEvidence"), "{index_ts}");
    assert!(index_ts.contains("CSHDLv1-fixed-202"), "{index_ts}");
    assert!(index_ts.contains("createProtocolBundleClient"), "{index_ts}");
    assert!(index_ts.contains("ProtocolBundleSigningRequest"), "{index_ts}");
    assert!(index_ts.contains("ProtocolBundleConfirmationPolicy"), "{index_ts}");
    assert!(index_ts.contains("ConfirmedProtocolBundleTx"), "{index_ts}");
    assert!(index_ts.contains("privateKeysIncluded: false"), "{index_ts}");

    let builder_test = std::fs::read_to_string(output_dir.join("test").join("builder.test.mjs")).unwrap();
    assert!(builder_test.contains("node:test"), "{builder_test}");
    assert!(builder_test.contains("plans all generated actions without submitting"), "{builder_test}");
    assert!(builder_test.contains("actionScanSelectors.schema"), "{builder_test}");
    assert!(builder_test.contains("selectorEvidenceForPlan"), "{builder_test}");
    assert!(builder_test.contains("scanSelectorEvidence.role mismatch"), "{builder_test}");
    assert!(builder_test.contains("scanSelectorEvidence.source missing"), "{builder_test}");
    assert!(builder_test.contains("duplicate selector_index"), "{builder_test}");
    assert!(builder_test.contains("delegates live-cell resolution and transaction build to runtime"), "{builder_test}");
    assert!(builder_test.contains("delegates dry-run and submit modes to runtime"), "{builder_test}");
    assert!(builder_test.contains("rejects missing runtime adapters and malformed runtime shapes"), "{builder_test}");
    assert!(builder_test.contains("maps runtime errors to action field context"), "{builder_test}");
    assert!(builder_test.contains("rejects mismatched lockfile identity"), "{builder_test}");
    assert!(builder_test.contains("rejects mismatched deployment identity"), "{builder_test}");
    assert!(builder_test.contains("trust policy requires a deployment record"), "{builder_test}");
    assert!(builder_test.contains("resumable ProtocolBundle runtime state machine without private keys"), "{builder_test}");
    assert!(builder_test.contains("shared-token"), "{builder_test}");
    assert!(builder_test.contains("bindCheckedExactScriptHandle"), "{builder_test}");

    let generated_metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("src").join("metadata.json")).unwrap()).unwrap();
    assert_eq!(generated_metadata["actions"][0]["name"], "mint");
    assert_eq!(generated_metadata["cell_data_codec_manifest"], manifest["cell_data_codec_manifest"]);
}

#[test]
fn cellc_gen_builder_preserves_typed_temporal_scalar_domains() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "temporal-builder"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module temporal_builder::main

action schedule(
    epoch: EpochNumber,
    duration: EpochDuration,
    block: BlockNumber,
    length: EpochLength,
    timestamp: TimestampMillis,
    encoded: EncodedSince,
    decoded: DecodedSince,
    absolute_block: AbsoluteBlockSince,
    absolute_epoch: AbsoluteEpochSince,
    absolute_timestamp: AbsoluteTimestampSince,
    relative_block: RelativeBlockSince,
    relative_epoch: RelativeEpochSince,
    relative_timestamp: RelativeTimestampSince,
) -> bool {
    verification
        return epoch == epoch
            && duration == duration
            && block == block
            && length == length
            && timestamp == timestamp
            && ckb::since_to_raw(encoded) == ckb::since_to_raw(decoded)
            && ckb::since_to_raw(absolute_block) == ckb::since_to_raw(relative_block)
            && ckb::since_to_raw(absolute_epoch) == ckb::since_to_raw(relative_epoch)
            && ckb::since_to_raw(absolute_timestamp) == ckb::since_to_raw(relative_timestamp)
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("temporal.meta.json");
    let metadata_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata_output.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata_output.stderr));

    let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    let params = metadata["actions"][0]["params"].as_array().unwrap();
    assert_eq!(params.len(), 13);
    assert!(params.iter().all(|param| param["schema_pointer_abi"] == false && param["schema_length_abi"] == false));

    let output_dir = root.join("generated-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--output")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["runtime_contract"]["temporal_interface"]["schema"], "cellscript-ckb-temporal-interface-v1");
    assert_eq!(manifest["runtime_contract"]["temporal_interface"]["since_abi"], "ckb-since-rfc0017-typed-v1");

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("export type CellScriptTemporalDomain ="), "{index_ts}");
    assert!(index_ts.contains("export function temporalValue"), "{index_ts}");
    assert!(index_ts.contains("temporalContract: typeof temporalContract;"), "{index_ts}");
    assert!(index_ts.contains("epoch: EpochNumber;"), "{index_ts}");
    assert!(index_ts.contains("duration: EpochDuration;"), "{index_ts}");
    assert!(index_ts.contains("encoded: EncodedSince;"), "{index_ts}");
    assert!(index_ts.contains("absolute_epoch: AbsoluteEpochSince;"), "{index_ts}");
    assert!(index_ts.contains("relative_timestamp: RelativeTimestampSince;"), "{index_ts}");
}

#[test]
fn cellc_gen_builder_preserves_dynamic_runtime_index_bounds() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "dynamic-index-builder"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module dynamic_index_builder::main

resource Token has store { amount: u64 }

action inspect(source_index: u64) -> u64 {
    let input = ckb::input<Token>(source_index)
    return input.capacity
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("inspect.meta.json");
    let metadata_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata_output.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata_output.stderr));

    let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    assert_eq!(metadata["metadata_schema_version"], 71);
    assert_eq!(metadata["runtime"]["ckb_runtime_access_provenance_contract"], "cellscript-ckb-runtime-access-provenance-v1");
    let dynamic_access = metadata["actions"][0]["ckb_runtime_accesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|access| access["operation"] == "source-input")
        .expect("source-input access");
    assert_eq!(dynamic_access["index"], 0);
    assert_eq!(dynamic_access["provenance"]["source"]["resolved_source"], "Input");
    assert_eq!(dynamic_access["provenance"]["index"]["kind"], "dynamic");
    assert_eq!(dynamic_access["provenance"]["index"]["binding"], "source_index");
    assert_eq!(dynamic_access["provenance"]["index"]["max_inclusive"], u64::from(u32::MAX));

    let output_dir = root.join("generated-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--output")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["runtime_contract"]["runtime_access_provenance"], "cellscript-ckb-runtime-access-provenance-v1");
    assert_eq!(manifest["actions"][0]["runtime_accesses"][0]["provenance"]["contract"], "cellscript-ckb-runtime-access-provenance-v1");

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("export const runtimeAccessProvenanceContract"), "{index_ts}");
    assert!(index_ts.contains("assertRuntimeAccessParams"), "{index_ts}");
    assert!(index_ts.contains("exceeds max_inclusive"), "{index_ts}");
    assert!(index_ts.contains("4294967295"), "{index_ts}");
    let builder_test = std::fs::read_to_string(output_dir.join("test").join("builder.test.mjs")).unwrap();
    assert!(builder_test.contains("dynamicIndexCases"), "{builder_test}");
    assert!(builder_test.contains("rejects dynamic source indexes above their declared bound"), "{builder_test}");
}

#[test]
fn cellc_gen_builder_preserves_bounded_witness_owner_contract() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "bounded-witness-builder"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module bounded_witness_builder::main

action inspect() -> u64 {
    verification
        let witness_args = witness::args(0)
        let lock = witness::bounded_lock(witness_args, 64)
        require lock.size <= 64
        return 0
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("inspect.meta.json");
    let metadata_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata_output.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata_output.stderr));

    let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    assert_eq!(metadata["metadata_schema_version"], 71);
    let handle = metadata["runtime"]["transaction_view_handles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|handle| handle["handle_type"] == "WitnessBytesView<lock,64>")
        .expect("bounded lock handle");
    assert_eq!(handle["witness_owner"], "lock");
    assert_eq!(handle["max_bytes"], 64);
    assert_eq!(handle["provenance"]["range"]["length"]["max_inclusive"], 64);

    let output_dir = root.join("generated-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--output")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    let generated_handle = manifest["transaction_view_handles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|handle| handle["handle_type"] == "WitnessBytesView<lock,64>")
        .expect("generated bounded lock handle");
    assert_eq!(generated_handle["witness_owner"], "lock");
    assert_eq!(generated_handle["max_bytes"], 64);
    assert!(manifest["actions"][0]["runtime_accesses"]
        .as_array()
        .unwrap()
        .iter()
        .any(|access| access["operation"] == "witness-bounded-lock-size"));

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("export const transactionViewHandles"), "{index_ts}");
    assert!(index_ts.contains("WitnessBytesView<lock,64>"), "{index_ts}");
    assert!(index_ts.contains("\"witness_owner\": \"lock\""), "{index_ts}");
    assert!(index_ts.contains("\"max_bytes\": 64"), "{index_ts}");
}

#[test]
fn cellc_gen_builder_preserves_zero_lock_signing_message_domain() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2027"
name = "sighash-zero-lock-builder"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module sighash_zero_lock_builder::main

action inspect() -> u64 {
    verification
        let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
        let expected = witness::args(0).lock
        require Hash::from_sighash_all(digest) == expected
        return 0
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("inspect.meta.json");
    let metadata_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata_output.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata_output.stderr));

    let output_dir = root.join("generated-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--output")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    let domain = &manifest["signing_message_domains"][0];
    assert_eq!(domain["contract"], "cellscript-ckb-sighash-all-zero-lock-v1");
    assert_eq!(domain["max_group_inputs"], 4);
    assert_eq!(domain["max_inputs"], 8);
    assert_eq!(domain["max_extra_witnesses"], 4);
    assert_eq!(domain["max_witness_bytes"], 4096);
    assert_eq!(manifest["runtime_contract"]["requires_pre_signing_witness_placement"], true);

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("export const signingMessageDomains"), "{index_ts}");
    assert!(index_ts.contains("cellscript-ckb-sighash-all-zero-lock-v1"), "{index_ts}");
    assert!(index_ts.contains("signingMessageDomains: typeof signingMessageDomains"), "{index_ts}");
}

#[test]
fn cellc_gen_builder_typescript_declares_raw_cell_data_codec_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "raw-codec-demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module raw_codec_demo::main

action inspect() -> u64 {
    verification
        let input = source::group_input(0)
        let quantity = ckb::cell_data_u32_le(input, 0)
        let amount = ckb::cell_data_u64_le(input, 4)
        if quantity != 7 {
            return 90
        }
        return amount
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("inspect.meta.json");
    let metadata = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata.stderr));

    let output_dir = root.join("generated-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--output")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["cell_data_codec_abi"], "molecule+raw-bytes-v1");
    assert_eq!(summary["raw_cell_data_required"], true);

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["cell_data_codec_manifest"]["abi"], "molecule+raw-bytes-v1");
    assert_eq!(manifest["cell_data_codec_manifest"]["raw_bytes_required"], true);
    assert!(manifest["cell_data_codec_manifest"]["raw_runtime_accesses"]
        .as_array()
        .is_some_and(|accesses| accesses.iter().any(|access| access["binding"] == "ckb::cell_data_u32_le")
            && accesses.iter().any(|access| access["binding"] == "ckb::cell_data_u64_le")));
    assert_eq!(manifest["runtime_contract"]["requires_external_cell_data_codec_adapter"], true);
    assert_eq!(manifest["runtime_contract"]["cell_data_codec_abi"], "molecule+raw-bytes-v1");

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("export const cellDataCodecManifest"), "{index_ts}");
    assert!(index_ts.contains("molecule+raw-bytes-v1"), "{index_ts}");
    assert!(index_ts.contains("cell_data_codec_materialization"), "{index_ts}");
}

#[test]
fn cellc_gen_builder_lockfile_identity_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64, owner: Address) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let metadata_path = root.join("mint.meta.json");
    let metadata_output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("metadata")
        .arg("--output")
        .arg(&metadata_path)
        .output()
        .unwrap();
    assert!(metadata_output.status.success(), "stderr: {}", String::from_utf8_lossy(&metadata_output.stderr));

    let metadata: cellscript::CompileMetadata = serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    let build_info = locked_build_from_metadata_for_test(&metadata);
    let deployment_network = "aggron4";
    let deployment_code_hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let deployment_out_point = "0xaaaa:0";
    let package_source_hash = "package-registry-source-hash".to_string();
    let mut lockfile = cellscript::package::Lockfile {
        version: cellscript::package::Lockfile::CURRENT_VERSION,
        schema: cellscript::package::Lockfile::CURRENT_SCHEMA.to_string(),
        package: cellscript::package::LockfilePackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "demo".to_string(),
            version: "0.1.0".to_string(),
            namespace: None,
            source_hash: Some(package_source_hash.clone()),
            compiler_source_hash: metadata.source_hash.clone(),
        },
        root: Default::default(),
        dependencies: Default::default(),
        environments: Default::default(),
        package_build: Some(build_info.clone()),
        deployment: Default::default(),
    };
    lockfile.deployment.insert(
        deployment_network.to_string(),
        cellscript::package::LockfileDeploymentRef {
            record: deployment_out_point.to_string(),
            record_hash: None,
            code_hash: Some(deployment_code_hash.to_string()),
            out_point: Some(deployment_out_point.to_string()),
            data_hash: Some(deployment_code_hash.to_string()),
        },
    );
    let lockfile_path = root.join("Cell.lock");
    std::fs::write(&lockfile_path, toml::to_string_pretty(&lockfile).unwrap()).unwrap();

    let deployed = cellscript::package::DeployedManifest {
        version: cellscript::package::DeployedManifest::CURRENT_VERSION,
        schema: cellscript::package::DEPLOYED_MANIFEST_SCHEMA.to_string(),
        package: cellscript::package::DeployedPackageInfo {
            edition: cellscript::CURRENT_EDITION,
            name: "demo".to_string(),
            version: "0.1.0".to_string(),
            source_hash: Some(package_source_hash.clone()),
        },
        build: Some(cellscript::package::DeployedBuildInfo {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: build_info.compatibility_profile_hash.clone(),
            compiler_version: build_info.compiler_version.clone(),
            artifact_hash: build_info.artifact_hash.clone(),
            metadata_hash: build_info.metadata_hash.clone(),
            schema_hash: build_info.schema_hash.clone(),
            cell_data_codec_manifest_hash: build_info.cell_data_codec_manifest_hash.clone(),
            abi_hash: build_info.abi_hash.clone(),
            constraints_hash: build_info.constraints_hash.clone(),
        }),
        deployments: vec![cellscript::package::DeploymentRecord {
            edition: cellscript::CURRENT_EDITION,
            compatibility_profile_hash: build_info.compatibility_profile_hash.clone(),
            network: deployment_network.to_string(),
            chain_id: "ckb-testnet".to_string(),
            tx_hash: "0xaaaa".to_string(),
            output_index: 0,
            code_hash: deployment_code_hash.to_string(),
            hash_type: "data1".to_string(),
            dep_type: "code".to_string(),
            data_hash: deployment_code_hash.to_string(),
            out_point: deployment_out_point.to_string(),
            artifact_hash: build_info.artifact_hash.clone(),
            metadata_hash: build_info.metadata_hash.clone(),
            schema_hash: build_info.schema_hash.clone(),
            cell_data_codec_manifest_hash: build_info.cell_data_codec_manifest_hash.clone(),
            abi_hash: build_info.abi_hash.clone(),
            constraints_hash: build_info.constraints_hash.clone(),
            compiler_version: build_info.compiler_version.clone(),
            type_id: None,
            script_role: Some(cellscript::package::ScriptRole::Type),
            status: Some(cellscript::package::DeploymentStatus::Active),
            upgrade_lineage: None,
            audit_report_hash: None,
            publisher_signature: None,
            cell_deps: vec![],
        }],
    };
    let deployed_path = root.join("Deployed.toml");
    std::fs::write(&deployed_path, toml::to_string_pretty(&deployed).unwrap()).unwrap();

    let output_dir = root.join("locked-builder");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--lockfile")
        .arg(&lockfile_path)
        .arg("--deployed")
        .arg(&deployed_path)
        .arg("--deployment-network")
        .arg(deployment_network)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(&output_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["lockfile_verified"], true);
    assert_eq!(summary["deployment_verified"], true);

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output_dir.join("cellscript-builder-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["locked_identity"]["schema"], "cellscript-builder-locked-identity-v0.20");
    assert_eq!(manifest["deployment_identity"]["schema"], "cellscript-builder-deployment-identity-v0.20");
    assert_eq!(manifest["deployment_identity"]["deployments"][0]["network"], deployment_network);
    assert_eq!(manifest["locked_identity"]["package"]["source_hash"], package_source_hash);
    assert_eq!(manifest["locked_identity"]["package"]["compiler_source_hash"], metadata.source_hash.as_deref().unwrap());
    assert_eq!(manifest["locked_identity"]["build"]["metadata_hash"], build_info.metadata_hash.as_deref().unwrap());

    let index_ts = std::fs::read_to_string(output_dir.join("src").join("index.ts")).unwrap();
    assert!(index_ts.contains("validateCellScriptLockfile"), "{index_ts}");
    assert!(index_ts.contains("validateCellScriptDeployment"), "{index_ts}");
    assert!(index_ts.contains("assertCellScriptLockfile(options.lockfile)"), "{index_ts}");
    assert!(
        index_ts.contains(
            "assertCellScriptDeployment(options.lockfile, options.deployment, options.liveDeploymentEvidence, options.trustPolicy)"
        ),
        "{index_ts}"
    );

    let mut bad_lockfile = lockfile;
    bad_lockfile.package_build.as_mut().unwrap().metadata_hash = Some("bad_metadata_hash".to_string());
    let bad_lockfile_path = root.join("Bad.lock");
    std::fs::write(&bad_lockfile_path, toml::to_string_pretty(&bad_lockfile).unwrap()).unwrap();

    let rejected = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--lockfile")
        .arg(&bad_lockfile_path)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(root.join("bad-builder"))
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("generated builder identity verification failed"), "{stderr}");
    assert!(stderr.contains("metadata_hash mismatch"), "{stderr}");

    let mut bad_codec_lockfile = bad_lockfile;
    bad_codec_lockfile.package_build.as_mut().unwrap().metadata_hash = build_info.metadata_hash.clone();
    bad_codec_lockfile.package_build.as_mut().unwrap().cell_data_codec_manifest_hash = Some("bad_codec_manifest_hash".to_string());
    let bad_codec_lockfile_path = root.join("BadCodec.lock");
    std::fs::write(&bad_codec_lockfile_path, toml::to_string_pretty(&bad_codec_lockfile).unwrap()).unwrap();

    let codec_rejected = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--lockfile")
        .arg(&bad_codec_lockfile_path)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(root.join("bad-codec-builder"))
        .output()
        .unwrap();
    assert!(!codec_rejected.status.success());
    let codec_stderr = String::from_utf8_lossy(&codec_rejected.stderr);
    assert!(codec_stderr.contains("cell_data_codec_manifest_hash mismatch"), "{codec_stderr}");

    let mut bad_deployed = deployed.clone();
    bad_deployed.deployments[0].code_hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let bad_deployed_path = root.join("BadDeployed.toml");
    std::fs::write(&bad_deployed_path, toml::to_string_pretty(&bad_deployed).unwrap()).unwrap();

    let rejected_deployment = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--lockfile")
        .arg(&lockfile_path)
        .arg("--deployed")
        .arg(&bad_deployed_path)
        .arg("--deployment-network")
        .arg(deployment_network)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(root.join("bad-deployment-builder"))
        .output()
        .unwrap();
    assert!(!rejected_deployment.status.success());
    let stderr = String::from_utf8_lossy(&rejected_deployment.stderr);
    assert!(stderr.contains("generated builder deployment identity verification failed"), "{stderr}");
    assert!(stderr.contains("code_hash mismatch"), "{stderr}");

    let mut missing_status_deployed = deployed.clone();
    missing_status_deployed.deployments[0].status = None;
    let missing_status_deployed_path = root.join("MissingStatusDeployed.toml");
    std::fs::write(&missing_status_deployed_path, toml::to_string_pretty(&missing_status_deployed).unwrap()).unwrap();

    let rejected_missing_status = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--lockfile")
        .arg(&lockfile_path)
        .arg("--deployed")
        .arg(&missing_status_deployed_path)
        .arg("--deployment-network")
        .arg(deployment_network)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(root.join("missing-status-deployment-builder"))
        .output()
        .unwrap();
    assert!(!rejected_missing_status.status.success());
    let stderr = String::from_utf8_lossy(&rejected_missing_status.stderr);
    assert!(stderr.contains("generated builder deployment identity verification failed"), "{stderr}");
    assert!(stderr.contains("has no status"), "{stderr}");

    let mut deprecated_deployed = deployed;
    deprecated_deployed.deployments[0].status = Some(cellscript::package::DeploymentStatus::Deprecated);
    let deprecated_deployed_path = root.join("DeprecatedDeployed.toml");
    std::fs::write(&deprecated_deployed_path, toml::to_string_pretty(&deprecated_deployed).unwrap()).unwrap();

    let rejected_deprecated = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("gen-builder")
        .arg("--target")
        .arg("typescript")
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--lockfile")
        .arg(&lockfile_path)
        .arg("--deployed")
        .arg(&deprecated_deployed_path)
        .arg("--deployment-network")
        .arg(deployment_network)
        .arg("--action")
        .arg("mint")
        .arg("--output")
        .arg(root.join("deprecated-deployment-builder"))
        .output()
        .unwrap();
    assert!(!rejected_deprecated.status.success());
    let stderr = String::from_utf8_lossy(&rejected_deprecated.stderr);
    assert!(stderr.contains("generated builder deployment identity verification failed"), "{stderr}");
    assert!(stderr.contains("not active"), "{stderr}");
}

#[test]
fn cellc_entry_witness_subcommand_emits_parameterized_witness_json() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action main(amount: u64) -> u64 {
    verification
        return amount
}
"#,
    )
    .unwrap();

    let output_path = root.join("witness.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("entry-witness")
        .arg("--action")
        .arg("main")
        .arg("--arg")
        .arg("77")
        .arg("--output")
        .arg(&output_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["abi"], "cellscript-entry-witness-v1");
    assert_eq!(stdout["placement_abi"], "cellscript-witnessargs-input-type-v2");
    assert_eq!(stdout["witness_args_field"], "input_type");
    assert_eq!(stdout["witness_source"], "group-input-0-then-group-output-0");
    assert_eq!(stdout["raw_v1_compatible"], false);
    assert_eq!(stdout["entry_kind"], "action");
    assert_eq!(stdout["entry"], "main");
    assert_eq!(stdout["witness_hex"], "43534152477631004d00000000000000");
    assert_eq!(stdout["witness_size_bytes"], 16);
    assert_eq!(stdout["payload_params"][0], "amount");
    assert_eq!(stdout["payload_args"], 1);

    let mut expected = b"CSARGv1\0".to_vec();
    expected.extend_from_slice(&77u64.to_le_bytes());
    assert_eq!(std::fs::read(output_path).unwrap(), expected);
}

#[test]
fn cellc_entry_witness_subcommand_encodes_bundled_token_amm_bootstrap_payloads() {
    let examples = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let launch = examples.join("launch.cell");
    let token = examples.join("token.cell");
    let amm_pool = examples.join("amm_pool.cell");
    let address = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let distribution = format!("0x{}", "22".repeat(160));

    let launch_output = cellc_command()
        .arg("entry-witness")
        .arg(&launch)
        .arg("--target-profile")
        .arg("ckb")
        .arg("--action")
        .arg("launch_token")
        .arg("--arg")
        .arg("0x4c41554e43483031")
        .arg("--arg")
        .arg("10000")
        .arg("--arg")
        .arg("1000")
        .arg("--arg")
        .arg("500")
        .arg("--arg")
        .arg("30")
        .arg("--arg")
        .arg(address)
        .arg("--arg")
        .arg(&distribution)
        .arg("--json")
        .output()
        .unwrap();
    assert!(launch_output.status.success(), "stderr: {}", String::from_utf8_lossy(&launch_output.stderr));
    let launch_stdout: serde_json::Value = serde_json::from_slice(&launch_output.stdout).unwrap();
    assert_eq!(launch_stdout["status"], "ok");
    assert_eq!(launch_stdout["entry"], "launch_token");
    assert_eq!(launch_stdout["payload_args"], 7);
    assert_eq!(launch_stdout["witness_size_bytes"], 234);
    assert_eq!(launch_stdout["payload_params"][0], "symbol");
    assert_eq!(launch_stdout["payload_params"][4], "fee_rate_bps");
    assert_eq!(launch_stdout["payload_params"][6], "distribution");

    let token_output = cellc_command()
        .arg("entry-witness")
        .arg(&token)
        .arg("--target-profile")
        .arg("ckb")
        .arg("--action")
        .arg("mint_with_authority")
        .arg("--arg")
        .arg(address)
        .arg("--arg")
        .arg("25")
        .arg("--json")
        .output()
        .unwrap();
    assert!(token_output.status.success(), "stderr: {}", String::from_utf8_lossy(&token_output.stderr));
    let token_stdout: serde_json::Value = serde_json::from_slice(&token_output.stdout).unwrap();
    assert_eq!(token_stdout["status"], "ok");
    assert_eq!(token_stdout["entry"], "mint_with_authority");
    assert_eq!(token_stdout["payload_params"][0], "to");
    assert_eq!(token_stdout["payload_params"][1], "amount");
    assert_eq!(token_stdout["witness_size_bytes"], 48);

    let seed_output = cellc_command()
        .arg("entry-witness")
        .arg(&amm_pool)
        .arg("--target-profile")
        .arg("ckb")
        .arg("--action")
        .arg("seed_pool")
        .arg("--arg")
        .arg("30")
        .arg("--arg")
        .arg(address)
        .arg("--json")
        .output()
        .unwrap();
    assert!(seed_output.status.success(), "stderr: {}", String::from_utf8_lossy(&seed_output.stderr));
    let seed_stdout: serde_json::Value = serde_json::from_slice(&seed_output.stdout).unwrap();
    assert_eq!(seed_stdout["status"], "ok");
    assert_eq!(seed_stdout["entry"], "seed_pool");
    assert_eq!(seed_stdout["payload_params"][0], "fee_rate_bps");
    assert_eq!(seed_stdout["payload_params"][1], "provider");
    assert_eq!(seed_stdout["witness_size_bytes"], 42);

    let swap_output = cellc_command()
        .arg("entry-witness")
        .arg(&amm_pool)
        .arg("--target-profile")
        .arg("ckb")
        .arg("--action")
        .arg("swap_a_for_b")
        .arg("--arg")
        .arg("2")
        .arg("--arg")
        .arg(address)
        .arg("--json")
        .output()
        .unwrap();
    assert!(swap_output.status.success(), "stderr: {}", String::from_utf8_lossy(&swap_output.stderr));
    let swap_stdout: serde_json::Value = serde_json::from_slice(&swap_output.stdout).unwrap();
    assert_eq!(swap_stdout["status"], "ok");
    assert_eq!(swap_stdout["entry"], "swap_a_for_b");
    assert_eq!(swap_stdout["payload_params"][0], "min_output");
    assert_eq!(swap_stdout["payload_params"][1], "to");
    assert_eq!(swap_stdout["witness_size_bytes"], 48);
}

#[test]
fn cellc_abi_subcommand_explains_entry_witness_layout() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

struct Snapshot {
    amount: u64,
}

action main(snapshot: Snapshot, amount: u64) -> u64 {
    verification
        return amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("abi").arg("--action").arg("main").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["abi"], "cellscript-entry-witness-v1");
    assert_eq!(stdout["entry_kind"], "action");
    assert_eq!(stdout["entry"], "main");
    assert_eq!(stdout["payload_params"][0], "snapshot");
    assert_eq!(stdout["payload_params"][1], "amount");
    assert_eq!(stdout["layout"]["abi_slots_used"], 3);
    assert_eq!(stdout["layout"]["min_witness_bytes"], 20);
    assert_eq!(stdout["params"][0]["name"], "snapshot");
    assert_eq!(stdout["params"][0]["abi_kind"], "schema-pointer");
    assert_eq!(stdout["params"][0]["witness_bytes"], 4);
    assert_eq!(stdout["params"][0]["slot_start"], 0);
    assert_eq!(stdout["params"][0]["slot_end"], 1);
    assert_eq!(stdout["params"][1]["name"], "amount");
    assert_eq!(stdout["params"][1]["abi_kind"], "scalar");
    assert_eq!(stdout["params"][1]["witness_bytes"], 8);
}

#[test]
fn cellc_scheduler_plan_consumes_shared_touch_hints() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

shared Ledger has store {
    balance: u64,
}

action credit(ledger_before: Ledger, delta: u64) -> ledger_after: Ledger {
    verification
        require ledger_after.balance == ledger_before.balance + delta

}
action debit(ledger_before: Ledger, delta: u64) -> ledger_after: Ledger {
    verification
        require ledger_after.balance == ledger_before.balance - delta

}
action read_only(value: u64) -> u64 {
    verification
        return value
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("scheduler-plan")
        .arg("--target-profile")
        .arg("ckb")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["policy"], "cellscript-scheduler-hints-v1");
    assert_eq!(stdout["action_count"], 3);
    assert_eq!(stdout["conflict_count"], 1);
    assert_eq!(stdout["conflicts"][0]["left"], "credit");
    assert_eq!(stdout["conflicts"][0]["right"], "debit");
    assert_eq!(stdout["conflicts"][0]["policy"], "must-not-run-in-parallel");
    assert_eq!(stdout["serial_required_actions"][0], "credit");
    assert_eq!(stdout["serial_required_actions"][1], "debit");
    assert!(stdout["estimated_cycles"]["total"].as_u64().unwrap() > 0);
    let read_only = stdout["actions"].as_array().unwrap().iter().find(|action| action["action"] == "read_only").unwrap();
    assert_eq!(read_only["admission"], "parallel-candidate");
}

#[test]
fn cellc_ckb_hash_emits_default_blake2b_vector() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("ckb-hash").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["algorithm"], "blake2b-256");
    assert_eq!(stdout["personalization"], "ckb-default-hash");
    assert_eq!(stdout["input_bytes"], 0);
    assert_eq!(stdout["hash"], "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e");

    let text = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("ckb-hash").arg("--hex").arg("00").output().unwrap();
    assert!(text.status.success(), "stderr: {}", String::from_utf8_lossy(&text.stderr));
    assert_eq!(String::from_utf8_lossy(&text.stdout).trim().len(), 64);
}

#[test]
fn cellc_ckb_std_compat_reports_runtime_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("ckb-std-compat").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["schema"], "cellscript-ckb-std-compat-report-v0.19");
    assert_eq!(report["runtime_policy"], "inline");
    assert_eq!(report["compiler_core_dependency"], "no-ckb-std");
    assert_eq!(report["test_evidence"]["compat_tests"], "tests/ckb_std_compat.rs");
    assert_eq!(report["test_evidence"]["packed_transaction_materialization"], true);
    assert_eq!(report["test_evidence"]["script_construction_api"], true);
    assert_eq!(report["ckb_std_refs"]["type_id"], "ckb_std::type_id");
    assert_eq!(report["inline_abi"]["fields"]["cell_occupied_capacity"], 6);
    assert_eq!(report["witness_args_policy"]["entry_payload_abi"], "cellscript-entry-witness-v1");
    assert_eq!(report["witness_args_policy"]["placement_abi"], "cellscript-witnessargs-input-type-v2");
    assert_eq!(report["witness_args_policy"]["default_action_payload_field"], "input_type");
    assert_eq!(report["witness_args_policy"]["runtime_source"], "group-input-0-then-group-output-0");
    assert_eq!(report["witness_args_policy"]["raw_v1_compatible"], false);
    assert_eq!(report["witness_args_policy"]["final_witness_args_owner"], "adapter");
    assert_eq!(report["witness_args_policy"]["lock_signature_policy"], "explicit-adapter-owned-do-not-overwrite");
    assert_eq!(report["adapter_boundary"]["transaction_realizer"], "ckb-sdk-rust-or-CCC-adapter");
    assert_eq!(report["adapter_boundary"]["compiler_core_uses_ckb_sdk_rust"], false);
    assert_eq!(report["adapter_boundary"]["script_construction"]["packed_type"], "ckb_types::packed::Script");
    assert_eq!(report["adapter_boundary"]["script_construction"]["evidence_schema"], "cellscript-ckb-script-evidence-v0.19");
    assert!(report["adapter_boundary"]["script_construction"]["supports"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == "script_ref_readback")));
    assert!(report["adapter_boundary"]["script_construction"]["supports"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == "explicit_cell_dep_binding")));
    assert!(report["non_goals"].as_array().is_some_and(|items| items.iter().any(|item| item == "does-not-execute-ckb-vm")));
}

#[test]
fn cellc_opt_report_compares_all_optimization_levels() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = root.join("main.cell");
    std::fs::write(
        &source,
        r#"
module demo::main

action main(value: u64) -> u64 {
    verification
        let doubled = value + value
        return doubled
}
"#,
    )
    .unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).arg("opt-report").arg(&source).arg("--target").arg("riscv64-asm").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["policy"], "cellscript-opt-report-v1");
    assert_eq!(stdout["baseline_opt_level"], 0);
    let rows = stdout["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 4);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["opt_level"], index as u64);
        assert_eq!(row["artifact_format"], "RISC-V assembly");
        assert_eq!(row["constraints_status"], "warn");
        assert!(row["artifact_size_bytes"].as_u64().unwrap() > 0);
        assert!(row["artifact_size_delta_from_o0"].is_i64());
        assert!(row["estimated_cycles_total"].as_u64().unwrap() > 0);
        assert!(row["estimated_cycles_total_delta_from_o0"].is_i64());
        assert!(row["backend_shape"]["text_bytes"].as_u64().unwrap() > 0);
        assert!(row["backend_shape"]["executable_text_op_count"].as_u64().unwrap() > 0);
        assert!(row["backend_shape"]["covered_text_op_count"].as_u64().unwrap() > 0);
        assert!(row["backend_shape"]["machine_block_count"].as_u64().unwrap() > 0);
        assert!(row["backend_shape"]["layout_order_text_size"].as_u64().unwrap() > 0);
        assert!(row["text_bytes_delta_from_o0"].is_i64());
        assert!(row["executable_text_op_count_delta_from_o0"].is_i64());
    }
}

#[test]
fn cellc_entry_witness_subcommand_encodes_schema_backed_params() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

struct Snapshot {
    amount: u64,
}

action main(snapshot: Snapshot, amount: u64) -> u64 {
    verification
        return amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("entry-witness")
        .arg("--action")
        .arg("main")
        .arg("--arg")
        .arg("0500000000000000")
        .arg("--arg")
        .arg("5")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["witness_hex"], "43534152477631000800000005000000000000000500000000000000");
    assert_eq!(stdout["payload_params"][0], "snapshot");
    assert_eq!(stdout["payload_params"][1], "amount");
}

#[test]
fn cellc_entry_witness_subcommand_rejects_wrong_width_fixed_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action owned(owner: Address) -> u64 {
    verification
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
        .arg("0x010203")
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success(), "stdout: {}", String::from_utf8_lossy(&output.stdout));
    assert!(output.stderr.is_empty(), "unexpected stderr: {}", String::from_utf8_lossy(&output.stderr));
    let failure: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(failure["diagnostics"][0]["message"]
        .as_str()
        .is_some_and(|message| message.contains("parameter 'owner' expects 32 byte(s), got 3")));
}

#[test]
fn cellc_fmt_subcommand_formats_sources() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    let source_path = root.join("src").join("main.cell");
    std::fs::write(&source_path, "module demo::main\naction ping(x:u64)->u64{\nverification\nx\n}\n").unwrap();

    let dirty_check =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("fmt").arg("--check").arg("--json").output().unwrap();
    assert!(!dirty_check.status.success(), "unexpected success: {}", String::from_utf8_lossy(&dirty_check.stdout));
    let stdout: serde_json::Value = serde_json::from_slice(&dirty_check.stdout).unwrap();
    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["mode"], "check");
    assert_eq!(stdout["changed"], 1);
    assert!(stdout["changed_files"][0].as_str().unwrap().ends_with("src/main.cell"));

    let status = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("fmt").status().unwrap();
    assert!(status.success());

    let formatted = std::fs::read_to_string(&source_path).unwrap();
    assert!(formatted.contains("action ping(x: u64) -> u64 {\n    verification"));

    let check = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("fmt").arg("--check").arg("--json").output().unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
    let stdout: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(stdout["status"], "ok");
    assert_eq!(stdout["mode"], "check");
    assert_eq!(stdout["changed"], 0);
}

#[cfg(not(feature = "vm-runner"))]
#[test]
fn cellc_run_subcommand_without_vm_runner_degrades_gracefully() {
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).arg("run").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("simulate") || stderr.contains("experimental") || stderr.contains("Cell.toml") || stderr.contains("compile")
    );
}

#[test]
fn cellc_run_simulate_json_reports_steps_and_null_cycles() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cell.toml"), "[package]\nedition = \"2026\"\nname = \"demo\"\nversion = \"0.1.0\"\n").unwrap();
    std::fs::write(root.join("src/main.cell"), "module demo::main\naction main() -> u64 {\n    verification\n        0\n}\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["run", "--simulate", "--json"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["mode"], "simulate");
    assert_eq!(summary["artifact_format"], "RISC-V ELF");
    assert_eq!(summary["entry"]["kind"], "action");
    assert_eq!(summary["entry"]["name"], "main");
    assert!(summary["steps"].as_u64().is_some());
    assert!(summary["cycles"].is_null());
    assert!(summary["has_cell_operations"].is_boolean());
    assert!(summary["result"].is_string());
    assert!(summary["trace"].is_array());
}

#[cfg(feature = "vm-runner")]
#[test]
fn cellc_run_subcommand_executes_pure_elf_package() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

action main() -> u64 {
    verification
        0
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).args(["run", "--json"]).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["mode"], "ckb-vm");
    assert_eq!(summary["artifact_format"], "RISC-V ELF");
    assert_eq!(summary["entry"]["kind"], "action");
    assert_eq!(summary["entry"]["name"], "main");
    assert!(summary["cycles"].as_u64().is_some());
    assert!(summary["steps"].is_null());
    assert!(summary["has_cell_operations"].is_null());
    assert!(summary["result"].is_null());
    assert!(summary["trace"].is_array());
}

#[cfg(feature = "vm-runner")]
#[test]
fn cellc_run_subcommand_rejects_parameterized_schema_elf() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

struct Snapshot {
    amount: u64,
}

action main(snapshot: Snapshot) -> u64 {
    verification
        snapshot.amount
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("run").output().unwrap();
    assert!(!output.status.success(), "stdout: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no-argument pure ELF entrypoints"), "stderr: {}", stderr);
    assert!(stderr.contains("action main"), "stderr: {}", stderr);
}

#[cfg(feature = "vm-runner")]
#[test]
fn cellc_run_subcommand_rejects_ckb_runtime_elf() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

shared Config {
    threshold: u64,
}

action main() -> u64 {
    verification
        let cfg = read_ref<Config>()
        cfg.threshold
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("run").output().unwrap();
    assert!(!output.status.success(), "stdout: {}", String::from_utf8_lossy(&output.stdout));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot provide CKB transaction/syscall context"), "stderr: {}", stderr);
    assert!(stderr.contains("read-cell-dep"), "stderr: {}", stderr);
}

// ── Workspace e2e tests ──────────────────────────────────────────────────────

#[test]
fn cellc_workspace_build_compiles_all_members() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Workspace root Cell.toml
    let workspace_toml = r#"[workspace]
members = ["pkg_a", "pkg_b"]
"#;
    std::fs::write(root.join("Cell.toml"), workspace_toml).unwrap();

    // Member pkg_a
    let pkg_a = root.join("pkg_a");
    std::fs::create_dir_all(pkg_a.join("src")).unwrap();
    std::fs::write(
        pkg_a.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "pkg_a"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        pkg_a.join("src").join("main.cell"),
        r#"module pkg_a
action hello() -> u64 {
    verification
        let x: u64 = 42
        return x
}
"#,
    )
    .unwrap();

    // Member pkg_b
    let pkg_b = root.join("pkg_b");
    std::fs::create_dir_all(pkg_b.join("src")).unwrap();
    std::fs::write(
        pkg_b.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "pkg_b"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        pkg_b.join("src").join("main.cell"),
        r#"module pkg_b
action world() -> u64 {
    verification
        let y: u64 = 99
        return y
}
"#,
    )
    .unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--workspace").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    let members = summary["results"].as_array().unwrap();
    assert_eq!(members.len(), 2);
}

#[test]
fn cellc_workspace_build_specific_member() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let workspace_toml = r#"[workspace]
members = ["alpha", "beta"]
"#;
    std::fs::write(root.join("Cell.toml"), workspace_toml).unwrap();

    // Member alpha
    let alpha = root.join("alpha");
    std::fs::create_dir_all(alpha.join("src")).unwrap();
    std::fs::write(
        alpha.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "alpha"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        alpha.join("src").join("main.cell"),
        r#"module alpha
action run() -> u64 { verification let x: u64 = 1 return x }
"#,
    )
    .unwrap();

    // Member beta
    let beta = root.join("beta");
    std::fs::create_dir_all(beta.join("src")).unwrap();
    std::fs::write(
        beta.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "beta"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        beta.join("src").join("main.cell"),
        r#"module beta
action run() -> u64 { verification let y: u64 = 2 return y }
"#,
    )
    .unwrap();

    // Build only the "alpha" member
    let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("build")
        .arg("-p")
        .arg("alpha")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    let members = summary["results"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert!(members[0]["member"].as_str().unwrap().contains("alpha"));
}

#[test]
fn cellc_workspace_check_all_members() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let workspace_toml = r#"[workspace]
members = ["lib_a"]
"#;
    std::fs::write(root.join("Cell.toml"), workspace_toml).unwrap();

    let lib_a = root.join("lib_a");
    std::fs::create_dir_all(lib_a.join("src")).unwrap();
    std::fs::write(
        lib_a.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "lib_a"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        lib_a.join("src").join("main.cell"),
        r#"module lib_a
action compute() -> u64 { verification let v: u64 = 7 return v }
"#,
    )
    .unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("check").arg("--workspace").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
}

#[test]
fn cellc_workspace_build_member_with_path_dependency_import() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::write(
        root.join("Cell.toml"),
        r#"[workspace]
members = ["shared_types", "app"]
"#,
    )
    .unwrap();

    let shared = root.join("shared_types");
    std::fs::create_dir_all(shared.join("src")).unwrap();
    std::fs::write(
        shared.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "shared_types"
version = "0.1.0"
entry = "src/types.cell"
"#,
    )
    .unwrap();
    std::fs::write(
        shared.join("src").join("types.cell"),
        r#"module shared::types

resource Token has store, replace, relock, consume, burn {
    amount: u64
}
"#,
    )
    .unwrap();

    let app = root.join("app");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(
        app.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "app"
version = "0.1.0"

[dependencies]
shared_types = { path = "../shared_types" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("src").join("main.cell"),
        r#"module app::main

use shared::types::Token

action passthrough(token: Token) -> Token {
    verification
        token
}
"#,
    )
    .unwrap();

    lock_package(&app);
    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("-p").arg("app").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["status"], "ok");
    let members = summary["results"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert!(members[0]["member"].as_str().unwrap().contains("app"));
}

// ── Incremental compilation e2e tests ────────────────────────────────────────

#[test]
fn cellc_incremental_cache_hit_on_second_build() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Set up a minimal package
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "cache_test"
version = "0.1.0"
"#,
    )
    .unwrap();

    let source = r#"module cache_test
action compute() -> u64 {
    verification
        let x: u64 = 123
        return x
}
"#;
    std::fs::write(root.join("src").join("main.cell"), source).unwrap();

    // First build
    let output1 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output1.status.success(), "stderr: {}", String::from_utf8_lossy(&output1.stderr));
    let summary1: serde_json::Value = serde_json::from_slice(&output1.stdout).unwrap();
    assert_eq!(summary1["status"], "ok");
    // First build should not be a cache hit
    assert_eq!(summary1["cache_hit"], false);

    // Second build (same source, same options)
    let output2 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output2.status.success(), "stderr: {}", String::from_utf8_lossy(&output2.stderr));
    let summary2: serde_json::Value = serde_json::from_slice(&output2.stdout).unwrap();
    assert_eq!(summary2["status"], "ok");
    // Second build should be a cache hit
    assert_eq!(summary2["cache_hit"], true);
}

#[test]
fn cellc_incremental_cache_invalidated_on_source_change() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Set up a minimal package
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "inval_test"
version = "0.1.0"
"#,
    )
    .unwrap();

    let source_v1 = r#"module inval_test
action compute() -> u64 {
    verification
        let x: u64 = 1
        return x
}
"#;
    std::fs::write(root.join("src").join("main.cell"), source_v1).unwrap();

    // Build v1
    let output1 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output1.status.success(), "stderr: {}", String::from_utf8_lossy(&output1.stderr));

    // Modify source
    let source_v2 = r#"module inval_test
action compute() -> u64 {
    verification
        let x: u64 = 2
        return x
}
"#;
    std::fs::write(root.join("src").join("main.cell"), source_v2).unwrap();

    // Build v2 - should NOT be a cache hit since source changed
    let output2 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output2.status.success(), "stderr: {}", String::from_utf8_lossy(&output2.stderr));
    let summary2: serde_json::Value = serde_json::from_slice(&output2.stdout).unwrap();
    assert_eq!(summary2["cache_hit"], false);
}

#[test]
fn cellc_clean_cache_flag_removes_incremental_cache() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Set up a minimal package
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "clean_test"
version = "0.1.0"
"#,
    )
    .unwrap();

    let source = r#"module clean_test
action compute() -> u64 {
    verification
        let x: u64 = 55
        return x
}
"#;
    std::fs::write(root.join("src").join("main.cell"), source).unwrap();

    // Build to populate incremental cache
    let output = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    // Verify cache directory was created
    let cache_dir = root.join(".cell").join("build").join("cache");
    assert!(cache_dir.exists(), "incremental cache directory should exist after build");
    let nested_cache = root.join("examples/nested/.cell/build/cache");
    std::fs::create_dir_all(&nested_cache).unwrap();
    std::fs::write(nested_cache.join("generated"), "cache").unwrap();

    // Clean with --cache flag
    let clean_output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("clean").arg("--cache").arg("--json").output().unwrap();
    assert!(clean_output.status.success(), "stderr: {}", String::from_utf8_lossy(&clean_output.stderr));

    // Verify cache directory was removed
    assert!(!cache_dir.exists(), "incremental cache directory should be removed after clean --cache");
    assert!(!nested_cache.exists(), "clean --cache should remove nested workspace caches");

    // Verify next build is NOT a cache hit
    let output2 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output2.status.success(), "stderr: {}", String::from_utf8_lossy(&output2.stderr));
    let summary2: serde_json::Value = serde_json::from_slice(&output2.stdout).unwrap();
    assert_eq!(summary2["cache_hit"], false, "build after clean --cache should not be a cache hit");
}

#[cfg(unix)]
#[test]
fn cellc_clean_cache_refuses_symlinked_managed_components() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(root.join(".cell")).unwrap();
    std::fs::create_dir_all(outside.join("cache/victim")).unwrap();
    std::fs::write(outside.join("cache/victim/evidence"), "preserve").unwrap();
    symlink(&outside, root.join(".cell/build")).unwrap();

    let output =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(&root).arg("clean").arg("--cache").arg("--json").output().unwrap();

    assert!(!output.status.success(), "clean --cache must reject an intermediate symlink");
    let diagnostic = format!("{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(diagnostic.contains("symlink or non-directory component"), "unexpected diagnostic: {diagnostic}");
    assert!(outside.join("cache/victim/evidence").is_file(), "clean must not escape the workspace");
}

#[test]
fn cellc_entry_action_bypasses_incremental_cache() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Set up a minimal package
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"[package]
edition = "2026"
name = "entry_bypass"
version = "0.1.0"
"#,
    )
    .unwrap();

    let source = r#"module entry_bypass
action compute() -> u64 {
    verification
        let x: u64 = 10
        return x
}
"#;
    std::fs::write(root.join("src").join("main.cell"), source).unwrap();

    // First build (default entry scope)
    let output1 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").arg("--json").output().unwrap();
    assert!(output1.status.success(), "stderr: {}", String::from_utf8_lossy(&output1.stderr));

    // Build with --entry-action: should bypass cache and produce a fresh compile
    let output2 = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("build")
        .arg("--entry-action")
        .arg("compute")
        .arg("--json")
        .output()
        .unwrap();
    assert!(output2.status.success(), "stderr: {}", String::from_utf8_lossy(&output2.stderr));
    let summary2: serde_json::Value = serde_json::from_slice(&output2.stdout).unwrap();
    assert_eq!(summary2["cache_hit"], false, "--entry-action should bypass incremental cache");
}

#[test]
fn cellc_install_rejects_self_path_dependency() {
    // `cellc install --path <self_root>` used to write a `[dependencies.""]` row
    // that turned every subsequent `cellc build` into a circular-dep failure.
    // The cellc install surface must now refuse the self-reference fail-closed.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies]
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let install = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("install").arg("--path").arg(".").output().unwrap();

    assert!(!install.status.success(), "self path install must be rejected");
    let stderr = String::from_utf8_lossy(&install.stderr);
    assert!(
        stderr.contains("refusing to add self-dependency") || stderr.contains("current package root"),
        "expected self-dep refusal, got: {stderr}"
    );

    // Cell.toml must not have gained a dependencies row.
    let manifest_text = std::fs::read_to_string(root.join("Cell.toml")).unwrap();
    let manifest: toml::Value = manifest_text.parse().unwrap();
    let deps = manifest.get("dependencies").and_then(|d| d.as_table()).map(|t| t.len()).unwrap_or(0);
    assert_eq!(deps, 0, "no dependency row should be written for a self path install");
}

#[test]
fn cellc_install_rejects_self_name_dependency() {
    // `cellc install demo --path <somewhere>` where the package's own name is
    // 'demo' must be rejected: a package cannot list itself as a dependency.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies]
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    // Even when the path points somewhere else, an explicit self-name dependency
    // is a logical circular dep and must be rejected.
    let install = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("install")
        .arg("demo")
        .arg("--path")
        .arg("./src")
        .output()
        .unwrap();

    assert!(!install.status.success(), "self name install must be rejected");
    let stderr = String::from_utf8_lossy(&install.stderr);
    assert!(
        stderr.contains("refusing to add self-dependency") && stderr.contains("cannot depend on itself"),
        "expected self-name refusal, got: {stderr}"
    );
}

#[test]
fn cellc_add_rejects_self_name_dependency() {
    // `cellc add` (manifest-mutating, distinct from `cellc install`) shares the
    // same self-dep hazard and must also be fail-closed.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies]
"#,
    )
    .unwrap();

    let add = Command::new(env!("CARGO_BIN_EXE_cellc"))
        .current_dir(root)
        .arg("add")
        .arg("demo")
        .arg("--path")
        .arg("./src")
        .output()
        .unwrap();

    assert!(!add.status.success(), "self name add must be rejected");
    let stderr = String::from_utf8_lossy(&add.stderr);
    assert!(stderr.contains("refusing to add self-dependency"), "expected self-dep refusal, got: {stderr}");
}

#[test]
fn cellc_build_writes_lockfile_deployment_ref_from_deployed_toml() {
    // `cellc build` is the canonical place where Cell.lock gets refreshed.
    // When a Deployed.toml is present, build must bridge its deployment
    // records into the lockfile so that `cellc registry verify` does not
    // always fail with "deployment for network 'X' is missing from Cell.lock".
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies]
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    // First build without Deployed.toml to capture the locked build identity.
    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(build.status.success(), "stderr: {}", String::from_utf8_lossy(&build.stderr));

    let lockfile: cellscript::package::Lockfile = toml::from_str(&std::fs::read_to_string(root.join("Cell.lock")).unwrap()).unwrap();
    assert!(lockfile.package_build.is_some(), "Cell.lock must carry build identity");
    assert!(lockfile.deployment.is_empty(), "no deployment section when Deployed.toml is absent");

    // Now write a Deployed.toml that matches the locked build identity and
    // build again. The lockfile should now carry a [deployment.devnet] entry.
    let artifact_hash = lockfile.package_build.as_ref().unwrap().artifact_hash.as_deref().unwrap();
    let metadata_hash = lockfile.package_build.as_ref().unwrap().metadata_hash.as_deref().unwrap();
    let schema_hash = lockfile.package_build.as_ref().unwrap().schema_hash.as_deref().unwrap();
    let cell_data_codec_manifest_hash = lockfile.package_build.as_ref().unwrap().cell_data_codec_manifest_hash.as_deref().unwrap();
    let abi_hash = lockfile.package_build.as_ref().unwrap().abi_hash.as_deref().unwrap();
    let constraints_hash = lockfile.package_build.as_ref().unwrap().constraints_hash.as_deref().unwrap();
    let compatibility_profile_hash = lockfile.package_build.as_ref().unwrap().compatibility_profile_hash.as_str();
    let source_hash = lockfile.package.source_hash.as_deref().unwrap();
    let compiler_version = lockfile.package_build.as_ref().unwrap().compiler_version.as_deref().unwrap();
    let deployed = format!(
        r#"version = 2
schema = "cellscript-deployed-v0.23-edition-2026"

[package]
edition = "2026"
name = "demo"
version = "0.1.0"
source_hash = "{source_hash}"

[build]
edition = "2026"
compatibility_profile_hash = "{compatibility_profile_hash}"
compiler_version = "{compiler_version}"
artifact_hash = "{artifact_hash}"
metadata_hash = "{metadata_hash}"
schema_hash = "{schema_hash}"
cell_data_codec_manifest_hash = "{cell_data_codec_manifest_hash}"
abi_hash = "{abi_hash}"
constraints_hash = "{constraints_hash}"

[[deployments]]
edition = "2026"
compatibility_profile_hash = "{compatibility_profile_hash}"
name = "demo-mock"
status = "active"
network = "devnet"
chain_id = "ckb-devnet"
tx_hash = "0x0000000000000000000000000000000000000000000000000000000000000001"
output_index = 0
code_hash = "{artifact_hash}"
data_hash = "{artifact_hash}"
hash_type = "data1"
dep_type = "code"
out_point = "0x0000000000000000000000000000000000000000000000000000000000000001:0"
artifact_hash = "{artifact_hash}"
metadata_hash = "{metadata_hash}"
schema_hash = "{schema_hash}"
cell_data_codec_manifest_hash = "{cell_data_codec_manifest_hash}"
abi_hash = "{abi_hash}"
constraints_hash = "{constraints_hash}"
compiler_version = "{compiler_version}"
"#
    );
    std::fs::write(root.join("Deployed.toml"), deployed).unwrap();

    let build2 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(build2.status.success(), "stderr: {}", String::from_utf8_lossy(&build2.stderr));

    let lockfile2: cellscript::package::Lockfile = toml::from_str(&std::fs::read_to_string(root.join("Cell.lock")).unwrap()).unwrap();
    let devnet = lockfile2
        .deployment
        .get("devnet")
        .expect("Cell.lock must carry a [deployment.devnet] entry after build bridges Deployed.toml");
    assert_eq!(devnet.record, "0x0000000000000000000000000000000000000000000000000000000000000001:0");
    assert_eq!(devnet.code_hash.as_deref(), Some(artifact_hash));
    assert_eq!(devnet.data_hash.as_deref(), Some(artifact_hash));
    assert_eq!(devnet.out_point.as_deref(), Some("0x0000000000000000000000000000000000000000000000000000000000000001:0"));
    assert!(devnet.record_hash.is_some(), "record_hash must be computed for build-identity-matching deployment");

    // Finally, registry verify on this clean fixture must succeed.
    let verify =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("registry").arg("verify").arg("--json").output().unwrap();
    assert!(
        verify.status.success(),
        "registry verify must pass after build bridges Deployed.toml: stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["violations"].as_array().map(|a| a.len()).unwrap_or(0), 0);
}

#[test]
fn cellc_build_omits_lockfile_deployment_when_artifact_hash_mismatches() {
    // When the Deployed.toml artifact_hash disagrees with the locked build
    // identity, the deployment ref must be written with hash fields left None
    // so that `registry verify` reports a deterministic build-identity mismatch
    // violation rather than silently agreeing.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cell.toml"),
        r#"
[package]
edition = "2026"
name = "demo"
version = "0.1.0"

[dependencies]
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("src").join("main.cell"),
        r#"
module demo::main

resource Token has store, replace, relock, consume {
    amount: u64,
}

action mint(amount: u64) -> Token {
    verification
        create Token { amount: amount }
}
"#,
    )
    .unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(build.status.success(), "stderr: {}", String::from_utf8_lossy(&build.stderr));

    // Deployed.toml with a wrong artifact_hash. The record field still points
    // at the out_point, but the code/out_point/data/record_hash fields must
    // be left None so the verifier can surface the build-identity mismatch.
    let deployed = r#"version = 2
schema = "cellscript-deployed-v0.23-edition-2026"

[package]
edition = "2026"
name = "demo"
version = "0.1.0"
source_hash = "fake"

[build]
edition = "2026"
compatibility_profile_hash = "mismatched-profile"
compiler_version = "0.17.0"
artifact_hash = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
metadata_hash = "0x00"
schema_hash = "0x00"
abi_hash = "0x00"
constraints_hash = "0x00"

[[deployments]]
edition = "2026"
compatibility_profile_hash = "mismatched-profile"
name = "demo-mock"
status = "active"
network = "devnet"
chain_id = "ckb-devnet"
tx_hash = "0x0000000000000000000000000000000000000000000000000000000000000001"
output_index = 0
code_hash = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
data_hash = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
hash_type = "data1"
dep_type = "code"
out_point = "0x0000000000000000000000000000000000000000000000000000000000000001:0"
artifact_hash = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
"#;
    std::fs::write(root.join("Deployed.toml"), deployed).unwrap();

    let build2 = Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("build").output().unwrap();
    assert!(build2.status.success(), "stderr: {}", String::from_utf8_lossy(&build2.stderr));

    let lockfile: cellscript::package::Lockfile = toml::from_str(&std::fs::read_to_string(root.join("Cell.lock")).unwrap()).unwrap();
    let devnet =
        lockfile.deployment.get("devnet").expect("Cell.lock must still record a deployment ref even when build identity mismatches");
    assert_eq!(devnet.record, "0x0000000000000000000000000000000000000000000000000000000000000001:0");
    assert!(devnet.code_hash.is_none());
    assert!(devnet.out_point.is_none());
    assert!(devnet.data_hash.is_none());
    assert!(devnet.record_hash.is_none());

    let verify =
        Command::new(env!("CARGO_BIN_EXE_cellc")).current_dir(root).arg("registry").arg("verify").arg("--json").output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    let violations = report["violations"].as_array().unwrap();
    // The ref carries no code_hash/out_point/data_hash/record_hash because
    // the build identity did not match, so the verifier must surface at least
    // one of the deterministic "no <field>" violations from the lockfile ref.
    assert!(
        violations.iter().any(|v| {
            let s = v.as_str().unwrap_or("");
            s.contains("has no code_hash")
                || s.contains("has no out_point")
                || s.contains("has no data_hash")
                || s.contains("has no record_hash")
        }),
        "expected a 'has no <hash>' violation from the mismatched ref, got: {violations:?}"
    );
    // Additionally, the top-level build-identity comparison must surface the
    // artifact_hash disagreement.
    assert!(
        violations.iter().any(|v| v.as_str().unwrap_or("").contains("artifact_hash mismatch")),
        "expected artifact_hash mismatch violation, got: {violations:?}"
    );
}
