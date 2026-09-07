use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use crate::crypto::{ckb_blake2b256, hex0x};
use crate::shared::stable_json_pretty;

const SCHEMA: &str = "novaseal-fiber-node-execution-v0.4";
const PREVIOUS_SCHEMAS: &[&str] =
    &["novaseal-fiber-node-execution-v0.1", "novaseal-fiber-node-execution-v0.2", "novaseal-fiber-node-execution-v0.3", SCHEMA];

struct Workflow {
    suite: &'static str,
    category: &'static str,
    description: &'static str,
    profiles: &'static [&'static str],
    terms: &'static [&'static str],
    requires_lnd: bool,
}

const WORKFLOWS: &[Workflow] = &[
    Workflow {
        suite: "open-use-close-a-channel",
        category: "channel-lifecycle",
        description: "single-channel open, TLC add/remove, cooperative shutdown, and closed-state checks",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["open-channel", "add-tlc", "remove-tlc", "shutdown", "list-channel"],
        requires_lnd: false,
    },
    Workflow {
        suite: "3-nodes-transfer",
        category: "multi-hop-transfer",
        description: "three-node channel graph with routed TLC transfer and shutdown",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["connect", "open-channel", "add-tlc", "remove-tlc", "shutdown"],
        requires_lnd: false,
    },
    Workflow {
        suite: "router-pay",
        category: "multi-hop-payment",
        description: "router payment workflow with invoice, keysend, graph, duplicate, and failure paths",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["send-payment", "gen-invoice", "get-payment-status", "list-graph", "will-fail"],
        requires_lnd: false,
    },
    Workflow {
        suite: "invoice-ops",
        category: "invoice",
        description: "invoice generation, duplicate rejection, decode, lookup, and cancellation",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["gen-invoice", "duplicate", "decode", "get-invoice", "cancel"],
        requires_lnd: false,
    },
    Workflow {
        suite: "shutdown-force",
        category: "force-close",
        description: "force shutdown after peer disconnect and closed-channel assertions",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["shutdown-force", "disconnect", "closed-channel", "trigger-check"],
        requires_lnd: false,
    },
    Workflow {
        suite: "reestablish",
        category: "reconnect",
        description: "channel reestablishment after disconnect before TLC removal and shutdown",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["disconnect", "reconnect", "remove-tlc", "shutdown"],
        requires_lnd: false,
    },
    Workflow {
        suite: "external-funding-open",
        category: "external-funding",
        description: "external funding script, signing, submission, channel ready, shutdown, and balance checks",
        profiles: &["fiber-candidate-profile-v0", "btc-transaction-commitment-profile-v0"],
        terms: &["funding-script", "external-funding", "sign", "submit", "balance-after"],
        requires_lnd: false,
    },
    Workflow {
        suite: "funding-tx-verification",
        category: "funding-verification",
        description: "funding transaction verification with a shell builder and auto-accepted channel check",
        profiles: &["fiber-candidate-profile-v0", "btc-transaction-commitment-profile-v0"],
        terms: &["funding-tx", "verification", "open-channel", "auto-accepted"],
        requires_lnd: false,
    },
    Workflow {
        suite: "udt",
        category: "udt-channel",
        description: "UDT channel open, invoice/TLC flow, invalid open, manual accept, and shutdown",
        profiles: &["fiber-candidate-profile-v0", "fungible-xudt-profile-v0"],
        terms: &["udt", "open-channel", "add-tlc", "remove-tlc", "invalid", "shutdown"],
        requires_lnd: false,
    },
    Workflow {
        suite: "udt-router-pay",
        category: "udt-routing",
        description: "multi-hop routed UDT payment including invoice and keysend paths",
        profiles: &["fiber-candidate-profile-v0", "fungible-xudt-profile-v0"],
        terms: &["udt", "router", "send-payment", "gen-invoice", "keysend"],
        requires_lnd: false,
    },
    Workflow {
        suite: "watchtower/force-close-after-open-channel",
        category: "watchtower",
        description: "watchtower force-close settlement after opening a channel",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["force-close", "commitment-tx", "settlement", "check-balance"],
        requires_lnd: false,
    },
    Workflow {
        suite: "watchtower/force-close-with-pending-tlcs",
        category: "watchtower",
        description: "force-close with pending TLCs, settlement transaction generation, and balance checks",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["pending-tlcs", "force-close", "settlement", "commitment-tx", "check-balance"],
        requires_lnd: false,
    },
    Workflow {
        suite: "watchtower/force-close-with-pending-tlcs-and-udt",
        category: "watchtower-udt",
        description: "force-close with pending UDT TLCs and CKB/UDT balance checks",
        profiles: &["fiber-candidate-profile-v0", "fungible-xudt-profile-v0"],
        terms: &["pending-tlcs", "udt", "force-close", "settlement", "check-balance"],
        requires_lnd: false,
    },
    Workflow {
        suite: "watchtower/force-close-preimage-multiple",
        category: "watchtower-preimage",
        description: "multiple preimage settlement path after force-close",
        profiles: &["fiber-candidate-profile-v0"],
        terms: &["preimage", "force-close", "settlement", "check-balance"],
        requires_lnd: false,
    },
    Workflow {
        suite: "cross-chain-hub",
        category: "cross-chain",
        description: "Fiber plus Lightning/BTC hub send and receive order workflow",
        profiles: &["fiber-candidate-profile-v0", "btc-transaction-commitment-profile-v0", "btc-utxo-seal-profile-v0"],
        terms: &["btc", "lnd", "send-payment", "order", "wrapped-btc", "shutdown"],
        requires_lnd: true,
    },
    Workflow {
        suite: "cross-chain-hub-separate",
        category: "cross-chain",
        description: "Fiber plus Lightning/BTC hub workflow with CCH running as a separate service",
        profiles: &["fiber-candidate-profile-v0", "btc-transaction-commitment-profile-v0", "btc-utxo-seal-profile-v0"],
        terms: &["btc", "lnd", "send-payment", "order", "wrapped-btc", "shutdown"],
        requires_lnd: true,
    },
];

fn git_value(repo: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).current_dir(repo).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn provenance(repo: &Path) -> Value {
    let tracked_dirty = git_value(repo, &["status", "--short", "--untracked-files=no"]).is_some_and(|value| !value.is_empty());
    json!({
        "path": repo.to_string_lossy().replace('\\', "/"),
        "origin": git_value(repo, &["remote", "get-url", "origin"]),
        "branch": git_value(repo, &["branch", "--show-current"]),
        "commit": git_value(repo, &["rev-parse", "HEAD"]),
        "dirty": git_value(repo, &["status", "--short"]).is_some_and(|value| !value.is_empty()),
        "tracked_dirty": tracked_dirty,
    })
}

fn same_provenance(left: Option<&Value>, right: &Value) -> bool {
    left.and_then(Value::as_object)
        .is_some_and(|left| ["path", "origin", "branch", "commit", "dirty"].iter().all(|key| left.get(*key) == right.get(*key)))
}

fn same_tracked_provenance(left: &Value, right: &Value) -> bool {
    ["path", "origin", "branch", "commit", "tracked_dirty"].iter().all(|key| left.get(*key) == right.get(*key))
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

fn suite_files(repo: &Path, suite: &str) -> Vec<PathBuf> {
    let directory = repo.join("tests/bruno/e2e").join(suite);
    let mut files = fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "bru"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn rpc_methods(files: &[PathBuf]) -> Vec<String> {
    let mut methods = BTreeSet::new();
    for path in files {
        let Ok(text) = fs::read_to_string(path) else { continue };
        for line in text.lines().filter(|line| line.contains("\"method\"")) {
            let after = line.split_once(':').map_or("", |(_, value)| value).trim().trim_end_matches(',').trim();
            if after.starts_with('"') && after.ends_with('"') {
                methods.insert(after.trim_matches('"').to_owned());
            }
        }
    }
    methods.into_iter().collect()
}

fn workflow_report(repo: &Path, workflow: &Workflow, execution: Option<&Value>) -> Value {
    let files = suite_files(repo, workflow.suite);
    let names = files.iter().map(|path| path.to_string_lossy().to_lowercase()).collect::<Vec<_>>().join(" ");
    let terms =
        workflow.terms.iter().map(|term| ((*term).to_owned(), json!(names.contains(&term.to_lowercase())))).collect::<Map<_, _>>();
    let present = !files.is_empty() && terms.values().all(|value| value == true);
    json!({
        "suite": workflow.suite, "category": workflow.category, "description": workflow.description,
        "mapped_profiles": workflow.profiles, "requires_lnd": workflow.requires_lnd,
        "status": execution.and_then(|value| value["status"].as_str()).unwrap_or(if present { "present" } else { "missing" }),
        "present": present, "step_count": files.len(), "expected_terms": terms, "rpc_methods": rpc_methods(&files),
        "evidence_files": files.iter().map(|path| relative(path, repo)).collect::<Vec<_>>(),
        "execution": execution.cloned().unwrap_or(Value::Null),
    })
}

fn previous(
    output: &Path,
    current: &Value,
    cellscript: &Value,
    artifact: &Value,
    execution_toolchain: &Value,
) -> BTreeMap<String, Value> {
    let Ok(bytes) = fs::read(output) else { return BTreeMap::new() };
    let Ok(report) = serde_json::from_slice::<Value>(&bytes) else { return BTreeMap::new() };
    if !report["schema"].as_str().is_some_and(|schema| PREVIOUS_SCHEMAS.contains(&schema))
        || !same_provenance(report.get("fiber_repo"), current)
        || !same_provenance(report.get("cellscript_repo"), cellscript)
        || report.get("cellscript_fungible_artifact") != Some(artifact)
        || report.get("execution_toolchain") != Some(execution_toolchain)
    {
        return BTreeMap::new();
    }
    report["workflows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let suite = row["suite"].as_str()?;
            let execution = row.get("execution")?;
            (execution.is_object() && same_provenance(execution.get("fiber_repo"), current))
                .then(|| (suite.to_owned(), execution.clone()))
        })
        .collect()
}

struct TemporaryContractOverride {
    target: PathBuf,
    original: Vec<u8>,
    restored: bool,
}

impl TemporaryContractOverride {
    fn install(repo: &Path, artifact: &Path) -> Result<Self> {
        let target = repo.join("tests/deploy/contracts/simple_udt");
        let original = fs::read(&target).with_context(|| format!("read Fiber dev contract {}", target.display()))?;
        let replacement = fs::read(artifact).with_context(|| format!("read CellScript fungible artifact {}", artifact.display()))?;
        fs::write(&target, replacement)
            .with_context(|| format!("temporarily install CellScript fungible artifact at {}", target.display()))?;
        Ok(Self { target, original, restored: false })
    }

    fn restore(&mut self) -> Result<()> {
        if !self.restored {
            fs::write(&self.target, &self.original)
                .with_context(|| format!("restore Fiber dev contract {}", self.target.display()))?;
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for TemporaryContractOverride {
    fn drop(&mut self) {
        if !self.restored {
            let _ = fs::write(&self.target, &self.original);
        }
    }
}

fn artifact_binding(repo_root: &Path, artifact: Option<&Path>) -> Result<Value> {
    let Some(artifact) = artifact else { return Ok(Value::Null) };
    let metadata =
        fs::symlink_metadata(artifact).with_context(|| format!("inspect CellScript fungible artifact {}", artifact.display()))?;
    if !metadata.file_type().is_file() {
        bail!("CellScript fungible artifact must be a regular, non-symlink file: {}", artifact.display());
    }
    let artifact = fs::canonicalize(artifact)?;
    let bytes = fs::read(&artifact)?;
    if !bytes.starts_with(b"\x7fELF") {
        bail!("CellScript fungible artifact is not an ELF file: {}", artifact.display());
    }
    Ok(json!({
        "path": relative(&artifact, repo_root),
        "size_bytes": bytes.len(),
        "sha256": format!("0x{}", hex::encode(Sha256::digest(&bytes))),
        "ckb_data_hash": hex0x(&ckb_blake2b256(&bytes)?),
        "fiber_dev_contract_slot": "tests/deploy/contracts/simple_udt",
        "hash_type": "data2",
        "temporary_install_restored": true,
    }))
}

fn which(name: &str) -> Option<String> {
    env::var_os("PATH")
        .and_then(|paths| env::split_paths(&paths).map(|path| path.join(name)).find(|path| path.is_file()))
        .map(|path| path.to_string_lossy().into_owned())
}

fn version(name: &str) -> Option<String> {
    let output = Command::new(name).arg("--version").output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn command_with_timeout(mut command: Command, timeout: Duration) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if child.wait_timeout(timeout)?.is_none() {
        let _ = child.kill();
    }
    Ok(child.wait_with_output()?)
}

fn cleanup(repo: &Path, all: bool) {
    let escaped = regex::escape(&repo.to_string_lossy());
    let mut patterns = vec![
        Regex::new(r"\.\./\.\./target/[^ ]*/fnn -d (?:[123]|cch)(?:\s|$)").unwrap(),
        Regex::new(&format!(r"ckb run -C {escaped}/tests/deploy/node-data")).unwrap(),
        Regex::new(&format!(r"bitcoind -conf={escaped}/tests/deploy/lnd-init/bitcoind/bitcoin\.conf")).unwrap(),
        Regex::new(&format!(r"lnd --lnddir={escaped}/tests/deploy/lnd-init/lnd-(?:bob|ingrid)")).unwrap(),
    ];
    if all {
        patterns.push(Regex::new(r"bash \./tests/nodes/start\.sh e2e/").unwrap());
    }
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,command="]).output() else { return };
    let mut pids = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((pid, command)) = line.trim().split_once(char::is_whitespace) else { continue };
        let Ok(pid) = pid.parse::<u32>() else { continue };
        if pid != std::process::id() && patterns.iter().any(|pattern| pattern.is_match(command.trim())) {
            let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).status();
            pids.push(pid);
        }
    }
    thread::sleep(Duration::from_secs(2));
    for pid in pids {
        let _ = Command::new("kill").args(["-KILL", &pid.to_string()]).status();
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_name() == "node_modules" {
            continue;
        }
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn bruno_workspace(repo: &Path, suite: &str, log: &Path) -> Result<(PathBuf, Vec<String>)> {
    if !matches!(
        suite,
        "udt-router-pay" | "watchtower/force-close-with-pending-tlcs-and-udt" | "cross-chain-hub" | "cross-chain-hub-separate"
    ) {
        return Ok((repo.join("tests/bruno"), vec![]));
    }
    let workspace = log.join("bruno-worktree");
    if workspace.exists() {
        fs::remove_dir_all(&workspace)?;
    }
    copy_tree(&repo.join("tests/bruno"), &workspace)?;
    let mut replacements = Vec::new();
    if suite == "udt-router-pay" {
        // Bruno can strand this collection in the two final post-response
        // scripts even after Fiber has returned the response. Express their
        // checks through Bruno's declarative assertion engine instead. The
        // requests, expected rejection, balance values, and all pre-request
        // synchronization remain unchanged.
        replacements.extend([
            (
                "script:post-response {\n  // Sleep for sometime to make sure current operation finishes before next request starts.\n  await new Promise(r => setTimeout(r, 100));\n  console.log(\"send payment result: \", res.body);\n}\n"
                    .into(),
                String::new(),
            ),
            (
                "assert {\n  res.status: eq 200\n}\n\nscript:post-response {\n  await new Promise(r => setTimeout(r, 1000));\n  console.log(\"step 17 list channels: \", res.body.result.channels[0]);\n  // step 12: 100000000\n  // step 14: 32\n  // step 15: 48\n  // sum is: 100000080 (0x5f5e150)\n  if (res.body.result.channels[0].remote_balance != \"0x5f5e150\" || res.body.result.channels[0].local_balance != \"0x35a4e8b0\") {\n    throw new Error(\"Assertion failed: channel amount is not right\");\n  }\n}\n"
                    .into(),
                "assert {\n  res.status: eq 200\n  res.body.result.channels[0].remote_balance: eq \"0x5f5e150\"\n  res.body.result.channels[0].local_balance: eq \"0x35a4e8b0\"\n}\n"
                    .into(),
            ),
        ]);
    }
    if suite == "watchtower/force-close-with-pending-tlcs-and-udt" {
        for name in ["NODE1_BALANCE", "NODE2_BALANCE", "NODE1_NEW_BALANCE", "NODE2_NEW_BALANCE"] {
            replacements.push((format!("bru.setVar(\"{name}\", capacity);"), format!("bru.setVar(\"{name}\", capacity.toString());")));
        }
    }
    if matches!(suite, "cross-chain-hub" | "cross-chain-hub-separate") {
        replacements.extend([
            ("bru.setVar(\"FIBER_PAY_REQ\", res.body.result.invoice_address);\n  bru.setVar(\"PAYMENT_HASH\", res.body.result.invoice.data.payment_hash);".into(), "bru.setVar(\"FIBER_PAY_REQ\", res.body.result.invoice_address);\n  bru.setVar(\"PAYMENT_HASH\", res.body.result.invoice.data.payment_hash);\n  console.log(\"receive_fiber_pay_req\", res.body.result.invoice_address);\n  console.log(\"receive_payment_hash\", res.body.result.invoice.data.payment_hash);".into()),
            ("if (resp.data !== undefined) {\n    resp.data.destroy();\n  }".into(), "if (resp.data !== undefined && typeof resp.data.destroy === \"function\") {\n    resp.data.destroy();\n  }".into()),
        ]);
    }
    let mut patched = Vec::new();
    for path in suite_files(&workspace.parent().unwrap().join("bruno-worktree/.."), suite) {
        let _ = path;
    }
    let suite_dir = workspace.join("e2e").join(suite);
    for entry in fs::read_dir(suite_dir).ok().into_iter().flatten().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_none_or(|value| value != "bru") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let updated = replacements.iter().fold(text.clone(), |text, (old, new)| text.replace(old, new));
        if updated != text {
            fs::write(&path, updated)?;
            patched.push(relative(&path, &workspace));
        }
    }
    patched.sort();
    Ok((workspace, patched))
}

fn bruno_command(suite_arg: &str, artifact_hash: Option<&str>, bruno_cli: &str, bruno_sandbox: &str) -> Vec<String> {
    let mut command = vec![
        "npm".into(),
        "exec".into(),
        "--".into(),
        bruno_cli.into(),
        "run".into(),
        suite_arg.into(),
        "-r".into(),
        "--env".into(),
        "test".into(),
        "--sandbox".into(),
        bruno_sandbox.into(),
    ];
    if let Some(artifact_hash) = artifact_hash {
        command.extend(["--env-var".into(), format!("UDT_CODE_HASH={artifact_hash}")]);
    }
    command
}

fn stop(child: &mut Child) {
    let _ = Command::new("kill").args(["-TERM", &child.id().to_string()]).status();
    if child.wait_timeout(Duration::from_secs(20)).ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_workflow(
    repo_root: &Path,
    repo: &Path,
    output: &Path,
    workflow: &Workflow,
    assume: bool,
    timeout: u64,
    info: &Value,
    artifact_hash: Option<&str>,
    bruno_cli: &str,
    bruno_sandbox: &str,
) -> Result<Value> {
    let suite_arg = format!("e2e/{}", workflow.suite);
    let log = output.parent().unwrap().join("novaseal-fiber-node-experiments").join(workflow.suite.replace('/', "__"));
    fs::create_dir_all(&log)?;
    let environment = env::vars().collect::<HashMap<_, _>>();
    let clean = environment.contains_key("REMOVE_OLD_STATE") || environment.contains_key("NOVASEAL_CLEAN_FIBER_DEVNET_PROCESSES");
    let started = Instant::now();
    let mut node = None;
    if !assume {
        cleanup(repo, clean);
        let file = File::create(log.join("start-node.log"))?;
        node = Some(
            Command::new("./tests/nodes/start.sh")
                .arg(&suite_arg)
                .current_dir(repo)
                .stdout(Stdio::from(file.try_clone()?))
                .stderr(Stdio::from(file))
                .envs(&environment)
                .spawn()?,
        );
        let wait = command_with_timeout(
            {
                let mut command = Command::new("./tests/nodes/wait.sh");
                command.current_dir(repo).envs(&environment);
                command
            },
            Duration::from_secs(timeout),
        )?;
        fs::write(log.join("wait.stdout"), &wait.stdout)?;
        fs::write(log.join("wait.stderr"), &wait.stderr)?;
        if !wait.status.success() || node.as_mut().is_some_and(|child| child.try_wait().ok().flatten().is_some()) {
            if let Some(child) = node.as_mut() {
                stop(child);
            }
            return Ok(json!({"status": "failed", "started_node": true, "command": ["./tests/nodes/start.sh", suite_arg],
                "duration_seconds": ((started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0), "fiber_repo": info,
                "failure": "fiber node wait failed", "wait_returncode": wait.status.code()}));
        }
    }
    let (bruno, patches) = bruno_workspace(repo, workflow.suite, &log)?;
    let command = bruno_command(&suite_arg, artifact_hash, bruno_cli, bruno_sandbox);
    let completed = command_with_timeout(
        {
            let mut value = Command::new(&command[0]);
            value.args(&command[1..]).current_dir(&bruno).envs(&environment);
            value
        },
        Duration::from_secs(timeout),
    )?;
    fs::write(log.join("bruno.stdout"), &completed.stdout)?;
    fs::write(log.join("bruno.stderr"), &completed.stderr)?;
    let mut execution = json!({
        "status": if completed.status.success() { "passed" } else { "failed" }, "started_node": !assume,
        "command": command, "returncode": completed.status.code().unwrap_or(-1),
        "noninteractive_ckb_cli_account_import_wrapper": log.join("tool-bin/ckb-cli").is_file(),
        "stdout_log": relative(&log.join("bruno.stdout"), repo_root), "stderr_log": relative(&log.join("bruno.stderr"), repo_root),
        "duration_seconds": ((started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0), "fiber_repo": info,
    });
    if !patches.is_empty() {
        execution["bruno_cwd"] = json!(relative(&bruno, repo_root));
        execution["bruno_compatibility_patches"] = json!(patches);
    }
    if let Some(child) = node.as_mut() {
        stop(child);
        cleanup(repo, clean);
    }
    Ok(execution)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    repo_root: &Path,
    fiber_repo: Option<&Path>,
    cellscript_fungible_artifact: Option<&Path>,
    bruno_cli: &str,
    bruno_sandbox: &str,
    output: Option<&Path>,
    pretty: bool,
    suites: &[String],
    run_all: bool,
    assume: bool,
    timeout: u64,
) -> Result<i32> {
    let repo_root = fs::canonicalize(repo_root)?;
    let fiber_repo = fiber_repo.map(Path::to_path_buf).unwrap_or_else(|| repo_root.parent().unwrap().join("fiber"));
    let fiber_repo = fs::canonicalize(&fiber_repo).unwrap_or(fiber_repo);
    let output = output.map(Path::to_path_buf).unwrap_or_else(|| repo_root.join("target/novaseal-fiber-node-experiments.json"));
    let allowed = WORKFLOWS.iter().map(|workflow| workflow.suite).collect::<BTreeSet<_>>();
    let exact_bruno = Regex::new(r"^@usebruno/cli@[0-9]+\.[0-9]+\.[0-9]+$").unwrap();
    if !exact_bruno.is_match(bruno_cli) {
        bail!("Bruno CLI must be an exact @usebruno/cli MAJOR.MINOR.PATCH package version");
    }
    if !matches!(bruno_sandbox, "safe" | "developer") {
        bail!("Bruno sandbox must be either safe or developer");
    }
    if let Some(invalid) = suites.iter().find(|suite| !allowed.contains(suite.as_str())) {
        bail!("unknown Fiber suite: {invalid}");
    }
    let selected = if run_all {
        allowed.iter().map(|value| (*value).to_owned()).collect::<BTreeSet<_>>()
    } else {
        suites.iter().cloned().collect()
    };
    let info = provenance(&fiber_repo);
    let cellscript_info = provenance(&repo_root);
    if cellscript_fungible_artifact.is_some() && assume {
        bail!("a temporary CellScript artifact cannot be installed when --assume-nodes-running is used");
    }
    if cellscript_fungible_artifact.is_some() && selected.is_empty() {
        bail!("a CellScript fungible artifact requires --run-suite or --run-all");
    }
    if cellscript_fungible_artifact.is_some() && info["dirty"] != false {
        bail!("Fiber checkout must be clean before temporarily installing a CellScript artifact");
    }
    if cellscript_fungible_artifact.is_some() && cellscript_info["dirty"] != false {
        bail!("CellScript checkout must be clean before recording live Fiber artifact evidence");
    }
    let artifact = artifact_binding(&repo_root, cellscript_fungible_artifact)?;
    let artifact_hash = artifact.get("ckb_data_hash").and_then(Value::as_str);
    let execution_toolchain = json!({
        "bruno_cli": bruno_cli,
        "bruno_sandbox": bruno_sandbox,
        "node": version("node"),
        "npm": version("npm"),
        "ckb": version("ckb"),
        "ckb_cli": version("ckb-cli"),
    });
    let mut executions = previous(&output, &info, &cellscript_info, &artifact, &execution_toolchain);
    let mut contract_override =
        cellscript_fungible_artifact.map(|path| TemporaryContractOverride::install(&fiber_repo, path)).transpose()?;
    for workflow in WORKFLOWS.iter().filter(|workflow| selected.contains(workflow.suite)) {
        executions.insert(
            workflow.suite.into(),
            execute_workflow(
                &repo_root,
                &fiber_repo,
                &output,
                workflow,
                assume,
                timeout,
                &info,
                artifact_hash,
                bruno_cli,
                bruno_sandbox,
            )?,
        );
    }
    let mut restored_info = info.clone();
    if let Some(contract_override) = contract_override.as_mut() {
        contract_override.restore()?;
        restored_info = provenance(&fiber_repo);
        if !same_tracked_provenance(&restored_info, &info) {
            bail!("tracked Fiber checkout state changed after restoring the temporary CellScript artifact");
        }
    }
    let workflows =
        WORKFLOWS.iter().map(|workflow| workflow_report(&fiber_repo, workflow, executions.get(workflow.suite))).collect::<Vec<_>>();
    let present = workflows.iter().filter(|row| row["present"] == true).count();
    let executed = workflows.iter().filter(|row| row["execution"].is_object()).count();
    let passed = workflows.iter().filter(|row| row["execution"]["status"] == "passed").count();
    let all_present = present == WORKFLOWS.len();
    let all_executed = executed == WORKFLOWS.len();
    let all_passed = all_executed && passed == WORKFLOWS.len();
    let partial = executed > 0 && executed < WORKFLOWS.len() && executed == passed;
    let runnable =
        ["tests/nodes/start.sh", "tests/nodes/wait.sh", "package.json", "tests/bruno/bruno.json", "docs/dev/README.md", "Cargo.lock"]
            .iter()
            .all(|path| fiber_repo.join(path).is_file());
    let status = if !fiber_repo.is_dir() {
        "missing_fiber_clone"
    } else if all_passed {
        "passed"
    } else if executed > 0 && passed != executed {
        "failed"
    } else if partial {
        "partial_execution_passed"
    } else if all_present && runnable {
        "discovery_ready_live_not_run"
    } else {
        "incomplete"
    };
    let profiles = WORKFLOWS.iter().flat_map(|workflow| workflow.profiles).copied().collect::<BTreeSet<_>>();
    let generated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = json!({
        "schema": SCHEMA, "status": status, "generated_at_unix": generated, "classification": "fiber_node_execution_v0",
        "cellscript_repo": cellscript_info, "fiber_repo": info, "fiber_repo_after_restore": restored_info,
        "cellscript_fungible_artifact": artifact,
        "execution_toolchain": execution_toolchain,
        "devnet_contract": {"runnable_devnet_contract_present": runnable, "start_command": "./tests/nodes/start.sh e2e/<suite>",
            "wait_command": "./tests/nodes/wait.sh", "bruno_command": format!("cd tests/bruno && npm exec -- {bruno_cli} run e2e/<suite> -r --env test --sandbox {bruno_sandbox}"), "source_docs": "docs/dev/README.md"},
        "workflow_coverage": {"required_count": WORKFLOWS.len(), "present_count": present, "executed_count": executed,
            "passed_execution_count": passed, "all_required_workflows_present": all_present, "all_required_workflows_executed": all_executed,
            "all_required_workflows_executed_passed": all_passed, "partial_execution_passed": partial},
        "profiles_covered": profiles, "workflows": workflows,
        "acceptance_boundary": {"discovery_ready_live_not_run": "the Fiber clone exposes the expected devnet/e2e workflow surface, but no live Fiber node execution is claimed",
            "passed": "all required Fiber workflow suites were executed through Fiber's devnet node runner and Bruno e2e harness",
            "partial_execution_passed": "at least one selected Fiber workflow suite was executed and passed, but complete Fiber coverage is not claimed",
            "novaseal_mapping": "NovaSeal consumes this as external Fiber-node evidence; it does not replace NovaSeal's own CKB stateful profile reports"},
        "generated_by": {"module": "crates/cellscript-tools/src/fiber_experiments.rs", "implementation": "cellscript_tools::fiber_experiments"},
        "tooling": {"npm": which("npm"), "cargo": which("cargo"), "ckb": which("ckb"), "ckb_cli": which("ckb-cli")}
    });
    fs::create_dir_all(output.parent().context("output path has no parent")?)?;
    let text = if pretty { stable_json_pretty(&report)? } else { serde_json::to_string(&report)? };
    fs::write(&output, format!("{}\n", text.trim_end_matches('\n')))?;
    println!("{}", output.display());
    Ok(if matches!(status, "missing_fiber_clone" | "incomplete" | "failed") { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRUNO_CLI: &str = "@usebruno/cli@1.20.0";

    fn test_root(name: &str) -> PathBuf {
        env::temp_dir().join(format!("cellscript-fiber-experiments-{name}-{}", std::process::id()))
    }

    #[test]
    fn temporary_contract_override_restores_explicitly_and_on_drop() {
        let root = test_root("restore");
        let contract_dir = root.join("fiber/tests/deploy/contracts");
        fs::create_dir_all(&contract_dir).unwrap();
        let target = contract_dir.join("simple_udt");
        let artifact = root.join("cellscript.elf");
        fs::write(&target, b"original").unwrap();
        fs::write(&artifact, b"replacement").unwrap();

        {
            let mut guard = TemporaryContractOverride::install(&root.join("fiber"), &artifact).unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"replacement");
            guard.restore().unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"original");
        }
        {
            let _guard = TemporaryContractOverride::install(&root.join("fiber"), &artifact).unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"replacement");
        }
        assert_eq!(fs::read(&target).unwrap(), b"original");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prior_execution_requires_the_exact_cellscript_artifact_binding() {
        let root = test_root("binding");
        fs::create_dir_all(&root).unwrap();
        let output = root.join("report.json");
        let provenance = json!({"path":"fiber", "origin":"origin", "branch":"develop", "commit":"abc", "dirty":false});
        let artifact = json!({"ckb_data_hash":"0x01"});
        let toolchain =
            json!({"bruno_cli": BRUNO_CLI, "bruno_sandbox": "safe", "node": "v20", "npm": "10", "ckb": "0.202", "ckb_cli": "1.15"});
        fs::write(
            &output,
            serde_json::to_vec(&json!({
                "schema": SCHEMA,
                "fiber_repo": provenance,
                "cellscript_repo": provenance,
                "cellscript_fungible_artifact": artifact,
                "execution_toolchain": toolchain,
                "workflows": [{"suite":"udt-router-pay", "execution":{"status":"passed", "fiber_repo": provenance}}],
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(previous(&output, &provenance, &provenance, &artifact, &toolchain).len(), 1);
        assert!(previous(&output, &provenance, &provenance, &json!({"ckb_data_hash":"0x02"}), &toolchain).is_empty());
        let changed_cellscript = json!({"path":"cellscript", "origin":"origin", "branch":"0.26b", "commit":"def", "dirty":false});
        assert!(previous(&output, &provenance, &changed_cellscript, &artifact, &toolchain).is_empty());
        let changed_toolchain = json!({"bruno_cli": "@usebruno/cli@4.1.0"});
        assert!(previous(&output, &provenance, &provenance, &artifact, &changed_toolchain).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_bruno_command_is_version_pinned_and_binds_the_artifact_hash() {
        let command = bruno_command("e2e/udt", Some("0x1234"), BRUNO_CLI, "developer");
        assert_eq!(
            command,
            [
                "npm",
                "exec",
                "--",
                "@usebruno/cli@1.20.0",
                "run",
                "e2e/udt",
                "-r",
                "--env",
                "test",
                "--sandbox",
                "developer",
                "--env-var",
                "UDT_CODE_HASH=0x1234",
            ]
        );

        let before = json!({
            "path": "fiber", "origin": "origin", "branch": "develop", "commit": "abc",
            "dirty": false, "tracked_dirty": false,
        });
        let after = json!({
            "path": "fiber", "origin": "origin", "branch": "develop", "commit": "abc",
            "dirty": true, "tracked_dirty": false,
        });
        assert!(same_tracked_provenance(&before, &after));
    }
}
