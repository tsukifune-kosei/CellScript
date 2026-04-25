use crate::docgen::{DocGenerator, OutputFormat};
use crate::error::Result;
use crate::fmt::format_default;
use crate::package::{Dependency, DetailedDependency, Lockfile, PackageManager, PolicyConfig};
use crate::{
    compile_path, compile_path_with_entry_action, compile_path_with_entry_lock, default_metadata_path_for_artifact,
    default_output_path_for_input, load_modules_for_input, resolve_input_path, validate_artifact_metadata,
    validate_source_units_on_disk, ArtifactFormat, CompileMetadata, CompileOptions, EntryWitnessArg, ParamMetadata, TargetProfile,
    ENTRY_WITNESS_ABI,
};
use camino::Utf8Path;
#[cfg(feature = "vm-runner")]
use ckb_vm::{
    cost_model::estimate_cycles, machine::VERSION2, Bytes, DefaultCoreMachine, DefaultMachineBuilder, DefaultMachineRunner,
    SparseMemory, SupportMachine, TraceMachine, WXorXMemory, ISA_B, ISA_IMC, ISA_MOP,
};
use colored::Colorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum Command {
    Build(BuildArgs),
    Test(TestArgs),
    Doc(DocArgs),
    Fmt(FmtArgs),
    Init(InitArgs),
    Add(AddArgs),
    Remove(RemoveArgs),
    Clean(CleanArgs),
    Repl,
    Check(CheckArgs),
    Metadata(MetadataArgs),
    Constraints(ConstraintsArgs),
    Abi(AbiArgs),
    SchedulerPlan(SchedulerPlanArgs),
    CkbHash(CkbHashArgs),
    OptReport(OptReportArgs),
    /// Encode generated entry wrapper witness bytes
    EntryWitness(EntryWitnessArgs),
    VerifyArtifact(VerifyArtifactArgs),
    Run(RunArgs),
    Publish(PublishArgs),
    Install(InstallArgs),
    Update,
    Info(InfoArgs),
    Login(LoginArgs),
}

#[derive(Debug, Default)]
pub struct BuildArgs {
    pub release: bool,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub entry_action: Option<String>,
    pub entry_lock: Option<String>,
    pub jobs: Option<usize>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub verbose: bool,
    pub json: bool,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_symbolic_runtime: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
}

#[derive(Debug, Default)]
pub struct TestArgs {
    pub filter: Option<String>,
    pub jobs: Option<usize>,
    pub release: bool,
    pub no_run: bool,
    pub nocapture: bool,
    pub fail_fast: bool,
    pub doc: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct DocArgs {
    pub open: bool,
    pub no_deps: bool,
    pub document_private_items: bool,
    pub output_format: OutputFormat,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct FmtArgs {
    pub check: bool,
    pub json: bool,
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Default)]
pub struct InitArgs {
    pub name: Option<String>,
    pub path: Option<PathBuf>,
    pub lib: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct AddArgs {
    pub crates: Vec<String>,
    pub dev: bool,
    pub build: bool,
    pub git: Option<String>,
    pub path: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct RemoveArgs {
    pub crates: Vec<String>,
    pub dev: bool,
    pub build: bool,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct CleanArgs {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct InfoArgs {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct CheckArgs {
    pub all_targets: bool,
    pub target_profile: Option<String>,
    pub features: Vec<String>,
    pub json: bool,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_symbolic_runtime: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
}

#[derive(Debug, Default)]
pub struct MetadataArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

#[derive(Debug, Default)]
pub struct ConstraintsArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub entry_action: Option<String>,
    pub entry_lock: Option<String>,
}

#[derive(Debug, Default)]
pub struct AbiArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub action: Option<String>,
    pub lock: Option<String>,
}

#[derive(Debug, Default)]
pub struct SchedulerPlanArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

#[derive(Debug, Default)]
pub struct CkbHashArgs {
    pub input: Option<String>,
    pub hex: Option<String>,
    pub file: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct OptReportArgs {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
}

/// Entry witness encoding arguments
#[derive(Debug, Default)]
pub struct EntryWitnessArgs {
    pub input: Option<PathBuf>,
    pub action: Option<String>,
    pub lock: Option<String>,
    pub args: Vec<String>,
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub target_profile: Option<String>,
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct VerifyArtifactArgs {
    pub artifact: PathBuf,
    pub metadata: Option<PathBuf>,
    pub verify_sources: bool,
    pub json: bool,
    pub expect_target_profile: Option<String>,
    pub expect_artifact_hash: Option<String>,
    pub expect_source_hash: Option<String>,
    pub expect_source_content_hash: Option<String>,
    pub production: bool,
    pub deny_fail_closed: bool,
    pub deny_symbolic_runtime: bool,
    pub deny_ckb_runtime: bool,
    pub deny_runtime_obligations: bool,
}

#[derive(Debug, Default)]
pub struct RunArgs {
    pub args: Vec<String>,
    pub release: bool,
    pub simulate: bool,
}

#[derive(Debug, Default)]
pub struct PublishArgs {
    pub dry_run: bool,
    pub allow_dirty: bool,
}

#[derive(Debug, Default)]
pub struct InstallArgs {
    pub crate_name: Option<String>,
    pub version: Option<String>,
    pub git: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct LoginArgs {
    pub registry: Option<String>,
}

pub struct CommandExecutor;

impl CommandExecutor {
    fn experimental_command(name: &str, detail: &str) -> Result<()> {
        Err(crate::error::CompileError::without_span(format!("cellc {} is still experimental: {}", name, detail)))
    }

    pub fn execute(cmd: Command) -> Result<()> {
        match cmd {
            Command::Build(args) => Self::build(args),
            Command::Test(args) => Self::test(args),
            Command::Doc(args) => Self::doc(args),
            Command::Fmt(args) => Self::fmt(args),
            Command::Init(args) => Self::init(args),
            Command::Add(args) => Self::add(args),
            Command::Remove(args) => Self::remove(args),
            Command::Clean(args) => Self::clean(args),
            Command::Repl => Self::repl(),
            Command::Check(args) => Self::check(args),
            Command::Metadata(args) => Self::metadata(args),
            Command::Constraints(args) => Self::constraints(args),
            Command::Abi(args) => Self::abi(args),
            Command::SchedulerPlan(args) => Self::scheduler_plan(args),
            Command::CkbHash(args) => Self::ckb_hash(args),
            Command::OptReport(args) => Self::opt_report(args),
            Command::EntryWitness(args) => Self::entry_witness(args),
            Command::VerifyArtifact(args) => Self::verify_artifact(args),
            Command::Run(args) => Self::run(args),
            Command::Publish(args) => Self::publish(args),
            Command::Install(args) => Self::install(args),
            Command::Update => Self::update(),
            Command::Info(args) => Self::info(args),
            Command::Login(args) => Self::login(args),
        }
    }

    fn build(args: BuildArgs) -> Result<()> {
        let opt_level = if args.release { 3 } else { 0 };
        let input = Utf8Path::new(".");
        let options = CompileOptions {
            opt_level,
            output: None,
            debug: false,
            target: args.target.clone(),
            target_profile: args.target_profile.clone(),
        };
        if args.entry_action.is_some() && args.entry_lock.is_some() {
            return Err(crate::error::CompileError::without_span("--entry-action and --entry-lock are mutually exclusive"));
        }
        let result = match (args.entry_action.as_deref(), args.entry_lock.as_deref()) {
            (Some(action), None) => compile_path_with_entry_action(input, options, action),
            (None, Some(lock)) => compile_path_with_entry_lock(input, options, lock),
            (None, None) => compile_path(input, options),
            (Some(_), Some(_)) => unreachable!("validated above"),
        }?;
        let policy_args = effective_build_check_args(&args)?;
        validate_check_policy(&result.metadata, &policy_args)?;
        let resolved = resolve_input_path(input)?;
        let output_path = default_output_path_for_input(input, &resolved, result.artifact_format)?;
        result.write_to_path(&output_path)?;
        let metadata_path = default_metadata_path_for_artifact(&output_path);
        result.write_metadata_to_path(&metadata_path)?;

        let policy_verified = policy_args.production
            || policy_args.deny_fail_closed
            || policy_args.deny_symbolic_runtime
            || policy_args.deny_ckb_runtime
            || policy_args.deny_runtime_obligations;
        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "artifact": output_path.to_string(),
                "metadata": metadata_path.to_string(),
                "artifact_format": result.artifact_format.display_name(),
                "target_profile": result.metadata.target_profile.name.as_str(),
                "artifact_hash_blake3": result.metadata.artifact_hash_blake3,
                "artifact_size_bytes": result.artifact_bytes.len(),
                "source_hash_blake3": result.metadata.source_hash_blake3,
                "source_content_hash_blake3": result.metadata.source_content_hash_blake3,
                "metadata_schema_version": result.metadata.metadata_schema_version,
                "compiler_version": result.metadata.compiler_version,
                "standalone_runner_compatible": result.metadata.runtime.standalone_runner_compatible,
                "ckb_runtime_required": result.metadata.runtime.ckb_runtime_required,
                "symbolic_cell_runtime_required": result.metadata.runtime.symbolic_cell_runtime_required,
                "verifier_obligations": result.metadata.runtime.verifier_obligations.len(),
                "runtime_required_verifier_obligations": runtime_required_obligation_count(&result.metadata),
                "fail_closed_verifier_obligations": fail_closed_obligation_count(&result.metadata),
                "runtime_required_transaction_invariants": runtime_required_transaction_invariant_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subconditions": runtime_required_transaction_invariant_checked_subcondition_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subcondition_summaries": transaction_invariant_checked_subcondition_summaries(&result.metadata),
                "transaction_runtime_input_requirements": transaction_runtime_input_requirement_count(&result.metadata),
                "transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries(&result.metadata),
                "checked_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "checked-runtime"),
                "checked_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "checked-runtime"),
                "runtime_required_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blockers": transaction_runtime_input_blocker_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_summaries": transaction_runtime_input_blocker_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_classes": transaction_runtime_input_blocker_class_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_class_summaries": transaction_runtime_input_blocker_class_summaries_by_status(&result.metadata, "runtime-required"),
                "checked_pool_invariant_families": checked_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_families": runtime_required_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_blocker_classes": pool_invariant_family_blocker_class_count(&result.metadata, "runtime-required"),
                "runtime_required_pool_invariant_blocker_class_summaries": pool_invariant_family_blocker_class_summaries(&result.metadata, "runtime-required"),
                "pool_runtime_input_requirements": pool_runtime_input_requirement_count(&result.metadata),
                "pool_runtime_input_requirement_summaries": pool_runtime_input_requirement_summaries(&result.metadata),
                "policy_verified": policy_verified,
                "constraints": &result.metadata.constraints,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize build summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Build complete".green());
        println!("  Artifact format: {}", result.artifact_format.display_name());
        println!("  Target profile: {}", result.metadata.target_profile.name);
        println!("  Output: {}", output_path);
        println!("  Metadata: {}", metadata_path);
        Ok(())
    }

    fn test(args: TestArgs) -> Result<()> {
        let doc_output = if args.doc {
            Some(Self::generate_docs(&DocArgs { output_format: OutputFormat::Markdown, ..Default::default() })?)
        } else {
            None
        };
        if args.doc && !args.json {
            println!("{}", "Documentation generated".green());
            if let Some(output) = &doc_output {
                println!("  Output: {}", output.display());
            }
        }

        let mut test_inputs = collect_cell_files(Path::new("tests"))?;
        if let Some(filter) = &args.filter {
            test_inputs.retain(|path| path.to_string_lossy().contains(filter));
        }
        test_inputs.sort();

        if test_inputs.is_empty() {
            compile_path(".", CompileOptions { opt_level: 0, output: None, debug: false, target: None, target_profile: None })?;
            if args.json {
                let summary = serde_json::json!({
                    "status": "ok",
                    "package_check": "passed",
                    "test_files": 0,
                    "passed": 0,
                    "failed": 0,
                    "fail_fast": args.fail_fast,
                    "no_run": args.no_run,
                    "execution": if args.no_run { "disabled" } else { "skipped-no-test-files" },
                    "docs_generated": args.doc,
                    "doc_output": doc_output.as_ref().map(|path| path.display().to_string()),
                    "tests": [],
                });
                let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                    crate::error::CompileError::without_span(format!("failed to serialize test summary: {}", error))
                })?;
                println!("{}", json);
                return Ok(());
            }
            println!("{}", "Test compile complete".green());
            println!("  Package check: passed");
            println!("  Test files: 0");
            if !args.no_run {
                println!("  Execution: skipped; no CellScript test files were found");
            }
            return Ok(());
        }

        let mut passed = 0usize;
        let mut failures = Vec::new();
        let mut test_reports = Vec::new();
        for input in &test_inputs {
            let utf8 = Utf8Path::from_path(input)
                .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input.display())))?;
            if args.nocapture && !args.json {
                println!("  Testing {}", utf8);
            }

            let expectation = read_test_expectation(input)?;
            let result = compile_path(
                utf8,
                CompileOptions { opt_level: 0, output: None, debug: false, target: expectation.target.clone(), target_profile: None },
            )
            .and_then(|result| {
                let policy_args = expectation.check_args();
                validate_check_policy(&result.metadata, &policy_args)?;
                Ok(result)
            });
            match evaluate_compile_test_result(utf8, &expectation, result) {
                Ok(()) => {
                    passed += 1;
                    test_reports.push(serde_json::json!({
                        "path": utf8.to_string(),
                        "status": "passed",
                        "target": expectation.target,
                    }));
                }
                Err(error) => {
                    let message = error.message;
                    test_reports.push(serde_json::json!({
                        "path": utf8.to_string(),
                        "status": "failed",
                        "error": message,
                        "target": expectation.target,
                    }));
                    failures.push(message);
                    if args.fail_fast {
                        break;
                    }
                }
            }
        }

        if !failures.is_empty() {
            return Err(crate::error::CompileError::without_span(format!("test failed:\n  - {}", failures.join("\n  - "))));
        }

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "package_check": "not-run",
                "test_files": test_inputs.len(),
                "passed": passed,
                "failed": 0,
                "fail_fast": args.fail_fast,
                "no_run": args.no_run,
                "execution": if args.no_run { "disabled" } else { "skipped-default-toolchain" },
                "docs_generated": args.doc,
                "doc_output": doc_output.as_ref().map(|path| path.display().to_string()),
                "tests": test_reports,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize test summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Test compile complete".green());
        println!("  Compiled {} test file(s)", passed);
        if !args.no_run {
            println!("  Execution: skipped; CellScript test execution is not enabled in the default toolchain yet");
        }
        Ok(())
    }

    fn doc(args: DocArgs) -> Result<()> {
        let output = Self::generate_docs(&args)?;
        let output_size_bytes = std::fs::metadata(&output).map(|metadata| metadata.len()).unwrap_or(0);

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "format": display_doc_output_format(&args.output_format),
                "output": output.display().to_string(),
                "output_size_bytes": output_size_bytes,
                "opened": args.open,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize doc summary: {}", error)))?;
            println!("{}", json);

            if args.open {
                let _ = std::process::Command::new("open").arg(&output).status();
            }

            return Ok(());
        }

        println!("{}", "Documentation generated".green());
        println!("  Output: {}", output.display());

        if args.open {
            let _ = std::process::Command::new("open").arg(&output).status();
        }

        Ok(())
    }

    fn generate_docs(args: &DocArgs) -> Result<PathBuf> {
        let modules = load_modules_for_input(".")?;
        let compile_result =
            compile_path(".", CompileOptions { opt_level: 0, output: None, debug: false, target: None, target_profile: None })?;
        let mut generator = DocGenerator::new(args.output_format);
        for module in &modules {
            generator.add_module(&module.ast);
        }
        generator.set_compile_metadata(&compile_result.metadata);
        let docs = generator.generate()?;
        let output = match args.output_format {
            OutputFormat::Html => PathBuf::from("docs/cellscript-api.html"),
            OutputFormat::Markdown => PathBuf::from("docs/cellscript-api.md"),
            OutputFormat::Json => PathBuf::from("docs/cellscript-api.json"),
        };
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&output, docs)?;

        Ok(output)
    }

    fn fmt(args: FmtArgs) -> Result<()> {
        let modules = if args.files.is_empty() {
            load_modules_for_input(".")?
        } else {
            let mut modules = Vec::new();
            for path in &args.files {
                let utf8 = Utf8Path::from_path(path).ok_or_else(|| {
                    crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", path.display()))
                })?;
                modules.extend(load_modules_for_input(utf8)?);
            }
            modules
        };

        let mut changed = Vec::new();
        for module in modules {
            let formatted = format_default(&module.ast)?;
            if formatted != module.source {
                changed.push(module.path.clone());
                if !args.check {
                    std::fs::write(&module.path, formatted)?;
                }
            }
        }
        let changed_files = changed.iter().map(|path| path.as_str()).collect::<Vec<_>>();

        if args.check {
            if changed.is_empty() {
                if args.json {
                    let summary = serde_json::json!({
                        "status": "ok",
                        "mode": "check",
                        "changed": 0,
                        "changed_files": changed_files,
                    });
                    let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                        crate::error::CompileError::without_span(format!("failed to serialize fmt summary: {}", error))
                    })?;
                    println!("{}", json);
                    return Ok(());
                }
                println!("{}", "Formatting is clean".green());
                Ok(())
            } else {
                if args.json {
                    let summary = serde_json::json!({
                        "status": "failed",
                        "mode": "check",
                        "changed": changed.len(),
                        "changed_files": changed_files,
                    });
                    let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                        crate::error::CompileError::without_span(format!("failed to serialize fmt summary: {}", error))
                    })?;
                    println!("{}", json);
                }
                Err(crate::error::CompileError::without_span(format!(
                    "format check failed for {} file(s): {}",
                    changed.len(),
                    changed_files.join(", ")
                )))
            }
        } else {
            if args.json {
                let summary = serde_json::json!({
                    "status": "ok",
                    "mode": "write",
                    "changed": changed.len(),
                    "changed_files": changed_files,
                });
                let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                    crate::error::CompileError::without_span(format!("failed to serialize fmt summary: {}", error))
                })?;
                println!("{}", json);
                return Ok(());
            }
            println!("{}", "Formatting complete".green());
            println!("  Updated {} file(s)", changed.len());
            Ok(())
        }
    }

    fn init(args: InitArgs) -> Result<()> {
        let path = args.path.unwrap_or_else(|| PathBuf::from("."));
        let name = args.name.unwrap_or_else(|| path.file_name().unwrap_or_default().to_string_lossy().to_string());

        if !args.json {
            println!("{} {} in {}", "Creating".cyan(), if args.lib { "library" } else { "binary" }, path.display());
        }

        let pm = PackageManager::new(&path);
        if args.lib {
            pm.init_library(&name)?;
        } else {
            pm.init(&name)?;
        }

        if args.json {
            let entry = if args.lib { "src/lib.cell" } else { "src/main.cell" };
            let summary = serde_json::json!({
                "status": "ok",
                "kind": if args.lib { "library" } else { "binary" },
                "package": name,
                "path": path.display().to_string(),
                "manifest": path.join("Cell.toml").display().to_string(),
                "entry": entry,
                "created_files": [
                    path.join("Cell.toml").display().to_string(),
                    path.join(entry).display().to_string(),
                    path.join(".gitignore").display().to_string(),
                ],
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize init summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Created package successfully".green());
        println!("  To get started:");
        println!("    cd {}", path.display());
        println!("    cellc build");

        Ok(())
    }

    fn add(args: AddArgs) -> Result<()> {
        validate_dependency_target_flags(args.dev, args.build)?;
        if args.git.is_some() && args.path.is_some() {
            return Err(crate::error::CompileError::without_span("cellc add accepts either --git or --path, not both"));
        }

        let pm = PackageManager::new(".");
        let mut manifest = pm.read_manifest()?;
        let dependency = dependency_from_add_args(&args);
        let target = dependency_target_label(args.dev, args.build);
        let mut added = Vec::new();

        for crate_name in &args.crates {
            if !args.json {
                println!("{} {} to {}", "Adding".cyan(), crate_name, target);
            }
            dependency_map_mut(&mut manifest, args.dev, args.build).insert(crate_name.clone(), dependency.clone());
            added.push(crate_name.clone());
        }

        pm.write_manifest(&manifest)?;

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "target": target,
                "added": added,
                "dependency": dependency,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize add summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Dependencies added successfully".green());
        Ok(())
    }

    fn remove(args: RemoveArgs) -> Result<()> {
        validate_dependency_target_flags(args.dev, args.build)?;
        let pm = PackageManager::new(".");
        let mut manifest = pm.read_manifest()?;
        let target = dependency_target_label(args.dev, args.build);
        let mut removed = Vec::new();
        let mut missing = Vec::new();

        for crate_name in &args.crates {
            if !args.json {
                println!("{} {} from {}", "Removing".cyan(), crate_name, target);
            }
            if dependency_map_mut(&mut manifest, args.dev, args.build).remove(crate_name).is_some() {
                removed.push(crate_name.clone());
            } else {
                missing.push(crate_name.clone());
            }
        }

        pm.write_manifest(&manifest)?;
        if !args.dev && !args.build && !removed.is_empty() {
            refresh_lockfile_from_manifest(Path::new("."))?;
        }

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "target": target,
                "removed": removed,
                "missing": missing,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize remove summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Dependencies removed successfully".green());
        Ok(())
    }

    fn clean(args: CleanArgs) -> Result<()> {
        if !args.json {
            println!("{}", "Cleaning...".cyan());
        }

        let paths = vec!["target", ".cell/cache"];
        let mut removed_paths = Vec::new();

        for path in paths {
            if std::path::Path::new(path).exists() {
                if !args.json {
                    println!("  Removing {}", path);
                }
                std::fs::remove_dir_all(path)?;
                removed_paths.push(path.to_string());
            }
        }

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "removed": removed_paths.len(),
                "removed_paths": removed_paths,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize clean summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Clean complete".green());
        Ok(())
    }

    fn repl() -> Result<()> {
        crate::repl::run_repl().map_err(|e| crate::error::CompileError::without_span(e.to_string()))
    }

    fn check(args: CheckArgs) -> Result<()> {
        let args = effective_check_args(args)?;
        let requested_profile = effective_check_target_profile(&args)?;
        let compile_target_profile = compile_target_profile_for_check(requested_profile);
        let mut checked_targets = Vec::new();
        let mut checked_target_json = Vec::new();
        let targets: Vec<Option<&'static str>> =
            if args.all_targets { vec![Some("riscv64-asm"), Some("riscv64-elf")] } else { vec![None] };

        for target in targets {
            let result = compile_path(
                ".",
                CompileOptions {
                    opt_level: 0,
                    output: None,
                    debug: false,
                    target: target.map(str::to_string),
                    target_profile: compile_target_profile.clone(),
                },
            )?;
            validate_check_policy(&result.metadata, &args)?;
            let target_profile_policy_violations =
                target_profile_policy_violations(&result.metadata, result.artifact_format, requested_profile);
            if !target_profile_policy_violations.is_empty() {
                return Err(crate::error::CompileError::without_span(format!(
                    "target profile policy failed for '{}':\n  - {}",
                    requested_profile.name(),
                    target_profile_policy_violations.join("\n  - ")
                )));
            }
            let target_label = match target {
                Some(target) => format!("{} ({})", target, result.artifact_format.display_name()),
                None => format!("package default ({})", result.artifact_format.display_name()),
            };
            let requested_profile_name = requested_profile.name();
            checked_target_json.push(serde_json::json!({
                "requested_target": target.unwrap_or("package-default"),
                "artifact_format": result.artifact_format.display_name(),
                "target_profile": requested_profile_name,
                "compiled_target_profile": result.metadata.target_profile.name.as_str(),
                "target_profile_policy_violations": target_profile_policy_violations,
                "metadata_schema_version": result.metadata.metadata_schema_version,
                "compiler_version": result.metadata.compiler_version,
                "standalone_runner_compatible": result.metadata.runtime.standalone_runner_compatible,
                "ckb_runtime_required": result.metadata.runtime.ckb_runtime_required,
                "symbolic_cell_runtime_required": result.metadata.runtime.symbolic_cell_runtime_required,
                "fail_closed_runtime_features": result.metadata.runtime.fail_closed_runtime_features,
                "verifier_obligations": result.metadata.runtime.verifier_obligations.len(),
                "runtime_required_verifier_obligations": runtime_required_obligation_count(&result.metadata),
                "fail_closed_verifier_obligations": fail_closed_obligation_count(&result.metadata),
                "runtime_required_transaction_invariants": runtime_required_transaction_invariant_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subconditions": runtime_required_transaction_invariant_checked_subcondition_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subcondition_summaries": transaction_invariant_checked_subcondition_summaries(&result.metadata),
                "transaction_runtime_input_requirements": transaction_runtime_input_requirement_count(&result.metadata),
                "transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries(&result.metadata),
                "checked_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "checked-runtime"),
                "checked_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "checked-runtime"),
                "runtime_required_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blockers": transaction_runtime_input_blocker_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_summaries": transaction_runtime_input_blocker_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_classes": transaction_runtime_input_blocker_class_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_class_summaries": transaction_runtime_input_blocker_class_summaries_by_status(&result.metadata, "runtime-required"),
                "checked_pool_invariant_families": checked_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_families": runtime_required_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_blocker_classes": pool_invariant_family_blocker_class_count(&result.metadata, "runtime-required"),
                "runtime_required_pool_invariant_blocker_class_summaries": pool_invariant_family_blocker_class_summaries(&result.metadata, "runtime-required"),
                "pool_runtime_input_requirements": pool_runtime_input_requirement_count(&result.metadata),
                "pool_runtime_input_requirement_summaries": pool_runtime_input_requirement_summaries(&result.metadata),
                "constraints": &result.metadata.constraints,
            }));
            checked_targets.push(target_label);
        }

        let policy_verified = args.production || args.deny_fail_closed || args.deny_symbolic_runtime || args.deny_ckb_runtime;
        let policy_verified = policy_verified || args.deny_runtime_obligations;
        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "checked_targets": checked_target_json,
                "all_targets": args.all_targets,
                "policy_verified": policy_verified,
                "policy": {
                    "production": args.production,
                    "deny_fail_closed": args.deny_fail_closed,
                    "deny_symbolic_runtime": args.deny_symbolic_runtime,
                    "deny_ckb_runtime": args.deny_ckb_runtime,
                    "deny_runtime_obligations": args.deny_runtime_obligations,
                },
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize check summary: {}", error)))?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Check succeeded".green());
        println!("  Target profile: {}", requested_profile.name());
        for target in checked_targets {
            println!("  Checked: {}", target);
        }
        Ok(())
    }

    fn metadata(args: MetadataArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions { opt_level: 0, output: None, debug: false, target: args.target, target_profile: args.target_profile },
        )?;
        let json = serde_json::to_string_pretty(&result.metadata)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize metadata: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Metadata generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn constraints(args: ConstraintsArgs) -> Result<()> {
        if args.entry_action.is_some() && args.entry_lock.is_some() {
            return Err(crate::error::CompileError::without_span(
                "constraints accepts either --entry-action or --entry-lock, not both",
            ));
        }
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let options =
            CompileOptions { opt_level: 0, output: None, debug: false, target: args.target, target_profile: args.target_profile };
        let result = match (args.entry_action.as_deref(), args.entry_lock.as_deref()) {
            (Some(action), None) => compile_path_with_entry_action(input, options, action),
            (None, Some(lock)) => compile_path_with_entry_lock(input, options, lock),
            (None, None) => compile_path(input, options),
            (Some(_), Some(_)) => unreachable!("validated above"),
        }?;
        let json = serde_json::to_string_pretty(&result.metadata.constraints)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize constraints: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Constraints generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn abi(args: AbiArgs) -> Result<()> {
        if args.action.is_some() && args.lock.is_some() {
            return Err(crate::error::CompileError::without_span("abi accepts either --action or --lock, not both"));
        }

        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions { opt_level: 0, output: None, debug: false, target: args.target, target_profile: args.target_profile },
        )?;
        let selected = select_entry_witness_metadata(&result.metadata, args.action.as_deref(), args.lock.as_deref())?;
        let entry_constraints = result
            .metadata
            .constraints
            .entry_abi
            .iter()
            .find(|entry| entry.entry_kind == selected.kind && entry.entry_name == selected.name)
            .ok_or_else(|| {
                crate::error::CompileError::without_span(format!(
                    "entry ABI constraints for {} '{}' were not found in metadata",
                    selected.kind, selected.name
                ))
            })?;

        let params = selected
            .params
            .iter()
            .map(|param| {
                let runtime_bound = selected.runtime_bound_param_names.contains(&param.name);
                let payload_bound = !param.cell_bound_abi && !param.ty.starts_with('&') && !runtime_bound;
                let layout = entry_constraints.params.iter().find(|candidate| candidate.name == param.name);
                serde_json::json!({
                    "name": param.name,
                    "type": param.ty,
                    "payload_bound": payload_bound,
                    "runtime_bound": runtime_bound,
                    "cell_bound": param.cell_bound_abi,
                    "schema_pointer_abi": param.schema_pointer_abi,
                    "fixed_byte_len": param.fixed_byte_len,
                    "abi_kind": layout.map(|layout| layout.abi_kind.as_str()),
                    "abi_slots": layout.map(|layout| layout.abi_slots),
                    "slot_start": layout.map(|layout| layout.slot_start),
                    "slot_end": layout.map(|layout| layout.slot_end),
                    "witness_bytes": layout.map(|layout| layout.witness_bytes),
                    "stack_spill_bytes": layout.map(|layout| layout.stack_spill_bytes),
                    "supported": layout.map(|layout| layout.supported).unwrap_or(false),
                    "unsupported_reason": layout.and_then(|layout| layout.unsupported_reason.as_deref()),
                })
            })
            .collect::<Vec<_>>();
        let payload_params = selected
            .params
            .iter()
            .filter(|param| {
                !param.cell_bound_abi && !param.ty.starts_with('&') && !selected.runtime_bound_param_names.contains(&param.name)
            })
            .map(|param| param.name.as_str())
            .collect::<Vec<_>>();
        let runtime_bound_params = selected.runtime_bound_param_names.iter().map(|name| name.as_str()).collect::<Vec<_>>();
        let summary = serde_json::json!({
            "status": if entry_constraints.unsupported { "fail" } else { "ok" },
            "abi": ENTRY_WITNESS_ABI,
            "target_profile": result.metadata.target_profile.name,
            "entry_kind": selected.kind,
            "entry": selected.name,
            "payload_params": payload_params,
            "runtime_bound_params": runtime_bound_params,
            "layout": entry_constraints,
            "params": params,
        });
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize ABI report: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "ABI report generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn scheduler_plan(args: SchedulerPlanArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions { opt_level: 0, output: None, debug: false, target: args.target, target_profile: args.target_profile },
        )?;

        let actions = result
            .metadata
            .actions
            .iter()
            .map(|action| {
                let mut reasons = Vec::new();
                if !action.parallelizable {
                    reasons.push("parallelizable=false".to_string());
                }
                if !action.touches_shared.is_empty() {
                    reasons.push("touches-shared-state".to_string());
                }
                serde_json::json!({
                    "action": action.name,
                    "effect_class": action.effect_class,
                    "parallelizable": action.parallelizable,
                    "touches_shared": action.touches_shared,
                    "estimated_cycles": action.estimated_cycles,
                    "scheduler_witness_abi": action.scheduler_witness_abi,
                    "admission": if action.parallelizable && action.touches_shared.is_empty() {
                        "parallel-candidate"
                    } else {
                        "serial-required"
                    },
                    "reasons": reasons,
                })
            })
            .collect::<Vec<_>>();

        let mut conflicts = Vec::new();
        for (left_index, left) in result.metadata.actions.iter().enumerate() {
            for right in result.metadata.actions.iter().skip(left_index + 1) {
                let shared =
                    left.touches_shared.iter().filter(|touch| right.touches_shared.contains(*touch)).cloned().collect::<Vec<_>>();
                if !shared.is_empty() {
                    conflicts.push(serde_json::json!({
                        "left": left.name,
                        "right": right.name,
                        "shared_touches": shared,
                        "policy": "must-not-run-in-parallel",
                    }));
                }
            }
        }

        let total_estimated_cycles = result.metadata.actions.iter().map(|action| action.estimated_cycles).sum::<u64>();
        let max_estimated_cycles = result.metadata.actions.iter().map(|action| action.estimated_cycles).max().unwrap_or_default();
        let serial_required_actions = result
            .metadata
            .actions
            .iter()
            .filter(|action| !action.parallelizable || !action.touches_shared.is_empty())
            .map(|action| action.name.as_str())
            .collect::<Vec<_>>();
        let summary = serde_json::json!({
            "status": "ok",
            "target_profile": result.metadata.target_profile.name,
            "policy": "cellscript-scheduler-hints-v1",
            "action_count": result.metadata.actions.len(),
            "serial_required_actions": serial_required_actions,
            "conflict_count": conflicts.len(),
            "conflicts": conflicts,
            "estimated_cycles": {
                "total": total_estimated_cycles,
                "max_action": max_estimated_cycles,
            },
            "actions": actions,
        });
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize scheduler plan: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Scheduler plan generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    fn ckb_hash(args: CkbHashArgs) -> Result<()> {
        let source_count = usize::from(args.input.is_some()) + usize::from(args.hex.is_some()) + usize::from(args.file.is_some());
        if source_count > 1 {
            return Err(crate::error::CompileError::without_span(
                "ckb-hash accepts at most one input source: positional UTF-8 text, --hex, or --file",
            ));
        }
        let bytes = if let Some(hex) = args.hex.as_deref() {
            decode_hex_arg("ckb-hash", hex, None)?
        } else if let Some(path) = args.file.as_ref() {
            std::fs::read(path).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to read CKB hash input '{}': {}", path.display(), error))
            })?
        } else {
            args.input.unwrap_or_default().into_bytes()
        };
        let hash = crate::ckb_blake2b256(&bytes);
        let hash_hex = crate::hex_encode(&hash);
        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "algorithm": "blake2b-256",
                "personalization": std::str::from_utf8(crate::CKB_DEFAULT_HASH_PERSONALIZATION).unwrap_or("ckb-default-hash"),
                "input_bytes": bytes.len(),
                "hash": hash_hex,
            });
            let json = serde_json::to_string_pretty(&summary)
                .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize CKB hash: {}", error)))?;
            println!("{}", json);
        } else {
            println!("{}", hash_hex);
        }
        Ok(())
    }

    fn opt_report(args: OptReportArgs) -> Result<()> {
        let input_path = args.input.unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let mut rows = Vec::new();
        for opt_level in 0..=3u8 {
            let result = compile_path(
                input,
                CompileOptions {
                    opt_level,
                    output: None,
                    debug: false,
                    target: args.target.clone(),
                    target_profile: args.target_profile.clone(),
                },
            )?;
            rows.push(serde_json::json!({
                "opt_level": opt_level,
                "artifact_format": result.metadata.artifact_format,
                "target_profile": result.metadata.target_profile.name,
                "artifact_size_bytes": result.artifact_bytes.len(),
                "constraints_status": result.metadata.constraints.status,
                "constraints_warnings": result.metadata.constraints.warnings.len(),
                "constraints_failures": result.metadata.constraints.failures.len(),
                "source_content_hash_blake3": result.metadata.source_content_hash_blake3,
            }));
        }
        let baseline_size = rows.first().and_then(|row| row["artifact_size_bytes"].as_u64()).unwrap_or_default();
        let summary_rows = rows
            .into_iter()
            .map(|mut row| {
                let size = row["artifact_size_bytes"].as_u64().unwrap_or_default();
                row["artifact_size_delta_from_o0"] = serde_json::json!(size as i64 - baseline_size as i64);
                row
            })
            .collect::<Vec<_>>();
        let summary = serde_json::json!({
            "status": "ok",
            "policy": "cellscript-opt-report-v1",
            "input": input_path.display().to_string(),
            "baseline_opt_level": 0,
            "rows": summary_rows,
        });
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|error| crate::error::CompileError::without_span(format!("failed to serialize opt report: {}", error)))?;

        if let Some(output_path) = args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_path, json)?;
            println!("{}", "Optimization report generated".green());
            println!("  Output: {}", output_path.display());
        } else {
            println!("{}", json);
        }
        Ok(())
    }

    /// Encode witness bytes for the generated `_cellscript_entry` wrapper.
    fn entry_witness(args: EntryWitnessArgs) -> Result<()> {
        if args.action.is_some() && args.lock.is_some() {
            return Err(crate::error::CompileError::without_span("entry-witness accepts either --action or --lock, not both"));
        }

        let input_path = args.input.clone().unwrap_or_else(|| PathBuf::from("."));
        let input = Utf8Path::from_path(&input_path)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("path '{}' is not valid UTF-8", input_path.display())))?;
        let result = compile_path(
            input,
            CompileOptions { opt_level: 0, output: None, debug: false, target: args.target, target_profile: args.target_profile },
        )?;

        let selected = select_entry_witness_metadata(&result.metadata, args.action.as_deref(), args.lock.as_deref())?;
        if selected.params.is_empty() {
            return Err(crate::error::CompileError::without_span(format!(
                "{} '{}' has no parameters; `_cellscript_entry` witness ABI is only emitted for parameterized entries",
                selected.kind, selected.name
            )));
        }

        let payload_params = selected
            .params
            .iter()
            .filter(|param| {
                !param.cell_bound_abi && !param.ty.starts_with('&') && !selected.runtime_bound_param_names.contains(&param.name)
            })
            .collect::<Vec<_>>();
        if args.args.len() != payload_params.len() {
            return Err(crate::error::CompileError::without_span(format!(
                "{} '{}' expects {} witness payload arg(s), got {}",
                selected.kind,
                selected.name,
                payload_params.len(),
                args.args.len()
            )));
        }

        let witness_args = payload_params
            .iter()
            .zip(args.args.iter())
            .map(|(param, value)| parse_entry_witness_arg(param, value))
            .collect::<Result<Vec<_>>>()?;
        let witness = crate::encode_entry_witness_args_for_params_with_runtime_bound(
            selected.params,
            &witness_args,
            &selected.runtime_bound_param_names,
        )
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to encode entry witness: {}", error)))?;
        let witness_hex = crate::hex_encode(&witness);

        if let Some(output_path) = &args.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output_path, &witness)?;
        }

        if args.json {
            let payload_param_names = payload_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>();
            let summary = serde_json::json!({
                "status": "ok",
                "abi": ENTRY_WITNESS_ABI,
                "entry_kind": selected.kind,
                "entry": selected.name,
                "witness_hex": witness_hex,
                "witness_size_bytes": witness.len(),
                "payload_args": witness_args.len(),
                "payload_params": payload_param_names,
                "output": args.output.as_ref().map(|path| path.display().to_string()),
            });
            let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize entry witness summary: {}", error))
            })?;
            println!("{}", json);
            return Ok(());
        }

        if let Some(output_path) = &args.output {
            println!("{}", "Entry witness encoded".green());
            println!("  ABI: {}", ENTRY_WITNESS_ABI);
            println!("  Entry: {} {}", selected.kind, selected.name);
            println!("  Output: {}", output_path.display());
            println!("  Hex: {}", witness_hex);
        } else {
            println!("{}", witness_hex);
        }
        Ok(())
    }

    fn verify_artifact(args: VerifyArtifactArgs) -> Result<()> {
        let artifact_path = Utf8Path::from_path(&args.artifact).ok_or_else(|| {
            crate::error::CompileError::without_span(format!("artifact path '{}' is not valid UTF-8", args.artifact.display()))
        })?;
        let metadata_path = match args.metadata {
            Some(path) => path,
            None => default_metadata_path_for_artifact(artifact_path).into_std_path_buf(),
        };

        let artifact_bytes = std::fs::read(&args.artifact).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read artifact '{}': {}", args.artifact.display(), error))
        })?;
        let metadata_bytes = std::fs::read(&metadata_path).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to read metadata '{}': {}", metadata_path.display(), error))
        })?;
        let metadata: CompileMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
            crate::error::CompileError::without_span(format!("failed to parse metadata '{}': {}", metadata_path.display(), error))
        })?;
        let result = validate_artifact_metadata(artifact_bytes, metadata)?;
        if args.verify_sources {
            validate_source_units_on_disk(&result.metadata)?;
        }
        validate_expected_target_profile(result.metadata.target_profile.name.as_str(), args.expect_target_profile.as_deref())?;
        validate_expected_metadata_hash(
            "artifact_hash_blake3",
            result.metadata.artifact_hash_blake3.as_deref(),
            args.expect_artifact_hash.as_deref(),
        )?;
        validate_expected_metadata_hash(
            "source_hash_blake3",
            result.metadata.source_hash_blake3.as_deref(),
            args.expect_source_hash.as_deref(),
        )?;
        validate_expected_metadata_hash(
            "source_content_hash_blake3",
            result.metadata.source_content_hash_blake3.as_deref(),
            args.expect_source_content_hash.as_deref(),
        )?;
        validate_check_policy(
            &result.metadata,
            &CheckArgs {
                production: args.production,
                deny_fail_closed: args.deny_fail_closed,
                deny_symbolic_runtime: args.deny_symbolic_runtime,
                deny_ckb_runtime: args.deny_ckb_runtime,
                deny_runtime_obligations: args.deny_runtime_obligations,
                ..CheckArgs::default()
            },
        )?;

        let expected_target_profile_verified = args.expect_target_profile.is_some();
        let expected_hashes_verified =
            args.expect_artifact_hash.is_some() || args.expect_source_hash.is_some() || args.expect_source_content_hash.is_some();
        let policy_verified = args.production
            || args.deny_fail_closed
            || args.deny_symbolic_runtime
            || args.deny_ckb_runtime
            || args.deny_runtime_obligations;

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "artifact": args.artifact.display().to_string(),
                "metadata": metadata_path.display().to_string(),
                "metadata_schema_version": result.metadata.metadata_schema_version,
                "compiler_version": result.metadata.compiler_version,
                "artifact_format": result.artifact_format.display_name(),
                "target_profile": result.metadata.target_profile.name.as_str(),
                "artifact_hash_blake3": result.metadata.artifact_hash_blake3,
                "artifact_size_bytes": result.artifact_bytes.len(),
                "source_hash_blake3": result.metadata.source_hash_blake3,
                "source_content_hash_blake3": result.metadata.source_content_hash_blake3,
                "source_units": result.metadata.source_units.len(),
                "verifier_obligations": result.metadata.runtime.verifier_obligations.len(),
                "runtime_required_verifier_obligations": runtime_required_obligation_count(&result.metadata),
                "fail_closed_verifier_obligations": fail_closed_obligation_count(&result.metadata),
                "runtime_required_transaction_invariants": runtime_required_transaction_invariant_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subconditions": runtime_required_transaction_invariant_checked_subcondition_count(&result.metadata),
                "runtime_required_transaction_invariant_checked_subcondition_summaries": transaction_invariant_checked_subcondition_summaries(&result.metadata),
                "transaction_runtime_input_requirements": transaction_runtime_input_requirement_count(&result.metadata),
                "transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries(&result.metadata),
                "checked_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "checked-runtime"),
                "checked_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "checked-runtime"),
                "runtime_required_transaction_runtime_input_requirements": transaction_runtime_input_requirement_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_requirement_summaries": transaction_runtime_input_requirement_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blockers": transaction_runtime_input_blocker_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_summaries": transaction_runtime_input_blocker_summaries_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_classes": transaction_runtime_input_blocker_class_count_by_status(&result.metadata, "runtime-required"),
                "runtime_required_transaction_runtime_input_blocker_class_summaries": transaction_runtime_input_blocker_class_summaries_by_status(&result.metadata, "runtime-required"),
                "checked_pool_invariant_families": checked_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_families": runtime_required_pool_invariant_family_count(&result.metadata),
                "runtime_required_pool_invariant_blocker_classes": pool_invariant_family_blocker_class_count(&result.metadata, "runtime-required"),
                "runtime_required_pool_invariant_blocker_class_summaries": pool_invariant_family_blocker_class_summaries(&result.metadata, "runtime-required"),
                "pool_runtime_input_requirements": pool_runtime_input_requirement_count(&result.metadata),
                "pool_runtime_input_requirement_summaries": pool_runtime_input_requirement_summaries(&result.metadata),
                "sources_verified": args.verify_sources,
                "expected_target_profile_verified": expected_target_profile_verified,
                "expected_hashes_verified": expected_hashes_verified,
                "policy_verified": policy_verified,
                "constraints": &result.metadata.constraints,
            });
            let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize verification summary: {}", error))
            })?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Artifact verification succeeded".green());
        println!("  Artifact: {}", args.artifact.display());
        println!("  Metadata: {}", metadata_path.display());
        println!("  Metadata schema: {}", result.metadata.metadata_schema_version);
        println!("  Compiler: {}", result.metadata.compiler_version);
        println!("  Format: {}", result.artifact_format.display_name());
        println!("  Target profile: {}", result.metadata.target_profile.name);
        println!("  Hash: {}", result.metadata.artifact_hash_blake3.as_deref().unwrap_or("missing"));
        println!("  Size: {} bytes", result.artifact_bytes.len());
        if expected_target_profile_verified {
            println!("  Expected target profile: verified");
        }
        if expected_hashes_verified {
            println!("  Expected hashes: verified");
        }
        if args.verify_sources {
            println!("  Sources: verified {} unit(s)", result.metadata.source_units.len());
        }
        if policy_verified {
            println!("  Policy: verified");
        }
        Ok(())
    }

    fn run(args: RunArgs) -> Result<()> {
        let opt_level = if args.release { 3 } else { 0 };
        let compile_result = compile_path(
            ".",
            CompileOptions { opt_level, output: None, debug: false, target: Some("riscv64-elf".to_string()), target_profile: None },
        );

        if args.simulate {
            let result = compile_result?;
            return Self::run_simulate(&result, &args);
        }

        #[cfg(feature = "vm-runner")]
        {
            let result = compile_result?;

            let parameterized_entries = result
                .metadata
                .actions
                .iter()
                .filter(|action| !action.params.is_empty())
                .map(|action| format!("action {}", action.name))
                .chain(result.metadata.locks.iter().filter(|lock| !lock.params.is_empty()).map(|lock| format!("lock {}", lock.name)))
                .collect::<Vec<_>>();
            if !parameterized_entries.is_empty() {
                eprintln!(
                    "{}",
                    format!(
                        "Warning: {} requires transaction/parameter ABI context; falling back to simulate mode",
                        parameterized_entries.join(", ")
                    )
                    .yellow()
                );
                return Self::run_simulate(&result, &args);
            }

            if result.metadata.runtime.ckb_runtime_required {
                eprintln!(
                    "{}",
                    format!(
                        "Warning: CKB runtime required ({}); falling back to simulate mode",
                        result.metadata.runtime.ckb_runtime_features.join(", ")
                    )
                    .yellow()
                );
                return Self::run_simulate(&result, &args);
            }

            if !result.metadata.runtime.standalone_runner_compatible {
                eprintln!("{}", "Warning: ELF is not standalone-compatible; falling back to simulate mode".yellow());
                return Self::run_simulate(&result, &args);
            }

            let vm_args = args.args.into_iter().map(|arg| arg.into_bytes()).collect::<Vec<_>>();
            let cycles = run_elf_in_ckb_vm(&result.artifact_bytes, &vm_args)?;

            println!("{}", "Run complete".green());
            println!("  Artifact format: {}", result.artifact_format.display_name());
            println!("  Cycles: {}", cycles);
            Ok(())
        }

        #[cfg(not(feature = "vm-runner"))]
        {
            let mode = if args.release { "release" } else { "debug" };
            Self::experimental_command(
                "run",
                &format!(
                    "feature-gated VM backend is not enabled (requested {}, {} argument(s)); use --simulate for AST-level symbolic execution or compile with --features vm-runner to execute",
                    mode,
                    args.args.len()
                ),
            )
        }
    }

    fn run_simulate(compile_result: &crate::CompileResult, _args: &RunArgs) -> Result<()> {
        use crate::simulate::{SimValue, SimulateInterpreter};

        let modules = crate::load_modules_for_input(".")?;
        let module =
            modules.iter().find(|module| module.ast.name == compile_result.metadata.module).map(|module| &module.ast).ok_or_else(
                || {
                    crate::error::CompileError::without_span(format!(
                        "failed to load module '{}' for simulation",
                        compile_result.metadata.module
                    ))
                },
            )?;

        let entry = compile_result
            .metadata
            .actions
            .iter()
            .find(|a| a.name == "main")
            .or_else(|| compile_result.metadata.actions.iter().find(|a| a.params.is_empty()));

        let Some(entry) = entry else {
            return Err(crate::error::CompileError::without_span(
                "no suitable entry point found for simulation; define an action main() or a zero-argument action",
            ));
        };

        let mut interp = SimulateInterpreter::new(module, 100_000);
        let sim_args: Vec<SimValue> = Vec::new();
        let sim_result = interp
            .simulate_action(&entry.name, &sim_args)
            .map_err(|e| crate::error::CompileError::without_span(format!("simulation error: {}", e)))?;

        println!("{}", "Simulate complete".green());
        println!("  Entry: action {}", sim_result.entry_name);
        println!("  Steps: {}", sim_result.steps);
        if sim_result.has_cell_ops {
            println!("  Cell operations: {} (symbolic)", "yes".yellow());
        } else {
            println!("  Cell operations: none (pure computation)");
        }
        println!("  Result: {}", sim_result.return_value);

        if !sim_result.trace.is_empty() {
            println!("  Trace:");
            for event in &sim_result.trace {
                println!("{}", event);
            }
        }

        Ok(())
    }

    fn publish(args: PublishArgs) -> Result<()> {
        let pm = PackageManager::new(".");
        let manifest = pm.read_manifest()?;

        if args.dry_run {
            let mut issues = Vec::<String>::new();
            if manifest.package.name.is_empty() {
                issues.push("package name is empty".to_string());
            }
            if manifest.package.version.is_empty() {
                issues.push("package version is empty".to_string());
            }
            if manifest.package.description.is_empty() {
                issues.push("package description is missing".to_string());
            }
            if manifest.package.license.is_empty() {
                issues.push("package license is missing".to_string());
            }
            if manifest.package.repository.is_empty() {
                issues.push("package repository is missing".to_string());
            }

            let entry_path = std::path::Path::new(".").join(&manifest.package.entry);
            if !entry_path.exists() {
                issues.push(format!("entry file '{}' does not exist", manifest.package.entry));
            }

            let compile_result = compile_path(".", CompileOptions::default());
            match compile_result {
                Ok(result) => {
                    println!("{}", "Publish dry-run passed".green());
                    println!("  Package: {} v{}", manifest.package.name, manifest.package.version);
                    println!("  Artifact: {} ({} bytes)", result.artifact_format.display_name(), result.artifact_bytes.len());
                }
                Err(e) => {
                    issues.push(format!("compilation failed: {}", e));
                }
            }

            if !issues.is_empty() {
                println!("{}", "Issues found:".yellow());
                for issue in &issues {
                    println!("  - {}", issue);
                }
                return Err(crate::error::CompileError::without_span(format!("publish dry-run found {} issue(s)", issues.len())));
            }

            Ok(())
        } else {
            let dirty = if args.allow_dirty { "allow-dirty" } else { "clean-tree-only" };
            Self::experimental_command(
                "publish",
                &format!(
                    "registry publication is not implemented yet (package {} v{}, {})",
                    manifest.package.name, manifest.package.version, dirty
                ),
            )
        }
    }

    fn install(args: InstallArgs) -> Result<()> {
        let pm = PackageManager::new(".");

        let _manifest = pm.read_manifest()?;

        if let Some(git_url) = &args.git {
            let crate_name = args.crate_name.clone().unwrap_or_else(|| {
                git_url.trim_end_matches('/').trim_end_matches(".git").split('/').next_back().unwrap_or("unknown").to_string()
            });

            let dep = DetailedDependency {
                version: args.version.clone().unwrap_or_else(|| "*".to_string()),
                git: Some(git_url.clone()),
                branch: None,
                tag: None,
                rev: None,
                path: None,
                optional: false,
                features: Vec::new(),
                default_features: true,
            };

            pm.resolve_from_git(&crate_name, git_url, &dep)?;

            let mut manifest = pm.read_manifest()?;
            manifest.dependencies.insert(crate_name.clone(), Dependency::Detailed(dep));
            pm.write_manifest(&manifest)?;

            refresh_lockfile_from_manifest(std::path::Path::new("."))?;

            println!("{}", format!("Installed {} from git {}", crate_name, git_url).green());
            Ok(())
        } else if let Some(path) = &args.path {
            let crate_name =
                args.crate_name.clone().unwrap_or_else(|| path.file_name().unwrap_or_default().to_string_lossy().to_string());

            let dep = DetailedDependency {
                version: args.version.clone().unwrap_or_else(|| "*".to_string()),
                git: None,
                branch: None,
                tag: None,
                rev: None,
                path: Some(path.to_string_lossy().to_string()),
                optional: false,
                features: Vec::new(),
                default_features: true,
            };

            pm.resolve_from_path(&crate_name, &path.to_string_lossy())?;

            let mut manifest = pm.read_manifest()?;
            manifest.dependencies.insert(crate_name.clone(), Dependency::Detailed(dep));
            pm.write_manifest(&manifest)?;

            refresh_lockfile_from_manifest(std::path::Path::new("."))?;

            println!("{}", format!("Installed {} from path {}", crate_name, path.display()).green());
            Ok(())
        } else if let Some(crate_name) = &args.crate_name {
            Self::experimental_command(
                "install",
                &format!(
                    "registry package installation is not implemented yet; use --git URL or --path PATH to install {}",
                    crate_name
                ),
            )
        } else {
            let mut pm = PackageManager::new(".");
            pm.resolve_dependencies()?;

            let mut lockfile = Lockfile::read_from_root(std::path::Path::new("."))?.unwrap_or_default();
            lockfile.replace_with_resolved(pm.get_resolved());
            lockfile.write_to_root(std::path::Path::new("."))?;

            println!("{}", "Dependencies resolved and lockfile updated".green());
            Ok(())
        }
    }

    fn update() -> Result<()> {
        let mut pm = PackageManager::new(".");
        let manifest = pm.read_manifest()?;

        pm.resolve_dependencies()?;

        let mut lockfile = Lockfile::read_from_root(std::path::Path::new("."))?.unwrap_or_default();

        lockfile.replace_with_resolved(pm.get_resolved());
        lockfile.write_to_root(std::path::Path::new("."))?;

        let resolved = pm.get_resolved();
        if resolved.is_empty() {
            println!("{}", "No dependencies to update".green());
        } else {
            println!("{}", format!("Updated {} dependencies", resolved.len()).green());
            for (name, package) in resolved {
                let source = match &package.source {
                    crate::package::PackageSource::Local(path) => format!("path: {}", path.display()),
                    crate::package::PackageSource::Git { url, revision } => format!("git: {}#{}", url, revision),
                    crate::package::PackageSource::Registry { name, version } => format!("registry: {}@{}", name, version),
                };
                println!("  {} v{} ({})", name, package.version, source);
            }
        }

        let lockfile_issues = lockfile.consistency_issues(&manifest);
        if !lockfile_issues.is_empty() {
            println!("{}", "Warning: lockfile is not consistent with Cell.toml".yellow());
            for issue in lockfile_issues {
                println!("  - {}", issue);
            }
        }

        Ok(())
    }

    fn info(args: InfoArgs) -> Result<()> {
        let pm = PackageManager::new(".");
        let manifest = pm.read_manifest()?;

        if args.json {
            let summary = serde_json::json!({
                "status": "ok",
                "manifest": "Cell.toml",
                "package": manifest.package,
                "dependencies": manifest.dependencies,
                "dev_dependencies": manifest.dev_dependencies,
                "build": manifest.build,
                "policy": manifest.policy,
                "deploy": manifest.deploy,
                "metadata": manifest.metadata,
            });
            let json = serde_json::to_string_pretty(&summary).map_err(|error| {
                crate::error::CompileError::without_span(format!("failed to serialize package info summary: {}", error))
            })?;
            println!("{}", json);
            return Ok(());
        }

        println!("{}", "Package Info:".bold());
        println!("  Name:        {}", manifest.package.name);
        println!("  Version:     {}", manifest.package.version);
        println!("  Description: {}", manifest.package.description);
        println!("  License:     {}", manifest.package.license);
        println!("  Authors:     {}", manifest.package.authors.join(", "));
        println!("  Entry:       {}", manifest.package.entry);
        println!("  Dependencies:");
        for (name, dep) in &manifest.dependencies {
            println!("    - {}: {:?}", name, dep);
        }

        Ok(())
    }

    fn login(args: LoginArgs) -> Result<()> {
        let registry = args.registry.unwrap_or_else(|| "https://cellscript.io".to_string());

        let config_dir = dirs_config_dir();
        std::fs::create_dir_all(&config_dir).map_err(|e| {
            crate::error::CompileError::without_span(format!("failed to create config directory '{}': {}", config_dir.display(), e))
        })?;

        let credentials_path = config_dir.join("credentials.toml");

        let mut credentials: HashMap<String, RegistryCredential> = if credentials_path.exists() {
            let content = std::fs::read_to_string(&credentials_path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

        eprintln!("Logging in to {}", registry);
        eprintln!("Enter your authentication token (or press Enter to use environment variable CELLSCRIPT_TOKEN):");

        let mut token = String::new();
        if std::io::stdin().read_line(&mut token).is_err() || token.trim().is_empty() {
            token = std::env::var("CELLSCRIPT_TOKEN").unwrap_or_default();
        }

        if token.trim().is_empty() {
            return Err(crate::error::CompileError::without_span(
                "no authentication token provided; set CELLSCRIPT_TOKEN environment variable or enter token interactively",
            ));
        }

        let token = token.trim().to_string();

        credentials.insert(registry.clone(), RegistryCredential { registry: registry.clone(), token });

        let content = toml::to_string_pretty(&credentials)?;
        std::fs::write(&credentials_path, content)?;

        println!("{}", format!("Login credentials saved for {}", registry).green());
        println!("  Config directory: {}", config_dir.display());
        Ok(())
    }
}

#[cfg(feature = "vm-runner")]
type CliVmMachine = TraceMachine<DefaultCoreMachine<u64, WXorXMemory<SparseMemory<u64>>>>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RegistryCredential {
    registry: String,
    token: String,
}

fn dirs_config_dir() -> PathBuf {
    if let Ok(config) = std::env::var("CELLSCRIPT_CONFIG") {
        return PathBuf::from(config);
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("cellscript");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("cellscript")
}

fn effective_check_args(mut args: CheckArgs) -> Result<CheckArgs> {
    let policy = PackageManager::new(".").read_manifest()?.policy;
    merge_check_policy(&mut args, &policy);
    Ok(args)
}

fn effective_check_target_profile(args: &CheckArgs) -> Result<TargetProfile> {
    if let Some(profile) = args.target_profile.as_deref() {
        return TargetProfile::from_name(profile);
    }

    if let Some(profile) = manifest_target_profile()? {
        return Ok(profile);
    }

    Ok(TargetProfile::Spora)
}

fn manifest_target_profile() -> Result<Option<TargetProfile>> {
    let manifest_path = Path::new("Cell.toml");
    if !manifest_path.exists() {
        return Ok(None);
    }

    let source = std::fs::read_to_string(manifest_path).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to read Cell.toml target profile policy: {}", error))
    })?;
    let manifest: toml::Value = toml::from_str(&source).map_err(|error| {
        crate::error::CompileError::without_span(format!("failed to parse Cell.toml target profile policy: {}", error))
    })?;
    let Some(profile) = manifest.get("build").and_then(|build| build.get("target_profile")).and_then(toml::Value::as_str) else {
        return Ok(None);
    };
    TargetProfile::from_name(profile).map(Some)
}

fn compile_target_profile_for_check(profile: TargetProfile) -> Option<String> {
    match profile {
        TargetProfile::Spora => Some(TargetProfile::Spora.name().to_string()),
        TargetProfile::Ckb => Some(TargetProfile::Ckb.name().to_string()),
        TargetProfile::PortableCell => Some(TargetProfile::Spora.name().to_string()),
    }
}

fn display_doc_output_format(format: &OutputFormat) -> &'static str {
    match format {
        OutputFormat::Html => "html",
        OutputFormat::Markdown => "markdown",
        OutputFormat::Json => "json",
    }
}

fn validate_dependency_target_flags(dev: bool, build: bool) -> Result<()> {
    if dev && build {
        return Err(crate::error::CompileError::without_span("dependency target flags --dev and --build are mutually exclusive"));
    }
    Ok(())
}

fn dependency_target_label(dev: bool, build: bool) -> &'static str {
    if build {
        "build-dependencies"
    } else if dev {
        "dev-dependencies"
    } else {
        "dependencies"
    }
}

fn dependency_map_mut(manifest: &mut crate::package::PackageManifest, dev: bool, build: bool) -> &mut HashMap<String, Dependency> {
    if build {
        &mut manifest.build.dependencies
    } else if dev {
        &mut manifest.dev_dependencies
    } else {
        &mut manifest.dependencies
    }
}

fn dependency_from_add_args(args: &AddArgs) -> Dependency {
    match (&args.git, &args.path) {
        (Some(git), _) => Dependency::Detailed(DetailedDependency {
            version: "*".to_string(),
            git: Some(git.clone()),
            branch: None,
            tag: None,
            rev: None,
            path: None,
            optional: false,
            features: Vec::new(),
            default_features: true,
        }),
        (_, Some(path)) => Dependency::Detailed(DetailedDependency {
            version: "*".to_string(),
            git: None,
            branch: None,
            tag: None,
            rev: None,
            path: Some(path.display().to_string()),
            optional: false,
            features: Vec::new(),
            default_features: true,
        }),
        _ => Dependency::Simple("*".to_string()),
    }
}

fn refresh_lockfile_from_manifest(root: &Path) -> Result<()> {
    let mut manager = PackageManager::new(root);
    manager.resolve_dependencies()?;

    let mut lockfile = Lockfile::read_from_root(root)?.unwrap_or_default();
    lockfile.replace_with_resolved(manager.get_resolved());
    lockfile.write_to_root(root)?;
    Ok(())
}

fn effective_build_check_args(args: &BuildArgs) -> Result<CheckArgs> {
    effective_check_args(CheckArgs {
        all_targets: false,
        target_profile: args.target_profile.clone(),
        features: args.features.clone(),
        json: false,
        production: args.production,
        deny_fail_closed: args.deny_fail_closed,
        deny_symbolic_runtime: args.deny_symbolic_runtime,
        deny_ckb_runtime: args.deny_ckb_runtime,
        deny_runtime_obligations: args.deny_runtime_obligations,
    })
}

fn merge_check_policy(args: &mut CheckArgs, policy: &PolicyConfig) {
    args.production |= policy.production;
    args.deny_fail_closed |= policy.deny_fail_closed;
    args.deny_symbolic_runtime |= policy.deny_symbolic_runtime;
    args.deny_ckb_runtime |= policy.deny_ckb_runtime;
    args.deny_runtime_obligations |= policy.deny_runtime_obligations;
}

fn validate_expected_metadata_hash(field: &str, actual: Option<&str>, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(crate::error::CompileError::without_span(format!(
            "{} expectation must be a 64-character lowercase BLAKE3 hex digest, got '{}'",
            field, expected
        )));
    }
    match actual {
        Some(actual) if actual.eq_ignore_ascii_case(expected) => Ok(()),
        Some(actual) => Err(crate::error::CompileError::without_span(format!(
            "metadata {} '{}' does not match expected '{}'",
            field, actual, expected
        ))),
        None => Err(crate::error::CompileError::without_span(format!(
            "metadata is missing {} required by expectation '{}'",
            field, expected
        ))),
    }
}

fn validate_expected_target_profile(actual: &str, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected_profile = TargetProfile::from_name(expected)?;
    if actual == expected_profile.name() {
        return Ok(());
    }

    Err(crate::error::CompileError::without_span(format!(
        "metadata target_profile '{}' does not match expected '{}'",
        actual,
        expected_profile.name()
    )))
}

fn validate_check_policy(metadata: &crate::CompileMetadata, args: &CheckArgs) -> Result<()> {
    let mut violations = Vec::new();

    if args.production || args.deny_fail_closed {
        if !metadata.constraints.failures.is_empty() {
            violations.push(format!("constraints failures: {}", metadata.constraints.failures.join(", ")));
        }

        if !metadata.runtime.fail_closed_runtime_features.is_empty() {
            violations.push(format!("fail-closed runtime features: {}", metadata.runtime.fail_closed_runtime_features.join(", ")));
        }

        let fail_closed_obligations = metadata
            .runtime
            .verifier_obligations
            .iter()
            .filter(|obligation| obligation.status == "fail-closed")
            .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
            .collect::<Vec<_>>();
        if !fail_closed_obligations.is_empty() {
            violations.push(format!("fail-closed verifier obligations: {}", fail_closed_obligations.join(", ")));
        }
    }

    if args.deny_symbolic_runtime {
        if metadata.runtime.symbolic_cell_runtime_required {
            violations.push(format!(
                "symbolic Cell/runtime features: {}",
                metadata.runtime.legacy_symbolic_cell_runtime_features.join(", ")
            ));
        }
        let unsupported_obligations = metadata
            .runtime
            .verifier_obligations
            .iter()
            .filter(|obligation| obligation.status == "unsupported-standalone")
            .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
            .collect::<Vec<_>>();
        if !unsupported_obligations.is_empty() {
            violations.push(format!("standalone-ELF limitations: {}", unsupported_obligations.join(", ")));
        }
    }

    if args.deny_ckb_runtime && metadata.runtime.ckb_runtime_required {
        violations.push(format!("CKB runtime features: {}", metadata.runtime.ckb_runtime_features.join(", ")));
    }

    if args.deny_runtime_obligations {
        let runtime_required_obligations = metadata
            .runtime
            .verifier_obligations
            .iter()
            .filter(|obligation| obligation.status == "runtime-required")
            .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
            .collect::<Vec<_>>();
        if !runtime_required_obligations.is_empty() {
            violations.push(format!("runtime-required verifier obligations: {}", runtime_required_obligations.join(", ")));
        }

        let transaction_invariants = transaction_invariant_checked_subcondition_summaries(metadata);
        if !transaction_invariants.is_empty() {
            violations.push(format!(
                "runtime-required transaction invariants with checked subconditions: {}",
                transaction_invariants.join(", ")
            ));
        }

        let transaction_runtime_inputs = transaction_runtime_input_requirement_summaries_by_status(metadata, "runtime-required");
        if !transaction_runtime_inputs.is_empty() {
            violations
                .push(format!("runtime-required transaction runtime input requirements: {}", transaction_runtime_inputs.join(", ")));
        }

        let transaction_runtime_input_blockers = transaction_runtime_input_blocker_summaries_by_status(metadata, "runtime-required");
        if !transaction_runtime_input_blockers.is_empty() {
            violations.push(format!(
                "runtime-required transaction runtime input blockers: {}",
                transaction_runtime_input_blockers.join(", ")
            ));
        }

        let transaction_runtime_input_blocker_classes =
            transaction_runtime_input_blocker_class_summaries_by_status(metadata, "runtime-required");
        if !transaction_runtime_input_blocker_classes.is_empty() {
            violations.push(format!(
                "runtime-required transaction runtime input blocker classes: {}",
                transaction_runtime_input_blocker_classes.join(", ")
            ));
        }

        let runtime_required_pool_invariants = pool_invariant_family_summaries(metadata, "runtime-required");
        if !runtime_required_pool_invariants.is_empty() {
            violations.push(format!("runtime-required Pool invariant families: {}", runtime_required_pool_invariants.join(", ")));
        }

        let runtime_required_pool_blocker_classes = pool_invariant_family_blocker_class_summaries(metadata, "runtime-required");
        if !runtime_required_pool_blocker_classes.is_empty() {
            violations.push(format!(
                "runtime-required Pool invariant blocker classes: {}",
                runtime_required_pool_blocker_classes.join(", ")
            ));
        }

        let pool_runtime_inputs = pool_runtime_input_requirement_summaries(metadata);
        if !pool_runtime_inputs.is_empty() {
            violations.push(format!("runtime-required Pool runtime input requirements: {}", pool_runtime_inputs.join(", ")));
        }
    }

    if violations.is_empty() {
        return Ok(());
    }

    Err(crate::error::CompileError::without_span(format!("check policy failed:\n  - {}", violations.join("\n  - "))))
}

fn target_profile_policy_violations(
    metadata: &crate::CompileMetadata,
    artifact_format: ArtifactFormat,
    profile: TargetProfile,
) -> Vec<String> {
    match profile {
        TargetProfile::Spora => spora_target_profile_policy_violations(metadata),
        TargetProfile::Ckb => ckb_target_profile_policy_violations(metadata, artifact_format),
        TargetProfile::PortableCell => portable_cell_target_profile_policy_violations(metadata),
    }
}

fn spora_target_profile_policy_violations(metadata: &crate::CompileMetadata) -> Vec<String> {
    let mut violations = Vec::new();
    let ckb_only_features = ckb_only_feature_names(metadata);
    if !ckb_only_features.is_empty() {
        violations.push(format!("CKB chain APIs require the 'ckb' target profile: {}", ckb_only_features.join(", ")));
    }
    violations
}

fn ckb_target_profile_policy_violations(metadata: &crate::CompileMetadata, _artifact_format: ArtifactFormat) -> Vec<String> {
    let mut violations = common_portability_policy_violations(metadata);

    let spora_only_features = metadata
        .runtime
        .ckb_runtime_features
        .iter()
        .filter(|feature| matches!(feature.as_str(), "load-claim-ecdsa-signature-hash" | "verify-claim-secp256k1-signature"))
        .cloned()
        .collect::<Vec<_>>();
    if !spora_only_features.is_empty() {
        violations.push(format!("Spora-only claim helper syscall features: {}", spora_only_features.join(", ")));
    }

    violations
}

fn portable_cell_target_profile_policy_violations(metadata: &crate::CompileMetadata) -> Vec<String> {
    let mut violations = common_portability_policy_violations(metadata);
    let ckb_only_features = ckb_only_feature_names(metadata);
    if !ckb_only_features.is_empty() {
        violations.push(format!("CKB chain APIs are target-specific and not portable: {}", ckb_only_features.join(", ")));
    }
    violations
}

fn common_portability_policy_violations(metadata: &crate::CompileMetadata) -> Vec<String> {
    let mut violations = Vec::new();

    if metadata.runtime.ckb_runtime_features.iter().any(|feature| feature == "load-header-daa-score") {
        violations.push("DAA/header assumptions are Spora-specific and not portable across target profiles".to_string());
    }

    if metadata.runtime.symbolic_cell_runtime_required {
        violations.push(format!(
            "symbolic Cell/runtime features are not portable: {}",
            metadata.runtime.legacy_symbolic_cell_runtime_features.join(", ")
        ));
    }
    if !metadata.runtime.fail_closed_runtime_features.is_empty() {
        violations.push(format!(
            "fail-closed runtime features are not portable: {}",
            metadata.runtime.fail_closed_runtime_features.join(", ")
        ));
    }

    let runtime_required_obligations = metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.status == "runtime-required")
        .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
        .collect::<Vec<_>>();
    if !runtime_required_obligations.is_empty() {
        violations
            .push(format!("runtime-required verifier obligations are not portable: {}", runtime_required_obligations.join(", ")));
    }

    let runtime_required_inputs = transaction_runtime_input_requirement_summaries_by_status(metadata, "runtime-required");
    if !runtime_required_inputs.is_empty() {
        violations.push(format!("runtime-required transaction inputs are not portable: {}", runtime_required_inputs.join(", ")));
    }

    let persistent_types_without_schema = metadata
        .types
        .iter()
        .filter(|ty| matches!(ty.kind.as_str(), "Resource" | "Shared" | "Receipt"))
        .filter(|ty| !type_has_public_molecule_schema(ty))
        .map(|ty| format!("{} ({})", ty.name, ty.kind))
        .collect::<Vec<_>>();
    if !persistent_types_without_schema.is_empty() {
        violations.push(format!(
            "generated Molecule schemas are required before persistent Cell types can be CKB-portable: {}",
            persistent_types_without_schema.join(", ")
        ));
    }

    let type_only_type_ids = metadata
        .types
        .iter()
        .filter(|ty| ty.type_id.is_some() && ty.ckb_type_id.is_none())
        .map(|ty| ty.name.clone())
        .collect::<Vec<_>>();
    if !type_only_type_ids.is_empty() {
        violations.push(format!(
            "type-only type_id declarations require profile-specific type-id lowering before they are portable: {}",
            type_only_type_ids.join(", ")
        ));
    }

    let shared_touch_actions = metadata
        .actions
        .iter()
        .filter(|action| !action.touches_shared.is_empty())
        .map(|action| action.name.clone())
        .collect::<Vec<_>>();
    if !shared_touch_actions.is_empty() {
        violations.push(format!("Spora shared-state scheduler touch domains are not portable: {}", shared_touch_actions.join(", ")));
    }

    if !metadata.runtime.pool_primitives.is_empty() {
        let pool_features = metadata.runtime.pool_primitives.iter().map(|primitive| primitive.feature.clone()).collect::<Vec<_>>();
        violations.push(format!("Spora pool-pattern scheduler/admission semantics are not portable: {}", pool_features.join(", ")));
    }

    violations
}

fn ckb_only_feature_names(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata
        .runtime
        .ckb_runtime_features
        .iter()
        .filter(|feature| feature.starts_with("ckb-header-epoch-") || feature.as_str() == "ckb-input-since")
        .cloned()
        .collect()
}

fn type_has_public_molecule_schema(ty: &crate::TypeMetadata) -> bool {
    ty.molecule_schema.as_ref().is_some_and(|schema| {
        schema.abi == "molecule"
            && matches!(schema.layout.as_str(), "fixed-struct-v1" | "molecule-table-v1")
            && !schema.schema.is_empty()
    })
}

fn runtime_required_obligation_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.verifier_obligations.iter().filter(|obligation| obligation.status == "runtime-required").count()
}

fn fail_closed_obligation_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.verifier_obligations.iter().filter(|obligation| obligation.status == "fail-closed").count()
}

fn runtime_required_transaction_invariant_count(metadata: &crate::CompileMetadata) -> usize {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .count()
}

fn runtime_required_transaction_invariant_checked_subcondition_count(metadata: &crate::CompileMetadata) -> usize {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .map(|obligation| checked_runtime_subconditions(&obligation.detail).len())
        .sum()
}

fn transaction_invariant_checked_subcondition_summaries(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .filter_map(|obligation| {
            let subconditions = checked_runtime_subconditions(&obligation.detail);
            if subconditions.is_empty() {
                None
            } else {
                Some(format!("{}:{} checked=[{}]", obligation.scope, obligation.feature, subconditions.join(",")))
            }
        })
        .collect()
}

fn transaction_runtime_input_requirement_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.transaction_runtime_input_requirements.len()
}

fn transaction_runtime_input_requirement_count_by_status(metadata: &crate::CompileMetadata, status: &str) -> usize {
    metadata.runtime.transaction_runtime_input_requirements.iter().filter(|requirement| requirement.status == status).count()
}

fn transaction_runtime_input_requirement_summaries(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata.runtime.transaction_runtime_input_requirements.iter().map(transaction_runtime_input_requirement_summary).collect()
}

fn transaction_runtime_input_requirement_summaries_by_status(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == status)
        .map(transaction_runtime_input_requirement_summary)
        .collect()
}

fn transaction_runtime_input_blocker_count_by_status(metadata: &crate::CompileMetadata, status: &str) -> usize {
    transaction_runtime_input_blocker_summaries_by_status(metadata, status).len()
}

fn transaction_runtime_input_blocker_summaries_by_status(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == status)
        .filter_map(|requirement| {
            requirement.blocker.as_deref().map(|blocker| {
                let blocker_class = requirement
                    .blocker_class
                    .as_deref()
                    .map(|blocker_class| format!(" blocker_class={}", blocker_class))
                    .unwrap_or_default();
                format!("{}:{}:{} blocker={}{}", requirement.scope, requirement.feature, requirement.component, blocker, blocker_class)
            })
        })
        .collect()
}

fn transaction_runtime_input_blocker_class_count_by_status(metadata: &crate::CompileMetadata, status: &str) -> usize {
    transaction_runtime_input_blocker_class_summaries_by_status(metadata, status).len()
}

fn transaction_runtime_input_blocker_class_summaries_by_status(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == status)
        .filter_map(|requirement| {
            requirement.blocker_class.as_deref().map(|blocker_class| {
                format!("{}:{}:{} blocker_class={}", requirement.scope, requirement.feature, requirement.component, blocker_class)
            })
        })
        .collect()
}

fn transaction_runtime_input_requirement_summary(requirement: &crate::TransactionRuntimeInputRequirementMetadata) -> String {
    let field = requirement.field.as_deref().map(|field| format!(".{}", field)).unwrap_or_default();
    let bytes = requirement.byte_len.map(|byte_len| format!("[{}]", byte_len)).unwrap_or_default();
    let blocker = requirement.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
    let blocker_class = requirement.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
    format!(
        "{}:{}:{}={}:{}{}:{}{} ({}){}{}",
        requirement.scope,
        requirement.feature,
        requirement.component,
        requirement.source,
        requirement.binding,
        field,
        requirement.abi,
        bytes,
        requirement.status,
        blocker,
        blocker_class
    )
}

fn checked_runtime_subconditions(detail: &str) -> Vec<String> {
    detail
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter_map(|part| part.trim().strip_suffix("=checked-runtime"))
        .map(|name| name.trim_matches(|ch: char| ch == '`' || ch == '.' || ch == ':').to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

fn checked_pool_invariant_family_count(metadata: &crate::CompileMetadata) -> usize {
    pool_invariant_family_summaries(metadata, "checked-runtime").len()
}

fn runtime_required_pool_invariant_family_count(metadata: &crate::CompileMetadata) -> usize {
    pool_invariant_family_summaries(metadata, "runtime-required").len()
}

fn pool_runtime_input_requirement_count(metadata: &crate::CompileMetadata) -> usize {
    metadata.runtime.pool_primitives.iter().map(|primitive| primitive.runtime_input_requirements.len()).sum()
}

fn pool_runtime_input_requirement_summaries(metadata: &crate::CompileMetadata) -> Vec<String> {
    metadata
        .runtime
        .pool_primitives
        .iter()
        .flat_map(|primitive| {
            primitive.runtime_input_requirements.iter().map(move |requirement| {
                let field = requirement.field.as_deref().map(|field| format!(".{}", field)).unwrap_or_default();
                let blocker = requirement.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
                let blocker_class =
                    requirement.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
                format!(
                    "{}:{}:{}={}#{}:{}{}:{}[{}]{}{}",
                    primitive.scope,
                    primitive.feature,
                    requirement.component,
                    requirement.source,
                    requirement.index,
                    requirement.binding,
                    field,
                    requirement.abi,
                    requirement.byte_len,
                    blocker,
                    blocker_class
                )
            })
        })
        .collect()
}

fn pool_invariant_family_summaries(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .pool_primitives
        .iter()
        .flat_map(|primitive| {
            primitive.invariant_families.iter().filter(move |family| family.status == status).map(move |family| {
                let blocker = family.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
                let blocker_class =
                    family.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
                format!("{}:{}:{} ({}){}{}", primitive.scope, primitive.feature, family.name, family.source, blocker, blocker_class)
            })
        })
        .collect()
}

fn pool_invariant_family_blocker_class_count(metadata: &crate::CompileMetadata, status: &str) -> usize {
    pool_invariant_family_blocker_class_summaries(metadata, status).len()
}

fn pool_invariant_family_blocker_class_summaries(metadata: &crate::CompileMetadata, status: &str) -> Vec<String> {
    metadata
        .runtime
        .pool_primitives
        .iter()
        .flat_map(|primitive| {
            primitive.invariant_families.iter().filter(move |family| family.status == status).filter_map(move |family| {
                family.blocker_class.as_deref().map(|blocker_class| {
                    format!("{}:{}:{} blocker_class={}", primitive.scope, primitive.feature, family.name, blocker_class)
                })
            })
        })
        .collect()
}

#[derive(Debug, Default)]
struct CompileTestExpectation {
    expect_success: bool,
    expect_fail: bool,
    expected_errors: Vec<String>,
    target: Option<String>,
    production: bool,
    deny_fail_closed: bool,
    deny_symbolic_runtime: bool,
    deny_ckb_runtime: bool,
    deny_runtime_obligations: bool,
    expect_standalone: Option<bool>,
    expect_ckb_runtime: Option<bool>,
    expect_symbolic_runtime: Option<bool>,
    expect_fail_closed: Option<bool>,
    expected_runtime_features: Vec<String>,
    forbidden_runtime_features: Vec<String>,
    expected_verifier_obligations: Vec<String>,
    forbidden_verifier_obligations: Vec<String>,
    expected_runtime_required_obligations: Vec<String>,
    forbidden_runtime_required_obligations: Vec<String>,
    expected_artifact_format: Option<String>,
    expected_actions: Vec<String>,
    forbidden_actions: Vec<String>,
    expected_functions: Vec<String>,
    forbidden_functions: Vec<String>,
    expected_locks: Vec<String>,
    forbidden_locks: Vec<String>,
}

impl CompileTestExpectation {
    fn check_args(&self) -> CheckArgs {
        CheckArgs {
            all_targets: false,
            target_profile: None,
            features: Vec::new(),
            json: false,
            production: self.production,
            deny_fail_closed: self.deny_fail_closed,
            deny_symbolic_runtime: self.deny_symbolic_runtime,
            deny_ckb_runtime: self.deny_ckb_runtime,
            deny_runtime_obligations: self.deny_runtime_obligations,
        }
    }
}

fn read_test_expectation(path: &Path) -> Result<CompileTestExpectation> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| crate::error::CompileError::without_span(format!("failed to read test '{}': {}", path.display(), error)))?;
    parse_test_expectation(path, &source)
}

fn parse_test_expectation(path: &Path, source: &str) -> Result<CompileTestExpectation> {
    let mut expectation = CompileTestExpectation::default();
    for (line_number, line) in source.lines().enumerate() {
        let Some(marker) = line.split("//").nth(1).map(str::trim) else {
            continue;
        };
        let Some(directive) = marker.strip_prefix("cellscript-test:").map(str::trim) else {
            continue;
        };

        if directive == "expect-success" {
            expectation.expect_success = true;
        } else if directive == "expect-fail" {
            expectation.expect_fail = true;
        } else if let Some(expected) = directive.strip_prefix("expect-error:").map(str::trim) {
            expectation.expect_fail = true;
            if !expected.is_empty() {
                expectation.expected_errors.push(expected.to_string());
            }
        } else if let Some(target) = directive.strip_prefix("target:").map(str::trim) {
            if target.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "target directive requires a non-empty target"));
            }
            if expectation.target.replace(target.to_string()).is_some() {
                return Err(compile_test_directive_error(path, line_number, "target directive may only appear once"));
            }
        } else if directive == "production" {
            expectation.production = true;
        } else if directive == "deny-fail-closed" {
            expectation.deny_fail_closed = true;
        } else if directive == "deny-symbolic-runtime" {
            expectation.deny_symbolic_runtime = true;
        } else if directive == "deny-ckb-runtime" {
            expectation.deny_ckb_runtime = true;
        } else if directive == "deny-runtime-obligations" {
            expectation.deny_runtime_obligations = true;
        } else if directive == "expect-standalone" {
            expectation.expect_standalone = Some(true);
        } else if directive == "expect-not-standalone" {
            expectation.expect_standalone = Some(false);
        } else if directive == "expect-ckb-runtime" {
            expectation.expect_ckb_runtime = Some(true);
        } else if directive == "expect-no-ckb-runtime" {
            expectation.expect_ckb_runtime = Some(false);
        } else if directive == "expect-symbolic-runtime" {
            expectation.expect_symbolic_runtime = Some(true);
        } else if directive == "expect-no-symbolic-runtime" {
            expectation.expect_symbolic_runtime = Some(false);
        } else if directive == "expect-fail-closed-runtime" {
            expectation.expect_fail_closed = Some(true);
        } else if directive == "expect-no-fail-closed-runtime" {
            expectation.expect_fail_closed = Some(false);
        } else if let Some(feature) = directive.strip_prefix("expect-runtime-feature:").map(str::trim) {
            if feature.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "expect-runtime-feature requires non-empty text"));
            }
            expectation.expected_runtime_features.push(feature.to_string());
        } else if let Some(feature) = directive.strip_prefix("expect-no-runtime-feature:").map(str::trim) {
            if feature.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "expect-no-runtime-feature requires non-empty text"));
            }
            expectation.forbidden_runtime_features.push(feature.to_string());
        } else if let Some(obligation) = directive.strip_prefix("expect-verifier-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-verifier-obligation",
                obligation,
                &mut expectation.expected_verifier_obligations,
            )?;
        } else if let Some(obligation) = directive.strip_prefix("expect-no-verifier-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-no-verifier-obligation",
                obligation,
                &mut expectation.forbidden_verifier_obligations,
            )?;
        } else if let Some(obligation) = directive.strip_prefix("expect-runtime-required-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-runtime-required-obligation",
                obligation,
                &mut expectation.expected_runtime_required_obligations,
            )?;
        } else if let Some(obligation) = directive.strip_prefix("expect-no-runtime-required-obligation:").map(str::trim) {
            push_non_empty_test_directive(
                path,
                line_number,
                "expect-no-runtime-required-obligation",
                obligation,
                &mut expectation.forbidden_runtime_required_obligations,
            )?;
        } else if let Some(format) = directive.strip_prefix("expect-artifact-format:").map(str::trim) {
            if format.is_empty() {
                return Err(compile_test_directive_error(path, line_number, "expect-artifact-format requires non-empty text"));
            }
            if expectation.expected_artifact_format.replace(format.to_string()).is_some() {
                return Err(compile_test_directive_error(path, line_number, "expect-artifact-format may only appear once"));
            }
        } else if let Some(name) = directive.strip_prefix("expect-action:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-action", name, &mut expectation.expected_actions)?;
        } else if let Some(name) = directive.strip_prefix("expect-no-action:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-no-action", name, &mut expectation.forbidden_actions)?;
        } else if let Some(name) = directive.strip_prefix("expect-function:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-function", name, &mut expectation.expected_functions)?;
        } else if let Some(name) = directive.strip_prefix("expect-no-function:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-no-function", name, &mut expectation.forbidden_functions)?;
        } else if let Some(name) = directive.strip_prefix("expect-lock:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-lock", name, &mut expectation.expected_locks)?;
        } else if let Some(name) = directive.strip_prefix("expect-no-lock:").map(str::trim) {
            push_non_empty_test_directive(path, line_number, "expect-no-lock", name, &mut expectation.forbidden_locks)?;
        } else {
            return Err(compile_test_directive_error(
                path,
                line_number,
                &format!("unknown cellscript-test directive '{}'", directive),
            ));
        }
    }
    if expectation.expect_success && expectation.expect_fail {
        return Err(crate::error::CompileError::without_span(format!(
            "{}: conflicting cellscript-test directives: expect-success cannot be combined with expect-fail/expect-error",
            path.display()
        )));
    }
    Ok(expectation)
}

fn push_non_empty_test_directive(
    path: &Path,
    zero_based_line: usize,
    directive: &str,
    value: &str,
    values: &mut Vec<String>,
) -> Result<()> {
    if value.is_empty() {
        return Err(compile_test_directive_error(path, zero_based_line, &format!("{} requires non-empty text", directive)));
    }
    values.push(value.to_string());
    Ok(())
}

fn compile_test_directive_error(path: &Path, zero_based_line: usize, message: &str) -> crate::error::CompileError {
    crate::error::CompileError::without_span(format!("{}:{}: {}", path.display(), zero_based_line + 1, message))
}

fn evaluate_compile_test_result(
    path: &Utf8Path,
    expectation: &CompileTestExpectation,
    result: Result<crate::CompileResult>,
) -> Result<()> {
    match (expectation.expect_fail, result) {
        (false, Ok(result)) => validate_compile_test_metadata(path, expectation, &result.metadata),
        (false, Err(error)) => {
            Err(crate::error::CompileError::without_span(format!("{}: expected compile success, got error: {}", path, error)))
        }
        (true, Ok(_)) => Err(crate::error::CompileError::without_span(format!("{}: expected compile failure, got success", path))),
        (true, Err(error)) => {
            let message = error.to_string();
            let missing = expectation
                .expected_errors
                .iter()
                .filter(|expected| !message.contains(expected.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if missing.is_empty() {
                Ok(())
            } else {
                Err(crate::error::CompileError::without_span(format!(
                    "{}: expected error text not found: {}; actual error: {}",
                    path,
                    missing.join(", "),
                    message
                )))
            }
        }
    }
}

fn validate_compile_test_metadata(
    path: &Utf8Path,
    expectation: &CompileTestExpectation,
    metadata: &crate::CompileMetadata,
) -> Result<()> {
    if let Some(expected) = &expectation.expected_artifact_format {
        if &metadata.artifact_format != expected {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected artifact_format='{}', got '{}'",
                path, expected, metadata.artifact_format
            )));
        }
    }

    if let Some(expected) = expectation.expect_standalone {
        if metadata.runtime.standalone_runner_compatible != expected {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected standalone_runner_compatible={}, got {}",
                path, expected, metadata.runtime.standalone_runner_compatible
            )));
        }
    }
    if let Some(expected) = expectation.expect_ckb_runtime {
        if metadata.runtime.ckb_runtime_required != expected {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected ckb_runtime_required={}, got {}",
                path, expected, metadata.runtime.ckb_runtime_required
            )));
        }
    }
    if let Some(expected) = expectation.expect_symbolic_runtime {
        if metadata.runtime.symbolic_cell_runtime_required != expected {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected symbolic_cell_runtime_required={}, got {}",
                path, expected, metadata.runtime.symbolic_cell_runtime_required
            )));
        }
    }
    if let Some(expected) = expectation.expect_fail_closed {
        let actual = !metadata.runtime.fail_closed_runtime_features.is_empty()
            || metadata.runtime.verifier_obligations.iter().any(|obligation| obligation.status == "fail-closed");
        if actual != expected {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected fail_closed_runtime={}, got {}",
                path, expected, actual
            )));
        }
    }

    let runtime_summary = compile_test_runtime_summary(metadata);
    for expected in &expectation.expected_runtime_features {
        if !runtime_summary.contains(expected) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected runtime metadata to contain '{}'",
                path, expected
            )));
        }
    }
    for forbidden in &expectation.forbidden_runtime_features {
        if runtime_summary.contains(forbidden) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected runtime metadata not to contain '{}'",
                path, forbidden
            )));
        }
    }

    validate_compile_test_summary_contains(
        path,
        "verifier obligation",
        &compile_test_obligation_summary(metadata, None),
        &expectation.expected_verifier_obligations,
        &expectation.forbidden_verifier_obligations,
    )?;
    validate_compile_test_summary_contains(
        path,
        "runtime-required verifier obligation",
        &compile_test_obligation_summary(metadata, Some("runtime-required")),
        &expectation.expected_runtime_required_obligations,
        &expectation.forbidden_runtime_required_obligations,
    )?;

    validate_named_metadata_set(
        path,
        "action",
        &metadata.actions.iter().map(|action| action.name.as_str()).collect::<Vec<_>>(),
        &expectation.expected_actions,
        &expectation.forbidden_actions,
    )?;
    validate_named_metadata_set(
        path,
        "function",
        &metadata.functions.iter().map(|function| function.name.as_str()).collect::<Vec<_>>(),
        &expectation.expected_functions,
        &expectation.forbidden_functions,
    )?;
    validate_named_metadata_set(
        path,
        "lock",
        &metadata.locks.iter().map(|lock| lock.name.as_str()).collect::<Vec<_>>(),
        &expectation.expected_locks,
        &expectation.forbidden_locks,
    )?;

    Ok(())
}

fn validate_compile_test_summary_contains(
    path: &Utf8Path,
    label: &str,
    summary: &str,
    expected: &[String],
    forbidden: &[String],
) -> Result<()> {
    for expected in expected {
        if !summary.contains(expected) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata to contain '{}'",
                path, label, expected
            )));
        }
    }
    for forbidden in forbidden {
        if summary.contains(forbidden) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata not to contain '{}'",
                path, label, forbidden
            )));
        }
    }
    Ok(())
}

fn validate_named_metadata_set(path: &Utf8Path, kind: &str, actual: &[&str], expected: &[String], forbidden: &[String]) -> Result<()> {
    for name in expected {
        if !actual.iter().any(|actual_name| actual_name == name) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata to contain '{}'",
                path, kind, name
            )));
        }
    }
    for name in forbidden {
        if actual.iter().any(|actual_name| actual_name == name) {
            return Err(crate::error::CompileError::without_span(format!(
                "{}: expected {} metadata not to contain '{}'",
                path, kind, name
            )));
        }
    }
    Ok(())
}

fn compile_test_runtime_summary(metadata: &crate::CompileMetadata) -> String {
    let mut values = Vec::new();
    values.extend(metadata.runtime.ckb_runtime_features.iter().cloned());
    values.extend(metadata.runtime.legacy_symbolic_cell_runtime_features.iter().cloned());
    values.extend(metadata.runtime.fail_closed_runtime_features.iter().cloned());
    for access in &metadata.runtime.ckb_runtime_accesses {
        values.push(format!("{}:{}:{}:{}:{}", access.operation, access.syscall, access.source, access.index, access.binding));
    }
    for obligation in &metadata.runtime.verifier_obligations {
        values.push(format!(
            "{}:{}:{}:{}:{}",
            obligation.scope, obligation.category, obligation.feature, obligation.status, obligation.detail
        ));
    }
    values.join("\n")
}

fn compile_test_obligation_summary(metadata: &crate::CompileMetadata, status: Option<&str>) -> String {
    metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| match status {
            Some(status) => obligation.status == status,
            None => true,
        })
        .map(|obligation| {
            format!("{}:{}:{}:{}:{}", obligation.scope, obligation.category, obligation.feature, obligation.status, obligation.detail)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_cell_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    if root.is_file() {
        return Ok(if root.extension().and_then(|ext| ext.to_str()) == Some("cell") { vec![root.to_path_buf()] } else { Vec::new() });
    }

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("cell") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

#[cfg(feature = "vm-runner")]
fn run_elf_in_ckb_vm(program: &[u8], args: &[Vec<u8>]) -> Result<u64> {
    let core_machine =
        <<CliVmMachine as DefaultMachineRunner>::Inner as SupportMachine>::new(ISA_IMC | ISA_B | ISA_MOP, VERSION2, 10_000_000);
    let builder = DefaultMachineBuilder::new(core_machine).instruction_cycle_func(Box::new(estimate_cycles));
    let mut machine = CliVmMachine::new(builder.build());
    let program = Bytes::copy_from_slice(crate::strip_vm_abi_trailer(program));
    let args = args.iter().cloned().map(Bytes::from).map(Ok);

    machine
        .load_program(&program, args)
        .map_err(|error| crate::error::CompileError::without_span(format!("cellc run failed to load ELF: {}", error)))?;
    let exit_code =
        machine.run().map_err(|error| crate::error::CompileError::without_span(format!("cellc run VM error: {}", error)))?;
    if exit_code != 0 {
        return Err(crate::error::CompileError::without_span(format!("cellc run exited with code {}", exit_code)));
    }

    Ok(machine.machine.cycles())
}

struct SelectedEntryWitnessMetadata<'a> {
    kind: &'static str,
    name: &'a str,
    params: &'a [ParamMetadata],
    runtime_bound_param_names: std::collections::BTreeSet<String>,
}

fn select_entry_witness_metadata<'a>(
    metadata: &'a CompileMetadata,
    action: Option<&str>,
    lock: Option<&str>,
) -> Result<SelectedEntryWitnessMetadata<'a>> {
    if let Some(name) = action {
        let action = metadata
            .actions
            .iter()
            .find(|candidate| candidate.name == name)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("action '{}' was not found in metadata", name)))?;
        return Ok(SelectedEntryWitnessMetadata {
            kind: "action",
            name: action.name.as_str(),
            params: &action.params,
            runtime_bound_param_names: action
                .consume_set
                .iter()
                .map(|pattern| pattern.binding.clone())
                .chain(action.read_refs.iter().map(|pattern| pattern.binding.clone()))
                .chain(action.mutate_set.iter().map(|pattern| pattern.binding.clone()))
                .collect(),
        });
    }
    if let Some(name) = lock {
        let lock = metadata
            .locks
            .iter()
            .find(|candidate| candidate.name == name)
            .ok_or_else(|| crate::error::CompileError::without_span(format!("lock '{}' was not found in metadata", name)))?;
        return Ok(SelectedEntryWitnessMetadata {
            kind: "lock",
            name: lock.name.as_str(),
            params: &lock.params,
            runtime_bound_param_names: lock
                .consume_set
                .iter()
                .map(|pattern| pattern.binding.clone())
                .chain(lock.read_refs.iter().map(|pattern| pattern.binding.clone()))
                .chain(lock.mutate_set.iter().map(|pattern| pattern.binding.clone()))
                .collect(),
        });
    }

    let mut entries = metadata
        .actions
        .iter()
        .filter(|action| !action.params.is_empty())
        .map(|action| SelectedEntryWitnessMetadata {
            kind: "action",
            name: action.name.as_str(),
            params: action.params.as_slice(),
            runtime_bound_param_names: action
                .consume_set
                .iter()
                .map(|pattern| pattern.binding.clone())
                .chain(action.read_refs.iter().map(|pattern| pattern.binding.clone()))
                .chain(action.mutate_set.iter().map(|pattern| pattern.binding.clone()))
                .collect(),
        })
        .chain(metadata.locks.iter().filter(|lock| !lock.params.is_empty()).map(|lock| {
            SelectedEntryWitnessMetadata {
                kind: "lock",
                name: lock.name.as_str(),
                params: lock.params.as_slice(),
                runtime_bound_param_names: lock
                    .consume_set
                    .iter()
                    .map(|pattern| pattern.binding.clone())
                    .chain(lock.read_refs.iter().map(|pattern| pattern.binding.clone()))
                    .chain(lock.mutate_set.iter().map(|pattern| pattern.binding.clone()))
                    .collect(),
            }
        }))
        .collect::<Vec<_>>();

    match entries.len() {
        1 => Ok(entries.remove(0)),
        0 => Err(crate::error::CompileError::without_span(
            "no parameterized action or lock found; specify --action or --lock for explicit selection",
        )),
        _ => Err(crate::error::CompileError::without_span(
            "multiple parameterized actions/locks found; specify --action NAME or --lock NAME",
        )),
    }
}

fn parse_entry_witness_arg(param: &ParamMetadata, value: &str) -> Result<EntryWitnessArg> {
    if param.schema_pointer_abi || param.schema_length_abi {
        return decode_hex_arg(&param.name, value, None).map(EntryWitnessArg::Bytes);
    }

    if let Some(width) = param.fixed_byte_len {
        return parse_entry_witness_fixed_arg(param, value, width);
    }

    match param.ty.as_str() {
        "bool" => parse_bool_arg(&param.name, value).map(EntryWitnessArg::Bool),
        "u8" => parse_integer_arg(&param.name, value, u8::MAX as u128).map(|value| EntryWitnessArg::U8(value as u8)),
        "u16" => parse_integer_arg(&param.name, value, u16::MAX as u128).map(|value| EntryWitnessArg::U16(value as u16)),
        "u32" => parse_integer_arg(&param.name, value, u32::MAX as u128).map(|value| EntryWitnessArg::U32(value as u32)),
        "u64" => parse_integer_arg(&param.name, value, u64::MAX as u128).map(|value| EntryWitnessArg::U64(value as u64)),
        "()" => Ok(EntryWitnessArg::Unit),
        other => {
            let Some(width) = crate::entry_witness_static_type_len(other).filter(|width| (1..=8).contains(width)) else {
                return Err(crate::error::CompileError::without_span(format!(
                    "parameter '{}' has unsupported entry witness CLI type '{}'",
                    param.name, param.ty
                )));
            };
            decode_hex_arg(&param.name, value, Some(width)).map(EntryWitnessArg::Bytes)
        }
    }
}

fn parse_entry_witness_fixed_arg(param: &ParamMetadata, value: &str, width: usize) -> Result<EntryWitnessArg> {
    match param.ty.as_str() {
        "u128" if width == 16 => parse_integer_arg(&param.name, value, u128::MAX).map(EntryWitnessArg::U128),
        "Address" if width == 32 => {
            let bytes = decode_hex_arg(&param.name, value, Some(32))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                crate::error::CompileError::without_span(format!("parameter '{}' expects exactly 32 hex bytes", param.name))
            })?;
            Ok(EntryWitnessArg::Address(bytes))
        }
        "Hash" if width == 32 => {
            let bytes = decode_hex_arg(&param.name, value, Some(32))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                crate::error::CompileError::without_span(format!("parameter '{}' expects exactly 32 hex bytes", param.name))
            })?;
            Ok(EntryWitnessArg::Hash(bytes))
        }
        _ => decode_hex_arg(&param.name, value, Some(width)).map(EntryWitnessArg::Bytes),
    }
}

fn parse_bool_arg(name: &str, value: &str) -> Result<bool> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(crate::error::CompileError::without_span(format!(
            "parameter '{}' expects bool value true/false/1/0, got '{}'",
            name, other
        ))),
    }
}

fn parse_integer_arg(name: &str, value: &str, max: u128) -> Result<u128> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u128>()
    }
    .map_err(|error| crate::error::CompileError::without_span(format!("parameter '{}' expects integer: {}", name, error)))?;
    if parsed > max {
        return Err(crate::error::CompileError::without_span(format!(
            "parameter '{}' integer value {} is out of range",
            name, parsed
        )));
    }
    Ok(parsed)
}

fn decode_hex_arg(name: &str, value: &str, expected_len: Option<usize>) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("hex:")
        .or_else(|| trimmed.strip_prefix("HEX:"))
        .or_else(|| trimmed.strip_prefix("0x"))
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() % 2 != 0 {
        return Err(crate::error::CompileError::without_span(format!("parameter '{}' hex value must contain full bytes", name)));
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16).map_err(|error| {
                crate::error::CompileError::without_span(format!(
                    "parameter '{}' has invalid hex byte at offset {}: {}",
                    name, index, error
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(expected_len) = expected_len {
        if bytes.len() != expected_len {
            return Err(crate::error::CompileError::without_span(format!(
                "parameter '{}' expects {} byte(s), got {}",
                name,
                expected_len,
                bytes.len()
            )));
        }
    }
    Ok(bytes)
}

pub struct CliParser;

impl CliParser {
    pub fn parse() -> Command {
        use clap::{Arg, ArgAction, Command as ClapCommand};

        let matches = ClapCommand::new("cellc")
            .version(crate::VERSION)
            .about("CellScript compiler for Spora blockchain")
            .subcommand_required(true)
            .arg_required_else_help(true)
            .subcommand(
                ClapCommand::new("build")
                    .about("Compile the current package")
                    .arg(Arg::new("release").long("release").short('r').action(ArgAction::SetTrue).help("Build in release mode"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    )
                    .arg(
                        Arg::new("entry-action")
                            .long("entry-action")
                            .value_name("ACTION")
                            .help("Compile only this action as the artifact entrypoint"),
                    )
                    .arg(
                        Arg::new("entry-lock")
                            .long("entry-lock")
                            .value_name("LOCK")
                            .conflicts_with("entry-action")
                            .help("Compile only this lock as the artifact entrypoint"),
                    )
                    .arg(Arg::new("jobs").long("jobs").short('j').value_name("N").help("Number of parallel jobs"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON build summary"))
                    .arg(
                        Arg::new("production")
                            .long("production")
                            .action(ArgAction::SetTrue)
                            .help("Reject generated fail-closed runtime paths before writing artifacts"),
                    )
                    .arg(
                        Arg::new("deny-fail-closed").long("deny-fail-closed").action(ArgAction::SetTrue).help(
                            "Reject metadata that contains fail-closed runtime features or obligations before writing artifacts",
                        ),
                    )
                    .arg(
                        Arg::new("deny-symbolic-runtime")
                            .long("deny-symbolic-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject symbolic Cell/runtime requirements before writing artifacts"),
                    )
                    .arg(
                        Arg::new("deny-ckb-runtime")
                            .long("deny-ckb-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject CKB transaction/syscall runtime requirements before writing artifacts"),
                    )
                    .arg(
                        Arg::new("deny-runtime-obligations")
                            .long("deny-runtime-obligations")
                            .action(ArgAction::SetTrue)
                            .help("Reject runtime-required verifier obligations before writing artifacts"),
                    ),
            )
            .subcommand(
                ClapCommand::new("test")
                    .about("Run the tests")
                    .arg(Arg::new("filter").value_name("FILTER").help("Filter tests by name"))
                    .arg(
                        Arg::new("no-run")
                            .long("no-run")
                            .action(ArgAction::SetTrue)
                            .help("Compile tests without attempting execution"),
                    )
                    .arg(Arg::new("nocapture").long("nocapture").action(ArgAction::SetTrue).help("Don't capture stdout"))
                    .arg(Arg::new("fail-fast").long("fail-fast").action(ArgAction::SetTrue).help("Stop on first failure"))
                    .arg(Arg::new("doc").long("doc").action(ArgAction::SetTrue).help("Generate docs before compiling tests"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON test summary")),
            )
            .subcommand(
                ClapCommand::new("doc")
                    .about("Generate documentation")
                    .arg(Arg::new("open").long("open").short('o').action(ArgAction::SetTrue).help("Open docs in browser"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON doc summary"))
                    .arg(
                        Arg::new("format")
                            .long("format")
                            .value_name("FORMAT")
                            .default_value("html")
                            .help("Output format: html, markdown, json"),
                    ),
            )
            .subcommand(
                ClapCommand::new("fmt")
                    .about("Format source code")
                    .arg(Arg::new("check").long("check").action(ArgAction::SetTrue).help("Check formatting without modifying files"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON format summary"))
                    .arg(Arg::new("files").value_name("FILES").num_args(1..).help("Files to format")),
            )
            .subcommand(
                ClapCommand::new("init")
                    .about("Create a new package")
                    .arg(Arg::new("name").value_name("NAME").help("Package name"))
                    .arg(Arg::new("path").value_name("PATH").help("Path to create package"))
                    .arg(Arg::new("lib").long("lib").action(ArgAction::SetTrue).help("Create a library package"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON init summary")),
            )
            .subcommand(
                ClapCommand::new("add")
                    .about("Add dependencies")
                    .arg(Arg::new("crates").value_name("CRATES").required(true).num_args(1..).help("Crates to add"))
                    .arg(Arg::new("dev").long("dev").action(ArgAction::SetTrue).help("Add as dev dependency"))
                    .arg(Arg::new("build").long("build").action(ArgAction::SetTrue).help("Add as build dependency"))
                    .arg(Arg::new("git").long("git").value_name("URL").help("Add a git dependency source"))
                    .arg(Arg::new("path").long("path").value_name("PATH").help("Add a local path dependency source"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON add summary")),
            )
            .subcommand(
                ClapCommand::new("clean")
                    .about("Remove build artifacts")
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON clean summary")),
            )
            .subcommand(
                ClapCommand::new("remove")
                    .about("Remove dependencies")
                    .arg(Arg::new("crates").value_name("CRATES").required(true).num_args(1..).help("Crates to remove"))
                    .arg(Arg::new("dev").long("dev").action(ArgAction::SetTrue).help("Remove from dev dependency section"))
                    .arg(Arg::new("build").long("build").action(ArgAction::SetTrue).help("Remove from build dependency section"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON remove summary")),
            )
            .subcommand(ClapCommand::new("repl").about("Start interactive REPL"))
            .subcommand(
                ClapCommand::new("check")
                    .about("Type-check and lower the current package without writing artifacts")
                    .arg(
                        Arg::new("all-targets")
                            .long("all-targets")
                            .action(ArgAction::SetTrue)
                            .help("Also check the current ELF-compatible target path"),
                    )
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    )
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON check summary"))
                    .arg(
                        Arg::new("production")
                            .long("production")
                            .action(ArgAction::SetTrue)
                            .help("Reject generated fail-closed runtime paths"),
                    )
                    .arg(
                        Arg::new("deny-fail-closed")
                            .long("deny-fail-closed")
                            .action(ArgAction::SetTrue)
                            .help("Reject metadata that contains fail-closed runtime features or obligations"),
                    )
                    .arg(
                        Arg::new("deny-symbolic-runtime")
                            .long("deny-symbolic-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject symbolic Cell/runtime requirements that are not standalone pure-ELF compatible"),
                    )
                    .arg(
                        Arg::new("deny-ckb-runtime")
                            .long("deny-ckb-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject CKB transaction/syscall runtime requirements"),
                    )
                    .arg(
                        Arg::new("deny-runtime-obligations")
                            .long("deny-runtime-obligations")
                            .action(ArgAction::SetTrue)
                            .help("Reject runtime-required verifier obligations"),
                    ),
            )
            .subcommand(
                ClapCommand::new("metadata")
                    .about("Emit compile metadata for lowering, scheduler, and CKB runtime auditing")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON metadata to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    ),
            )
            .subcommand(
                ClapCommand::new("constraints")
                    .about("Emit profile-aware production constraints for compiler, builder, CI, and acceptance gates")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON constraints to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    )
                    .arg(
                        Arg::new("entry-action")
                            .long("entry-action")
                            .value_name("ACTION")
                            .help("Report constraints for this action entry"),
                    )
                    .arg(Arg::new("entry-lock").long("entry-lock").value_name("LOCK").help("Report constraints for this lock entry")),
            )
            .subcommand(
                ClapCommand::new("abi")
                    .about("Explain the generated _cellscript_entry witness ABI for an action or lock")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON ABI report to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    )
                    .arg(Arg::new("action").long("action").value_name("NAME").help("Explain ABI for this action"))
                    .arg(Arg::new("lock").long("lock").value_name("NAME").help("Explain ABI for this lock")),
            )
            .subcommand(
                ClapCommand::new("scheduler-plan")
                    .about("Consume scheduler hints and emit a Spora admission/conflict policy report")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write JSON scheduler plan to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    ),
            )
            .subcommand(
                ClapCommand::new("ckb-hash")
                    .about("Compute CKB default Blake2b-256 hashes for builders, manifests, and release evidence")
                    .arg(Arg::new("input").value_name("TEXT").help("UTF-8 text to hash; omitted input hashes empty bytes"))
                    .arg(Arg::new("hex").long("hex").value_name("HEX").help("Hex bytes to hash"))
                    .arg(Arg::new("file").long("file").value_name("FILE").help("File bytes to hash"))
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON summary")),
            )
            .subcommand(
                ClapCommand::new("opt-report")
                    .about("Compile O0..O3 and emit artifact-size/constraints comparison evidence")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .help("Write JSON optimization report to a file"),
                    )
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    ),
            )
            .subcommand(
                ClapCommand::new("entry-witness")
                    .about("Encode witness bytes for the generated _cellscript_entry wrapper")
                    .arg(Arg::new("input").value_name("INPUT").help("Input .cell file, package directory, or Cell.toml"))
                    .arg(Arg::new("action").long("action").value_name("NAME").help("Encode witness bytes for this action"))
                    .arg(Arg::new("lock").long("lock").value_name("NAME").help("Encode witness bytes for this lock"))
                    .arg(
                        Arg::new("arg")
                            .long("arg")
                            .value_name("VALUE")
                            .num_args(1)
                            .action(ArgAction::Append)
                            .help("Witness payload argument; schema-backed params are omitted, byte params use hex"),
                    )
                    .arg(Arg::new("output").long("output").short('o').value_name("FILE").help("Write raw witness bytes to a file"))
                    .arg(Arg::new("target").long("target").short('t').value_name("TARGET").help("Target architecture"))
                    .arg(
                        Arg::new("target-profile")
                            .long("target-profile")
                            .value_name("PROFILE")
                            .help("Target profile: spora, ckb, or portable-cell"),
                    )
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit a machine-readable JSON summary")),
            )
            .subcommand(
                ClapCommand::new("verify-artifact")
                    .about("Verify an emitted CellScript artifact against its metadata sidecar")
                    .arg(Arg::new("artifact").value_name("ARTIFACT").required(true).help("Artifact file to verify"))
                    .arg(
                        Arg::new("metadata")
                            .long("metadata")
                            .short('m')
                            .value_name("FILE")
                            .help("Metadata JSON file; defaults to ARTIFACT.meta.json"),
                    )
                    .arg(
                        Arg::new("verify-sources")
                            .long("verify-sources")
                            .action(ArgAction::SetTrue)
                            .help("Also verify metadata source_units against files on disk"),
                    )
                    .arg(
                        Arg::new("json")
                            .long("json")
                            .action(ArgAction::SetTrue)
                            .help("Emit a machine-readable JSON verification summary"),
                    )
                    .arg(
                        Arg::new("expect-target-profile")
                            .long("expect-target-profile")
                            .value_name("PROFILE")
                            .help("Require metadata target_profile to match this value: spora or ckb"),
                    )
                    .arg(
                        Arg::new("expect-artifact-hash")
                            .long("expect-artifact-hash")
                            .value_name("BLAKE3")
                            .help("Require metadata artifact_hash_blake3 to match this value"),
                    )
                    .arg(
                        Arg::new("expect-source-hash")
                            .long("expect-source-hash")
                            .value_name("BLAKE3")
                            .help("Require metadata source_hash_blake3 to match this path-bound value"),
                    )
                    .arg(
                        Arg::new("expect-source-content-hash")
                            .long("expect-source-content-hash")
                            .value_name("BLAKE3")
                            .help("Require metadata source_content_hash_blake3 to match this path-independent value"),
                    )
                    .arg(
                        Arg::new("production")
                            .long("production")
                            .action(ArgAction::SetTrue)
                            .help("Reject fail-closed runtime paths in emitted metadata"),
                    )
                    .arg(
                        Arg::new("deny-fail-closed")
                            .long("deny-fail-closed")
                            .action(ArgAction::SetTrue)
                            .help("Reject metadata that contains fail-closed runtime features or obligations"),
                    )
                    .arg(
                        Arg::new("deny-symbolic-runtime")
                            .long("deny-symbolic-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject symbolic Cell/runtime requirements"),
                    )
                    .arg(
                        Arg::new("deny-ckb-runtime")
                            .long("deny-ckb-runtime")
                            .action(ArgAction::SetTrue)
                            .help("Reject CKB transaction/syscall runtime requirements"),
                    )
                    .arg(
                        Arg::new("deny-runtime-obligations")
                            .long("deny-runtime-obligations")
                            .action(ArgAction::SetTrue)
                            .help("Reject runtime-required verifier obligations"),
                    ),
            )
            .subcommand(
                ClapCommand::new("run")
                    .about("Experimental: build and run a package")
                    .arg(Arg::new("release").long("release").short('r').action(ArgAction::SetTrue).help("Run in release mode"))
                    .arg(
                        Arg::new("simulate")
                            .long("simulate")
                            .short('s')
                            .action(ArgAction::SetTrue)
                            .help("Simulate execution using AST interpreter instead of ckb-vm"),
                    )
                    .arg(Arg::new("args").value_name("ARGS").num_args(0..).trailing_var_arg(true)),
            )
            .subcommand(
                ClapCommand::new("publish")
                    .about("Experimental: publish a package")
                    .arg(Arg::new("dry-run").long("dry-run").action(ArgAction::SetTrue))
                    .arg(Arg::new("allow-dirty").long("allow-dirty").action(ArgAction::SetTrue)),
            )
            .subcommand(
                ClapCommand::new("install")
                    .about("Experimental: install a package")
                    .arg(Arg::new("crate").value_name("CRATE"))
                    .arg(Arg::new("version").long("version").value_name("VERSION"))
                    .arg(Arg::new("git").long("git").value_name("URL"))
                    .arg(Arg::new("path").long("path").value_name("PATH")),
            )
            .subcommand(ClapCommand::new("update").about("Experimental: update dependencies"))
            .subcommand(
                ClapCommand::new("info")
                    .about("Show package information")
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("Emit machine-readable package information")),
            )
            .subcommand(
                ClapCommand::new("login")
                    .about("Experimental: authenticate against a registry")
                    .arg(Arg::new("registry").long("registry").value_name("URL")),
            )
            .get_matches();

        match matches.subcommand() {
            Some(("build", m)) => Command::Build(BuildArgs {
                release: m.get_flag("release"),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                entry_action: m.get_one::<String>("entry-action").cloned(),
                entry_lock: m.get_one::<String>("entry-lock").cloned(),
                jobs: m.get_one::<String>("jobs").and_then(|s| s.parse().ok()),
                json: m.get_flag("json"),
                production: m.get_flag("production"),
                deny_fail_closed: m.get_flag("deny-fail-closed"),
                deny_symbolic_runtime: m.get_flag("deny-symbolic-runtime"),
                deny_ckb_runtime: m.get_flag("deny-ckb-runtime"),
                deny_runtime_obligations: m.get_flag("deny-runtime-obligations"),
                ..Default::default()
            }),
            Some(("test", m)) => Command::Test(TestArgs {
                filter: m.get_one::<String>("filter").cloned(),
                no_run: m.get_flag("no-run"),
                nocapture: m.get_flag("nocapture"),
                fail_fast: m.get_flag("fail-fast"),
                doc: m.get_flag("doc"),
                json: m.get_flag("json"),
                ..Default::default()
            }),
            Some(("doc", m)) => Command::Doc(DocArgs {
                open: m.get_flag("open"),
                json: m.get_flag("json"),
                output_format: match m.get_one::<String>("format").map(|s| s.as_str()) {
                    Some("markdown") => OutputFormat::Markdown,
                    Some("json") => OutputFormat::Json,
                    _ => OutputFormat::Html,
                },
                ..Default::default()
            }),
            Some(("fmt", m)) => Command::Fmt(FmtArgs {
                check: m.get_flag("check"),
                json: m.get_flag("json"),
                files: m.get_many::<String>("files").map(|v| v.map(PathBuf::from).collect()).unwrap_or_default(),
            }),
            Some(("init", m)) => Command::Init(InitArgs {
                name: m.get_one::<String>("name").cloned(),
                path: m.get_one::<String>("path").map(PathBuf::from),
                lib: m.get_flag("lib"),
                json: m.get_flag("json"),
            }),
            Some(("add", m)) => Command::Add(AddArgs {
                crates: m.get_many::<String>("crates").map(|v| v.cloned().collect()).unwrap_or_default(),
                dev: m.get_flag("dev"),
                build: m.get_flag("build"),
                git: m.get_one::<String>("git").cloned(),
                path: m.get_one::<String>("path").map(PathBuf::from),
                json: m.get_flag("json"),
            }),
            Some(("remove", m)) => Command::Remove(RemoveArgs {
                crates: m.get_many::<String>("crates").map(|v| v.cloned().collect()).unwrap_or_default(),
                dev: m.get_flag("dev"),
                build: m.get_flag("build"),
                json: m.get_flag("json"),
            }),
            Some(("clean", m)) => Command::Clean(CleanArgs { json: m.get_flag("json") }),
            Some(("repl", _)) => Command::Repl,
            Some(("check", m)) => Command::Check(CheckArgs {
                all_targets: m.get_flag("all-targets"),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: m.get_flag("json"),
                production: m.get_flag("production"),
                deny_fail_closed: m.get_flag("deny-fail-closed"),
                deny_symbolic_runtime: m.get_flag("deny-symbolic-runtime"),
                deny_ckb_runtime: m.get_flag("deny-ckb-runtime"),
                deny_runtime_obligations: m.get_flag("deny-runtime-obligations"),
                features: Vec::new(),
            }),
            Some(("metadata", m)) => Command::Metadata(MetadataArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("constraints", m)) => Command::Constraints(ConstraintsArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                entry_action: m.get_one::<String>("entry-action").cloned(),
                entry_lock: m.get_one::<String>("entry-lock").cloned(),
            }),
            Some(("abi", m)) => Command::Abi(AbiArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                action: m.get_one::<String>("action").cloned(),
                lock: m.get_one::<String>("lock").cloned(),
            }),
            Some(("scheduler-plan", m)) => Command::SchedulerPlan(SchedulerPlanArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("ckb-hash", m)) => Command::CkbHash(CkbHashArgs {
                input: m.get_one::<String>("input").cloned(),
                hex: m.get_one::<String>("hex").cloned(),
                file: m.get_one::<String>("file").map(PathBuf::from),
                json: m.get_flag("json"),
            }),
            Some(("opt-report", m)) => Command::OptReport(OptReportArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
            }),
            Some(("entry-witness", m)) => Command::EntryWitness(EntryWitnessArgs {
                input: m.get_one::<String>("input").map(PathBuf::from),
                action: m.get_one::<String>("action").cloned(),
                lock: m.get_one::<String>("lock").cloned(),
                args: m.get_many::<String>("arg").map(|values| values.cloned().collect()).unwrap_or_default(),
                output: m.get_one::<String>("output").map(PathBuf::from),
                target: m.get_one::<String>("target").cloned(),
                target_profile: m.get_one::<String>("target-profile").cloned(),
                json: m.get_flag("json"),
            }),
            Some(("verify-artifact", m)) => Command::VerifyArtifact(VerifyArtifactArgs {
                artifact: m.get_one::<String>("artifact").map(PathBuf::from).expect("required artifact"),
                metadata: m.get_one::<String>("metadata").map(PathBuf::from),
                verify_sources: m.get_flag("verify-sources"),
                json: m.get_flag("json"),
                expect_target_profile: m.get_one::<String>("expect-target-profile").cloned(),
                expect_artifact_hash: m.get_one::<String>("expect-artifact-hash").cloned(),
                expect_source_hash: m.get_one::<String>("expect-source-hash").cloned(),
                expect_source_content_hash: m.get_one::<String>("expect-source-content-hash").cloned(),
                production: m.get_flag("production"),
                deny_fail_closed: m.get_flag("deny-fail-closed"),
                deny_symbolic_runtime: m.get_flag("deny-symbolic-runtime"),
                deny_ckb_runtime: m.get_flag("deny-ckb-runtime"),
                deny_runtime_obligations: m.get_flag("deny-runtime-obligations"),
            }),
            Some(("run", m)) => Command::Run(RunArgs {
                args: m.get_many::<String>("args").map(|values| values.cloned().collect()).unwrap_or_default(),
                release: m.get_flag("release"),
                simulate: m.get_flag("simulate"),
            }),
            Some(("publish", m)) => {
                Command::Publish(PublishArgs { dry_run: m.get_flag("dry-run"), allow_dirty: m.get_flag("allow-dirty") })
            }
            Some(("install", m)) => Command::Install(InstallArgs {
                crate_name: m.get_one::<String>("crate").cloned(),
                version: m.get_one::<String>("version").cloned(),
                git: m.get_one::<String>("git").cloned(),
                path: m.get_one::<String>("path").map(PathBuf::from),
            }),
            Some(("update", _)) => Command::Update,
            Some(("info", m)) => Command::Info(InfoArgs { json: m.get_flag("json") }),
            Some(("login", m)) => Command::Login(LoginArgs { registry: m.get_one::<String>("registry").cloned() }),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_execution() {
        let _cmd = Command::Clean(CleanArgs::default());
    }
}
