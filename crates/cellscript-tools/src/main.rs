//! Native Rust release, audit, fixture, and acceptance tooling for CellScript.

#![recursion_limit = "256"]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod acceptance_helpers;
mod bip340_tcb;
mod btc_anchor;
mod btc_spv_adapter;
mod ckb_acceptance;
mod ckb_acceptance_live;
mod ckb_adapter_live;
mod ckb_devnet;
mod crypto;
mod evidence_retention;
mod executable_surface;
mod external_attestation;
mod external_handoff;
mod fiber_experiments;
mod novaseal_agreement_live;
mod novaseal_core_live;
mod novaseal_planned_btc_tx;
mod novaseal_planned_btc_utxo;
mod novaseal_planned_dual;
mod novaseal_planned_fiber;
mod novaseal_planned_fungible;
mod novaseal_planned_live;
mod novaseal_planned_rwa;
mod production_evidence;
mod profile_operator;
mod repository_checks;
mod service_builder;
mod shared;
mod skill_pack;
mod strict_backend;
mod syntax_combo;
mod tooling_release;
mod verifier_pinning;
mod wallet_vectors;

#[derive(Debug, Parser)]
#[command(name = "cellscript-tools", version, about = "CellScript repository tooling")]
struct Cli {
    /// Override repository-root autodetection.
    #[arg(long, global = true, value_name = "PATH")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the pinned Rust toolchain channel.
    RustToolchainChannel,
    /// Print the tab-separated fields consumed by the NovaSeal acceptance wrapper.
    NovasealAcceptanceSummary { report: PathBuf },
    /// Verify that Fiber compatibility and acceptance reports share one binding.
    FiberReportBinding { compatibility_report: PathBuf, acceptance_report: PathBuf, fiber_revision: String },
    /// Validate CKB compatibility and action-builder CLI contracts.
    EcosystemReuseContracts { compatibility_report: PathBuf, action_report: PathBuf },
    /// Validate the CellScript 0.14 metadata scope.
    Scope014 {
        out_dir: PathBuf,
        #[arg(required = true)]
        metadata: Vec<PathBuf>,
    },
    /// Validate the CellScript-to-CellFabric bridge summary.
    CellfabricBridge { envelope: PathBuf, summary: PathBuf },
    /// Run the focused CKB adapter local-node acceptance scenario.
    CkbAdapterLive {
        #[arg(long)]
        ckb_repo: PathBuf,
        #[arg(long)]
        ckb_bin: Option<PathBuf>,
        #[arg(long)]
        run_dir: PathBuf,
        #[arg(long)]
        action_plan: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    /// Compile and, when requested, execute the production CKB acceptance matrix.
    CkbAcceptance {
        #[arg(long)]
        ckb_repo: Option<PathBuf>,
        #[arg(long)]
        ckb_bin: Option<PathBuf>,
        #[arg(long)]
        compile_only: bool,
        #[arg(long)]
        stateful_scenarios: bool,
        #[arg(long, default_value = "production", value_parser = ["production", "bounded"])]
        mode: String,
        #[arg(long)]
        run_dir: Option<PathBuf>,
        #[arg(long)]
        keep_node: bool,
    },
    /// Validate the tooling release boundary.
    ValidateToolingRelease,
    /// Validate the CellScript skill pack.
    CheckSkillPack,
    /// Run the strict backend audit.
    StrictBackend {
        #[arg(default_value = "quick")]
        mode: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        extra: Vec<String>,
    },
    /// Generate NovaSeal service-builder fixtures.
    ServiceBuilderFixtures {
        #[arg(long)]
        operator_fixtures: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Generate NovaSeal profile-operator fixtures.
    ProfileOperatorFixtures {
        /// Read live and external evidence below this root instead of the repository root.
        #[arg(long)]
        evidence_root: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Generate NovaSeal wallet-signing vectors.
    WalletSigningVectors {
        #[arg(long)]
        core_vectors: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Run the syntax-combination audit.
    SyntaxComboAudit {
        #[arg(default_value = "quick", value_parser = ["quick", "ci", "deep", "repro"])]
        mode: String,
        #[arg(long, default_value_t = 20_260_503)]
        seed: u64,
        #[arg(long)]
        budget: Option<usize>,
        #[arg(long = "case")]
        case_name: Option<String>,
    },
    /// Validate freshness markers in CellScript documentation headers.
    CheckDocStatus,
    /// Validate or regenerate the compiler-owned executable-surface matrix.
    CheckExecutableSurface {
        #[arg(long)]
        write: bool,
    },
    /// Validate repository-local Markdown link targets.
    CheckMarkdownLinks,
    /// Reject retired runtime sources, artifacts, and active-tooling residue.
    CheckSourcePolicy,
    /// Validate the file list emitted by `cargo package --list`.
    CheckPackageContents { package_files: PathBuf },
    /// Print the root package version from Cargo.toml.
    WorkspaceVersion,
    /// Build the NovaSeal external-attestation adapter report.
    ExternalAttestationAdapter {
        #[arg(long)]
        tcb_review: Option<PathBuf>,
        #[arg(long)]
        public_template: Option<PathBuf>,
        #[arg(long)]
        external_template: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Build the NovaSeal BTC SPV evidence adapter report.
    BtcSpvEvidenceAdapter {
        #[arg(long)]
        service_builder_fixtures: Option<PathBuf>,
        #[arg(long)]
        template: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Run the NovaSeal BIP340 TCB review.
    Bip340TcbReview {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Build the NovaSeal external-evidence handoff bundle.
    ExternalEvidenceHandoff {
        #[arg(long)]
        btc_spv_adapter: Option<PathBuf>,
        #[arg(long)]
        external_attestation_adapter: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Validate release-critical CKB production acceptance evidence.
    ValidateProductionEvidence {
        report: PathBuf,
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        compile_only: bool,
    },
    /// Recompute and verify the pinned NovaSeal RISC-V verifier identity.
    CheckNovasealVerifierPinning,
    /// Discover or execute the required external Fiber node workflow suites.
    FiberNodeExperiments {
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        fiber_repo: Option<PathBuf>,
        /// Temporarily install this exact CellScript fungible ELF as Fiber's dev SimpleUDT contract.
        #[arg(long)]
        cellscript_fungible_artifact: Option<PathBuf>,
        /// Exact Bruno CLI package version (defaults to the version pinned by Fiber CI).
        #[arg(long, default_value = "@usebruno/cli@1.20.0")]
        bruno_cli: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
        #[arg(long = "run-suite")]
        run_suite: Vec<String>,
        #[arg(long)]
        run_all: bool,
        #[arg(long)]
        assume_nodes_running: bool,
        #[arg(long, default_value_t = 1800)]
        timeout_seconds: u64,
    },
    /// Run the live NovaSeal core bootstrap/transition CKB devnet scenario.
    NovasealCoreDevnet {
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        ckb_repo: Option<PathBuf>,
        #[arg(long)]
        ckb_bin: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        run_dir: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
        #[arg(long)]
        keep_node: bool,
    },
    /// Run the live NovaSeal Agreement originate/repay/claim CKB devnet scenario.
    NovasealAgreementDevnet {
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        ckb_repo: Option<PathBuf>,
        #[arg(long)]
        ckb_bin: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        run_dir: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
        #[arg(long)]
        keep_node: bool,
    },
    /// Run or describe a planned NovaSeal profile devnet evidence contract.
    NovasealPlannedDevnet {
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        ckb_repo: Option<PathBuf>,
        #[arg(long)]
        ckb_bin: Option<PathBuf>,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        run_dir: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
        #[arg(long)]
        keep_node: bool,
        #[arg(long)]
        list_contract: bool,
        #[arg(long)]
        prepare_artifacts: bool,
        #[arg(long)]
        live: bool,
    },
}

fn failure(error: anyhow::Error) -> ExitCode {
    eprintln!("{error:#}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = match shared::resolve_repo_root(cli.root.as_deref()) {
        Ok(root) => root,
        Err(error) => return failure(error),
    };

    match cli.command {
        Command::RustToolchainChannel => match acceptance_helpers::rust_toolchain_channel(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::NovasealAcceptanceSummary { report } => match acceptance_helpers::novaseal_summary(&report) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::FiberReportBinding { compatibility_report, acceptance_report, fiber_revision } => {
            match acceptance_helpers::fiber_report_binding(&compatibility_report, &acceptance_report, &fiber_revision) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => failure(error),
            }
        }
        Command::EcosystemReuseContracts { compatibility_report, action_report } => {
            match acceptance_helpers::ecosystem_reuse_contracts(&compatibility_report, &action_report) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => failure(error),
            }
        }
        Command::Scope014 { out_dir, metadata } => match acceptance_helpers::scope_014(&out_dir, &metadata) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CellfabricBridge { envelope, summary } => match acceptance_helpers::cellfabric_bridge(&envelope, &summary) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CkbAdapterLive { ckb_repo, ckb_bin, run_dir, action_plan, report } => {
            match ckb_adapter_live::run(&ckb_repo, ckb_bin.as_deref(), &run_dir, &action_plan, &report) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::CkbAcceptance { ckb_repo, ckb_bin, compile_only, stateful_scenarios, mode, run_dir, keep_node } => {
            match ckb_acceptance::run(
                &root,
                ckb_repo.as_deref(),
                ckb_bin.as_deref(),
                compile_only,
                stateful_scenarios,
                &mode,
                run_dir.as_deref(),
                keep_node,
            ) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::ValidateToolingRelease => match tooling_release::run(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CheckSkillPack => match skill_pack::run(&root) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => failure(error),
        },
        Command::StrictBackend { mode, extra: _ } => match strict_backend::run(&root, &mode) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(2) => ExitCode::from(2),
            Ok(_) => ExitCode::FAILURE,
            Err(error) => failure(error),
        },
        Command::ServiceBuilderFixtures { operator_fixtures, output, pretty } => {
            match service_builder::run(&root, operator_fixtures.as_deref(), output.as_deref(), pretty) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::ProfileOperatorFixtures { evidence_root, output, pretty } => {
            match profile_operator::run(&root, evidence_root.as_deref(), output.as_deref(), pretty) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::WalletSigningVectors { core_vectors, output, pretty } => {
            match wallet_vectors::run(&root, core_vectors.as_deref(), output.as_deref(), pretty) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::SyntaxComboAudit { mode, seed, budget, case_name } => {
            match syntax_combo::run(&root, &mode, seed, budget, case_name.as_deref()) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(2) => ExitCode::from(2),
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::CheckDocStatus => match repository_checks::check_doc_status(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CheckExecutableSurface { write } => match executable_surface::run(&root, write) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CheckMarkdownLinks => match repository_checks::check_markdown_links(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CheckSourcePolicy => match repository_checks::check_source_policy(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::CheckPackageContents { package_files } => match repository_checks::check_package_contents(&package_files) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(error),
        },
        Command::WorkspaceVersion => match repository_checks::workspace_version(&root) {
            Ok(version) => {
                println!("{version}");
                ExitCode::SUCCESS
            }
            Err(error) => failure(error),
        },
        Command::ExternalAttestationAdapter { tcb_review, public_template, external_template, output, pretty } => {
            match external_attestation::run(
                &root,
                tcb_review.as_deref(),
                public_template.as_deref(),
                external_template.as_deref(),
                output.as_deref(),
                pretty,
            ) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::BtcSpvEvidenceAdapter { service_builder_fixtures, template, output, pretty } => {
            match btc_spv_adapter::run(&root, service_builder_fixtures.as_deref(), template.as_deref(), output.as_deref(), pretty) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::Bip340TcbReview { output, pretty } => match bip340_tcb::run(&root, output.as_deref(), pretty) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => failure(error),
        },
        Command::ExternalEvidenceHandoff { btc_spv_adapter, external_attestation_adapter, output, pretty } => {
            match external_handoff::run(
                &root,
                btc_spv_adapter.as_deref(),
                external_attestation_adapter.as_deref(),
                output.as_deref(),
                pretty,
            ) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::ValidateProductionEvidence { report, repo_root, compile_only } => {
            match production_evidence::run(&root, &report, repo_root.as_deref(), compile_only) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::CheckNovasealVerifierPinning => match verifier_pinning::run(&root) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => failure(error),
        },
        Command::FiberNodeExperiments {
            repo_root,
            fiber_repo,
            cellscript_fungible_artifact,
            bruno_cli,
            output,
            pretty,
            run_suite,
            run_all,
            assume_nodes_running,
            timeout_seconds,
        } => match fiber_experiments::run(
            repo_root.as_deref().unwrap_or(&root),
            fiber_repo.as_deref(),
            cellscript_fungible_artifact.as_deref(),
            &bruno_cli,
            output.as_deref(),
            pretty,
            &run_suite,
            run_all,
            assume_nodes_running,
            timeout_seconds,
        ) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => failure(error),
        },
        Command::NovasealCoreDevnet { repo_root, ckb_repo, ckb_bin, output, run_dir, pretty, keep_node } => {
            match novaseal_core_live::run(
                repo_root.as_deref().unwrap_or(&root),
                ckb_repo.as_deref(),
                ckb_bin.as_deref(),
                output.as_deref(),
                run_dir.as_deref(),
                pretty,
                keep_node,
            ) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::NovasealAgreementDevnet { repo_root, ckb_repo, ckb_bin, output, run_dir, pretty, keep_node } => {
            match novaseal_agreement_live::run(
                repo_root.as_deref().unwrap_or(&root),
                ckb_repo.as_deref(),
                ckb_bin.as_deref(),
                output.as_deref(),
                run_dir.as_deref(),
                pretty,
                keep_node,
            ) {
                Ok(0) => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(error) => failure(error),
            }
        }
        Command::NovasealPlannedDevnet {
            repo_root,
            ckb_repo,
            ckb_bin,
            profile,
            output,
            run_dir,
            pretty,
            keep_node,
            list_contract,
            prepare_artifacts,
            live,
        } => match novaseal_planned_live::run(
            repo_root.as_deref().unwrap_or(&root),
            &profile,
            output.as_deref(),
            ckb_repo.as_deref(),
            ckb_bin.as_deref(),
            run_dir.as_deref(),
            pretty,
            keep_node,
            list_contract,
            prepare_artifacts,
            live,
        ) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => failure(error),
        },
    }
}
