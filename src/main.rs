use camino::Utf8Path;
use cellscript::error::CompileError;
use clap::Parser;
use colored::Colorize;
use std::process;

use cellscript::{
    compile_path, compile_path_with_entry_action, compile_path_with_entry_lock, default_metadata_path_for_artifact,
    default_output_path_for_input, resolve_input_path, CompileOptions,
};

#[derive(Parser, Debug)]
#[command(name = "cellc")]
#[command(about = "CellScript compiler for Spora blockchain")]
#[command(version = cellscript::VERSION)]
struct Cli {
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    #[arg(short = 'O', long, default_value = "0")]
    opt: u8,

    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    #[arg(short, long)]
    debug: bool,

    #[arg(short, long)]
    target: Option<String>,

    #[arg(long)]
    target_profile: Option<String>,

    #[arg(long, value_name = "ACTION")]
    entry_action: Option<String>,

    #[arg(long, value_name = "LOCK")]
    entry_lock: Option<String>,

    #[arg(long)]
    lex: bool,

    #[arg(long)]
    parse: bool,

    #[arg(short, long)]
    interactive: bool,

    #[arg(long)]
    gen_stdlib: bool,

    /// Start the language server (JSON-RPC over stdio).
    #[arg(long)]
    lsp: bool,
}

fn main() {
    // Start the LSP server before any CLI parsing side effects.
    if std::env::args().any(|arg| arg == "--lsp") {
        cellscript::lsp::server::run_lsp_server_blocking();
        return;
    }

    if std::env::args()
        .nth(1)
        .map(|arg| {
            matches!(
                arg.as_str(),
                "build"
                    | "test"
                    | "doc"
                    | "fmt"
                    | "init"
                    | "new"
                    | "add"
                    | "remove"
                    | "clean"
                    | "repl"
                    | "check"
                    | "metadata"
                    | "constraints"
                    | "abi"
                    | "scheduler-plan"
                    | "ckb-hash"
                    | "explain"
                    | "explain-generics"
                    | "opt-report"
                    | "action"
                    | "entry-witness"
                    | "verify-artifact"
                    | "run"
                    | "publish"
                    | "install"
                    | "update"
                    | "info"
                    | "login"
            )
        })
        .unwrap_or(false)
    {
        if let Err(e) = cellscript::cli::run() {
            print_cli_error(&e);
            process::exit(1);
        }
        return;
    }

    let cli = Cli::parse();

    env_logger::init();

    if cli.interactive {
        if let Err(e) = cellscript::repl::run_repl() {
            eprintln!("{}: {}", "REPL error".red(), e);
            process::exit(1);
        }
        return;
    }

    if cli.gen_stdlib {
        let target_profile = cli
            .target_profile
            .as_deref()
            .map(cellscript::TargetProfile::from_name)
            .transpose()
            .unwrap_or_else(|e| {
                print_cli_error(&e);
                process::exit(1);
            })
            .unwrap_or(cellscript::TargetProfile::Spora);
        let asm = cellscript::stdlib::StdLib::generate_assembly_for_target_profile(target_profile);
        println!("{}", asm);
        return;
    }

    if cli.opt > 3 {
        eprintln!("{}: optimization level must be between 0 and 3", "error".red());
        process::exit(1);
    }

    let input_file = cli.input.unwrap_or_else(|| ".".to_string());
    let resolved_input = match resolve_input_path(Utf8Path::new(&input_file)) {
        Ok(path) => path,
        Err(e) => {
            print_cli_error(&e);
            process::exit(1);
        }
    };

    let source = match std::fs::read_to_string(&resolved_input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: failed to read '{}': {}", "error".red(), resolved_input, e);
            process::exit(1);
        }
    };

    if cli.lex {
        match cellscript::lexer::lex(&source) {
            Ok(tokens) => {
                println!("{}: found {} tokens", "success".green(), tokens.len());
                for token in tokens {
                    println!("  {:?}", token);
                }
            }
            Err(e) => {
                print_cli_error(&e);
                process::exit(1);
            }
        }
        return;
    }

    if cli.parse {
        let tokens = match cellscript::lexer::lex(&source) {
            Ok(t) => t,
            Err(e) => {
                print_cli_error(&e);
                process::exit(1);
            }
        };

        match cellscript::parser::parse(&tokens) {
            Ok(ast) => {
                println!("{}: parsed successfully", "success".green());
                println!("{:#?}", ast);
            }
            Err(e) => {
                print_cli_error(&e);
                process::exit(1);
            }
        }
        return;
    }

    let output = cli.output.clone();
    let options = CompileOptions {
        opt_level: cli.opt,
        output: output.clone(),
        debug: cli.debug,
        target: cli.target,
        target_profile: cli.target_profile,
    };

    if cli.entry_action.is_some() && cli.entry_lock.is_some() {
        eprintln!("{}: --entry-action and --entry-lock are mutually exclusive", "error".red());
        process::exit(1);
    }

    let compile_result = match (cli.entry_action, cli.entry_lock) {
        (Some(action), None) => compile_path_with_entry_action(Utf8Path::new(&input_file), options, action),
        (None, Some(lock)) => compile_path_with_entry_lock(Utf8Path::new(&input_file), options, lock),
        (None, None) => compile_path(Utf8Path::new(&input_file), options),
        (Some(_), Some(_)) => unreachable!("validated above"),
    };

    match compile_result {
        Ok(result) => {
            let output_path = output
                .as_deref()
                .map(Utf8Path::new)
                .map(|path| path.to_owned())
                .map(Ok)
                .unwrap_or_else(|| default_output_path_for_input(Utf8Path::new(&input_file), &resolved_input, result.artifact_format))
                .unwrap_or_else(|e| {
                    print_cli_error(&e);
                    process::exit(1);
                });

            if let Err(e) = result.write_to_path(&output_path) {
                print_cli_error(&e);
                process::exit(1);
            }
            let metadata_path = default_metadata_path_for_artifact(&output_path);
            if let Err(e) = result.write_metadata_to_path(&metadata_path) {
                print_cli_error(&e);
                process::exit(1);
            }

            println!("{}: compiled successfully", "success".green());
            println!("  Artifact format: {}", result.artifact_format.display_name());
            println!("  Target profile: {}", result.metadata.target_profile.name);
            println!("  Artifact hash: {:x?}", result.artifact_hash);
            println!("  Output: {}", output_path);
            println!("  Metadata: {}", metadata_path);
        }
        Err(e) => {
            print_cli_error(&e);
            process::exit(1);
        }
    }
}

fn print_cli_error(error: &CompileError) {
    if let Some(info) = cellscript::runtime_errors::runtime_error_info_for_diagnostic_message(&error.message) {
        eprintln!("{}: {}", format!("error[E{:04}]", info.code).red(), error);
        eprintln!("  {}: run `cellc explain E{:04}` for {}", "help".cyan(), info.code, info.name);
    } else {
        eprintln!("{}: {}", "error".red(), error);
    }
}
