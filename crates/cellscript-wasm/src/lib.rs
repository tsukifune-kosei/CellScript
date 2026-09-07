//! Browser-facing WASM bindings for the CellScript compiler.
//!
//! This crate exposes the pure in-memory compile path
//! (`lex -> parse -> types -> flow -> ir -> metadata`) to JavaScript
//! via `wasm-bindgen`. It does NOT expose the ELF codegen path in v1. The
//! default bundle returns a bounded authoring summary rather than the native
//! public-interface, typed-semantics, ProofPlan, or verified-artifact records.
//! Those records and the optional semantic language service would inflate the
//! default bundle beyond the 600 KB budget.
//!
//! The primary `compile_metadata_json` function takes source text, a mandatory
//! edition, and an optional target profile, and returns a JSON string.
//! On success the string is the serialized browser metadata summary; on
//! failure it is `{"error": "..."}` so the playground can parse it
//! uniformly and render diagnostics.

use cellscript::error::{CompileError, Span};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

const MAX_SOURCE_SET_JSON_BYTES: usize = cellscript::MAX_SOURCE_BYTES * 2 + 64 * 1024;

#[derive(Serialize)]
struct CompileDiagnosticRange {
    start: CompileDiagnosticPosition,
    end: CompileDiagnosticPosition,
}

#[derive(Serialize)]
struct CompileDiagnosticPosition {
    line: usize,
    column: usize,
    offset: usize,
}

#[derive(Serialize)]
struct CompileDiagnostic {
    message: String,
    severity: &'static str,
    code: Option<String>,
    file: Option<String>,
    range: Option<CompileDiagnosticRange>,
}

#[derive(Deserialize)]
struct CompileSourceInput {
    path: String,
    source: String,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Serialize)]
struct CompileDiagnosticResult<T: Serialize> {
    metadata: Option<T>,
    diagnostic_count: usize,
    error_count: usize,
    warning_count: usize,
    diagnostics: Vec<CompileDiagnostic>,
}

impl<T: Serialize> CompileDiagnosticResult<T> {
    fn new(metadata: Option<T>, diagnostics: Vec<CompileDiagnostic>) -> Self {
        let warning_count = diagnostics.iter().filter(|diagnostic| diagnostic.severity == "warning").count();
        let error_count = diagnostics.len().saturating_sub(warning_count);
        Self { metadata, diagnostic_count: diagnostics.len(), error_count, warning_count, diagnostics }
    }
}

#[cfg(feature = "language-service")]
#[derive(Serialize)]
struct LanguageServiceResult {
    completions: Vec<cellscript::lsp::CompletionItem>,
    hover: Option<cellscript::lsp::Hover>,
    definition: Option<cellscript::lsp::Location>,
    diagnostics: Vec<cellscript::lsp::Diagnostic>,
}

/// Compile CellScript source to metadata JSON (path A, no ELF).
///
/// Returns a JSON string. On success this is the serialized
/// browser metadata summary (module, types, actions with effect_class /
/// consume_set / create_set / estimated_cycles, plus module-wide fail-closed
/// runtime features and their scoped reasons). On error it
/// is `{"error": "<message>"}`.
///
/// `edition` is mandatory and accepts stable `"2026"` or experimental
/// `"2027"`. Edition 2027 remains a bounded preview rather than a stable
/// browser-language contract.
/// The `target` argument is optional; pass `None` for the default target.
#[wasm_bindgen]
pub fn compile_metadata_json(source: &str, edition: &str, target: Option<String>) -> String {
    let edition = match edition.parse::<cellscript::CellScriptEdition>() {
        Ok(edition) => edition,
        Err(error) => return error_json(&error.to_string()),
    };
    match cellscript::compile_metadata(source, edition, target) {
        Ok(metadata) => serde_json::to_string(&browser_metadata_value(&metadata))
            .unwrap_or_else(|e| error_json(&format!("failed to serialize metadata: {e}"))),
        Err(e) => error_json(&e.to_string()),
    }
}

/// Compile CellScript source and return a stable result envelope for tools.
///
/// On success the response is:
/// `{ "metadata": <browser summary>, "diagnostic_count": 0, "error_count": 0, "warning_count": 0, "diagnostics": [] }`
///
/// On failure the response is:
/// `{ "metadata": null, "diagnostic_count": N, "error_count": E, "warning_count": W, "diagnostics": [{ message, severity, code, range }, ...] }`
///
/// `range` is omitted when the compiler error is not tied to a source
/// span. Offsets are UTF-8 byte offsets from the original source; line and
/// column are 1-based.
#[wasm_bindgen]
pub fn compile_metadata_json_diagnostics(source: &str, edition: &str, target: Option<String>) -> String {
    let edition = match edition.parse::<cellscript::CellScriptEdition>() {
        Ok(edition) => edition,
        Err(error) => return diagnostic_error_json(&error.to_string(), source),
    };
    let report = cellscript::compile_metadata_with_diagnostics(source, edition, target);
    let diagnostics = report.diagnostics.iter().map(|error| diagnostic_from_error(error, source)).collect();
    let result = CompileDiagnosticResult::new(report.metadata.as_ref().map(browser_metadata_value), diagnostics);
    serde_json::to_string(&result)
        .unwrap_or_else(|e| diagnostic_error_json(&format!("failed to serialize diagnostic report: {e}"), source))
}

/// Compile a virtual multi-file source set and return metadata diagnostics.
///
/// `sources_json` must be a JSON array of `{ path, source, role? }` objects.
/// `entry_path` selects the source that should produce metadata. This is an
/// additive API; the single-source functions remain stable.
#[wasm_bindgen]
pub fn compile_metadata_json_sources(sources_json: &str, entry_path: &str, edition: &str, target: Option<String>) -> String {
    if sources_json.len() > MAX_SOURCE_SET_JSON_BYTES {
        return diagnostic_error_json(&format!("source set JSON exceeds the {} byte WASM input limit", MAX_SOURCE_SET_JSON_BYTES), "");
    }
    let inputs: Vec<CompileSourceInput> = match serde_json::from_str(sources_json) {
        Ok(inputs) => inputs,
        Err(error) => return diagnostic_error_json(&format!("failed to parse source set JSON: {error}"), ""),
    };
    let sources = inputs
        .into_iter()
        .map(|input| cellscript::InMemorySource { path: input.path, source: input.source, role: input.role })
        .collect::<Vec<_>>();
    let source_by_path = sources.iter().map(|source| (source.path.clone(), source.source.clone())).collect::<HashMap<_, _>>();
    let fallback_source = sources.iter().find(|source| source.path == entry_path).map(|source| source.source.as_str()).unwrap_or("");
    let edition = match edition.parse::<cellscript::CellScriptEdition>() {
        Ok(edition) => edition,
        Err(error) => return diagnostic_error_json(&error.to_string(), fallback_source),
    };
    let report = cellscript::compile_sources_metadata_with_diagnostics(&sources, entry_path, edition, target);
    let diagnostics =
        report.diagnostics.iter().map(|error| diagnostic_from_error_for_sources(error, &source_by_path, fallback_source)).collect();
    let result = CompileDiagnosticResult::new(report.metadata.as_ref().map(browser_metadata_value), diagnostics);
    serde_json::to_string(&result)
        .unwrap_or_else(|e| diagnostic_error_json(&format!("failed to serialize multi-file diagnostic report: {e}"), fallback_source))
}

/// Query the in-process CellScript language service for browser tooling.
///
/// `line` and `character` are zero-based UTF-16 positions, matching LSP.
/// The result contains completion, hover, definition and current document
/// diagnostics in one JSON payload so the playground can avoid multiple
/// WASM calls per cursor move.
#[cfg(feature = "language-service")]
#[wasm_bindgen]
pub fn language_service_json(source: &str, line: u32, character: u32) -> String {
    language_service_json_for_edition(source, "2026", line, character)
}

/// Query the in-process language service under an explicit source edition.
///
/// This is the virtual-document counterpart of native LSP manifest edition
/// resolution. It keeps the original Edition 2026 entry point compatible.
#[cfg(feature = "language-service")]
#[wasm_bindgen]
pub fn language_service_json_for_edition(source: &str, edition: &str, line: u32, character: u32) -> String {
    if source.len() > cellscript::MAX_SOURCE_BYTES {
        return error_json(&format!("source exceeds the {} byte compiler limit", cellscript::MAX_SOURCE_BYTES));
    }
    let edition = match edition.parse::<cellscript::CellScriptEdition>() {
        Ok(edition) => edition,
        Err(error) => return error_json(&error.to_string()),
    };
    let uri = "file:///playground.cell";
    let position = cellscript::lsp::Position { line, character };
    let mut server = cellscript::lsp::LspServer::new();
    server.open_document_with_edition(uri.to_string(), source.to_string(), edition);
    let result = LanguageServiceResult {
        completions: server.completion(uri, position),
        hover: server.hover(uri, position),
        definition: server.goto_definition(uri, position),
        diagnostics: server.get_diagnostics(uri),
    };
    serde_json::to_string(&result).unwrap_or_else(|error| {
        serde_json::json!({ "error": format!("failed to serialize language service result: {error}") }).to_string()
    })
}

/// Return the compiler version string (e.g. "0.17.0").
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn browser_metadata_value(metadata: &cellscript::CompileMetadata) -> serde_json::Value {
    let types = metadata
        .types
        .iter()
        .map(|ty| {
            serde_json::json!({
                "name": ty.name,
                "kind": ty.kind,
                "capabilities": ty.capabilities,
                "encoded_size": ty.encoded_size,
                "hash_type_source": ty.hash_type_source,
            })
        })
        .collect::<Vec<_>>();
    let actions = metadata
        .actions
        .iter()
        .map(|action| {
            let params =
                action.params.iter().map(|param| serde_json::json!({ "name": param.name, "ty": param.ty })).collect::<Vec<_>>();
            let consume_set = action
                .consume_set
                .iter()
                .map(|item| serde_json::json!({ "binding": item.binding, "type_hash": item.type_hash }))
                .collect::<Vec<_>>();
            let read_refs = action
                .read_refs
                .iter()
                .map(|item| serde_json::json!({ "binding": item.binding, "type_hash": item.type_hash }))
                .collect::<Vec<_>>();
            let create_set =
                action.create_set.iter().map(|item| serde_json::json!({ "binding": item.binding, "ty": item.ty })).collect::<Vec<_>>();
            let mutate_set =
                action.mutate_set.iter().map(|item| serde_json::json!({ "binding": item.binding, "ty": item.ty })).collect::<Vec<_>>();
            serde_json::json!({
                "name": action.name,
                "params": params,
                "effect_class": action.effect_class,
                "estimated_cycles": action.estimated_cycles,
                "consume_set": consume_set,
                "read_refs": read_refs,
                "create_set": create_set,
                "mutate_set": mutate_set,
                "ckb_runtime_features": action.ckb_runtime_features,
                "fail_closed_runtime_features": action.fail_closed_runtime_features,
            })
        })
        .collect::<Vec<_>>();
    let fail_closed_obligations = metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.status == "fail-closed")
        .map(|obligation| {
            serde_json::json!({
                "scope": obligation.scope,
                "feature": obligation.feature,
                "status": obligation.status,
                "detail": obligation.detail,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "metadata_scope": "cellscript-browser-summary-v1",
        "metadata_schema_version": metadata.metadata_schema_version,
        "compiler_version": metadata.compiler_version,
        "edition": metadata.edition.to_string(),
        "module": metadata.module,
        "artifact_format": metadata.artifact_format,
        "artifact_hash": metadata.artifact_hash,
        "artifact_size_bytes": metadata.artifact_size_bytes,
        "target_profile": {
            "name": metadata.target_profile.name,
            "since_abi": metadata.target_profile.since_abi,
        },
        "types": types,
        "actions": actions,
        "runtime": {
            "fail_closed_runtime_features": metadata.runtime.fail_closed_runtime_features,
            "fail_closed_obligations": fail_closed_obligations,
        },
        "native_records_omitted": [
            "public_interface",
            "typed_semantics",
            "generic_instantiations",
            "verified_artifact",
            "proof_plan",
        ],
    })
}

fn error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

fn diagnostic_error_json(message: &str, source: &str) -> String {
    let result: CompileDiagnosticResult<serde_json::Value> =
        CompileDiagnosticResult::new(None, vec![diagnostic_from_error(&CompileError::without_span(message), source)]);
    serde_json::to_string(&result).unwrap_or_else(|_| {
        serde_json::json!({
            "metadata": null,
            "diagnostic_count": 1,
            "error_count": 1,
            "warning_count": 0,
            "diagnostics": [{ "message": message, "severity": "error" }],
        })
        .to_string()
    })
}

fn diagnostic_from_error(error: &CompileError, source: &str) -> CompileDiagnostic {
    CompileDiagnostic {
        message: error.message.clone(),
        severity: error.severity.label(),
        code: error.code.clone(),
        file: error.file.as_ref().map(|file| file.to_string()),
        range: span_range(error.span, source),
    }
}

fn diagnostic_from_error_for_sources(
    error: &CompileError,
    source_by_path: &HashMap<String, String>,
    fallback_source: &str,
) -> CompileDiagnostic {
    let source = error.file.as_ref().and_then(|file| source_by_path.get(file.as_str())).map(String::as_str).unwrap_or(fallback_source);
    diagnostic_from_error(error, source)
}

fn span_range(span: Span, source: &str) -> Option<CompileDiagnosticRange> {
    if span.line == 0 || span.column == 0 {
        return None;
    }
    let source_len = source.len();
    let start = span.start.min(source_len);
    let end = span.end.min(source_len).max(start);
    let (end_line, end_column) = line_column_at(source, end);
    Some(CompileDiagnosticRange {
        start: CompileDiagnosticPosition { line: span.line, column: span.column, offset: start },
        end: CompileDiagnosticPosition { line: end_line, column: end_column, offset: end },
    })
}

fn line_column_at(source: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    let capped_offset = byte_offset.min(source.len());
    for (offset, ch) in source.char_indices() {
        if offset >= capped_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_success_returns_bounded_browser_summary() {
        let source = "module demo\n\npublic fn answer() -> u64 { return 42 }\n";
        let result: serde_json::Value = serde_json::from_str(&compile_metadata_json(source, "2026", None)).unwrap();
        assert_eq!(result["metadata_scope"], "cellscript-browser-summary-v1");
        assert_eq!(result["module"], "demo");
        assert!(result["native_records_omitted"].as_array().is_some_and(|records| {
            records.iter().any(|record| record == "public_interface") && records.iter().any(|record| record == "typed_semantics")
        }));
        assert!(result.get("public_interface").is_none());
        assert!(result.get("typed_semantics").is_none());
        assert_eq!(result["runtime"]["fail_closed_runtime_features"], serde_json::json!([]));
        assert_eq!(result["runtime"]["fail_closed_obligations"], serde_json::json!([]));
    }

    #[test]
    fn wasm_summary_exposes_deferred_runtime_in_locks_and_helpers() {
        let fixtures = [
            (
                "lock:unlock",
                "module deferred_digest\nlock unlock() -> bool { verification let value = env::sighash_all(source::group_input(0)) return value == value }\n",
            ),
            (
                "fn:digest",
                "module deferred_digest\nfn digest() -> Hash { return env::sighash_all(source::group_input(0)) }\n",
            ),
            (
                "fn:digest",
                "module deferred_digest\nfn digest() -> Hash { return env::sighash_all(source::group_input(0)) }\nlock unlock() -> bool { verification let value = digest() return value == value }\n",
            ),
        ];
        for edition in ["2026", "2027"] {
            for (scope, source) in fixtures {
                let source = if edition == "2027" { source.replace("verification", "") } else { source.to_string() };
                let metadata =
                    cellscript::compile_metadata(&source, edition.parse().unwrap(), None).expect("audit metadata remains available");
                let result: serde_json::Value = serde_json::from_str(&compile_metadata_json(&source, edition, None)).unwrap();
                assert!(result.get("error").is_none(), "{result}");
                assert_eq!(result["actions"], serde_json::json!([]), "the module warning must not depend on actions");
                assert_eq!(
                    result["runtime"]["fail_closed_runtime_features"],
                    serde_json::json!(metadata.runtime.fail_closed_runtime_features)
                );
                assert!(result["runtime"]["fail_closed_runtime_features"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|feature| feature == "ckb-sighash-all-deferred"));
                let obligation = metadata
                    .runtime
                    .verifier_obligations
                    .iter()
                    .find(|obligation| {
                        obligation.scope == scope
                            && obligation.feature == "ckb-sighash-all-deferred"
                            && obligation.status == "fail-closed"
                    })
                    .expect("shared metadata must explain the deferred operation");
                assert!(result["runtime"]["fail_closed_obligations"].as_array().unwrap().iter().any(|reason| {
                    reason["scope"] == scope && reason["feature"] == obligation.feature && reason["detail"] == obligation.detail
                }));
                assert!(result.get("typed_semantics").is_none());
                assert!(result["runtime"].get("proof_plan").is_none());

                let report: serde_json::Value =
                    serde_json::from_str(&compile_metadata_json_diagnostics(&source, edition, None)).unwrap();
                assert_eq!(report["error_count"], 0);
                assert_eq!(report["metadata"]["runtime"], result["runtime"]);
            }
        }
    }

    #[test]
    fn wasm_accepts_the_bounded_edition_2027_type_script_surface() {
        let source = r#"
module demo
resource Token has store, replace, relock { owner: Address, amount: u64 }
type_script TokenTransfer on type_group<Token> {
    entry transfer(
        input token: Token from group_input[0],
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify { enforce token.amount > 0 }
        effects {
            replace token -> next {
                data { owner = same; amount = same }
                identity = same
                type_script = same
                lock_script = exact_hash(recipient)
                capacity = same
                cardinality = one_to_one
            }
        }
    }
}
"#;
        let result: serde_json::Value = serde_json::from_str(&compile_metadata_json(source, "2027", None)).unwrap();
        assert_eq!(result["edition"], "2027");
        assert_eq!(result["actions"][0]["name"], "transfer");

        #[cfg(feature = "language-service")]
        {
            let language: serde_json::Value = serde_json::from_str(&language_service_json_for_edition(source, "2027", 3, 0)).unwrap();
            assert_eq!(language["diagnostics"].as_array().map(Vec::len), Some(0));
            assert!(language["completions"].as_array().is_some_and(|items| items.iter().any(|item| item["label"] == "type_script")));
            assert!(language["completions"].as_array().is_some_and(|items| items.iter().any(|item| item["label"] == "pool")));
            assert!(language["completions"].as_array().is_some_and(|items| items.iter().any(|item| item["label"] == "audit")));
        }
    }

    #[test]
    fn wasm_accepts_checked_pool_and_metadata_only_audit_source() {
        let source = r#"
module demo
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
"#;
        let result: serde_json::Value = serde_json::from_str(&compile_metadata_json(source, "2027", None)).unwrap();
        assert_eq!(result["edition"], "2027");
        assert_eq!(result["actions"][0]["name"], "merge");
    }

    #[test]
    fn wasm_accepts_the_bounded_edition_2027_lock_script_surface() {
        let source = r#"
module demo
resource Vault has store { owner: Address }
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
"#;
        let result: serde_json::Value = serde_json::from_str(&compile_metadata_json(source, "2027", None)).unwrap();
        assert_eq!(result["edition"], "2027");

        #[cfg(feature = "language-service")]
        {
            let language: serde_json::Value = serde_json::from_str(&language_service_json_for_edition(source, "2027", 3, 0)).unwrap();
            assert_eq!(language["diagnostics"].as_array().map(Vec::len), Some(0));
            assert!(language["completions"].as_array().is_some_and(|items| items.iter().any(|item| item["label"] == "lock_script")));
        }
    }

    #[test]
    fn wasm_accepts_the_edition_2027_typed_since_surface() {
        let source = r#"
module demo

resource Token has store { amount: u64 }

action inspect() -> bool {
    verification
        let input = ckb::input<Token>(0)
        let decoded = ckb::since_decode(input.since)
        let block = ckb::since_absolute_block(42)
        let timestamp = ckb::since_relative_timestamp(3600)
        let duration = ckb::epoch_duration(5)
        let header = ckb::header_dep(0)
        let next_epoch = ckb::epoch_add(header.epoch_number, duration)
        return ckb::since_metric(decoded) <= 2
            && ckb::since_to_raw(block) == 42
            && ckb::since_to_raw(timestamp) == 13835058055282167312
            && ckb::epoch_duration_to_u64(duration) == 5
            && ckb::epoch_number_to_u64(next_epoch) >= 5
            && ckb::block_number_to_u64(header.block_number) >= 0
            && ckb::timestamp_millis_to_u64(header.timestamp) >= 0
}
"#;
        let result: serde_json::Value = serde_json::from_str(&compile_metadata_json(source, "2027", None)).unwrap();
        assert!(result.get("error").is_none(), "unexpected wasm compile error: {result}");
        assert_eq!(result["edition"], "2027");
        assert_eq!(result["target_profile"]["since_abi"], "ckb-since-rfc0017-typed-v1");
        let features = result["actions"][0]["ckb_runtime_features"].as_array().expect("runtime features");
        for expected in ["ckb-header-epoch-number", "ckb-header-block-number", "ckb-header-timestamp-millis"] {
            assert!(features.iter().any(|feature| feature == expected), "missing {expected}: {result}");
        }
    }

    #[test]
    fn wasm_diagnostics_expose_legacy_temporal_migration_warnings() {
        let source = "module legacy_time\naction inspect() -> u64 { verification return env::current_timepoint() }\n";
        let result: serde_json::Value = serde_json::from_str(&compile_metadata_json_diagnostics(source, "2026", None)).unwrap();
        assert_eq!(result["error_count"], 0);
        assert_eq!(result["warning_count"], 1);
        assert_eq!(result["diagnostics"][0]["severity"], "warning");
        assert_eq!(result["diagnostics"][0]["code"], "W3012");
        assert!(result["diagnostics"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("ckb::epoch_number_to_u64(ckb::header_dep(0).epoch_number)")));
    }

    #[test]
    fn wasm_single_source_entrypoints_reject_oversized_input() {
        let source = " ".repeat(cellscript::MAX_SOURCE_BYTES + 1);
        let compile: serde_json::Value = serde_json::from_str(&compile_metadata_json(&source, "2026", None)).unwrap();
        assert!(compile["error"].as_str().is_some_and(|message| message.contains("source exceeds")));

        #[cfg(feature = "language-service")]
        {
            let language: serde_json::Value = serde_json::from_str(&language_service_json(&source, 0, 0)).unwrap();
            assert!(language["error"].as_str().is_some_and(|message| message.contains("source exceeds")));
        }
    }

    #[test]
    fn wasm_multi_source_entrypoint_rejects_aggregate_source_budget() {
        let half = cellscript::MAX_SOURCE_BYTES / 2 + 1;
        let sources = serde_json::json!([
            { "path": "a.cell", "source": " ".repeat(half) },
            { "path": "b.cell", "source": " ".repeat(half) }
        ])
        .to_string();
        let result: serde_json::Value =
            serde_json::from_str(&compile_metadata_json_sources(&sources, "a.cell", "2026", None)).unwrap();
        assert!(result["diagnostics"][0]["message"].as_str().is_some_and(|message| message.contains("source set exceeds")));
    }
}
