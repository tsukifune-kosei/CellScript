use super::parse;
use crate::ast::{ActionDef, Expr, Item, LockDef, Module, NextLockSurface, ParamSource, Stmt, Type, Visibility};
use crate::edition::CellScriptEdition;
use crate::error::{CompileError, Result, Span};
use crate::lexer;
use crate::lexer::token::{Token, TokenKind};
use serde::Serialize;
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationKind {
    TypeScript,
    LockScript,
}

impl MigrationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypeScript => "type-script",
            Self::LockScript => "lock-script",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationCandidate {
    pub schema: String,
    pub source_edition: String,
    pub target_edition: String,
    pub kind: MigrationKind,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TemporalMigrationCandidate {
    pub schema: String,
    pub source_edition: String,
    pub migration: String,
    pub replacements: usize,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyTemporalApi {
    CurrentTimepoint,
    HeaderEpochNumber,
    HeaderEpochStartBlockNumber,
    HeaderEpochLength,
    InputSince,
    InputSinceAt,
    SinceEpochAbsolute,
    SinceEpochRelative,
}

impl LegacyTemporalApi {
    fn from_qualified_name(namespace: &str, name: &str) -> Option<Self> {
        match (namespace, name) {
            ("env", "current_timepoint") => Some(Self::CurrentTimepoint),
            ("ckb", "header_epoch_number") => Some(Self::HeaderEpochNumber),
            ("ckb", "header_epoch_start_block_number") => Some(Self::HeaderEpochStartBlockNumber),
            ("ckb", "header_epoch_length") => Some(Self::HeaderEpochLength),
            ("ckb", "input_since") => Some(Self::InputSince),
            ("ckb", "input_since_at") => Some(Self::InputSinceAt),
            ("ckb", "since_epoch_absolute") => Some(Self::SinceEpochAbsolute),
            ("ckb", "since_epoch_relative") => Some(Self::SinceEpochRelative),
            _ => None,
        }
    }

    fn qualified_name(self) -> &'static str {
        match self {
            Self::CurrentTimepoint => "env::current_timepoint",
            Self::HeaderEpochNumber => "ckb::header_epoch_number",
            Self::HeaderEpochStartBlockNumber => "ckb::header_epoch_start_block_number",
            Self::HeaderEpochLength => "ckb::header_epoch_length",
            Self::InputSince => "ckb::input_since",
            Self::InputSinceAt => "ckb::input_since_at",
            Self::SinceEpochAbsolute => "ckb::since_epoch_absolute",
            Self::SinceEpochRelative => "ckb::since_epoch_relative",
        }
    }

    fn replacement_summary(self) -> &'static str {
        match self {
            Self::CurrentTimepoint | Self::HeaderEpochNumber => "ckb::epoch_number_to_u64(ckb::header_dep(0).epoch_number)",
            Self::HeaderEpochStartBlockNumber => "ckb::block_number_to_u64(ckb::header_dep(0).epoch_start_block_number)",
            Self::HeaderEpochLength => "ckb::epoch_length_to_u64(ckb::header_dep(0).epoch_length)",
            Self::InputSince => "ckb::input_since_raw()",
            Self::InputSinceAt => "ckb::since_to_raw((input).since)",
            Self::SinceEpochAbsolute => "ckb::since_to_raw(ckb::since_absolute_epoch(...))",
            Self::SinceEpochRelative => "ckb::since_to_raw(ckb::since_relative_epoch(...))",
        }
    }

    fn requires_no_arguments(self) -> bool {
        matches!(
            self,
            Self::CurrentTimepoint
                | Self::HeaderEpochNumber
                | Self::HeaderEpochStartBlockNumber
                | Self::HeaderEpochLength
                | Self::InputSince
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct LegacyTemporalCall {
    api: LegacyTemporalApi,
    span: Span,
    start: usize,
    name_start: usize,
    name_end: usize,
    lparen_end: usize,
    rparen_start: usize,
    end: usize,
}

#[derive(Debug)]
struct SourceEdit {
    start: usize,
    end: usize,
    replacement: &'static str,
}

/// Rewrite the legacy raw-`u64` CKB temporal calls to explicit typed-domain
/// operations while preserving the surrounding raw result type. The edit is
/// lexical, so comments and formatting outside the qualified call names remain
/// byte-for-byte intact. It never changes a package manifest or source edition.
pub fn migrate_legacy_temporal_source(source: &str, edition: CellScriptEdition) -> Result<TemporalMigrationCandidate> {
    parse(source, edition)?;
    let calls = legacy_temporal_calls(source)?;
    let mut edits = Vec::new();
    for call in &calls {
        match call.api {
            LegacyTemporalApi::CurrentTimepoint | LegacyTemporalApi::HeaderEpochNumber => edits.push(SourceEdit {
                start: call.start,
                end: call.end,
                replacement: "ckb::epoch_number_to_u64(ckb::header_dep(0).epoch_number)",
            }),
            LegacyTemporalApi::HeaderEpochStartBlockNumber => edits.push(SourceEdit {
                start: call.start,
                end: call.end,
                replacement: "ckb::block_number_to_u64(ckb::header_dep(0).epoch_start_block_number)",
            }),
            LegacyTemporalApi::HeaderEpochLength => edits.push(SourceEdit {
                start: call.start,
                end: call.end,
                replacement: "ckb::epoch_length_to_u64(ckb::header_dep(0).epoch_length)",
            }),
            LegacyTemporalApi::InputSince => {
                edits.push(SourceEdit { start: call.start, end: call.end, replacement: "ckb::input_since_raw()" })
            }
            LegacyTemporalApi::InputSinceAt => {
                edits.push(SourceEdit { start: call.start, end: call.lparen_end, replacement: "ckb::since_to_raw((" });
                edits.push(SourceEdit { start: call.rparen_start, end: call.rparen_start, replacement: ").since" });
            }
            LegacyTemporalApi::SinceEpochAbsolute | LegacyTemporalApi::SinceEpochRelative => {
                edits.push(SourceEdit { start: call.start, end: call.start, replacement: "ckb::since_to_raw(" });
                edits.push(SourceEdit {
                    start: call.name_start,
                    end: call.name_end,
                    replacement: if call.api == LegacyTemporalApi::SinceEpochAbsolute {
                        "since_absolute_epoch"
                    } else {
                        "since_relative_epoch"
                    },
                });
                edits.push(SourceEdit { start: call.end, end: call.end, replacement: ")" });
            }
        }
    }
    edits.sort_by(|left, right| right.start.cmp(&left.start).then_with(|| right.end.cmp(&left.end)));
    let mut migrated = source.to_string();
    for edit in edits {
        migrated.replace_range(edit.start..edit.end, edit.replacement);
    }
    parse(&migrated, edition).map_err(|error| {
        CompileError::new(
            format!("generated temporal migration candidate failed its frontend contract: {}", error.message),
            error.span,
        )
    })?;
    Ok(TemporalMigrationCandidate {
        schema: "cellscript-temporal-source-migration-v1".to_string(),
        source_edition: edition.as_str().to_string(),
        migration: "legacy-raw-ckb-temporal-to-explicit-typed-v1".to_string(),
        replacements: calls.len(),
        source: migrated,
    })
}

/// Targeted warnings for every legacy temporal call that has a total,
/// raw-result-compatible typed-domain replacement.
pub fn legacy_temporal_migration_diagnostics(source: &str) -> Vec<CompileError> {
    let Ok(calls) = legacy_temporal_calls(source) else {
        return Vec::new();
    };
    calls
        .into_iter()
        .map(|call| {
            CompileError::warning(
                format!(
                    "legacy raw temporal API '{}' keeps Edition 2026 semantics; migrate mechanically to '{}'",
                    call.api.qualified_name(),
                    call.api.replacement_summary()
                ),
                call.span,
            )
            .with_code("W3012")
            .with_details(serde_json::json!({
                "legacy_api": call.api.qualified_name(),
                "replacement": call.api.replacement_summary(),
                "migration": "legacy-raw-ckb-temporal-to-explicit-typed-v1",
            }))
        })
        .collect()
}

fn legacy_temporal_calls(source: &str) -> Result<Vec<LegacyTemporalCall>> {
    let tokens = lexer::lex(source)?;
    let mut calls = Vec::new();
    let mut index = 0usize;
    while index + 3 < tokens.len() {
        let Some(namespace) = token_name(&tokens[index]) else {
            index += 1;
            continue;
        };
        if tokens[index + 1].kind != TokenKind::ColonColon || tokens[index + 3].kind != TokenKind::LParen {
            index += 1;
            continue;
        }
        let Some(name) = token_name(&tokens[index + 2]) else {
            index += 1;
            continue;
        };
        let Some(api) = LegacyTemporalApi::from_qualified_name(namespace, name) else {
            index += 1;
            continue;
        };
        let Some(rparen_index) = matching_rparen(&tokens, index + 3) else {
            index += 1;
            continue;
        };
        if api.requires_no_arguments() && tokens[index + 4..rparen_index].iter().any(|token| token.kind != TokenKind::Newline) {
            index += 1;
            continue;
        }
        let start = tokens[index].span.start;
        let end = tokens[rparen_index].span.end;
        calls.push(LegacyTemporalCall {
            api,
            span: Span::new(start, end, tokens[index].span.line, tokens[index].span.column),
            start,
            name_start: tokens[index + 2].span.start,
            name_end: tokens[index + 2].span.end,
            lparen_end: tokens[index + 3].span.end,
            rparen_start: tokens[rparen_index].span.start,
            end,
        });
        index += 1;
    }
    Ok(calls)
}

fn token_name(token: &Token) -> Option<&str> {
    match &token.kind {
        TokenKind::Identifier(name) => Some(name),
        TokenKind::Env => Some("env"),
        _ => None,
    }
}

fn matching_rparen(tokens: &[Token], lparen_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(lparen_index) {
        match token.kind {
            TokenKind::LParen => depth += 1,
            TokenKind::RParen => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Produce a review-only Edition 2027 candidate for the exact bounded subset
/// whose source/target lowerings are covered by differential evidence. Action
/// candidates retain ordinary transaction-absolute authoring: converting them
/// to native group ports would change their accepted transaction set. The
/// function never edits the input and fails before returning a partial candidate.
pub fn migrate_source_to_2027(source: &str) -> Result<MigrationCandidate> {
    let module = parse(source, CellScriptEdition::Edition2026)?;
    if module.items.iter().any(|item| matches!(item, Item::Use(_))) {
        return Err(CompileError::new(
            "Edition 2027 preview migration currently requires one self-contained source module; imported modules need graph-wide migration",
            module.span,
        ));
    }
    let entries =
        module.items.iter().enumerate().filter(|(_, item)| matches!(item, Item::Action(_) | Item::Lock(_))).collect::<Vec<_>>();
    let [(entry_index, entry)] = entries.as_slice() else {
        return Err(CompileError::new("Edition 2027 preview migration requires exactly one legacy action or lock entry", module.span));
    };
    if *entry_index + 1 != module.items.len() {
        return Err(CompileError::new(
            "the migratable entry must be the final declaration so migration does not reorder unrelated source",
            entry_span(entry),
        ));
    }

    let (replacement_item, kind, entry_span) = match entry {
        Item::Action(action) => (Item::Action(migrate_action(&module, action)?), MigrationKind::TypeScript, action.span),
        Item::Lock(lock) => (Item::Lock(migrate_lock(&module, lock)?), MigrationKind::LockScript, lock.span),
        _ => unreachable!("filtered to executable entries"),
    };
    let replacement = format_single_item(&module, replacement_item)?;
    let source_range = executable_source_range(source, entry_span, kind)?;
    let mut candidate = String::with_capacity(source.len() - source_range.len() + replacement.len());
    candidate.push_str(&source[..source_range.start]);
    candidate.push_str(&replacement);
    candidate.push_str(&source[source_range.end..]);
    parse(&candidate, CellScriptEdition::Edition2027).map_err(|error| {
        CompileError::new(format!("generated Edition 2027 candidate failed its frontend contract: {}", error.message), error.span)
    })?;

    Ok(MigrationCandidate {
        schema: "cellscript-source-migration-preview-v1".to_string(),
        source_edition: "2026".to_string(),
        target_edition: "2027".to_string(),
        kind,
        source: candidate,
    })
}

fn migrate_action(module: &Module, action: &ActionDef) -> Result<ActionDef> {
    if action.next_surface.is_some()
        || action.return_type.is_some()
        || !action.state_edges.is_empty()
        || action.effect_declared
        || action.scheduler_hint.is_some()
        || action.doc_comment.is_some()
    {
        return migration_error(
            action.span,
            "legacy action uses return, transition, effect, scheduler, documentation, or native-container syntax outside the bounded migration subset",
        );
    }
    if module.visibility_of(&action.name) != Visibility::LegacyPublic {
        return migration_error(action.span, "explicit entry visibility has no lossless native-container mapping in this preview");
    }
    if action.params.iter().any(|param| !matches!(param.source, ParamSource::Input | ParamSource::Witness)) {
        return migration_error(
            action.span,
            "type-script migration requires every parameter to be explicitly sourced as input or witness",
        );
    }
    if action.params.iter().any(|param| param.is_mut || param.is_ref || param.is_read_ref) {
        return migration_error(
            action.span,
            "mutable, reference, or read-role parameters have no lossless native-container mapping in this preview",
        );
    }
    let input_types = action
        .params
        .iter()
        .filter(|param| param.source == ParamSource::Input)
        .map(|param| named_type(&param.ty, param.span))
        .collect::<Result<Vec<_>>>()?;
    let output_types = action.outputs.iter().map(|output| named_type(&output.ty, output.span)).collect::<Result<Vec<_>>>()?;
    let Some(trigger_type) = input_types.first().map(|ty| (*ty).to_string()) else {
        return migration_error(action.span, "type-script migration requires at least one explicitly sourced input role");
    };
    if output_types.is_empty() || input_types.iter().chain(&output_types).any(|ty| **ty != trigger_type) {
        return migration_error(
            action.span,
            "type-script migration requires non-empty input/output roles using one identical Cell-backed schema",
        );
    }
    let declared_fields = cell_fields(module, &trigger_type, action.span)?;

    let mut cursor = 0usize;
    while let Some(Stmt::Expr(Expr::Require(require))) = action.body.get(cursor) {
        if require.message.is_some() {
            return migration_error(require.span, "Edition 2027 enforce has no accepted custom-message mapping in this preview");
        }
        cursor += 1;
    }

    let mut replacements = 0usize;
    while cursor < action.body.len() {
        let Some(Stmt::Expr(Expr::StdlibCall(transfer))) = action.body.get(cursor) else {
            return migration_error(action.body[cursor].span(), "type-script migration expected an exact lifecycle transfer");
        };
        let Some(Stmt::Expr(Expr::StdlibCall(capacity))) = action.body.get(cursor + 1) else {
            return migration_error(transfer.span, "each migrated transfer must be followed by preserve_capacity");
        };
        if transfer.namespace != "lifecycle" || transfer.name != "transfer" || transfer.args.len() != 3 {
            return migration_error(transfer.span, "only std::lifecycle::transfer(input, output, lock) is migratable");
        }
        let input = identifier(&transfer.args[0], transfer.span, "transfer input")?;
        let output = identifier(&transfer.args[1], transfer.span, "transfer output")?;
        if transfer.preserve_fields != declared_fields {
            return migration_error(transfer.span, "transfer field list must exhaustively match the Cell schema in declaration order");
        }
        if capacity.namespace != "cell"
            || capacity.name != "preserve_capacity"
            || capacity.args.len() != 2
            || !capacity.preserve_fields.is_empty()
            || identifier(&capacity.args[0], capacity.span, "capacity output")? != output
            || identifier(&capacity.args[1], capacity.span, "capacity input")? != input
        {
            return migration_error(capacity.span, "each migrated transfer requires std::cell::preserve_capacity(output, input)");
        }
        replacements += 1;
        cursor += 2;
    }
    if replacements == 0 {
        return migration_error(action.span, "type-script migration requires at least one exhaustive one-to-one transfer");
    }

    // The authoring frontend accepts this structured action directly. Retain
    // its absolute binding contract instead of silently selecting GroupInput
    // and GroupOutput. Native migration requires a separate reviewed change.
    Ok(action.clone())
}

fn migrate_lock(module: &Module, lock: &LockDef) -> Result<LockDef> {
    if lock.next_surface.is_some() || lock.return_type != Type::Bool {
        return migration_error(lock.span, "lock migration requires the legacy bool-returning lock contract");
    }
    if module.visibility_of(&lock.name) != Visibility::LegacyPublic {
        return migration_error(lock.span, "explicit entry visibility has no lossless native-container mapping in this preview");
    }
    if lock.params.iter().any(|param| !matches!(param.source, ParamSource::Protected | ParamSource::Witness | ParamSource::LockArgs)) {
        return migration_error(
            lock.span,
            "lock-script migration requires every parameter to be explicitly sourced as protected, witness, or lock_args",
        );
    }
    if lock.params.iter().any(|param| param.is_mut || param.is_ref || param.is_read_ref) {
        return migration_error(
            lock.span,
            "mutable, reference, or read-role parameters have no lossless native-container mapping in this preview",
        );
    }
    let protected = lock.params.iter().filter(|param| param.source == ParamSource::Protected).collect::<Vec<_>>();
    let [protected] = protected.as_slice() else {
        return migration_error(lock.span, "lock-script migration requires exactly one protected Cell role");
    };
    let protected_type = match &protected.ty {
        Type::Named(name) => name.as_str(),
        Type::Ref(inner) => named_type(inner, protected.span)?,
        _ => return migration_error(protected.span, "protected role must name a Cell-backed schema"),
    };
    cell_fields(module, protected_type, protected.span)?;

    let mut verify = Vec::new();
    for statement in &lock.body {
        let Stmt::Expr(Expr::Require(require)) = statement else {
            return migration_error(statement.span(), "lock-script migration currently accepts only require conditions");
        };
        if require.message.is_some() {
            return migration_error(require.span, "Edition 2027 enforce has no accepted custom-message mapping in this preview");
        }
        verify.push(require.condition.as_ref().clone());
    }
    let mut migrated = lock.clone();
    migrated.next_surface =
        Some(NextLockSurface { container_name: format!("{}Lock", pascal_case(&lock.name)), verify, audits: Vec::new() });
    Ok(migrated)
}

fn named_type(ty: &Type, span: Span) -> Result<&str> {
    let Type::Named(name) = ty else {
        return migration_error(span, "migrated Cell roles must use a named Cell-backed schema");
    };
    Ok(name)
}

fn cell_fields(module: &Module, name: &str, span: Span) -> Result<Vec<String>> {
    module
        .items
        .iter()
        .find_map(|item| match item {
            Item::Resource(definition) if definition.name == name => Some(&definition.fields),
            Item::Shared(definition) if definition.name == name => Some(&definition.fields),
            Item::Receipt(definition) if definition.name == name => Some(&definition.fields),
            _ => None,
        })
        .map(|fields| fields.iter().map(|field| field.name.clone()).collect())
        .ok_or_else(|| {
            CompileError::new(format!("migrated type_group<{name}> is not declared as a Cell-backed type in this module"), span)
        })
}

fn identifier(expr: &Expr, span: Span, role: &str) -> Result<String> {
    let Expr::Identifier(name) = expr else {
        return migration_error(span, &format!("{role} must be a direct role binding"));
    };
    Ok(name.clone())
}

fn format_single_item(module: &Module, item: Item) -> Result<String> {
    let one = Module {
        name: module.name.clone(),
        items: vec![item],
        interface_templates: Vec::new(),
        visibilities: Default::default(),
        span: module.span,
    };
    let formatted = crate::fmt::format_default(&one)?;
    let header = format!("module {}\n\n", module.name);
    formatted
        .strip_prefix(&header)
        .map(|body| body.trim_end().to_string())
        .ok_or_else(|| CompileError::new("failed to isolate the generated native Script container", module.span))
}

fn executable_source_range(source: &str, entry_span: Span, kind: MigrationKind) -> Result<Range<usize>> {
    let tokens = lexer::lex(source)?;
    let expected = match kind {
        MigrationKind::TypeScript => TokenKind::Action,
        MigrationKind::LockScript => TokenKind::Lock,
    };
    let start_index = tokens
        .iter()
        .position(|token| token.span.start == entry_span.start && token.kind == expected)
        .ok_or_else(|| CompileError::new("failed to locate the legacy entry token for migration", entry_span))?;
    let mut depth = 0usize;
    let mut opened = false;
    for token in &tokens[start_index..] {
        match token.kind {
            TokenKind::LBrace => {
                depth += 1;
                opened = true;
            }
            TokenKind::RBrace if opened => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(entry_span.start..token.span.end);
                }
            }
            _ => {}
        }
    }
    Err(CompileError::new("failed to find the end of the legacy entry for migration", entry_span))
}

fn entry_span(item: &Item) -> Span {
    match item {
        Item::Action(action) => action.span,
        Item::Lock(lock) => lock.span,
        _ => Span::default(),
    }
}

fn pascal_case(name: &str) -> String {
    let mut output = String::new();
    let mut uppercase = true;
    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            uppercase = true;
        } else if uppercase {
            output.extend(ch.to_uppercase());
            uppercase = false;
        } else {
            output.push(ch);
        }
    }
    output
}

fn migration_error<T>(span: Span, message: &str) -> Result<T> {
    Err(CompileError::new(format!("Edition 2027 preview migration stopped: {message}"), span))
}

trait StatementSpan {
    fn span(&self) -> Span;
}

impl StatementSpan for Stmt {
    fn span(&self) -> Span {
        match self {
            Stmt::Let(statement) => statement.span,
            Stmt::Expr(expression) => expression.span(),
            Stmt::Return(statement) => statement.span,
            Stmt::If(statement) => statement.span,
            Stmt::For(statement) => statement.span,
            Stmt::While(statement) => statement.span,
            Stmt::Break(statement) | Stmt::Continue(statement) => statement.span,
            Stmt::Borrow(statement) => statement.span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile, CompileOptions};

    const LEGACY_TYPE: &str = r#"module migrate_type

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

    const LEGACY_LOCK: &str = r#"module migrate_lock

resource Vault has store {
    owner: Address,
}

lock unlock(protected vault: Vault, lock_args owner: Address, witness claimed_owner: Address) -> bool {
    verification
        require vault.owner == owner
        require claimed_owner == owner
}
"#;

    #[test]
    fn migrates_only_the_legacy_type_entry() {
        let candidate = migrate_source_to_2027(LEGACY_TYPE).unwrap();
        assert_eq!(candidate.kind, MigrationKind::TypeScript);
        assert!(candidate.source.starts_with(&LEGACY_TYPE[..LEGACY_TYPE.find("action transfer").unwrap()]));
        assert!(candidate.source.contains("action transfer("));
        assert!(candidate.source.contains("require token.amount > 0"));
        assert!(candidate.source.contains("std::lifecycle::transfer(token, next, recipient)"));
        assert!(!candidate.source.contains("type_script"));
        let legacy = compile(
            LEGACY_TYPE,
            CompileOptions {
                edition: CellScriptEdition::Edition2026,
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();
        let migrated = compile(
            &candidate.source,
            CompileOptions {
                edition: CellScriptEdition::Edition2027,
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();
        assert_eq!(legacy.artifact_bytes, migrated.artifact_bytes);
        assert_eq!(
            legacy.metadata.typed_semantics.foundation.identities.core_semantic_id,
            migrated.metadata.typed_semantics.foundation.identities.core_semantic_id
        );
    }

    #[test]
    fn migrates_only_the_legacy_lock_entry() {
        let candidate = migrate_source_to_2027(LEGACY_LOCK).unwrap();
        assert_eq!(candidate.kind, MigrationKind::LockScript);
        assert!(candidate.source.starts_with(&LEGACY_LOCK[..LEGACY_LOCK.find("lock unlock").unwrap()]));
        assert!(candidate.source.contains("lock_script UnlockLock on lock_group"));
        assert!(candidate.source.contains("protected vault: Vault from group_input[0]"));
        let legacy = compile(
            LEGACY_LOCK,
            CompileOptions {
                edition: CellScriptEdition::Edition2026,
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();
        let migrated = compile(
            &candidate.source,
            CompileOptions {
                edition: CellScriptEdition::Edition2027,
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();
        assert_eq!(legacy.artifact_bytes, migrated.artifact_bytes);
        assert_eq!(legacy.metadata.typed_semantics.foundation.identities, migrated.metadata.typed_semantics.foundation.identities);
    }

    #[test]
    fn rejects_ambiguous_or_lossy_legacy_source() {
        let ambiguous = "module demo\nresource Token has consume { amount: u64 }\naction main(input token: Token) -> next: Token { verification consume token }";
        assert!(migrate_source_to_2027(ambiguous).unwrap_err().message.contains("expected an exact lifecycle transfer"));
        let message = LEGACY_LOCK.replace("require vault.owner == owner", "require vault.owner == owner, \"owner mismatch\"");
        assert!(migrate_source_to_2027(&message).unwrap_err().message.contains("no accepted custom-message mapping"));
        let visibility = LEGACY_TYPE.replace("action transfer", "private action transfer");
        assert!(migrate_source_to_2027(&visibility).unwrap_err().message.contains("explicit entry visibility"));
    }

    #[test]
    fn temporal_migration_preserves_raw_results_comments_and_nested_calls() {
        let source = r#"module temporal
resource Token has store { amount: u64 }
fn inspect() -> u64 {
    let input = ckb::input<Token>(0)
    let epoch = env::current_timepoint()
    let header_epoch = ckb::header_epoch_number()
    let start = ckb::header_epoch_start_block_number()
    let length = ckb::header_epoch_length()
    let implicit_since = ckb::input_since()
    let observed = ckb::input_since_at(input /* keep */)
    let required = ckb::since_epoch_absolute(42, 3, 10)
    let nested = ckb::since_epoch_relative(ckb::header_epoch_number(), 1, 4)
    return epoch + header_epoch + start + length + implicit_since + observed + required + nested
}
"#;
        let candidate = migrate_legacy_temporal_source(source, CellScriptEdition::Edition2026).unwrap();
        assert_eq!(candidate.replacements, 9);
        assert!(candidate.source.contains("input /* keep */).since"));
        assert!(candidate.source.contains("ckb::epoch_number_to_u64(ckb::header_dep(0).epoch_number)"));
        assert!(candidate.source.contains(
            "ckb::since_to_raw(ckb::since_relative_epoch(ckb::epoch_number_to_u64(ckb::header_dep(0).epoch_number), 1, 4))"
        ));
        let original = compile(source, CompileOptions::default()).unwrap();
        let migrated = compile(&candidate.source, CompileOptions::default()).unwrap();
        assert_eq!(original.metadata.functions[0].return_type, migrated.metadata.functions[0].return_type);
        assert!(legacy_temporal_migration_diagnostics(&candidate.source).is_empty());
        let diagnostics = legacy_temporal_migration_diagnostics(source);
        assert_eq!(diagnostics.len(), 9);
        assert!(diagnostics.iter().all(|diagnostic| diagnostic.code.as_deref() == Some("W3012")));
    }
}
