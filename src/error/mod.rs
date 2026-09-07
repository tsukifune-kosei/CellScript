use camino::Utf8PathBuf;
use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

impl Span {
    pub fn new(start: usize, end: usize, line: usize, column: usize) -> Self {
        Self { start, end, line, column }
    }

    pub fn combine(&self, other: &Span) -> Span {
        let (line, column) = if self.start <= other.start { (self.line, self.column) } else { (other.line, other.column) };
        Span { start: self.start.min(other.start), end: self.end.max(other.end), line, column }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} (bytes {}..{})", self.line, self.column, self.start, self.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompileErrorCategory {
    #[default]
    Compilation,
    Usage,
    Io,
    Network,
    Authentication,
    Internal,
}

impl CompileErrorCategory {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Compilation => "compilation",
            Self::Usage => "usage",
            Self::Io => "io",
            Self::Network => "network",
            Self::Authentication => "authentication",
            Self::Internal => "internal",
        }
    }

    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Compilation => 1,
            Self::Usage => 2,
            Self::Io => 74,
            Self::Network => 69,
            Self::Authentication => 77,
            Self::Internal => 70,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilerErrorInfo {
    pub code: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub hint: &'static str,
}

pub const COMPILER_ERROR_INFOS: &[CompilerErrorInfo] = &[
    CompilerErrorInfo {
        code: "E2000",
        name: "backend-uncategorized",
        description: "The backend failed outside a more specific classified boundary.",
        hint: "Preserve the complete diagnostic and report the generated input that reached code generation.",
    },
    CompilerErrorInfo {
        code: "E2001",
        name: "backend-empty-artifact",
        description: "Code generation completed without producing artifact bytes.",
        hint: "Check entrypoint selection and the requested artifact target.",
    },
    CompilerErrorInfo {
        code: "E2100",
        name: "type-layout-lowering",
        description: "A type definition could not be lowered to its backend storage layout.",
        hint: "Inspect fixed widths, schema fields, and payload layout requirements.",
    },
    CompilerErrorInfo {
        code: "E2101",
        name: "entry-abi-lowering",
        description: "The selected entrypoint could not be lowered to the CellScript entry ABI.",
        hint: "Check entry parameters and witness ABI support for the selected target.",
    },
    CompilerErrorInfo {
        code: "E2102",
        name: "action-lowering",
        description: "An action body could not be lowered to executable backend operations.",
        hint: "Inspect the named action and the unsupported operation reported by the diagnostic.",
    },
    CompilerErrorInfo {
        code: "E2103",
        name: "lock-lowering",
        description: "A lock body could not be lowered to executable backend operations.",
        hint: "Inspect the named lock and its target-specific runtime requirements.",
    },
    CompilerErrorInfo {
        code: "E2104",
        name: "pure-function-lowering",
        description: "A pure function could not be lowered to backend instructions.",
        hint: "Inspect the function call ABI, return layout, and unsupported expression in the diagnostic.",
    },
    CompilerErrorInfo {
        code: "E2105",
        name: "executable-surface-incomplete",
        description: "Production artifact generation was requested for source whose executable lowering is incomplete.",
        hint: "Remove the reported construct, use metadata-only analysis, or complete its compiler and CKB-VM lowering before production use.",
    },
    CompilerErrorInfo {
        code: "E2106",
        name: "shift-amount-out-of-range",
        description: "A compile-time integer shift amount is outside the width of its left operand.",
        hint: "Use a shift amount from zero up to one less than the left operand's bit width.",
    },
    CompilerErrorInfo {
        code: "E2110",
        name: "generic-declaration-invalid",
        description: "A generic declaration violates parameter, phantom, or value-ability rules.",
        hint: "Check parameter uniqueness, phantom layout use, and the separation between value abilities and Cell capabilities.",
    },
    CompilerErrorInfo {
        code: "E2111",
        name: "generic-instantiation-invalid",
        description: "A concrete generic instantiation violates arity, constraints, layout, or Cell-ownership rules.",
        hint: "Supply explicit type arguments that satisfy the declared value constraints and do not hide Cell-backed values.",
    },
    CompilerErrorInfo {
        code: "E2112",
        name: "generic-instantiation-budget",
        description: "Generic specialization exceeded a deterministic nesting, count, or identity-size budget.",
        hint: "Reduce nested or recursively expanding instantiations and keep concrete type identities compact.",
    },
    CompilerErrorInfo {
        code: "E2113",
        name: "trusted-external-binding-invalid",
        description: "A trusted external verifier call or declaration is missing, mismatched, non-canonical, unused, or ambiguous.",
        hint: "Use a trusted_* intrinsic with an exact compile-time data hash and one matching versioned Cell.toml declaration.",
    },
    CompilerErrorInfo {
        code: "E2200",
        name: "unresolved-assembly-symbol",
        description: "Generated assembly references a label or call target that was not emitted.",
        hint: "Check callable reachability and generated helper closure.",
    },
    CompilerErrorInfo {
        code: "E2201",
        name: "assembly-layout",
        description: "Generated assembly could not be parsed or arranged into a valid machine layout.",
        hint: "Inspect labels, sections, branch targets, and block ordering in the generated assembly.",
    },
    CompilerErrorInfo {
        code: "E2202",
        name: "instruction-encoding",
        description: "A generated RISC-V instruction or immediate could not be encoded.",
        hint: "Inspect the mnemonic, operands, register names, and immediate range in the diagnostic.",
    },
    CompilerErrorInfo {
        code: "E2300",
        name: "elf-emission",
        description: "The backend could not construct a valid RISC-V ELF artifact.",
        hint: "Inspect entrypoint, section layout, offsets, and ELF size constraints.",
    },
    CompilerErrorInfo {
        code: "E2400",
        name: "verified-artifact-boundary",
        description: "The compiler could not construct or persist the verified lowering/source-map boundary for an ELF artifact.",
        hint: "Inspect the verified lowering record, source artifact map, and canonical sidecar diagnostic.",
    },
    CompilerErrorInfo {
        code: "E2501",
        name: "public-interface-breaking",
        description: "A public interface comparison found a breaking source API, serialized layout, runtime ABI, effect/capability, builder, or deployment change.",
        hint: "Inspect every reported compatibility dimension and intentionally version or reverse the incompatible change before Registry publication.",
    },
    CompilerErrorInfo {
        code: "E2900",
        name: "backend-invariant",
        description: "A backend invariant was violated after semantic checking.",
        hint: "Retain the source and compiler version and report this as a compiler defect.",
    },
];

pub fn compiler_error_info_by_code(code: &str) -> Option<CompilerErrorInfo> {
    COMPILER_ERROR_INFOS.iter().copied().find(|info| info.code == code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiagnosticSeverity {
    #[default]
    Error,
    Warning,
}

impl DiagnosticSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }

    fn colour(self) -> &'static str {
        match self {
            Self::Error => "\x1b[31m",
            Self::Warning => "\x1b[33m",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RelatedDiagnostics(Option<Box<RelatedDiagnosticList>>);

#[derive(Debug, Clone)]
struct RelatedDiagnosticList(Vec<CompileError>);

impl RelatedDiagnostics {
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, CompileError> {
        self.as_slice().iter()
    }

    pub fn as_slice(&self) -> &[CompileError] {
        self.0.as_deref().map(RelatedDiagnosticList::as_slice).unwrap_or(&[])
    }
}

impl From<Vec<CompileError>> for RelatedDiagnostics {
    fn from(diagnostics: Vec<CompileError>) -> Self {
        if diagnostics.is_empty() {
            Self::default()
        } else {
            Self(Some(Box::new(RelatedDiagnosticList(diagnostics))))
        }
    }
}

impl std::ops::Deref for RelatedDiagnostics {
    type Target = [CompileError];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a RelatedDiagnostics {
    type Item = &'a CompileError;
    type IntoIter = std::slice::Iter<'a, CompileError>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl RelatedDiagnosticList {
    fn as_slice(&self) -> &[CompileError] {
        &self.0
    }
}

/// Heap-backed compiler diagnostic.
///
/// The diagnostic payload is intentionally rich, but errors are the slow path.
/// Keeping the public handle pointer-sized prevents every `Result<T,
/// CompileError>` in the compiler from reserving the full diagnostic envelope
/// on its success path. `Deref` preserves the existing field-access surface.
#[derive(Debug, Clone)]
pub struct CompileError {
    pub category: CompileErrorCategory,
    inner: Box<CompileErrorData>,
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct CompileErrorData {
    pub message: String,
    pub span: Span,
    pub file: Option<Utf8PathBuf>,
    pub code: Option<String>,
    pub severity: DiagnosticSeverity,
    pub related: RelatedDiagnostics,
    pub details: Option<serde_json::Value>,
    cause: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl std::ops::Deref for CompileError {
    type Target = CompileErrorData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for CompileError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl CompileError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            category: CompileErrorCategory::Compilation,
            inner: Box::new(CompileErrorData {
                message: message.into(),
                span,
                file: None,
                code: None,
                severity: DiagnosticSeverity::Error,
                related: RelatedDiagnostics::default(),
                details: None,
                cause: None,
            }),
        }
    }

    pub fn warning(message: impl Into<String>, span: Span) -> Self {
        Self::new(message, span).with_severity(DiagnosticSeverity::Warning)
    }

    pub fn with_severity(mut self, severity: DiagnosticSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_category(mut self, category: CompileErrorCategory) -> Self {
        self.category = category;
        self
    }

    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.cause = Some(Arc::new(source));
        self
    }

    pub const fn exit_code(&self) -> i32 {
        self.category.exit_code()
    }

    pub fn without_span(message: impl Into<String>) -> Self {
        Self::new(message, Span::default())
    }

    pub fn with_file(mut self, file: Utf8PathBuf) -> Self {
        self.file = Some(file);
        self
    }

    pub fn with_related(mut self, related: Vec<CompileError>) -> Self {
        self.related = related.into();
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn into_message(self) -> String {
        self.inner.message
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref code) = self.code {
            if let Some(ref file) = self.file {
                write!(f, "{}:{}: [{}] {}", file, self.span.line, code, self.message)
            } else {
                write!(f, "line {}: [{}] {}", self.span.line, code, self.message)
            }
        } else if let Some(ref file) = self.file {
            write!(f, "{}:{}: {}", file, self.span.line, self.message)
        } else {
            write!(f, "line {}: {}", self.span.line, self.message)
        }
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for CompileError {
    fn from(value: std::io::Error) -> Self {
        Self::without_span(value.to_string()).with_code("IO0001").with_category(CompileErrorCategory::Io).with_source(value)
    }
}

impl From<toml::de::Error> for CompileError {
    fn from(value: toml::de::Error) -> Self {
        Self::without_span(value.to_string()).with_source(value)
    }
}

impl From<toml::ser::Error> for CompileError {
    fn from(value: toml::ser::Error) -> Self {
        Self::without_span(value.to_string()).with_source(value)
    }
}

impl From<serde_json::Error> for CompileError {
    fn from(value: serde_json::Error) -> Self {
        Self::without_span(value.to_string()).with_source(value)
    }
}

pub type Result<T> = std::result::Result<T, CompileError>;

/// v0.15 migration diagnostic codes.
///
/// These codes are emitted in `--primitive-strict=0.15` mode when the compiler
/// encounters v0.14-era syntax that must be migrated. In `--primitive-compat=0.14`
/// mode they appear as warnings with migration hints instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationDiagnostic {
    /// CS0151: legacy `has destroy` capability must be expressed as kernel effects
    Cs0151,
    /// CS0152: `Address` cannot be used as `LockHash` without a resolver
    Cs0152,
    /// CS0153: CKB entry role must be explicit
    Cs0153,
    /// CS0154: claim proof bindings must be explicit
    Cs0154,
    /// CS0155: type_id lifecycle must be explicit
    Cs0155,
    /// CS0156: protocol capabilities are not allowed in strict mode
    Cs0156,
    /// CS0157: schema-backed replacement requires a layout policy
    Cs0157,
    /// CS0158: invariant trigger and scope must be explicit
    Cs0158,
    /// CS0159: lock_group + transaction scope requires explicit coverage acknowledgement
    Cs0159,
    /// CS0160: builder assumption is not on-chain checked
    Cs0160,
}

impl MigrationDiagnostic {
    pub fn code(self) -> &'static str {
        match self {
            Self::Cs0151 => "CS0151",
            Self::Cs0152 => "CS0152",
            Self::Cs0153 => "CS0153",
            Self::Cs0154 => "CS0154",
            Self::Cs0155 => "CS0155",
            Self::Cs0156 => "CS0156",
            Self::Cs0157 => "CS0157",
            Self::Cs0158 => "CS0158",
            Self::Cs0159 => "CS0159",
            Self::Cs0160 => "CS0160",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Cs0151 => "legacy destroy capability must use consume + burn kernel effects",
            Self::Cs0152 => "Address cannot be used as LockHash without a resolver",
            Self::Cs0153 => "CKB entry role must be explicit",
            Self::Cs0154 => "claim proof bindings must be explicit",
            Self::Cs0155 => "type_id lifecycle must be explicit",
            Self::Cs0156 => "protocol capabilities are not allowed in strict mode",
            Self::Cs0157 => "schema-backed replacement requires a layout policy",
            Self::Cs0158 => "invariant trigger and scope must be explicit",
            Self::Cs0159 => "lock_group + transaction scope requires explicit coverage acknowledgement",
            Self::Cs0160 => "builder assumption is not on-chain checked",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Self::Cs0151 => {
                "replace `has destroy` with `has consume, burn`; use a policy-specific destruction form when the proof needs one"
            }
            Self::Cs0152 => "use LockHash, LockScript, or transfer_to_lock_hash/transfer_to_lock_script explicitly",
            Self::Cs0153 => "add #[entry(lock)] or #[entry(type)] to the entry declaration",
            Self::Cs0154 => "use claim_proof(receipt, signer=..., recipient=..., amount=..., nonce=...) with explicit bindings",
            Self::Cs0155 => {
                "add `identity = ckb_type_id` to the resource declaration and use create_unique/replace_unique/destroy_unique"
            }
            Self::Cs0156 => "replace `has destroy` with `has consume, burn`",
            Self::Cs0157 => "add `preserve_layout<T>()` or `migrate_layout<T>(from=..., to=...)` to the replacement",
            Self::Cs0158 => "add `trigger:` and `scope:` to the invariant declaration",
            Self::Cs0159 => "add `acknowledge_coverage` or restructure to `scope: group`",
            Self::Cs0160 => "promote the builder assumption to an on-chain check or document it explicitly",
        }
    }

    /// Build a full diagnostic message with code, description, and migration hint.
    pub fn full_message(self) -> String {
        format!("{}: {}\n  hint: {}", self.code(), self.message(), self.hint())
    }

    pub fn warning(self, span: Span) -> CompileError {
        CompileError::warning(self.full_message(), span).with_code(self.code())
    }

    pub fn error(self, span: Span) -> CompileError {
        CompileError::new(self.full_message(), span).with_code(self.code())
    }
}

pub struct ErrorReporter {
    diagnostics: Vec<CompileError>,
    source: String,
    filename: Option<Utf8PathBuf>,
}

impl ErrorReporter {
    pub fn new(source: String, filename: Option<Utf8PathBuf>) -> Self {
        Self { diagnostics: Vec::new(), source, filename }
    }

    pub fn report(&mut self, message: impl Into<String>, span: Span) {
        self.push(CompileError::new(message, span));
    }

    pub fn report_warning(&mut self, message: impl Into<String>, span: Span) {
        self.push(CompileError::warning(message, span));
    }

    fn push(&mut self, diagnostic: CompileError) {
        let mut diagnostic = diagnostic;
        if let Some(ref file) = self.filename {
            diagnostic = diagnostic.with_file(file.clone());
        }
        self.diagnostics.push(diagnostic);
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    }

    pub fn errors(&self) -> &[CompileError] {
        &self.diagnostics
    }

    pub fn print_errors(&self) {
        for diagnostic in &self.diagnostics {
            eprintln!("{}{}\x1b[0m: {}", diagnostic.severity.colour(), diagnostic.severity.label(), diagnostic);
            if let Some(line) = self.source.lines().nth(diagnostic.span.line.saturating_sub(1)) {
                eprintln!("  \x1b[34m{}\x1b[0m | {}", diagnostic.span.line, line);
                let spaces = " ".repeat(diagnostic.span.line.to_string().len() + 3);
                let carets = "^".repeat(diagnostic.span.end.saturating_sub(diagnostic.span.start).max(1));
                eprintln!("{}  \x1b[32m{}\x1b[0m", spaces, carets);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_error_defaults_to_error_severity() {
        let error = CompileError::new("boom", Span::default());
        assert_eq!(error.severity, DiagnosticSeverity::Error);
        assert_eq!(error.category, CompileErrorCategory::Compilation);
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn compile_error_handle_stays_pointer_sized() {
        assert!(std::mem::size_of::<CompileError>() <= 2 * std::mem::size_of::<usize>());
    }

    #[test]
    fn span_combine_uses_the_earliest_start_position() {
        let later = Span::new(8, 10, 3, 4);
        let earlier = Span::new(2, 5, 1, 3);
        assert_eq!(later.combine(&earlier), Span::new(2, 10, 1, 3));
        assert_eq!(earlier.combine(&later), Span::new(2, 10, 1, 3));
    }

    #[test]
    fn span_display_names_source_and_byte_positions_unambiguously() {
        assert_eq!(Span::new(8, 12, 2, 5).to_string(), "2:5 (bytes 8..12)");
    }

    #[test]
    fn io_errors_retain_their_category_and_source() {
        use std::error::Error;

        let error = CompileError::from(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"));
        assert_eq!(error.category, CompileErrorCategory::Io);
        assert_eq!(error.exit_code(), 74);
        assert!(error.source().is_some());
    }

    #[test]
    fn compiler_error_registry_has_unique_stable_codes() {
        let mut codes = std::collections::BTreeSet::new();
        for info in COMPILER_ERROR_INFOS {
            assert!(codes.insert(info.code), "duplicate compiler error code {}", info.code);
            assert_eq!(compiler_error_info_by_code(info.code), Some(*info));
            assert!(info.code.starts_with("E2"));
            assert!(!info.description.is_empty());
            assert!(!info.hint.is_empty());
        }
    }

    #[test]
    fn error_reporter_distinguishes_warnings_from_errors() {
        let mut reporter = ErrorReporter::new("let x = 1".to_string(), None);
        reporter.report_warning("compatibility note", Span::new(0, 3, 1, 1));
        assert!(!reporter.has_errors());
        assert_eq!(reporter.errors()[0].severity, DiagnosticSeverity::Warning);

        reporter.report("hard failure", Span::new(4, 5, 1, 5));
        assert!(reporter.has_errors());
        assert_eq!(reporter.errors()[1].severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn migration_diagnostic_can_build_typed_warning() {
        let warning = MigrationDiagnostic::Cs0151.warning(Span::new(0, 3, 1, 1));
        assert_eq!(warning.severity, DiagnosticSeverity::Warning);
        assert_eq!(warning.code.as_deref(), Some("CS0151"));
        assert!(warning.message.contains("legacy destroy capability"));
    }
}
