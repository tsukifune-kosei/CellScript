use camino::Utf8PathBuf;
use std::fmt;

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
        Span { start: self.start.min(other.start), end: self.end.max(other.end), line: self.line, column: self.column }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}-{}:{}:{}", self.line, self.column, self.end, self.start, self.end)
    }
}

#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    pub span: Span,
    pub file: Option<Utf8PathBuf>,
}

impl CompileError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self { message: message.into(), span, file: None }
    }

    pub fn without_span(message: impl Into<String>) -> Self {
        Self::new(message, Span::default())
    }

    pub fn with_file(mut self, file: Utf8PathBuf) -> Self {
        self.file = Some(file);
        self
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref file) = self.file {
            write!(f, "{}:{}: {}", file, self.span.line, self.message)
        } else {
            write!(f, "line {}: {}", self.span.line, self.message)
        }
    }
}

impl std::error::Error for CompileError {}

impl From<std::io::Error> for CompileError {
    fn from(value: std::io::Error) -> Self {
        Self::without_span(value.to_string())
    }
}

impl From<toml::de::Error> for CompileError {
    fn from(value: toml::de::Error) -> Self {
        Self::without_span(value.to_string())
    }
}

impl From<toml::ser::Error> for CompileError {
    fn from(value: toml::ser::Error) -> Self {
        Self::without_span(value.to_string())
    }
}

impl From<serde_json::Error> for CompileError {
    fn from(value: serde_json::Error) -> Self {
        Self::without_span(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CompileError>;

pub struct ErrorReporter {
    errors: Vec<CompileError>,
    source: String,
    filename: Option<Utf8PathBuf>,
}

impl ErrorReporter {
    pub fn new(source: String, filename: Option<Utf8PathBuf>) -> Self {
        Self { errors: Vec::new(), source, filename }
    }

    pub fn report(&mut self, message: impl Into<String>, span: Span) {
        let mut error = CompileError::new(message, span);
        if let Some(ref file) = self.filename {
            error = error.with_file(file.clone());
        }
        self.errors.push(error);
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn errors(&self) -> &[CompileError] {
        &self.errors
    }

    pub fn print_errors(&self) {
        for error in &self.errors {
            eprintln!("\x1b[31merror\x1b[0m: {}", error);
            if let Some(line) = self.source.lines().nth(error.span.line.saturating_sub(1)) {
                eprintln!("  \x1b[34m{}\x1b[0m | {}", error.span.line, line);
                let spaces = " ".repeat(error.span.line.to_string().len() + 3);
                let carets = "^".repeat(error.span.end.saturating_sub(error.span.start).max(1));
                eprintln!("{}  \x1b[32m{}\x1b[0m", spaces, carets);
            }
        }
    }
}
