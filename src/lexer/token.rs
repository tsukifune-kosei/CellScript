use crate::error::Span;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Module,     // module
    Use,        // use
    Resource,   // resource
    Shared,     // shared
    Receipt,    // receipt
    Struct,     // struct
    Const,      // const
    Enum,       // enum
    Action,     // action
    Fn,         // fn
    Lock,       // lock
    Has,        // has
    Store,      // store
    Transfer,   // transfer
    Destroy,    // destroy
    If,         // if
    Else,       // else
    For,        // for
    In,         // in
    While,      // while
    Match,      // match
    Return,     // return
    Let,        // let
    Mut,        // mut
    Ref,        // ref
    Consume,    // consume
    Create,     // create
    ReadRef,    // read_ref
    TransferKw, // transfer (keyword)
    DestroyKw,  // destroy (keyword)
    Claim,      // claim
    Settle,     // settle
    Launch,     // launch
    Assert,     // assert_invariant
    True,       // true
    False,      // false
    Self_,      // self
    Env,        // env

    Identifier(String),
    Integer(u64),
    HexLiteral(String),
    ByteString(Vec<u8>),
    String(String),

    U8,
    U16,
    U32,
    U64,
    U128,
    Bool,
    Address,
    Hash,

    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    LBracket,   // [
    RBracket,   // ]
    Pound,      // #
    Semi,       // ;
    Colon,      // :
    ColonColon, // ::
    Comma,      // ,
    Dot,        // .
    Arrow,      // ->
    FatArrow,   // =>
    Underscore, // _

    Plus,      // +
    Minus,     // -
    Star,      // *
    Slash,     // /
    Percent,   // %
    Eq,        // =
    EqEq,      // ==
    NotEq,     // !=
    Lt,        // <
    Le,        // <=
    Gt,        // >
    Ge,        // >=
    And,       // &&
    Or,        // ||
    Not,       // !
    Ampersand, // &
    Pipe,      // |

    Comment(String),
    Whitespace,
    Newline,

    Eof,
    Invalid(char),
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Module => write!(f, "'module'"),
            TokenKind::Use => write!(f, "'use'"),
            TokenKind::Resource => write!(f, "'resource'"),
            TokenKind::Shared => write!(f, "'shared'"),
            TokenKind::Receipt => write!(f, "'receipt'"),
            TokenKind::Struct => write!(f, "'struct'"),
            TokenKind::Const => write!(f, "'const'"),
            TokenKind::Enum => write!(f, "'enum'"),
            TokenKind::Action => write!(f, "'action'"),
            TokenKind::Fn => write!(f, "'fn'"),
            TokenKind::Lock => write!(f, "'lock'"),
            TokenKind::Has => write!(f, "'has'"),
            TokenKind::Store => write!(f, "'store'"),
            TokenKind::Transfer => write!(f, "'transfer'"),
            TokenKind::Destroy => write!(f, "'destroy'"),
            TokenKind::If => write!(f, "'if'"),
            TokenKind::Else => write!(f, "'else'"),
            TokenKind::For => write!(f, "'for'"),
            TokenKind::In => write!(f, "'in'"),
            TokenKind::While => write!(f, "'while'"),
            TokenKind::Match => write!(f, "'match'"),
            TokenKind::Return => write!(f, "'return'"),
            TokenKind::Let => write!(f, "'let'"),
            TokenKind::Mut => write!(f, "'mut'"),
            TokenKind::Ref => write!(f, "'ref'"),
            TokenKind::Consume => write!(f, "'consume'"),
            TokenKind::Create => write!(f, "'create'"),
            TokenKind::ReadRef => write!(f, "'read_ref'"),
            TokenKind::TransferKw => write!(f, "'transfer'"),
            TokenKind::DestroyKw => write!(f, "'destroy'"),
            TokenKind::Claim => write!(f, "'claim'"),
            TokenKind::Settle => write!(f, "'settle'"),
            TokenKind::Launch => write!(f, "'launch'"),
            TokenKind::Assert => write!(f, "'assert_invariant'"),
            TokenKind::True => write!(f, "'true'"),
            TokenKind::False => write!(f, "'false'"),
            TokenKind::Self_ => write!(f, "'self'"),
            TokenKind::Env => write!(f, "'env'"),
            TokenKind::Identifier(s) => write!(f, "identifier '{}'", s),
            TokenKind::Integer(n) => write!(f, "integer {}", n),
            TokenKind::HexLiteral(s) => write!(f, "hex literal {}", s),
            TokenKind::ByteString(_) => write!(f, "byte string"),
            TokenKind::String(s) => write!(f, "string {:?}", s),
            TokenKind::U8 => write!(f, "'u8'"),
            TokenKind::U16 => write!(f, "'u16'"),
            TokenKind::U32 => write!(f, "'u32'"),
            TokenKind::U64 => write!(f, "'u64'"),
            TokenKind::U128 => write!(f, "'u128'"),
            TokenKind::Bool => write!(f, "'bool'"),
            TokenKind::Address => write!(f, "'Address'"),
            TokenKind::Hash => write!(f, "'Hash'"),
            TokenKind::LParen => write!(f, "'('"),
            TokenKind::RParen => write!(f, "')'"),
            TokenKind::LBrace => write!(f, "'{{'"),
            TokenKind::RBrace => write!(f, "'}}'"),
            TokenKind::LBracket => write!(f, "'['"),
            TokenKind::RBracket => write!(f, "']'"),
            TokenKind::Pound => write!(f, "'#'"),
            TokenKind::Semi => write!(f, "';'"),
            TokenKind::Colon => write!(f, "':'"),
            TokenKind::ColonColon => write!(f, "'::'"),
            TokenKind::Comma => write!(f, "','"),
            TokenKind::Dot => write!(f, "'.'"),
            TokenKind::Arrow => write!(f, "'->'"),
            TokenKind::FatArrow => write!(f, "'=>'"),
            TokenKind::Underscore => write!(f, "'_'"),
            TokenKind::Plus => write!(f, "'+'"),
            TokenKind::Minus => write!(f, "'-'"),
            TokenKind::Star => write!(f, "'*'"),
            TokenKind::Slash => write!(f, "'/'"),
            TokenKind::Percent => write!(f, "'%'"),
            TokenKind::Eq => write!(f, "'='"),
            TokenKind::EqEq => write!(f, "'=='"),
            TokenKind::NotEq => write!(f, "'!='"),
            TokenKind::Lt => write!(f, "'<'"),
            TokenKind::Le => write!(f, "'<='"),
            TokenKind::Gt => write!(f, "'>'"),
            TokenKind::Ge => write!(f, "'>='"),
            TokenKind::And => write!(f, "'&&'"),
            TokenKind::Or => write!(f, "'||'"),
            TokenKind::Not => write!(f, "'!'"),
            TokenKind::Ampersand => write!(f, "'&'"),
            TokenKind::Pipe => write!(f, "'|'"),
            TokenKind::Comment(_) => write!(f, "comment"),
            TokenKind::Whitespace => write!(f, "whitespace"),
            TokenKind::Newline => write!(f, "newline"),
            TokenKind::Eof => write!(f, "end of file"),
            TokenKind::Invalid(c) => write!(f, "invalid character '{}'", c),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub text: String,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span, text: impl Into<String>) -> Self {
        Self { kind, span, text: text.into() }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {:?}", self.kind, self.span.line, self.text)
    }
}

pub fn keyword_or_identifier(text: &str) -> TokenKind {
    match text {
        "module" => TokenKind::Module,
        "use" => TokenKind::Use,
        "resource" => TokenKind::Resource,
        "shared" => TokenKind::Shared,
        "receipt" => TokenKind::Receipt,
        "struct" => TokenKind::Struct,
        "const" => TokenKind::Const,
        "enum" => TokenKind::Enum,
        "action" => TokenKind::Action,
        "fn" => TokenKind::Fn,
        "lock" => TokenKind::Lock,
        "has" => TokenKind::Has,
        "store" => TokenKind::Store,
        "transfer" => TokenKind::TransferKw,
        "destroy" => TokenKind::DestroyKw,
        "if" => TokenKind::If,
        "else" => TokenKind::Else,
        "for" => TokenKind::For,
        "in" => TokenKind::In,
        "while" => TokenKind::While,
        "match" => TokenKind::Match,
        "return" => TokenKind::Return,
        "let" => TokenKind::Let,
        "mut" => TokenKind::Mut,
        "ref" => TokenKind::Ref,
        "consume" => TokenKind::Consume,
        "create" => TokenKind::Create,
        "read_ref" => TokenKind::ReadRef,
        "claim" => TokenKind::Claim,
        "settle" => TokenKind::Settle,
        "launch" => TokenKind::Launch,
        "assert" | "assert_invariant" => TokenKind::Assert,
        "true" => TokenKind::True,
        "false" => TokenKind::False,
        "self" => TokenKind::Self_,
        "env" => TokenKind::Env,
        "u8" => TokenKind::U8,
        "u16" => TokenKind::U16,
        "u32" => TokenKind::U32,
        "u64" => TokenKind::U64,
        "u128" => TokenKind::U128,
        "bool" => TokenKind::Bool,
        "Address" => TokenKind::Address,
        "Hash" => TokenKind::Hash,
        _ => TokenKind::Identifier(text.to_string()),
    }
}
