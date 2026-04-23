pub mod token;

use crate::error::{CompileError, Result, Span};
use token::{keyword_or_identifier, Token, TokenKind};

pub struct Lexer<'a> {
    input: &'a str,
    chars: std::str::Chars<'a>,
    position: usize,
    line: usize,
    column: usize,
    current: Option<char>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        let mut chars = input.chars();
        let current = chars.next();
        Self { input, chars, position: 0, line: 1, column: 1, current }
    }

    fn advance(&mut self) -> Option<char> {
        if let Some(c) = self.current {
            self.position += c.len_utf8();
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        self.current = self.chars.next();
        self.current
    }

    fn peek(&self) -> Option<char> {
        self.current
    }

    fn peek_next(&self) -> Option<char> {
        self.input[self.position..].chars().nth(1)
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() && c != '\n' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) {
        if self.peek() == Some('/') && self.peek_next() == Some('/') {
            while let Some(c) = self.peek() {
                if c == '\n' {
                    break;
                }
                self.advance();
            }
        } else if self.peek() == Some('/') && self.peek_next() == Some('*') {
            self.advance(); // /
            self.advance(); // *
            let mut depth = 1;
            while depth > 0 {
                match (self.peek(), self.peek_next()) {
                    (Some('/'), Some('*')) => {
                        self.advance();
                        self.advance();
                        depth += 1;
                    }
                    (Some('*'), Some('/')) => {
                        self.advance();
                        self.advance();
                        depth -= 1;
                    }
                    (Some(_), _) => {
                        self.advance();
                    }
                    (None, _) => break,
                }
            }
        }
    }

    fn read_identifier(&mut self) -> Token {
        let start = self.position;
        let start_line = self.line;
        let start_col = self.column;

        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' {
                self.advance();
            } else {
                break;
            }
        }

        let text = &self.input[start..self.position];
        let kind = keyword_or_identifier(text);
        let span = Span::new(start, self.position, start_line, start_col);

        Token::new(kind, span, text)
    }

    fn read_number(&mut self) -> Result<Token> {
        let start = self.position;
        let start_line = self.line;
        let start_col = self.column;

        if self.peek() == Some('0') && self.peek_next() == Some('x') {
            self.advance(); // 0
            self.advance(); // x
            let hex_start = self.position;
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    self.advance();
                } else {
                    break;
                }
            }
            let text = &self.input[hex_start..self.position];
            let span = Span::new(start, self.position, start_line, start_col);
            return Ok(Token::new(TokenKind::HexLiteral(text.to_string()), span, &self.input[start..self.position]));
        }

        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }

        let text = &self.input[start..self.position];
        let value = text.parse::<u64>().map_err(|_| {
            CompileError::new(format!("invalid integer literal: {}", text), Span::new(start, self.position, start_line, start_col))
        })?;

        let span = Span::new(start, self.position, start_line, start_col);
        Ok(Token::new(TokenKind::Integer(value), span, text))
    }

    fn read_string(&mut self) -> Result<Token> {
        let start = self.position;
        let start_line = self.line;
        let start_col = self.column;

        let quote = self.peek().unwrap();
        self.advance();

        let mut content = String::new();
        while let Some(c) = self.peek() {
            if c == quote {
                self.advance();
                break;
            } else if c == '\\' {
                self.advance();
                match self.peek() {
                    Some('n') => {
                        content.push('\n');
                        self.advance();
                    }
                    Some('t') => {
                        content.push('\t');
                        self.advance();
                    }
                    Some('r') => {
                        content.push('\r');
                        self.advance();
                    }
                    Some('\\') => {
                        content.push('\\');
                        self.advance();
                    }
                    Some('"') => {
                        content.push('"');
                        self.advance();
                    }
                    Some('0') => {
                        content.push('\0');
                        self.advance();
                    }
                    Some(c) => {
                        return Err(CompileError::new(
                            format!("unknown escape sequence: \\{}", c),
                            Span::new(self.position, self.position + 1, self.line, self.column),
                        ));
                    }
                    None => break,
                }
            } else {
                content.push(c);
                self.advance();
            }
        }

        let span = Span::new(start, self.position, start_line, start_col);
        Ok(Token::new(TokenKind::String(content), span, &self.input[start..self.position]))
    }

    fn read_byte_string(&mut self) -> Result<Token> {
        let start = self.position;
        let start_line = self.line;
        let start_col = self.column;

        self.advance(); // b
        self.advance(); // "

        let mut bytes = Vec::new();
        while let Some(c) = self.peek() {
            if c == '"' {
                self.advance();
                break;
            } else if c == '\\' {
                self.advance();
                match self.peek() {
                    Some('n') => {
                        bytes.push(b'\n');
                        self.advance();
                    }
                    Some('t') => {
                        bytes.push(b'\t');
                        self.advance();
                    }
                    Some('r') => {
                        bytes.push(b'\r');
                        self.advance();
                    }
                    Some('\\') => {
                        bytes.push(b'\\');
                        self.advance();
                    }
                    Some('"') => {
                        bytes.push(b'"');
                        self.advance();
                    }
                    Some('0') => {
                        bytes.push(0);
                        self.advance();
                    }
                    Some('x') => {
                        self.advance();
                        let hi = self.peek().ok_or_else(|| {
                            CompileError::new(
                                "incomplete hex escape in byte string",
                                Span::new(self.position, self.position, self.line, self.column),
                            )
                        })?;
                        if !hi.is_ascii_hexdigit() {
                            return Err(CompileError::new(
                                format!("invalid hex escape in byte string: \\x{}", hi),
                                Span::new(self.position, self.position + 1, self.line, self.column),
                            ));
                        }
                        self.advance();

                        let lo = self.peek().ok_or_else(|| {
                            CompileError::new(
                                "incomplete hex escape in byte string",
                                Span::new(self.position, self.position, self.line, self.column),
                            )
                        })?;
                        if !lo.is_ascii_hexdigit() {
                            return Err(CompileError::new(
                                format!("invalid hex escape in byte string: \\x{}{}", hi, lo),
                                Span::new(self.position, self.position + 1, self.line, self.column),
                            ));
                        }
                        self.advance();

                        let hex = &self.input[self.position - 2..self.position];
                        let val = u8::from_str_radix(hex, 16).map_err(|_| {
                            CompileError::new(
                                format!("invalid hex escape in byte string: \\x{}", hex),
                                Span::new(self.position - 2, self.position, self.line, self.column),
                            )
                        })?;
                        bytes.push(val);
                    }
                    Some(c) => {
                        return Err(CompileError::new(
                            format!("unknown escape sequence in byte string: \\{}", c),
                            Span::new(self.position, self.position + 1, self.line, self.column),
                        ));
                    }
                    None => break,
                }
            } else if c.is_ascii() {
                bytes.push(c as u8);
                self.advance();
            } else {
                return Err(CompileError::new(
                    "non-ASCII character in byte string",
                    Span::new(self.position, self.position + 1, self.line, self.column),
                ));
            }
        }

        let span = Span::new(start, self.position, start_line, start_col);
        Ok(Token::new(TokenKind::ByteString(bytes), span, &self.input[start..self.position]))
    }

    pub fn next_token(&mut self) -> Result<Token> {
        loop {
            self.skip_whitespace();
            if self.peek() == Some('/') && (self.peek_next() == Some('/') || self.peek_next() == Some('*')) {
                self.skip_comment();
            } else {
                break;
            }
        }

        let start = self.position;
        let start_line = self.line;
        let start_col = self.column;

        let c = match self.peek() {
            Some(c) => c,
            None => {
                return Ok(Token::new(TokenKind::Eof, Span::new(start, start, start_line, start_col), ""));
            }
        };

        if c == '\n' {
            self.advance();
            return Ok(Token::new(TokenKind::Newline, Span::new(start, self.position, start_line, start_col), "\n"));
        }

        if c == 'b' && self.peek_next() == Some('"') {
            return self.read_byte_string();
        }

        if c.is_alphabetic() || c == '_' {
            return Ok(self.read_identifier());
        }

        if c.is_ascii_digit() {
            return self.read_number();
        }

        if c == '"' || c == '\'' {
            return self.read_string();
        }

        self.advance();
        let span = Span::new(start, self.position, start_line, start_col);

        match c {
            '(' => Ok(Token::new(TokenKind::LParen, span, "(")),
            ')' => Ok(Token::new(TokenKind::RParen, span, ")")),
            '{' => Ok(Token::new(TokenKind::LBrace, span, "{")),
            '}' => Ok(Token::new(TokenKind::RBrace, span, "}")),
            '[' => Ok(Token::new(TokenKind::LBracket, span, "[")),
            ']' => Ok(Token::new(TokenKind::RBracket, span, "]")),
            '#' => Ok(Token::new(TokenKind::Pound, span, "#")),
            ',' => Ok(Token::new(TokenKind::Comma, span, ",")),
            ';' => Ok(Token::new(TokenKind::Semi, span, ";")),
            '_' => Ok(Token::new(TokenKind::Underscore, span, "_")),

            '+' => Ok(Token::new(TokenKind::Plus, span, "+")),
            '-' => {
                if self.peek() == Some('>') {
                    self.advance();
                    Ok(Token::new(TokenKind::Arrow, span.combine(&Span::new(start, self.position, start_line, start_col)), "->"))
                } else {
                    Ok(Token::new(TokenKind::Minus, span, "-"))
                }
            }
            '*' => Ok(Token::new(TokenKind::Star, span, "*")),
            '/' => Ok(Token::new(TokenKind::Slash, span, "/")),
            '%' => Ok(Token::new(TokenKind::Percent, span, "%")),

            '&' => {
                if self.peek() == Some('&') {
                    self.advance();
                    Ok(Token::new(TokenKind::And, span.combine(&Span::new(start, self.position, start_line, start_col)), "&&"))
                } else {
                    Ok(Token::new(TokenKind::Ampersand, span, "&"))
                }
            }
            '|' => {
                if self.peek() == Some('|') {
                    self.advance();
                    Ok(Token::new(TokenKind::Or, span.combine(&Span::new(start, self.position, start_line, start_col)), "||"))
                } else {
                    Ok(Token::new(TokenKind::Pipe, span, "|"))
                }
            }
            '!' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::new(TokenKind::NotEq, span.combine(&Span::new(start, self.position, start_line, start_col)), "!="))
                } else {
                    Ok(Token::new(TokenKind::Not, span, "!"))
                }
            }

            '=' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::new(TokenKind::EqEq, span.combine(&Span::new(start, self.position, start_line, start_col)), "=="))
                } else if self.peek() == Some('>') {
                    self.advance();
                    Ok(Token::new(TokenKind::FatArrow, span.combine(&Span::new(start, self.position, start_line, start_col)), "=>"))
                } else {
                    Ok(Token::new(TokenKind::Eq, span, "="))
                }
            }
            '<' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::new(TokenKind::Le, span.combine(&Span::new(start, self.position, start_line, start_col)), "<="))
                } else {
                    Ok(Token::new(TokenKind::Lt, span, "<"))
                }
            }
            '>' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::new(TokenKind::Ge, span.combine(&Span::new(start, self.position, start_line, start_col)), ">="))
                } else {
                    Ok(Token::new(TokenKind::Gt, span, ">"))
                }
            }

            ':' => {
                if self.peek() == Some(':') {
                    self.advance();
                    Ok(Token::new(TokenKind::ColonColon, span.combine(&Span::new(start, self.position, start_line, start_col)), "::"))
                } else {
                    Ok(Token::new(TokenKind::Colon, span, ":"))
                }
            }
            '.' => Ok(Token::new(TokenKind::Dot, span, ".")),

            _ => Ok(Token::new(TokenKind::Invalid(c), span, c.to_string())),
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        loop {
            let token = self.next_token()?;
            if token.kind == TokenKind::Eof {
                tokens.push(token);
                break;
            }
            tokens.push(token);
        }
        Ok(tokens)
    }
}

pub fn lex(input: &str) -> Result<Vec<Token>> {
    Lexer::new(input).tokenize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keywords() {
        let input = "module resource action consume create launch";
        let tokens = lex(input).unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Module);
        assert_eq!(tokens[1].kind, TokenKind::Resource);
        assert_eq!(tokens[2].kind, TokenKind::Action);
        assert_eq!(tokens[3].kind, TokenKind::Consume);
        assert_eq!(tokens[4].kind, TokenKind::Create);
        assert_eq!(tokens[5].kind, TokenKind::Launch);
    }

    #[test]
    fn test_identifiers() {
        let input = "foo bar_baz MyType";
        let tokens = lex(input).unwrap();
        assert!(matches!(tokens[0].kind, TokenKind::Identifier(ref s) if s == "foo"));
        assert!(matches!(tokens[1].kind, TokenKind::Identifier(ref s) if s == "bar_baz"));
        assert!(matches!(tokens[2].kind, TokenKind::Identifier(ref s) if s == "MyType"));
    }

    #[test]
    fn test_numbers() {
        let input = "42 0xFF 100_000";
        let tokens = lex(input).unwrap();
        assert!(matches!(tokens[0].kind, TokenKind::Integer(42)));
        assert!(matches!(tokens[1].kind, TokenKind::HexLiteral(ref s) if s == "FF"));
    }

    #[test]
    fn test_operators() {
        let input = "+ - * / == != <= >= && ||";
        let tokens = lex(input).unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Plus);
        assert_eq!(tokens[1].kind, TokenKind::Minus);
        assert_eq!(tokens[2].kind, TokenKind::Star);
        assert_eq!(tokens[3].kind, TokenKind::Slash);
        assert_eq!(tokens[4].kind, TokenKind::EqEq);
        assert_eq!(tokens[5].kind, TokenKind::NotEq);
        assert_eq!(tokens[6].kind, TokenKind::Le);
        assert_eq!(tokens[7].kind, TokenKind::Ge);
        assert_eq!(tokens[8].kind, TokenKind::And);
        assert_eq!(tokens[9].kind, TokenKind::Or);
    }

    #[test]
    fn test_punctuation() {
        let input = "() {} [] :: -> =>";
        let tokens = lex(input).unwrap();
        assert_eq!(tokens[0].kind, TokenKind::LParen);
        assert_eq!(tokens[1].kind, TokenKind::RParen);
        assert_eq!(tokens[2].kind, TokenKind::LBrace);
        assert_eq!(tokens[3].kind, TokenKind::RBrace);
        assert_eq!(tokens[4].kind, TokenKind::LBracket);
        assert_eq!(tokens[5].kind, TokenKind::RBracket);
        assert_eq!(tokens[6].kind, TokenKind::ColonColon);
        assert_eq!(tokens[7].kind, TokenKind::Arrow);
        assert_eq!(tokens[8].kind, TokenKind::FatArrow);
    }

    #[test]
    fn test_string() {
        let input = r#""hello world" "escaped \"quote\"""#;
        let tokens = lex(input).unwrap();
        assert!(matches!(tokens[0].kind, TokenKind::String(ref s) if s == "hello world"));
        assert!(matches!(tokens[1].kind, TokenKind::String(ref s) if s == "escaped \"quote\""));
    }

    #[test]
    fn test_byte_string() {
        let input = r#"b"hello" b"\x00\xFF""#;
        let tokens = lex(input).unwrap();
        assert!(matches!(tokens[0].kind, TokenKind::ByteString(ref b) if b == b"hello"));
    }

    #[test]
    fn test_comment() {
        let input = "foo // this is a comment\nbar /* block */ baz";
        let tokens = lex(input).unwrap();
        let semantic_tokens: Vec<_> =
            tokens.into_iter().filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof)).collect();
        assert!(matches!(semantic_tokens[0].kind, TokenKind::Identifier(ref s) if s == "foo"));
        assert!(matches!(semantic_tokens[1].kind, TokenKind::Identifier(ref s) if s == "bar"));
        assert!(matches!(semantic_tokens[2].kind, TokenKind::Identifier(ref s) if s == "baz"));
    }
}
