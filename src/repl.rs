use crate::codegen::{self, CodegenOptions};
use crate::ir::generate;
use crate::lexer::lex;
use crate::parser::parse;
use crate::types::check;
use colored::Colorize;
use std::io::{self, Write};

pub struct Repl {
    history: Vec<String>,
    context: String,
    show_ir: bool,
    show_asm: bool,
}

impl Default for Repl {
    fn default() -> Self {
        Self::new()
    }
}

impl Repl {
    pub fn new() -> Self {
        Self { history: Vec::new(), context: String::new(), show_ir: false, show_asm: false }
    }

    pub fn run(&mut self) -> io::Result<()> {
        self.print_banner();

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        loop {
            print!("{} ", "cellc>".cyan().bold());
            stdout.flush()?;

            let mut input = String::new();
            stdin.read_line(&mut input)?;

            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            self.history.push(input.to_string());

            if input.starts_with(':') {
                if self.handle_command(input) {
                    break;
                }
                continue;
            }

            if let Err(e) = self.process_input(input) {
                eprintln!("{}: {}", "error".red(), e);
            }
        }

        Ok(())
    }

    fn print_banner(&self) {
        println!(
            "{}",
            r#"
   ____     _       _   _           _   
  / ___|__| | ___ | |_| |__   ___ | |_ 
 | |   / _` |/ _ \| __| '_ \ / _ \| __|
 | |__| (_| | (_) | |_| | | | (_) | |_ 
  \____\__,_|\___/ \__|_| |_|\___/ \__|
                                       
        CellScript Interactive Shell
              Version 0.1.0
"#
            .cyan()
        );
        println!("Type {} for help, {} to exit\n", ":help".yellow(), ":quit".yellow());
    }

    fn handle_command(&mut self, input: &str) -> bool {
        let parts: Vec<&str> = input.split_whitespace().collect();
        let cmd = parts[0];

        match cmd {
            ":quit" | ":q" => {
                println!("Goodbye!");
                true
            }
            ":help" | ":h" => {
                self.print_help();
                false
            }
            ":history" => {
                for (i, line) in self.history.iter().enumerate() {
                    println!("  {}: {}", i + 1, line);
                }
                false
            }
            ":clear" => {
                self.context.clear();
                println!("Context cleared.");
                false
            }
            ":show" => {
                if parts.len() > 1 {
                    match parts[1] {
                        "ir" => {
                            self.show_ir = !self.show_ir;
                            println!("Show IR: {}", if self.show_ir { "on" } else { "off" });
                        }
                        "asm" => {
                            self.show_asm = !self.show_asm;
                            println!("Show ASM: {}", if self.show_asm { "on" } else { "off" });
                        }
                        _ => println!("Unknown show option: {}", parts[1]),
                    }
                }
                false
            }
            ":lex" => {
                if parts.len() > 1 {
                    let code = parts[1..].join(" ");
                    self.show_tokens(&code);
                }
                false
            }
            ":parse" => {
                if parts.len() > 1 {
                    let code = parts[1..].join(" ");
                    self.show_ast(&code);
                }
                false
            }
            _ => {
                println!("Unknown command: {}. Type :help for help.", cmd);
                false
            }
        }
    }

    fn print_help(&self) {
        println!("{}", "Commands:".bold());
        println!("  {:15} - Exit the REPL", ":quit, :q".yellow());
        println!("  {:15} - Show this help message", ":help, :h".yellow());
        println!("  {:15} - Show input history", ":history".yellow());
        println!("  {:15} - Clear current context", ":clear".yellow());
        println!("  {:15} - Toggle IR display", ":show ir".yellow());
        println!("  {:15} - Toggle ASM display", ":show asm".yellow());
        println!("  {:15} - Tokenize code", ":lex <code>".yellow());
        println!("  {:15} - Parse code to AST", ":parse <code>".yellow());
        println!();
        println!("{}", "Example code:".bold());
        println!("  let x = 42");
        println!("  resource Token {{ amount: u64 }}");
        println!("  action mint() {{ create Token {{ amount: 100 }} }}");
    }

    fn process_input(&mut self, input: &str) -> Result<(), String> {
        let full_code = if self.context.is_empty() {
            format!("module repl\n{}", input)
        } else {
            format!("module repl\n{}\n{}", self.context, input)
        };

        let tokens = lex(&full_code).map_err(|e| format!("Lexer error: {}", e))?;

        let ast = parse(&tokens).map_err(|e| format!("Parser error: {}", e))?;

        check(&ast).map_err(|e| format!("Type error: {}", e))?;

        let ir = generate(&ast).map_err(|e| format!("IR generation error: {}", e))?;

        println!("{}", "✓".green().bold());

        if self.show_ir {
            println!("{}\n{:#?}", "Generated IR:".cyan().bold(), ir);
        }

        if self.show_asm {
            let asm_bytes = codegen::generate(&ir, &CodegenOptions::default(), crate::ArtifactFormat::RiscvAssembly)
                .map_err(|e| format!("Codegen error: {}", e))?;
            let asm = String::from_utf8(asm_bytes).map_err(|e| format!("Assembly output is not valid UTF-8: {}", e))?;
            println!("{}\n{}", "Generated ASM:".cyan().bold(), asm);
        }

        if !input.starts_with("action") && !input.starts_with("resource") {
            self.context.push_str(input);
            self.context.push('\n');
        }

        Ok(())
    }

    fn show_tokens(&self, code: &str) {
        let full_code = format!("module repl\n{}", code);
        match lex(&full_code) {
            Ok(tokens) => {
                println!("{}", "Tokens:".cyan().bold());
                for token in tokens {
                    if !matches!(
                        token.kind,
                        crate::lexer::token::TokenKind::Whitespace
                            | crate::lexer::token::TokenKind::Newline
                            | crate::lexer::token::TokenKind::Eof
                    ) {
                        println!("  {:?}", token);
                    }
                }
            }
            Err(e) => eprintln!("{}: {}", "Error".red(), e),
        }
    }

    fn show_ast(&self, code: &str) {
        let full_code = format!("module repl\n{}", code);
        match lex(&full_code) {
            Ok(tokens) => match parse(&tokens) {
                Ok(ast) => {
                    println!("{}", "AST:".cyan().bold());
                    println!("{:#?}", ast);
                }
                Err(e) => eprintln!("{}: {}", "Parse error".red(), e),
            },
            Err(e) => eprintln!("{}: {}", "Lexer error".red(), e),
        }
    }
}

pub fn run_repl() -> io::Result<()> {
    let mut repl = Repl::new();
    repl.run()
}
