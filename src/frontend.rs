//! Edition-routed source frontends.
//!
//! Edition 2026 remains frozen on the legacy lexer/parser path. Edition 2027
//! has its own entry point and authoring policy. Both frontends share the value,
//! declaration, and statement kernel, so an authoring improvement does not
//! discard existing language features. The older bounded native preview keeps
//! its own syntax checks. All routes produce structured AST, never intermediate
//! preview source text, before the shared typed semantic foundation.

use crate::ast;
use crate::edition::CellScriptEdition;
use crate::error::{CompileError, Result};
use crate::lexer;
use crate::parser;

mod authoring;
mod migrate;
mod next;

pub use migrate::{
    legacy_temporal_migration_diagnostics, migrate_legacy_temporal_source, migrate_source_to_2027, MigrationCandidate, MigrationKind,
    TemporalMigrationCandidate,
};

/// Tooling uses the same contextual surface selection as the parser. This
/// remains usable while a native container body is incomplete during editing.
pub(crate) fn uses_native_preview(source: &str) -> bool {
    lexer::lex(source).is_ok_and(|tokens| next::has_native_surface(&tokens))
}

pub fn parse(source: &str, edition: CellScriptEdition) -> Result<ast::Module> {
    match edition {
        CellScriptEdition::Edition2026 => legacy::parse(source),
        CellScriptEdition::Edition2027 => next::parse(source),
    }
}

pub fn parse_diagnostics(source: &str, edition: CellScriptEdition) -> std::result::Result<ast::Module, Vec<CompileError>> {
    match edition {
        CellScriptEdition::Edition2026 => legacy::parse_diagnostics(source),
        CellScriptEdition::Edition2027 => next::parse_diagnostics(source),
    }
}

mod legacy {
    use super::*;

    pub(super) fn parse(source: &str) -> Result<ast::Module> {
        let tokens = lexer::lex(source)?;
        parser::parse(&tokens)
    }

    pub(super) fn parse_diagnostics(source: &str) -> std::result::Result<ast::Module, Vec<CompileError>> {
        let tokens = lexer::lex(source).map_err(|error| vec![error])?;
        parser::parse_diagnostics(&tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Item;
    use crate::error::Span;

    #[test]
    fn legacy_and_next_frontends_are_independently_routed() {
        let implicit = "module demo\naction main(value: u64) -> u64 { verification return value }";
        assert!(parse(implicit, CellScriptEdition::Edition2026).is_ok());
        assert!(parse(implicit, CellScriptEdition::Edition2027).is_ok());

        let explicit = "module demo\naction main(witness value: u64) -> u64 { verification return value }";
        assert!(parse(explicit, CellScriptEdition::Edition2027).is_ok());

        let concise = "module demo\naction main(witness value: u64) -> u64 { return value }";
        assert!(parse(concise, CellScriptEdition::Edition2027).is_ok());
        assert!(parse(concise, CellScriptEdition::Edition2026).is_err());
    }

    #[test]
    fn authoring_frontend_keeps_legacy_lifecycle_and_source_entry_organization() {
        let consume = r#"
module demo
resource Token has consume { amount: u64 }
action main(input token: Token) { verification consume token }
"#;
        assert!(parse(consume, CellScriptEdition::Edition2026).is_ok());
        let module = parse(consume, CellScriptEdition::Edition2027).unwrap();
        let Item::Action(action) = module.items.last().unwrap() else { panic!("expected action") };
        assert!(matches!(action.body.as_slice(), [ast::Stmt::Expr(ast::Expr::Consume(_))]));
        assert!(action.next_surface.is_none(), "a legacy consume must not acquire a native disposition policy");

        let multiple = r#"
module demo
action first() { verification return }
action second() { verification return }
"#;
        assert_eq!(parse(multiple, CellScriptEdition::Edition2027).unwrap().items.len(), 2);

        let capability_only = r#"
module demo
resource Token has consume { amount: u64 }
action main(witness value: u64) -> u64 { verification return value }
"#;
        assert!(parse(capability_only, CellScriptEdition::Edition2027).is_ok());
    }

    #[test]
    fn diagnostic_frontend_keeps_source_spans() {
        let source = "module demo\naction main(value: ) { return }";
        let diagnostics = parse_diagnostics(source, CellScriptEdition::Edition2027).unwrap_err();
        assert_eq!(diagnostics.len(), 1);
        assert_ne!(diagnostics[0].span, Span::default());
    }

    #[test]
    fn native_container_words_remain_ordinary_authoring_names() {
        let source = r#"
module type_script
const lock_script: u64 = 3
fn type_script(value: u64) -> u64 { value + lock_script }
action main(value: u64) -> u64 { return type_script(value) }
"#;
        let module = parse(source, CellScriptEdition::Edition2027).unwrap();
        let formatted = crate::fmt::format_default(&module).unwrap();
        assert!(parse(&formatted, CellScriptEdition::Edition2026).is_ok());
        assert_eq!(crate::fmt::format_default(&parse(&formatted, CellScriptEdition::Edition2027).unwrap()).unwrap(), formatted);
    }

    #[test]
    fn authoring_lock_constraint_blocks_keep_the_legacy_verification_model() {
        let source = "module demo\nlock owner(witness value: u64) { require value > 0\n return true }";
        let module = parse(source, CellScriptEdition::Edition2027).unwrap();
        assert!(parse(source, CellScriptEdition::Edition2026).is_err());
        let Item::Lock(lock) = module.items.last().unwrap() else { panic!("expected lock") };
        assert!(matches!(lock.body[0], ast::Stmt::Expr(ast::Expr::Require(_))));
        assert!(lock.next_surface.is_none());
        let formatted = crate::fmt::format_default(&module).unwrap();
        assert!(formatted.contains("verification"));
        assert!(parse(&formatted, CellScriptEdition::Edition2026).is_ok());
    }

    #[test]
    fn next_frontend_parses_native_type_script_surface() {
        let source = r#"
module demo

resource Token has store, replace, relock {
    owner: Address,
    amount: u64,
}

type_script TokenTransfer on type_group<Token> {
    entry transfer(
        input token: Token from group_input[0],
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify {
            enforce token.amount > 0
        }

        effects {
            replace token -> next {
                data {
                    owner = same
                    amount = same
                }
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
        let module = parse(source, CellScriptEdition::Edition2027).unwrap();
        let Item::Action(action) = module.items.last().unwrap() else {
            panic!("expected native Edition 2027 entry to lower to an action");
        };
        let surface = action.next_surface.as_ref().expect("native surface marker");
        assert_eq!(surface.container_name, "TokenTransfer");
        assert_eq!(surface.trigger_type, "Token");
        assert_eq!(surface.verify.len(), 1);
        assert_eq!(surface.dispositions.len(), 1);
        assert_eq!(action.params.len(), 2);
        assert_eq!(action.outputs.len(), 1);

        let formatted = crate::fmt::format_default(&module).unwrap();
        assert!(formatted.contains("type_script TokenTransfer on type_group<Token>"));
        assert!(formatted.contains("replace token -> next"));
        let reparsed = parse(&formatted, CellScriptEdition::Edition2027).unwrap();
        assert_eq!(crate::fmt::format_default(&reparsed).unwrap(), formatted);

        assert!(parse(source, CellScriptEdition::Edition2026).is_err());
        let missing_field = source.replace("                    amount = same\n", "");
        assert!(parse(&missing_field, CellScriptEdition::Edition2027).unwrap_err().message.contains("exhaustively list fields"));
        let wrong_ordinal = source.replace("group_output[0]", "group_output[1]");
        assert!(parse(&wrong_ordinal, CellScriptEdition::Edition2027).unwrap_err().message.contains("non-canonical"));
        let mismatched_output = source
            .replace(
                "resource Token has",
                "resource Other has store, replace, relock { owner: Address, amount: u64 }\nresource Token has",
            )
            .replace("output next: Token", "output next: Other");
        assert!(parse(&mismatched_output, CellScriptEdition::Edition2027)
            .unwrap_err()
            .message
            .contains("input/output ports must all use"));
        let unhashed_lock = source.replace("lock_script = exact_hash(recipient)", "lock_script = recipient");
        assert!(parse(&unhashed_lock, CellScriptEdition::Edition2027).unwrap_err().message.contains("exact_hash"));
    }

    #[test]
    fn next_frontend_parses_fresh_retire_and_audit_surfaces_fail_closed() {
        let fresh = r#"
module demo
#[type_id("demo::Token:v1")]
resource Token has store, create, burn identity(ckb_type_id) { amount: u64 }
type_script TokenMint on type_group<Token> {
    entry mint(
        witness amount: u64 from group_witness.input_type,
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify { enforce amount > 0 }
        audit issuance_policy {
            expected_evidence = external_policy(recipient)
        }
        effects {
            fresh next {
                data { amount = amount }
                identity = ckb_type_id
                type_script = declared
                lock_script = exact_hash(recipient)
                capacity = builder_computed
                cardinality = one
            }
        }
    }
}
"#;
        let module = parse(fresh, CellScriptEdition::Edition2027).unwrap();
        let Item::Action(action) = module.items.last().unwrap() else {
            panic!("expected native fresh entry to lower to an action");
        };
        let surface = action.next_surface.as_ref().expect("native surface marker");
        assert_eq!(surface.audits.len(), 1);
        assert!(matches!(surface.dispositions.as_slice(), [crate::ast::NextDisposition::Fresh(_)]));
        let formatted = crate::fmt::format_default(&module).unwrap();
        assert!(formatted.contains("audit issuance_policy"));
        assert!(formatted.contains("fresh next"));
        assert_eq!(crate::fmt::format_default(&parse(&formatted, CellScriptEdition::Edition2027).unwrap()).unwrap(), formatted);

        let duplicate_audit = fresh.replace(
            "        effects {",
            "        audit issuance_policy { expected_evidence = external_policy(amount) }\n        effects {",
        );
        assert!(parse(&duplicate_audit, CellScriptEdition::Edition2027).unwrap_err().message.contains("duplicate audit declaration"));
        let missing_field = fresh.replace("                data { amount = amount }", "                data { }");
        assert!(parse(&missing_field, CellScriptEdition::Edition2027).unwrap_err().message.contains("exhaustively list fields"));

        let retire = r#"
module demo
resource Note has store, consume, burn identity(field(note_id)) { note_id: u64, amount: u64 }
type_script NoteRetirement on type_group<Note> {
    entry retire_note(input note: Note from group_input[0]) {
        verify { enforce note.amount == 0 }
        effects {
            retire note {
                absence = field(note_id)
                data = discarded
                lock_script = none
                type_script = absent
                capacity = released
                cardinality = one
            }
        }
    }
}
"#;
        let module = parse(retire, CellScriptEdition::Edition2027).unwrap();
        let Item::Action(action) = module.items.last().unwrap() else {
            panic!("expected native retirement entry to lower to an action");
        };
        assert!(matches!(action.next_surface.as_ref().unwrap().dispositions.as_slice(), [crate::ast::NextDisposition::Retire(_)]));
        let missing_capacity = retire.replace("                capacity = released\n", "");
        assert!(parse(&missing_capacity, CellScriptEdition::Edition2027).is_err());

        let reordered_outputs = r#"
module demo
resource Token has store, create { amount: u64 }
type_script TokenMint on type_group<Token> {
    entry mint(
        witness amount: u64 from group_witness.input_type,
        witness recipient: Address from group_witness.input_type,
        output first: Token from group_output[0],
        output second: Token from group_output[1],
    ) {
        verify { }
        effects {
            fresh second {
                data { amount = amount }
                identity = none
                type_script = declared
                lock_script = exact_hash(recipient)
                capacity = builder_computed
                cardinality = one
            }
            fresh first {
                data { amount = amount }
                identity = none
                type_script = declared
                lock_script = exact_hash(recipient)
                capacity = builder_computed
                cardinality = one
            }
        }
    }
}
"#;
        assert!(parse(reordered_outputs, CellScriptEdition::Edition2027).unwrap_err().message.contains("declared group_output order"));
    }

    #[test]
    fn next_frontend_parses_checked_pool_surface_fail_closed() {
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
        effects {
            pool value_flow {
                inputs { left, right }
                outputs { merged }
                data {
                    owner { merged = recipient }
                    amount = conserve
                }
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
        let module = parse(source, CellScriptEdition::Edition2027).unwrap();
        let Item::Action(action) = module.items.last().unwrap() else {
            panic!("expected native pool entry to lower to an action");
        };
        assert!(matches!(action.next_surface.as_ref().unwrap().dispositions.as_slice(), [crate::ast::NextDisposition::Pool(_)]));
        let formatted = crate::fmt::format_default(&module).unwrap();
        assert!(formatted.contains("pool value_flow"));
        assert!(formatted.contains("amount = conserve"));
        assert_eq!(crate::fmt::format_default(&parse(&formatted, CellScriptEdition::Edition2027).unwrap()).unwrap(), formatted);

        let no_conservation =
            source.replace("                    amount = conserve", "                    amount { merged = merged.amount }");
        assert!(parse(&no_conservation, CellScriptEdition::Edition2027).unwrap_err().message.contains("at least one numeric field"));
        let missing_lock =
            source.replace("                lock_script { merged = exact_hash(recipient) }", "                lock_script { }");
        assert!(parse(&missing_lock, CellScriptEdition::Edition2027).unwrap_err().message.contains("assign every pool output"));
        let reused_input = source.replace("inputs { left, right }", "inputs { left, left }");
        assert!(parse(&reused_input, CellScriptEdition::Edition2027).unwrap_err().message.contains("exactly one disposition"));
    }

    #[test]
    fn next_frontend_parses_native_lock_script_surface() {
        let source = r#"
module demo

resource Vault has store {
    owner: Address,
}

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
        let module = parse(source, CellScriptEdition::Edition2027).unwrap();
        let Item::Lock(lock) = module.items.last().unwrap() else {
            panic!("expected native Edition 2027 entry to lower to a lock");
        };
        let surface = lock.next_surface.as_ref().expect("native lock surface marker");
        assert_eq!(surface.container_name, "VaultOwner");
        assert_eq!(surface.verify.len(), 2);
        assert_eq!(lock.params.len(), 3);

        let formatted = crate::fmt::format_default(&module).unwrap();
        assert!(formatted.contains("lock_script VaultOwner on lock_group"));
        assert!(formatted.contains("protected vault: Vault from group_input[0]"));
        assert!(formatted.contains("lock_args owner: Address from current_script.args"));
        let reparsed = parse(&formatted, CellScriptEdition::Edition2027).unwrap();
        assert_eq!(crate::fmt::format_default(&reparsed).unwrap(), formatted);

        assert!(parse(source, CellScriptEdition::Edition2026).is_err());
        let wrong_ordinal = source.replace("group_input[0]", "group_input[1]");
        assert!(parse(&wrong_ordinal, CellScriptEdition::Edition2027).unwrap_err().message.contains("non-canonical"));
        let no_protected = source.replace("        protected vault: Vault from group_input[0],\n", "");
        assert!(parse(&no_protected, CellScriptEdition::Edition2027).unwrap_err().message.contains("exactly one protected"));
    }
}
