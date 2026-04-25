use cellscript::{compile, CompileOptions};

#[test]
fn adversarial_0_13_rejects_unsupported_generic_collection_surfaces() {
    let cases = [
        (
            "hashmap",
            r#"
module bad_hashmap

action main() -> u64 {
    let orders: HashMap<Hash, u64> = HashMap::new()
    return orders.len()
}
"#,
            "HashMap",
        ),
        (
            "cell_vec",
            r#"
module bad_cell_vec

resource Token has store {
    amount: u64,
}

action main() -> u64 {
    let cells: Vec<Cell<Token>> = Vec::new()
    return cells.len()
}
"#,
            "Cell",
        ),
        (
            "option_reserved",
            r#"
module bad_option

action main() -> Option<u64> {
    return Option::some(1)
}
"#,
            "Option",
        ),
    ];

    for (name, source, expected) in cases {
        let err = compile(source, CompileOptions::default()).expect_err(name);
        assert!(err.message.contains(expected), "{name} should mention {expected}; got {}", err.message);
    }
}

#[test]
fn adversarial_0_13_rejects_invalid_hash_type_dsl() {
    let err = compile(
        r#"
module bad_hash_type

resource Token
with_default_hash_type(Legacy)
{
    amount: u64,
}

action main(amount: u64) -> Token {
    create Token { amount: amount }
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .expect_err("invalid hash_type should be rejected");

    assert!(err.message.contains("unsupported CKB hash_type 'Legacy'"), "unexpected error: {}", err.message);
}
