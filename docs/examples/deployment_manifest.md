# Deployment Manifest Example

Use `Cell.toml` for deployment facts that must be visible to builders and
release gates.

```toml
[package]
name = "token"
version = "0.1.0"

[deploy.ckb]
hash_type = "data1"
out_point = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0"
dep_type = "code"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd:0"
dep_type = "dep_group"
hash_type = "type"
```

Validate the manifest through normal package commands and inspect metadata:

```bash
cellc info --json
cellc constraints examples/token.cell --target-profile ckb --json
```

The compiler rejects unknown `hash_type` and `dep_type` values.
