use cellscript::{compile, CompileOptions};

#[test]
fn v0_14_exposes_spawn_ipc_source_witness_time_capacity_metadata() {
    let source = r#"
module cellscript::v0_14_surface

resource Token has store {
    amount: u64,
}

resource Wallet has store {
    owner: Address,
}

struct Proof {
    pubkey: Hash,
    signature: Hash,
}

action delegate_verify(proof: Proof) -> u64 {
    let pid = spawn("secp256k1_verifier")
    let status = wait()
    assert_invariant(status == 0, "delegate failed")
    return pid
}

action pipe_pipeline(value: u64) -> u64 {
    let fds = pipe()
    let read_fd = fds.0
    let write_fd = fds.1
    pipe_write(write_fd, value)
    let echoed = pipe_read(read_fd)
    close(read_fd)
    close(write_fd)
    return echoed
}

action capacity_and_time(amount: u64) -> Token {
    require_maturity(100)
    require_time(1714000000)
    require_epoch_relative(10, 0, 1)
    let floor = occupied_capacity("Token")
    assert_invariant(floor >= 0, "capacity floor visible")
    create Token { amount }
}

lock owner_lock(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    let view = source::group_input(0)
    let sig = witness::lock(view)
    let digest = env::sighash_all(view)
    require sig == digest
}
"#;

    let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
    let features = &result.metadata.runtime.ckb_runtime_features;
    for expected in [
        "ckb-spawn-ipc",
        "ckb-source-view",
        "ckb-witness-args",
        "ckb-sighash-all",
        "ckb-declarative-since",
        "ckb-declarative-capacity",
    ] {
        assert!(features.iter().any(|feature| feature == expected), "missing {expected}: {features:?}");
    }

    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "witness-lock" && access.syscall == "LOAD_WITNESS_ARGS_LOCK" && access.source == "GroupInput"
    }));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| access.operation == "spawn"));
    assert_eq!(result.metadata.target_profile.spawn_ipc_abi, "ckb-vm-v2-spawn-ipc-syscalls-2601-2608");
    assert_eq!(result.metadata.target_profile.source_encoding, "ckb-source-group-high-bit");
}

#[test]
fn v0_14_rejects_unavailable_dynamic_blake2b() {
    let err = compile(
        r#"
module cellscript::bad_blake2b

action bad(input: Hash) -> Hash {
    return hash_blake2b(input)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();

    assert!(err.message.contains("hash_blake2b is not available"), "unexpected error: {}", err.message);
}
