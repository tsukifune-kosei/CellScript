//! Pure source/runtime constants for exact Script handles.
//!
//! This module stays available to the wasm metadata compiler. Native receipt
//! construction lives in `script_handle`, which additionally depends on the
//! package, artifact-checker, and ProtocolBundle boundary.

pub const EXACT_SCRIPT_HANDLE_TYPE: &str = "ExactScriptHandle";
pub const EXACT_SCRIPT_HANDLE_ENCODING: &str = "CSHDLv1-fixed-202";
pub const EXACT_SCRIPT_HANDLE_BYTES: usize = 202;
pub const EXACT_SCRIPT_HANDLE_MAGIC: &[u8; 8] = b"CSHDLv1\0";

pub const EXACT_SCRIPT_HANDLE_CLASS_OFFSET: usize = 8;
pub const EXACT_SCRIPT_HANDLE_ROLE_OFFSET: usize = 9;
pub const EXACT_SCRIPT_HANDLE_RECEIPT_HASH_OFFSET: usize = 10;
pub const EXACT_SCRIPT_HANDLE_SCRIPT_HASH_OFFSET: usize = 42;
pub const EXACT_SCRIPT_HANDLE_INTERFACE_HASH_OFFSET: usize = 74;
pub const EXACT_SCRIPT_HANDLE_ARTIFACT_HASH_OFFSET: usize = 106;
pub const EXACT_SCRIPT_HANDLE_TARGET_PROFILE_HASH_OFFSET: usize = 138;
pub const EXACT_SCRIPT_HANDLE_RUNTIME_ABI_HASH_OFFSET: usize = 170;

pub const EXACT_SCRIPT_HANDLE_HASH_BYTES: usize = 32;
pub const EXACT_SCRIPT_HANDLE_CLASS_SCRIPT: u8 = 0;
pub const EXACT_SCRIPT_HANDLE_CLASS_VERIFIER: u8 = 1;
pub const EXACT_SCRIPT_HANDLE_ROLE_LOCK: u8 = 0;
pub const EXACT_SCRIPT_HANDLE_ROLE_TYPE: u8 = 1;
pub const EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER: u8 = 2;
