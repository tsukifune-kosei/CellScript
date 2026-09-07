/// Stable runtime verifier error codes emitted by generated CellScript artifacts.
///
/// These codes are part of the debugging and release-reporting surface. They are
/// intentionally stable: the same generated verifier condition should return
/// the same numeric code across releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum CellScriptRuntimeError {
    SyscallFailed = 1,
    BoundsCheckFailed = 2,
    CellLoadFailed = 3,
    ExactSizeMismatch = 4,
    AssertionFailed = 5,
    FlowTransitionMismatch = 7,
    FlowNewStateInvalid = 8,
    FlowOldStateInvalid = 9,
    EntryWitnessMagicMismatch = 10,
    TypeHashPreservationMismatch = 11,
    LockHashPreservationMismatch = 12,
    FieldPreservationMismatch = 13,
    MutateTransitionMismatch = 14,
    DataPreservationMismatch = 15,
    DynamicFieldBoundsInvalid = 16,
    TypeHashMismatch = 17,
    FixedByteComparisonUnresolved = 18,
    NumericOrDiscriminantInvalid = 20,
    CollectionBoundsInvalid = 21,
    ConsumeInvalidOperand = 22,
    DestroyInvalidOperand = 23,
    CollectionRuntimeUnsupported = 24,
    EntryWitnessAbiInvalid = 25,
    CapacityPreservationMismatch = 26,
    DynamicFieldValueMismatch = 32,
    OutPointMismatch = 33,
    ScriptFieldMalformed = 34,
    DaoHeaderLineageMismatch = 35,
    DaoMaturityViolation = 36,
    CkbSinceMalformed = 37,
    ScriptArgsMismatch = 38,
    MetaPointMismatch = 39,
    MetaPointCardinalityMismatch = 40,
    ScriptIdentityMismatch = 41,
    WitnessMalformed = 42,
    WitnessFieldTruncated = 43,
    CkbSourceViewInvalid = 44,
    HeaderDepMissing = 45,
    DaoFieldMalformed = 46,
    ScriptRoleMismatch = 47,
    XudtBindingMismatch = 48,
    AggregateAmountMismatch = 49,
    Bip340PipeCreateFailed = 50,
    Bip340SpawnFailed = 51,
    Bip340MessageWriteFailed = 52,
    Bip340PubkeyWriteFailed = 53,
    Bip340SignatureWriteFailed = 54,
    Bip340VerifierReadFailed = 55,
    Bip340ChildRejected = 56,
    FixedU64LeInputUnresolved = 57,
    FixedByteComparisonMaterializationUnresolved = 58,
    Bip340MessageMaterializationUnresolved = 59,
    Bip340PubkeyMaterializationUnresolved = 60,
    Bip340SignatureMaterializationUnresolved = 61,
    PackedHashPreimageMaterializationUnresolved = 62,
    BoundedCellDepNotFound = 63,
    MerkleRootMismatch = 64,
    ShiftAmountInvalid = 65,
    SighashAllUnsupported = 66,
}

impl CellScriptRuntimeError {
    pub const fn code(self) -> u64 {
        self as u64
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SyscallFailed => "syscall-failed",
            Self::BoundsCheckFailed => "bounds-check-failed",
            Self::CellLoadFailed => "cell-load-failed",
            Self::ExactSizeMismatch => "exact-size-mismatch",
            Self::AssertionFailed => "assertion-failed",
            Self::FlowTransitionMismatch => "flow-transition-mismatch",
            Self::FlowNewStateInvalid => "flow-new-state-invalid",
            Self::FlowOldStateInvalid => "flow-old-state-invalid",
            Self::EntryWitnessMagicMismatch => "entry-witness-magic-mismatch",
            Self::TypeHashPreservationMismatch => "type-hash-preservation-mismatch",
            Self::LockHashPreservationMismatch => "lock-hash-preservation-mismatch",
            Self::FieldPreservationMismatch => "field-preservation-mismatch",
            Self::MutateTransitionMismatch => "mutate-transition-mismatch",
            Self::DataPreservationMismatch => "data-preservation-mismatch",
            Self::DynamicFieldBoundsInvalid => "dynamic-field-bounds-invalid",
            Self::TypeHashMismatch => "type-hash-mismatch",
            Self::FixedByteComparisonUnresolved => "fixed-byte-comparison-unresolved",
            Self::NumericOrDiscriminantInvalid => "numeric-or-discriminant-invalid",
            Self::CollectionBoundsInvalid => "collection-bounds-invalid",
            Self::ConsumeInvalidOperand => "consume-invalid-operand",
            Self::DestroyInvalidOperand => "destroy-invalid-operand",
            Self::CollectionRuntimeUnsupported => "collection-runtime-unsupported",
            Self::EntryWitnessAbiInvalid => "entry-witness-abi-invalid",
            Self::CapacityPreservationMismatch => "capacity-preservation-mismatch",
            Self::DynamicFieldValueMismatch => "dynamic-field-value-mismatch",
            Self::OutPointMismatch => "out-point-mismatch",
            Self::ScriptFieldMalformed => "script-field-malformed",
            Self::DaoHeaderLineageMismatch => "dao-header-lineage-mismatch",
            Self::DaoMaturityViolation => "dao-maturity-violation",
            Self::CkbSinceMalformed => "ckb-since-malformed",
            Self::ScriptArgsMismatch => "script-args-mismatch",
            Self::MetaPointMismatch => "metapoint-mismatch",
            Self::MetaPointCardinalityMismatch => "metapoint-cardinality-mismatch",
            Self::ScriptIdentityMismatch => "script-identity-mismatch",
            Self::WitnessMalformed => "witness-malformed",
            Self::WitnessFieldTruncated => "witness-field-truncated",
            Self::CkbSourceViewInvalid => "ckb-source-view-invalid",
            Self::HeaderDepMissing => "header-dep-missing",
            Self::DaoFieldMalformed => "dao-field-malformed",
            Self::ScriptRoleMismatch => "script-role-mismatch",
            Self::XudtBindingMismatch => "xudt-binding-mismatch",
            Self::AggregateAmountMismatch => "aggregate-amount-mismatch",
            Self::Bip340PipeCreateFailed => "bip340-pipe-create-failed",
            Self::Bip340SpawnFailed => "bip340-spawn-failed",
            Self::Bip340MessageWriteFailed => "bip340-message-write-failed",
            Self::Bip340PubkeyWriteFailed => "bip340-pubkey-write-failed",
            Self::Bip340SignatureWriteFailed => "bip340-signature-write-failed",
            Self::Bip340VerifierReadFailed => "bip340-verifier-read-failed",
            Self::Bip340ChildRejected => "bip340-child-rejected",
            Self::FixedU64LeInputUnresolved => "fixed-u64-le-input-unresolved",
            Self::FixedByteComparisonMaterializationUnresolved => "fixed-byte-comparison-materialization-unresolved",
            Self::Bip340MessageMaterializationUnresolved => "bip340-message-materialization-unresolved",
            Self::Bip340PubkeyMaterializationUnresolved => "bip340-pubkey-materialization-unresolved",
            Self::Bip340SignatureMaterializationUnresolved => "bip340-signature-materialization-unresolved",
            Self::PackedHashPreimageMaterializationUnresolved => "packed-hash-preimage-materialization-unresolved",
            Self::BoundedCellDepNotFound => "bounded-cell-dep-not-found",
            Self::MerkleRootMismatch => "merkle-root-mismatch",
            Self::ShiftAmountInvalid => "shift-amount-invalid",
            Self::SighashAllUnsupported => "sighash-all-unsupported",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::SyscallFailed => "A target VM syscall returned a non-zero status while loading transaction context.",
            Self::BoundsCheckFailed => "Loaded bytes were smaller than the verifier-required minimum.",
            Self::CellLoadFailed => "Cell data or field loading failed or returned an unusable result.",
            Self::ExactSizeMismatch => "Loaded bytes did not match the exact fixed-size schema requirement.",
            Self::AssertionFailed => "A source-level assert or invariant check evaluated to false.",
            Self::FlowTransitionMismatch => "A flow transition did not match the declared transition rule.",
            Self::FlowNewStateInvalid => "A created or proposed output state value was outside the declared state range.",
            Self::FlowOldStateInvalid => "A consumed state value was outside the declared state range.",
            Self::EntryWitnessMagicMismatch => "Entry witness bytes did not start with the CellScript witness ABI magic.",
            Self::TypeHashPreservationMismatch => "A proposed output did not preserve the consumed input type hash.",
            Self::LockHashPreservationMismatch => "A proposed output did not preserve the consumed input lock hash.",
            Self::FieldPreservationMismatch => "An output field required to be preserved differs from its input field.",
            Self::MutateTransitionMismatch => "A proposed output failed its declared field transition check.",
            Self::DataPreservationMismatch => "Proposed output data outside transition ranges differs from the input data.",
            Self::DynamicFieldBoundsInvalid => "A Molecule dynamic field offset or length failed bounds validation.",
            Self::TypeHashMismatch => "A loaded cell type hash did not match the expected CellScript type identity.",
            Self::FixedByteComparisonUnresolved => "A fixed-byte verifier comparison could not resolve its trusted source bytes.",
            Self::NumericOrDiscriminantInvalid => "A numeric verifier check, enum discriminant, or arithmetic guard failed.",
            Self::CollectionBoundsInvalid => "A runtime collection index, length, or capacity check failed.",
            Self::ConsumeInvalidOperand => "A consume operation reached codegen with an invalid or unsupported operand.",
            Self::DestroyInvalidOperand => "A destroy operation reached codegen with an invalid or unsupported operand.",
            Self::CollectionRuntimeUnsupported => "A runtime collection helper shape is not supported by the current backend.",
            Self::EntryWitnessAbiInvalid => "Entry witness payload layout, width, or parameter ABI placement was invalid.",
            Self::CapacityPreservationMismatch => "A proposed output did not preserve the consumed input capacity.",
            Self::DynamicFieldValueMismatch => "A dynamic Molecule field value did not match the expected verifier source.",
            Self::OutPointMismatch => "A loaded input OutPoint field did not match the expected transaction lineage.",
            Self::ScriptFieldMalformed => "A loaded CKB Script field did not match the expected Molecule Script layout.",
            Self::DaoHeaderLineageMismatch => {
                "The DAO field loaded from an input's committed block header did not match the supplied HeaderDep."
            }
            Self::DaoMaturityViolation => "The DAO input since value was below the required maturity lower bound.",
            Self::CkbSinceMalformed => "A CKB since value or requested since constructor argument was malformed.",
            Self::ScriptArgsMismatch => "A loaded CKB Script args field did not match the expected args policy.",
            Self::MetaPointMismatch => {
                "A loaded CKB MetaPoint relation did not match the expected input/output index and relative distance."
            }
            Self::MetaPointCardinalityMismatch => {
                "A current-script lock/type MetaPoint pair scan found a duplicate, missing, or unbalanced relation."
            }
            Self::ScriptIdentityMismatch => "A loaded CKB Script code_hash or hash_type did not match the expected identity.",
            Self::WitnessMalformed => "Loaded witness bytes did not match the expected Molecule WitnessArgs layout or ABI magic.",
            Self::WitnessFieldTruncated => "A WitnessArgs field offset or length exceeded the loaded witness byte range.",
            Self::CkbSourceViewInvalid => "A CKB SourceView value was malformed or used with an incompatible source-specific helper.",
            Self::HeaderDepMissing => "A required HeaderDep source view was absent or could not be bound to the requested header.",
            Self::DaoFieldMalformed => "A loaded DAO header or cell field did not match the expected encoded layout.",
            Self::ScriptRoleMismatch => "The script was used in a lock/type role that violates the declared invariant.",
            Self::XudtBindingMismatch => "An xUDT type args, owner-mode, or amount binding check failed.",
            Self::AggregateAmountMismatch => "A lowered aggregate/C256 accounting equality or inequality check failed.",
            Self::Bip340PipeCreateFailed => "The BIP340 runtime verifier path failed while creating the IPC pipe.",
            Self::Bip340SpawnFailed => "The BIP340 runtime verifier path failed while resolving or spawning the verifier CellDep.",
            Self::Bip340MessageWriteFailed => "The BIP340 runtime verifier path failed while writing the 32-byte message hash.",
            Self::Bip340PubkeyWriteFailed => "The BIP340 runtime verifier path failed while writing the 32-byte x-only pubkey.",
            Self::Bip340SignatureWriteFailed => "The BIP340 runtime verifier path failed while writing the 64-byte signature.",
            Self::Bip340VerifierReadFailed => "The BIP340 runtime verifier path failed while closing or reading verifier IPC status.",
            Self::Bip340ChildRejected => "The spawned BIP340 child verifier returned a non-zero verification status.",
            Self::FixedU64LeInputUnresolved => "The backend could not materialize a fixed-byte input for a u64 little-endian load.",
            Self::FixedByteComparisonMaterializationUnresolved => {
                "The backend could not materialize one side of a fixed-byte comparison."
            }
            Self::Bip340MessageMaterializationUnresolved => {
                "The backend could not materialize the 32-byte BIP340 message hash for verifier IPC."
            }
            Self::Bip340PubkeyMaterializationUnresolved => {
                "The backend could not materialize the 32-byte BIP340 x-only pubkey for verifier IPC."
            }
            Self::Bip340SignatureMaterializationUnresolved => {
                "The backend could not materialize the 64-byte BIP340 signature for verifier IPC."
            }
            Self::PackedHashPreimageMaterializationUnresolved => {
                "The backend could not materialize canonical packed bytes for a packed hash preimage."
            }
            Self::BoundedCellDepNotFound => {
                "A bounded CellDep scan did not find the required data hash before reaching the declared scan limit."
            }
            Self::MerkleRootMismatch => "A bounded Merkle proof did not reconstruct the expected root.",
            Self::ShiftAmountInvalid => "A runtime integer shift amount was greater than or equal to the left operand width.",
            Self::SighashAllUnsupported => "Canonical CKB transaction sighash construction is deferred and cannot produce a digest.",
        }
    }

    pub const fn hint(self) -> &'static str {
        match self {
            Self::SyscallFailed => {
                "Check transaction input/output/cell_dep indexes, source flags, and target-profile syscall compatibility."
            }
            Self::BoundsCheckFailed => "Check witness or cell data length against the schema manifest and entry ABI report.",
            Self::CellLoadFailed => {
                "Check that the expected input, output, or dep cell exists and is reachable by the generated script."
            }
            Self::ExactSizeMismatch => {
                "Check fixed-width schema fields and ensure the builder encodes the exact Molecule byte length."
            }
            Self::AssertionFailed => "Inspect the action invariant or assert expression and the transaction values that feed it.",
            Self::FlowTransitionMismatch => "Compare consumed and produced state fields with the declared flow transitions.",
            Self::FlowNewStateInvalid => "Check created output state values and declared flow states.",
            Self::FlowOldStateInvalid => "Check consumed input state values and declared flow states.",
            Self::EntryWitnessMagicMismatch => {
                "Encode entry witnesses with cellc entry-witness or the documented CSARGv1 wire format."
            }
            Self::TypeHashPreservationMismatch => "Check the proposed output type script and builder output ordering.",
            Self::LockHashPreservationMismatch => "Check the proposed output lock script and builder output ordering.",
            Self::FieldPreservationMismatch => "Check proposed output fields that should preserve lock/type/data identity.",
            Self::MutateTransitionMismatch => "Check the mutable field delta against the documented transition formula.",
            Self::DataPreservationMismatch => "Check that non-transition output data bytes are copied from the consumed input.",
            Self::DynamicFieldBoundsInvalid => "Validate Molecule table offsets, field count, and dynamic field lengths.",
            Self::TypeHashMismatch => "Check type script hash/hash_type/args and the expected CellScript type identity.",
            Self::FixedByteComparisonUnresolved => "Use schema-backed parameters or fixed-byte values that the verifier can address.",
            Self::NumericOrDiscriminantInvalid => "Check enum tags, arithmetic bounds, and generated collection length arithmetic.",
            Self::CollectionBoundsInvalid => "Check collection length, index, and capacity values in witness or cell data.",
            Self::ConsumeInvalidOperand => "This indicates an unsupported lowering path; inspect compiler metadata blockers.",
            Self::DestroyInvalidOperand => "This indicates an unsupported lowering path; inspect compiler metadata blockers.",
            Self::CollectionRuntimeUnsupported => {
                "Avoid advertising this collection helper as production-ready until support is implemented."
            }
            Self::EntryWitnessAbiInvalid => {
                "Inspect cellc constraints or cellc abi output for parameter slots and witness byte layout."
            }
            Self::CapacityPreservationMismatch => "Check the proposed output capacity and builder output ordering.",
            Self::DynamicFieldValueMismatch => "Check dynamic Molecule field encoding and the value source used by the verifier.",
            Self::OutPointMismatch => "Check the input OutPoint tx hash/index and the expected lineage binding.",
            Self::ScriptFieldMalformed => {
                "Check the lock/type Script Molecule encoding, args length, and whether the cell actually has that script field."
            }
            Self::DaoHeaderLineageMismatch => {
                "Bind the HeaderDep to the exact input/deposit header used for DAO accumulated-rate accounting."
            }
            Self::DaoMaturityViolation => {
                "Check the withdrawal request since value and ensure the consumed DAO input has reached the required maturity."
            }
            Self::CkbSinceMalformed => {
                "Check reserved flags, metric type, scalar and timestamp bounds, epoch number/index/length, and requested mode/metric."
            }
            Self::ScriptArgsMismatch => "Check lock/type script args and whether this protocol path requires empty script args.",
            Self::MetaPointMismatch => "Check the paired input OutPoints or output indexes and the signed relative-distance field.",
            Self::MetaPointCardinalityMismatch => {
                "Check current-script lock-only/type-only cell counts and ensure every MetaPoint has exactly one paired cell."
            }
            Self::ScriptIdentityMismatch => "Check Script code_hash, hash_type, deployed dep, and whether lock/type role is correct.",
            Self::WitnessMalformed => "Check witness byte layout, WitnessArgs table header, and entry ABI magic bytes.",
            Self::WitnessFieldTruncated => {
                "Check that expected WitnessArgs field offsets plus field lengths stay within loaded witness size."
            }
            Self::CkbSourceViewInvalid => "Pass a SourceView produced by the matching source::* helper and keep indexes in range.",
            Self::HeaderDepMissing => "Add the required header dep and bind it to the input/deposit whose DAO data is read.",
            Self::DaoFieldMalformed => "Check DAO header bytes, accumulated-rate width, and deposit/withdrawal cell data layout.",
            Self::ScriptRoleMismatch => "Check whether the script is deployed and invoked as the expected lock or type script.",
            Self::XudtBindingMismatch => "Check xUDT type args, owner-mode flags, input type hash, and token data layout.",
            Self::AggregateAmountMismatch => {
                "Compare generated aggregate inputs/outputs and inspect overflow or exact-equality assumptions."
            }
            Self::Bip340PipeCreateFailed => "Check CKB VM v2 pipe syscall availability and parent script VM version.",
            Self::Bip340SpawnFailed => "Check verifier CellDep ordering, out_point, hash_type, and spawn source/place wiring.",
            Self::Bip340MessageWriteFailed => "Compare the generated 32-byte message hash words with the verifier CLI input.",
            Self::Bip340PubkeyWriteFailed => "Compare the generated 32-byte x-only pubkey words with the verifier CLI input.",
            Self::Bip340SignatureWriteFailed => "Compare the generated 64-byte signature words with the verifier CLI input.",
            Self::Bip340VerifierReadFailed => "Check IPC fd close/read/wait wiring between parent and child verifier.",
            Self::Bip340ChildRejected => "Run the exact message, pubkey, and signature tuple through the local verifier CLI.",
            Self::FixedU64LeInputUnresolved => "Inspect schema field provenance for the fixed-byte scalar source.",
            Self::FixedByteComparisonMaterializationUnresolved => {
                "Inspect fixed-byte provenance for schema fields, aliases, nested projections, and local aggregates."
            }
            Self::Bip340MessageMaterializationUnresolved => "Compare signed_intent_hash provenance with the local verifier tuple.",
            Self::Bip340PubkeyMaterializationUnresolved => "Inspect the nested witness pubkey field source and copied ABI bytes.",
            Self::Bip340SignatureMaterializationUnresolved => {
                "Inspect the nested witness signature field source and copied ABI bytes."
            }
            Self::PackedHashPreimageMaterializationUnresolved => {
                "Inspect packed-hash lowering and schema-backed fixed aggregate materialization."
            }
            Self::BoundedCellDepNotFound => {
                "Check the expected data hash, resolved CellDep order, scan limit, and manifest-pinned DepGroup origin."
            }
            Self::MerkleRootMismatch => "Check leaf byte order, sibling order, depth, leaf index, hash algorithm, and expected root.",
            Self::ShiftAmountInvalid => "Keep runtime shift amounts below the bit width of the shifted integer value.",
            Self::SighashAllUnsupported => {
                "Use an authenticated standard Lock or an explicit verifier with an independently specified message contract."
            }
        }
    }

    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::SyscallFailed),
            2 => Some(Self::BoundsCheckFailed),
            3 => Some(Self::CellLoadFailed),
            4 => Some(Self::ExactSizeMismatch),
            5 => Some(Self::AssertionFailed),
            7 => Some(Self::FlowTransitionMismatch),
            8 => Some(Self::FlowNewStateInvalid),
            9 => Some(Self::FlowOldStateInvalid),
            10 => Some(Self::EntryWitnessMagicMismatch),
            11 => Some(Self::TypeHashPreservationMismatch),
            12 => Some(Self::LockHashPreservationMismatch),
            13 => Some(Self::FieldPreservationMismatch),
            14 => Some(Self::MutateTransitionMismatch),
            15 => Some(Self::DataPreservationMismatch),
            16 => Some(Self::DynamicFieldBoundsInvalid),
            17 => Some(Self::TypeHashMismatch),
            18 => Some(Self::FixedByteComparisonUnresolved),
            20 => Some(Self::NumericOrDiscriminantInvalid),
            21 => Some(Self::CollectionBoundsInvalid),
            22 => Some(Self::ConsumeInvalidOperand),
            23 => Some(Self::DestroyInvalidOperand),
            24 => Some(Self::CollectionRuntimeUnsupported),
            25 => Some(Self::EntryWitnessAbiInvalid),
            26 => Some(Self::CapacityPreservationMismatch),
            32 => Some(Self::DynamicFieldValueMismatch),
            33 => Some(Self::OutPointMismatch),
            34 => Some(Self::ScriptFieldMalformed),
            35 => Some(Self::DaoHeaderLineageMismatch),
            36 => Some(Self::DaoMaturityViolation),
            37 => Some(Self::CkbSinceMalformed),
            38 => Some(Self::ScriptArgsMismatch),
            39 => Some(Self::MetaPointMismatch),
            40 => Some(Self::MetaPointCardinalityMismatch),
            41 => Some(Self::ScriptIdentityMismatch),
            42 => Some(Self::WitnessMalformed),
            43 => Some(Self::WitnessFieldTruncated),
            44 => Some(Self::CkbSourceViewInvalid),
            45 => Some(Self::HeaderDepMissing),
            46 => Some(Self::DaoFieldMalformed),
            47 => Some(Self::ScriptRoleMismatch),
            48 => Some(Self::XudtBindingMismatch),
            49 => Some(Self::AggregateAmountMismatch),
            50 => Some(Self::Bip340PipeCreateFailed),
            51 => Some(Self::Bip340SpawnFailed),
            52 => Some(Self::Bip340MessageWriteFailed),
            53 => Some(Self::Bip340PubkeyWriteFailed),
            54 => Some(Self::Bip340SignatureWriteFailed),
            55 => Some(Self::Bip340VerifierReadFailed),
            56 => Some(Self::Bip340ChildRejected),
            57 => Some(Self::FixedU64LeInputUnresolved),
            58 => Some(Self::FixedByteComparisonMaterializationUnresolved),
            59 => Some(Self::Bip340MessageMaterializationUnresolved),
            60 => Some(Self::Bip340PubkeyMaterializationUnresolved),
            61 => Some(Self::Bip340SignatureMaterializationUnresolved),
            62 => Some(Self::PackedHashPreimageMaterializationUnresolved),
            63 => Some(Self::BoundedCellDepNotFound),
            64 => Some(Self::MerkleRootMismatch),
            65 => Some(Self::ShiftAmountInvalid),
            66 => Some(Self::SighashAllUnsupported),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellScriptRuntimeErrorInfo {
    pub code: u64,
    pub name: &'static str,
    pub description: &'static str,
    pub hint: &'static str,
}

pub const ALL_RUNTIME_ERRORS: &[CellScriptRuntimeError] = &[
    CellScriptRuntimeError::SyscallFailed,
    CellScriptRuntimeError::BoundsCheckFailed,
    CellScriptRuntimeError::CellLoadFailed,
    CellScriptRuntimeError::ExactSizeMismatch,
    CellScriptRuntimeError::AssertionFailed,
    CellScriptRuntimeError::FlowTransitionMismatch,
    CellScriptRuntimeError::FlowNewStateInvalid,
    CellScriptRuntimeError::FlowOldStateInvalid,
    CellScriptRuntimeError::EntryWitnessMagicMismatch,
    CellScriptRuntimeError::TypeHashPreservationMismatch,
    CellScriptRuntimeError::LockHashPreservationMismatch,
    CellScriptRuntimeError::FieldPreservationMismatch,
    CellScriptRuntimeError::MutateTransitionMismatch,
    CellScriptRuntimeError::DataPreservationMismatch,
    CellScriptRuntimeError::DynamicFieldBoundsInvalid,
    CellScriptRuntimeError::TypeHashMismatch,
    CellScriptRuntimeError::FixedByteComparisonUnresolved,
    CellScriptRuntimeError::NumericOrDiscriminantInvalid,
    CellScriptRuntimeError::CollectionBoundsInvalid,
    CellScriptRuntimeError::ConsumeInvalidOperand,
    CellScriptRuntimeError::DestroyInvalidOperand,
    CellScriptRuntimeError::CollectionRuntimeUnsupported,
    CellScriptRuntimeError::EntryWitnessAbiInvalid,
    CellScriptRuntimeError::CapacityPreservationMismatch,
    CellScriptRuntimeError::DynamicFieldValueMismatch,
    CellScriptRuntimeError::OutPointMismatch,
    CellScriptRuntimeError::ScriptFieldMalformed,
    CellScriptRuntimeError::DaoHeaderLineageMismatch,
    CellScriptRuntimeError::DaoMaturityViolation,
    CellScriptRuntimeError::CkbSinceMalformed,
    CellScriptRuntimeError::ScriptArgsMismatch,
    CellScriptRuntimeError::MetaPointMismatch,
    CellScriptRuntimeError::MetaPointCardinalityMismatch,
    CellScriptRuntimeError::ScriptIdentityMismatch,
    CellScriptRuntimeError::WitnessMalformed,
    CellScriptRuntimeError::WitnessFieldTruncated,
    CellScriptRuntimeError::CkbSourceViewInvalid,
    CellScriptRuntimeError::HeaderDepMissing,
    CellScriptRuntimeError::DaoFieldMalformed,
    CellScriptRuntimeError::ScriptRoleMismatch,
    CellScriptRuntimeError::XudtBindingMismatch,
    CellScriptRuntimeError::AggregateAmountMismatch,
    CellScriptRuntimeError::Bip340PipeCreateFailed,
    CellScriptRuntimeError::Bip340SpawnFailed,
    CellScriptRuntimeError::Bip340MessageWriteFailed,
    CellScriptRuntimeError::Bip340PubkeyWriteFailed,
    CellScriptRuntimeError::Bip340SignatureWriteFailed,
    CellScriptRuntimeError::Bip340VerifierReadFailed,
    CellScriptRuntimeError::Bip340ChildRejected,
    CellScriptRuntimeError::FixedU64LeInputUnresolved,
    CellScriptRuntimeError::FixedByteComparisonMaterializationUnresolved,
    CellScriptRuntimeError::Bip340MessageMaterializationUnresolved,
    CellScriptRuntimeError::Bip340PubkeyMaterializationUnresolved,
    CellScriptRuntimeError::Bip340SignatureMaterializationUnresolved,
    CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved,
    CellScriptRuntimeError::BoundedCellDepNotFound,
    CellScriptRuntimeError::MerkleRootMismatch,
    CellScriptRuntimeError::ShiftAmountInvalid,
    CellScriptRuntimeError::SighashAllUnsupported,
];

pub const RESERVED_RUNTIME_ERROR_CODES: &[u64] = &[6, 19, 27, 28, 29, 30, 31];

pub fn runtime_error_info(error: CellScriptRuntimeError) -> CellScriptRuntimeErrorInfo {
    CellScriptRuntimeErrorInfo { code: error.code(), name: error.name(), description: error.description(), hint: error.hint() }
}

pub fn runtime_error_info_by_code(code: u64) -> Option<CellScriptRuntimeErrorInfo> {
    CellScriptRuntimeError::from_code(code).map(runtime_error_info)
}

pub fn runtime_error_info_by_name(name: &str) -> Option<CellScriptRuntimeErrorInfo> {
    ALL_RUNTIME_ERRORS.iter().copied().find(|error| error.name() == name).map(runtime_error_info)
}

pub fn runtime_error_info_for_diagnostic(error: &crate::error::CompileError) -> Option<CellScriptRuntimeErrorInfo> {
    if let Some(code) = error.code.as_deref().and_then(parse_diagnostic_runtime_code) {
        return runtime_error_info_by_code(code);
    }
    runtime_error_info_for_diagnostic_message(&error.message)
}

fn parse_diagnostic_runtime_code(code: &str) -> Option<u64> {
    code.strip_prefix('E')?.parse().ok()
}

/// Compatibility bridge for legacy diagnostics that predate typed runtime
/// codes. New diagnostics should attach their exact `E####` code instead.
pub fn runtime_error_info_for_diagnostic_message(message: &str) -> Option<CellScriptRuntimeErrorInfo> {
    if let Some(info) = ALL_RUNTIME_ERRORS.iter().copied().map(runtime_error_info).find(|info| message.contains(info.name)) {
        return Some(info);
    }

    if message.contains(crate::ir::IrDeferredRuntimeFeature::CkbSighashAll.feature()) {
        return Some(runtime_error_info(CellScriptRuntimeError::SighashAllUnsupported));
    }

    if message.contains("fixed-byte-comparison") {
        return Some(runtime_error_info(CellScriptRuntimeError::FixedByteComparisonUnresolved));
    }
    if message.contains("collection-") || message.contains("cell-backed collection") {
        return Some(runtime_error_info(CellScriptRuntimeError::CollectionRuntimeUnsupported));
    }
    if message.contains("entry witness") || message.contains("entry-witness") {
        return Some(runtime_error_info(CellScriptRuntimeError::EntryWitnessAbiInvalid));
    }
    if message.contains("mutate-field-transition") {
        return Some(runtime_error_info(CellScriptRuntimeError::MutateTransitionMismatch));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn runtime_error_registry_roundtrips_and_has_unique_codes() {
        let mut codes = BTreeSet::new();
        let mut names = BTreeSet::new();
        for error in ALL_RUNTIME_ERRORS {
            let info = runtime_error_info(*error);
            assert_eq!(CellScriptRuntimeError::from_code(info.code), Some(*error));
            assert_eq!(runtime_error_info_by_code(info.code), Some(info));
            assert_eq!(runtime_error_info_by_name(info.name), Some(info));
            assert!(!info.name.is_empty());
            assert!(!info.description.is_empty());
            assert!(!info.hint.is_empty());
            assert!(codes.insert(info.code), "duplicate runtime error code {}", info.code);
            assert!(names.insert(info.name), "duplicate runtime error name {}", info.name);
        }
        for code in RESERVED_RUNTIME_ERROR_CODES {
            assert!(!codes.contains(code), "reserved runtime error code {} is registered", code);
            assert_eq!(runtime_error_info_by_code(*code), None);
        }
    }

    #[test]
    fn diagnostic_messages_map_to_runtime_error_codes_where_possible() {
        assert_eq!(
            runtime_error_info_for_diagnostic_message("fail-closed runtime features: ckb-sighash-all-deferred").map(|info| info.code),
            Some(66)
        );
        assert_eq!(
            runtime_error_info_for_diagnostic_message("fail-closed runtime features: collection-push").map(|info| info.code),
            Some(24)
        );
        assert_eq!(runtime_error_info_for_diagnostic_message("fixed-byte-comparison unresolved").map(|info| info.code), Some(18));
        assert_eq!(runtime_error_info_for_diagnostic_message("ordinary type mismatch").map(|info| info.code), None);
    }

    #[test]
    fn typed_diagnostic_runtime_code_wins_over_message_heuristics() {
        let diagnostic = crate::error::CompileError::without_span("entry witness text in an unrelated diagnostic").with_code("E0018");
        assert_eq!(runtime_error_info_for_diagnostic(&diagnostic).map(|info| info.code), Some(18));
    }

    #[test]
    fn runtime_error_docs_cover_every_registered_code() {
        let docs = include_str!("../docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md");
        for error in ALL_RUNTIME_ERRORS {
            let info = runtime_error_info(*error);
            assert!(docs.contains(&format!("| {} |", info.code)), "docs missing code {}", info.code);
            assert!(docs.contains(info.name), "docs missing runtime error name {}", info.name);
        }
    }

    #[test]
    fn codegen_does_not_emit_unregistered_numeric_fail_literals() {
        let codegen = include_str!("codegen/mod.rs");
        for code in 1..=64 {
            assert!(
                !codegen.contains(&format!("emit_fail({})", code)),
                "codegen must use CellScriptRuntimeError instead of emit_fail({})",
                code
            );
            assert!(
                !codegen.contains(&format!("emit_return_on_syscall_error({})", code)),
                "codegen must use CellScriptRuntimeError instead of emit_return_on_syscall_error({})",
                code
            );
        }
    }
}
