use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::CompileError;

pub const COMPATIBILITY_PROFILE_SCHEMA: &str = "cellscript-resolved-compatibility-profile-v1";

/// CellScript source-language edition.
///
/// Editions are a closed set. A package must opt into the current edition
/// explicitly in `Cell.toml`; missing or unknown editions are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CellScriptEdition {
    #[serde(rename = "2026")]
    Edition2026,
    /// Experimental semantic-foundation frontend. This edition is accepted on
    /// the `0.30` implementation branch but is not the default stable edition.
    #[serde(rename = "2027")]
    Edition2027,
}

pub const CURRENT_EDITION: CellScriptEdition = CellScriptEdition::Edition2026;
pub const NEXT_EDITION: CellScriptEdition = CellScriptEdition::Edition2027;

impl Default for CellScriptEdition {
    fn default() -> Self {
        CURRENT_EDITION
    }
}

impl CellScriptEdition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edition2026 => "2026",
            Self::Edition2027 => "2027",
        }
    }

    /// Stable source-language semantics selected by this edition.
    ///
    /// Target, wire ABI, assurance, metadata, and compiler release versions
    /// are deliberately not edition properties. They are independent axes
    /// assembled by [`resolve_compatibility_profile`].
    pub const fn source_semantics(self) -> &'static str {
        match self {
            Self::Edition2026 => "cellscript-source-semantics-2026",
            Self::Edition2027 => "cellscript-source-semantics-2027-0.30-dev1",
        }
    }
}

/// Resolve the complete compile-time compatibility contract from independent
/// version axes.
///
/// The edition contributes source semantics only. Target behavior, primitive
/// assurance, metadata schemas, and entry/witness wire ABIs retain their own
/// version identities so that any of them can advance without inventing a new
/// source edition.
pub fn resolve_compatibility_profile(
    edition: CellScriptEdition,
    target_profile: &str,
    primitive_assurance: Option<&str>,
) -> ResolvedCompatibilityProfile {
    let primitive_assurance = primitive_assurance.unwrap_or("default").to_string();
    let source_semantics = edition.source_semantics().to_string();
    let mut profile = ResolvedCompatibilityProfile {
        schema: COMPATIBILITY_PROFILE_SCHEMA.to_string(),
        id: String::new(),
        edition,
        source_semantics,
        target_profile: target_profile.to_string(),
        primitive_assurance,
        metadata_schema_version: crate::METADATA_SCHEMA_VERSION,
        source_metadata_schema_version: crate::SOURCE_METADATA_SCHEMA_VERSION,
        artifact_metadata_schema_version: crate::ARTIFACT_METADATA_SCHEMA_VERSION,
        constraints_metadata_schema_version: crate::CONSTRAINTS_METADATA_SCHEMA_VERSION,
        entry_witness_payload_abi: crate::ENTRY_WITNESS_ABI.to_string(),
        entry_witness_placement_abi: crate::ENTRY_WITNESS_PLACEMENT_ABI.to_string(),
        entry_witness_placement_field: crate::ENTRY_WITNESS_PLACEMENT_FIELD.to_string(),
        entry_witness_placement_source: crate::ENTRY_WITNESS_PLACEMENT_SOURCE.to_string(),
        raw_entry_witness_payload_compatible: false,
    };
    profile.id = compatibility_profile_id(&profile);
    profile
}

fn compatibility_profile_id(profile: &ResolvedCompatibilityProfile) -> String {
    format!(
        "{}-{}-target-{}-primitive-{}-entry-{}-placement-{}-metadata-{}-{}-{}-{}",
        profile.schema,
        profile.source_semantics,
        profile.target_profile,
        profile.primitive_assurance,
        profile.entry_witness_payload_abi,
        profile.entry_witness_placement_abi,
        profile.metadata_schema_version,
        profile.source_metadata_schema_version,
        profile.artifact_metadata_schema_version,
        profile.constraints_metadata_schema_version,
    )
}

/// A selected artifact may declare an outer witness ABI without changing the
/// source edition or the legacy per-action parameter codec.
pub(crate) fn set_entry_compatibility_profile(
    profile: &mut ResolvedCompatibilityProfile,
    payload: &str,
    placement: &str,
    field: &str,
    source: &str,
) {
    profile.entry_witness_payload_abi = payload.to_string();
    profile.entry_witness_placement_abi = placement.to_string();
    profile.entry_witness_placement_field = field.to_string();
    profile.entry_witness_placement_source = source.to_string();
    profile.raw_entry_witness_payload_compatible = false;
    profile.id = compatibility_profile_id(profile);
}

impl fmt::Display for CellScriptEdition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CellScriptEdition {
    type Err = CompileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "2026" => Ok(Self::Edition2026),
            "2027" => Ok(Self::Edition2027),
            other => Err(CompileError::without_span(format!(
                "unsupported CellScript edition '{}'; expected 2026 or experimental 2027",
                other
            ))),
        }
    }
}

/// Fully resolved compile-time compatibility contract.
///
/// The edition contributes source semantics. Target, assurance, metadata, and
/// wire contracts remain independently named because they evolve on separate
/// schedules and CKB-VM cannot read `Cell.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCompatibilityProfile {
    pub schema: String,
    pub id: String,
    pub edition: CellScriptEdition,
    pub source_semantics: String,
    pub target_profile: String,
    pub primitive_assurance: String,
    pub metadata_schema_version: u32,
    pub source_metadata_schema_version: u32,
    pub artifact_metadata_schema_version: u32,
    pub constraints_metadata_schema_version: u32,
    pub entry_witness_payload_abi: String,
    pub entry_witness_placement_abi: String,
    pub entry_witness_placement_field: String,
    pub entry_witness_placement_source: String,
    pub raw_entry_witness_payload_compatible: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_experimental_editions_are_accepted() {
        assert_eq!("2026".parse::<CellScriptEdition>().unwrap(), CellScriptEdition::Edition2026);
        assert_eq!("2027".parse::<CellScriptEdition>().unwrap(), CellScriptEdition::Edition2027);
        assert!("unsupported".parse::<CellScriptEdition>().unwrap_err().message.contains("expected 2026 or experimental 2027"));
    }

    #[test]
    fn serde_uses_the_manifest_year() {
        assert_eq!(serde_json::to_string(&CURRENT_EDITION).unwrap(), "\"2026\"");
        assert_eq!(serde_json::to_string(&NEXT_EDITION).unwrap(), "\"2027\"");
        assert_eq!(serde_json::from_str::<CellScriptEdition>("\"2026\"").unwrap(), CURRENT_EDITION);
        assert_eq!(serde_json::from_str::<CellScriptEdition>("\"2027\"").unwrap(), NEXT_EDITION);
        assert!(serde_json::from_str::<CellScriptEdition>("\"unsupported\"").is_err());
    }

    #[test]
    fn edition_owns_source_semantics_only() {
        assert_eq!(CURRENT_EDITION.source_semantics(), "cellscript-source-semantics-2026");
        assert_eq!(NEXT_EDITION.source_semantics(), "cellscript-source-semantics-2027-0.30-dev1");
    }

    #[test]
    fn compatibility_profile_composes_independent_version_axes() {
        let profile = resolve_compatibility_profile(CURRENT_EDITION, "ckb", Some("0.16"));

        assert_eq!(profile.schema, COMPATIBILITY_PROFILE_SCHEMA);
        assert_eq!(profile.edition, CURRENT_EDITION);
        assert_eq!(profile.source_semantics, CURRENT_EDITION.source_semantics());
        assert_eq!(profile.target_profile, "ckb");
        assert_eq!(profile.primitive_assurance, "0.16");
        assert_eq!(profile.metadata_schema_version, crate::METADATA_SCHEMA_VERSION);
        assert_eq!(profile.source_metadata_schema_version, crate::SOURCE_METADATA_SCHEMA_VERSION);
        assert_eq!(profile.artifact_metadata_schema_version, crate::ARTIFACT_METADATA_SCHEMA_VERSION);
        assert_eq!(profile.constraints_metadata_schema_version, crate::CONSTRAINTS_METADATA_SCHEMA_VERSION);
        assert_eq!(profile.entry_witness_payload_abi, crate::ENTRY_WITNESS_ABI);
        assert_eq!(profile.entry_witness_placement_abi, crate::ENTRY_WITNESS_PLACEMENT_ABI);

        let other_assurance = resolve_compatibility_profile(CURRENT_EDITION, "ckb", Some("0.17"));
        assert_ne!(profile.id, other_assurance.id);
    }
}
