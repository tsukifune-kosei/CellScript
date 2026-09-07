use crate::descriptor::canonical_hex;
use crate::{
    CodeDeploymentIdentity, ExactArgsMatcherEvidence, FiberAssetDescriptor, FiberUdtArgInfo, LiveCellDepEvidence, ResolvedAssetScript,
    FIBER_ACCEPTANCE_SCHEMA, FIBER_COMPATIBILITY_SCHEMA, FIBER_REGISTRATION_SCHEMA, FIBER_TOPOLOGY_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OperationalState {
    StaticallyCompatible,
    ArtifactDeployed,
    AssetScriptResolved,
    LocalNodeConfiguredRestartRequired,
    LocalNodeAdvertised,
    ChannelReady,
    TopologyCertified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBinding {
    pub source_hash: String,
    pub artifact_hash: String,
    pub network: String,
    pub fiber_revision: String,
    pub ckb_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_out_point: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_script_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_hash: Option<String>,
}

impl EvidenceBinding {
    pub fn fingerprint(&self) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(format!("0x{}", hex::encode(cellscript::ckb_blake2b256(&bytes))))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiberCompatibilityReportV1 {
    pub schema: String,
    pub status: OperationalState,
    pub binding: EvidenceBinding,
    pub binding_fingerprint: String,
    pub descriptor: FiberAssetDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<CodeDeploymentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_script: Option<ResolvedAssetScript>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_cell_deps: Vec<LiveCellDepEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<ExactArgsMatcherEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_config: Option<FiberUdtArgInfo>,
    pub generated_report_is_authority: bool,
    pub ordinary_business_action_executed: bool,
    pub code_cell_type_id_args_used_as_asset_args: bool,
}

impl FiberCompatibilityReportV1 {
    pub fn new_static(
        descriptor: FiberAssetDescriptor,
        network: impl Into<String>,
        fiber_revision: impl Into<String>,
        ckb_revision: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let network = network.into();
        let fiber_revision = fiber_revision.into();
        let ckb_revision = canonical_hex(&ckb_revision.into(), Some(32), "CKB genesis identity")?;
        validate_git_revision(&fiber_revision, "Fiber revision")?;
        if network.trim().is_empty() {
            anyhow::bail!("evidence network must not be empty");
        }
        let binding = EvidenceBinding {
            source_hash: descriptor.source_hash.clone(),
            artifact_hash: descriptor.artifact_hash.clone(),
            network,
            fiber_revision,
            ckb_revision,
            deployment_out_point: None,
            asset_script_hash: None,
            configuration_hash: None,
        };
        let binding_fingerprint = binding.fingerprint()?;
        Ok(Self {
            schema: FIBER_COMPATIBILITY_SCHEMA.to_string(),
            status: OperationalState::StaticallyCompatible,
            binding,
            binding_fingerprint,
            descriptor,
            deployment: None,
            asset_script: None,
            live_cell_deps: Vec::new(),
            matcher: None,
            generated_config: None,
            generated_report_is_authority: false,
            ordinary_business_action_executed: false,
            code_cell_type_id_args_used_as_asset_args: false,
        })
    }

    pub fn bind_deployment(&mut self, deployment: CodeDeploymentIdentity, dependency: LiveCellDepEvidence) -> anyhow::Result<()> {
        if deployment.artifact_hash != self.descriptor.artifact_hash
            || !dependency.live
            || !dependency.artifact_hash_verified
            || !dependency.code_identity_verified
        {
            anyhow::bail!("deployment evidence is not bound to the checked artifact and live code Cell");
        }
        self.binding.deployment_out_point = Some(deployment.code_cell_out_point.display());
        self.deployment = Some(deployment);
        self.live_cell_deps.push(dependency);
        self.status = OperationalState::ArtifactDeployed;
        self.rebind()
    }

    pub fn bind_asset_script(&mut self, asset_script: ResolvedAssetScript) -> anyhow::Result<()> {
        let deployment = self.deployment.as_ref().ok_or_else(|| anyhow::anyhow!("bind deployment before asset Script"))?;
        if asset_script.script.code_hash != deployment.code_hash || asset_script.script.hash_type != deployment.hash_type {
            anyhow::bail!("resolved asset Script does not use the verified deployment code identity");
        }
        self.binding.asset_script_hash = Some(script_fingerprint(&asset_script.script)?);
        self.asset_script = Some(asset_script);
        self.status = OperationalState::AssetScriptResolved;
        self.rebind()
    }

    pub fn bind_configuration(&mut self, config: FiberUdtArgInfo, matcher: ExactArgsMatcherEvidence) -> anyhow::Result<()> {
        let asset = self.asset_script.as_ref().ok_or_else(|| anyhow::anyhow!("bind asset Script before Fiber configuration"))?;
        matcher.validate()?;
        config.validate()?;
        if matcher.intended_args != asset.script.args
            || config.script.code_hash != asset.script.code_hash
            || config.script.hash_type != asset.script.hash_type
            || config.script.args != matcher.matcher
        {
            anyhow::bail!("Fiber configuration is not exactly bound to the resolved asset Script");
        }
        let config_bytes = serde_json::to_vec(&config)?;
        self.binding.configuration_hash = Some(format!("0x{}", hex::encode(cellscript::ckb_blake2b256(&config_bytes))));
        self.matcher = Some(matcher);
        self.generated_config = Some(config);
        self.status = OperationalState::LocalNodeConfiguredRestartRequired;
        self.rebind()
    }

    pub fn mark_local_node_advertised(&mut self, observed_configuration_hash: &str) -> anyhow::Result<()> {
        if self.status < OperationalState::LocalNodeConfiguredRestartRequired {
            anyhow::bail!("cannot mark local node advertised before a bound configuration exists");
        }
        if self.binding.configuration_hash.as_deref() != Some(observed_configuration_hash) {
            anyhow::bail!("observed local-node configuration hash differs from generated configuration");
        }
        self.status = OperationalState::LocalNodeAdvertised;
        self.rebind()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != FIBER_COMPATIBILITY_SCHEMA || self.descriptor.schema != FIBER_COMPATIBILITY_SCHEMA {
            anyhow::bail!("unsupported Fiber compatibility report schema");
        }
        validate_git_revision(&self.binding.fiber_revision, "Fiber revision")?;
        canonical_hex(&self.descriptor.artifact_hash, Some(32), "descriptor.artifact_hash")?;
        if self.descriptor.metadata_schema_version != cellscript::METADATA_SCHEMA_VERSION
            || self.descriptor.contract != crate::FUNGIBLE_ENTRY_CONTRACT
            || self.descriptor.data_length_bytes != 16
            || self.descriptor.amount_offset_bytes != 0
            || self.descriptor.amount_width_bytes != 16
            || self.descriptor.endianness != "little"
            || self.descriptor.payload_required
            || self.descriptor.owner_mode != "script-args-32-byte-owner-lock-hash"
            || self.descriptor.owner_args_length_bytes != 32
            || self.descriptor.authority_modes != ["input-lock-hash".to_string(), "tagged-input-type-script-hash".to_string()]
            || self.descriptor.authority_args_lengths_bytes != [32, 33]
            || !self.descriptor.owner_authorized_mint
            || !self.descriptor.owner_authorized_burn
            || !self.descriptor.non_owner_input_group_non_empty
            || !self.descriptor.non_owner_output_group_non_empty
            || !self.descriptor.non_owner_conservation_required
        {
            anyhow::bail!("compatibility descriptor does not match the closed CellScript 0.22 Fiber v1 contract");
        }
        if self.binding.source_hash != self.descriptor.source_hash
            || self.binding.artifact_hash != self.descriptor.artifact_hash
            || self.binding.network.trim().is_empty()
            || canonical_hex(&self.binding.ckb_revision, Some(32), "CKB genesis identity").is_err()
            || self.binding_fingerprint != self.binding.fingerprint()?
        {
            anyhow::bail!("compatibility report binding or fingerprint is stale or inconsistent");
        }
        if self.generated_report_is_authority
            || self.ordinary_business_action_executed
            || self.code_cell_type_id_args_used_as_asset_args
        {
            anyhow::bail!("compatibility report violates the no-profile authority or identity-separation boundary");
        }

        let requires_deployment = self.status >= OperationalState::ArtifactDeployed;
        let requires_asset = self.status >= OperationalState::AssetScriptResolved;
        let requires_config = self.status >= OperationalState::LocalNodeConfiguredRestartRequired;
        if self.status > OperationalState::LocalNodeAdvertised {
            anyhow::bail!("compatibility report cannot self-certify channel or topology states");
        }
        if requires_deployment {
            let deployment =
                self.deployment.as_ref().ok_or_else(|| anyhow::anyhow!("deployment state omitted deployment identity"))?;
            if deployment.artifact_hash != self.descriptor.artifact_hash
                || self.binding.deployment_out_point.as_deref() != Some(deployment.code_cell_out_point.display().as_str())
                || self.live_cell_deps.len() != 1
            {
                anyhow::bail!("deployment state is not exactly bound to one verified live code Cell");
            }
            let dependency = &self.live_cell_deps[0];
            if !dependency.live
                || !dependency.artifact_hash_verified
                || !dependency.code_identity_verified
                || dependency.resolved_out_point != deployment.code_cell_out_point
            {
                anyhow::bail!("deployment dependency evidence is incomplete or points to a different Cell");
            }
            dependency.dependency.validate()?;
        } else if self.deployment.is_some() || !self.live_cell_deps.is_empty() || self.binding.deployment_out_point.is_some() {
            anyhow::bail!("static compatibility report contains premature deployment evidence");
        }

        if requires_asset {
            let deployment = self.deployment.as_ref().expect("deployment required by state ordering");
            let asset = self.asset_script.as_ref().ok_or_else(|| anyhow::anyhow!("asset state omitted resolved asset Script"))?;
            if asset.script.code_hash != deployment.code_hash
                || asset.script.hash_type != deployment.hash_type
                || asset.data_length_bytes != 16
                || self.binding.asset_script_hash.as_deref() != Some(script_fingerprint(&asset.script)?.as_str())
            {
                anyhow::bail!("asset state is not exactly bound to the verified deployment and 16-byte codec");
            }
        } else if self.asset_script.is_some() || self.binding.asset_script_hash.is_some() {
            anyhow::bail!("pre-asset report contains premature asset identity evidence");
        }

        if requires_config {
            let asset = self.asset_script.as_ref().expect("asset required by state ordering");
            let config = self.generated_config.as_ref().ok_or_else(|| anyhow::anyhow!("configured state omitted Fiber UDT config"))?;
            let matcher =
                self.matcher.as_ref().ok_or_else(|| anyhow::anyhow!("configured state omitted exact args matcher evidence"))?;
            config.validate()?;
            matcher.validate()?;
            let config_hash = format!("0x{}", hex::encode(cellscript::ckb_blake2b256(&serde_json::to_vec(config)?)));
            if config.script.code_hash != asset.script.code_hash
                || config.script.hash_type != asset.script.hash_type
                || config.script.args != matcher.matcher
                || matcher.intended_args != asset.script.args
                || self.binding.configuration_hash.as_deref() != Some(config_hash.as_str())
            {
                anyhow::bail!("generated Fiber configuration is not exactly bound to the resolved asset Script");
            }
        } else if self.generated_config.is_some() || self.matcher.is_some() || self.binding.configuration_hash.is_some() {
            anyhow::bail!("pre-configuration report contains premature Fiber configuration evidence");
        }
        Ok(())
    }

    fn rebind(&mut self) -> anyhow::Result<()> {
        self.binding_fingerprint = self.binding.fingerprint()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationReportV1 {
    pub schema: String,
    pub status: OperationalState,
    pub binding_fingerprint: String,
    pub fiber_rpc_url: String,
    pub trusted_local_rpc: bool,
    pub node_version: String,
    pub node_commit_hash: String,
    pub node_pubkey: String,
    pub chain_hash: String,
    pub exact_udt_observed: bool,
    pub signed_announcement_observed: bool,
    pub configuration_hash: String,
}

impl RegistrationReportV1 {
    pub fn schema() -> String {
        FIBER_REGISTRATION_SCHEMA.to_string()
    }

    pub fn validate(&self, compatibility: &FiberCompatibilityReportV1) -> anyhow::Result<()> {
        if self.schema != FIBER_REGISTRATION_SCHEMA
            || self.status != OperationalState::LocalNodeAdvertised
            || compatibility.status != OperationalState::LocalNodeAdvertised
            || self.binding_fingerprint != compatibility.binding_fingerprint
            || !self.trusted_local_rpc
            || !self.exact_udt_observed
            || !self.signed_announcement_observed
            || compatibility.binding.configuration_hash.as_deref() != Some(self.configuration_hash.as_str())
            || !node_commit_matches_revision(&self.node_commit_hash, &compatibility.binding.fiber_revision)
            || !chain_identity_matches(&self.chain_hash, &compatibility.binding.ckb_revision)
        {
            anyhow::bail!("registration report is not bound to the exact advertised configuration and pinned environment");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyReportV1 {
    pub schema: String,
    pub status: OperationalState,
    pub binding_fingerprint: String,
    pub participating_nodes: Vec<String>,
    pub exact_asset_route_channels: Vec<String>,
    pub liquidity_sufficient: bool,
    pub ckb_reserve_sufficient: bool,
    pub gossip_converged: bool,
    pub payment_observed: bool,
    pub certified: bool,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub path: String,
    pub blake2b_256: String,
}

impl EvidenceReference {
    fn validate(&self, root: &Path) -> anyhow::Result<()> {
        let relative = Path::new(&self.path);
        if relative.is_absolute() || relative.components().any(|component| !matches!(component, Component::Normal(_))) {
            anyhow::bail!("Fiber evidence path must be a normalized relative path: {}", self.path);
        }
        canonical_hex(&self.blake2b_256, Some(32), "evidence.blake2b_256")?;
        let root_metadata = fs::symlink_metadata(root)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            anyhow::bail!("Fiber evidence root must be a real directory, not a symlink: {}", root.display());
        }
        let mut path = fs::canonicalize(root)?;
        for component in relative.components() {
            let Component::Normal(component) = component else {
                unreachable!("evidence path components were validated above");
            };
            path.push(component);
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                anyhow::bail!("Fiber evidence path must not traverse a symlink: {}", self.path);
            }
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() == 0 {
            anyhow::bail!("Fiber evidence must be a non-empty regular file without symlinks: {}", self.path);
        }
        let actual = format!("0x{}", hex::encode(cellscript::ckb_blake2b256(&fs::read(&path)?)));
        if actual != self.blake2b_256.to_ascii_lowercase() {
            anyhow::bail!("Fiber evidence hash mismatch for {}", self.path);
        }
        Ok(())
    }
}

impl TopologyReportV1 {
    pub fn pending(binding_fingerprint: impl Into<String>) -> Self {
        Self {
            schema: FIBER_TOPOLOGY_SCHEMA.to_string(),
            status: OperationalState::LocalNodeConfiguredRestartRequired,
            binding_fingerprint: binding_fingerprint.into(),
            participating_nodes: Vec::new(),
            exact_asset_route_channels: Vec::new(),
            liquidity_sufficient: false,
            ckb_reserve_sufficient: false,
            gossip_converged: false,
            payment_observed: false,
            certified: false,
            reason: "topology certification requires restarted participating nodes, live channels, liquidity, reserve, gossip, and a concrete payment".to_string(),
            evidence: Vec::new(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != FIBER_TOPOLOGY_SCHEMA || self.certified != (self.status == OperationalState::TopologyCertified) {
            anyhow::bail!("topology status and certification flag are inconsistent");
        }
        if self.certified
            && (self.binding_fingerprint.is_empty()
                || self.participating_nodes.len() < 2
                || self.exact_asset_route_channels.is_empty()
                || !self.liquidity_sufficient
                || !self.ckb_reserve_sufficient
                || !self.gossip_converged
                || !self.payment_observed
                || self.evidence.is_empty())
        {
            anyhow::bail!(
                "topology report claims certification without complete node/channel/liquidity/reserve/gossip/payment evidence"
            );
        }
        Ok(())
    }

    pub fn validate_evidence(&self, root: &Path) -> anyhow::Result<()> {
        self.validate()?;
        for evidence in &self.evidence {
            evidence.validate(root)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceRowStatus {
    Pending,
    Passed,
    RejectedAsExpected,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceMatrixRow {
    pub id: String,
    pub class: String,
    pub status: AcceptanceRowStatus,
    pub evidence: Vec<EvidenceReference>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceMatrixReportV1 {
    pub schema: String,
    pub binding_fingerprint: String,
    pub complete: bool,
    pub rows: Vec<AcceptanceMatrixRow>,
}

impl AcceptanceMatrixReportV1 {
    pub fn pending(binding_fingerprint: impl Into<String>) -> Self {
        let rows = required_acceptance_rows()
            .into_iter()
            .map(|(id, class)| AcceptanceMatrixRow {
                id: id.to_string(),
                class: class.to_string(),
                status: AcceptanceRowStatus::Pending,
                evidence: Vec::new(),
                detail: "not executed".to_string(),
            })
            .collect();
        Self { schema: FIBER_ACCEPTANCE_SCHEMA.to_string(), binding_fingerprint: binding_fingerprint.into(), complete: false, rows }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != FIBER_ACCEPTANCE_SCHEMA {
            anyhow::bail!("unsupported Fiber acceptance report schema '{}'", self.schema);
        }
        if self.binding_fingerprint.is_empty() {
            anyhow::bail!("Fiber acceptance report is missing its evidence binding fingerprint");
        }
        let required = required_acceptance_rows().into_iter().collect::<std::collections::BTreeSet<_>>();
        let actual = self.rows.iter().map(|row| (row.id.as_str(), row.class.as_str())).collect::<std::collections::BTreeSet<_>>();
        if self.rows.len() != actual.len() {
            anyhow::bail!("Fiber acceptance report contains duplicate row identifiers/classes");
        }
        if actual != required {
            anyhow::bail!("Fiber acceptance report rows differ from the closed required v1 matrix");
        }
        let all_pass = self.rows.iter().all(|row| match row.class.as_str() {
            "positive" => row.status == AcceptanceRowStatus::Passed,
            "negative" => row.status == AcceptanceRowStatus::RejectedAsExpected,
            _ => false,
        });
        if self.complete != all_pass {
            anyhow::bail!("Fiber acceptance report complete flag does not match row outcomes");
        }
        if self.complete && self.rows.iter().any(|row| row.evidence.is_empty()) {
            anyhow::bail!("complete Fiber acceptance report contains a row without evidence references");
        }
        Ok(())
    }

    pub fn validate_evidence(&self, root: &Path) -> anyhow::Result<()> {
        self.validate()?;
        for row in &self.rows {
            for evidence in &row.evidence {
                evidence.validate(root)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_git_revision(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{label} must be an exact 40-hex Git commit");
    }
    Ok(())
}

pub(crate) fn node_commit_matches_revision(commit_info: &str, revision: &str) -> bool {
    let Some(reported) = commit_info.split_whitespace().next() else {
        return false;
    };
    if reported.ends_with("-dirty") || revision.len() != 40 {
        return false;
    }
    let reported = reported.to_ascii_lowercase();
    let revision = revision.to_ascii_lowercase();
    (reported.len() == 40 && reported == revision) || (reported.len() == 7 && revision.starts_with(&reported))
}

pub(crate) fn chain_identity_matches(observed_chain_hash: &str, expected: &str) -> bool {
    expected.len() == 66 && expected.starts_with("0x") && observed_chain_hash.eq_ignore_ascii_case(expected)
}

pub fn write_json_atomic(path: impl AsRef<Path>, value: &impl Serialize) -> anyhow::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let original_extension = path.extension().and_then(|value| value.to_str()).unwrap_or("json");
    let mut opened = None;
    for attempt in 0..16u8 {
        let temp = path.with_extension(format!("{original_extension}.tmp-{}-{nonce}-{attempt}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(file) => {
                opened = Some((temp, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temp, mut file) = opened.ok_or_else(|| anyhow::anyhow!("unable to create a unique temporary evidence file"))?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

fn script_fingerprint(script: &crate::ScriptIdentity) -> anyhow::Result<String> {
    Ok(format!("0x{}", hex::encode(cellscript::ckb_blake2b256(&serde_json::to_vec(script)?))))
}

fn required_acceptance_rows() -> Vec<(&'static str, &'static str)> {
    vec![
        ("P01-deploy-exact-artifact", "positive"),
        ("P02-resolve-independent-asset-script", "positive"),
        ("P03-anchored-args-matcher", "positive"),
        ("P04-live-direct-or-type-id-deps", "positive"),
        ("P05-node-restart-and-announcement", "positive"),
        ("P06-single-input-funding", "positive"),
        ("P07-multi-input-funding-change", "positive"),
        ("P08-manual-accept", "positive"),
        ("P09-auto-accept", "positive"),
        ("P10-direct-payment", "positive"),
        ("P11-multihop-payment", "positive"),
        ("P12-split-merge-payments", "positive"),
        ("P13-cooperative-shutdown", "positive"),
        ("P14-force-close-no-tlc", "positive"),
        ("P15-force-close-pending-udt-tlc", "positive"),
        ("P16-watchtower-settlement", "positive"),
        ("P17-fiber-witness-encodings", "positive"),
        ("P18-final-transaction-celldeps", "positive"),
        ("P19-node-restart-channel-reestablishment", "positive"),
        ("P20-ckb-vm-and-node-replay", "positive"),
        ("N01-short-data", "negative"),
        ("N02-long-data", "negative"),
        ("N03-wrong-script-or-args", "negative"),
        ("N04-overbroad-regex", "negative"),
        ("N05-code-cell-args-as-asset-args", "negative"),
        ("N06-dead-or-wrong-direct-dep", "negative"),
        ("N07-unresolved-type-id-dep", "negative"),
        ("N08-invalid-dependency-union", "negative"),
        ("N09-final-tx-missing-dep", "negative"),
        ("N10-amount-mismatch", "negative"),
        ("N11-sum-overflow", "negative"),
        ("N12-mint", "negative"),
        ("N13-burn", "negative"),
        ("N14-custom-entry-witness", "negative"),
        ("N15-empty-witness-assumption", "negative"),
        ("N16-header-or-oracle-dependency", "negative"),
        ("N17-fixed-output-topology", "negative"),
        ("N18-insufficient-ckb", "negative"),
        ("N19-insufficient-liquidity", "negative"),
        ("N20-node-without-asset", "negative"),
        ("N21-route-script-mismatch", "negative"),
        ("N22-gossip-not-converged", "negative"),
        ("N23-false-hotload-claim", "negative"),
        ("N24-untrusted-rpc", "negative"),
        ("N25-restart-or-upgrade-drift", "negative"),
        ("N26-tampered-artifact-manifest-config", "negative"),
        ("N27-unsupported-revision", "negative"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn pending_matrix_is_explicitly_incomplete() {
        let matrix = AcceptanceMatrixReportV1::pending("0x01");
        assert!(!matrix.complete);
        assert!(matrix.rows.len() >= 47);
        matrix.validate().unwrap();
    }

    #[test]
    fn topology_cannot_claim_certification_from_local_config() {
        let mut report = TopologyReportV1::pending("0x01");
        report.certified = true;
        report.status = OperationalState::TopologyCertified;
        assert!(report.validate().is_err());
    }

    #[test]
    fn live_registration_requires_an_exact_genesis_identity() {
        let genesis = format!("0x{}", "11".repeat(32));
        assert!(chain_identity_matches(&genesis, &genesis));
        assert!(!chain_identity_matches(&genesis, &"22".repeat(20)));
        assert!(!chain_identity_matches(&genesis, &format!("0x{}", "33".repeat(32))));
    }

    #[test]
    fn node_revision_accepts_only_fibers_seven_hex_abbreviation_or_the_full_hash() {
        let revision = "f9232d52254a5aa52195ecae296c896de7078887";
        assert!(node_commit_matches_revision("f9232d5 2026-09-07", revision));
        assert!(node_commit_matches_revision(revision, revision));
        assert!(!node_commit_matches_revision("f9232d5-dirty 2026-09-07", revision));
        assert!(!node_commit_matches_revision("f9232d50 2026-09-07", revision));
        assert!(!node_commit_matches_revision("04e091 2026-07-01", revision));
    }

    #[test]
    fn external_evidence_is_content_addressed_and_confined() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"fiber acceptance evidence\n";
        fs::write(root.path().join("row.log"), bytes).unwrap();
        let valid = EvidenceReference {
            path: "row.log".to_string(),
            blake2b_256: format!("0x{}", hex::encode(cellscript::ckb_blake2b256(bytes))),
        };
        valid.validate(root.path()).unwrap();

        let mut tampered = valid.clone();
        tampered.blake2b_256 = format!("0x{}", "00".repeat(32));
        assert!(tampered.validate(root.path()).is_err());

        let escaped = EvidenceReference { path: "../row.log".to_string(), blake2b_256: valid.blake2b_256.clone() };
        assert!(escaped.validate(root.path()).is_err());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.path(), root.path().join("linked")).unwrap();
            let linked = EvidenceReference {
                path: "linked/row.log".to_string(),
                blake2b_256: format!("0x{}", hex::encode(cellscript::ckb_blake2b256(bytes))),
            };
            assert!(linked.validate(root.path()).is_err());

            let root_link = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(root.path(), root_link.path().join("evidence-root")).unwrap();
            assert!(valid.validate(&root_link.path().join("evidence-root")).is_err());
        }
    }

    #[test]
    fn certified_topology_requires_verified_evidence_files() {
        let root = tempfile::tempdir().unwrap();
        let mut report = TopologyReportV1::pending("0x01");
        report.status = OperationalState::TopologyCertified;
        report.certified = true;
        report.participating_nodes = vec!["node-a".to_string(), "node-b".to_string()];
        report.exact_asset_route_channels = vec!["channel-a-b".to_string()];
        report.liquidity_sufficient = true;
        report.ckb_reserve_sufficient = true;
        report.gossip_converged = true;
        report.payment_observed = true;
        assert!(report.validate().is_err());

        let bytes = b"topology evidence\n";
        fs::write(root.path().join("topology.log"), bytes).unwrap();
        report.evidence.push(EvidenceReference {
            path: "topology.log".to_string(),
            blake2b_256: format!("0x{}", hex::encode(cellscript::ckb_blake2b256(bytes))),
        });
        report.validate_evidence(root.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_json_write_does_not_follow_the_legacy_temp_symlink() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim.txt");
        fs::write(&victim, b"do not overwrite").unwrap();
        let report = root.path().join("report.json");
        std::os::unix::fs::symlink(&victim, root.path().join("report.json.tmp")).unwrap();

        write_json_atomic(&report, &serde_json::json!({"ok": true})).unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"do not overwrite");
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&fs::read(report).unwrap()).unwrap(), serde_json::json!({"ok": true}));
    }
}
