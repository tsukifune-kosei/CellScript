import { describe, expect, it, vi } from "vitest";
import type { SignChallengeResponseData } from "@joyid/ckb";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  AUTH_ACTION,
  AUTH_PROTOCOL,
  AUTH_REVOKE_CAPABILITY_ACTION,
  ARTIFACT_PROFILE_CATALOG,
  ARTIFACT_PROFILE_CATALOG_SCHEMA,
  AVAILABILITY_ACTION,
  AVAILABILITY_PROTOCOL,
  DEPLOYMENT_ACTION,
  DEPLOYMENT_PROTOCOL,
  DEFAULT_REGISTRY_ORIGIN,
  PUBLISH_ACTION,
  PUBLISH_PROTOCOL,
  ApiError,
  canonicalJson,
  capabilityKeyId,
  ckbBlake2bHex,
  ckbScriptHash,
  ckbSecp256k1PrincipalIdFromPublicKey,
  compareVersions,
  artifactProfileSupportsDependencyResolution,
  joyidPrincipalIdFromBinding,
  interfacePredecessorVersion,
  scopeAllows,
  sha256Hex,
  validatePublishPayload,
  validateInterfaceUpgrade,
  validateArtifactDescriptor,
  validateVersion,
  versionCompatibilityLine,
  type CapabilityAuthorisationPayload,
  type CapabilityRevocationPayload,
  type AvailabilityPayload,
  type CkbSecp256k1Signature,
  type DeploymentPayload,
  type PublishPayload,
} from "../src/domain";
import {
  CANONICAL_REGISTRY_TYPE_SCRIPT,
  CKB_MAINNET_SIGHASH_DEP_GROUP,
  CKB_MAINNET_SIGHASH_LOCK,
  MemoryRegistryStore,
  createApp,
  parseDepGroupOutPoints,
  registryCommitmentHash,
  registryRuntimeConfig,
  validatePromotionEvidence,
  verifyDeployment,
  verifyMainnetDeployment,
  type AppDeps,
  type SnapshotWriter,
} from "../src/index";
import type { PackageVersionRecord } from "../src/store";
import { nodeCkbRpcEnv } from "../src/node-runtime-env";

const now = new Date("2026-06-23T12:00:00Z");
const execFileAsync = promisify(execFile);
const ckbPrivateKey = Uint8Array.from({ length: 32 }, (_, index) => index === 31 ? 7 : 0);
const reproducerPublicKeys = {
  "builder-a": "p256-spki:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2GpMwoWK1SO7Vrd_Rn3kxf_VllpSMGMu1Mo40vH2IotxFkJwZwO7acw8A-lZB7z4l5QAYDKTP4ua7YilwZQfBw",
  "builder-b": "p256-spki:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcZljLFjOhAdes8hm88phoxoMmsya3kKGRbmwjtH1eW4tWV_sn81NRL5EwkrqhjPuYxXfEbYBfuSVPMVD3at7hQ",
} as const;

describe("ProtocolBundle Registry discovery evidence", () => {
  const sourceHash = `0x${"11".repeat(32)}`;
  const manifestHash = `0x${"12".repeat(32)}`;
  const artifactHash = `0x${"13".repeat(32)}`;
  const version = {
    version: "1.2.3",
    source_hash: sourceHash,
    manifest_hash: manifestHash,
    artifact: { profile: "ckb_executable" },
    registry_entry: { versions: [{ version: "1.2.3", artifact_hash: artifactHash }] },
  } as PackageVersionRecord;
  const evidence = {
    schema: "cellscript-registry-evidence",
    kind: "verified_build",
    producer: "cellscript-registry-artifact-verifier/test",
    generated_at: new Date(Date.now() - 1_000).toISOString(),
    verification_status: "passed",
    verification_level: "structurally_verified",
    source_hash: sourceHash,
    manifest_hash: manifestHash,
    artifact_hash: artifactHash,
    metadata_hash: `0x${"14".repeat(32)}`,
    checker_version: "0.1.0",
    checker_policy_schema: "cellscript-artifact-checker-policy-v1",
    checker_report_hash: `0x${"15".repeat(32)}`,
    artifact_format: "ckb-vm-executable",
    protocol_bundle_schema: "cellscript-protocol-bundle-v1",
    protocol_bundle_artifact_binding_schema: "cellscript-protocol-bundle-artifact-binding-v1",
    protocol_bundle_runtime_adapter: "cellscript-ckb-adapter",
  };

  it("accepts only the complete versioned ProtocolBundle capability triple", () => {
    expect(validatePromotionEvidence(evidence, "verified_build", version, [])).toMatchObject({
      protocol_bundle_schema: "cellscript-protocol-bundle-v1",
      protocol_bundle_artifact_binding_schema: "cellscript-protocol-bundle-artifact-binding-v1",
      protocol_bundle_runtime_adapter: "cellscript-ckb-adapter",
    });
    expect(() => validatePromotionEvidence(
      { ...evidence, protocol_bundle_runtime_adapter: undefined },
      "verified_build",
      version,
      [],
    )).toThrow("ProtocolBundle discovery contract is incomplete or unrecognised");
    expect(() => validatePromotionEvidence(
      { ...evidence, verification_level: "hash_bound" },
      "verified_build",
      version,
      [],
    )).toThrow("ProtocolBundle discovery requires a structurally verified CKB ELF bundle with complete sidecars");
  });
});

describe("Node CKB RPC environment", () => {
  it("forwards every bounded RPC control used by the shared API", () => {
    expect(nodeCkbRpcEnv({
      CKB_MAINNET_RPC_URL: "https://mainnet.ckb.dev/rpc",
      CKB_RPC_URL: "https://testnet.ckb.dev/rpc",
      CKB_RPC_TIMEOUT_MS: "15000",
      CKB_RPC_MAX_RESPONSE_BYTES: "8388608",
      CKB_DEP_GROUP_MAX_MEMBERS: "256",
      UNRELATED_SECRET: "must-not-pass-through",
    })).toEqual({
      CKB_MAINNET_RPC_URL: "https://mainnet.ckb.dev/rpc",
      CKB_RPC_URL: "https://testnet.ckb.dev/rpc",
      CKB_RPC_TIMEOUT_MS: "15000",
      CKB_RPC_MAX_RESPONSE_BYTES: "8388608",
      CKB_DEP_GROUP_MAX_MEMBERS: "256",
    });
  });
});

describe("capability scopes", () => {
  it("keeps publishing, deployment evidence, and availability changes independent", () => {
    const scopes = ["publish:cellscript/demo", "deployment:cellscript/*"];

    expect(scopeAllows(scopes, "publish", "cellscript", "demo")).toBe(true);
    expect(scopeAllows(scopes, "deployment", "cellscript", "other")).toBe(true);
    expect(scopeAllows(scopes, "availability", "cellscript", "demo")).toBe(false);
    expect(scopeAllows(scopes, "publish", "cellscript", "other")).toBe(false);
  });
});

describe("SemVer admission", () => {
  it("accepts canonical release, prerelease, and build metadata forms", () => {
    expect(validateVersion("0.24.0")).toBe("0.24.0");
    expect(validateVersion("1.2.3-rc.1+build.7")).toBe("1.2.3-rc.1+build.7");
  });

  it.each(["01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3-rc..1", "1.2.3+"])(
    "rejects non-canonical version %s",
    (version) => {
      expect(() => validateVersion(version)).toThrow(ApiError);
    },
  );
});

function bytesHex(value: Uint8Array): string {
  return `0x${[...value].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function depGroupData(outPoints: Array<{ tx_hash_byte: number; index: number }>): string {
  const bytes = new Uint8Array(4 + outPoints.length * 36);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, outPoints.length, true);
  outPoints.forEach((outPoint, item) => {
    const offset = 4 + item * 36;
    bytes.fill(outPoint.tx_hash_byte, offset, offset + 32);
    view.setUint32(offset + 32, outPoint.index, true);
  });
  return bytesHex(bytes);
}

describe("DepGroup decoding", () => {
  it("decodes canonical Molecule OutPointVec data", () => {
    expect(parseDepGroupOutPoints(depGroupData([
      { tx_hash_byte: 0x11, index: 3 },
      { tx_hash_byte: 0xab, index: 0xffff_fffe },
    ]))).toEqual([
      { tx_hash: `0x${"11".repeat(32)}`, index: 3 },
      { tx_hash: `0x${"ab".repeat(32)}`, index: 0xffff_fffe },
    ]);
  });

  it("rejects empty and non-canonical DepGroup data", () => {
    expect(() => parseDepGroupOutPoints("0x00000000")).toThrow(/canonical non-empty/);
    expect(() => parseDepGroupOutPoints("0x01000000aa")).toThrow(/canonical non-empty/);
  });
});

describe("CKB mainnet observations", () => {
  it("requires the configured confirmation depth for a live deployment Cell", async () => {
    const blockHash = `0x${"aa".repeat(32)}`;
    const artifactHash = `0x${"bb".repeat(32)}`;
    const deploymentTxHash = `0x${"dd".repeat(32)}`;
    let reportedChain = "ckb";
    let transactionStatus = "committed";
    let transactionBlockHash: string | null = blockHash;
    const transactionRequests: unknown[][] = [];
    vi.stubGlobal("fetch", async (_input: RequestInfo | URL, init?: RequestInit) => {
      const request = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      if (request.method === "get_transaction") transactionRequests.push(request.params);
      const results: Record<string, unknown> = {
        get_blockchain_info: { chain: reportedChain },
        get_live_cell: {
          status: "live",
          cell: {
            data: { hash: artifactHash, content: "0x00" },
            output: {
              capacity: "0x0",
              lock: { code_hash: `0x${"cc".repeat(32)}`, hash_type: "type", args: "0x" },
              type: null,
            },
          },
        },
        get_transaction: {
          transaction: null,
          cycles: null,
          fee: null,
          min_replace_fee: null,
          time_added_to_pool: null,
          tx_status: {
            status: transactionStatus,
            block_hash: transactionStatus === "committed" ? transactionBlockHash : null,
            block_number: transactionStatus === "committed" ? "0x64" : null,
            tx_index: transactionStatus === "committed" ? "0x0" : null,
            reason: null,
          },
        },
        get_header: { number: "0x64" },
        get_tip_header: { number: "0x6a" },
      };
      return Response.json({ jsonrpc: "2.0", id: 1, result: results[request.method] });
    });
    const payload: DeploymentPayload = {
      protocol: DEPLOYMENT_PROTOCOL,
      action: DEPLOYMENT_ACTION,
      registry_origin: DEFAULT_REGISTRY_ORIGIN,
      namespace: "fixture",
      name: "contract",
      release: "1.0.0",
      network: "mainnet",
      artifact_hash: artifactHash,
      data_hash: artifactHash,
      code_hash: artifactHash,
      hash_type: "data1",
      dep_type: "code",
      out_point: { tx_hash: deploymentTxHash, index: 0 },
      capability_key_id: "cap_11111111111111111111111111111111",
      nonce: "0x1111111111111111",
      issued_at: "2026-06-23T12:00:00Z",
      expires_at: "2026-06-23T12:10:00Z",
      cli_version: "cellc 0.23.0",
    };
    try {
      await expect(verifyMainnetDeployment({ CKB_MIN_CONFIRMATIONS: "8" }, payload))
        .rejects.toMatchObject({ code: "chain_confirmation_depth_insufficient" });
      await expect(verifyMainnetDeployment({ CKB_MIN_CONFIRMATIONS: "7" }, payload))
        .resolves.toMatchObject({ block_hash: blockHash, block_number: "0x64", tip_block_number: "0x6a", confirmations: 7 });
      transactionStatus = "pending";
      await expect(verifyMainnetDeployment({ CKB_MIN_CONFIRMATIONS: "7" }, payload))
        .rejects.toMatchObject({ code: "chain_observation_uncommitted" });
      transactionStatus = "committed";
      transactionBlockHash = null;
      await expect(verifyMainnetDeployment({ CKB_MIN_CONFIRMATIONS: "7" }, payload))
        .rejects.toMatchObject({ code: "invalid_ckb_rpc_response", status: 503 });
      transactionBlockHash = blockHash;
      reportedChain = "ckb_testnet";
      await expect(verifyDeployment({
        REGISTRY_ENVIRONMENT: "testnet-sandbox",
        REGISTRY_ORIGIN: "https://api.testnet.registry.cellscript.dev",
        STATIC_REGISTRY_ORIGIN: "https://objects.testnet.registry.cellscript.dev",
        CKB_MIN_CONFIRMATIONS: "7",
      }, { ...payload, network: "testnet" }))
        .resolves.toMatchObject({ block_number: "0x64", tip_block_number: "0x6a", confirmations: 7 });
      await expect(verifyDeployment({
        REGISTRY_ENVIRONMENT: "testnet-sandbox",
        REGISTRY_ORIGIN: "https://api.testnet.registry.cellscript.dev",
        STATIC_REGISTRY_ORIGIN: "https://objects.testnet.registry.cellscript.dev",
      }, payload)).rejects.toMatchObject({ code: "unsupported_deployment_network" });
      expect(transactionRequests).toEqual([
        [deploymentTxHash],
        [deploymentTxHash],
        [deploymentTxHash],
        [deploymentTxHash],
        [deploymentTxHash],
      ]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

async function ckbAuthPayload(): Promise<CapabilityAuthorisationPayload> {
  const publicKey = bytesHex(secp256k1.getPublicKey(ckbPrivateKey, true));
  return {
    ...authPayload(),
    principal_type: "ckb_secp256k1",
    principal_id: await ckbSecp256k1PrincipalIdFromPublicKey(publicKey),
  };
}

function ckbWalletSignature(
  payload: CapabilityAuthorisationPayload | CapabilityRevocationPayload,
): CkbSecp256k1Signature {
  const challenge = canonicalJson(payload);
  const message = new TextEncoder().encode(`Nervos Message:${challenge}`);
  const messageHash = blake2b(message, {
    dkLen: 32,
    personalization: new TextEncoder().encode("ckb-default-hash"),
  });
  const recovered = secp256k1.sign(messageHash, ckbPrivateKey, { format: "recovered", prehash: false });
  const ckbSignature = new Uint8Array(65);
  ckbSignature.set(recovered.subarray(1), 0);
  ckbSignature[64] = recovered[0] ?? 0;
  return {
    scheme: "ckb_secp256k1",
    challenge,
    signature: bytesHex(ckbSignature),
    public_key: bytesHex(secp256k1.getPublicKey(ckbPrivateKey, true)),
  };
}

function authPayload(principalId = "0x1111111111111111111111111111111111111111"): CapabilityAuthorisationPayload {
  return {
    protocol: AUTH_PROTOCOL,
    action: AUTH_ACTION,
    registry_origin: DEFAULT_REGISTRY_ORIGIN,
    principal_type: "joyid_ckb",
    principal_id: principalId,
    capability_pubkey: `p256-spki:${principalId.slice(2)}`,
    requested_scopes: [
      "publish:cellscript/demo",
      "deployment:cellscript/demo",
      "availability:cellscript/demo",
    ],
    capability_expires_at: "2026-09-21T12:00:00Z",
    nonce: "0x1111111111111111",
    issued_at: "2026-06-23T12:00:00Z",
    expires_at: "2026-06-23T12:10:00Z",
    cli_version: "cellc 0.23.0",
  };
}

function joyidSignature(
  payload: CapabilityAuthorisationPayload,
  challenge = canonicalJson(payload),
  pubkey = payload.principal_id.startsWith("0x") ? payload.principal_id.slice(2) : "pubkey",
): SignChallengeResponseData {
  return {
    challenge,
    signature: "sig",
    message: "message",
    pubkey,
    keyType: "main_key",
    alg: -7,
  };
}

function revokePayload(keyId: string, principalId = "0x1111111111111111111111111111111111111111"): CapabilityRevocationPayload {
  return {
    protocol: AUTH_PROTOCOL,
    action: AUTH_REVOKE_CAPABILITY_ACTION,
    registry_origin: DEFAULT_REGISTRY_ORIGIN,
    principal_type: "joyid_ckb",
    principal_id: principalId,
    capability_key_id: keyId,
    nonce: "0x3333333333333333",
    issued_at: "2026-06-23T12:00:00Z",
    expires_at: "2026-06-23T12:10:00Z",
    cli_version: "cellc 0.23.0",
  };
}

function availabilityPayload(
  keyId: string,
  status: AvailabilityPayload["availability_status"] = "yanked",
  nonce = "0x7777777777777777",
): AvailabilityPayload {
  return {
    protocol: AVAILABILITY_PROTOCOL,
    action: AVAILABILITY_ACTION,
    registry_origin: DEFAULT_REGISTRY_ORIGIN,
    namespace: "cellscript",
    name: "demo",
    release: "1.2.3",
    availability_status: status,
    ...(status === "yanked" ? { reason: "security review" } : {}),
    capability_key_id: keyId,
    nonce,
    issued_at: "2026-06-23T12:00:00Z",
    expires_at: "2026-06-23T12:10:00Z",
    cli_version: "cellc 0.23.0",
  };
}

function joyidRevocationSignature(
  payload: CapabilityRevocationPayload,
  challenge = canonicalJson(payload),
  pubkey = payload.principal_id.startsWith("0x") ? payload.principal_id.slice(2) : "pubkey",
): SignChallengeResponseData {
  return {
    challenge,
    signature: "sig",
    message: "message",
    pubkey,
    keyType: "main_key",
    alg: -7,
  };
}

async function publishPayload(keyId: string): Promise<PublishPayload> {
  return {
    protocol: PUBLISH_PROTOCOL,
    action: PUBLISH_ACTION,
    registry_origin: DEFAULT_REGISTRY_ORIGIN,
    namespace: "cellscript",
    name: "demo",
    version: "1.2.3",
    source_hash: `0x${"ab".repeat(32)}`,
    manifest_hash: `0x${"cd".repeat(32)}`,
    capability_key_id: keyId,
    nonce: "0x2222222222222222",
    issued_at: "2026-06-23T12:00:00Z",
    expires_at: "2026-06-23T12:10:00Z",
    cli_version: "cellc 0.23.0",
    artifact: {
      kind: "source_library",
      profile: "cellscript_source",
      consumption_mode: "dependency",
      language: "cellscript",
    },
    registry_entry: {
      schema_version: 1,
      namespace: "cellscript",
      name: "demo",
      artifact: {
        kind: "source_library",
        profile: "cellscript_source",
        consumption_mode: "dependency",
        language: "cellscript",
      },
      repository: "https://github.com/cellscript/demo",
      versions: [{
        version: "1.2.3",
        tag: "v1.2.3",
        source_hash: `0x${"ab".repeat(32)}`,
        cellscript_version: "0.23.0",
        edition: "2026",
        compatibility_profile_hash: "ef".repeat(32),
        interface_hash: ckbBlake2bHex(canonicalJson({
          schema: "cellscript-package-interface-v2",
          version: 2,
          module: "cellscript::demo",
          types: [],
          constants: [],
          callables: [],
        })),
        interface: {
          schema: "cellscript-package-interface-v2",
          version: 2,
          module: "cellscript::demo",
          types: [],
          constants: [],
          callables: [],
        },
        dependencies: {},
        verification_status: "pending",
        deployment_status: "not_applicable",
        availability_status: "active",
      }],
    },
  };
}

async function ckbExecutablePublishPayload(keyId: string): Promise<PublishPayload> {
  const payload = await publishPayload(keyId);
  payload.artifact = {
    kind: "deployable_contract",
    profile: "ckb_executable",
    consumption_mode: "deployment",
    language: "rust",
  };
  payload.registry_entry.artifact = payload.artifact;
  const release = payload.registry_entry.versions[0];
  delete release.cellscript_version;
  delete release.edition;
  delete release.compatibility_profile_hash;
  delete release.interface_hash;
  delete release.interface;
  delete release.dependencies;
  release.artifact_hash = `0x${"31".repeat(32)}`;
  release.abi_hash = `0x${"32".repeat(32)}`;
  release.profile_contract = {
    schema: "cellscript-registry-profile-contract-v1",
    artifact_kind: "deployable_contract",
    profile: "ckb_executable",
    build: {
      target: "riscv64imac-unknown-none-elf",
      toolchain: "rustc 1.97.1",
      profile: "release",
      source_revision: "0123456789abcdef",
      reproducible: false,
    },
    security: { status: "review_required" },
    ckb: {
      vm_version: "2",
      script_role: "type",
      hash_type: "data1",
      dep_type: "code",
      abi_hash: release.abi_hash,
    },
  };
  payload.manifest_hash = ckbBlake2bHex(canonicalJson(release.profile_contract));
  release.deployment_status = "undeployed";
  return payload;
}

describe("CellScript public interface admission", () => {
  const baseInterface = {
    schema: "cellscript-package-interface-v2",
    version: 2,
    module: "cellscript::demo",
    types: [{
      identity: "cellscript::demo::Value",
      kind: "struct",
      type_parameters: [],
      value_abilities: ["copy"],
      cell_capabilities: [],
      layout_identity: "11".repeat(32),
      type_identity: null,
    }],
    constants: [],
    callables: [],
    runtime_contract: { target_profile: "ckb", witness_abi: "v2" },
    deployment_contract_hash: "22".repeat(32),
  };

  it("accepts additive exports and rejects layout changes before admission", () => {
    expect(() => validateInterfaceUpgrade(baseInterface, {
      ...baseInterface,
      callables: [{
        identity: "cellscript::demo::read",
        kind: "function",
        type_parameters: [],
        params: [],
        return_type: "u64",
        outputs: [],
        effect: "Pure",
        entry_witness_abi: null,
        builder_contract_hash: "33".repeat(32),
      }],
    })).not.toThrow();
    expect(() => validateInterfaceUpgrade(baseInterface, {
      ...baseInterface,
      types: [{ ...baseInterface.types[0], layout_identity: "44".repeat(32) }],
    })).toThrow(/changed incompatibly/);
  });

  it("uses strict SemVer precedence and explicit compatibility lines", () => {
    expect(compareVersions("1.10.0", "1.9.9")).toBeGreaterThan(0);
    expect(compareVersions("2.0.0-rc.1", "2.0.0-beta.11")).toBeGreaterThan(0);
    expect(compareVersions("2.0.0", "2.0.0-rc.1")).toBeGreaterThan(0);
    expect(versionCompatibilityLine("2.4.0")).toBe("2");
    expect(versionCompatibilityLine("0.25.3")).toBe("0.25");
    expect(() => validateVersion("01.2.3")).toThrow(/valid SemVer/);
    expect(() => validateVersion("1.2.3-01")).toThrow(/leading zeroes/);
    expect(interfacePredecessorVersion(["1.9.0", "2.0.0"], "2.1.0")).toBe("2.0.0");
    expect(interfacePredecessorVersion(["1.9.0", "2.1.0"], "3.0.0")).toBeNull();
    expect(() => interfacePredecessorVersion(["2.0.0"], "1.10.0")).toThrow(/highest admitted version/);
  });
});

function declareReproducibleBuild(payload: PublishPayload): void {
  const release = payload.registry_entry.versions[0];
  const contract = release.profile_contract!;
  const recipeHash = `0x${"34".repeat(32)}`;
  (contract["build"] as Record<string, unknown>)["reproducible"] = true;
  contract["reproduction"] = {
    environment: "docker.io/library/rust:1.97.1@sha256:0123456789abcdef",
    command: "cargo build --locked --release",
    recipe_hash: recipeHash,
    expected_artifact_hash: release.artifact_hash,
  };
  release.build_recipe_hash = recipeHash;
  payload.manifest_hash = ckbBlake2bHex(canonicalJson(contract));
}

describe("generic artifact profile contracts", () => {
  it("exposes one versioned, fail-closed definition for every artifact profile", () => {
    expect(Object.keys(ARTIFACT_PROFILE_CATALOG).sort()).toEqual([
      "cellscript_source",
      "ckb_executable",
      "copy_material",
      "reproducible_build",
    ]);
    expect(Object.values(ARTIFACT_PROFILE_CATALOG).every((definition) => definition.schema === ARTIFACT_PROFILE_CATALOG_SCHEMA)).toBe(true);
    expect(artifactProfileSupportsDependencyResolution("cellscript_source")).toBe(true);
    expect(artifactProfileSupportsDependencyResolution("ckb_executable")).toBe(false);
  });

  it("keeps unknown profiles and non-source dependency contracts out of the resolver surface", () => {
    expect(() => validateArtifactDescriptor({
      kind: "source_library",
      profile: "future_profile",
      consumption_mode: "dependency",
      language: "cellscript",
    })).toThrow(/artifact.profile must be one of/);
    expect(() => validateArtifactDescriptor({
      kind: "deployable_contract",
      profile: "ckb_executable",
      consumption_mode: "dependency",
      language: "rust",
    })).toThrow(/do not match its kind/);
  });

  it("requires a typed profile contract for non-CellScript releases", async () => {
    const payload = await ckbExecutablePublishPayload("cap_test");
    delete payload.registry_entry.versions[0].profile_contract;
    expect(() => validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now)).toThrow(/profile_contract/);
  });

  it("rejects contract hashes that do not bind the immutable ABI identity", async () => {
    const payload = await ckbExecutablePublishPayload("cap_test");
    const contract = payload.registry_entry.versions[0].profile_contract!;
    (contract["ckb"] as Record<string, unknown>)["abi_hash"] = `0x${"99".repeat(32)}`;
    payload.manifest_hash = ckbBlake2bHex(canonicalJson(contract));
    expect(() => validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now)).toThrow(/abi_hash.*does not match/);
  });

  it("rejects unknown profile contract fields", async () => {
    const payload = await ckbExecutablePublishPayload("cap_test");
    const contract = payload.registry_entry.versions[0].profile_contract!;
    contract["trust_me"] = true;
    payload.manifest_hash = ckbBlake2bHex(canonicalJson(contract));
    expect(() => validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now)).toThrow(/trust_me is not recognised/);
  });

  it("allows a deployed CKB executable to bind a reproducible build recipe", async () => {
    const payload = await ckbExecutablePublishPayload("cap_test");
    declareReproducibleBuild(payload);

    expect(validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now).artifact.profile).toBe("ckb_executable");
  });

  it("admits only the exact LS-IDL 0.1 lock-script profile shape", async () => {
    const payload = await ckbExecutablePublishPayload("cap_test");
    const release = payload.registry_entry.versions[0];
    const contract = release.profile_contract!;
    (contract["ckb"] as Record<string, unknown>)["script_role"] = "lock";
    contract["interface"] = {
      schema: "cellscript-registry-ls-idl-interface-v1",
      format: "ls-idl",
      format_version: "0.1",
      object_role: "abi",
      content_type: "application/vnd.ckb.ls-idl+json",
      encoding: "linear-le-v0",
      commitment: {
        algorithm: "sha256",
        placement: "code-cell-data-suffix-32",
        digest: `0x${"77".repeat(32)}`,
      },
    };
    payload.manifest_hash = ckbBlake2bHex(canonicalJson(contract));
    expect(validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now).registry_entry.versions[0].profile_contract)
      .toMatchObject({ interface: { format: "ls-idl", format_version: "0.1" } });

    (contract["ckb"] as Record<string, unknown>)["script_role"] = "type";
    payload.manifest_hash = ckbBlake2bHex(canonicalJson(contract));
    expect(() => validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now)).toThrow(/script_role must be 'lock'/);
  });
});

function deploymentPayload(keyId: string): DeploymentPayload {
  return {
    protocol: DEPLOYMENT_PROTOCOL,
    action: DEPLOYMENT_ACTION,
    registry_origin: DEFAULT_REGISTRY_ORIGIN,
    namespace: "cellscript",
    name: "demo",
    release: "1.2.3",
    network: "mainnet",
    artifact_hash: `0x${"31".repeat(32)}`,
    data_hash: `0x${"31".repeat(32)}`,
    code_hash: `0x${"31".repeat(32)}`,
    hash_type: "data1",
    dep_type: "code",
    out_point: { tx_hash: `0x${"41".repeat(32)}`, index: 0 },
    capability_key_id: keyId,
    nonce: "0x4444444444444444",
    issued_at: "2026-06-23T12:00:00Z",
    expires_at: "2026-06-23T12:10:00Z",
    cli_version: "cellc 0.23.0",
  };
}

function base64(value: string): string {
  return btoa(value);
}

function utf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function testApp(store = new MemoryRegistryStore(), writer?: SnapshotWriter, deps: Partial<AppDeps> = {}) {
  const snapshots: Array<{ key: string; body: Uint8Array; contentType: string }> = [];
  const snapshotWriter =
    writer ??
    ({
      async put(key, body, options) {
        snapshots.push({ key, body, contentType: options.contentType });
      },
    } satisfies SnapshotWriter);
  const app = createApp({
    store,
    now: () => now,
    joyidVerifier: { verifySignature: async () => true },
    capabilityVerifier: { verify: async () => true },
    snapshotWriter,
    ...deps,
  });
  return { app, store, snapshots };
}

async function post(
  app: ReturnType<typeof createApp>,
  path: string,
  body: unknown,
  env: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Promise<Response> {
  return app.fetch(
    new Request(`https://api.registry.cellscript.dev${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.5", ...headers },
      body: JSON.stringify(body),
    }),
    { REGISTRY_ORIGIN: DEFAULT_REGISTRY_ORIGIN, ...env },
  );
}

async function get(
  app: ReturnType<typeof createApp>,
  path: string,
  env: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Promise<Response> {
  return app.fetch(
    new Request(`https://api.registry.cellscript.dev${path}`, {
      method: "GET",
      headers: { "cf-connecting-ip": "203.0.113.5", ...headers },
    }),
    { REGISTRY_ORIGIN: DEFAULT_REGISTRY_ORIGIN, ...env },
  );
}

async function createBrowserAuthorisationSession(
  app: ReturnType<typeof createApp>,
  namespace = "walletdemo",
  name = "demo",
) {
  const response = await post(app, "/v1/authorisation-sessions", {
    capability_pubkey: reproducerPublicKeys["builder-a"],
    requested_scopes: [`publish:${namespace}/${name}`],
    artifact_kind: "source_library",
    capability_expires_at: "2026-09-21T12:00:00Z",
    cli_version: "0.23.0",
  });
  expect(response.status).toBe(201);
  const created = await response.json() as any;
  const browserParams = new URLSearchParams(new URL(created.browser_url).hash.slice(1));
  const browserToken = browserParams.get("browser_token");
  expect(browserToken).toMatch(/^browser_[0-9a-f]{32}$/);
  return { created, browserToken: String(browserToken) };
}

async function prepareBrowserAuthorisationChallenge(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  browserToken: string,
) {
  const wallet = await ckbAuthPayload();
  const response = await post(app, `/v1/authorisation-sessions/${sessionId}/challenge`, {
    principal_type: wallet.principal_type,
    principal_id: wallet.principal_id,
  }, {}, { authorization: `Bearer ${browserToken}` });
  expect(response.status).toBe(200);
  return await response.json() as any;
}

async function completeBrowserAuthorisationSession(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  browserToken: string,
  challenge: any,
) {
  return post(app, `/v1/authorisation-sessions/${sessionId}/complete`, {
    challenge_token: challenge.challenge_token,
    wallet_signature: ckbWalletSignature(challenge.payload),
  }, {}, { authorization: `Bearer ${browserToken}` });
}

async function lsIdlLookupApp(idlBytes: Uint8Array) {
  const store = new MemoryRegistryStore();
  const idl = new TextDecoder().decode(idlBytes);
  const digest = await sha256Hex(idlBytes);
  const codeHash = `0x${"31".repeat(32)}`;
  const payload = await ckbExecutablePublishPayload("cap_test");
  const release = payload.registry_entry.versions[0];
  const contract = release.profile_contract!;
  (contract["ckb"] as Record<string, unknown>)["script_role"] = "lock";
  contract["interface"] = {
    schema: "cellscript-registry-ls-idl-interface-v1",
    format: "ls-idl",
    format_version: "0.1",
    object_role: "abi",
    content_type: "application/vnd.ckb.ls-idl+json",
    encoding: "linear-le-v0",
    commitment: { algorithm: "sha256", placement: "code-cell-data-suffix-32", digest: `0x${digest}` },
  };
  payload.manifest_hash = ckbBlake2bHex(canonicalJson(contract));
  const version: PackageVersionRecord = {
    namespace: "cellscript",
    name: "demo",
    version: "1.2.3",
    status: "deployed",
    artifact: payload.artifact,
    verification_status: "hash_bound",
    deployment_status: "chain_verified",
    availability_status: "active",
    source_hash: payload.source_hash,
    manifest_hash: payload.manifest_hash,
    capability_key_id: "cap_test",
    principal_type: "joyid_ckb",
    principal_id: `0x${"11".repeat(20)}`,
    registry_entry: payload.registry_entry,
    snapshot_hash: `sha256:${"ab".repeat(32)}`,
    direct_url: "https://registry.cellscript.dev/artifacts/cellscript/demo/releases/1.2.3.json",
    created_at: now.toISOString(),
    registry_environment: "production",
    network: "mainnet",
  };
  store.packageVersions.set("cellscript/demo@1.2.3", version);
  store.packageEvidence.set("cellscript/demo@1.2.3:deployed:test", {
    namespace: "cellscript",
    name: "demo",
    version: "1.2.3",
    kind: "deployed",
    evidence_hash: `sha256:${"cd".repeat(32)}`,
    evidence: {
      network: "mainnet",
      code_hash: codeHash,
      data_hash: codeHash,
      hash_type: "data1",
      dep_type: "code",
    },
    request_id: "test",
    admin_actor: "test",
    created_at: now.toISOString(),
  });
  store.snapshots.set(version.snapshot_hash, {
    snapshot_hash: version.snapshot_hash,
    r2_key: "source-snapshots/cellscript/demo/1.2.3/bundle.json",
    source_hash: version.source_hash,
    size_bytes: 1,
    content_type: "application/vnd.cellscript.artifact-bundle+json",
  });
  const bundle = JSON.stringify({
    schema: "cellscript-registry-bundle",
    namespace: "cellscript",
    name: "demo",
    release: "1.2.3",
    profile: "ckb_executable",
    manifest_json: canonicalJson(contract),
    objects: [
      { role: "source", content_base64: base64("source") },
      { role: "executable", content_base64: base64("binary") },
      { role: "abi", content_base64: Buffer.from(idlBytes).toString("base64") },
    ],
  });
  const app = createApp({
    store,
    registryObjectReader: {
      async get(key) {
        expect(key).toBe("source-snapshots/cellscript/demo/1.2.3/bundle.json");
        return { body: bundle, contentType: "application/json" };
      },
    },
  });
  return { app, codeHash, digest, idl };
}

describe("registry api", () => {
  it("serves exact LS-IDL bytes by chain-verified code hash without JSON reserialization", async () => {
    const idl = "{\n  \"witness\": [{\"name\":\"signature\",\"type\":\"secp256k1_sig\",\"required\":true}]\n}\n";
    const { app, codeHash, digest } = await lsIdlLookupApp(new TextEncoder().encode(idl));

    const compatibility = await get(app, `/idl/${codeHash.slice(2)}`);
    expect(compatibility.status).toBe(200);
    expect(await compatibility.text()).toBe(idl);
    expect(compatibility.headers.get("x-ls-idl-sha256")).toBe(digest);
    expect(compatibility.headers.get("x-ls-idl-verification")).toBe("schema-and-suffix-bound");

    const formal = await get(app, `/v1/ckb/scripts/${codeHash}/interfaces/ls-idl?hash_type=data1&data_hash=${codeHash}`);
    expect(formal.status).toBe(200);
    expect(await formal.text()).toBe(idl);
  });

  it.runIf(Boolean(process.env.CELLSCRIPT_CKB_IDL_CLIENT_REPO))(
    "interoperates with the pinned upstream Rust client over the compatibility route",
    async () => {
      const upstreamClientRepo = String(process.env.CELLSCRIPT_CKB_IDL_CLIENT_REPO);
      const encodedFixture = await readFile(
        new URL("../../../tests/compat/ls_idl/scripts/simple-lock.idl.json.b64", import.meta.url),
        "utf8",
      );
      const idlBytes = Buffer.from(encodedFixture.replace(/\s/g, ""), "base64");
      const { app, codeHash } = await lsIdlLookupApp(idlBytes);
      const server = createServer(async (request, response) => {
        try {
          const registryResponse = await app.fetch(
            new Request(`http://127.0.0.1${request.url ?? "/"}`),
            { REGISTRY_ORIGIN: DEFAULT_REGISTRY_ORIGIN },
          );
          const headers: Record<string, string> = {};
          registryResponse.headers.forEach((value, name) => { headers[name] = value; });
          response.writeHead(registryResponse.status, headers);
          response.end(Buffer.from(await registryResponse.arrayBuffer()));
        } catch (error) {
          response.writeHead(500, { "content-type": "text/plain" });
          response.end(error instanceof Error ? error.message : "Registry bridge failed");
        }
      });
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Registry bridge did not bind a TCP port");

      const temporaryProject = await mkdtemp(join(tmpdir(), "cellscript-ls-idl-upstream-"));
      try {
        await writeFile(
          join(temporaryProject, "Cargo.toml"),
          `[package]\nname = "cellscript-ls-idl-upstream-probe"\nversion = "0.0.0"\nedition = "2024"\n\n[[bin]]\nname = "cellscript-ls-idl-upstream-probe"\npath = "main.rs"\n\n[dependencies]\nckb-idl-client = { path = ${JSON.stringify(upstreamClientRepo)} }\nhex = "0.4"\nsha2 = "0.11.0"\ntokio = { version = "1", features = ["rt-multi-thread", "macros"] }\n`,
        );
        await writeFile(
          join(temporaryProject, "main.rs"),
          `use ckb_idl_client::IdlClient;\nuse sha2::{Digest as _, Sha256};\n\n#[tokio::main]\nasync fn main() -> Result<(), Box<dyn std::error::Error>> {\n    let arguments: Vec<String> = std::env::args().collect();\n    let base_url = &arguments[1];\n    let code_hash_bytes = hex::decode(&arguments[2])?;\n    let code_hash: [u8; 32] = code_hash_bytes.try_into().map_err(|_| std::io::Error::other("code hash must be 32 bytes"))?;\n    let idl_path = &arguments[3];\n\n    let mut client = IdlClient::new();\n    let document = client.fetch(base_url, code_hash).await?;\n    assert_eq!(document.witness.len(), 1);\n    assert_eq!(document.witness[0].name, "preimage");\n    assert_eq!(document.witness[0].type_, "bytes");\n\n    let expected_idl_bytes = std::fs::read(idl_path)?;\n    let raw_url = format!("{}/idl/{}", base_url, hex::encode(code_hash));\n    let fetched_idl_bytes = client.http.get(raw_url).send().await?.bytes().await?;\n    assert_eq!(fetched_idl_bytes.as_ref(), expected_idl_bytes.as_slice());\n    let mut code_cell_data = b"fixture executable".to_vec();\n    code_cell_data.extend_from_slice(&Sha256::digest(&expected_idl_bytes));\n    client.verify(code_hash, &fetched_idl_bytes, &code_cell_data)?;\n\n    let cached = client.witness_requirements(base_url, code_hash).await?;\n    assert_eq!(cached, document.witness);\n    let decoded = client.validate_witness_bytes(&cached, &[5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'])?;\n    assert_eq!(decoded.len(), 1);\n    println!("upstream client fetch, SHA-256 verify, cache, and witness decode passed");\n    Ok(())\n}\n`,
        );
        const idlPath = join(temporaryProject, "simple-lock.idl.json");
        await writeFile(idlPath, idlBytes);
        const targetDir = process.env.CELLSCRIPT_LS_IDL_CARGO_TARGET_DIR ?? join(temporaryProject, "target");
        const result = await execFileAsync(
          "cargo",
          [
            "run",
            "--quiet",
            "--manifest-path",
            join(temporaryProject, "Cargo.toml"),
            "--target-dir",
            targetDir,
            "--",
            `http://127.0.0.1:${address.port}`,
            codeHash.slice(2),
            idlPath,
          ],
          { env: process.env, maxBuffer: 1024 * 1024 },
        );
        expect(result.stdout).toContain("upstream client fetch, SHA-256 verify, cache, and witness decode passed");
      } finally {
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
        await rm(temporaryProject, { recursive: true, force: true });
      }
    },
    180_000,
  );

  it("matches the canonical CKB Molecule Script hash", () => {
    expect(ckbScriptHash({
      code_hash: `0x${"11".repeat(32)}`,
      hash_type: "type",
      args: "0x1234",
    })).toBe("0x6106e30cbb34d68302798abf8259e5a6e0adbbd73c7f3dfe1c96ada1f6c00cee");
  });

  it("treats edition and compatibility profile as independent registry axes", async () => {
    const first = await publishPayload("profile-axis-test");
    const second = structuredClone(first);
    second.registry_entry.versions[0].compatibility_profile_hash = "12".repeat(32);

    const firstValidated = validatePublishPayload(first, DEFAULT_REGISTRY_ORIGIN, now);
    const secondValidated = validatePublishPayload(second, DEFAULT_REGISTRY_ORIGIN, now);

    expect(firstValidated.registry_entry.versions[0].edition).toBe("2026");
    expect(secondValidated.registry_entry.versions[0].edition).toBe("2026");
    expect(secondValidated.registry_entry.versions[0].compatibility_profile_hash)
      .not.toBe(firstValidated.registry_entry.versions[0].compatibility_profile_hash);
  });

  it("accepts the versioned typed temporal interface and rejects contract drift", async () => {
    const payload = await publishPayload("temporal-interface-test");
    const published = payload.registry_entry.versions[0];
    const temporal = {
      schema: "cellscript-ckb-temporal-interface-v1",
      wire_representation: "fixed-u64-register-and-little-endian-wire",
      since_abi: "ckb-since-rfc0017-typed-v1",
      constructors: [
        "ckb::since_absolute_block(u64)->AbsoluteBlockSince",
        "ckb::since_absolute_epoch(u64,u64,u64)->AbsoluteEpochSince",
        "ckb::since_absolute_timestamp(u64-seconds)->AbsoluteTimestampSince",
        "ckb::since_relative_block(u64)->RelativeBlockSince",
        "ckb::since_relative_epoch(u64,u64,u64)->RelativeEpochSince",
        "ckb::since_relative_timestamp(u64-seconds)->RelativeTimestampSince",
      ],
      decoder: "ckb::since_decode(EncodedSince)->DecodedSince;ckb::since_from_raw_checked(u64)->DecodedSince",
      domains: [
        "EpochNumber",
        "EpochDuration",
        "BlockNumber",
        "EpochLength",
        "TimestampMillis",
        "EncodedSince",
        "DecodedSince",
        "AbsoluteBlockSince",
        "AbsoluteEpochSince",
        "AbsoluteTimestampSince",
        "RelativeBlockSince",
        "RelativeEpochSince",
        "RelativeTimestampSince",
      ],
      migration: "legacy-raw-ckb-temporal-to-explicit-typed-v1",
    };
    const interfaceV3 = {
      ...published.interface,
      schema: "cellscript-package-interface-v3",
      version: 3,
      runtime_contract: { temporal },
    };
    published.interface = interfaceV3;
    published.interface_hash = ckbBlake2bHex(canonicalJson(interfaceV3));
    expect(validatePublishPayload(payload, DEFAULT_REGISTRY_ORIGIN, now).registry_entry.versions[0].interface)
      .toEqual(interfaceV3);

    const drifted = structuredClone(payload);
    const driftedInterface = drifted.registry_entry.versions[0].interface as Record<string, unknown>;
    const runtime = driftedInterface.runtime_contract as Record<string, unknown>;
    const driftedTemporal = runtime.temporal as Record<string, unknown>;
    driftedTemporal.since_abi = "unchecked";
    drifted.registry_entry.versions[0].interface_hash = ckbBlake2bHex(canonicalJson(driftedInterface));
    expect(() => validatePublishPayload(drifted, DEFAULT_REGISTRY_ORIGIN, now)).toThrow(/temporal.since_abi/);
  });

  it("reports readiness only when production bindings are configured", async () => {
    const app = createApp();
    const live = await get(app, "/health");
    expect(live.status).toBe(200);
    expect(await live.json()).toMatchObject({ status: "ok" });
    const missing = await get(app, "/ready");
    expect(missing.status).toBe(503);
    expect(await missing.json()).toMatchObject({
      status: "not_ready",
      checks: {
        store: "missing_hyperdrive",
        object_store: "missing_r2",
        admin_token: "missing_secret",
      },
    });

    const readyApp = createApp({
      store: new MemoryRegistryStore(),
      snapshotWriter: { async put() {} },
      registryObjectReader: { async get() { return null; } },
      readinessCheck: async () => ({ runtime: "ready" }),
    });
    const ready = await get(readyApp, "/ready", { REGISTRY_ADMIN_TOKEN: "secret" });
    expect(ready.status).toBe(200);
    expect(ready.headers.get("content-security-policy"))
      .toBe("default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    expect(ready.headers.get("permissions-policy")).toBe("camera=(), geolocation=(), microphone=()");
    expect(ready.headers.get("strict-transport-security")).toBe("max-age=31536000");
    expect(ready.headers.get("x-frame-options")).toBe("DENY");
    expect(ready.headers.get("x-permitted-cross-domain-policies")).toBe("none");
    expect(await ready.json()).toMatchObject({
      status: "ready",
      checks: {
        store: "ready",
        object_store: "configured",
        admin_token: "configured",
        runtime: "ready",
      },
    });

    const partiallyConfigured = await get(readyApp, "/ready", {
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_TYPE_SCRIPT_JSON: JSON.stringify({ code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" }),
    });
    expect(partiallyConfigured.status).toBe(503);
    expect(await partiallyConfigured.json()).toMatchObject({
      status: "not_ready",
      checks: { registry_commitment: "misconfigured" },
    });

    const typeScript = { code_hash: `0x${"11".repeat(32)}`, hash_type: "data1", args: "0x01" };
    const commitmentLock = { code_hash: `0x${"22".repeat(32)}`, hash_type: "type", args: "0x02" };
    const typeCellDep = {
      out_point: { tx_hash: `0x${"33".repeat(32)}`, index: "0x0" },
      dep_type: "code",
    };
    const lockCellDep = {
      out_point: { tx_hash: `0x${"44".repeat(32)}`, index: "0x0" },
      dep_type: "code",
    };
    let configurationChecked = false;
    const commitmentReadyApp = createApp({
      store: new MemoryRegistryStore(),
      snapshotWriter: { async put() {} },
      registryObjectReader: { async get() { return null; } },
      verifyRegistryCommitmentConfiguration: async (configuration) => {
        configurationChecked = true;
        expect(configuration.type_script_hash).toBe(ckbScriptHash(typeScript));
        expect(configuration.commitment_lock_hash).toBe(ckbScriptHash(commitmentLock));
      },
    });
    const configured = await get(commitmentReadyApp, "/ready", {
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_TYPE_SCRIPT_JSON: JSON.stringify(typeScript),
      REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON: JSON.stringify(typeCellDep),
      REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON: JSON.stringify(commitmentLock),
      REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON: JSON.stringify(lockCellDep),
    });
    expect(configured.status).toBe(200);
    expect(configurationChecked).toBe(true);
    expect(await configured.json()).toMatchObject({
      status: "ready",
      checks: { registry_commitment: "configured_and_live" },
    });

    const nonCanonicalProduction = await get(commitmentReadyApp, "/ready", {
      ENVIRONMENT: "production",
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_TYPE_SCRIPT_JSON: JSON.stringify(typeScript),
      REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON: JSON.stringify(typeCellDep),
      REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON: JSON.stringify(commitmentLock),
      REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON: JSON.stringify(lockCellDep),
    });
    expect(nonCanonicalProduction.status).toBe(503);
    expect(await nonCanonicalProduction.json()).toMatchObject({
      status: "not_ready",
      checks: { registry_commitment: "misconfigured" },
    });

    const canonicalLock = { ...CKB_MAINNET_SIGHASH_LOCK, args: `0x${"55".repeat(20)}` };
    const canonicalTypeScript = {
      ...CANONICAL_REGISTRY_TYPE_SCRIPT,
      args: ckbScriptHash(canonicalLock),
    };
    const canonicalTypeCellDep = {
      out_point: { tx_hash: `0x${"66".repeat(32)}`, index: "0x0" },
      dep_type: "code",
    };
    let canonicalConfigurationChecked = false;
    const productionCommitmentApp = createApp({
      store: new MemoryRegistryStore(),
      snapshotWriter: { async put() {} },
      registryObjectReader: { async get() { return null; } },
      verifyRegistryCommitmentConfiguration: async () => {
        canonicalConfigurationChecked = true;
      },
    });
    const canonicalProduction = await get(productionCommitmentApp, "/ready", {
      ENVIRONMENT: "production",
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_TYPE_SCRIPT_JSON: JSON.stringify(canonicalTypeScript),
      REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON: JSON.stringify(canonicalTypeCellDep),
      REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON: JSON.stringify(canonicalLock),
      REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON: JSON.stringify(CKB_MAINNET_SIGHASH_DEP_GROUP),
    });
    expect(canonicalProduction.status).toBe(200);
    expect(canonicalConfigurationChecked).toBe(true);

    const invalidReproducerPolicy = await get(commitmentReadyApp, "/ready", {
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_REPRODUCER_POLICY_JSON: JSON.stringify({
        schema: "cellscript-reproducer-policy-v1",
        minimum_trust_domains: 2,
        builders: [
          { builder_id: "builder-a", trust_domain: "same-operator", public_key: reproducerPublicKeys["builder-a"] },
          { builder_id: "builder-b", trust_domain: "same-operator", public_key: reproducerPublicKeys["builder-b"] },
        ],
      }),
    });
    expect(invalidReproducerPolicy.status).toBe(503);
    expect(await invalidReproducerPolicy.json()).toMatchObject({
      status: "not_ready",
      checks: { reproducer_policy: "misconfigured" },
    });
  });

  it("rejects JoyID signatures that do not bind the canonical capability payload", async () => {
    const { app } = testApp();
    const payload = authPayload();
    const response = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload, "different challenge"),
    });

    expect(response.status).toBe(401);
    const body = await response.json() as any;
    expect(body.error.code).toBe("joyid_challenge_mismatch");
  });

  it("rejects empty, duplicate, and unknown capability scopes", async () => {
    for (const [requestedScopes, expectedCode] of [
      [[], "invalid_scope"],
      [["publish:cellscript/demo", "publish:cellscript/demo"], "duplicate_scope"],
      [["admin:cellscript/demo"], "invalid_scope"],
    ] as const) {
      const { app } = testApp();
      const payload = { ...authPayload(), requested_scopes: [...requestedScopes] };
      const response = await post(app, "/v1/capabilities", {
        payload,
        joyid_signature: joyidSignature(payload),
      });
      expect(response.status).toBe(400);
      expect((await response.json() as any).error.code).toBe(expectedCode);
    }
  });

  it("rejects JoyID signatures whose signer does not match principal_id", async () => {
    const { app } = testApp();
    const payload = authPayload("0x1111111111111111111111111111111111111111");
    const response = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload, canonicalJson(payload), "2222222222222222222222222222222222222222"),
    });

    expect(response.status).toBe(401);
    const body = await response.json() as any;
    expect(body.error.code).toBe("joyid_principal_mismatch");
  });

  it("does not let invalid JoyID signatures consume principal quota", async () => {
    const store = new MemoryRegistryStore();
    const app = createApp({
      store,
      now: () => now,
      joyidVerifier: { verifySignature: async () => false },
      capabilityVerifier: { verify: async () => true },
      snapshotWriter: {
        async put() {},
      },
    });
    const payload = authPayload();
    const response = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });

    expect(response.status).toBe(401);
    expect((await response.json() as any).error.code).toBe("joyid_signature_invalid");
    expect(store.quotaEvents.some((event) => event.quotaKey === `principal:${payload.principal_type}:${payload.principal_id}`)).toBe(false);
  });

  it("accepts hashed JoyID principal bindings", async () => {
    const { app } = testApp();
    const pubkey = "33".repeat(32);
    const principalId = await joyidPrincipalIdFromBinding("main_key", pubkey);
    const payload = authPayload(principalId);
    const response = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload, canonicalJson(payload), pubkey),
    });

    expect(response.status).toBe(201);
    const body = await response.json() as any;
    expect(body.principal_id).toBe(principalId);
  });

  it("accepts a capability authorised by a standard CKB secp256k1 wallet", async () => {
    const { app } = testApp();
    const payload = await ckbAuthPayload();
    const response = await post(app, "/v1/capabilities", {
      payload,
      wallet_signature: ckbWalletSignature(payload),
    });

    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      principal_type: "ckb_secp256k1",
      principal_id: payload.principal_id,
      status: "active",
    });
  });

  it("completes a short-lived CLI-to-browser authorisation session without exposing the poll result", async () => {
    const { app, store } = testApp();
    const createdResponse = await post(app, "/v1/authorisation-sessions", {
      capability_pubkey: reproducerPublicKeys["builder-a"],
      requested_scopes: ["publish:walletdemo/demo"],
      artifact_kind: "source_library",
      capability_expires_at: "2026-09-21T12:00:00Z",
      cli_version: "0.23.0",
    });
    expect(createdResponse.status).toBe(201);
    const created = await createdResponse.json() as any;
    const browserUrl = new URL(created.browser_url);
    const browserParams = new URLSearchParams(browserUrl.hash.slice(1));
    const browserToken = browserParams.get("browser_token");
    expect(browserUrl.origin + browserUrl.pathname).toBe("https://cellscript.dev/registry/submit");
    expect(browserParams.get("authorisation_session")).toBe(created.session_id);
    expect(browserToken).toMatch(/^browser_[0-9a-f]{32}$/);

    const publicPending = await get(app, `/v1/authorisation-sessions/${created.session_id}`);
    expect(publicPending.status).toBe(401);
    const browserPending = await get(app, `/v1/authorisation-sessions/${created.session_id}`, {}, {
      authorization: `Bearer ${browserToken}`,
    });
    expect(await browserPending.json()).not.toHaveProperty("capability_key_id");

    const wallet = await ckbAuthPayload();
    const challengeResponse = await post(app, `/v1/authorisation-sessions/${created.session_id}/challenge`, {
      principal_type: wallet.principal_type,
      principal_id: wallet.principal_id,
    }, {}, { authorization: `Bearer ${browserToken}` });
    expect(challengeResponse.status).toBe(200);
    const challenge = await challengeResponse.json() as any;
    expect(challenge.payload).toMatchObject({
      principal_type: "ckb_secp256k1",
      principal_id: wallet.principal_id,
      requested_scopes: ["publish:walletdemo/demo"],
      capability_pubkey: reproducerPublicKeys["builder-a"],
    });

    const completeResponse = await post(app, `/v1/authorisation-sessions/${created.session_id}/complete`, {
      challenge_token: challenge.challenge_token,
      wallet_signature: ckbWalletSignature(challenge.payload),
    }, {}, { authorization: `Bearer ${browserToken}` });
    expect(completeResponse.status).toBe(201);
    expect(await completeResponse.json()).toMatchObject({ status: "authorised", namespace_status: "active" });

    const browserComplete = await get(app, `/v1/authorisation-sessions/${created.session_id}`, {}, {
      authorization: `Bearer ${browserToken}`,
    });
    expect(await browserComplete.json()).not.toHaveProperty("capability_key_id");
    const cliPoll = await get(app, `/v1/authorisation-sessions/${created.session_id}`, {}, {
      authorization: `Bearer ${created.poll_token}`,
    });
    expect(await cliPoll.json()).toMatchObject({
      status: "authorised",
      namespace_status: "active",
      capability_key_id: await capabilityKeyId(reproducerPublicKeys["builder-a"]),
    });
    expect(store.namespaces.get("walletdemo")).toMatchObject({
      owner_principal_type: "ckb_secp256k1",
      owner_principal_id: wallet.principal_id,
    });
  });

  it("expires browser authorisation sessions without creating Registry authority", async () => {
    const store = new MemoryRegistryStore();
    const { app } = testApp(store);
    const { created, browserToken } = await createBrowserAuthorisationSession(app);
    const expiredApp = testApp(store, undefined, {
      now: () => new Date("2026-06-23T12:16:00Z"),
    }).app;

    const response = await get(expiredApp, `/v1/authorisation-sessions/${created.session_id}`, {}, {
      authorization: `Bearer ${browserToken}`,
    });

    expect(response.status).toBe(410);
    expect(await response.json()).toMatchObject({ error: { code: "authorisation_session_expired" } });
    expect(store.capabilities.size).toBe(0);
    expect(store.namespaces.size).toBe(0);
    expect(store.usedNonces.size).toBe(0);
  });

  it("keeps a completed authorisation session readable after its approval window closes", async () => {
    const store = new MemoryRegistryStore();
    const { app } = testApp(store);
    const { created, browserToken } = await createBrowserAuthorisationSession(app, "terminalread", "demo");
    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);
    const completed = await completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge);
    expect(completed.status).toBe(201);

    const afterExpiry = testApp(store, undefined, {
      now: () => new Date("2026-06-23T12:16:00Z"),
    }).app;
    const poll = await get(afterExpiry, `/v1/authorisation-sessions/${created.session_id}`, {}, {
      authorization: `Bearer ${created.poll_token}`,
    });

    expect(poll.status).toBe(200);
    expect(await poll.json()).toMatchObject({
      status: "authorised",
      namespace_status: "active",
      capability_key_id: await capabilityKeyId(reproducerPublicKeys["builder-a"]),
    });

    const retained = await store.cleanupExpiredState({
      now_iso: "2026-06-23T12:16:00.000Z",
      quota_events_before_iso: "2026-06-22T12:16:00.000Z",
    });
    expect(retained.authorisation_sessions_deleted).toBe(0);
    expect(await store.getAuthorisationSession(created.session_id)).not.toBeNull();

    const purged = await store.cleanupExpiredState({
      now_iso: "2026-06-24T12:01:00.000Z",
      quota_events_before_iso: "2026-06-23T12:01:00.000Z",
    });
    expect(purged.authorisation_sessions_deleted).toBe(1);
    expect(await store.getAuthorisationSession(created.session_id)).toBeNull();
  });

  it("rejects browser, poll, and challenge token substitution", async () => {
    const { app, store } = testApp();
    const { created, browserToken } = await createBrowserAuthorisationSession(app);
    const wrongSessionToken = await get(app, `/v1/authorisation-sessions/${created.session_id}`, {}, {
      authorization: "Bearer browser_00000000000000000000000000000000",
    });
    expect(wrongSessionToken.status).toBe(401);

    const pollAsBrowser = await post(app, `/v1/authorisation-sessions/${created.session_id}/challenge`, {
      principal_type: "ckb_secp256k1",
      principal_id: `0x${"11".repeat(20)}`,
    }, {}, { authorization: `Bearer ${created.poll_token}` });
    expect(pollAsBrowser.status).toBe(401);

    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);
    const wrongChallenge = await post(app, `/v1/authorisation-sessions/${created.session_id}/complete`, {
      challenge_token: "challenge_00000000000000000000000000000000",
      wallet_signature: ckbWalletSignature(challenge.payload),
    }, {}, { authorization: `Bearer ${browserToken}` });
    expect(wrongChallenge.status).toBe(401);
    expect(await wrongChallenge.json()).toMatchObject({ error: { code: "invalid_authorisation_challenge_token" } });
    expect(store.capabilities.size).toBe(0);
    expect(store.namespaces.size).toBe(0);
    expect(store.usedNonces.size).toBe(0);
  });

  it("treats a completed challenge replay as an idempotent session read", async () => {
    const { app, store } = testApp();
    const { created, browserToken } = await createBrowserAuthorisationSession(app);
    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);

    const first = await completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge);
    const replay = await completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge);

    expect(first.status).toBe(201);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ status: "authorised", namespace_status: "active" });
    expect(store.capabilities.size).toBe(1);
    expect(store.namespaces.size).toBe(1);
    expect(store.usedNonces.size).toBe(1);
    expect(store.auditEvents.filter((event) => event.event_type === "authorisation_session.completed")).toHaveLength(1);
  });

  it("serialises concurrent complete calls into one atomic authorisation", async () => {
    const { app, store } = testApp();
    const { created, browserToken } = await createBrowserAuthorisationSession(app, "concurrent", "demo");
    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);

    const responses = await Promise.all([
      completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge),
      completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge),
    ]);
    const statuses = responses.map((response) => response.status).sort();
    const bodies = await Promise.all(responses.map((response) => response.json()));

    expect(statuses).toEqual([200, 201]);
    expect(bodies).toEqual([
      expect.objectContaining({ status: "authorised", namespace_status: "active" }),
      expect.objectContaining({ status: "authorised", namespace_status: "active" }),
    ]);
    expect(store.capabilities.size).toBe(1);
    expect(store.namespaces.size).toBe(1);
    expect(store.usedNonces.size).toBe(1);
    expect(store.auditEvents.filter((event) => event.event_type === "capability.created")).toHaveLength(1);
    expect(store.auditEvents.filter((event) => event.event_type === "authorisation_session.completed")).toHaveLength(1);
  });

  it("rolls back capability, namespace, nonce, and session changes when completion fails", async () => {
    const { app, store } = testApp();
    const { created, browserToken } = await createBrowserAuthorisationSession(app, "rollback", "demo");
    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);
    const appendAuditEvent = store.appendAuditEvent.bind(store);
    vi.spyOn(store, "appendAuditEvent").mockImplementation(async (event) => {
      if (event.event_type === "authorisation_session.completed") throw new Error("injected completion failure");
      await appendAuditEvent(event);
    });

    const response = await completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge);

    expect(response.status).toBe(500);
    expect(store.capabilities.size).toBe(0);
    expect(store.namespaces.size).toBe(0);
    expect(store.usedNonces.size).toBe(0);
    expect(store.authorisationSessions.get(created.session_id)).toMatchObject({ status: "pending" });
    expect(store.authorisationSessions.get(created.session_id)?.capability_key_id).toBeFalsy();
    expect(store.auditEvents.some((event) => event.event_type === "capability.created")).toBe(false);
    expect(store.auditEvents.some((event) => event.event_type === "namespace.claimed")).toBe(false);
  });

  it("keeps a session pending when another identity owns its namespace", async () => {
    const { app, store } = testApp();
    const { created, browserToken } = await createBrowserAuthorisationSession(app, "occupied", "demo");
    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);
    store.namespaces.set("occupied", {
      namespace: "occupied",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: `0x${"44".repeat(20)}`,
    });

    const response = await completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge);

    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: { code: "namespace_already_claimed" } });
    expect(store.capabilities.size).toBe(0);
    expect(store.usedNonces.size).toBe(0);
    expect(store.authorisationSessions.get(created.session_id)).toMatchObject({ status: "pending" });
    expect(store.authorisationSessions.get(created.session_id)?.capability_key_id).toBeFalsy();
  });

  it("records review_pending atomically for a namespace that requires review", async () => {
    const { app, store } = testApp();
    const { created, browserToken } = await createBrowserAuthorisationSession(app, "abc", "demo");
    const challenge = await prepareBrowserAuthorisationChallenge(app, created.session_id, browserToken);

    const response = await completeBrowserAuthorisationSession(app, created.session_id, browserToken, challenge);

    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({ status: "review_pending", namespace_status: "review_pending" });
    expect(store.capabilities.size).toBe(1);
    expect(store.usedNonces.size).toBe(1);
    expect(store.namespaces.get("abc")).toMatchObject({ status: "review_pending", review_reason: "short_namespace_review" });
    expect(store.authorisationSessions.get(created.session_id)).toMatchObject({
      status: "review_pending",
      namespace_status: "review_pending",
    });
  });

  it("checks an existing capability against its exact artifact and namespace owner", async () => {
    const { app, store } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(capabilityResponse.status).toBe(201);
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: payload.principal_type,
      owner_principal_id: payload.principal_id,
    });

    const ready = await get(app, `/v1/capabilities/${capability.key_id}/check?namespace=cellscript&name=demo`);
    expect(ready.status).toBe(200);
    expect(await ready.json()).toMatchObject({
      schema: "cellscript-registry-capability-check-v1",
      key_id: capability.key_id,
      status: "active",
      namespace: {
        name: "cellscript",
        status: "active",
        owned_by_capability_principal: true,
      },
      allows: { publish: true, deployment: true, availability: true },
      usable_for_publish: true,
      reasons: [],
    });

    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: payload.principal_type,
      owner_principal_id: "0x2222222222222222222222222222222222222222",
    });
    const wrongOwner = await get(app, `/v1/capabilities/${capability.key_id}/check?namespace=cellscript&name=demo`);
    expect(await wrongOwner.json()).toMatchObject({
      namespace: { owned_by_capability_principal: false },
      usable_for_publish: false,
      reasons: ["namespace_owner_mismatch"],
    });

    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: payload.principal_type,
      owner_principal_id: payload.principal_id,
    });
    const storedCapability = store.capabilities.get(capability.key_id)!;
    storedCapability.scopes = ["deployment:cellscript/demo"];
    const missingScope = await get(app, `/v1/capabilities/${capability.key_id}/check?namespace=cellscript&name=demo`);
    expect(await missingScope.json()).toMatchObject({
      allows: { publish: false, deployment: true, availability: false },
      usable_for_publish: false,
      reasons: ["publish_scope_missing"],
    });

    storedCapability.scopes = [...payload.requested_scopes];
    storedCapability.expires_at = "2026-06-23T11:59:59Z";
    const expired = await get(app, `/v1/capabilities/${capability.key_id}/check?namespace=cellscript&name=demo`);
    expect(await expired.json()).toMatchObject({
      status: "expired",
      usable_for_publish: false,
      reasons: ["capability_expired"],
    });

    storedCapability.expires_at = "not-a-timestamp";
    const invalidExpiry = await get(app, `/v1/capabilities/${capability.key_id}/check?namespace=cellscript&name=demo`);
    expect(await invalidExpiry.json()).toMatchObject({
      status: "expired",
      usable_for_publish: false,
      reasons: ["capability_expiry_invalid"],
    });

    storedCapability.expires_at = payload.capability_expires_at;
    storedCapability.revoked_at = "2026-06-23T11:59:59Z";
    const revoked = await get(app, `/v1/capabilities/${capability.key_id}/check?namespace=cellscript&name=demo`);
    expect(await revoked.json()).toMatchObject({
      status: "revoked",
      usable_for_publish: false,
      reasons: ["capability_revoked"],
    });
  });

  it("rejects malformed or unknown capability IDs from the check route", async () => {
    const { app } = testApp();
    const malformed = await get(app, "/v1/capabilities/not-a-capability/check?namespace=cellscript&name=demo");
    expect(malformed.status).toBe(400);
    expect((await malformed.json() as any).error.code).toBe("invalid_capability_key_id");

    const missing = await get(app, "/v1/capabilities/cap_11111111111111111111111111111111/check?namespace=cellscript&name=demo");
    expect(missing.status).toBe(404);
    expect((await missing.json() as any).error.code).toBe("capability_not_found");
  });

  it("lets a standard CKB wallet claim a namespace and revoke its capability", async () => {
    const { app, store } = testApp();
    const payload = await ckbAuthPayload();
    payload.requested_scopes = ["publish:walletdemo/demo"];
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      wallet_signature: ckbWalletSignature(payload),
    });
    expect(capabilityResponse.status).toBe(201);
    const capability = await capabilityResponse.json() as any;

    const claimResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "walletdemo",
      payload,
      wallet_signature: ckbWalletSignature(payload),
    });
    expect(claimResponse.status).toBe(201);
    expect(await claimResponse.json()).toMatchObject({
      namespace: "walletdemo",
      status: "active",
    });
    expect(store.namespaces.get("walletdemo")).toMatchObject({
      owner_principal_type: "ckb_secp256k1",
      owner_principal_id: payload.principal_id,
    });

    const revoke: CapabilityRevocationPayload = {
      ...revokePayload(capability.key_id, payload.principal_id),
      principal_type: "ckb_secp256k1",
    };
    const revokeResponse = await post(app, `/v1/capabilities/${capability.key_id}/revoke`, {
      payload: revoke,
      wallet_signature: ckbWalletSignature(revoke),
      reason: "rotated",
    });
    expect(revokeResponse.status).toBe(200);
    expect((await revokeResponse.json() as any).status).toBe("revoked");
    expect(store.capabilities.get(capability.key_id)?.revoked_at).toBeTruthy();
  });

  it("rejects a CKB wallet signature whose public key is not the payload principal", async () => {
    const { app } = testApp();
    const payload = await ckbAuthPayload();
    payload.principal_id = `0x${"44".repeat(32)}`;
    const response = await post(app, "/v1/capabilities", {
      payload,
      wallet_signature: ckbWalletSignature(payload),
    });

    expect(response.status).toBe(401);
    expect((await response.json() as any).error.code).toBe("ckb_principal_mismatch");
  });

  it("creates a capability, claims namespace, stores snapshot, and admits source_published publish", async () => {
    const { app, store, snapshots } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(capabilityResponse.status).toBe(201);
    const capability = await capabilityResponse.json() as any;
    expect(capability.key_id).toBe(await capabilityKeyId(payload.capability_pubkey));

    const claimResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "cellscript",
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(claimResponse.status).toBe(202);
    expect((await claimResponse.json() as any).status).toBe("review_pending");

    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const publish = await publishPayload(capability.key_id);
    const publishResponse = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });

    expect(publishResponse.status).toBe(202);
    const body = await publishResponse.json() as any;
    expect(body).toMatchObject({
      verification_status: "pending",
      deployment_status: "not_applicable",
      availability_status: "active",
    });
    expect(body.direct_url).toBe("https://registry.cellscript.dev/artifacts/cellscript/demo/releases/1.2.3.json");
    expect(snapshots).toHaveLength(2);
    const sourceSnapshot = snapshots.find((snapshot) => snapshot.key.startsWith("source-snapshots/"));
    const staticEntry = snapshots.find((snapshot) => snapshot.key === "artifacts/cellscript/demo/releases/1.2.3.json");
    expect(sourceSnapshot?.key).toContain("source-snapshots/cellscript/demo/1.2.3/");
    expect(staticEntry).toBeTruthy();
    const staticBody = JSON.parse(utf8(staticEntry!.body)) as any;
    expect(staticBody.kind).toBe("cellscript.registry.artifact_release");
    expect(staticBody.schema_version).toBe(1);
    expect(staticBody.coordinate).toBe("cellscript/demo@1.2.3");
    expect(staticBody).toMatchObject({
      verification_status: "pending",
      deployment_status: "not_applicable",
      availability_status: "active",
    });
    expect(staticBody.edition).toBe("2026");
    expect(staticBody.compatibility_profile_hash).toBe("ef".repeat(32));
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("source_published");
    expect(store.capabilities.get(capability.key_id)?.last_used_at).toBeTruthy();
    expect(store.auditEvents.some((event) => event.event_type === "capability.used" && event.capability_key_id === capability.key_id)).toBe(true);
    expect(store.auditEvents.some((event) => event.event_type === "publish.accepted")).toBe(true);
    expect([...store.verificationJobs.values()]).toHaveLength(1);
    expect([...store.verificationJobs.values()][0]?.status).toBe("queued");
  });

  it("leases verification jobs once, dead-letters terminal failures, and resumes static sync without rebuilding", async () => {
    const { app, store } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });
    const publish = await publishPayload(capability.key_id);
    const publishResponse = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source-snapshot+json",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });
    expect(publishResponse.status).toBe(202);

    const claimTime = new Date().toISOString();
    const first = await store.claimVerificationJob({ worker_id: "worker-a", lease_seconds: 300, now_iso: claimTime });
    expect(first).toMatchObject({ status: "running", attempt_count: 1, lease_owner: "worker-a" });
    expect(await store.claimVerificationJob({ worker_id: "worker-b", lease_seconds: 300, now_iso: claimTime })).toBeNull();

    const dead = await store.failVerificationJob({
      job_id: first!.id,
      worker_id: "worker-a",
      error_code: "compile_rejected",
      error_message: "package does not compile",
      retryable: false,
      retry_after_seconds: 5,
      request_id: "verification:test:1",
    });
    expect(dead.status).toBe("dead_letter");

    const adminEnv = { REGISTRY_ADMIN_TOKEN: "secret" };
    const adminHeaders = { authorization: "Bearer secret", "x-registry-admin-actor": "release-bot" };
    const queue = await get(app, "/v1/admin/verification-queue", adminEnv, adminHeaders);
    expect(queue.status).toBe(200);
    expect(await queue.json()).toMatchObject({ counts: { dead_letter: 1, running: 0 } });
    const retry = await post(app, `/v1/admin/verification-jobs/${first!.id}/retry`, {}, adminEnv, adminHeaders);
    expect(retry.status).toBe(200);
    expect((await retry.json() as any).job.status).toBe("queued");

    const second = await store.claimVerificationJob({
      worker_id: "worker-b",
      lease_seconds: 300,
      now_iso: new Date(Date.now() + 1_000).toISOString(),
    });
    expect(second).toMatchObject({ status: "running", attempt_count: 1, lease_owner: "worker-b" });
    const evidence = {
      schema: "cellscript-registry-evidence-v1",
      kind: "verified_build",
      producer: "test-verifier",
      generated_at: new Date().toISOString(),
      verification_status: "passed",
      verification_level: "compiled",
      source_hash: publish.source_hash,
      manifest_hash: publish.manifest_hash,
      compatibility_profile_hash: publish.registry_entry.versions[0].compatibility_profile_hash,
      artifact_hash: `0x${"31".repeat(32)}`,
      metadata_hash: `0x${"32".repeat(32)}`,
      compiler_version: "0.23.0",
    };
    const promoted = await store.promoteVerifiedBuildForJob({
      job_id: second!.id,
      worker_id: "worker-b",
      evidence_hash: `sha256:${"11".repeat(32)}`,
      evidence,
      request_id: "verification:test:2",
      admin_actor: "verification-worker:test",
    });
    expect(promoted.job.status).toBe("publishing");
    expect(promoted.version.status).toBe("verified_build");

    const staticRetry = await store.failVerificationJob({
      job_id: second!.id,
      worker_id: "worker-b",
      error_code: "static_sync_failed",
      error_message: "object store unavailable",
      retryable: true,
      retry_after_seconds: 5,
      request_id: "verification:test:2",
    });
    expect(staticRetry).toMatchObject({ status: "retry_wait", attempt_count: 1, evidence_hash: `sha256:${"11".repeat(32)}` });
    const resumed = await store.claimVerificationJob({
      worker_id: "worker-c",
      lease_seconds: 300,
      now_iso: new Date(Date.now() + 10_000).toISOString(),
    });
    expect(resumed).toMatchObject({ status: "publishing", attempt_count: 2, lease_owner: "worker-c" });
    const completed = await store.completeVerificationJob({ job_id: resumed!.id, worker_id: "worker-c" });
    expect(completed.status).toBe("succeeded");
    expect((await store.getVerificationQueueMetrics()).counts.succeeded).toBe(1);
  });

  it("serves package-version JSON from the static registry read path without the write store", async () => {
    const app = createApp({
      registryObjectReader: {
        async get(key) {
          expect(key).toBe("artifacts/cellscript/demo/releases/1.2.3.json");
          return {
            body: JSON.stringify({ schema_version: 1, coordinate: "cellscript/demo@1.2.3", status: "source_published" }),
            contentType: "application/json; charset=utf-8",
            etag: "\"static-entry\"",
          };
        },
      },
    });

    const response = await app.fetch(new Request("https://registry.cellscript.dev/artifacts/cellscript/demo/releases/1.2.3.json"));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("max-age=60");
    expect(response.headers.get("etag")).toBe("\"static-entry\"");
    expect((await response.json() as any).coordinate).toBe("cellscript/demo@1.2.3");
  });

  it("rejects unknown schemas, incomplete entries, and mismatched nested identities", async () => {
    const { app } = testApp();
    const publish = await publishPayload("cap_11111111111111111111111111111111");
    const sourceSnapshot = {
      content_base64: base64("source snapshot"),
      content_type: "application/vnd.cellscript.source+tar",
      size_bytes: "source snapshot".length,
      source_hash: publish.source_hash,
    };
    const submit = (payload: unknown) =>
      post(app, "/v1/artifacts/cellscript/demo/releases", {
        payload,
        capability_signature: { algorithm: "p256-sha256", signature: "sig" },
        source_snapshot: sourceSnapshot,
      });

    const unknownSchema = await submit({
      ...publish,
      registry_entry: { ...publish.registry_entry, schema_version: 2 },
    });
    expect(unknownSchema.status).toBe(400);
    expect((await unknownSchema.json() as any).error.code).toBe("unsupported_registry_schema");

    for (const [field, expectedCode] of [
      ["dependencies", "invalid_registry_dependencies"],
      ["verification_status", "invalid_initial_artifact_state"],
      ["availability_status", "invalid_initial_artifact_state"],
    ] as const) {
      const incompleteVersion = { ...publish.registry_entry.versions[0] } as Record<string, unknown>;
      delete incompleteVersion[field];
      const incomplete = await submit({
        ...publish,
        registry_entry: { ...publish.registry_entry, versions: [incompleteVersion] },
      });
      expect(incomplete.status).toBe(400);
      expect((await incomplete.json() as any).error.code).toBe(expectedCode);
    }

    const wrongVersion = await submit({
      ...publish,
      registry_entry: {
        ...publish.registry_entry,
        versions: [{ ...publish.registry_entry.versions[0], version: "1.2.4", tag: "v1.2.4" }],
      },
    });
    expect(wrongVersion.status).toBe(400);
    expect((await wrongVersion.json() as any).error.code).toBe("registry_identity_mismatch");
  });

  it("replays a successful publish response for the same Idempotency-Key without rewriting objects", async () => {
    const { app, store, snapshots } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const publish = await publishPayload(capability.key_id);
    const body = {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    };
    const first = await post(app, "/v1/artifacts/cellscript/demo/releases", body, {}, { "idempotency-key": "publish-key-0001" });
    expect(first.status).toBe(202);
    const firstBody = await first.json() as any;

    const replay = await post(app, "/v1/artifacts/cellscript/demo/releases", body, {}, { "idempotency-key": "publish-key-0001" });
    expect(replay.status).toBe(202);
    expect(replay.headers.get("x-idempotency-status")).toBe("replayed");
    const replayBody = await replay.json() as any;
    expect(replayBody.direct_url).toBe(firstBody.direct_url);
    expect(replayBody.snapshot_hash).toBe(firstBody.snapshot_hash);
    expect(snapshots).toHaveLength(2);
  });

  it("rejects conflicting publish payloads that reuse an Idempotency-Key", async () => {
    const { app, store } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const publish = await publishPayload(capability.key_id);
    const first = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    }, {}, { "idempotency-key": "publish-key-0002" });
    expect(first.status).toBe(202);

    const changed = {
      ...publish,
      version: "1.2.4",
      source_hash: `0x${"ef".repeat(32)}`,
      registry_entry: {
        ...publish.registry_entry,
        versions: [{
          ...publish.registry_entry.versions[0],
          version: "1.2.4",
          tag: "v1.2.4",
          source_hash: `0x${"ef".repeat(32)}`,
        }],
      },
    };
    const conflict = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: changed,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("changed source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "changed source snapshot".length,
        source_hash: changed.source_hash,
      },
    }, {}, { "idempotency-key": "publish-key-0002" });
    expect(conflict.status).toBe(409);
    expect((await conflict.json() as any).error.code).toBe("idempotency_key_conflict");
  });

  it("blocks publish nonce replay before another version can write source objects", async () => {
    const { app, store, snapshots } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const publish = await publishPayload(capability.key_id);
    const first = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });
    expect(first.status).toBe(202);

    const replayedNonce = {
      ...publish,
      version: "1.2.4",
      source_hash: `0x${"ef".repeat(32)}`,
      registry_entry: {
        ...publish.registry_entry,
        versions: [{
          ...publish.registry_entry.versions[0],
          version: "1.2.4",
          tag: "v1.2.4",
          source_hash: `0x${"ef".repeat(32)}`,
        }],
      },
    };
    const replay = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: replayedNonce,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("replayed nonce source"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "replayed nonce source".length,
        source_hash: replayedNonce.source_hash,
      },
    });
    expect(replay.status).toBe(409);
    expect((await replay.json() as any).error.code).toBe("nonce_replay");
    expect(snapshots).toHaveLength(2);
    expect(store.auditEvents.some((event) => event.event_type === "nonce.replay_blocked")).toBe(true);
  });

  it("keeps the database authoritative when a static mirror write fails after admission", async () => {
    const store = new MemoryRegistryStore();
    const writes: Array<{ key: string; body: Uint8Array; contentType: string }> = [];
    let failStaticWrites = true;
    const app = createApp({
      store,
      now: () => now,
      joyidVerifier: { verifySignature: async () => true },
      capabilityVerifier: { verify: async () => true },
      snapshotWriter: {
        async put(key, body, options) {
          if (failStaticWrites && key.startsWith("artifacts/")) {
            throw new Error("static registry object write failed");
          }
          writes.push({ key, body, contentType: options.contentType });
        },
      } satisfies SnapshotWriter,
    });
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const publish = await publishPayload(capability.key_id);
    const sourceSnapshot = {
      content_base64: base64("source snapshot"),
      content_type: "application/vnd.cellscript.source+tar",
      size_bytes: "source snapshot".length,
      source_hash: publish.source_hash,
    };
    const idempotencyKey = "publish-key-static-fail";
    const noncesBeforePublish = store.usedNonces.size;
    const response = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: sourceSnapshot,
    }, {}, { "idempotency-key": idempotencyKey });

    expect(response.status).toBe(202);
    expect((await response.json() as any).verification_status).toBe("pending");
    expect(writes).toHaveLength(1);
    expect(writes[0]?.key).toContain("source-snapshots/cellscript/demo/1.2.3/");
    expect(store.snapshots.size).toBe(1);
    expect(store.packageVersions.has("cellscript/demo@1.2.3")).toBe(true);
    expect(store.idempotencyKeys.get(`publish:${idempotencyKey}`)?.status).toBe("completed");
    expect(store.usedNonces.size).toBe(noncesBeforePublish + 1);
    expect(store.capabilities.get(capability.key_id)?.last_used_at).toBeTruthy();
    expect(store.auditEvents.some((event) => event.event_type === "capability.used")).toBe(true);
    expect(store.auditEvents.some((event) => event.event_type === "publish.accepted")).toBe(true);
    expect(store.auditEvents.some((event) => event.event_type === "static_registry.sync_deferred")).toBe(true);
    expect([...store.verificationJobs.values()][0]?.status).toBe("retry_wait");

    failStaticWrites = false;
    const retry = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: sourceSnapshot,
    }, {}, { "idempotency-key": idempotencyKey });

    expect(retry.status).toBe(202);
    expect(retry.headers.get("x-idempotency-status")).toBe("replayed");
    expect((await retry.json() as any).verification_status).toBe("pending");
    expect(store.packageVersions.has("cellscript/demo@1.2.3")).toBe(true);
    expect(store.idempotencyKeys.get(`publish:${idempotencyKey}`)?.status).toBe("completed");
    expect(store.capabilities.get(capability.key_id)?.last_used_at).toBeTruthy();
    expect(store.auditEvents.some((event) => event.event_type === "capability.used")).toBe(true);
    expect(store.auditEvents.some((event) => event.event_type === "publish.accepted")).toBe(true);
  });

  it("allows audited admin review and quarantine transitions with an admin token", async () => {
    const { app, store, snapshots } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;

    const claimResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "cellscript",
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(claimResponse.status).toBe(202);
    expect((await claimResponse.json() as any).status).toBe("review_pending");

    const adminEnv = { REGISTRY_ADMIN_TOKEN: "secret" };
    const adminHeaders = { authorization: "Bearer secret", "x-registry-admin-actor": "ops@example.com" };
    const approveResponse = await post(
      app,
      "/v1/admin/namespaces/cellscript/status",
      { status: "active", review_reason: "approved core namespace" },
      adminEnv,
      adminHeaders,
    );
    expect(approveResponse.status).toBe(200);
    expect((await approveResponse.json() as any).status).toBe("active");

    const publish = await publishPayload(capability.key_id);
    const publishResponse = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });
    expect(publishResponse.status).toBe(202);

    const unsupportedPromotion = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/availability",
      { availability_status: "verified_build", reason: "manual claim without evidence" },
      adminEnv,
      adminHeaders,
    );
    expect(unsupportedPromotion.status).toBe(400);
    expect((await unsupportedPromotion.json() as any).error.code).toBe("invalid_availability_status");

    const quarantineResponse = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/availability",
      { availability_status: "quarantined", reason: "manual review" },
      adminEnv,
      adminHeaders,
    );
    expect(quarantineResponse.status).toBe(200);
    expect((await quarantineResponse.json() as any).availability_status).toBe("quarantined");
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.availability_status).toBe("quarantined");
    const staticEntryWrites = snapshots.filter((snapshot) => snapshot.key === "artifacts/cellscript/demo/releases/1.2.3.json");
    expect(staticEntryWrites).toHaveLength(2);
    expect(JSON.parse(utf8(staticEntryWrites.at(-1)!.body)).availability_status).toBe("quarantined");
    expect(store.auditEvents.some((event) => event.event_type === "admin.namespace.status_updated")).toBe(true);
    expect(store.auditEvents.some((event) => event.event_type === "admin.package_version.status_updated")).toBe(true);
  });

  it("lists public packages and requires chained evidence for production promotions", async () => {
    const registryTypeScript = { code_hash: `0x${"71".repeat(32)}`, hash_type: "data1", args: "0x01" };
    const commitmentLockScript = { code_hash: `0x${"72".repeat(32)}`, hash_type: "type", args: "0x02" };
    const registryTypeCellDep = { out_point: { tx_hash: `0x${"73".repeat(32)}`, index: "0x0" }, dep_type: "code" };
    const commitmentLockCellDep = { out_point: { tx_hash: `0x${"74".repeat(32)}`, index: "0x0" }, dep_type: "code" };
    const { app, store, snapshots } = testApp(undefined, undefined, {
      verifyMainnetDeployment: async () => ({ block_hash: `0x${"60".repeat(32)}` }),
      verifyRegistryCommitmentConfiguration: async () => {},
      verifyMainnetCommitment: async () => ({
        commitment_schema: "cellscript-registry-commitment-v1",
        chain_verification: "get_live_cell+type_index",
        observed_block_hash: `0x${"61".repeat(32)}`,
      }),
    });
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });
    const publish = await ckbExecutablePublishPayload(capability.key_id);
    const publishResponse = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("artifact bundle"),
        content_type: "application/vnd.cellscript.artifact-bundle+json",
        size_bytes: "artifact bundle".length,
        source_hash: publish.source_hash,
      },
    });
    expect(publishResponse.status).toBe(202);

    const publicIndex = await get(app, "/v1/artifacts?q=demo&limit=10");
    expect(publicIndex.status).toBe(200);
    expect(await publicIndex.json()).toMatchObject({
      schema: "cellscript-registry-artifact-index",
      count: 0,
      artifacts: [],
    });
    const explicitlyUnverified = await get(app, "/v1/artifacts?q=demo&verification=pending&limit=10");
    expect(explicitlyUnverified.status).toBe(200);
    expect(await explicitlyUnverified.json()).toMatchObject({
      schema: "cellscript-registry-artifact-index",
      count: 1,
      artifacts: [{
        coordinate: "cellscript/demo",
        latest_release: "1.2.3",
        verification_status: "pending",
        releases: [{
          immutable_bundle: {
            schema: "cellscript-registry-immutable-bundle",
            url: expect.stringContaining("https://registry.cellscript.dev/source-snapshots/cellscript/demo/1.2.3/"),
            content_type: "application/vnd.cellscript.artifact-bundle+json",
          },
        }],
      }],
    });

    const adminEnv = {
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_TYPE_SCRIPT_JSON: JSON.stringify(registryTypeScript),
      REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON: JSON.stringify(registryTypeCellDep),
      REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON: JSON.stringify(commitmentLockScript),
      REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON: JSON.stringify(commitmentLockCellDep),
    };
    const adminHeaders = { authorization: "Bearer secret", "x-registry-admin-actor": "release-bot" };
    const commonEvidence = {
      schema: "cellscript-registry-evidence",
      producer: "cellscript-release-gate/0.23.0",
      generated_at: "2026-06-23T12:00:00Z",
      verification_status: "passed",
      source_hash: publish.source_hash,
      manifest_hash: publish.manifest_hash,
    };

    const missingDependency = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "deployed",
        evidence: {
          ...commonEvidence,
          kind: "deployed",
          verified_build_evidence_hash: `sha256:${"11".repeat(32)}`,
          artifact_hash: `0x${"31".repeat(32)}`,
          network: "mainnet",
          code_hash: `0x${"31".repeat(32)}`,
          data_hash: `0x${"31".repeat(32)}`,
          hash_type: "data1",
          dep_type: "code",
          out_point: { tx_hash: `0x${"43".repeat(32)}`, index: 0 },
          deployment_status: "live",
        },
      },
      adminEnv,
      adminHeaders,
    );
    expect(missingDependency.status).toBe(409);
    expect((await missingDependency.json() as any).error.code).toBe("evidence_dependency_missing");

    const verified = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "verified_build",
        evidence: {
          ...commonEvidence,
          kind: "verified_build",
          verification_level: "hash_bound",
          artifact_hash: `0x${"31".repeat(32)}`,
          metadata_hash: `0x${"32".repeat(32)}`,
        },
      },
      adminEnv,
      adminHeaders,
    );
    expect(verified.status).toBe(200);
    const verifiedBody = await verified.json() as any;
    expect(verifiedBody.status).toBe("verified_build");
    const verifiedIndex = await (await get(app, "/v1/artifacts?q=demo&limit=10")).json() as any;
    expect(verifiedIndex.count).toBe(1);
    expect(verifiedIndex.artifacts[0].verification_status).toBe("hash_bound");

    const mismatchedDeployment = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "deployed",
        evidence: {
          ...commonEvidence,
          kind: "deployed",
          verified_build_evidence_hash: verifiedBody.evidence.evidence_hash,
          artifact_hash: `0x${"31".repeat(32)}`,
          network: "mainnet",
          code_hash: `0x${"44".repeat(32)}`,
          data_hash: `0x${"44".repeat(32)}`,
          hash_type: "data1",
          dep_type: "code",
          out_point: { tx_hash: `0x${"43".repeat(32)}`, index: 0 },
          deployment_status: "live",
        },
      },
      adminEnv,
      adminHeaders,
    );
    expect(mismatchedDeployment.status).toBe(400);
    expect((await mismatchedDeployment.json() as any).error.code).toBe("deployment_data_hash_mismatch");

    const deployed = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "deployed",
        evidence: {
          ...commonEvidence,
          kind: "deployed",
          verified_build_evidence_hash: verifiedBody.evidence.evidence_hash,
          artifact_hash: `0x${"31".repeat(32)}`,
          network: "mainnet",
          code_hash: `0x${"31".repeat(32)}`,
          data_hash: `0x${"31".repeat(32)}`,
          hash_type: "data1",
          dep_type: "code",
          out_point: { tx_hash: `0x${"43".repeat(32)}`, index: 0 },
          deployment_status: "live",
        },
      },
      adminEnv,
      adminHeaders,
    );
    expect(deployed.status).toBe(200);
    const deployedBody = await deployed.json() as any;
    expect(deployedBody.status).toBe("deployed");
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.deployment_status).toBe("chain_verified");

    const attested = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "on_chain_committed",
        evidence: {
          ...commonEvidence,
          kind: "on_chain_committed",
          deployed_evidence_hash: deployedBody.evidence.evidence_hash,
          network: "mainnet",
          commitment_tx_hash: `0x${"51".repeat(32)}`,
          commitment_hash: `0x${"52".repeat(32)}`,
          commitment_lock_hash: `0x${"53".repeat(32)}`,
          registry_type_hash: `0x${"54".repeat(32)}`,
          commitment_out_point: { tx_hash: `0x${"51".repeat(32)}`, index: 0 },
          observed_at: "2026-06-23T12:00:00Z",
          commitment_status: "confirmed",
        },
      },
      adminEnv,
      adminHeaders,
    );
    expect(attested.status).toBe(200);
    expect((await attested.json() as any).status).toBe("on_chain_committed");

    const acceptedIndex = await get(app, "/v1/artifacts?q=demo&limit=10");
    expect(acceptedIndex.status).toBe(200);
    expect(await acceptedIndex.json()).toMatchObject({
      count: 1,
      artifacts: [{ coordinate: "cellscript/demo", verification_status: "hash_bound", deployment_status: "chain_verified" }],
    });

    const detail = await get(app, "/v1/artifacts/cellscript/demo");
    expect(detail.status).toBe(200);
    expect(await detail.json()).toMatchObject({
      coordinate: "cellscript/demo",
      verification_status: "hash_bound",
      deployment_status: "chain_verified",
      releases: [{
        release: "1.2.3",
        verification_status: "hash_bound",
        deployment_status: "chain_verified",
        immutable_bundle: { schema: "cellscript-registry-immutable-bundle" },
        evidence: [{ kind: "verified_build" }, { kind: "deployed" }, { kind: "on_chain_committed" }],
      }],
    });
    const evidence = await get(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/evidence");
    expect(evidence.status).toBe(200);
    expect((await evidence.json() as any).evidence).toHaveLength(3);
    const staticWrites = snapshots.filter((snapshot) => snapshot.key === "artifacts/cellscript/demo/releases/1.2.3.json");
    expect(staticWrites).toHaveLength(4);
    expect(JSON.parse(utf8(staticWrites.at(-1)!.body)).evidence).toHaveLength(3);
    expect(JSON.parse(utf8(staticWrites.at(-1)!.body)).immutable_bundle.url).toContain("/source-snapshots/cellscript/demo/1.2.3/");
  });

  it("requires two independent reproduction reports before deploying a reproducible executable", async () => {
    let acceptReproducerSignatures = true;
    const { app, store } = testApp(undefined, undefined, {
      verifyMainnetDeployment: async () => ({ block_hash: `0x${"60".repeat(32)}` }),
      capabilityVerifier: {
        verify: async (canonicalPayload) => !canonicalPayload.includes('"schema":"cellscript-reproduction-report-v2"')
          || acceptReproducerSignatures,
      },
    });
    const payload = authPayload();
    const capability = await (await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    })).json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });
    const publish = await ckbExecutablePublishPayload(capability.key_id);
    declareReproducibleBuild(publish);
    expect((await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("reproducible artifact bundle"),
        content_type: "application/vnd.cellscript.artifact-bundle+json",
        size_bytes: "reproducible artifact bundle".length,
        source_hash: publish.source_hash,
      },
    })).status).toBe(202);

    const adminEnv = {
      REGISTRY_ADMIN_TOKEN: "secret",
      REGISTRY_REPRODUCER_POLICY_JSON: JSON.stringify({
        schema: "cellscript-reproducer-policy-v1",
        minimum_trust_domains: 2,
        builders: [
          { builder_id: "builder-a", trust_domain: "org-a", public_key: reproducerPublicKeys["builder-a"] },
          { builder_id: "builder-b", trust_domain: "org-b", public_key: reproducerPublicKeys["builder-b"] },
        ],
      }),
    };
    const adminHeaders = { authorization: "Bearer secret", "x-registry-admin-actor": "release-bot" };
    const commonEvidence = {
      schema: "cellscript-registry-evidence",
      producer: "cellscript-release-gate/0.23.0",
      generated_at: "2026-06-23T12:00:00Z",
      verification_status: "passed",
      source_hash: publish.source_hash,
      manifest_hash: publish.manifest_hash,
    };
    const verifiedResponse = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "verified_build",
        evidence: {
          ...commonEvidence,
          kind: "verified_build",
          verification_level: "evidence_required",
          artifact_hash: `0x${"31".repeat(32)}`,
          metadata_hash: `0x${"32".repeat(32)}`,
        },
      },
      adminEnv,
      adminHeaders,
    );
    expect(verifiedResponse.status).toBe(200);
    const verified = await verifiedResponse.json() as any;
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.verification_status).toBe("evidence_required");

    const deploymentEvidence = (buildEvidenceHash: string) => ({
      ...commonEvidence,
      kind: "deployed",
      verified_build_evidence_hash: buildEvidenceHash,
      artifact_hash: `0x${"31".repeat(32)}`,
      network: "mainnet",
      code_hash: `0x${"31".repeat(32)}`,
      data_hash: `0x${"31".repeat(32)}`,
      hash_type: "data1",
      dep_type: "code",
      out_point: { tx_hash: `0x${"43".repeat(32)}`, index: 0 },
      deployment_status: "live",
    });
    const prematureDeployment = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      { kind: "deployed", evidence: deploymentEvidence(verified.evidence.evidence_hash) },
      adminEnv,
      adminHeaders,
    );
    expect(prematureDeployment.status).toBe(409);
    expect((await prematureDeployment.json() as any).error.code).toBe("reproduction_evidence_missing");

    const report = (builderId: "builder-a" | "builder-b") => ({
      schema: "cellscript-reproduction-report-v2",
      builder_id: builderId,
      trust_domain: builderId === "builder-a" ? "org-a" : "org-b",
      builder_public_key: reproducerPublicKeys[builderId],
      environment: "docker.io/library/rust:1.97.1@sha256:0123456789abcdef",
      source_hash: publish.source_hash,
      build_recipe_hash: `0x${"34".repeat(32)}`,
      artifact_hash: `0x${"31".repeat(32)}`,
      build_log_hash: `0x${"71".repeat(32)}`,
      generated_at: "2026-06-23T12:00:00Z",
      signature: { algorithm: "p256-sha256", signature: "signed-reproduction-report-value" },
    });
    const reproducedEvidence = {
      ...commonEvidence,
      kind: "reproduced_build",
      verification_level: "reproduced",
      verified_build_evidence_hash: verified.evidence.evidence_hash,
      artifact_hash: `0x${"31".repeat(32)}`,
      build_recipe_hash: `0x${"34".repeat(32)}`,
      minimum_reproducers: 2,
      reproducers: [report("builder-a"), report("builder-b")],
    };
    const duplicate = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      { kind: "reproduced_build", evidence: { ...reproducedEvidence, reproducers: [report("builder-a"), report("builder-a")] } },
      adminEnv,
      adminHeaders,
    );
    expect(duplicate.status).toBe(400);
    expect((await duplicate.json() as any).error.code).toBe("duplicate_reproducer");

    acceptReproducerSignatures = false;
    const invalidSignature = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      { kind: "reproduced_build", evidence: reproducedEvidence },
      adminEnv,
      adminHeaders,
    );
    expect(invalidSignature.status).toBe(401);
    expect((await invalidSignature.json() as any).error.code).toBe("reproduction_signature_invalid");
    acceptReproducerSignatures = true;

    const reproducedResponse = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      { kind: "reproduced_build", evidence: reproducedEvidence },
      adminEnv,
      adminHeaders,
    );
    expect(reproducedResponse.status).toBe(200);
    const reproduced = await reproducedResponse.json() as any;
    expect(reproduced.status).toBe("verified_build");
    expect(reproduced.evidence.evidence.reproducer_policy).toMatchObject({
      schema: "cellscript-reproducer-policy-acceptance-v1",
      policy_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      minimum_trust_domains: 2,
    });
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.verification_status).toBe("verified");

    const deployed = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      { kind: "deployed", evidence: deploymentEvidence(reproduced.evidence.evidence_hash) },
      adminEnv,
      adminHeaders,
    );
    expect(deployed.status).toBe(200);
    expect((await deployed.json() as any).status).toBe("deployed");
  });

  it("paginates public discovery by package without splitting a package's releases", async () => {
    const { app, store } = testApp();
    const snapshotHash = `sha256:${"90".repeat(32)}`;
    const sourceHash = `0x${"91".repeat(32)}`;
    store.snapshots.set(snapshotHash, {
      snapshot_hash: snapshotHash,
      r2_key: "source-snapshots/shared.tar",
      source_hash: sourceHash,
      size_bytes: 1,
      content_type: "application/vnd.cellscript.source+tar",
    });
    const record = (name: string, version: string, createdAt: string): PackageVersionRecord => ({
      namespace: "cellscript",
      name,
      version,
      status: "verified_build",
      artifact: { kind: "source_library", profile: "cellscript_source", consumption_mode: "dependency", language: "cellscript" },
      verification_status: "verified",
      deployment_status: "not_applicable",
      availability_status: "active",
      source_hash: sourceHash,
      manifest_hash: `0x${"92".repeat(32)}`,
      edition: "2026",
      compatibility_profile_hash: "93".repeat(32),
      capability_key_id: "cap_11111111111111111111111111111111",
      principal_type: "joyid_ckb",
      principal_id: "0x1111111111111111111111111111111111111111",
      registry_entry: {
        schema_version: 1,
        namespace: "cellscript",
        name,
        artifact: { kind: "source_library", profile: "cellscript_source", consumption_mode: "dependency", language: "cellscript" },
        versions: [{
          version,
          tag: `v${version}`,
          source_hash: sourceHash,
          cellscript_version: "0.23.0",
          edition: "2026",
          compatibility_profile_hash: "93".repeat(32),
          dependencies: {},
          verification_status: "pending",
          deployment_status: "not_applicable",
          availability_status: "active",
        }],
      },
      snapshot_hash: snapshotHash,
      direct_url: `https://registry.cellscript.dev/artifacts/cellscript/${name}/releases/${version}.json`,
      created_at: createdAt,
    });
    for (const item of [
      record("alpha", "2.0.0", "2026-06-23T12:04:00Z"),
      record("alpha", "1.0.0", "2026-06-23T12:01:00Z"),
      record("beta", "1.0.0", "2026-06-23T12:03:00Z"),
      record("gamma", "1.0.0", "2026-06-23T12:02:00Z"),
    ]) {
      store.packageVersions.set(`${item.namespace}/${item.name}@${item.version}`, item);
    }

    const first = await (await get(app, "/v1/artifacts?limit=1&offset=0")).json() as any;
    const second = await (await get(app, "/v1/artifacts?limit=1&offset=1")).json() as any;
    const third = await (await get(app, "/v1/artifacts?limit=1&offset=2")).json() as any;
    expect(first.artifacts[0].coordinate).toBe("cellscript/alpha");
    expect(first.artifacts[0].releases).toHaveLength(2);
    expect(first.next_offset).toBe(1);
    expect(second.artifacts[0].coordinate).toBe("cellscript/beta");
    expect(second.next_offset).toBe(2);
    expect(third.artifacts[0].coordinate).toBe("cellscript/gamma");
    expect(third.next_offset).toBeUndefined();
  });

  it("records only capability-signed, chain-verified mainnet deployments for executable artifacts", async () => {
    const store = new MemoryRegistryStore();
    const snapshots: Array<{ key: string; body: Uint8Array }> = [];
    const app = createApp({
      store,
      now: () => now,
      joyidVerifier: { verifySignature: async () => true },
      capabilityVerifier: { verify: async () => true },
      verifyMainnetDeployment: async (payload) => {
        expect(payload.network).toBe("mainnet");
        expect(payload.out_point).toEqual({ tx_hash: `0x${"41".repeat(32)}`, index: 0 });
        return { block_hash: `0x${"51".repeat(32)}` };
      },
      snapshotWriter: {
        async put(key, body) { snapshots.push({ key, body }); },
      },
    });
    const root = authPayload();
    const capability = await (await post(app, "/v1/capabilities", {
      payload: root,
      joyid_signature: joyidSignature(root),
    })).json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: root.principal_id,
    });
    const publish = await ckbExecutablePublishPayload(capability.key_id);
    const published = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("artifact bundle"),
        content_type: "application/vnd.cellscript.artifact-bundle+json",
        size_bytes: "artifact bundle".length,
        source_hash: publish.source_hash,
      },
    });
    expect(published.status).toBe(202);
    await store.updatePackageVersionStatus({
      namespace: "cellscript",
      name: "demo",
      version: "1.2.3",
      status: "yanked",
      request_id: "yank-during-verification",
      admin_actor: "test",
    });
    const verifiedWhileYanked = await store.promotePackageVersion({
      namespace: "cellscript",
      name: "demo",
      version: "1.2.3",
      kind: "verified_build",
      evidence_hash: `sha256:${"61".repeat(32)}`,
      evidence: { verification_level: "hash_bound", artifact_hash: `0x${"31".repeat(32)}` },
      request_id: "verification:test",
      admin_actor: "verification-worker:test",
    });
    expect(verifiedWhileYanked.version.status).toBe("yanked");
    expect(verifiedWhileYanked.version.verification_status).toBe("hash_bound");
    const restoredAfterVerification = await store.updatePackageVersionStatus({
      namespace: "cellscript",
      name: "demo",
      version: "1.2.3",
      status: "active",
      request_id: "restore-after-verification",
      admin_actor: "test",
    });
    expect(restoredAfterVerification.status).toBe("verified_build");

    const deployment = deploymentPayload(capability.key_id);
    const contractMismatch = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/deployments", {
      payload: { ...deployment, hash_type: "data" },
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    });
    expect(contractMismatch.status).toBe(400);
    expect((await contractMismatch.json() as any).error.code).toBe("deployment_hash_type_contract_mismatch");
    const deploymentRequest = {
      payload: deployment,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    };
    store.capabilities.get(capability.key_id)!.scopes = ["publish:cellscript/demo"];
    const publishOnlyDeployment = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/deployments", deploymentRequest);
    expect(publishOnlyDeployment.status).toBe(403);
    expect((await publishOnlyDeployment.json() as any).error.code).toBe("capability_scope_denied");
    store.capabilities.get(capability.key_id)!.scopes = root.requested_scopes;
    const response = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/deployments", deploymentRequest);
    expect(response.status).toBe(201);
    const deploymentResponse = await response.json();
    expect(deploymentResponse).toMatchObject({
      coordinate: "cellscript/demo@1.2.3",
      deployment_status: "chain_verified",
      evidence: {
        kind: "deployed",
        evidence: {
          network: "mainnet",
          deployment_status: "live",
          chain_verification: "get_transaction+get_live_cell",
        },
      },
    });
    const replayedDeployment = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/deployments", deploymentRequest);
    expect(replayedDeployment.status).toBe(201);
    expect(await replayedDeployment.json()).toEqual(deploymentResponse);
    const deploymentNonceReplay = await post(
      app,
      "/v1/artifacts/cellscript/demo/releases/1.2.3/deployments",
      deploymentRequest,
      {},
      { "idempotency-key": "deployment-replay-cleanup" },
    );
    expect(deploymentNonceReplay.status).toBe(409);
    expect((await deploymentNonceReplay.json() as any).error.code).toBe("nonce_replay");
    expect(store.idempotencyKeys.has("deployment:deployment-replay-cleanup")).toBe(false);
    expect((await store.listPackageEvidence("cellscript", "demo", "1.2.3")).filter((item) => item.kind === "deployed")).toHaveLength(1);
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.deployment_status).toBe("chain_verified");
    expect(store.auditEvents.some((event) => event.event_type === "deployment.chain_verified")).toBe(true);
    expect(snapshots.filter((item) => item.key === "artifacts/cellscript/demo/releases/1.2.3.json")).toHaveLength(2);
    const commitment = await get(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/commitment");
    expect(commitment.status).toBe(200);
    expect(await commitment.json()).toMatchObject({
      schema: "cellscript-registry-commitment-proof-v1",
      status: "commitment_ready",
      payload: {
        schema: "cellscript-registry-commitment-v1",
        namespace: "cellscript",
        name: "demo",
        release: "1.2.3",
      },
      cell_data: expect.stringMatching(/^0x43535245477631[0-9a-f]{64}$/),
    });
  });

  it("lets the namespace owner yank and restore a release with a scoped capability", async () => {
    const { app, store, snapshots } = testApp();
    const root = authPayload();
    const capability = await (await post(app, "/v1/capabilities", {
      payload: root,
      joyid_signature: joyidSignature(root),
    })).json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: root.principal_id,
    });
    const publish = await publishPayload(capability.key_id);
    expect((await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    })).status).toBe(202);

    const yank = availabilityPayload(capability.key_id);
    store.capabilities.get(capability.key_id)!.scopes = ["publish:cellscript/demo"];
    const publishOnlyYank = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/availability", {
      payload: yank,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    });
    expect(publishOnlyYank.status).toBe(403);
    expect((await publishOnlyYank.json() as any).error.code).toBe("capability_scope_denied");
    store.capabilities.get(capability.key_id)!.scopes = root.requested_scopes;
    const yanked = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/availability", {
      payload: yank,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    });
    expect(yanked.status).toBe(200);
    const yankedBody = await yanked.json();
    expect(yankedBody).toMatchObject({
      coordinate: "cellscript/demo@1.2.3",
      availability_status: "yanked",
    });
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.availability_status).toBe("yanked");
    expect(store.auditEvents.some((event) => event.event_type === "publisher.package_version.availability_updated")).toBe(true);
    expect(JSON.parse(utf8(snapshots.at(-1)!.body)).availability_status).toBe("yanked");

    const replayedYank = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/availability", {
      payload: yank,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    });
    expect(replayedYank.status).toBe(200);
    expect(await replayedYank.json()).toEqual(yankedBody);
    expect(store.auditEvents.filter((event) => event.event_type === "publisher.package_version.availability_updated")).toHaveLength(1);
    const availabilityNonceReplay = await post(
      app,
      "/v1/artifacts/cellscript/demo/releases/1.2.3/availability",
      {
        payload: yank,
        capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      },
      {},
      { "idempotency-key": "availability-replay-cleanup" },
    );
    expect(availabilityNonceReplay.status).toBe(409);
    expect((await availabilityNonceReplay.json() as any).error.code).toBe("nonce_replay");
    expect(store.idempotencyKeys.has("availability:availability-replay-cleanup")).toBe(false);

    const active = availabilityPayload(capability.key_id, "active", "0x8888888888888888");
    const restored = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/availability", {
      payload: active,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    });
    expect(restored.status).toBe(200);
    expect((await restored.json() as any).availability_status).toBe("active");
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.availability_status).toBe("active");
  });

  it("rejects testnet deployment payloads and exposes no retired package routes", async () => {
    const { app } = testApp();
    const deployment = { ...deploymentPayload("cap_11111111111111111111111111111111"), network: "testnet" };
    const rejected = await post(app, "/v1/artifacts/cellscript/demo/releases/1.2.3/deployments", {
      payload: deployment,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
    });
    expect(rejected.status).toBe(400);
    expect((await rejected.json() as any).error.code).toBe("unsupported_deployment_network");
    expect((await get(app, "/v1/packages")).status).toBe(404);
    expect((await get(app, "/v1/packages/cellscript/demo")).status).toBe(404);
  });

  it("does not change DB package status when a suppressive static update fails", async () => {
    const store = new MemoryRegistryStore();
    const snapshots: Array<{ key: string; body: Uint8Array; contentType: string }> = [];
    let failStaticWrites = false;
    const app = createApp({
      store,
      now: () => now,
      joyidVerifier: { verifySignature: async () => true },
      capabilityVerifier: { verify: async () => true },
      snapshotWriter: {
        async put(key, body, options) {
          if (failStaticWrites && key.startsWith("artifacts/")) {
            throw new Error("static registry object write failed");
          }
          snapshots.push({ key, body, contentType: options.contentType });
        },
      } satisfies SnapshotWriter,
    });
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });
    const publish = await publishPayload(capability.key_id);
    const publishResponse = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });
    expect(publishResponse.status).toBe(202);

    failStaticWrites = true;
    const response = await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/availability",
      { availability_status: "quarantined", reason: "manual review" },
      { REGISTRY_ADMIN_TOKEN: "secret" },
      { authorization: "Bearer secret" },
    );

    expect(response.status).toBe(500);
    expect((await response.json() as any).error.code).toBe("internal_error");
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.availability_status).toBe("active");
    expect(store.auditEvents.some((event) => event.event_type === "admin.package_version.status_updated")).toBe(false);
    const staticEntryWrites = snapshots.filter((snapshot) => snapshot.key === "artifacts/cellscript/demo/releases/1.2.3.json");
    expect(staticEntryWrites).toHaveLength(1);
    expect(JSON.parse(utf8(staticEntryWrites[0]!.body)).availability_status).toBe("active");
  });

  it("rejects publish when the capability principal does not own the namespace", async () => {
    const { app, store } = testApp();
    const ownerPayload = authPayload("0x1111111111111111111111111111111111111111");
    const otherPayload = authPayload("0x2222222222222222222222222222222222222222");
    await post(app, "/v1/capabilities", {
      payload: otherPayload,
      joyid_signature: joyidSignature(otherPayload),
    });
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: ownerPayload.principal_id,
    });
    const keyId = await capabilityKeyId(otherPayload.capability_pubkey);
    const publish = await publishPayload(keyId);

    const response = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });

    expect(response.status).toBe(403);
    expect((await response.json() as any).error.code).toBe("namespace_owner_mismatch");
  });

  it("records auth failure audit events for invalid capability signatures", async () => {
    const store = new MemoryRegistryStore();
    const snapshots: Array<{ key: string; body: Uint8Array; contentType: string }> = [];
    const app = createApp({
      store,
      now: () => now,
      joyidVerifier: { verifySignature: async () => true },
      capabilityVerifier: { verify: async () => false },
      snapshotWriter: {
        async put(key, body, options) {
          snapshots.push({ key, body, contentType: options.contentType });
        },
      },
    });
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const publish = await publishPayload(capability.key_id);
    const response = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });

    expect(response.status).toBe(401);
    expect((await response.json() as any).error.code).toBe("capability_signature_invalid");
    expect(snapshots).toHaveLength(0);
    const event = store.auditEvents.find((entry) => entry.event_type === "auth.failure");
    expect(event?.data).toMatchObject({
      path: "/v1/artifacts/cellscript/demo/releases",
      status: 401,
      code: "capability_signature_invalid",
    });
  });

  it("rejects namespace claims by a different JoyID principal", async () => {
    const { app } = testApp();
    const first = {
      ...authPayload("0x1111111111111111111111111111111111111111"),
      requested_scopes: ["publish:alpha/demo"],
    };
    const second = {
      ...authPayload("0x2222222222222222222222222222222222222222"),
      requested_scopes: ["publish:alpha/demo"],
    };

    const firstResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "alpha",
      payload: first,
      joyid_signature: joyidSignature(first),
    });
    expect(firstResponse.status).toBe(201);

    const secondResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "alpha",
      payload: second,
      joyid_signature: joyidSignature(second),
    });
    expect(secondResponse.status).toBe(409);
    expect((await secondResponse.json() as any).error.code).toBe("namespace_already_claimed");
  });

  it("applies a cooldown between new namespace claims for the same JoyID principal", async () => {
    const { app, store } = testApp();
    const principalId = "0x1111111111111111111111111111111111111111";
    const first = {
      ...authPayload(principalId),
      requested_scopes: ["publish:alpha/demo"],
      nonce: "0xaaaaaaaaaaaaaaaa",
    };
    const second = {
      ...authPayload(principalId),
      requested_scopes: ["publish:bravo/demo"],
      nonce: "0xbbbbbbbbbbbbbbbb",
    };

    const firstResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "alpha",
      payload: first,
      joyid_signature: joyidSignature(first),
    });
    expect(firstResponse.status).toBe(201);

    const secondResponse = await post(app, "/v1/namespaces/claim", {
      namespace: "bravo",
      payload: second,
      joyid_signature: joyidSignature(second),
    });
    expect(secondResponse.status).toBe(429);
    expect((await secondResponse.json() as any).error.code).toBe("namespace_claim_cooldown");
    expect(store.auditEvents.some((event) => event.event_type === "namespace_claim.cooldown_blocked")).toBe(true);
  });

  it("exposes token-gated audit events for registry operations", async () => {
    const { app } = testApp();
    const payload = {
      ...authPayload("0x1111111111111111111111111111111111111111"),
      requested_scopes: ["publish:alpha/demo"],
    };
    const claim = await post(app, "/v1/namespaces/claim", {
      namespace: "alpha",
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(claim.status).toBe(201);

    const unauthorized = await get(app, "/v1/admin/audit-events", { REGISTRY_ADMIN_TOKEN: "secret" });
    expect(unauthorized.status).toBe(401);
    expect((await unauthorized.json() as any).error.code).toBe("admin_unauthorized");

    const wrongToken = await get(
      app,
      "/v1/admin/audit-events",
      { REGISTRY_ADMIN_TOKEN: "secret" },
      { authorization: "Bearer secres" },
    );
    expect(wrongToken.status).toBe(401);
    expect((await wrongToken.json() as any).error.code).toBe("admin_unauthorized");

    const invalidLimit = await get(
      app,
      "/v1/admin/audit-events?limit=999",
      { REGISTRY_ADMIN_TOKEN: "secret" },
      { authorization: "Bearer secret" },
    );
    expect(invalidLimit.status).toBe(400);
    expect((await invalidLimit.json() as any).error.code).toBe("invalid_audit_limit");

    const response = await get(
      app,
      "/v1/admin/audit-events?event_type=namespace.claimed&limit=10",
      { REGISTRY_ADMIN_TOKEN: "secret" },
      { authorization: "Bearer secret" },
    );
    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.events).toHaveLength(1);
    expect(body.events[0]).toMatchObject({
      event_type: "namespace.claimed",
      principal_type: "joyid_ckb",
      principal_id: payload.principal_id,
      namespace: "alpha",
    });
    expect(body.events[0].id).toBeTruthy();
    expect(body.events[0].created_at).toBeTruthy();
  });

  it("rate-limits capability creation by request IP before JoyID becomes the only spam control", async () => {
    const { app } = testApp();
    let response: Response | undefined;
    for (let i = 0; i < 121; i += 1) {
      const principalId = `0x${(i + 1).toString(16).padStart(40, "0")}`;
      const payload = authPayload(principalId);
      response = await post(app, "/v1/capabilities", {
        payload,
        joyid_signature: joyidSignature(payload),
      });
    }

    expect(response?.status).toBe(429);
    expect((await response!.json() as any).error.code).toBe("rate_limited");
  });

  it("runs scheduled cleanup for expired replay and quota state", async () => {
    const { app, store } = testApp();
    store.usedNonces.set("old-nonce", {
      protocol: PUBLISH_PROTOCOL,
      action: "publish",
      nonce: "0xaaaaaaaaaaaaaaaa",
      request_id: "old-request",
      expires_at: "2026-06-23T11:59:00Z",
      created_at: "2026-06-23T11:50:00Z",
    });
    store.usedNonces.set("live-nonce", {
      protocol: PUBLISH_PROTOCOL,
      action: "publish",
      nonce: "0xbbbbbbbbbbbbbbbb",
      request_id: "live-request",
      expires_at: "2026-06-23T12:01:00Z",
      created_at: "2026-06-23T11:50:00Z",
    });
    store.idempotencyKeys.set("old-key", {
      key: "old-key",
      request_hash: "old-hash",
      request_id: "old-request",
      status: "processing",
      expires_at: "2026-06-23T11:59:00Z",
      created_at: "2026-06-23T11:50:00Z",
      completed_at: null,
    });
    store.idempotencyKeys.set("live-key", {
      key: "live-key",
      request_hash: "live-hash",
      request_id: "live-request",
      status: "processing",
      expires_at: "2026-06-23T12:01:00Z",
      created_at: "2026-06-23T11:50:00Z",
      completed_at: null,
    });
    store.quotaEvents = [
      { quotaKey: "old-quota", bucket: "publish", at: "2026-06-21T11:59:00Z" },
      { quotaKey: "live-quota", bucket: "publish", at: "2026-06-21T12:01:00Z" },
    ];

    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      { CLEANUP_QUOTA_EVENT_RETENTION_HOURS: "48" },
    );

    expect(store.usedNonces.has("old-nonce")).toBe(false);
    expect(store.usedNonces.has("live-nonce")).toBe(true);
    expect(store.idempotencyKeys.has("old-key")).toBe(false);
    expect(store.idempotencyKeys.has("live-key")).toBe(true);
    expect(store.quotaEvents).toEqual([{ quotaKey: "live-quota", bucket: "publish", at: "2026-06-21T12:01:00Z" }]);
    const event = store.auditEvents.find((entry) => entry.event_type === "maintenance.cleanup");
    expect(event?.data).toMatchObject({
      used_nonces_deleted: 1,
      idempotency_keys_deleted: 1,
      quota_events_deleted: 1,
    });
  });

  it("isolates the Pudge sandbox and purges records on the 72-hour lifecycle", async () => {
    expect(() => registryRuntimeConfig({ REGISTRY_ENVIRONMENT: "testnet-sandbox" }))
      .toThrow(/dedicated Registry API and object origins/);
    const sandboxEnv = {
      REGISTRY_ENVIRONMENT: "testnet-sandbox",
      REGISTRY_ORIGIN: "https://api.testnet.registry.cellscript.dev",
      STATIC_REGISTRY_ORIGIN: "https://objects.testnet.registry.cellscript.dev",
    } as const;
    expect(registryRuntimeConfig(sandboxEnv)).toMatchObject({
      environment: "testnet-sandbox",
      network: "testnet",
      record_ttl_hours: 72,
      object_purge_grace_hours: 24,
    });

    const deleted: string[] = [];
    const writer: SnapshotWriter = {
      async put() {},
      async delete(key) { deleted.push(key); },
    };
    const { app, store } = testApp(undefined, writer);
    const snapshotHash = `sha256:${"a1".repeat(32)}`;
    store.snapshots.set(snapshotHash, {
      snapshot_hash: snapshotHash,
      r2_key: "source-snapshots/sandbox/demo/1.0.0/a1.tar",
      source_hash: `0x${"a2".repeat(32)}`,
      size_bytes: 1,
      content_type: "application/x-tar",
    });
    store.packageVersions.set("sandbox/demo@1.0.0", {
      namespace: "sandbox",
      name: "demo",
      version: "1.0.0",
      status: "source_published",
      artifact: { kind: "source_library", profile: "cellscript_source", consumption_mode: "dependency", language: "cellscript" },
      verification_status: "pending",
      deployment_status: "not_applicable",
      availability_status: "active",
      source_hash: `0x${"a2".repeat(32)}`,
      manifest_hash: `0x${"a3".repeat(32)}`,
      capability_key_id: "cap_sandbox",
      principal_type: "joyid_ckb",
      principal_id: "0x1111111111111111111111111111111111111111",
      registry_entry: {
        schema_version: 1,
        namespace: "sandbox",
        name: "demo",
        artifact: { kind: "source_library", profile: "cellscript_source", consumption_mode: "dependency", language: "cellscript" },
        versions: [{
          version: "1.0.0",
          tag: "v1.0.0",
          source_hash: `0x${"a2".repeat(32)}`,
          dependencies: {},
          verification_status: "pending",
          deployment_status: "not_applicable",
          availability_status: "active",
        }],
      },
      snapshot_hash: snapshotHash,
      direct_url: "https://objects.testnet.registry.cellscript.dev/artifacts/sandbox/demo/releases/1.0.0.json",
      created_at: "2026-06-20T11:00:00Z",
      registry_environment: "testnet-sandbox",
      network: "testnet",
      expires_at: "2026-06-23T11:00:00Z",
      purge_after: "2026-06-23T11:30:00Z",
    });

    await app.scheduled({ scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController, sandboxEnv);

    expect(await store.getPackageVersion("sandbox", "demo", "1.0.0")).toBeNull();
    expect(deleted).toEqual([
      "artifacts/sandbox/demo/releases/1.0.0.json",
      "source-snapshots/sandbox/demo/1.0.0/a1.tar",
    ]);
    expect(store.packageVersions.get("sandbox/demo@1.0.0")).toMatchObject({
      expired_at: now.toISOString(),
      static_purged_at: now.toISOString(),
      source_purged_at: now.toISOString(),
    });
  });

  it("stamps sandbox publishes with the isolated network and fixed retention window", async () => {
    const sandboxEnv = {
      REGISTRY_ENVIRONMENT: "testnet-sandbox",
      REGISTRY_ORIGIN: "https://api.testnet.registry.cellscript.dev",
      STATIC_REGISTRY_ORIGIN: "https://objects.testnet.registry.cellscript.dev",
    } as const;
    const { app, store, snapshots } = testApp();
    const authorisation = authPayload();
    authorisation.registry_origin = sandboxEnv.REGISTRY_ORIGIN;
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload: authorisation,
      joyid_signature: joyidSignature(authorisation),
    }, sandboxEnv);
    expect(capabilityResponse.status).toBe(201);
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: authorisation.principal_id,
    });
    const publish = await publishPayload(capability.key_id);
    publish.registry_origin = sandboxEnv.REGISTRY_ORIGIN;
    const response = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("sandbox source"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "sandbox source".length,
        source_hash: publish.source_hash,
      },
    }, sandboxEnv);

    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({
      registry_environment: "testnet-sandbox",
      network: "testnet",
      expires_at: "2026-06-26T12:00:00.000Z",
      purge_after: "2026-06-27T12:00:00.000Z",
    });
    expect(store.packageVersions.get("cellscript/demo@1.2.3")).toMatchObject({
      registry_environment: "testnet-sandbox",
      network: "testnet",
      expires_at: "2026-06-26T12:00:00.000Z",
      purge_after: "2026-06-27T12:00:00.000Z",
    });
    const staticEntry = snapshots.find((snapshot) => snapshot.key === "artifacts/cellscript/demo/releases/1.2.3.json");
    expect(JSON.parse(utf8(staticEntry!.body))).toMatchObject({
      registry_environment: "testnet-sandbox",
      network: "testnet",
      expires_at: "2026-06-26T12:00:00.000Z",
    });
  });

  it("serialises overlapping scheduled maintenance runs", async () => {
    const { app, store } = testApp();
    const cleanup = store.cleanupExpiredState.bind(store);
    let cleanupCalls = 0;
    let announceStarted!: () => void;
    let releaseCleanup!: () => void;
    const started = new Promise<void>((resolve) => { announceStarted = resolve; });
    const held = new Promise<void>((resolve) => { releaseCleanup = resolve; });
    store.cleanupExpiredState = async (input) => {
      cleanupCalls += 1;
      announceStarted();
      await held;
      return cleanup(input);
    };

    const first = app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      {},
    );
    await started;
    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      {},
    );
    expect(cleanupCalls).toBe(1);
    releaseCleanup();
    await first;
    expect(cleanupCalls).toBe(1);
  });

  it("indexes configured Registry commitment Cells and never restores a spent commitment from history", async () => {
    const typeScript = { code_hash: `0x${"71".repeat(32)}`, hash_type: "data1", args: "0x01" };
    const commitmentLock = { code_hash: `0x${"72".repeat(32)}`, hash_type: "type", args: "0x02" };
    const typeCellDep = {
      out_point: { tx_hash: `0x${"73".repeat(32)}`, index: "0x0" },
      dep_type: "code",
    };
    const lockCellDep = {
      out_point: { tx_hash: `0x${"75".repeat(32)}`, index: "0x0" },
      dep_type: "code",
    };
    let commitmentHash = `0x${"00".repeat(32)}`;
    let commitmentLive = true;
    let commitmentConfigurationLive = true;
    let deploymentLive = true;
    const { app, store } = testApp(undefined, undefined, {
      verifyMainnetDeployment: async () => {
        if (!deploymentLive) {
          throw new ApiError(409, "deployment_cell_not_live", "deployment Cell is spent");
        }
        return { block_hash: `0x${"60".repeat(32)}` };
      },
      verifyRegistryCommitmentConfiguration: async () => {
        if (!commitmentConfigurationLive) {
          throw new ApiError(409, "deployment_cell_not_live", "Registry commitment Lock CellDep is not live");
        }
      },
      listMainnetCommitmentCells: async (configuration) => {
        expect(configuration.type_script_hash).toBe(ckbScriptHash(typeScript));
        expect(configuration.commitment_lock_hash).toBe(ckbScriptHash(commitmentLock));
        return commitmentLive
          ? [{
              commitment_hash: commitmentHash,
              out_point: { tx_hash: `0x${"74".repeat(32)}`, index: 1 },
              block_number: "0x1234",
              output: { lock: commitmentLock, type: typeScript },
            }]
          : [];
      },
    });
    const owner = authPayload();
    const capability = await (await post(app, "/v1/capabilities", {
      payload: owner,
      joyid_signature: joyidSignature(owner),
    })).json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: owner.principal_id,
    });
    const publish = await ckbExecutablePublishPayload(capability.key_id);
    expect((await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("commitment artifact bundle"),
        content_type: "application/vnd.cellscript.artifact-bundle+json",
        size_bytes: "commitment artifact bundle".length,
        source_hash: publish.source_hash,
      },
    })).status).toBe(202);
    const adminEnv = { REGISTRY_ADMIN_TOKEN: "secret" };
    const adminHeaders = { authorization: "Bearer secret", "x-registry-admin-actor": "release-bot" };
    const commonEvidence = {
      schema: "cellscript-registry-evidence",
      producer: "cellscript-release-gate/0.23.0",
      generated_at: "2026-06-23T12:00:00Z",
      verification_status: "passed",
      source_hash: publish.source_hash,
      manifest_hash: publish.manifest_hash,
    };
    const verified = await (await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "verified_build",
        evidence: {
          ...commonEvidence,
          kind: "verified_build",
          verification_level: "hash_bound",
          artifact_hash: `0x${"31".repeat(32)}`,
          metadata_hash: `0x${"32".repeat(32)}`,
        },
      },
      adminEnv,
      adminHeaders,
    )).json() as any;
    const deployed = await (await post(
      app,
      "/v1/admin/artifacts/cellscript/demo/releases/1.2.3/promote",
      {
        kind: "deployed",
        evidence: {
          ...commonEvidence,
          kind: "deployed",
          verified_build_evidence_hash: verified.evidence.evidence_hash,
          artifact_hash: `0x${"31".repeat(32)}`,
          network: "mainnet",
          code_hash: `0x${"31".repeat(32)}`,
          data_hash: `0x${"31".repeat(32)}`,
          hash_type: "data1",
          dep_type: "code",
          out_point: { tx_hash: `0x${"43".repeat(32)}`, index: 0 },
          deployment_status: "live",
        },
      },
      adminEnv,
      adminHeaders,
    )).json() as any;
    const version = store.packageVersions.get("cellscript/demo@1.2.3")!;
    commitmentHash = registryCommitmentHash(version, deployed.evidence.evidence_hash);
    const scheduledEnv = {
      REGISTRY_TYPE_SCRIPT_JSON: JSON.stringify(typeScript),
      REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON: JSON.stringify(typeCellDep),
      REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON: JSON.stringify(commitmentLock),
      REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON: JSON.stringify(lockCellDep),
    };

    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      scheduledEnv,
    );
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("on_chain_committed");
    const commitmentProof = await (await get(
      app,
      "/v1/artifacts/cellscript/demo/releases/1.2.3/commitment",
      scheduledEnv,
    )).json() as any;
    expect(commitmentProof.status).toBe("on_chain_committed");
    expect(commitmentProof.transaction_intent.output.type).toEqual(typeScript);
    expect(commitmentProof.transaction_intent.required_cell_deps).toEqual([typeCellDep]);
    expect(commitmentProof.transaction_intent.custody_cell_dep).toEqual(lockCellDep);

    commitmentConfigurationLive = false;
    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      scheduledEnv,
    );
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("deployed");
    expect(store.auditEvents.some((event) => event.event_type === "maintenance.registry_commitment_configuration_failed"
      && event.data?.["demoted_commitments"] === 1)).toBe(true);

    const unsafeIntent = await get(
      app,
      "/v1/artifacts/cellscript/demo/releases/1.2.3/commitment",
      scheduledEnv,
    );
    expect(unsafeIntent.status).toBe(409);

    commitmentConfigurationLive = true;
    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      scheduledEnv,
    );
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("on_chain_committed");

    const proofWithoutConfiguration = await (await get(
      app,
      "/v1/artifacts/cellscript/demo/releases/1.2.3/commitment",
    )).json() as any;
    expect(proofWithoutConfiguration.status).toBe("commitment_unconfigured");
    expect(proofWithoutConfiguration.commitment).toBeUndefined();
    expect(proofWithoutConfiguration.transaction_intent).toBeNull();

    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      {},
    );
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("deployed");
    expect(store.auditEvents.some((event) => event.event_type === "maintenance.registry_commitment_disabled"
      && event.data?.["demoted_commitments"] === 1)).toBe(true);

    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      scheduledEnv,
    );
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("on_chain_committed");

    commitmentLive = false;
    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      scheduledEnv,
    );
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.status).toBe("deployed");
    const reconciledProof = await (await get(
      app,
      "/v1/artifacts/cellscript/demo/releases/1.2.3/commitment",
      scheduledEnv,
    )).json() as any;
    expect(reconciledProof.status).toBe("commitment_ready");
    expect(store.auditEvents.some((event) => event.event_type === "lifecycle.chain_state_reconciled")).toBe(true);
    expect(store.packageVersions.get("cellscript/demo@1.2.3")?.current_commitment_evidence_hash).toBeNull();

    await store.updatePackageVersionStatus({
      namespace: "cellscript",
      name: "demo",
      version: "1.2.3",
      status: "yanked",
      request_id: "yank-after-spend",
      admin_actor: "test",
    });
    const restored = await store.updatePackageVersionStatus({
      namespace: "cellscript",
      name: "demo",
      version: "1.2.3",
      status: "active",
      request_id: "restore-after-spend",
      admin_actor: "test",
    });
    expect(restored.status).toBe("deployed");
    expect(restored.current_commitment_evidence_hash).toBeNull();

    deploymentLive = false;
    await app.scheduled(
      { scheduledTime: now.getTime(), cron: "*/15 * * * *" } as ScheduledController,
      scheduledEnv,
    );
    const staleDeployment = store.packageVersions.get("cellscript/demo@1.2.3")!;
    expect(staleDeployment.status).toBe("verified_build");
    expect(staleDeployment.deployment_status).toBe("undeployed");
    expect(staleDeployment.current_commitment_evidence_hash).toBeNull();
  });

  it("revokes a capability with JoyID and blocks later publish", async () => {
    const { app, store } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(capabilityResponse.status).toBe(201);
    const capability = await capabilityResponse.json() as any;
    store.namespaces.set("cellscript", {
      namespace: "cellscript",
      status: "active",
      owner_principal_type: "joyid_ckb",
      owner_principal_id: payload.principal_id,
    });

    const revoke = revokePayload(capability.key_id);
    const revokeResponse = await post(app, `/v1/capabilities/${capability.key_id}/revoke`, {
      payload: revoke,
      joyid_signature: joyidRevocationSignature(revoke),
      reason: "rotated",
    });
    expect(revokeResponse.status).toBe(200);
    expect((await revokeResponse.json() as any).status).toBe("revoked");
    expect(store.capabilities.get(capability.key_id)?.revoked_at).toBeTruthy();

    const publish = await publishPayload(capability.key_id);
    const publishResponse = await post(app, "/v1/artifacts/cellscript/demo/releases", {
      payload: publish,
      capability_signature: { algorithm: "p256-sha256", signature: "sig" },
      source_snapshot: {
        content_base64: base64("source snapshot"),
        content_type: "application/vnd.cellscript.source+tar",
        size_bytes: "source snapshot".length,
        source_hash: publish.source_hash,
      },
    });

    expect(publishResponse.status).toBe(401);
    expect((await publishResponse.json() as any).error.code).toBe("capability_revoked");
    expect(store.auditEvents.some((event) => event.event_type === "capability.revoked")).toBe(true);
  });

  it("does not allow a replayed capability creation to reactivate a revoked key", async () => {
    const { app, store } = testApp();
    const payload = authPayload();
    const capabilityResponse = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(capabilityResponse.status).toBe(201);
    const capability = await capabilityResponse.json() as any;

    const revoke = revokePayload(capability.key_id);
    const revokeResponse = await post(app, `/v1/capabilities/${capability.key_id}/revoke`, {
      payload: revoke,
      joyid_signature: joyidRevocationSignature(revoke),
      reason: "rotated",
    });
    expect(revokeResponse.status).toBe(200);

    const replayCreate = await post(app, "/v1/capabilities", {
      payload,
      joyid_signature: joyidSignature(payload),
    });
    expect(replayCreate.status).toBe(409);
    expect((await replayCreate.json() as any).error.code).toBe("nonce_replay");
    expect(store.capabilities.get(capability.key_id)?.revoked_at).toBeTruthy();
  });
});
