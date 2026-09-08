import type { SignChallengeResponseData } from "@joyid/ckb";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";

export const AUTH_PROTOCOL = "cellscript-registry-auth-v1";
export const AUTH_ACTION = "authorize_capability";
export const AUTH_REVOKE_CAPABILITY_ACTION = "revoke_capability";
export const PUBLISH_PROTOCOL = "cellscript-registry-publish-v1";
export const PUBLISH_ACTION = "publish";
export const DEPLOYMENT_PROTOCOL = "cellscript-registry-deployment";
export const DEPLOYMENT_ACTION = "record_deployment";
export const AVAILABILITY_PROTOCOL = "cellscript-registry-availability-v1";
export const AVAILABILITY_ACTION = "set_availability";
export const REGISTRY_SCHEMA_VERSION = 1;
export const ARTIFACT_PROFILE_CONTRACT_SCHEMA = "cellscript-registry-profile-contract-v1";
export const ARTIFACT_PROFILE_CATALOG_SCHEMA = "cellscript-registry-profile-catalog-v1";
export const LS_IDL_INTERFACE_SCHEMA = "cellscript-registry-ls-idl-interface-v1";
export const LS_IDL_CONTENT_TYPE = "application/vnd.ckb.ls-idl+json";
export const LS_IDL_FORMAT_VERSION = "0.1";
export const CELLSCRIPT_EDITION = "2026";
export const DEFAULT_REGISTRY_ORIGIN = "https://api.registry.cellscript.dev";
export const DEFAULT_STATIC_REGISTRY_ORIGIN = "https://registry.cellscript.dev";
export const JOYID_PRINCIPAL_TYPE = "joyid_ckb";
export const CKB_SECP256K1_PRINCIPAL_TYPE = "ckb_secp256k1";
export const ACCEPTED_PRINCIPAL_TYPES = [JOYID_PRINCIPAL_TYPE, CKB_SECP256K1_PRINCIPAL_TYPE] as const;
export const ARTIFACT_KINDS = [
  "source_library",
  "profile_library",
  "runtime_verifier",
  "deployable_contract",
  "reproducible_binary",
  "template",
] as const;
export const ARTIFACT_PROFILES = ["cellscript_source", "ckb_executable", "reproducible_build", "copy_material"] as const;
export const ARTIFACT_LANGUAGES = ["cellscript", "rust", "c", "javascript", "other", "unspecified"] as const;
export const CONSUMPTION_MODES = ["dependency", "tcb", "deployment", "copy"] as const;
export const CAPABILITY_SCOPE_ACTIONS = ["publish", "deployment", "availability"] as const;
export const JOYID_CKB_PRINCIPAL_BINDING_CONTEXT = "cellscript-registry-joyid-ckb-principal-v1";
export const CKB_SECP256K1_PRINCIPAL_BINDING_CONTEXT = "cellscript-registry-ckb-secp256k1-principal-v1";

export type PrincipalType = (typeof ACCEPTED_PRINCIPAL_TYPES)[number];
export type ArtifactKind = (typeof ARTIFACT_KINDS)[number];
export type ArtifactProfile = (typeof ARTIFACT_PROFILES)[number];
export type ArtifactLanguage = (typeof ARTIFACT_LANGUAGES)[number];
export type ConsumptionMode = (typeof CONSUMPTION_MODES)[number];
export type CapabilityScopeAction = (typeof CAPABILITY_SCOPE_ACTIONS)[number];
export type VerificationStatus = "pending" | "hash_bound" | "verified" | "evidence_required" | "rejected";
export type DeploymentStatus = "not_applicable" | "undeployed" | "deployed" | "chain_verified";
export type AvailabilityStatus = "active" | "deprecated" | "yanked" | "quarantined";

export interface ArtifactDescriptor {
  kind: ArtifactKind;
  profile: ArtifactProfile;
  consumption_mode: ConsumptionMode;
  language: ArtifactLanguage;
}

export interface ArtifactProfileDefinition {
  schema: typeof ARTIFACT_PROFILE_CATALOG_SCHEMA;
  profile: ArtifactProfile;
  validator_id:
    | "cellscript-source-package-v1"
    | "ckb-executable-profile-v1"
    | "reproducible-build-profile-v1"
    | "copy-material-profile-v1";
  resolver_capability: "dependency" | "non_resolving";
  requires_profile_contract: boolean;
  contracts: Partial<Record<ArtifactKind, { consumption_mode: ConsumptionMode; languages: readonly ArtifactLanguage[] }>>;
}

export type RegistryEntryStatus =
  | "source_published"
  | "indexed_pending"
  | "verified_build"
  | "deployed"
  | "on_chain_committed"
  | "deprecated"
  | "yanked"
  | "quarantined";

export interface CapabilityAuthorisationPayload {
  protocol: typeof AUTH_PROTOCOL;
  action: typeof AUTH_ACTION;
  registry_origin: string;
  principal_type: PrincipalType;
  principal_id: string;
  capability_pubkey: string;
  requested_scopes: string[];
  capability_expires_at: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  cli_version: string;
}

export interface CapabilityRevocationPayload {
  protocol: typeof AUTH_PROTOCOL;
  action: typeof AUTH_REVOKE_CAPABILITY_ACTION;
  registry_origin: string;
  principal_type: PrincipalType;
  principal_id: string;
  capability_key_id: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  cli_version: string;
}

export interface PublishPayload {
  protocol: typeof PUBLISH_PROTOCOL;
  action: typeof PUBLISH_ACTION;
  registry_origin: string;
  namespace: string;
  name: string;
  version: string;
  source_hash: string;
  manifest_hash: string;
  capability_key_id: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  cli_version: string;
  artifact: ArtifactDescriptor;
  registry_entry: RegistryIndexEntry;
}

export interface DeploymentPayload {
  protocol: typeof DEPLOYMENT_PROTOCOL;
  action: typeof DEPLOYMENT_ACTION;
  registry_origin: string;
  namespace: string;
  name: string;
  release: string;
  network: "mainnet" | "testnet";
  artifact_hash: string;
  data_hash: string;
  code_hash: string;
  hash_type: "data" | "data1" | "data2" | "type";
  dep_type: "code" | "dep_group";
  out_point: { tx_hash: string; index: number };
  capability_key_id: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  cli_version: string;
}

export interface AvailabilityPayload {
  protocol: typeof AVAILABILITY_PROTOCOL;
  action: typeof AVAILABILITY_ACTION;
  registry_origin: string;
  namespace: string;
  name: string;
  release: string;
  availability_status: Exclude<AvailabilityStatus, "quarantined">;
  reason?: string;
  capability_key_id: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  cli_version: string;
}

export interface RegistryVersionEntry {
  version: string;
  tag: string;
  source_hash: string;
  cellscript_version?: string;
  /** SemVer range declared by the source package for compatible cellc releases. */
  compiler_requirement?: string;
  /** Source-language semantics only; target/ABI/schema identity is separate. */
  edition?: typeof CELLSCRIPT_EDITION;
  /** Hash of the resolved edition + target + assurance + ABI + schema axes. */
  compatibility_profile_hash?: string;
  /** CKB Blake2b-256 hash of the canonical CellScript public interface. */
  interface_hash?: string;
  /** Canonical interface used for deterministic server-side upgrade admission. */
  interface?: Record<string, unknown>;
  artifact_hash?: string;
  build_recipe_hash?: string;
  abi_hash?: string;
  profile_contract?: Record<string, unknown>;
  dependencies?: Record<string, { namespace: string; version: string }>;
  verification_status: "pending";
  deployment_status: DeploymentStatus;
  availability_status: "active";
  [key: string]: unknown;
}

export interface RegistryIndexEntry {
  schema_version: typeof REGISTRY_SCHEMA_VERSION;
  namespace: string;
  name: string;
  artifact: ArtifactDescriptor;
  versions: [RegistryVersionEntry];
  [key: string]: unknown;
}

export interface SourceSnapshotInput {
  content_base64: string;
  content_type: string;
  size_bytes: number;
  source_hash: string;
}

export interface CapabilitySignature {
  algorithm: "p256-sha256";
  signature: string;
}

export interface JoyidVerifier {
  verifySignature(signature: SignChallengeResponseData): Promise<boolean>;
}

export interface CkbSecp256k1Signature {
  scheme: typeof CKB_SECP256K1_PRINCIPAL_TYPE;
  challenge: string;
  signature: string;
  public_key: string;
}

export type PrincipalSignature = SignChallengeResponseData | CkbSecp256k1Signature;

export interface CapabilitySignatureVerifier {
  verify(canonicalPayload: string, capabilityPubkey: string, signature: CapabilitySignature): Promise<boolean>;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortForJson(value));
}

function sortForJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortForJson);
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item !== undefined) {
        out[key] = sortForJson(item);
      }
    }
    return out;
  }
  return value;
}

export async function sha256Hex(input: string | Uint8Array | ArrayBuffer): Promise<string> {
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  const hash = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function ckbBlake2bHex(input: string | Uint8Array): string {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = blake2b(data, {
    dkLen: 32,
    personalization: new TextEncoder().encode("ckb-default-hash"),
  });
  return `0x${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(base64);
}

export function hexToBytes(value: string): Uint8Array<ArrayBuffer> {
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new ApiError(400, "invalid_hex", "hex string is malformed");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

export function parseSignatureBytes(value: string): Uint8Array<ArrayBuffer> {
  return value.startsWith("0x") ? hexToBytes(value) : base64UrlToBytes(value);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function assertPlainObject(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, code, "request body must be a JSON object");
  }
  return value as Record<string, unknown>;
}

export function requireString(value: Record<string, unknown>, key: string): string {
  const item = value[key];
  if (typeof item !== "string" || item.trim() === "") {
    throw new ApiError(400, "invalid_field", `${key} is required`);
  }
  return item.trim();
}

export function requireStringArray(value: Record<string, unknown>, key: string): string[] {
  const item = value[key];
  if (!Array.isArray(item) || item.length === 0 || item.some((entry) => typeof entry !== "string" || entry.trim() === "")) {
    throw new ApiError(400, "invalid_field", `${key} must be a non-empty string array`);
  }
  return item.map((entry) => entry.trim());
}

export function isPrincipalType(value: string): value is PrincipalType {
  return ACCEPTED_PRINCIPAL_TYPES.some((principalType) => principalType === value);
}

export function validatePrincipalType(value: string): PrincipalType {
  if (!isPrincipalType(value)) {
    throw new ApiError(
      400,
      "unsupported_principal_type",
      `principal_type must be one of: ${ACCEPTED_PRINCIPAL_TYPES.join(", ")}`,
    );
  }
  return value;
}

function validatePrincipalId(value: string, principalType: PrincipalType): string {
  const principalId = value.trim().toLowerCase();
  if (principalType === CKB_SECP256K1_PRINCIPAL_TYPE) {
    if (!/^0x[0-9a-f]{64}$/.test(principalId)) {
      throw new ApiError(
        400,
        "invalid_principal_id",
        "ckb_secp256k1 principal_id must be the 32-byte CellScript public-key binding",
      );
    }
    return principalId;
  }
  if (!/^0x[0-9a-f]{40,64}$/.test(principalId) && !/^ck[bt]1[0-9a-z]+$/.test(principalId)) {
    throw new ApiError(400, "invalid_principal_id", "principal_id must be a normalized JoyID/CKB identity binding");
  }
  return principalId;
}

export function parseTimestamp(value: string, key: string): Date {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new ApiError(400, "invalid_timestamp", `${key} must be an ISO timestamp`);
  }
  return date;
}

export function validatePackageIdent(value: string, field: string): string {
  const trimmed = value.trim();
  if (!/^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$/.test(trimmed)) {
    throw new ApiError(
      400,
      "invalid_package_identifier",
      `${field} must be 1-64 lowercase letters or numbers, with _ or - only between characters`,
    );
  }
  return trimmed;
}

export function validateVersion(value: string): string {
  const trimmed = value.trim();
  parseSemVer(trimmed);
  return trimmed;
}

type ParsedSemVer = {
  major: bigint;
  minor: bigint;
  patch: bigint;
  prerelease: string[] | null;
};

function parseSemVer(value: string): ParsedSemVer {
  const match = /^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:[.][0-9A-Za-z-]+)*))?(?:[+]([0-9A-Za-z-]+(?:[.][0-9A-Za-z-]+)*))?$/.exec(value);
  if (!match) {
    throw new ApiError(400, "invalid_version", "version must be valid SemVer");
  }
  const prerelease = match[4]?.split(".") ?? null;
  if (prerelease?.some((identifier) => /^[0-9]+$/.test(identifier) && identifier.length > 1 && identifier.startsWith("0"))) {
    throw new ApiError(400, "invalid_version", "numeric SemVer prerelease identifiers must not contain leading zeroes");
  }
  return {
    major: BigInt(match[1]!),
    minor: BigInt(match[2]!),
    patch: BigInt(match[3]!),
    prerelease,
  };
}

export function compareVersions(left: string, right: string): number {
  const a = parseSemVer(left);
  const b = parseSemVer(right);
  for (const key of ["major", "minor", "patch"] as const) {
    if (a[key] < b[key]) return -1;
    if (a[key] > b[key]) return 1;
  }
  if (a.prerelease === null || b.prerelease === null) {
    return a.prerelease === b.prerelease ? 0 : a.prerelease === null ? 1 : -1;
  }
  const count = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < count; index += 1) {
    const leftIdentifier = a.prerelease[index];
    const rightIdentifier = b.prerelease[index];
    if (leftIdentifier === undefined || rightIdentifier === undefined) {
      return leftIdentifier === rightIdentifier ? 0 : leftIdentifier === undefined ? -1 : 1;
    }
    if (leftIdentifier === rightIdentifier) continue;
    const leftNumeric = /^[0-9]+$/.test(leftIdentifier);
    const rightNumeric = /^[0-9]+$/.test(rightIdentifier);
    if (leftNumeric && rightNumeric) return BigInt(leftIdentifier) < BigInt(rightIdentifier) ? -1 : 1;
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftIdentifier < rightIdentifier ? -1 : 1;
  }
  return 0;
}

export function versionCompatibilityLine(version: string): string {
  const parsed = parseSemVer(version);
  return parsed.major === 0n ? `0.${parsed.minor}` : parsed.major.toString();
}

export function interfacePredecessorVersion(existingVersions: string[], candidateVersion: string): string | null {
  validateVersion(candidateVersion);
  const ordered = [...existingVersions].map(validateVersion).sort((left, right) => compareVersions(right, left));
  const highest = ordered[0];
  if (highest && compareVersions(candidateVersion, highest) <= 0) {
    throw new ApiError(
      409,
      "non_monotonic_release_version",
      `release ${candidateVersion} must be greater than the highest admitted version ${highest}`,
    );
  }
  const compatibilityLine = versionCompatibilityLine(candidateVersion);
  return ordered.find((version) => versionCompatibilityLine(version) === compatibilityLine) ?? null;
}

export function validateDeploymentPayload(
  input: unknown,
  registryOrigin: string,
  now: Date,
  expectedNetwork: DeploymentPayload["network"] = "mainnet",
): DeploymentPayload {
  const value = assertPlainObject(input, "invalid_deployment_payload");
  if (requireString(value, "protocol") !== DEPLOYMENT_PROTOCOL || requireString(value, "action") !== DEPLOYMENT_ACTION) {
    throw new ApiError(400, "invalid_deployment_action", "deployment payload has the wrong protocol or action");
  }
  if (requireString(value, "registry_origin") !== registryOrigin) {
    throw new ApiError(400, "invalid_registry_origin", "deployment payload registry_origin does not match this API");
  }
  const network = requireString(value, "network");
  if (network !== expectedNetwork) {
    throw new ApiError(
      400,
      "unsupported_deployment_network",
      `Registry deployment records for this environment must use ${expectedNetwork}`,
    );
  }
  const artifactHash = requireString(value, "artifact_hash");
  const dataHash = requireString(value, "data_hash");
  const codeHash = requireString(value, "code_hash");
  validateHash(artifactHash, "artifact_hash", "invalid_artifact_hash");
  validateHash(dataHash, "data_hash", "invalid_data_hash");
  validateHash(codeHash, "code_hash", "invalid_code_hash");
  if (!sameCkbHash(artifactHash, dataHash)) {
    throw new ApiError(400, "deployment_data_hash_mismatch", "data_hash must equal the published executable artifact_hash");
  }
  const hashType = requireString(value, "hash_type");
  if (!(hashType === "data" || hashType === "data1" || hashType === "data2" || hashType === "type")) {
    throw new ApiError(400, "invalid_hash_type", "hash_type must be data, data1, data2, or type");
  }
  const depType = requireString(value, "dep_type");
  if (!(depType === "code" || depType === "dep_group")) {
    throw new ApiError(400, "invalid_dep_type", "dep_type must be code or dep_group");
  }
  const outPoint = assertPlainObject(value["out_point"], "invalid_deployment_out_point");
  const txHash = requireString(outPoint, "tx_hash");
  validateHash(txHash, "out_point.tx_hash", "invalid_deployment_out_point");
  const index = outPoint["index"];
  if (!Number.isSafeInteger(index) || Number(index) < 0 || Number(index) > 0xffff_ffff) {
    throw new ApiError(400, "invalid_deployment_out_point", "out_point.index must be a non-negative u32 integer");
  }
  const nonce = requireString(value, "nonce");
  if (!/^0x[0-9a-fA-F]{16,}$/.test(nonce)) {
    throw new ApiError(400, "invalid_nonce", "nonce must be hex and at least 8 bytes");
  }
  const issuedAt = requireString(value, "issued_at");
  const expiresAt = requireString(value, "expires_at");
  parseTimestamp(issuedAt, "issued_at");
  if (parseTimestamp(expiresAt, "expires_at").getTime() <= now.getTime()) {
    throw new ApiError(401, "deployment_payload_expired", "deployment payload has expired");
  }
  return {
    protocol: DEPLOYMENT_PROTOCOL,
    action: DEPLOYMENT_ACTION,
    registry_origin: registryOrigin,
    namespace: validatePackageIdent(requireString(value, "namespace"), "namespace"),
    name: validatePackageIdent(requireString(value, "name"), "name"),
    release: validateVersion(requireString(value, "release")),
    network: expectedNetwork,
    artifact_hash: artifactHash,
    data_hash: dataHash,
    code_hash: codeHash,
    hash_type: hashType,
    dep_type: depType,
    out_point: { tx_hash: txHash, index: Number(index) },
    capability_key_id: requireString(value, "capability_key_id"),
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    cli_version: requireString(value, "cli_version"),
  };
}

export function validateAvailabilityPayload(
  input: unknown,
  registryOrigin: string,
  now: Date,
): AvailabilityPayload {
  const value = assertPlainObject(input, "invalid_availability_payload");
  if (requireString(value, "protocol") !== AVAILABILITY_PROTOCOL || requireString(value, "action") !== AVAILABILITY_ACTION) {
    throw new ApiError(400, "invalid_availability_action", "availability payload has the wrong protocol or action");
  }
  if (requireString(value, "registry_origin") !== registryOrigin) {
    throw new ApiError(400, "invalid_registry_origin", "availability payload registry_origin does not match this API");
  }
  const availabilityStatus = requireString(value, "availability_status");
  if (!(availabilityStatus === "active" || availabilityStatus === "deprecated" || availabilityStatus === "yanked")) {
    throw new ApiError(400, "invalid_publisher_availability_status", "publishers may set availability_status to active, deprecated, or yanked");
  }
  const reason = value["reason"] === undefined ? undefined : requireString(value, "reason").trim();
  if (availabilityStatus === "yanked" && !reason) {
    throw new ApiError(400, "availability_reason_required", "yanking a release requires a reason");
  }
  if (reason && reason.length > 500) {
    throw new ApiError(400, "invalid_availability_reason", "availability reason must be no longer than 500 characters");
  }
  const capabilityKeyId = requireString(value, "capability_key_id");
  if (!/^cap_[0-9a-f]{32}$/.test(capabilityKeyId)) {
    throw new ApiError(400, "invalid_capability_key_id", "capability_key_id is malformed");
  }
  const nonce = requireString(value, "nonce");
  if (!/^0x[0-9a-fA-F]{16,}$/.test(nonce)) {
    throw new ApiError(400, "invalid_nonce", "nonce must be hex and at least 8 bytes");
  }
  const issuedAt = requireString(value, "issued_at");
  const expiresAt = requireString(value, "expires_at");
  parseTimestamp(issuedAt, "issued_at");
  if (parseTimestamp(expiresAt, "expires_at").getTime() <= now.getTime()) {
    throw new ApiError(401, "availability_payload_expired", "availability payload has expired");
  }
  return {
    protocol: AVAILABILITY_PROTOCOL,
    action: AVAILABILITY_ACTION,
    registry_origin: registryOrigin,
    namespace: validatePackageIdent(requireString(value, "namespace"), "namespace"),
    name: validatePackageIdent(requireString(value, "name"), "name"),
    release: validateVersion(requireString(value, "release")),
    availability_status: availabilityStatus,
    ...(reason ? { reason } : {}),
    capability_key_id: capabilityKeyId,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    cli_version: requireString(value, "cli_version"),
  };
}

export function sameCkbHash(left: string, right: string): boolean {
  return left.replace(/^0x/, "").toLowerCase() === right.replace(/^0x/, "").toLowerCase();
}

export function ckbScriptHash(value: unknown): string {
  const script = assertPlainObject(value, "invalid_ckb_script");
  const codeHash = hexToBytes(requireString(script, "code_hash"));
  if (codeHash.length !== 32) {
    throw new ApiError(502, "invalid_ckb_rpc_response", "CKB RPC returned a script with a non-Byte32 code_hash");
  }
  const hashType = requireString(script, "hash_type");
  const hashTypeByte = ({ data: 0, type: 1, data1: 2, data2: 4 } as const)[hashType as "data" | "type" | "data1" | "data2"];
  if (hashTypeByte === undefined) {
    throw new ApiError(502, "invalid_ckb_rpc_response", "CKB RPC returned an unknown script hash_type");
  }
  const args = hexToBytes(requireString(script, "args"));
  const totalSize = 53 + args.length;
  const serialized = new Uint8Array(totalSize);
  writeU32Le(serialized, 0, totalSize);
  writeU32Le(serialized, 4, 16);
  writeU32Le(serialized, 8, 48);
  writeU32Le(serialized, 12, 49);
  serialized.set(codeHash, 16);
  serialized[48] = hashTypeByte;
  // Molecule Bytes is a byte FixVec: the u32 header stores the item count,
  // while the enclosing Script table stores the total byte size.
  writeU32Le(serialized, 49, args.length);
  serialized.set(args, 53);
  const digest = blake2b(serialized, {
    dkLen: 32,
    personalization: new TextEncoder().encode("ckb-default-hash"),
  });
  return `0x${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function writeU32Le(target: Uint8Array, offset: number, value: number): void {
  new DataView(target.buffer, target.byteOffset, target.byteLength).setUint32(offset, value, true);
}

export function validateCapabilityPayload(
  payload: unknown,
  registryOrigin: string,
  now: Date,
): CapabilityAuthorisationPayload {
  const obj = assertPlainObject(payload, "invalid_capability_payload");
  const protocol = requireString(obj, "protocol");
  const action = requireString(obj, "action");
  const principalType = validatePrincipalType(requireString(obj, "principal_type"));
  const principalId = validatePrincipalId(requireString(obj, "principal_id"), principalType);
  const capabilityPubkey = requireString(obj, "capability_pubkey");
  const requestedScopesValue = obj["requested_scopes"];
  if (!Array.isArray(requestedScopesValue) || requestedScopesValue.some((scope) => typeof scope !== "string" || scope.trim() === "")) {
    throw new ApiError(400, "invalid_field", "requested_scopes must be a string array");
  }
  const requestedScopes = requestedScopesValue.map((scope) => scope.trim());
  const capabilityExpiresAt = requireString(obj, "capability_expires_at");
  const nonce = requireString(obj, "nonce");
  const issuedAt = requireString(obj, "issued_at");
  const expiresAt = requireString(obj, "expires_at");
  const cliVersion = requireString(obj, "cli_version");

  if (protocol !== AUTH_PROTOCOL || action !== AUTH_ACTION) {
    throw new ApiError(400, "invalid_auth_action", "capability payload has the wrong protocol or action");
  }
  if (requireString(obj, "registry_origin") !== registryOrigin) {
    throw new ApiError(400, "invalid_registry_origin", "capability payload registry_origin does not match this API");
  }
  const ident = "[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?";
  const scopeActionsPattern = CAPABILITY_SCOPE_ACTIONS.join("|");
  const scopePattern = new RegExp(`^(?:${scopeActionsPattern}):${ident}/(?:${ident}|\\*)$`);
  if (requestedScopes.length === 0 || requestedScopes.some((scope) => !scopePattern.test(scope))) {
    throw new ApiError(
      400,
      "invalid_scope",
      "requested_scopes must contain publish, deployment, or availability scopes for namespace/package or namespace/*",
    );
  }
  if (new Set(requestedScopes).size !== requestedScopes.length) {
    throw new ApiError(400, "duplicate_scope", "requested_scopes must not contain duplicates");
  }
  if (!/^0x[0-9a-fA-F]{16,}$/.test(nonce)) {
    throw new ApiError(400, "invalid_nonce", "nonce must be hex and at least 8 bytes");
  }
  const expires = parseTimestamp(expiresAt, "expires_at");
  const capabilityExpires = parseTimestamp(capabilityExpiresAt, "capability_expires_at");
  parseTimestamp(issuedAt, "issued_at");
  if (expires.getTime() <= now.getTime()) {
    throw new ApiError(401, "auth_payload_expired", "capability authorisation challenge has expired");
  }
  if (capabilityExpires.getTime() <= now.getTime()) {
    throw new ApiError(400, "capability_expired", "capability expiry must be in the future");
  }

  return {
    protocol: AUTH_PROTOCOL,
    action: AUTH_ACTION,
    registry_origin: registryOrigin,
    principal_type: principalType,
    principal_id: principalId,
    capability_pubkey: capabilityPubkey,
    requested_scopes: requestedScopes,
    capability_expires_at: capabilityExpiresAt,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    cli_version: cliVersion,
  };
}

export function validateCapabilityRevocationPayload(
  payload: unknown,
  registryOrigin: string,
  now: Date,
): CapabilityRevocationPayload {
  const obj = assertPlainObject(payload, "invalid_capability_revocation_payload");
  const protocol = requireString(obj, "protocol");
  const action = requireString(obj, "action");
  const principalType = validatePrincipalType(requireString(obj, "principal_type"));
  const principalId = validatePrincipalId(requireString(obj, "principal_id"), principalType);
  const capabilityKeyId = requireString(obj, "capability_key_id");
  const nonce = requireString(obj, "nonce");
  const issuedAt = requireString(obj, "issued_at");
  const expiresAt = requireString(obj, "expires_at");
  const cliVersion = requireString(obj, "cli_version");

  if (protocol !== AUTH_PROTOCOL || action !== AUTH_REVOKE_CAPABILITY_ACTION) {
    throw new ApiError(400, "invalid_capability_revocation_action", "capability revocation payload has the wrong protocol or action");
  }
  if (requireString(obj, "registry_origin") !== registryOrigin) {
    throw new ApiError(400, "invalid_registry_origin", "capability revocation registry_origin does not match this API");
  }
  if (!/^cap_[0-9a-f]{32}$/.test(capabilityKeyId)) {
    throw new ApiError(400, "invalid_capability_key_id", "capability_key_id is malformed");
  }
  if (!/^0x[0-9a-fA-F]{16,}$/.test(nonce)) {
    throw new ApiError(400, "invalid_nonce", "nonce must be hex and at least 8 bytes");
  }
  parseTimestamp(issuedAt, "issued_at");
  if (parseTimestamp(expiresAt, "expires_at").getTime() <= now.getTime()) {
    throw new ApiError(401, "capability_revocation_payload_expired", "capability revocation challenge has expired");
  }

  return {
    protocol: AUTH_PROTOCOL,
    action: AUTH_REVOKE_CAPABILITY_ACTION,
    registry_origin: registryOrigin,
    principal_type: principalType,
    principal_id: principalId,
    capability_key_id: capabilityKeyId,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    cli_version: cliVersion,
  };
}

export function validatePublishPayload(payload: unknown, registryOrigin: string, now: Date): PublishPayload {
  const obj = assertPlainObject(payload, "invalid_publish_payload");
  const protocol = requireString(obj, "protocol");
  const action = requireString(obj, "action");
  if (protocol !== PUBLISH_PROTOCOL || action !== PUBLISH_ACTION) {
    throw new ApiError(400, "invalid_publish_action", "publish payload has the wrong protocol or action");
  }
  if (requireString(obj, "registry_origin") !== registryOrigin) {
    throw new ApiError(400, "invalid_registry_origin", "publish payload registry_origin does not match this API");
  }
  const namespace = validatePackageIdent(requireString(obj, "namespace"), "namespace");
  const name = validatePackageIdent(requireString(obj, "name"), "name");
  const version = validateVersion(requireString(obj, "version"));
  const sourceHash = requireString(obj, "source_hash");
  validateHash(sourceHash, "source_hash", "invalid_source_hash");
  const manifestHash = requireString(obj, "manifest_hash");
  validateHash(manifestHash, "manifest_hash", "invalid_manifest_hash");
  const capabilityKeyId = requireString(obj, "capability_key_id");
  const nonce = requireString(obj, "nonce");
  const issuedAt = requireString(obj, "issued_at");
  const expiresAt = requireString(obj, "expires_at");
  const cliVersion = requireString(obj, "cli_version");
  const artifact = validateArtifactDescriptor(obj["artifact"]);
  const registryEntry = validateRegistryEntry(obj["registry_entry"], { namespace, name, version, sourceHash, manifestHash, artifact });
  parseTimestamp(issuedAt, "issued_at");
  if (parseTimestamp(expiresAt, "expires_at").getTime() <= now.getTime()) {
    throw new ApiError(401, "publish_payload_expired", "publish payload has expired");
  }
  if (!/^0x[0-9a-fA-F]{16,}$/.test(nonce)) {
    throw new ApiError(400, "invalid_nonce", "nonce must be hex and at least 8 bytes");
  }

  const result: PublishPayload = {
    protocol: PUBLISH_PROTOCOL,
    action: PUBLISH_ACTION,
    registry_origin: registryOrigin,
    namespace,
    name,
    version,
    source_hash: sourceHash,
    manifest_hash: manifestHash,
    capability_key_id: capabilityKeyId,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    cli_version: cliVersion,
    artifact,
    registry_entry: registryEntry,
  };
  return result;
}

/**
 * Conservative server-side upgrade admission for canonical CellScript
 * interfaces. Additive exports are accepted; removing or changing an existing
 * public signature, layout, effect/capability, builder, runtime, or deployment
 * contract is rejected before the signed release is recorded.
 */
export function validateInterfaceUpgrade(previous: unknown, candidate: unknown): void {
  const oldInterface = assertPlainObject(previous, "invalid_previous_public_interface");
  const newInterface = assertPlainObject(candidate, "invalid_public_interface");
  for (const key of ["types", "constants", "callables"] as const) {
    const oldItems = interfaceItems(oldInterface[key], key);
    const newItems = interfaceItems(newInterface[key], key);
    for (const [identity, oldItem] of oldItems) {
      const newItem = newItems.get(identity);
      if (!newItem) {
        throw new ApiError(409, "incompatible_public_interface", `${key} export '${identity}' was removed`);
      }
      const oldComparable = interfaceCompatibilityShape(key, oldItem);
      const newComparable = interfaceCompatibilityShape(key, newItem);
      if (canonicalJson(oldComparable) !== canonicalJson(newComparable)) {
        throw new ApiError(409, "incompatible_public_interface", `${key} export '${identity}' changed incompatibly`);
      }
      if ((key === "types" || key === "callables")
        && compareInterfaceTypeParameters(oldItem["type_parameters"], newItem["type_parameters"]) === "breaking") {
        throw new ApiError(409, "incompatible_public_interface", `${key} export '${identity}' generic constraints changed incompatibly`);
      }
    }
  }
  for (const key of ["runtime_contract", "deployment_contract_hash"] as const) {
    if (canonicalJson(oldInterface[key]) !== canonicalJson(newInterface[key])) {
      throw new ApiError(409, "incompatible_public_interface", `${key} changed incompatibly`);
    }
  }
}

function validatePublicInterfaceVersion(publicInterface: Record<string, unknown>): void {
  const schema = publicInterface["schema"];
  const version = publicInterface["version"];
  if (schema === "cellscript-package-interface-v2" && version === 2) return;
  if (schema !== "cellscript-package-interface-v3" || version !== 3) {
    throw new ApiError(
      400,
      "unsupported_public_interface",
      "public interface must use cellscript-package-interface-v2 or cellscript-package-interface-v3",
    );
  }
  const runtime = assertPlainObject(publicInterface["runtime_contract"], "invalid_public_interface");
  const temporal = assertPlainObject(runtime["temporal"], "invalid_public_interface");
  const expectedConstructors = [
    "ckb::since_absolute_block(u64)->AbsoluteBlockSince",
    "ckb::since_absolute_epoch(u64,u64,u64)->AbsoluteEpochSince",
    "ckb::since_absolute_timestamp(u64-seconds)->AbsoluteTimestampSince",
    "ckb::since_relative_block(u64)->RelativeBlockSince",
    "ckb::since_relative_epoch(u64,u64,u64)->RelativeEpochSince",
    "ckb::since_relative_timestamp(u64-seconds)->RelativeTimestampSince",
  ];
  const expectedDomains = [
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
  ];
  const exactStrings = {
    schema: "cellscript-ckb-temporal-interface-v1",
    wire_representation: "fixed-u64-register-and-little-endian-wire",
    since_abi: "ckb-since-rfc0017-typed-v1",
    decoder: "ckb::since_decode(EncodedSince)->DecodedSince;ckb::since_from_raw_checked(u64)->DecodedSince",
    migration: "legacy-raw-ckb-temporal-to-explicit-typed-v1",
  } as const;
  for (const [key, expected] of Object.entries(exactStrings)) {
    if (temporal[key] !== expected) {
      throw new ApiError(400, "invalid_public_interface", `runtime_contract.temporal.${key} must be '${expected}'`);
    }
  }
  if (canonicalJson(temporal["constructors"]) !== canonicalJson(expectedConstructors)) {
    throw new ApiError(400, "invalid_public_interface", "runtime_contract.temporal.constructors is not canonical");
  }
  if (canonicalJson(temporal["domains"]) !== canonicalJson(expectedDomains)) {
    throw new ApiError(400, "invalid_public_interface", "runtime_contract.temporal.domains is not canonical");
  }
  validatePublicInterfaceGenerics(publicInterface);
}

const VALUE_ABILITY_ORDER = ["copy", "drop", "store", "fixed", "serializable", "non_linear", "cell"] as const;

function canonicalValueAbilities(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((ability) => typeof ability !== "string")) {
    throw new ApiError(400, "invalid_public_interface", `${label} must be an array of value abilities`);
  }
  const abilities = value as string[];
  const canonical = VALUE_ABILITY_ORDER.filter((ability) => abilities.includes(ability));
  if (canonical.length !== abilities.length || canonicalJson(canonical) !== canonicalJson(abilities)) {
    throw new ApiError(400, "invalid_public_interface", `${label} must be unique, known, and canonically ordered`);
  }
  if (abilities.includes("cell") && abilities.includes("non_linear")) {
    throw new ApiError(400, "invalid_public_interface", `${label} cannot combine cell and non_linear`);
  }
  return abilities;
}

function validateTypeParameters(value: unknown, label: string, layoutType: boolean): void {
  if (!Array.isArray(value)) {
    throw new ApiError(400, "invalid_public_interface", `${label} must be an array`);
  }
  const names = new Set<string>();
  for (const rawParameter of value) {
    const parameter = assertPlainObject(rawParameter, "invalid_public_interface");
    const name = requireString(parameter, "name");
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || names.has(name)) {
      throw new ApiError(400, "invalid_public_interface", `${label} has an invalid or duplicate parameter '${name}'`);
    }
    names.add(name);
    if (typeof parameter["phantom"] !== "boolean") {
      throw new ApiError(400, "invalid_public_interface", `${label}.${name}.phantom must be boolean`);
    }
    const constraints = canonicalValueAbilities(parameter["constraints"], `${label}.${name}.constraints`);
    if (layoutType && !parameter["phantom"]
      && !["fixed", "serializable", "non_linear"].every((ability) => constraints.includes(ability))) {
      throw new ApiError(
        400,
        "invalid_public_interface",
        `${label}.${name} must preserve the fixed, serializable, non_linear layout boundary`,
      );
    }
  }
}

function validatePublicInterfaceGenerics(publicInterface: Record<string, unknown>): void {
  for (const item of interfaceItems(publicInterface["types"], "types").values()) {
    validateTypeParameters(item["type_parameters"], `${requireString(item, "identity")}.type_parameters`, true);
    canonicalValueAbilities(item["value_abilities"], `${requireString(item, "identity")}.value_abilities`);
  }
  for (const item of interfaceItems(publicInterface["callables"], "callables").values()) {
    validateTypeParameters(item["type_parameters"], `${requireString(item, "identity")}.type_parameters`, false);
  }
}

function interfaceItems(value: unknown, label: string): Map<string, Record<string, unknown>> {
  if (!Array.isArray(value)) {
    throw new ApiError(400, "invalid_public_interface", `public interface ${label} must be an array`);
  }
  const items = new Map<string, Record<string, unknown>>();
  for (const rawItem of value) {
    const item = assertPlainObject(rawItem, "invalid_public_interface");
    const identity = requireString(item, "identity");
    if (items.has(identity)) {
      throw new ApiError(400, "invalid_public_interface", `duplicate public interface identity '${identity}'`);
    }
    items.set(identity, item);
  }
  return items;
}

function interfaceCompatibilityShape(kind: "types" | "constants" | "callables", item: Record<string, unknown>): unknown {
  if (kind === "types") {
    return {
      kind: item["kind"],
      value_abilities: item["value_abilities"],
      cell_capabilities: item["cell_capabilities"],
      layout_identity: item["layout_identity"],
      type_identity: item["type_identity"] ?? null,
    };
  }
  if (kind === "callables") {
    return {
      kind: item["kind"],
      params: item["params"],
      return_type: item["return_type"] ?? null,
      outputs: item["outputs"],
      effect: item["effect"],
      entry_witness_abi: item["entry_witness_abi"] ?? null,
      builder_contract_hash: item["builder_contract_hash"],
    };
  }
  return { type: item["type"] };
}

function compareInterfaceTypeParameters(oldValue: unknown, newValue: unknown): "same" | "relaxed" | "breaking" {
  if (!Array.isArray(oldValue) || !Array.isArray(newValue) || oldValue.length !== newValue.length) return "breaking";
  let relaxed = false;
  for (let index = 0; index < oldValue.length; index += 1) {
    const oldParameter = assertPlainObject(oldValue[index], "invalid_previous_public_interface");
    const newParameter = assertPlainObject(newValue[index], "invalid_public_interface");
    if (oldParameter["name"] !== newParameter["name"] || oldParameter["phantom"] !== newParameter["phantom"]) return "breaking";
    const oldConstraints = oldParameter["constraints"];
    const newConstraints = newParameter["constraints"];
    if (!Array.isArray(oldConstraints) || !Array.isArray(newConstraints)
      || oldConstraints.some((value) => typeof value !== "string")
      || newConstraints.some((value) => typeof value !== "string")) return "breaking";
    const oldSet = new Set(oldConstraints as string[]);
    const newSet = new Set(newConstraints as string[]);
    if ([...newSet].some((constraint) => !oldSet.has(constraint))) return "breaking";
    relaxed ||= oldSet.size !== newSet.size;
  }
  return relaxed ? "relaxed" : "same";
}

function validateHash(value: string, field: string, code: string): void {
  if (!/^(?:0x)?[0-9a-fA-F]{64}$/.test(value)) {
    throw new ApiError(400, code, `${field} must be a 32-byte hex content hash`);
  }
}

function validateRegistryEntry(
  input: unknown,
  outer: { namespace: string; name: string; version: string; sourceHash: string; manifestHash: string; artifact: ArtifactDescriptor },
): RegistryIndexEntry {
  const entry = assertPlainObject(input, "invalid_registry_entry");
  if (entry["schema_version"] !== REGISTRY_SCHEMA_VERSION) {
    throw new ApiError(
      400,
      "unsupported_registry_schema",
      `registry_entry.schema_version must be ${REGISTRY_SCHEMA_VERSION}`,
    );
  }
  if (requireString(entry, "namespace") !== outer.namespace || requireString(entry, "name") !== outer.name) {
    throw new ApiError(400, "registry_identity_mismatch", "registry_entry namespace/name must match the signed publish identity");
  }
  const artifact = validateArtifactDescriptor(entry["artifact"]);
  if (canonicalJson(artifact) !== canonicalJson(outer.artifact)) {
    throw new ApiError(400, "artifact_identity_mismatch", "registry_entry artifact descriptor must match the signed publish identity");
  }

  const versions = entry["versions"];
  if (!Array.isArray(versions) || versions.length !== 1) {
    throw new ApiError(400, "invalid_registry_versions", "registry_entry.versions must contain exactly the published version");
  }
  const published = assertPlainObject(versions[0], "invalid_registry_version");
  const version = validateVersion(requireString(published, "version"));
  const sourceHash = requireString(published, "source_hash");
  if (version !== outer.version || sourceHash !== outer.sourceHash) {
    throw new ApiError(400, "registry_identity_mismatch", "registry version and source_hash must match the signed publish identity");
  }
  if (requireString(published, "tag") !== `v${outer.version}`) {
    throw new ApiError(400, "invalid_registry_tag", "registry version tag must be v<version>");
  }
  const initialStates = initialArtifactStates(artifact);
  if (
    published["verification_status"] !== initialStates.verification_status
    || published["deployment_status"] !== initialStates.deployment_status
    || published["availability_status"] !== initialStates.availability_status
  ) {
    throw new ApiError(400, "invalid_initial_artifact_state", "new releases must use the profile's initial verification, deployment, and availability states");
  }

  const profileDefinition = ARTIFACT_PROFILE_CATALOG[artifact.profile];
  switch (profileDefinition.validator_id) {
    case "cellscript-source-package-v1": {
      if (published["profile_contract"] !== undefined) {
        throw new ApiError(400, "invalid_profile_contract", "CellScript source releases do not use profile_contract");
      }
      validateVersion(requireString(published, "cellscript_version"));
      const compilerRequirement = requireString(published, "compiler_requirement");
      if (compilerRequirement.length > 128 || !/[0-9*]/.test(compilerRequirement)
        || !/^[0-9A-Za-z.*+<>=^~|, -]+$/.test(compilerRequirement)) {
        throw new ApiError(400, "invalid_compiler_requirement", "compiler_requirement must be a bounded SemVer requirement");
      }
      if (published["edition"] !== CELLSCRIPT_EDITION) {
        throw new ApiError(400, "unsupported_cellscript_edition", `registry version edition must be ${CELLSCRIPT_EDITION}`);
      }
      const compatibilityProfileHash = requireString(published, "compatibility_profile_hash");
      validateHash(compatibilityProfileHash, "compatibility_profile_hash", "invalid_compatibility_profile_hash");
      const interfaceHash = requireString(published, "interface_hash");
      validateHash(interfaceHash, "interface_hash", "invalid_interface_hash");
      const publicInterface = assertPlainObject(published["interface"], "invalid_public_interface");
      validatePublicInterfaceVersion(publicInterface);
      const computedInterfaceHash = ckbBlake2bHex(canonicalJson(publicInterface));
      if (computedInterfaceHash.replace(/^0x/, "") !== interfaceHash.replace(/^0x/, "")) {
        throw new ApiError(400, "interface_hash_mismatch", "interface_hash must bind the canonical public interface");
      }
      const dependencies = assertPlainObject(published["dependencies"], "invalid_registry_dependencies");
      for (const [dependencyName, dependencyValue] of Object.entries(dependencies)) {
        validatePackageIdent(dependencyName, "dependency name");
        const dependency = assertPlainObject(dependencyValue, "invalid_registry_dependency");
        validatePackageIdent(requireString(dependency, "namespace"), "dependency namespace");
        validateVersion(requireString(dependency, "version"));
      }
      break;
    }
    case "ckb-executable-profile-v1":
      validateHash(requireString(published, "artifact_hash"), "artifact_hash", "invalid_artifact_hash");
      validateHash(requireString(published, "abi_hash"), "abi_hash", "invalid_abi_hash");
      break;
    case "reproducible-build-profile-v1":
      validateHash(requireString(published, "artifact_hash"), "artifact_hash", "invalid_artifact_hash");
      validateHash(requireString(published, "build_recipe_hash"), "build_recipe_hash", "invalid_build_recipe_hash");
      break;
    case "copy-material-profile-v1":
      break;
  }
  if (profileDefinition.requires_profile_contract) {
    validateArtifactProfileContract(published["profile_contract"], artifact, published, outer.manifestHash);
  }

  return entry as unknown as RegistryIndexEntry;
}

function validateArtifactProfileContract(
  input: unknown,
  artifact: ArtifactDescriptor,
  release: Record<string, unknown>,
  manifestHash: string,
): void {
  let contract: Record<string, unknown>;
  try {
    contract = assertPlainObject(input, "invalid_profile_contract");
  } catch {
    throw new ApiError(400, "invalid_profile_contract", "profile_contract must be a JSON object");
  }
  exactKeys(
    contract,
    ["schema", "artifact_kind", "profile", "build", "security", "ckb", "interface", "verifier", "reproduction", "copy"],
    "profile_contract",
  );
  requireLiteral(contract, "schema", ARTIFACT_PROFILE_CONTRACT_SCHEMA, "profile_contract");
  requireLiteral(contract, "artifact_kind", artifact.kind, "profile_contract");
  requireLiteral(contract, "profile", artifact.profile, "profile_contract");
  requireSameContentHash(ckbBlake2bHex(canonicalJson(contract)), manifestHash, "profile_contract manifest_hash");

  if (artifact.kind === "runtime_verifier" || artifact.kind === "deployable_contract") {
    const reproducible = validateBuildContract(contract);
    validateSecurityContract(contract);
    const ckb = requiredObject(contract, "ckb", "profile_contract");
    exactKeys(ckb, ["vm_version", "script_role", "hash_type", "dep_type", "abi_hash"], "profile_contract.ckb");
    requireOneOf(ckb, "vm_version", ["0", "1", "2"], "profile_contract.ckb");
    requireOneOf(ckb, "script_role", ["lock", "type", "dual_role", "helper"], "profile_contract.ckb");
    requireOneOf(ckb, "hash_type", ["data", "data1", "data2", "type"], "profile_contract.ckb");
    requireOneOf(ckb, "dep_type", ["code", "dep_group"], "profile_contract.ckb");
    requireBoundHash(ckb, "abi_hash", release["abi_hash"], "profile_contract.ckb");
    validateLsIdlInterfaceContract(contract, artifact);
    validateReproductionContract(contract, release, reproducible);
    forbidKeys(contract, ["copy"], "profile_contract");
    if (artifact.kind === "runtime_verifier") {
      forbidKeys(contract, ["interface"], "profile_contract");
      const verifier = requiredObject(contract, "verifier", "profile_contract");
      exactKeys(verifier, ["verifier_id", "ipc_abi", "ipc_abi_hash"], "profile_contract.verifier");
      requireString(verifier, "verifier_id");
      requireString(verifier, "ipc_abi");
      requireBoundHash(verifier, "ipc_abi_hash", release["abi_hash"], "profile_contract.verifier");
    } else {
      forbidKeys(contract, ["verifier"], "profile_contract");
    }
    return;
  }
  if (artifact.kind === "reproducible_binary") {
    validateBuildContract(contract, true);
    validateSecurityContract(contract);
    forbidKeys(contract, ["ckb", "interface", "verifier", "copy"], "profile_contract");
    validateReproductionContract(contract, release, true);
    return;
  }
  if (artifact.kind === "template") {
    forbidKeys(contract, ["build", "security", "ckb", "interface", "verifier", "reproduction"], "profile_contract");
    const copy = requiredObject(contract, "copy", "profile_contract");
    exactKeys(copy, ["format", "entrypoint"], "profile_contract.copy");
    requireOneOf(copy, "format", ["file_map_v1"], "profile_contract.copy");
    requireString(copy, "entrypoint");
    return;
  }
  throw new ApiError(400, "invalid_profile_contract", "profile_contract is not valid for this artifact kind");
}

function validateLsIdlInterfaceContract(contract: Record<string, unknown>, artifact: ArtifactDescriptor): void {
  if (contract["interface"] === undefined) return;
  if (artifact.kind !== "deployable_contract") {
    throw new ApiError(400, "invalid_profile_contract", "LS-IDL is valid only for deployable_contract artifacts");
  }
  const ckb = requiredObject(contract, "ckb", "profile_contract");
  requireLiteral(ckb, "script_role", "lock", "profile_contract.ckb");
  const interfaceContract = requiredObject(contract, "interface", "profile_contract");
  exactKeys(
    interfaceContract,
    ["schema", "format", "format_version", "object_role", "content_type", "encoding", "commitment"],
    "profile_contract.interface",
  );
  requireLiteral(interfaceContract, "schema", LS_IDL_INTERFACE_SCHEMA, "profile_contract.interface");
  requireLiteral(interfaceContract, "format", "ls-idl", "profile_contract.interface");
  requireLiteral(interfaceContract, "format_version", LS_IDL_FORMAT_VERSION, "profile_contract.interface");
  requireLiteral(interfaceContract, "object_role", "abi", "profile_contract.interface");
  requireLiteral(interfaceContract, "content_type", LS_IDL_CONTENT_TYPE, "profile_contract.interface");
  requireLiteral(interfaceContract, "encoding", "linear-le-v0", "profile_contract.interface");
  const commitment = requiredObject(interfaceContract, "commitment", "profile_contract.interface");
  exactKeys(commitment, ["algorithm", "placement", "digest"], "profile_contract.interface.commitment");
  requireLiteral(commitment, "algorithm", "sha256", "profile_contract.interface.commitment");
  requireLiteral(commitment, "placement", "code-cell-data-suffix-32", "profile_contract.interface.commitment");
  validateHash(
    requireString(commitment, "digest"),
    "profile_contract.interface.commitment.digest",
    "invalid_profile_contract",
  );
}

function validateBuildContract(contract: Record<string, unknown>, expectedReproducible?: boolean): boolean {
  const build = requiredObject(contract, "build", "profile_contract");
  exactKeys(build, ["target", "toolchain", "profile", "source_revision", "reproducible"], "profile_contract.build");
  for (const field of ["target", "toolchain", "profile", "source_revision"]) requireString(build, field);
  if (typeof build["reproducible"] !== "boolean") {
    throw new ApiError(400, "invalid_profile_contract", "profile_contract.build.reproducible must be a boolean");
  }
  if (expectedReproducible !== undefined && build["reproducible"] !== expectedReproducible) {
    throw new ApiError(400, "invalid_profile_contract", `profile_contract.build.reproducible must be ${expectedReproducible}`);
  }
  return build["reproducible"];
}

function validateReproductionContract(
  contract: Record<string, unknown>,
  release: Record<string, unknown>,
  reproducible: boolean,
): void {
  if (!reproducible) {
    forbidKeys(contract, ["reproduction"], "profile_contract");
    if (release["build_recipe_hash"] !== undefined) {
      throw new ApiError(400, "invalid_profile_contract", "build_recipe_hash requires profile_contract.build.reproducible=true");
    }
    return;
  }
  const reproduction = requiredObject(contract, "reproduction", "profile_contract");
  exactKeys(reproduction, ["environment", "command", "recipe_hash", "expected_artifact_hash"], "profile_contract.reproduction");
  requireString(reproduction, "environment");
  requireString(reproduction, "command");
  requireBoundHash(reproduction, "recipe_hash", release["build_recipe_hash"], "profile_contract.reproduction");
  requireBoundHash(reproduction, "expected_artifact_hash", release["artifact_hash"], "profile_contract.reproduction");
}

function validateSecurityContract(contract: Record<string, unknown>): void {
  const security = requiredObject(contract, "security", "profile_contract");
  exactKeys(security, ["status", "audit_report_hash"], "profile_contract.security");
  const status = requireOneOf(security, "status", ["unaudited", "review_required", "audited", "rejected"], "profile_contract.security");
  if (status === "audited" && security["audit_report_hash"] === undefined) {
    throw new ApiError(400, "invalid_profile_contract", "profile_contract.security.audit_report_hash is required for audited artifacts");
  }
  if (security["audit_report_hash"] !== undefined) {
    validateHash(requireString(security, "audit_report_hash"), "profile_contract.security.audit_report_hash", "invalid_profile_contract");
  }
}

function exactKeys(object: Record<string, unknown>, allowed: string[], label: string): void {
  const unexpected = Object.keys(object).find((key) => !allowed.includes(key));
  if (unexpected) throw new ApiError(400, "invalid_profile_contract", `${label}.${unexpected} is not recognised`);
}

function forbidKeys(object: Record<string, unknown>, forbidden: string[], label: string): void {
  const present = forbidden.find((key) => object[key] !== undefined);
  if (present) throw new ApiError(400, "invalid_profile_contract", `${label}.${present} is not valid for this artifact kind`);
}

function requiredObject(object: Record<string, unknown>, key: string, label: string): Record<string, unknown> {
  try {
    return assertPlainObject(object[key], "invalid_profile_contract");
  } catch {
    throw new ApiError(400, "invalid_profile_contract", `${label}.${key} must be a JSON object`);
  }
}

function requireLiteral(object: Record<string, unknown>, key: string, expected: string, label: string): void {
  if (requireString(object, key) !== expected) {
    throw new ApiError(400, "invalid_profile_contract", `${label}.${key} must be '${expected}'`);
  }
}

function requireOneOf(object: Record<string, unknown>, key: string, allowed: string[], label: string): string {
  const value = requireString(object, key);
  if (!allowed.includes(value)) {
    throw new ApiError(400, "invalid_profile_contract", `${label}.${key} must be one of ${allowed.join(", ")}`);
  }
  return value;
}

function requireBoundHash(object: Record<string, unknown>, key: string, expected: unknown, label: string): void {
  const value = requireString(object, key);
  validateHash(value, `${label}.${key}`, "invalid_profile_contract");
  if (typeof expected !== "string") {
    throw new ApiError(400, "invalid_profile_contract", `${label}.${key} has no release hash to bind`);
  }
  requireSameContentHash(value, expected, `${label}.${key}`);
}

function requireSameContentHash(actual: string, expected: string, label: string): void {
  const normalize = (value: string) => value.replace(/^0x/i, "").toLowerCase();
  if (normalize(actual) !== normalize(expected)) {
    throw new ApiError(400, "invalid_profile_contract", `${label} does not match the signed immutable object hash`);
  }
}

export const ARTIFACT_PROFILE_CATALOG = {
  cellscript_source: {
    schema: ARTIFACT_PROFILE_CATALOG_SCHEMA,
    profile: "cellscript_source",
    validator_id: "cellscript-source-package-v1",
    resolver_capability: "dependency",
    requires_profile_contract: false,
    contracts: {
      source_library: { consumption_mode: "dependency", languages: ["cellscript"] },
      profile_library: { consumption_mode: "dependency", languages: ["cellscript"] },
    },
  },
  ckb_executable: {
    schema: ARTIFACT_PROFILE_CATALOG_SCHEMA,
    profile: "ckb_executable",
    validator_id: "ckb-executable-profile-v1",
    resolver_capability: "non_resolving",
    requires_profile_contract: true,
    contracts: {
      runtime_verifier: { consumption_mode: "tcb", languages: ["cellscript", "rust", "c", "javascript", "other"] },
      deployable_contract: { consumption_mode: "deployment", languages: ["cellscript", "rust", "c", "javascript", "other"] },
    },
  },
  reproducible_build: {
    schema: ARTIFACT_PROFILE_CATALOG_SCHEMA,
    profile: "reproducible_build",
    validator_id: "reproducible-build-profile-v1",
    resolver_capability: "non_resolving",
    requires_profile_contract: true,
    contracts: {
      reproducible_binary: { consumption_mode: "tcb", languages: ["rust", "c", "other"] },
    },
  },
  copy_material: {
    schema: ARTIFACT_PROFILE_CATALOG_SCHEMA,
    profile: "copy_material",
    validator_id: "copy-material-profile-v1",
    resolver_capability: "non_resolving",
    requires_profile_contract: true,
    contracts: {
      template: { consumption_mode: "copy", languages: ["cellscript", "rust", "c", "javascript", "other", "unspecified"] },
    },
  },
} as const satisfies Record<ArtifactProfile, ArtifactProfileDefinition>;

export function artifactProfileSupportsDependencyResolution(profile: ArtifactProfile): boolean {
  return ARTIFACT_PROFILE_CATALOG[profile].resolver_capability === "dependency";
}

export function validateArtifactDescriptor(input: unknown): ArtifactDescriptor {
  const value = assertPlainObject(input, "invalid_artifact_descriptor");
  const kind = requireString(value, "kind") as ArtifactKind;
  const profile = requireString(value, "profile") as ArtifactProfile;
  const consumptionMode = requireString(value, "consumption_mode") as ConsumptionMode;
  const language = requireString(value, "language") as ArtifactLanguage;
  if (!ARTIFACT_KINDS.includes(kind)) {
    throw new ApiError(400, "invalid_artifact_kind", `artifact.kind must be one of ${ARTIFACT_KINDS.join(", ")}`);
  }
  if (!ARTIFACT_PROFILES.includes(profile)) {
    throw new ApiError(400, "invalid_artifact_profile", `artifact.profile must be one of ${ARTIFACT_PROFILES.join(", ")}`);
  }
  const profileDefinition = ARTIFACT_PROFILE_CATALOG[profile];
  const contracts = profileDefinition.contracts as Partial<
    Record<ArtifactKind, { consumption_mode: ConsumptionMode; languages: readonly ArtifactLanguage[] }>
  >;
  const contract = contracts[kind];
  if (!contract || consumptionMode !== contract.consumption_mode || !(contract.languages as readonly string[]).includes(language)) {
    throw new ApiError(400, "invalid_artifact_contract", "artifact profile, consumption mode, and language do not match its kind");
  }
  return { kind, profile, consumption_mode: consumptionMode, language };
}

export function initialArtifactStates(artifact: ArtifactDescriptor): {
  verification_status: VerificationStatus;
  deployment_status: DeploymentStatus;
  availability_status: AvailabilityStatus;
} {
  return {
    verification_status: "pending",
    deployment_status: artifact.profile === "ckb_executable" ? "undeployed" : "not_applicable",
    availability_status: "active",
  };
}

export function validateSnapshot(input: unknown, payload: PublishPayload, maxBytes: number): SourceSnapshotInput {
  const obj = assertPlainObject(input, "invalid_source_snapshot");
  const contentBase64 = requireString(obj, "content_base64");
  const contentType = requireString(obj, "content_type");
  const sizeBytes = Number(obj["size_bytes"]);
  const sourceHash = requireString(obj, "source_hash");
  if (!Number.isInteger(sizeBytes) || sizeBytes <= 0 || sizeBytes > maxBytes) {
    throw new ApiError(413, "snapshot_too_large", `source snapshot must be 1..${maxBytes} bytes`);
  }
  if (sourceHash !== payload.source_hash) {
    throw new ApiError(400, "snapshot_source_hash_mismatch", "snapshot source_hash must match publish payload source_hash");
  }
  return { content_base64: contentBase64, content_type: contentType, size_bytes: sizeBytes, source_hash: sourceHash };
}

export async function verifyJoyidAuthorisationPayload(
  payload: CapabilityAuthorisationPayload,
  signature: SignChallengeResponseData,
  verifier: JoyidVerifier,
): Promise<void> {
  return verifyJoyidPayloadSignature(payload, signature, verifier);
}

export async function verifyPrincipalAuthorisationPayload(
  payload: CapabilityAuthorisationPayload,
  signature: PrincipalSignature,
  joyidVerifier: JoyidVerifier,
): Promise<void> {
  return verifyPrincipalPayloadSignature(payload, signature, joyidVerifier);
}

export async function verifyPrincipalPayloadSignature(
  payload: unknown,
  signature: PrincipalSignature,
  joyidVerifier: JoyidVerifier,
): Promise<void> {
  const principalType = principalTypeFromPayload(payload);
  if (principalType === JOYID_PRINCIPAL_TYPE) {
    if (isCkbSecp256k1Signature(signature)) {
      throw new ApiError(400, "signature_scheme_mismatch", "joyid_ckb requires a JoyID signature");
    }
    return verifyJoyidPayloadSignature(payload, signature, joyidVerifier);
  }
  if (!isCkbSecp256k1Signature(signature)) {
    throw new ApiError(400, "signature_scheme_mismatch", "ckb_secp256k1 requires a CKB secp256k1 signature");
  }
  return verifyCkbSecp256k1PayloadSignature(payload, signature);
}

function principalTypeFromPayload(payload: unknown): PrincipalType {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ApiError(400, "invalid_principal_payload", "signed payload must be a JSON object");
  }
  return validatePrincipalType(requireString(payload as Record<string, unknown>, "principal_type"));
}

export function isCkbSecp256k1Signature(signature: PrincipalSignature): signature is CkbSecp256k1Signature {
  return "scheme" in signature && signature.scheme === CKB_SECP256K1_PRINCIPAL_TYPE;
}

export async function verifyJoyidPayloadSignature(
  payload: unknown,
  signature: SignChallengeResponseData,
  verifier: JoyidVerifier,
): Promise<void> {
  const expectedChallenge = canonicalJson(payload);
  if (signature.challenge !== expectedChallenge) {
    throw new ApiError(401, "joyid_challenge_mismatch", "JoyID signature challenge does not match the capability payload");
  }
  if (signature.keyType !== "main_key" && signature.keyType !== "sub_key") {
    throw new ApiError(401, "joyid_root_required", "capability authorisation must be signed by a JoyID main or sub key");
  }
  await verifyJoyidPrincipalBinding(payload, signature);
  if (!(await verifier.verifySignature(signature))) {
    throw new ApiError(401, "joyid_signature_invalid", "JoyID signature verification failed");
  }
}

async function verifyJoyidPrincipalBinding(payload: unknown, signature: SignChallengeResponseData): Promise<void> {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return;
  }
  const obj = payload as Record<string, unknown>;
  if (obj["principal_type"] !== JOYID_PRINCIPAL_TYPE || typeof obj["principal_id"] !== "string") {
    return;
  }
  const principalId = obj["principal_id"].trim().toLowerCase();
  const candidates = await joyidPrincipalIdCandidates(signature);
  if (!candidates.includes(principalId)) {
    throw new ApiError(401, "joyid_principal_mismatch", "JoyID signature does not match payload principal_id");
  }
}

export async function joyidPrincipalIdCandidates(signature: Pick<SignChallengeResponseData, "pubkey" | "keyType">): Promise<string[]> {
  if (typeof signature.pubkey !== "string" || signature.pubkey.trim() === "") {
    throw new ApiError(401, "joyid_pubkey_missing", "JoyID signature must include pubkey");
  }
  if (signature.keyType !== "main_key" && signature.keyType !== "sub_key") {
    throw new ApiError(401, "joyid_root_required", "capability authorisation must be signed by a JoyID main or sub key");
  }
  const pubkey = normalizeJoyidPubkey(signature.pubkey);
  const candidates = new Set<string>();
  candidates.add(await joyidPrincipalIdFromBinding(signature.keyType, pubkey));
  if (/^[0-9a-f]{40,64}$/.test(pubkey)) {
    candidates.add(`0x${pubkey}`);
  }
  return [...candidates];
}

export async function joyidPrincipalIdFromBinding(keyType: "main_key" | "sub_key", pubkey: string): Promise<string> {
  const material = `${JOYID_CKB_PRINCIPAL_BINDING_CONTEXT}\n${keyType}\n${normalizeJoyidPubkey(pubkey)}`;
  return `0x${await sha256Hex(material)}`;
}

function normalizeJoyidPubkey(pubkey: string): string {
  const value = pubkey.trim().toLowerCase();
  return value.startsWith("0x") ? value.slice(2) : value;
}

export async function ckbSecp256k1PrincipalIdFromPublicKey(publicKey: string): Promise<string> {
  const normalized = normalizeCkbSecp256k1PublicKey(publicKey);
  const material = `${CKB_SECP256K1_PRINCIPAL_BINDING_CONTEXT}\n${normalized}`;
  return `0x${await sha256Hex(material)}`;
}

export async function verifyCkbSecp256k1PayloadSignature(
  payload: unknown,
  signature: CkbSecp256k1Signature,
): Promise<void> {
  const expectedChallenge = canonicalJson(payload);
  if (signature.challenge !== expectedChallenge) {
    throw new ApiError(401, "ckb_challenge_mismatch", "CKB signature challenge does not match the payload");
  }
  const publicKey = normalizeCkbSecp256k1PublicKey(signature.public_key);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ApiError(400, "invalid_principal_payload", "signed payload must be a JSON object");
  }
  const obj = payload as Record<string, unknown>;
  if (obj["principal_type"] !== CKB_SECP256K1_PRINCIPAL_TYPE || typeof obj["principal_id"] !== "string") {
    throw new ApiError(400, "signature_scheme_mismatch", "payload is not bound to ckb_secp256k1");
  }
  const expectedPrincipalId = await ckbSecp256k1PrincipalIdFromPublicKey(publicKey);
  if (obj["principal_id"].trim().toLowerCase() !== expectedPrincipalId) {
    throw new ApiError(401, "ckb_principal_mismatch", "CKB public key does not match payload principal_id");
  }

  const signatureBytes = hexToBytes(signature.signature);
  const recoveryId = signatureBytes[64];
  if (signatureBytes.length !== 65 || recoveryId === undefined || recoveryId > 3) {
    throw new ApiError(401, "ckb_signature_invalid", "CKB signature must be a 65-byte recoverable secp256k1 signature");
  }
  const message = new TextEncoder().encode(`Nervos Message:${expectedChallenge}`);
  const messageHash = blake2b(message, {
    dkLen: 32,
    personalization: new TextEncoder().encode("ckb-default-hash"),
  });
  const recoveredSignature = new Uint8Array(65);
  recoveredSignature[0] = recoveryId;
  recoveredSignature.set(signatureBytes.subarray(0, 64), 1);
  let verified = false;
  try {
    verified = secp256k1.verify(recoveredSignature, messageHash, hexToBytes(publicKey), {
      format: "recovered",
      prehash: false,
    });
  } catch {
    verified = false;
  }
  if (!verified) {
    throw new ApiError(401, "ckb_signature_invalid", "CKB secp256k1 signature verification failed");
  }
}

function normalizeCkbSecp256k1PublicKey(publicKey: string): string {
  const normalized = publicKey.trim().toLowerCase();
  const clean = normalized.startsWith("0x") ? normalized.slice(2) : normalized;
  if (!/^(02|03)[0-9a-f]{64}$/.test(clean)) {
    throw new ApiError(400, "invalid_ckb_public_key", "CKB public key must be a compressed 33-byte secp256k1 key");
  }
  return `0x${clean}`;
}

export function scopeAllows(
  scopes: string[],
  action: CapabilityScopeAction,
  namespace: string,
  name: string,
): boolean {
  return scopes.includes(`${action}:${namespace}/${name}`) || scopes.includes(`${action}:${namespace}/*`);
}

export async function capabilityKeyId(capabilityPubkey: string): Promise<string> {
  return `cap_${(await sha256Hex(capabilityPubkey)).slice(0, 32)}`;
}

const P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

export function isCanonicalP256SpkiPublicKey(value: string): boolean {
  if (!value.startsWith("p256-spki:")) return false;
  try {
    const bytes = base64UrlToBytes(value.slice("p256-spki:".length));
    if (bytes.length !== P256_SPKI_PREFIX.length + 65 || bytes[P256_SPKI_PREFIX.length] !== 0x04) return false;
    return P256_SPKI_PREFIX.every((byte, index) => bytes[index] === byte);
  } catch {
    return false;
  }
}

export async function isImportableP256SpkiPublicKey(value: string): Promise<boolean> {
  if (!isCanonicalP256SpkiPublicKey(value)) return false;
  try {
    await crypto.subtle.importKey(
      "spki",
      toArrayBuffer(base64UrlToBytes(value.slice("p256-spki:".length))),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return true;
  } catch {
    return false;
  }
}

export class WebCryptoP256Verifier implements CapabilitySignatureVerifier {
  async verify(canonicalPayload: string, capabilityPubkey: string, signature: CapabilitySignature): Promise<boolean> {
    if (signature.algorithm !== "p256-sha256" || !isCanonicalP256SpkiPublicKey(capabilityPubkey)) {
      return false;
    }
    try {
      const spki = base64UrlToBytes(capabilityPubkey.slice("p256-spki:".length));
      const sig = parseSignatureBytes(signature.signature);
      const key = await crypto.subtle.importKey(
        "spki",
        toArrayBuffer(spki),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        toArrayBuffer(sig),
        new TextEncoder().encode(canonicalPayload),
      );
    } catch {
      return false;
    }
  }
}
