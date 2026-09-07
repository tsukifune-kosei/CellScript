import { verifySignature, type SignChallengeResponseData } from "@joyid/ckb";
import {
  ARTIFACT_KINDS,
  CKB_SECP256K1_PRINCIPAL_TYPE,
  JOYID_PRINCIPAL_TYPE,
  ApiError,
  DEPLOYMENT_ACTION,
  DEPLOYMENT_PROTOCOL,
  DEFAULT_REGISTRY_ORIGIN,
  DEFAULT_STATIC_REGISTRY_ORIGIN,
  REGISTRY_SCHEMA_VERSION,
  WebCryptoP256Verifier,
  assertPlainObject,
  base64ToBytes,
  canonicalJson,
  capabilityKeyId,
  ckbBlake2bHex,
  ckbScriptHash,
  hexToBytes,
  initialArtifactStates,
  interfacePredecessorVersion,
  isCanonicalP256SpkiPublicKey,
  isImportableP256SpkiPublicKey,
  isPrincipalType,
  scopeAllows,
  sha256Hex,
  sameCkbHash,
  validateCapabilityPayload,
  validateCapabilityRevocationPayload,
  validateDeploymentPayload,
  validateAvailabilityPayload,
  validatePackageIdent,
  validatePublishPayload,
  validateInterfaceUpgrade,
  validateSnapshot,
  validateVersion,
  verifyPrincipalAuthorisationPayload,
  verifyPrincipalPayloadSignature,
  type CapabilitySignature,
  type CapabilitySignatureVerifier,
  type CkbSecp256k1Signature,
  type JoyidVerifier,
  type PrincipalSignature,
  type PrincipalType,
  type ArtifactKind,
  type AvailabilityStatus,
  type DeploymentStatus,
  type DeploymentPayload,
  type SourceSnapshotInput,
  type VerificationStatus,
} from "./domain";
import {
  MemoryRegistryStore,
  deriveRegistryEntryStatus,
  packageVersionRequiresReproduction,
  type IdempotencyRecord,
  type PackageEvidenceKind,
  type PackageEvidenceRecord,
  type PackageVersionRecord,
  type RegistryStore,
  type SnapshotRecord,
} from "./store";
import { SqlRegistryStore, type HyperdriveLike } from "./sql-store";

export interface Env {
  HYPERDRIVE?: HyperdriveLike;
  REGISTRY_OBJECTS?: R2Bucket;
  SOURCE_SNAPSHOTS?: R2Bucket;
  REGISTRY_ORIGIN?: string;
  STATIC_REGISTRY_ORIGIN?: string;
  REGISTRY_WEBSITE_ORIGIN?: string;
  MAX_JSON_BODY_BYTES?: string;
  MAX_SNAPSHOT_BYTES?: string;
  REGISTRY_ADMIN_TOKEN?: string;
  ENVIRONMENT?: string;
  REGISTRY_ENVIRONMENT?: string;
  CLEANUP_QUOTA_EVENT_RETENTION_HOURS?: string;
  NAMESPACE_CLAIM_COOLDOWN_SECONDS?: string;
  CKB_MAINNET_RPC_URL?: string;
  CKB_RPC_URL?: string;
  CKB_RPC_TIMEOUT_MS?: string;
  CKB_RPC_MAX_RESPONSE_BYTES?: string;
  CKB_DEP_GROUP_MAX_MEMBERS?: string;
  REGISTRY_TYPE_SCRIPT_JSON?: string;
  REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON?: string;
  REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON?: string;
  REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON?: string;
  REGISTRY_REPRODUCER_POLICY_JSON?: string;
  CKB_REGISTRY_SCAN_MAX_CELLS?: string;
  CKB_MIN_CONFIRMATIONS?: string;
}

export interface SnapshotWriter {
  put(key: string, body: Uint8Array, options: { contentType: string; metadata: Record<string, string> }): Promise<void>;
  delete?(key: string): Promise<void>;
}

export interface RegistryObjectRead {
  body: BodyInit;
  contentType?: string;
  etag?: string;
}

export interface RegistryObjectReader {
  get(key: string): Promise<RegistryObjectRead | null>;
}

export interface AppDeps {
  store?: RegistryStore;
  joyidVerifier?: JoyidVerifier;
  capabilityVerifier?: CapabilitySignatureVerifier;
  snapshotWriter?: SnapshotWriter;
  registryObjectReader?: RegistryObjectReader;
  readinessCheck?: () => Promise<Record<string, string>>;
  verifyDeployment?: (payload: DeploymentPayload) => Promise<VerifiedDeployment>;
  /** @deprecated Use verifyDeployment. */
  verifyMainnetDeployment?: (payload: DeploymentPayload) => Promise<VerifiedDeployment>;
  verifyRegistryCommitment?: (
    evidence: Record<string, unknown>,
    version: PackageVersionRecord,
    deployed: PackageEvidenceRecord,
  ) => Promise<Record<string, unknown>>;
  /** @deprecated Use verifyRegistryCommitment. */
  verifyMainnetCommitment?: (
    evidence: Record<string, unknown>,
    version: PackageVersionRecord,
    deployed: PackageEvidenceRecord,
  ) => Promise<Record<string, unknown>>;
  verifyRegistryCommitmentConfiguration?: (configuration: RegistryCommitmentConfiguration) => Promise<void>;
  listRegistryCommitmentCells?: (configuration: RegistryCommitmentConfiguration) => Promise<RegistryCommitmentCell[]>;
  /** @deprecated Use listRegistryCommitmentCells. */
  listMainnetCommitmentCells?: (configuration: RegistryCommitmentConfiguration) => Promise<RegistryCommitmentCell[]>;
  now?: () => Date;
}

export interface RegistryCommitmentConfiguration {
  type_script: Record<string, unknown>;
  type_script_hash: string;
  type_script_cell_dep: Record<string, unknown>;
  commitment_lock_script: Record<string, unknown>;
  commitment_lock_hash: string;
  commitment_lock_cell_dep: Record<string, unknown>;
}

export interface RegistryCommitmentCell {
  commitment_hash: string;
  out_point: { tx_hash: string; index: number };
  block_number: string;
  tip_block_number?: string;
  confirmations?: number;
  output: Record<string, unknown>;
}

const DEFAULT_MAX_JSON_BODY_BYTES = 6 * 1024 * 1024;
const DEFAULT_MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024;
const DEFAULT_QUOTA_EVENT_RETENTION_HOURS = 48;
const DEFAULT_NAMESPACE_CLAIM_COOLDOWN_SECONDS = 60 * 60;
const TESTNET_SANDBOX_TTL_HOURS = 72;
const TESTNET_SANDBOX_PURGE_GRACE_HOURS = 24;
const AUTHORISATION_SESSION_TTL_MINUTES = 15;

export type RegistryEnvironment = "production" | "testnet-sandbox";

export interface RegistryRuntimeConfig {
  environment: RegistryEnvironment;
  network: DeploymentPayload["network"];
  rpc_url: string;
  record_ttl_hours: number | null;
  object_purge_grace_hours: number | null;
}

export function registryRuntimeConfig(env: Env): RegistryRuntimeConfig {
  const value = (env.REGISTRY_ENVIRONMENT ?? "production").trim().toLowerCase();
  if (value === "production") {
    return {
      environment: "production",
      network: "mainnet",
      rpc_url: env.CKB_RPC_URL?.trim() || env.CKB_MAINNET_RPC_URL?.trim() || "https://mainnet.ckb.dev/rpc",
      record_ttl_hours: null,
      object_purge_grace_hours: null,
    };
  }
  if (value === "testnet-sandbox") {
    const registryOrigin = (env.REGISTRY_ORIGIN ?? "").trim();
    const staticOrigin = (env.STATIC_REGISTRY_ORIGIN ?? "").trim();
    if (!registryOrigin || !staticOrigin
      || registryOrigin === DEFAULT_REGISTRY_ORIGIN
      || staticOrigin === DEFAULT_STATIC_REGISTRY_ORIGIN) {
      throw new ApiError(
        503,
        "testnet_sandbox_not_isolated",
        "testnet-sandbox requires dedicated Registry API and object origins",
      );
    }
    return {
      environment: "testnet-sandbox",
      network: "testnet",
      rpc_url: env.CKB_RPC_URL?.trim() || "https://testnet.ckb.dev/rpc",
      record_ttl_hours: TESTNET_SANDBOX_TTL_HOURS,
      object_purge_grace_hours: TESTNET_SANDBOX_PURGE_GRACE_HOURS,
    };
  }
  throw new ApiError(503, "invalid_registry_environment", "REGISTRY_ENVIRONMENT must be production or testnet-sandbox");
}
export const CANONICAL_REGISTRY_TYPE_SCRIPT = Object.freeze({
  code_hash: "0x0dd596ade29e06e5bcc00f56abf36ecbe9afaa09f1b26a64436aa37854da622b",
  hash_type: "data1",
});
export const CKB_MAINNET_SIGHASH_LOCK = Object.freeze({
  code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
  hash_type: "type",
});
export const CKB_MAINNET_SIGHASH_DEP_GROUP = Object.freeze({
  out_point: Object.freeze({
    tx_hash: "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
    index: "0x0",
  }),
  dep_type: "dep_group",
});
export const CKB_TESTNET_SIGHASH_DEP_GROUP = Object.freeze({
  out_point: Object.freeze({
    tx_hash: "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
    index: "0x0",
  }),
  dep_type: "dep_group",
});

export function createApp(deps: AppDeps = {}) {
  return {
    async fetch(request: Request, env: Env = {}, ctx?: ExecutionContext): Promise<Response> {
      const requestId = request.headers.get("cf-ray") ?? crypto.randomUUID();
      try {
        return await routeRequest(request, env, requestId, deps, ctx);
      } catch (error) {
        await appendFailureAuditEvent(request, env, requestId, deps, error);
        return errorResponse(error, requestId);
      }
    },
    async scheduled(_controller: ScheduledController, env: Env = {}, _ctx?: ExecutionContext): Promise<void> {
      await runScheduledMaintenance(env, deps);
    },
  };
}

async function runScheduledMaintenance(env: Env, deps: AppDeps): Promise<void> {
  const store = deps.store ?? getProductionStore(env);
  await store.withMaintenanceLease("cellscript-registry:scheduled-maintenance", async () => {
    await runScheduledMaintenanceUnderLease(env, deps, store);
  });
}

async function runScheduledMaintenanceUnderLease(env: Env, deps: AppDeps, store: RegistryStore): Promise<void> {
  const now = deps.now?.() ?? new Date();
  const runtime = registryRuntimeConfig(env);
  const requestId = `scheduled:${now.toISOString()}`;
  const quotaCutoff = new Date(now.getTime() - quotaEventRetentionHours(env) * 60 * 60 * 1000).toISOString();
  const result = await store.cleanupExpiredState({
    now_iso: now.toISOString(),
    quota_events_before_iso: quotaCutoff,
  });
  await store.appendAuditEvent({
    request_id: requestId,
    event_type: "maintenance.cleanup",
    data: {
      quota_events_before_iso: quotaCutoff,
      ...result,
    },
  });
  if (runtime.environment === "testnet-sandbox") {
    await purgeExpiredSandboxObjects(env, deps, store, now, requestId, result);
  }
  let configuration: RegistryCommitmentConfiguration | null;
  try {
    configuration = registryCommitmentConfiguration(env, false);
    if (!configuration) {
      const demoted = await demoteCurrentCommitments(
        env,
        deps,
        store,
        requestId,
        "registry_commitment_unconfigured",
      );
      await store.appendAuditEvent({
        request_id: requestId,
        event_type: "maintenance.registry_commitment_disabled",
        data: { demoted_commitments: demoted },
      });
      return;
    }
    await requireLiveRegistryCommitmentConfiguration(env, deps, configuration);
  } catch (error) {
    const code = error instanceof ApiError ? error.code : "registry_commitment_configuration_check_failed";
    const deterministic = error instanceof ApiError && [
      "registry_commitment_misconfigured",
      "registry_commitment_cell_dep_invalid",
      "registry_commitment_code_hash_unresolved",
      "ckb_rpc_not_mainnet",
      "ckb_rpc_not_testnet",
      "deployment_cell_not_live",
      "invalid_dep_group",
      "chain_observation_uncommitted",
      "chain_confirmation_depth_insufficient",
    ].includes(error.code);
    const demoted = deterministic
      ? await demoteCurrentCommitments(env, deps, store, requestId, code)
      : 0;
    await store.appendAuditEvent({
      request_id: requestId,
      event_type: "maintenance.registry_commitment_configuration_failed",
      data: {
        error_code: code,
        error: error instanceof Error ? error.message : String(error),
        deterministic,
        demoted_commitments: demoted,
      },
    });
    return;
  }
  await reconcileRegistryChainState(env, deps, store, now, requestId);
}

async function purgeExpiredSandboxObjects(
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  now: Date,
  requestId: string,
  result: Awaited<ReturnType<RegistryStore["cleanupExpiredState"]>>,
): Promise<void> {
  const staticCandidates = result.static_objects ?? [];
  const sourceCandidates = result.source_objects ?? [];
  if (staticCandidates.length === 0 && sourceCandidates.length === 0) return;
  const writer = deps.snapshotWriter ?? r2SnapshotWriter(env);
  if (!writer.delete) {
    throw new ApiError(503, "registry_object_delete_unconfigured", "testnet-sandbox requires an object store with delete support");
  }
  const deletedStatic = [];
  const deletedSource = [];
  for (const candidate of staticCandidates) {
    await writer.delete(candidate.key);
    deletedStatic.push(candidate);
  }
  for (const candidate of sourceCandidates) {
    await writer.delete(candidate.key);
    deletedSource.push(candidate);
  }
  await store.markSandboxObjectsPurged({
    static_objects: deletedStatic,
    source_objects: deletedSource,
    purged_at: now.toISOString(),
  });
  await store.appendAuditEvent({
    request_id: requestId,
    event_type: "maintenance.testnet_sandbox_objects_purged",
    data: {
      static_objects_deleted: deletedStatic.length,
      source_objects_deleted: deletedSource.length,
    },
  });
}

async function routeRequest(
  request: Request,
  env: Env,
  requestId: string,
  deps: AppDeps,
  _ctx?: ExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  const headers = corsHeaders(requestId);
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }
  if (request.method === "GET" && url.pathname === "/health") {
    const runtime = registryRuntimeConfig(env);
    return json({
      status: "ok",
      request_id: requestId,
      registry_environment: runtime.environment,
      network: runtime.network,
      record_ttl_hours: runtime.record_ttl_hours,
    }, 200, headers);
  }
  if (request.method === "GET" && url.pathname === "/ready") {
    return handleReadiness(env, deps, requestId, headers);
  }
  const staticPackageVersionMatch = url.pathname.match(/^\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)[.]json$/);
  if (request.method === "GET" && staticPackageVersionMatch) {
    const runtime = registryRuntimeConfig(env);
    const staticStore = runtime.environment === "testnet-sandbox"
      ? deps.store ?? getProductionStore(env)
      : deps.store;
    return handleStaticPackageVersionRead(
      env,
      deps,
      staticStore,
      requestId,
      decodeURIComponent(staticPackageVersionMatch[1] ?? ""),
      decodeURIComponent(staticPackageVersionMatch[2] ?? ""),
      decodeURIComponent(staticPackageVersionMatch[3] ?? ""),
    );
  }

  const store = deps.store ?? getProductionStore(env);
  const now = deps.now?.() ?? new Date();
  const runtime = registryRuntimeConfig(env);
  const registryOrigin = env.REGISTRY_ORIGIN ?? DEFAULT_REGISTRY_ORIGIN;
  const staticOrigin = env.STATIC_REGISTRY_ORIGIN ?? DEFAULT_STATIC_REGISTRY_ORIGIN;

  const lsIdlInterfaceMatch = url.pathname.match(/^\/v1\/ckb\/scripts\/([^/]+)\/interfaces\/ls-idl$/);
  if (request.method === "GET" && lsIdlInterfaceMatch) {
    return handleLsIdlRead(
      request,
      env,
      deps,
      store,
      requestId,
      headers,
      decodeURIComponent(lsIdlInterfaceMatch[1] ?? ""),
      false,
    );
  }
  const lsIdlCompatibilityMatch = url.pathname.match(/^\/idl\/([^/]+)$/);
  if (request.method === "GET" && lsIdlCompatibilityMatch) {
    return handleLsIdlRead(
      request,
      env,
      deps,
      store,
      requestId,
      headers,
      decodeURIComponent(lsIdlCompatibilityMatch[1] ?? ""),
      true,
    );
  }

  if (request.method === "POST" && url.pathname === "/v1/authorisation-sessions") {
    return handleCreateAuthorisationSession(request, env, store, requestId, registryOrigin, now, headers);
  }

  const authorisationSessionMatch = url.pathname.match(/^\/v1\/authorisation-sessions\/([^/]+)$/);
  if (request.method === "GET" && authorisationSessionMatch) {
    return handleGetAuthorisationSession(
      request,
      store,
      requestId,
      now,
      headers,
      decodeURIComponent(authorisationSessionMatch[1] ?? ""),
    );
  }

  const authorisationChallengeMatch = url.pathname.match(/^\/v1\/authorisation-sessions\/([^/]+)\/challenge$/);
  if (request.method === "POST" && authorisationChallengeMatch) {
    return handlePrepareAuthorisationSession(
      request,
      env,
      store,
      requestId,
      registryOrigin,
      now,
      headers,
      decodeURIComponent(authorisationChallengeMatch[1] ?? ""),
    );
  }

  const authorisationCompleteMatch = url.pathname.match(/^\/v1\/authorisation-sessions\/([^/]+)\/complete$/);
  if (request.method === "POST" && authorisationCompleteMatch) {
    return handleCompleteAuthorisationSession(
      request,
      env,
      store,
      requestId,
      registryOrigin,
      now,
      deps,
      headers,
      decodeURIComponent(authorisationCompleteMatch[1] ?? ""),
    );
  }

  if (request.method === "GET" && url.pathname === "/v1/artifacts") {
    return handleListPackages(request, store, requestId, staticOrigin, headers);
  }

  const publicEvidenceMatch = url.pathname.match(/^\/v1\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)\/evidence$/);
  if (request.method === "GET" && publicEvidenceMatch) {
    return handlePublicPackageEvidence(
      store,
      requestId,
      headers,
      decodeURIComponent(publicEvidenceMatch[1] ?? ""),
      decodeURIComponent(publicEvidenceMatch[2] ?? ""),
      decodeURIComponent(publicEvidenceMatch[3] ?? ""),
    );
  }

  const publicCommitmentMatch = url.pathname.match(/^\/v1\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)\/commitment$/);
  if (request.method === "GET" && publicCommitmentMatch) {
    return handlePublicRegistryCommitment(
      env,
      deps,
      store,
      requestId,
      headers,
      decodeURIComponent(publicCommitmentMatch[1] ?? ""),
      decodeURIComponent(publicCommitmentMatch[2] ?? ""),
      decodeURIComponent(publicCommitmentMatch[3] ?? ""),
    );
  }

  const deploymentMatch = url.pathname.match(/^\/v1\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)\/deployments$/);
  if (request.method === "POST" && deploymentMatch) {
    return handleRecordDeployment(
      request,
      env,
      store,
      requestId,
      registryOrigin,
      staticOrigin,
      now,
      deps,
      runtime,
      headers,
      decodeURIComponent(deploymentMatch[1] ?? ""),
      decodeURIComponent(deploymentMatch[2] ?? ""),
      decodeURIComponent(deploymentMatch[3] ?? ""),
    );
  }

  const availabilityMatch = url.pathname.match(/^\/v1\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)\/availability$/);
  if (request.method === "POST" && availabilityMatch) {
    return handlePublisherAvailability(
      request,
      env,
      store,
      requestId,
      registryOrigin,
      staticOrigin,
      now,
      deps,
      headers,
      decodeURIComponent(availabilityMatch[1] ?? ""),
      decodeURIComponent(availabilityMatch[2] ?? ""),
      decodeURIComponent(availabilityMatch[3] ?? ""),
    );
  }

  const publicPackageMatch = url.pathname.match(/^\/v1\/artifacts\/([^/]+)\/([^/]+)$/);
  if (request.method === "GET" && publicPackageMatch) {
    return handlePublicPackageDetail(
      store,
      requestId,
      staticOrigin,
      headers,
      decodeURIComponent(publicPackageMatch[1] ?? ""),
      decodeURIComponent(publicPackageMatch[2] ?? ""),
    );
  }

  if (request.method === "POST" && url.pathname === "/v1/capabilities") {
    return handleCreateCapability(request, env, store, requestId, registryOrigin, now, deps, headers);
  }

  const capabilityCheckMatch = url.pathname.match(/^\/v1\/capabilities\/([^/]+)\/check$/);
  if (request.method === "GET" && capabilityCheckMatch) {
    return handleCapabilityCheck(
      request,
      store,
      requestId,
      now,
      headers,
      decodeURIComponent(capabilityCheckMatch[1] ?? ""),
    );
  }

  if (request.method === "POST" && url.pathname === "/v1/admin/reserved-namespaces") {
    return handleAdminReservedNamespace(request, env, store, requestId, headers);
  }

  if (request.method === "GET" && url.pathname === "/v1/admin/audit-events") {
    return handleAdminAuditEvents(request, env, store, requestId, headers);
  }

  if (request.method === "GET" && url.pathname === "/v1/admin/verification-queue") {
    return handleAdminVerificationQueue(request, env, store, requestId, headers);
  }

  const adminVerificationRetryMatch = url.pathname.match(/^\/v1\/admin\/verification-jobs\/([^/]+)\/retry$/);
  if (request.method === "POST" && adminVerificationRetryMatch) {
    return handleAdminVerificationRetry(
      request,
      env,
      store,
      requestId,
      headers,
      decodeURIComponent(adminVerificationRetryMatch[1] ?? ""),
    );
  }

  const adminNamespaceStatusMatch = url.pathname.match(/^\/v1\/admin\/namespaces\/([^/]+)\/status$/);
  if (request.method === "POST" && adminNamespaceStatusMatch) {
    return handleAdminNamespaceStatus(request, env, store, requestId, headers, decodeURIComponent(adminNamespaceStatusMatch[1] ?? ""));
  }

  const adminVersionStatusMatch = url.pathname.match(/^\/v1\/admin\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)\/availability$/);
  if (request.method === "POST" && adminVersionStatusMatch) {
    return handleAdminPackageVersionStatus(
      request,
      env,
      store,
      requestId,
      staticOrigin,
      deps,
      headers,
      decodeURIComponent(adminVersionStatusMatch[1] ?? ""),
      decodeURIComponent(adminVersionStatusMatch[2] ?? ""),
      decodeURIComponent(adminVersionStatusMatch[3] ?? ""),
    );
  }

  const adminPromotionMatch = url.pathname.match(/^\/v1\/admin\/artifacts\/([^/]+)\/([^/]+)\/releases\/([^/]+)\/promote$/);
  if (request.method === "POST" && adminPromotionMatch) {
    return handleAdminPackageVersionPromotion(
      request,
      env,
      store,
      requestId,
      staticOrigin,
      deps,
      headers,
      decodeURIComponent(adminPromotionMatch[1] ?? ""),
      decodeURIComponent(adminPromotionMatch[2] ?? ""),
      decodeURIComponent(adminPromotionMatch[3] ?? ""),
    );
  }

  const revokeMatch = url.pathname.match(/^\/v1\/capabilities\/([^/]+)\/revoke$/);
  if (request.method === "POST" && revokeMatch) {
    return handleRevokeCapability(
      request,
      env,
      store,
      requestId,
      registryOrigin,
      now,
      deps,
      headers,
      decodeURIComponent(revokeMatch[1] ?? ""),
    );
  }

  if (request.method === "POST" && url.pathname === "/v1/namespaces/claim") {
    return handleClaimNamespace(request, env, store, requestId, registryOrigin, now, deps, headers);
  }

  const publishMatch = url.pathname.match(/^\/v1\/artifacts\/([^/]+)\/([^/]+)\/releases$/);
  if (request.method === "POST" && publishMatch) {
    return handlePublishVersion(
      request,
      env,
      store,
      requestId,
      registryOrigin,
      staticOrigin,
      now,
      deps,
      headers,
      decodeURIComponent(publishMatch[1] ?? ""),
      decodeURIComponent(publishMatch[2] ?? ""),
    );
  }

  throw new ApiError(404, "not_found", "route not found");
}

async function handleLsIdlRead(
  request: Request,
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
  codeHashInput: string,
  compatibilityRoute: boolean,
): Promise<Response> {
  const codeHash = canonicalLookupHash(codeHashInput, "code_hash");
  const params = new URL(request.url).searchParams;
  const runtime = registryRuntimeConfig(env);
  const network = optionalPublicQuery(params, "network") ?? runtime.network;
  if (network !== "mainnet" && network !== "testnet") {
    throw new ApiError(400, "invalid_network", "network must be mainnet or testnet");
  }
  const hashTypeRaw = optionalPublicQuery(params, "hash_type");
  const hashType = hashTypeRaw
    ? requireOneOf(hashTypeRaw, ["data", "data1", "data2", "type"] as const, "invalid_hash_type") as
      "data" | "data1" | "data2" | "type"
    : undefined;
  const dataHashRaw = optionalPublicQuery(params, "data_hash");
  const dataHash = dataHashRaw ? canonicalLookupHash(dataHashRaw, "data_hash") : undefined;
  if (!compatibilityRoute && hashType === "type" && !dataHash) {
    throw new ApiError(
      400,
      "ls_idl_data_hash_required",
      "Type-hash LS-IDL lookup requires data_hash so an upgrade cannot resolve to ambiguous interface bytes",
    );
  }
  const candidates = await store.findScriptInterfaceCandidates({
    code_hash: codeHash,
    network,
    ...(hashType ? { hash_type: hashType } : {}),
    ...(dataHash ? { data_hash: dataHash } : {}),
    limit: 17,
  });
  if (candidates.length === 0) {
    throw new ApiError(404, "ls_idl_not_found", "no active chain-verified LS-IDL release matches this script identity");
  }
  if (candidates.length !== 1) {
    throw new ApiError(
      409,
      "ls_idl_ambiguous",
      "multiple active LS-IDL releases match this code hash; provide hash_type and data_hash on the versioned endpoint",
    );
  }
  const candidate = candidates[0]!;
  const deployment = candidate.deployment.evidence;
  if (!compatibilityRoute && deployment["hash_type"] === "type" && !dataHash) {
    throw new ApiError(
      409,
      "ls_idl_data_hash_required",
      "this Type-hash deployment requires data_hash to bind the current code Cell bytes",
    );
  }
  const signedRelease = candidate.version.registry_entry.versions.find((entry) => entry.version === candidate.version.version);
  const profileContract = signedRelease?.profile_contract as Record<string, unknown> | undefined;
  const interfaceContract = profileContract?.["interface"] as Record<string, unknown> | undefined;
  const commitment = interfaceContract?.["commitment"] as Record<string, unknown> | undefined;
  if (interfaceContract?.["format"] !== "ls-idl" || commitment?.["algorithm"] !== "sha256") {
    throw new ApiError(500, "ls_idl_contract_inconsistent", "stored release no longer has a readable LS-IDL contract");
  }
  const expectedDigest = canonicalLookupHash(String(commitment["digest"] ?? ""), "interface commitment digest");
  const snapshot = await requireSnapshot(store, candidate.version);
  const reader = deps.registryObjectReader ?? r2RegistryObjectReader(env);
  const object = await reader.get(snapshot.r2_key);
  if (!object) {
    throw new ApiError(503, "ls_idl_bundle_unavailable", "the immutable LS-IDL bundle is temporarily unavailable");
  }
  const bundleBytes = new Uint8Array(await new Response(object.body).arrayBuffer());
  if (bundleBytes.length === 0 || bundleBytes.length > DEFAULT_MAX_SNAPSHOT_BYTES) {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL bundle violates its size contract");
  }
  let bundle: Record<string, unknown>;
  try {
    bundle = assertPlainObject(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bundleBytes)), "ls_idl_bundle_invalid");
  } catch {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL bundle is not valid UTF-8 JSON");
  }
  if (bundle["schema"] !== "cellscript-registry-bundle"
    || bundle["namespace"] !== candidate.version.namespace
    || bundle["name"] !== candidate.version.name
    || bundle["release"] !== candidate.version.version
    || bundle["profile"] !== "ckb_executable") {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL bundle identity does not match its Registry release");
  }
  const objects = bundle["objects"];
  if (!Array.isArray(objects)) {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL bundle has no object list");
  }
  const abiObjects = objects.filter((value) => {
    try { return assertPlainObject(value, "ls_idl_bundle_invalid")["role"] === "abi"; } catch { return false; }
  });
  if (abiObjects.length !== 1) {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL bundle must contain exactly one abi object");
  }
  const abiObject = assertPlainObject(abiObjects[0], "ls_idl_bundle_invalid");
  if (typeof abiObject["content_base64"] !== "string") {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL abi object is not base64 encoded");
  }
  let idlBytes: Uint8Array;
  try {
    idlBytes = base64ToBytes(abiObject["content_base64"]);
  } catch {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL abi object is malformed base64");
  }
  if (idlBytes.length === 0 || idlBytes.length > 256 * 1024) {
    throw new ApiError(500, "ls_idl_bundle_invalid", "the immutable LS-IDL document violates its size contract");
  }
  const actualDigest = await sha256Hex(idlBytes);
  if (actualDigest !== expectedDigest.slice(2)) {
    throw new ApiError(500, "ls_idl_digest_mismatch", "stored LS-IDL bytes no longer match the admitted SHA-256 commitment");
  }
  const out = new Headers(headers);
  out.set("content-type", "application/vnd.ckb.ls-idl+json");
  out.set("cache-control", "public, max-age=300, stale-while-revalidate=3600");
  out.set("etag", `"sha256-${actualDigest}"`);
  out.set("x-ls-idl-format-version", String(interfaceContract["format_version"] ?? "0.1"));
  out.set("x-ls-idl-sha256", actualDigest);
  out.set("x-ls-idl-coordinate", `${candidate.version.namespace}/${candidate.version.name}@${candidate.version.version}`);
  out.set("x-ls-idl-commitment", "code-cell-data-suffix-32");
  out.set("x-ls-idl-verification", "schema-and-suffix-bound");
  return new Response(idlBytes.slice().buffer as ArrayBuffer, { status: 200, headers: out });
}

function canonicalLookupHash(value: string, label: string): string {
  const bare = value.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(bare)) {
    throw new ApiError(400, "invalid_script_hash", `${label} must be a 32-byte hexadecimal hash`);
  }
  return `0x${bare.toLowerCase()}`;
}

async function handleStaticPackageVersionRead(
  env: Env,
  deps: AppDeps,
  store: RegistryStore | undefined,
  requestId: string,
  namespaceFromPath: string,
  nameFromPath: string,
  versionFromPath: string,
): Promise<Response> {
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const version = validateVersion(versionFromPath);
  if (store && !await store.getPackageVersion(namespace, name, version)) {
    throw new ApiError(404, "registry_object_not_found", "artifact release registry object was not found");
  }
  const key = staticPackageVersionKey(namespace, name, version);
  const reader = deps.registryObjectReader ?? r2RegistryObjectReader(env);
  const object = await reader.get(key);
  if (!object) {
    throw new ApiError(404, "registry_object_not_found", "artifact release registry object was not found");
  }
  const headers = corsHeaders(requestId);
  headers.set("content-type", object.contentType ?? "application/json; charset=utf-8");
  headers.set("cache-control", "public, max-age=60, stale-while-revalidate=300");
  if (object.etag) {
    headers.set("etag", object.etag);
  }
  return new Response(object.body, { status: 200, headers });
}

async function handleListPackages(
  request: Request,
  store: RegistryStore,
  requestId: string,
  staticOrigin: string,
  headers: Headers,
): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const query = optionalPublicQuery(params, "q");
  const namespaceRaw = optionalPublicQuery(params, "namespace");
  const kindRaw = optionalPublicQuery(params, "kind");
  const verificationRaw = optionalPublicQuery(params, "verification");
  const deploymentRaw = optionalPublicQuery(params, "deployment");
  const availabilityRaw = optionalPublicQuery(params, "availability");
  const namespace = namespaceRaw ? validatePackageIdent(namespaceRaw, "namespace") : undefined;
  const artifactKind = kindRaw ? requireOneOf(kindRaw, ARTIFACT_KINDS, "invalid_artifact_kind") as ArtifactKind : undefined;
  const verificationStatus = verificationRaw
    ? requireOneOf(verificationRaw, ["pending", "hash_bound", "verified", "evidence_required", "rejected"] as const, "invalid_verification_status") as VerificationStatus
    : undefined;
  const deploymentStatus = deploymentRaw
    ? requireOneOf(deploymentRaw, ["not_applicable", "undeployed", "deployed", "chain_verified"] as const, "invalid_deployment_status") as DeploymentStatus
    : undefined;
  const availabilityStatus = availabilityRaw
    ? requireOneOf(availabilityRaw, ["active", "deprecated", "yanked", "quarantined"] as const, "invalid_availability_status") as AvailabilityStatus
    : "active";
  const limit = publicListInteger(params, "limit", 50, 1, 100);
  const offset = publicListInteger(params, "offset", 0, 0, 10_000);
  const page = await store.listArtifactPackagePage({
    ...(query ? { query } : {}),
    ...(namespace ? { namespace } : {}),
    ...(artifactKind ? { artifact_kind: artifactKind } : {}),
    ...(verificationStatus ? { verification_status: verificationStatus } : {}),
    ...(!verificationStatus ? { verification_statuses: ["hash_bound", "verified", "evidence_required"] as VerificationStatus[] } : {}),
    ...(deploymentStatus ? { deployment_status: deploymentStatus } : {}),
    ...(availabilityStatus ? { availability_status: availabilityStatus } : {}),
    limit,
    offset,
  });
  const records = page.records;
  const visible = records.filter((record) => record.availability_status !== "quarantined");
  const grouped = new Map<string, PackageVersionRecord[]>();
  for (const record of visible) {
    const key = `${record.namespace}/${record.name}`;
    const versions = grouped.get(key) ?? [];
    versions.push(record);
    grouped.set(key, versions);
  }
  const snapshots = await requireSnapshots(store, visible);
  const packages = [...grouped.entries()].map(([coordinate, versions]) => {
    const latest = versions[0]!;
    const entry = latest.registry_entry as Record<string, unknown>;
    return {
      coordinate,
      namespace: latest.namespace,
      name: latest.name,
      latest_release: latest.version,
      artifact: latest.artifact,
      verification_status: latest.verification_status,
      deployment_status: latest.deployment_status,
      availability_status: latest.availability_status,
      description: typeof entry["description"] === "string" ? entry["description"] : null,
      repository: typeof entry["repository"] === "string" ? entry["repository"] : null,
      keywords: Array.isArray(entry["keywords"]) ? entry["keywords"] : [],
      categories: Array.isArray(entry["categories"]) ? entry["categories"] : [],
      releases: versions.map((version) => staticRegistryVersionPayload(version, snapshotForVersion(snapshots, version), staticOrigin)),
      updated_at: latest.created_at,
      registry_environment: latest.registry_environment ?? "production",
      network: latest.network ?? "mainnet",
    };
  });
  return json(
    {
      schema: "cellscript-registry-artifact-index",
      request_id: requestId,
      artifacts: packages,
      count: packages.length,
      offset,
      limit,
      ...(page.has_more ? { next_offset: offset + packages.length } : {}),
    },
    200,
    headers,
  );
}

async function handlePublicPackageDetail(
  store: RegistryStore,
  requestId: string,
  staticOrigin: string,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
): Promise<Response> {
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const versions = await store.listPackageVersions({ namespace, name, limit: 200, offset: 0 });
  const visible = versions.filter((version) => version.availability_status !== "quarantined");
  if (visible.length === 0) {
    throw new ApiError(404, "artifact_not_found", "artifact is not known to the public registry");
  }
  const snapshots = await requireSnapshots(store, visible);
  const evidenceByVersion = new Map<string, PackageEvidenceRecord[]>();
  for (const evidence of await store.listPackageEvidenceForPackage(namespace, name)) {
    const records = evidenceByVersion.get(evidence.version) ?? [];
    records.push(evidence);
    evidenceByVersion.set(evidence.version, records);
  }
  const payloads = visible.map((version) => staticRegistryVersionPayload(
    version,
    snapshotForVersion(snapshots, version),
    staticOrigin,
    evidenceByVersion.get(version.version) ?? [],
  ));
  const latest = visible[0]!;
  const entry = latest.registry_entry as Record<string, unknown>;
  return json(
    {
      schema: "cellscript-registry-artifact",
      request_id: requestId,
      coordinate: `${namespace}/${name}`,
      namespace,
      name,
      description: typeof entry["description"] === "string" ? entry["description"] : null,
      repository: typeof entry["repository"] === "string" ? entry["repository"] : null,
      homepage: typeof entry["homepage"] === "string" ? entry["homepage"] : null,
      documentation: typeof entry["documentation"] === "string" ? entry["documentation"] : null,
      keywords: Array.isArray(entry["keywords"]) ? entry["keywords"] : [],
      categories: Array.isArray(entry["categories"]) ? entry["categories"] : [],
      latest_release: latest.version,
      artifact: latest.artifact,
      verification_status: latest.verification_status,
      deployment_status: latest.deployment_status,
      availability_status: latest.availability_status,
      registry_environment: latest.registry_environment ?? "production",
      network: latest.network ?? "mainnet",
      releases: payloads,
    },
    200,
    headers,
  );
}

async function handlePublicPackageEvidence(
  store: RegistryStore,
  requestId: string,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
  versionFromPath: string,
): Promise<Response> {
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const version = validateVersion(versionFromPath);
  const record = await store.getPackageVersion(namespace, name, version);
  if (!record || record.availability_status === "quarantined") {
    throw new ApiError(404, "artifact_release_not_found", "artifact release is not known to the public registry");
  }
  const evidence = await store.listPackageEvidence(namespace, name, version);
  return json({ schema: "cellscript-registry-evidence-list", request_id: requestId, namespace, name, release: version, evidence }, 200, headers);
}

async function handlePublicRegistryCommitment(
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
  versionFromPath: string,
): Promise<Response> {
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const version = validateVersion(versionFromPath);
  const record = await store.getPackageVersion(namespace, name, version);
  if (!record || record.availability_status === "quarantined") {
    throw new ApiError(404, "artifact_release_not_found", "artifact release is not known to the public Registry");
  }
  const evidence = await store.listPackageEvidence(namespace, name, version);
  const deployed = evidence.filter((item) => item.kind === "deployed").at(-1);
  if (!deployed) {
    throw new ApiError(409, "deployment_evidence_missing", "Registry commitment requires accepted deployment evidence for this environment");
  }
  if (!deployed.evidence["chain_verification"]) {
    throw new ApiError(409, "deployment_chain_evidence_missing", "Registry commitment requires RPC-verified deployment evidence");
  }
  const commitmentEvidence = record.status === "on_chain_committed"
    ? evidence
      .filter((item) => item.kind === "on_chain_committed"
        && item.evidence_hash === record.current_commitment_evidence_hash
        && item.evidence["deployed_evidence_hash"] === deployed.evidence_hash
        && [
          "get_live_cell+type_index",
          "get_live_cell+configured_type_index",
          "get_cells+configured_type_index",
          "get_transaction+get_live_cell+configured_type_index",
        ]
          .includes(String(item.evidence["chain_verification"])))
      .at(-1)
    : undefined;
  const commitmentHash = registryCommitmentHash(record, deployed.evidence_hash);
  const configuration = registryCommitmentConfiguration(env, false);
  if (configuration) {
    await requireLiveRegistryCommitmentConfiguration(env, deps, configuration);
  }
  const committed = configuration ? commitmentEvidence : undefined;
  return json(
    {
      schema: "cellscript-registry-commitment-proof-v1",
      request_id: requestId,
      namespace,
      name,
      release: version,
      status: committed
        ? "on_chain_committed"
        : commitmentEvidence
          ? "commitment_unconfigured"
          : "commitment_ready",
      payload: registryCommitmentPayload(record, deployed.evidence_hash),
      commitment_hash: commitmentHash,
      cell_data: registryCommitmentCellData(commitmentHash),
      deployed_evidence_hash: deployed.evidence_hash,
      ...(configuration
        ? {
            transaction_intent: {
              schema: "cellscript-registry-commitment-transaction-intent-v1",
              network: registryRuntimeConfig(env).network,
              output: {
                lock: configuration.commitment_lock_script,
                type: configuration.type_script,
                data: registryCommitmentCellData(commitmentHash),
              },
              required_cell_deps: [configuration.type_script_cell_dep],
              custody_cell_dep: configuration.commitment_lock_cell_dep,
              wallet_completes: ["capacity", "inputs", "change", "fee", "witnesses", "signatures", "broadcast"],
            },
            registry_type_hash: configuration.type_script_hash,
            commitment_lock_hash: configuration.commitment_lock_hash,
          }
        : { transaction_intent: null, configuration_status: "registry_commitment_scripts_unconfigured" }),
      ...(committed
        ? {
            commitment_evidence_hash: committed.evidence_hash,
            commitment: committed.evidence,
          }
        : {}),
    },
    200,
    headers,
  );
}

async function handleRecordDeployment(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  staticOrigin: string,
  now: Date,
  deps: AppDeps,
  runtime: RegistryRuntimeConfig,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
  releaseFromPath: string,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "deployment", 40, 60 * 60, now);
  const body = await readJson(request, Math.min(maxJsonBytes(env), 512 * 1024));
  const payload = validateDeploymentPayload(body["payload"], registryOrigin, now, runtime.network);
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const release = validateVersion(releaseFromPath);
  if (payload.namespace !== namespace || payload.name !== name || payload.release !== release) {
    throw new ApiError(400, "route_payload_mismatch", "artifact route and deployment payload do not match");
  }
  const version = await store.getPackageVersion(namespace, name, release);
  if (!version) {
    throw new ApiError(404, "artifact_release_not_found", "artifact release is not known to the registry");
  }
  if (version.artifact.profile !== "ckb_executable" || version.deployment_status === "not_applicable") {
    throw new ApiError(409, "deployment_not_applicable", "this artifact profile cannot have a CKB deployment");
  }
  const signedRelease = version.registry_entry.versions.find((entry) => entry.version === release);
  if (!signedRelease?.artifact_hash || !sameCkbHash(signedRelease.artifact_hash, payload.artifact_hash)) {
    throw new ApiError(400, "deployment_artifact_mismatch", "deployment artifact_hash does not match the published release");
  }
  requireDeploymentProfileContract(version, payload.hash_type, payload.dep_type);
  const capability = await store.getCapability(payload.capability_key_id);
  if (!capability || capability.revoked_at || new Date(capability.expires_at).getTime() <= now.getTime()) {
    throw new ApiError(401, "capability_inactive", "deployment capability is missing, revoked, or expired");
  }
  if (!scopeAllows(capability.scopes, "deployment", namespace, name)) {
    throw new ApiError(403, "capability_scope_denied", "capability scope does not allow this artifact deployment");
  }
  const namespaceRecord = await store.getNamespace(namespace);
  if (
    !namespaceRecord
    || namespaceRecord.status !== "active"
    || namespaceRecord.owner_principal_type !== capability.principal_type
    || namespaceRecord.owner_principal_id !== capability.principal_id
  ) {
    throw new ApiError(403, "namespace_owner_mismatch", "capability principal does not own the active namespace");
  }
  const signature = requireCapabilitySignature(body["capability_signature"]);
  const verifier = deps.capabilityVerifier ?? new WebCryptoP256Verifier();
  if (!(await verifier.verify(canonicalJson(payload), capability.capability_pubkey, signature))) {
    throw new ApiError(401, "capability_signature_invalid", "capability signature verification failed");
  }
  await throttle(store, requestId, `capability:${capability.key_id}`, "deployment", 20, 60 * 60, now);
  await throttle(store, requestId, `artifact:${namespace}/${name}`, "deployment", 20, 60 * 60, now);

  const requestHash = await sha256Hex(canonicalJson({
    route: "record_deployment",
    payload,
    capability_signature: signature,
  }));
  const idempotencyKey = requestIdempotencyKey(request, "deployment") ?? `deployment:auto:${requestHash}`;
  const replay = await idempotencyReplayResponse(store, idempotencyKey, requestHash, headers);
  if (replay) return replay;
  const reservation = await store.reserveIdempotencyKey({
    key: idempotencyKey,
    request_hash: requestHash,
    request_id: requestId,
    expires_at: payload.expires_at,
  });
  if (reservation.state === "conflict") {
    throw new ApiError(409, "idempotency_key_conflict", "deployment command identity conflicts with an earlier request");
  }
  if (reservation.state === "in_progress") {
    throw new ApiError(409, "idempotency_request_in_progress", "matching deployment command is already processing");
  }
  if (reservation.state === "completed") return idempotencyResponse(reservation.record, headers);

  let nonceKey: string | undefined;
  let commandCommitted = false;
  try {
    nonceKey = await consumeSignedNonce(store, requestId, {
      protocol: payload.protocol,
      action: payload.action,
      nonce: payload.nonce,
      expires_at: payload.expires_at,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      capability_key_id: capability.key_id,
    });
    const deploymentVerifier = deps.verifyDeployment ?? deps.verifyMainnetDeployment;
    const chain = deploymentVerifier
      ? await deploymentVerifier(payload)
      : await verifyDeployment(env, payload);
    const previousEvidence = await store.listPackageEvidence(namespace, name, release);
    const buildEvidence = latestBuildEvidence(previousEvidence, version);
    const lsIdlInterface = releaseLsIdlInterface(version);
    const evidence = {
      schema: "cellscript-registry-evidence",
      kind: "deployed",
      producer: `publisher:${capability.principal_type}`,
      generated_at: now.toISOString(),
      verification_status: "passed",
      source_hash: version.source_hash,
      manifest_hash: version.manifest_hash,
      verified_build_evidence_hash: buildEvidence.evidence_hash,
      network: runtime.network,
      artifact_hash: payload.artifact_hash,
      data_hash: payload.data_hash,
      code_hash: payload.code_hash,
      hash_type: payload.hash_type,
      dep_type: payload.dep_type,
      out_point: payload.out_point,
      deployment_status: "live",
      chain_verification: "get_transaction+get_live_cell",
      ...(lsIdlInterface ? { interface: lsIdlInterface } : {}),
      ...(chain.block_hash ? { block_hash: chain.block_hash } : {}),
      ...(chain.block_number ? { block_number: chain.block_number } : {}),
      ...(chain.tip_block_number ? { observed_tip_block_number: chain.tip_block_number } : {}),
      ...(chain.confirmations !== undefined ? { confirmations: chain.confirmations } : {}),
      ...(chain.resolved_code_out_point ? { resolved_code_out_point: chain.resolved_code_out_point } : {}),
      ...(chain.dep_group_size !== undefined ? { dep_group_size: chain.dep_group_size } : {}),
    };
    const evidenceHash = `sha256:${await sha256Hex(canonicalJson(evidence))}`;
    const responseBody = {
      request_id: requestId,
      coordinate: `${namespace}/${name}@${release}`,
      deployment_status: "chain_verified",
      evidence_hash: evidenceHash,
      evidence: {
        kind: "deployed" as const,
        evidence_hash: evidenceHash,
        evidence,
      },
    };
    const snapshot = await requireSnapshot(store, version);
    const recorded = await store.recordChainVerifiedDeployment({
      namespace,
      name,
      version: release,
      kind: "deployed",
      evidence_hash: evidenceHash,
      evidence,
      request_id: requestId,
      admin_actor: `publisher:${capability.principal_id}`,
      capability_usage: {
        key_id: capability.key_id,
        principal_type: capability.principal_type,
        principal_id: capability.principal_id,
        request_id: requestId,
        action: "record_deployment",
        namespace,
        name,
        version: release,
      },
      idempotency: {
        key: idempotencyKey,
        request_hash: requestHash,
        response_status: 201,
        response_body: responseBody,
      },
    });
    commandCommitted = true;
    const allEvidence = await store.listPackageEvidence(namespace, name, release);
    await tryWriteStaticRegistryVersionObject(
      env,
      deps,
      store,
      requestId,
      recorded.version,
      snapshot,
      staticOrigin,
      allEvidence,
    );
    return json(responseBody, 201, headers);
  } catch (error) {
    if (!commandCommitted) {
      if (nonceKey) await store.releaseNonce({ nonce_key: nonceKey, request_id: requestId });
      await store.releaseProcessingIdempotencyKey({ key: idempotencyKey, request_hash: requestHash });
    }
    throw error;
  }
}

async function handlePublisherAvailability(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  staticOrigin: string,
  now: Date,
  deps: AppDeps,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
  releaseFromPath: string,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "availability", 40, 60 * 60, now);
  const body = await readJson(request, Math.min(maxJsonBytes(env), 128 * 1024));
  const payload = validateAvailabilityPayload(body["payload"], registryOrigin, now);
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const release = validateVersion(releaseFromPath);
  if (payload.namespace !== namespace || payload.name !== name || payload.release !== release) {
    throw new ApiError(400, "route_payload_mismatch", "artifact route and availability payload do not match");
  }
  const version = await store.getPackageVersion(namespace, name, release);
  if (!version) {
    throw new ApiError(404, "artifact_release_not_found", "artifact release is not known to the registry");
  }
  if (version.availability_status === "quarantined") {
    throw new ApiError(403, "quarantine_admin_required", "a publisher cannot change an administratively quarantined release");
  }
  const capability = await store.getCapability(payload.capability_key_id);
  if (!capability || capability.revoked_at || new Date(capability.expires_at).getTime() <= now.getTime()) {
    throw new ApiError(401, "capability_inactive", "availability capability is missing, revoked, or expired");
  }
  if (!scopeAllows(capability.scopes, "availability", namespace, name)) {
    throw new ApiError(403, "capability_scope_denied", "capability scope does not allow this artifact update");
  }
  const namespaceRecord = await store.getNamespace(namespace);
  if (
    !namespaceRecord
    || namespaceRecord.status !== "active"
    || namespaceRecord.owner_principal_type !== capability.principal_type
    || namespaceRecord.owner_principal_id !== capability.principal_id
  ) {
    throw new ApiError(403, "namespace_owner_mismatch", "capability principal does not own the active namespace");
  }
  const signature = requireCapabilitySignature(body["capability_signature"]);
  const verifier = deps.capabilityVerifier ?? new WebCryptoP256Verifier();
  if (!(await verifier.verify(canonicalJson(payload), capability.capability_pubkey, signature))) {
    throw new ApiError(401, "capability_signature_invalid", "capability signature verification failed");
  }
  await throttle(store, requestId, `capability:${capability.key_id}`, "availability", 30, 60 * 60, now);
  await throttle(store, requestId, `artifact:${namespace}/${name}`, "availability", 20, 60 * 60, now);

  const requestHash = await sha256Hex(canonicalJson({
    route: "set_availability",
    payload,
    capability_signature: signature,
  }));
  const idempotencyKey = requestIdempotencyKey(request, "availability") ?? `availability:auto:${requestHash}`;
  const replay = await idempotencyReplayResponse(store, idempotencyKey, requestHash, headers);
  if (replay) return replay;
  const reservation = await store.reserveIdempotencyKey({
    key: idempotencyKey,
    request_hash: requestHash,
    request_id: requestId,
    expires_at: payload.expires_at,
  });
  if (reservation.state === "conflict") {
    throw new ApiError(409, "idempotency_key_conflict", "availability command identity conflicts with an earlier request");
  }
  if (reservation.state === "in_progress") {
    throw new ApiError(409, "idempotency_request_in_progress", "matching availability command is already processing");
  }
  if (reservation.state === "completed") return idempotencyResponse(reservation.record, headers);

  let nonceKey: string | undefined;
  let commandCommitted = false;
  try {
    nonceKey = await consumeSignedNonce(store, requestId, {
      protocol: payload.protocol,
      action: payload.action,
      nonce: payload.nonce,
      expires_at: payload.expires_at,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      capability_key_id: capability.key_id,
    });
    const snapshot = await requireSnapshot(store, version);
    const evidence = await store.listPackageEvidence(namespace, name, release);
    const directUrl = staticPackageVersionUrl(staticOrigin, namespace, name, release);
    const prospective = { ...version, availability_status: payload.availability_status };
    prospective.status = deriveRegistryEntryStatus(prospective, version.status);
    const responseBody = {
      request_id: requestId,
      coordinate: `${namespace}/${name}@${release}`,
      availability_status: payload.availability_status,
      status: prospective.status,
    };
    if (isSuppressivePackageVersionStatus(payload.availability_status)) {
      await writeStaticRegistryVersionObject(
        env,
        deps,
        {
          ...version,
          status: payload.availability_status === "active" ? version.status : payload.availability_status,
          availability_status: payload.availability_status,
          direct_url: directUrl,
        },
        snapshot,
        staticOrigin,
        evidence,
      );
    }
    const record = await store.updatePackageVersionStatus({
      namespace,
      name,
      version: release,
      status: payload.availability_status,
      ...(payload.reason ? { reason: payload.reason } : {}),
      request_id: requestId,
      admin_actor: `publisher:${capability.principal_id}`,
      audit_event_type: "publisher.package_version.availability_updated",
      capability_usage: {
        key_id: capability.key_id,
        principal_type: capability.principal_type,
        principal_id: capability.principal_id,
        request_id: requestId,
        action: "set_availability",
        namespace,
        name,
        version: release,
      },
      idempotency: {
        key: idempotencyKey,
        request_hash: requestHash,
        response_status: 200,
        response_body: responseBody,
      },
    });
    commandCommitted = true;
    if (!isSuppressivePackageVersionStatus(payload.availability_status)) {
      await tryWriteStaticRegistryVersionObject(
        env,
        deps,
        store,
        requestId,
        { ...record, direct_url: directUrl },
        snapshot,
        staticOrigin,
        evidence,
      );
    }
    return json(responseBody, 200, headers);
  } catch (error) {
    if (!commandCommitted) {
      if (nonceKey) await store.releaseNonce({ nonce_key: nonceKey, request_id: requestId });
      await store.releaseProcessingIdempotencyKey({ key: idempotencyKey, request_hash: requestHash });
    }
    throw error;
  }
}

interface LiveCellRpcResult {
  status: string;
  cell: Record<string, unknown>;
  block_hash: string;
}

interface VerifiedDeployment {
  block_hash?: string | null;
  block_number?: string;
  tip_block_number?: string;
  confirmations?: number;
  resolved_code_out_point?: { tx_hash: string; index: number };
  dep_group_size?: number;
}

export async function verifyDeployment(env: Env, payload: DeploymentPayload): Promise<VerifiedDeployment> {
  const runtime = registryRuntimeConfig(env);
  if (payload.network !== runtime.network) {
    throw new ApiError(400, "unsupported_deployment_network", `deployment must use ${runtime.network}`);
  }
  const rpcUrl = runtime.rpc_url;
  const rpcOptions = {
    timeout_ms: boundedIntegerEnv(env.CKB_RPC_TIMEOUT_MS, 10_000, 1_000, 30_000),
    maximum_bytes: boundedIntegerEnv(env.CKB_RPC_MAX_RESPONSE_BYTES, 2 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024),
  };
  await requireRegistryRpc(rpcUrl, rpcOptions, runtime.network);
  const declared = await getLiveCell(rpcUrl, payload.out_point, rpcOptions);
  const observation = await requireMinimumConfirmations(env, rpcUrl, declared.block_hash, rpcOptions, "deployment");
  if (payload.dep_type === "code") {
    verifyDeploymentCodeCell(declared.cell, payload);
    return { ...(declared.block_hash !== undefined ? { block_hash: declared.block_hash } : {}), ...observation };
  }

  const depGroupData = assertPlainObject(declared.cell["data"], "invalid_ckb_rpc_response");
  const content = depGroupData["content"];
  if (typeof content !== "string") {
    throw new ApiError(409, "invalid_dep_group", `${runtime.network} DepGroup Cell did not return output data`);
  }
  const members = parseDepGroupOutPoints(content);
  const memberLimit = boundedIntegerEnv(env.CKB_DEP_GROUP_MAX_MEMBERS, 256, 1, 2048);
  if (members.length > memberLimit) {
    throw new ApiError(409, "dep_group_too_large", `DepGroup has ${members.length} members; Registry verification limit is ${memberLimit}`);
  }
  for (let offset = 0; offset < members.length; offset += 16) {
    const candidates = await Promise.all(members.slice(offset, offset + 16).map(async (member) => {
      try {
        const candidate = await getLiveCell(rpcUrl, member, rpcOptions);
        verifyDeploymentCodeCell(candidate.cell, payload);
        await requireMinimumConfirmations(env, rpcUrl, candidate.block_hash, rpcOptions, "DepGroup code member");
        return member;
      } catch (error) {
        if (error instanceof ApiError && ["deployment_cell_not_live", "deployment_data_hash_mismatch", "deployment_code_hash_mismatch"].includes(error.code)) {
          return null;
        }
        throw error;
      }
    }));
    const member = candidates.find((candidate) => candidate !== null);
    if (member) {
      return {
        ...(declared.block_hash !== undefined ? { block_hash: declared.block_hash } : {}),
        ...observation,
        resolved_code_out_point: member,
        dep_group_size: members.length,
      };
    }
  }
  throw new ApiError(409, "dep_group_artifact_not_found", "DepGroup does not resolve to a live code Cell matching the published executable");
}

/** Backward-compatible export for callers that predate the isolated testnet environment. */
export async function verifyMainnetDeployment(env: Env, payload: DeploymentPayload): Promise<VerifiedDeployment> {
  return verifyDeployment(env, payload);
}

async function getLiveCell(
  rpcUrl: string,
  outPoint: { tx_hash: string; index: number },
  options: { timeout_ms: number; maximum_bytes: number },
): Promise<LiveCellRpcResult> {
  const rpc = await ckbRpcRequest(
    rpcUrl,
    "get_live_cell",
    [{ tx_hash: outPoint.tx_hash, index: `0x${outPoint.index.toString(16)}` }, true, false],
    options,
  );
  const result = assertPlainObject(rpc, "invalid_ckb_rpc_response");
  if (result["status"] !== "live") {
    throw new ApiError(409, "deployment_cell_not_live", "deployment OutPoint is not a live Cell on the configured network");
  }
  const cell = assertPlainObject(result["cell"], "invalid_ckb_rpc_response");
  const blockHash = await getCommittedTransactionBlockHash(rpcUrl, outPoint.tx_hash, options);
  return {
    status: "live",
    cell,
    block_hash: blockHash,
  };
}

async function getCommittedTransactionBlockHash(
  rpcUrl: string,
  txHash: string,
  options: { timeout_ms: number; maximum_bytes: number },
): Promise<string> {
  const rawTransaction = await ckbRpcRequest(rpcUrl, "get_transaction", [txHash], options);
  if (!rawTransaction || typeof rawTransaction !== "object" || Array.isArray(rawTransaction)) {
    throw new ApiError(503, "invalid_ckb_rpc_response", "CKB RPC get_transaction returned no transaction status");
  }
  const transaction = rawTransaction as Record<string, unknown>;
  const rawStatus = transaction["tx_status"];
  if (!rawStatus || typeof rawStatus !== "object" || Array.isArray(rawStatus)) {
    throw new ApiError(503, "invalid_ckb_rpc_response", "CKB RPC get_transaction returned no tx_status object");
  }
  const txStatus = rawStatus as Record<string, unknown>;
  if (typeof txStatus["status"] !== "string") {
    throw new ApiError(503, "invalid_ckb_rpc_response", "CKB RPC get_transaction returned no transaction status value");
  }
  if (txStatus["status"] !== "committed") {
    throw new ApiError(409, "chain_observation_uncommitted", "Cell creation transaction is not committed");
  }
  const blockHash = txStatus["block_hash"];
  if (typeof blockHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(blockHash)) {
    throw new ApiError(503, "invalid_ckb_rpc_response", "committed CKB transaction has no valid block hash");
  }
  return blockHash;
}

async function requireRegistryRpc(
  rpcUrl: string,
  options: { timeout_ms: number; maximum_bytes: number },
  expectedNetwork: DeploymentPayload["network"] = "mainnet",
): Promise<void> {
  const info = assertPlainObject(await ckbRpcRequest(rpcUrl, "get_blockchain_info", [], options), "invalid_ckb_rpc_response");
  const chain = typeof info["chain"] === "string"
    ? info["chain"]
    : typeof info["chain_id"] === "string" ? info["chain_id"] : "";
  const normalized = chain.trim().toLowerCase().replaceAll("_", "-");
  const accepted = expectedNetwork === "mainnet"
    ? ["ckb", "ckb-mainnet"]
    : ["ckb-testnet", "pudge", "pudge-testnet"];
  if (!accepted.includes(normalized)) {
    const code = expectedNetwork === "mainnet" ? "ckb_rpc_not_mainnet" : "ckb_rpc_not_testnet";
    throw new ApiError(503, code, `configured CKB RPC is not ${expectedNetwork} (reported chain '${chain || "unknown"}')`);
  }
}

interface ChainConfirmationObservation {
  block_number: string;
  tip_block_number: string;
  confirmations: number;
}

async function requireMinimumConfirmations(
  env: Env,
  rpcUrl: string,
  blockHash: string | null | undefined,
  options: { timeout_ms: number; maximum_bytes: number },
  label: string,
): Promise<ChainConfirmationObservation> {
  if (!blockHash || !/^0x[0-9a-fA-F]{64}$/.test(blockHash)) {
    throw new ApiError(409, "chain_observation_uncommitted", `${label} Cell has no committed block hash`);
  }
  const [rawHeader, rawTip] = await Promise.all([
    ckbRpcRequest(rpcUrl, "get_header", [blockHash], options),
    ckbRpcRequest(rpcUrl, "get_tip_header", [], options),
  ]);
  const header = assertPlainObject(rawHeader, "invalid_ckb_rpc_response");
  const tip = assertPlainObject(rawTip, "invalid_ckb_rpc_response");
  const blockNumber = parseRpcBlockNumber(header["number"], `${label} block number`);
  const tipNumber = parseRpcBlockNumber(tip["number"], "CKB tip block number");
  if (tipNumber < blockNumber) {
    throw new ApiError(503, "invalid_ckb_rpc_response", `${label} block is ahead of the reported CKB tip`);
  }
  const confirmationsBig = tipNumber - blockNumber + 1n;
  const minimum = boundedIntegerEnv(env.CKB_MIN_CONFIRMATIONS, 24, 1, 10_000);
  if (confirmationsBig < BigInt(minimum)) {
    throw new ApiError(
      409,
      "chain_confirmation_depth_insufficient",
      `${label} Cell has ${confirmationsBig} confirmations; Registry requires ${minimum}`,
    );
  }
  return {
    block_number: `0x${blockNumber.toString(16)}`,
    tip_block_number: `0x${tipNumber.toString(16)}`,
    confirmations: Number(confirmationsBig > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : confirmationsBig),
  };
}

function parseRpcBlockNumber(value: unknown, label: string): bigint {
  try {
    if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) return BigInt(value);
    if (typeof value === "string" && /^[0-9]+$/.test(value)) return BigInt(value);
    if (Number.isSafeInteger(value) && Number(value) >= 0) return BigInt(Number(value));
  } catch {
    // Fall through to the stable API error below.
  }
  throw new ApiError(503, "invalid_ckb_rpc_response", `${label} is not a non-negative block number`);
}

async function ckbRpcRequest(
  rpcUrl: string,
  method: string,
  params: unknown[],
  options: { timeout_ms: number; maximum_bytes: number },
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method,
        params,
      }),
      signal: AbortSignal.timeout(options.timeout_ms),
    });
  } catch (error) {
    throw new ApiError(503, "ckb_rpc_unavailable", `CKB RPC ${method} request failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!response.ok) {
    throw new ApiError(503, "ckb_rpc_unavailable", `CKB RPC returned HTTP ${response.status}`);
  }
  let rpcBody: unknown;
  try {
    rpcBody = await readBoundedRpcJson(response, options.maximum_bytes);
  } catch (error) {
    if (error instanceof ApiError && error.code === "ckb_rpc_response_too_large") {
      throw new ApiError(
        error.status,
        error.code,
        `CKB RPC ${method} response exceeds the configured size limit`,
      );
    }
    throw error;
  }
  const rpc = assertPlainObject(rpcBody, "invalid_ckb_rpc_response");
  if (rpc["error"]) {
    throw new ApiError(503, "ckb_rpc_error", `CKB RPC rejected ${method}`);
  }
  if (!("result" in rpc)) {
    throw new ApiError(503, "invalid_ckb_rpc_response", `CKB RPC ${method} returned no result`);
  }
  return rpc["result"];
}

async function readBoundedRpcJson(response: Response, maximumBytes: number): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength && Number(declaredLength) > maximumBytes) {
    throw new ApiError(503, "ckb_rpc_response_too_large", "CKB RPC response exceeds the configured size limit");
  }
  if (!response.body) {
    throw new ApiError(503, "invalid_ckb_rpc_response", "CKB RPC returned an empty response");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximumBytes) {
      await reader.cancel();
      throw new ApiError(503, "ckb_rpc_response_too_large", "CKB RPC response exceeds the configured size limit");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new ApiError(503, "invalid_ckb_rpc_response", "CKB RPC returned invalid JSON");
  }
}

function boundedIntegerEnv(raw: string | undefined, fallback: number, minimum: number, maximum: number): number {
  const parsed = raw === undefined ? fallback : Number(raw);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function verifyDeploymentCodeCell(cell: Record<string, unknown>, payload: DeploymentPayload): void {
  const data = assertPlainObject(cell["data"], "invalid_ckb_rpc_response");
  if (typeof data["hash"] !== "string" || !sameCkbHash(data["hash"], payload.data_hash)) {
    throw new ApiError(409, "deployment_data_hash_mismatch", "live Cell data hash does not match the published executable");
  }
  if (payload.hash_type === "type") {
    const output = assertPlainObject(cell["output"], "invalid_ckb_rpc_response");
    if (!output["type"] || !sameCkbHash(ckbScriptHash(output["type"]), payload.code_hash)) {
      throw new ApiError(409, "deployment_code_hash_mismatch", "live Cell type script hash does not match code_hash");
    }
  } else if (!sameCkbHash(payload.code_hash, payload.data_hash)) {
    throw new ApiError(400, "deployment_code_hash_mismatch", "data hash deployments must use the executable data hash as code_hash");
  }
}

export function parseDepGroupOutPoints(content: string): Array<{ tx_hash: string; index: number }> {
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(content)) {
    throw new ApiError(409, "invalid_dep_group", "DepGroup Cell data must be non-empty hexadecimal Molecule OutPointVec bytes");
  }
  const bytes = Uint8Array.from(content.slice(2).match(/.{2}/g) ?? [], (value) => Number.parseInt(value, 16));
  if (bytes.length < 4) {
    throw new ApiError(409, "invalid_dep_group", "DepGroup Cell data is shorter than an OutPointVec header");
  }
  const count = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, true);
  if (count === 0 || count > 2048 || bytes.length !== 4 + count * 36) {
    throw new ApiError(409, "invalid_dep_group", "DepGroup Cell data is not a canonical non-empty Molecule OutPointVec");
  }
  const outPoints = [];
  for (let item = 0; item < count; item += 1) {
    const offset = 4 + item * 36;
    const txHash = `0x${[...bytes.slice(offset, offset + 32)].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    const index = new DataView(bytes.buffer, bytes.byteOffset + offset + 32, 4).getUint32(0, true);
    outPoints.push({ tx_hash: txHash, index });
  }
  return outPoints;
}

export function registryCommitmentPayload(
  version: PackageVersionRecord,
  deployedEvidenceHash: string,
): Record<string, unknown> {
  const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
  if (!signedRelease) {
    throw new ApiError(500, "registry_release_identity_missing", "signed Registry release identity is missing");
  }
  return {
    schema: "cellscript-registry-commitment-v1",
    namespace: version.namespace,
    name: version.name,
    release: version.version,
    source_hash: version.source_hash,
    manifest_hash: version.manifest_hash,
    artifact_hash: signedRelease.artifact_hash ?? null,
    deployed_evidence_hash: deployedEvidenceHash,
  };
}

export function registryCommitmentHash(version: PackageVersionRecord, deployedEvidenceHash: string): string {
  return ckbBlake2bHex(canonicalJson(registryCommitmentPayload(version, deployedEvidenceHash)));
}

export function registryCommitmentCellData(commitmentHash: string): string {
  if (!/^(?:0x)?[0-9a-fA-F]{64}$/.test(commitmentHash)) {
    throw new ApiError(400, "invalid_commitment_hash", "Registry commitment hash must be 32-byte hexadecimal data");
  }
  const magic = [...new TextEncoder().encode("CSREGv1")].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `0x${magic}${commitmentHash.replace(/^0x/, "").toLowerCase()}`;
}

export function registryCommitmentConfiguration(env: Env, required: boolean): RegistryCommitmentConfiguration | null {
  const values = [
    env.REGISTRY_TYPE_SCRIPT_JSON,
    env.REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON,
    env.REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON,
    env.REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON,
  ]
    .map((value) => value?.trim() || undefined);
  if (values.every((value) => value === undefined)) {
    if (required) {
      throw new ApiError(503, "registry_commitment_unconfigured", "Registry Type Script, commitment lock, and both CellDeps are required");
    }
    return null;
  }
  if (values.some((value) => value === undefined)) {
    throw new ApiError(503, "registry_commitment_misconfigured", "Registry commitment Script configuration must be complete");
  }
  const typeScript = parseConfiguredJson(values[0]!, "REGISTRY_TYPE_SCRIPT_JSON");
  const typeScriptCellDep = parseConfiguredJson(values[1]!, "REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON");
  const commitmentLockScript = parseConfiguredJson(values[2]!, "REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON");
  const commitmentLockCellDep = parseConfiguredJson(values[3]!, "REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON");
  validateConfiguredScript(typeScript, "Registry Type Script");
  validateConfiguredScript(commitmentLockScript, "Registry commitment lock");
  validateConfiguredCellDep(typeScriptCellDep, "Registry Type Script CellDep");
  validateConfiguredCellDep(commitmentLockCellDep, "Registry commitment Lock CellDep");
  validateCanonicalMainnetRegistryConfiguration(
    env,
    typeScript,
    typeScriptCellDep,
    commitmentLockScript,
    commitmentLockCellDep,
  );
  return {
    type_script: typeScript,
    type_script_hash: ckbScriptHash(typeScript),
    type_script_cell_dep: typeScriptCellDep,
    commitment_lock_script: commitmentLockScript,
    commitment_lock_hash: ckbScriptHash(commitmentLockScript),
    commitment_lock_cell_dep: commitmentLockCellDep,
  };
}

function validateCanonicalMainnetRegistryConfiguration(
  env: Env,
  typeScript: Record<string, unknown>,
  typeScriptCellDep: Record<string, unknown>,
  commitmentLockScript: Record<string, unknown>,
  commitmentLockCellDep: Record<string, unknown>,
): void {
  if (env.REGISTRY_ENVIRONMENT?.trim().toLowerCase() === "testnet-sandbox") {
    validateCanonicalRegistryScripts(
      typeScript,
      typeScriptCellDep,
      commitmentLockScript,
      commitmentLockCellDep,
      CKB_TESTNET_SIGHASH_DEP_GROUP,
      "testnet-sandbox",
    );
    return;
  }
  if (env.ENVIRONMENT?.trim().toLowerCase() !== "production") return;

  validateCanonicalRegistryScripts(
    typeScript,
    typeScriptCellDep,
    commitmentLockScript,
    commitmentLockCellDep,
    CKB_MAINNET_SIGHASH_DEP_GROUP,
    "production",
  );
}

function validateCanonicalRegistryScripts(
  typeScript: Record<string, unknown>,
  typeScriptCellDep: Record<string, unknown>,
  commitmentLockScript: Record<string, unknown>,
  commitmentLockCellDep: Record<string, unknown>,
  sighashDepGroup: { out_point: { tx_hash: string; index: string }; dep_type: string },
  environment: RegistryEnvironment,
): void {

  const typeScriptIsCanonical = sameCkbHash(
    String(typeScript["code_hash"]),
    CANONICAL_REGISTRY_TYPE_SCRIPT.code_hash,
  )
    && typeScript["hash_type"] === CANONICAL_REGISTRY_TYPE_SCRIPT.hash_type
    && typeof typeScript["args"] === "string"
    && /^0x[0-9a-fA-F]{64}$/.test(typeScript["args"])
    && sameCkbHash(String(typeScript["args"]), ckbScriptHash(commitmentLockScript));
  if (!typeScriptIsCanonical || typeScriptCellDep["dep_type"] !== "code") {
    throw new ApiError(
      503,
      "registry_commitment_misconfigured",
      `${environment} Registry Type Script must use the tracked immutable data1 release and a direct code CellDep`,
    );
  }

  const lockArgs = commitmentLockScript["args"];
  const lockIsCanonical = sameCkbHash(
    String(commitmentLockScript["code_hash"]),
    CKB_MAINNET_SIGHASH_LOCK.code_hash,
  )
    && commitmentLockScript["hash_type"] === CKB_MAINNET_SIGHASH_LOCK.hash_type
    && typeof lockArgs === "string"
    && /^0x[0-9a-fA-F]{40}$/.test(lockArgs);
  if (!lockIsCanonical || !sameConfiguredCellDep(commitmentLockCellDep, sighashDepGroup)) {
    throw new ApiError(
      503,
      "registry_commitment_misconfigured",
      `${environment} commitment custody must use a 20-byte secp256k1-blake160 lock and the matching network genesis DepGroup`,
    );
  }
}

function sameConfiguredCellDep(
  actual: Record<string, unknown>,
  expected: { out_point: { tx_hash: string; index: string }; dep_type: string },
): boolean {
  const actualOutPoint = actual["out_point"] as Record<string, unknown>;
  const actualIndex = actualOutPoint["index"];
  const normalizedIndex = typeof actualIndex === "number" ? `0x${actualIndex.toString(16)}` : String(actualIndex).toLowerCase();
  return actual["dep_type"] === expected.dep_type
    && sameCkbHash(String(actualOutPoint["tx_hash"]), expected.out_point.tx_hash)
    && normalizedIndex === expected.out_point.index;
}

async function verifyRegistryCommitmentConfigurationOnChain(
  env: Env,
  configuration: RegistryCommitmentConfiguration,
): Promise<void> {
  const runtime = registryRuntimeConfig(env);
  const rpcUrl = runtime.rpc_url;
  const rpcOptions = {
    timeout_ms: boundedIntegerEnv(env.CKB_RPC_TIMEOUT_MS, 10_000, 1_000, 30_000),
    maximum_bytes: boundedIntegerEnv(env.CKB_RPC_MAX_RESPONSE_BYTES, 2 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024),
  };
  await requireRegistryRpc(rpcUrl, rpcOptions, runtime.network);
  await verifyConfiguredScriptCellDepOnChain(
    env,
    rpcUrl,
    rpcOptions,
    configuration.type_script,
    configuration.type_script_cell_dep,
    "Registry Type Script",
  );
  await verifyConfiguredScriptCellDepOnChain(
    env,
    rpcUrl,
    rpcOptions,
    configuration.commitment_lock_script,
    configuration.commitment_lock_cell_dep,
    "Registry commitment Lock Script",
  );
}

async function requireLiveRegistryCommitmentConfiguration(
  env: Env,
  deps: AppDeps,
  configuration: RegistryCommitmentConfiguration,
): Promise<void> {
  if (deps.verifyRegistryCommitmentConfiguration) {
    await deps.verifyRegistryCommitmentConfiguration(configuration);
    return;
  }
  await verifyRegistryCommitmentConfigurationOnChain(env, configuration);
}

async function verifyConfiguredScriptCellDepOnChain(
  env: Env,
  rpcUrl: string,
  rpcOptions: { timeout_ms: number; maximum_bytes: number },
  script: Record<string, unknown>,
  cellDep: Record<string, unknown>,
  label: string,
): Promise<void> {
  const rawOutPoint = assertPlainObject(cellDep["out_point"], "registry_commitment_misconfigured");
  const outPoint = {
    tx_hash: String(rawOutPoint["tx_hash"]),
    index: parseRpcUint32(rawOutPoint["index"], `${label} CellDep out_point.index`),
  };
  const declared = await getLiveCell(rpcUrl, outPoint, rpcOptions);
  await requireMinimumConfirmations(env, rpcUrl, declared.block_hash, rpcOptions, `${label} CellDep`);
  const candidates: Record<string, unknown>[] = [];
  if (cellDep["dep_type"] === "code") {
    candidates.push(declared.cell);
  } else {
    const data = assertPlainObject(declared.cell["data"], "invalid_ckb_rpc_response");
    if (typeof data["content"] !== "string") {
      throw new ApiError(503, "registry_commitment_cell_dep_invalid", `${label} DepGroup has no output data`);
    }
    const members = parseDepGroupOutPoints(data["content"]);
    const memberLimit = boundedIntegerEnv(env.CKB_DEP_GROUP_MAX_MEMBERS, 256, 1, 2048);
    if (members.length > memberLimit) {
      throw new ApiError(503, "registry_commitment_cell_dep_invalid", `${label} DepGroup exceeds the member limit`);
    }
    for (let offset = 0; offset < members.length; offset += 16) {
      const page = await Promise.all(members.slice(offset, offset + 16).map(async (member) => {
        try {
          const live = await getLiveCell(rpcUrl, member, rpcOptions);
          await requireMinimumConfirmations(env, rpcUrl, live.block_hash, rpcOptions, `${label} code Cell`);
          return live.cell;
        } catch (error) {
          if (error instanceof ApiError && error.code === "deployment_cell_not_live") return null;
          throw error;
        }
      }));
      candidates.push(...page.filter((cell): cell is Record<string, unknown> => cell !== null));
    }
  }
  if (!candidates.some((cell) => configuredScriptCodeHashMatches(cell, script))) {
    throw new ApiError(
      503,
      "registry_commitment_code_hash_unresolved",
      `${label} CellDep does not resolve the configured code_hash`,
    );
  }
}

function configuredScriptCodeHashMatches(cell: Record<string, unknown>, script: Record<string, unknown>): boolean {
  const codeHash = String(script["code_hash"]);
  if (script["hash_type"] === "type") {
    const output = assertPlainObject(cell["output"], "invalid_ckb_rpc_response");
    return Boolean(output["type"] && sameCkbHash(ckbScriptHash(output["type"]), codeHash));
  }
  const data = assertPlainObject(cell["data"], "invalid_ckb_rpc_response");
  const content = data["content"];
  if (typeof content !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(content)) return false;
  const dataHash = typeof data["hash"] === "string" ? data["hash"] : ckbBlake2bHex(hexToBytes(content));
  return sameCkbHash(dataHash, codeHash);
}

function parseConfiguredJson(raw: string, name: string): Record<string, unknown> {
  try {
    return assertPlainObject(JSON.parse(raw), "registry_commitment_misconfigured");
  } catch {
    throw new ApiError(503, "registry_commitment_misconfigured", `${name} must contain one JSON object`);
  }
}

function validateConfiguredScript(script: Record<string, unknown>, label: string): void {
  if (Object.keys(script).some((key) => !["code_hash", "hash_type", "args"].includes(key))) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} has an unknown field`);
  }
  if (typeof script["code_hash"] !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(script["code_hash"])) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label}.code_hash must be a 32-byte hash`);
  }
  if (!(typeof script["hash_type"] === "string" && ["data", "data1", "data2", "type"].includes(script["hash_type"]))) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label}.hash_type is invalid`);
  }
  if (typeof script["args"] !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(script["args"])) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label}.args must be hexadecimal bytes`);
  }
}

function validateConfiguredCellDep(cellDep: Record<string, unknown>, label: string): void {
  if (Object.keys(cellDep).some((key) => !["out_point", "dep_type"].includes(key))) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} has an unknown field`);
  }
  if (!(cellDep["dep_type"] === "code" || cellDep["dep_type"] === "dep_group")) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} dep_type is invalid`);
  }
  const rawOutPoint = cellDep["out_point"];
  if (typeof rawOutPoint !== "object" || rawOutPoint === null || Array.isArray(rawOutPoint)) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} out_point must be an object`);
  }
  const outPoint = rawOutPoint as Record<string, unknown>;
  if (Object.keys(outPoint).some((key) => !["tx_hash", "index"].includes(key))) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} out_point has an unknown field`);
  }
  if (typeof outPoint["tx_hash"] !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(outPoint["tx_hash"])) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} tx_hash is invalid`);
  }
  const index = outPoint["index"];
  if (!(typeof index === "string" && /^0x[0-9a-fA-F]+$/.test(index)) && !(Number.isSafeInteger(index) && Number(index) >= 0)) {
    throw new ApiError(503, "registry_commitment_misconfigured", `${label} index is invalid`);
  }
}

async function listRegistryCommitmentCells(
  env: Env,
  configuration: RegistryCommitmentConfiguration,
): Promise<RegistryCommitmentCell[]> {
  const runtime = registryRuntimeConfig(env);
  const rpcUrl = runtime.rpc_url;
  const rpcOptions = {
    timeout_ms: boundedIntegerEnv(env.CKB_RPC_TIMEOUT_MS, 10_000, 1_000, 30_000),
    maximum_bytes: boundedIntegerEnv(env.CKB_RPC_MAX_RESPONSE_BYTES, 2 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024),
  };
  await requireRegistryRpc(rpcUrl, rpcOptions, runtime.network);
  const tip = assertPlainObject(await ckbRpcRequest(rpcUrl, "get_tip_header", [], rpcOptions), "invalid_ckb_rpc_response");
  const tipNumber = parseRpcBlockNumber(tip["number"], "CKB tip block number");
  const minimumConfirmations = boundedIntegerEnv(env.CKB_MIN_CONFIRMATIONS, 24, 1, 10_000);
  const maximumCells = boundedIntegerEnv(env.CKB_REGISTRY_SCAN_MAX_CELLS, 1_000, 100, 10_000);
  const cells: RegistryCommitmentCell[] = [];
  let after: string | undefined;
  while (cells.length < maximumCells) {
    const searchKey = {
      script: configuration.type_script,
      script_type: "type",
      script_search_mode: "exact",
      filter: {
        output_data: "0x43535245477631",
        output_data_filter_mode: "prefix",
        output_data_len_range: ["0x27", "0x28"],
      },
      with_data: true,
    };
    const params: unknown[] = [searchKey, "asc", "0x64"];
    if (after) params.push(after);
    const page = assertPlainObject(await ckbRpcRequest(rpcUrl, "get_cells", params, rpcOptions), "invalid_ckb_rpc_response");
    const objects = page["objects"];
    if (!Array.isArray(objects)) {
      throw new ApiError(503, "invalid_ckb_rpc_response", "CKB Indexer get_cells returned no objects array");
    }
    for (const raw of objects) {
      const cell = assertPlainObject(raw, "invalid_ckb_rpc_response");
      const output = assertPlainObject(cell["output"], "invalid_ckb_rpc_response");
      const content = cell["output_data"];
      if (typeof content !== "string" || !/^0x43535245477631[0-9a-fA-F]{64}$/.test(content)) continue;
      if (!output["type"] || !sameCkbHash(ckbScriptHash(output["type"]), configuration.type_script_hash)) continue;
      if (!output["lock"] || !sameCkbHash(ckbScriptHash(output["lock"]), configuration.commitment_lock_hash)) continue;
      const outPoint = assertPlainObject(cell["out_point"], "invalid_ckb_rpc_response");
      const txHash = String(outPoint["tx_hash"] ?? "");
      const index = parseRpcUint32(outPoint["index"], "Registry commitment out_point.index");
      if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
        throw new ApiError(503, "invalid_ckb_rpc_response", "Registry commitment out_point.tx_hash is invalid");
      }
      const blockNumber = parseRpcBlockNumber(cell["block_number"], "Registry commitment block number");
      if (tipNumber < blockNumber || tipNumber - blockNumber + 1n < BigInt(minimumConfirmations)) continue;
      cells.push({
        commitment_hash: `0x${content.slice(-64).toLowerCase()}`,
        out_point: { tx_hash: txHash, index },
        block_number: `0x${blockNumber.toString(16)}`,
        tip_block_number: `0x${tipNumber.toString(16)}`,
        confirmations: Number(tipNumber - blockNumber + 1n),
        output,
      });
      if (cells.length >= maximumCells) break;
    }
    if (objects.length < 100) return cells;
    const cursor = page["last_cursor"];
    if (typeof cursor !== "string" || cursor === after) {
      throw new ApiError(503, "invalid_ckb_rpc_response", "CKB Indexer pagination cursor is invalid");
    }
    after = cursor;
  }
  throw new ApiError(503, "registry_commitment_scan_limit", `Registry commitment scan exceeded ${maximumCells} live Cells`);
}

function parseRpcUint32(value: unknown, label: string): number {
  const parsed = typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value) ? Number.parseInt(value.slice(2), 16) : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    throw new ApiError(503, "invalid_ckb_rpc_response", `${label} is not a u32`);
  }
  return parsed;
}

async function reconcileRegistryChainState(
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  now: Date,
  requestId: string,
): Promise<void> {
  const configuration = registryCommitmentConfiguration(env, true)!;
  const listCommitmentCells = deps.listRegistryCommitmentCells ?? deps.listMainnetCommitmentCells;
  const cells = listCommitmentCells
    ? await listCommitmentCells(configuration)
    : await listRegistryCommitmentCells(env, configuration);
  const cellsByHash = new Map(cells.map((cell) => [cell.commitment_hash.toLowerCase(), cell]));
  const staticOrigin = env.STATIC_REGISTRY_ORIGIN ?? DEFAULT_STATIC_REGISTRY_ORIGIN;
  let checked = 0;
  let committed = 0;
  let demotedCommitments = 0;
  let staleDeployments = 0;
  const versionsToCheck: PackageVersionRecord[] = [];
  for (let offset = 0; offset < 10_000; offset += 200) {
    const versions = await store.listPackageVersions({ deployment_status: "chain_verified", limit: 200, offset });
    versionsToCheck.push(...versions);
    if (versions.length < 200) break;
  }
  for (const version of versionsToCheck) {
    checked += 1;
    const previous = await store.listPackageEvidence(version.namespace, version.name, version.version);
    const deployed = previous.filter((item) => item.kind === "deployed").at(-1);
    if (!deployed) continue;
    try {
      const payload = deploymentPayloadFromEvidence(version, deployed.evidence, registryRuntimeConfig(env).network);
      const deploymentVerifier = deps.verifyDeployment ?? deps.verifyMainnetDeployment;
      if (deploymentVerifier) await deploymentVerifier(payload);
      else await verifyDeployment(env, payload);
    } catch (error) {
      if (error instanceof ApiError && [
        "deployment_cell_not_live",
        "dep_group_artifact_not_found",
        "deployment_data_hash_mismatch",
        "deployment_code_hash_mismatch",
        "chain_observation_uncommitted",
        "chain_confirmation_depth_insufficient",
      ].includes(error.code)) {
        const reconciled = await store.reconcilePackageVersionLifecycle({
          namespace: version.namespace,
          name: version.name,
          version: version.version,
          status: "verified_build",
          deployment_status: "undeployed",
          request_id: requestId,
          reason: error.code,
        });
        staleDeployments += 1;
        await syncLifecycleStatic(env, deps, store, reconciled, staticOrigin, requestId);
        continue;
      }
      await store.appendAuditEvent({
        request_id: requestId,
        event_type: "maintenance.lifecycle_check_failed",
        namespace: version.namespace,
        name: version.name,
        version: version.version,
        data: { error: error instanceof Error ? error.message : String(error) },
      });
      continue;
    }

    const commitmentHash = registryCommitmentHash(version, deployed.evidence_hash);
    const cell = cellsByHash.get(commitmentHash.toLowerCase());
    const priorCommitment = version.current_commitment_evidence_hash
      ? previous.find((item) => item.kind === "on_chain_committed"
        && item.evidence_hash === version.current_commitment_evidence_hash
        && item.evidence["deployed_evidence_hash"] === deployed.evidence_hash)
      : undefined;
    if (!cell) {
      if (version.current_commitment_evidence_hash) {
        const reconciled = await store.reconcilePackageVersionLifecycle({
          namespace: version.namespace,
          name: version.name,
          version: version.version,
          status: "deployed",
          deployment_status: "chain_verified",
          request_id: requestId,
          reason: "registry_commitment_cell_not_live",
        });
        demotedCommitments += 1;
        await syncLifecycleStatic(env, deps, store, reconciled, staticOrigin, requestId);
      }
      continue;
    }
    const sameLiveCell = priorCommitment
      && version.current_commitment_evidence_hash === priorCommitment.evidence_hash
      && priorCommitment.evidence["commitment_tx_hash"] === cell.out_point.tx_hash
      && assertPlainObject(priorCommitment.evidence["commitment_out_point"], "invalid_commitment_out_point")["index"] === cell.out_point.index;
    if (sameLiveCell || version.availability_status !== "active") continue;
    let evidence: Record<string, unknown> = {
      schema: "cellscript-registry-evidence",
      kind: "on_chain_committed",
      producer: `cellscript-registry-${registryRuntimeConfig(env).network}-indexer`,
      generated_at: now.toISOString(),
      verification_status: "passed",
      source_hash: version.source_hash,
      manifest_hash: version.manifest_hash,
      deployed_evidence_hash: deployed.evidence_hash,
      network: registryRuntimeConfig(env).network,
      commitment_tx_hash: cell.out_point.tx_hash,
      commitment_hash: commitmentHash,
      commitment_lock_hash: configuration.commitment_lock_hash,
      registry_type_hash: configuration.type_script_hash,
      commitment_out_point: cell.out_point,
      observed_at: now.toISOString(),
      observed_block_number: cell.block_number,
      ...(cell.tip_block_number ? { observed_tip_block_number: cell.tip_block_number } : {}),
      ...(cell.confirmations !== undefined ? { confirmations: cell.confirmations } : {}),
      commitment_status: "confirmed",
      commitment_schema: "cellscript-registry-commitment-v1",
      commitment_payload: registryCommitmentPayload(version, deployed.evidence_hash),
      chain_verification: "get_cells+configured_type_index",
    };
    if (version.compatibility_profile_hash) {
      evidence = { ...evidence, compatibility_profile_hash: version.compatibility_profile_hash };
    }
    evidence = validatePromotionEvidence(
      evidence,
      "on_chain_committed",
      version,
      previous,
      registryRuntimeConfig(env).network,
    );
    const evidenceHash = `sha256:${await sha256Hex(canonicalJson(evidence))}`;
    const promoted = await store.promotePackageVersion({
      namespace: version.namespace,
      name: version.name,
      version: version.version,
      kind: "on_chain_committed",
      evidence_hash: evidenceHash,
      evidence,
      request_id: requestId,
      admin_actor: `registry-${registryRuntimeConfig(env).network}-indexer`,
    });
    committed += 1;
    await syncLifecycleStatic(env, deps, store, promoted.version, staticOrigin, requestId);
  }
  await store.appendAuditEvent({
    request_id: requestId,
    event_type: "maintenance.registry_commitments_reconciled",
    data: {
      checked,
      live_commitment_cells: cells.length,
      committed,
      demoted_commitments: demotedCommitments,
      stale_deployments: staleDeployments,
    },
  });
}

async function demoteCurrentCommitments(
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  requestId: string,
  reason: string,
): Promise<number> {
  const staticOrigin = env.STATIC_REGISTRY_ORIGIN ?? DEFAULT_STATIC_REGISTRY_ORIGIN;
  let demoted = 0;
  for (let offset = 0; offset < 10_000; offset += 200) {
    const versions = await store.listPackageVersions({ deployment_status: "chain_verified", limit: 200, offset });
    for (const version of versions) {
      if (!version.current_commitment_evidence_hash) continue;
      const reconciled = await store.reconcilePackageVersionLifecycle({
        namespace: version.namespace,
        name: version.name,
        version: version.version,
        status: "deployed",
        deployment_status: "chain_verified",
        request_id: requestId,
        reason,
      });
      demoted += 1;
      await syncLifecycleStatic(env, deps, store, reconciled, staticOrigin, requestId);
    }
    if (versions.length < 200) break;
  }
  return demoted;
}

function deploymentPayloadFromEvidence(
  version: PackageVersionRecord,
  evidence: Record<string, unknown>,
  network: DeploymentPayload["network"],
): DeploymentPayload {
  const outPoint = assertPlainObject(evidence["out_point"], "invalid_deployment_out_point");
  return {
    protocol: DEPLOYMENT_PROTOCOL,
    action: DEPLOYMENT_ACTION,
    registry_origin: DEFAULT_REGISTRY_ORIGIN,
    namespace: version.namespace,
    name: version.name,
    release: version.version,
    network,
    artifact_hash: String(evidence["artifact_hash"]),
    data_hash: String(evidence["data_hash"]),
    code_hash: String(evidence["code_hash"]),
    hash_type: evidence["hash_type"] as DeploymentPayload["hash_type"],
    dep_type: evidence["dep_type"] as DeploymentPayload["dep_type"],
    out_point: { tx_hash: String(outPoint["tx_hash"]), index: Number(outPoint["index"]) },
    capability_key_id: "registry-lifecycle-reconciliation",
    nonce: `0x${"00".repeat(32)}`,
    issued_at: String(evidence["generated_at"]),
    expires_at: String(evidence["generated_at"]),
    cli_version: "registry-lifecycle-reconciliation",
  };
}

async function syncLifecycleStatic(
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  version: PackageVersionRecord,
  staticOrigin: string,
  requestId: string,
): Promise<void> {
  const snapshot = await store.getSnapshot(version.snapshot_hash);
  if (!snapshot) return;
  const evidence = await store.listPackageEvidence(version.namespace, version.name, version.version);
  await tryWriteStaticRegistryVersionObject(
    env,
    deps,
    store,
    requestId,
    { ...version, direct_url: staticPackageVersionUrl(staticOrigin, version.namespace, version.name, version.version) },
    snapshot,
    staticOrigin,
    evidence,
  );
}

async function verifyRegistryCommitment(
  env: Env,
  evidence: Record<string, unknown>,
  version: PackageVersionRecord,
  deployed: PackageEvidenceRecord,
): Promise<Record<string, unknown>> {
  const configuration = registryCommitmentConfiguration(env, true)!;
  const expectedHash = registryCommitmentHash(version, deployed.evidence_hash);
  if (!sameCkbHash(String(evidence["commitment_hash"]), expectedHash)) {
    throw new ApiError(409, "registry_commitment_mismatch", "commitment_hash does not commit to the accepted Registry release and deployment evidence");
  }
  const rawOutPoint = assertPlainObject(evidence["commitment_out_point"], "invalid_commitment_out_point");
  const outPoint = { tx_hash: String(rawOutPoint["tx_hash"]), index: Number(rawOutPoint["index"]) };
  const runtime = registryRuntimeConfig(env);
  const rpcUrl = runtime.rpc_url;
  const rpcOptions = {
    timeout_ms: boundedIntegerEnv(env.CKB_RPC_TIMEOUT_MS, 10_000, 1_000, 30_000),
    maximum_bytes: boundedIntegerEnv(env.CKB_RPC_MAX_RESPONSE_BYTES, 2 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024),
  };
  await requireRegistryRpc(rpcUrl, rpcOptions, runtime.network);
  const live = await getLiveCell(rpcUrl, outPoint, rpcOptions);
  const observation = await requireMinimumConfirmations(env, rpcUrl, live.block_hash, rpcOptions, "Registry commitment");
  const data = assertPlainObject(live.cell["data"], "invalid_ckb_rpc_response");
  if (typeof data["content"] !== "string" || data["content"].toLowerCase() !== registryCommitmentCellData(expectedHash)) {
    throw new ApiError(409, "registry_commitment_data_mismatch", "live Registry commitment Cell data does not contain the expected compact commitment");
  }
  const output = assertPlainObject(live.cell["output"], "invalid_ckb_rpc_response");
  const typeScript = output["type"];
  if (!typeScript) {
    throw new ApiError(409, "registry_commitment_type_missing", "Registry commitment Cell must have a Type Script for chain indexing");
  }
  const actualTypeHash = ckbScriptHash(typeScript);
  if (!sameCkbHash(actualTypeHash, configuration.type_script_hash)
    || !sameCkbHash(actualTypeHash, String(evidence["registry_type_hash"]))) {
    throw new ApiError(409, "registry_commitment_type_mismatch", "Registry commitment Cell does not use the configured Registry Type Script");
  }
  const actualLockHash = ckbScriptHash(output["lock"]);
  if (!sameCkbHash(actualLockHash, configuration.commitment_lock_hash)
    || !sameCkbHash(actualLockHash, String(evidence["commitment_lock_hash"]))) {
    throw new ApiError(409, "commitment_lock_mismatch", "Registry commitment Cell does not use the configured commitment lock");
  }
  return {
    commitment_schema: "cellscript-registry-commitment-v1",
    commitment_payload: registryCommitmentPayload(version, deployed.evidence_hash),
    chain_verification: "get_transaction+get_live_cell+configured_type_index",
    observed_block_hash: live.block_hash ?? null,
    observed_block_number: observation.block_number,
    observed_tip_block_number: observation.tip_block_number,
    confirmations: observation.confirmations,
  };
}

async function handleReadiness(env: Env, deps: AppDeps, requestId: string, headers: Headers): Promise<Response> {
  let runtime: RegistryRuntimeConfig | null = null;
  const storeConfigured = !!deps.store || !!env.HYPERDRIVE;
  const objectStoreConfigured =
    (!!deps.snapshotWriter && !!deps.registryObjectReader)
    || !!env.REGISTRY_OBJECTS
    || !!env.SOURCE_SNAPSHOTS;
  const adminConfigured = typeof env.REGISTRY_ADMIN_TOKEN === "string" && env.REGISTRY_ADMIN_TOKEN.trim() !== "";
  const checks: Record<string, string> = {
    store: storeConfigured ? "configured" : "missing_hyperdrive",
    object_store: objectStoreConfigured ? "configured" : "missing_r2",
    admin_token: adminConfigured ? "configured" : "missing_secret",
  };
  let dependenciesHealthy = true;
  try {
    runtime = registryRuntimeConfig(env);
    checks["registry_environment"] = runtime.environment;
    checks["ckb_network"] = runtime.network;
    if (runtime.environment === "testnet-sandbox" || env.CKB_RPC_URL || env.CKB_MAINNET_RPC_URL) {
      await requireRegistryRpc(runtime.rpc_url, {
        timeout_ms: boundedIntegerEnv(env.CKB_RPC_TIMEOUT_MS, 10_000, 1_000, 30_000),
        maximum_bytes: boundedIntegerEnv(env.CKB_RPC_MAX_RESPONSE_BYTES, 2 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024),
      }, runtime.network);
      checks["ckb_rpc"] = "configured_network_confirmed";
    } else {
      checks["ckb_rpc"] = "default_mainnet";
    }
  } catch {
    checks["registry_environment"] = "misconfigured";
    checks["ckb_rpc"] = "wrong_network_or_unreachable";
    dependenciesHealthy = false;
  }
  try {
    const commitmentConfiguration = registryCommitmentConfiguration(env, false);
    if (commitmentConfiguration) {
      await requireLiveRegistryCommitmentConfiguration(env, deps, commitmentConfiguration);
      checks["registry_commitment"] = "configured_and_live";
    } else {
      checks["registry_commitment"] = "disabled";
    }
  } catch {
    checks["registry_commitment"] = "misconfigured";
    dependenciesHealthy = false;
  }
  try {
    const policy = registryReproducerPolicy(env, false);
    if (policy) {
      const keysAreImportable = await Promise.all(
        [...policy.builders.values()].map((builder) => isImportableP256SpkiPublicKey(builder.public_key)),
      );
      if (keysAreImportable.some((valid) => !valid)) {
        throw new ApiError(503, "reproducer_policy_misconfigured", "trusted builder policy contains an invalid P-256 public key");
      }
      checks["reproducer_policy"] = "configured";
    } else {
      checks["reproducer_policy"] = "disabled";
    }
  } catch {
    checks["reproducer_policy"] = "misconfigured";
    dependenciesHealthy = false;
  }
  const store = optionalStore(env, deps);
  if (store) {
    try {
      await store.healthCheck();
      checks["store"] = "ready";
    } catch {
      checks["store"] = "unreachable";
      dependenciesHealthy = false;
    }
  }
  if (deps.readinessCheck) {
    try {
      Object.assign(checks, await deps.readinessCheck());
    } catch {
      checks["runtime"] = "unready";
      dependenciesHealthy = false;
    }
  }
  const ready = storeConfigured && objectStoreConfigured && adminConfigured && dependenciesHealthy;
  return json(
    {
      status: ready ? "ready" : "not_ready",
      request_id: requestId,
      checks,
    },
    ready ? 200 : 503,
    headers,
  );
}

async function handleAdminReservedNamespace(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
): Promise<Response> {
  const adminActor = await requireAdminActor(request, env);
  const body = await readJson(request, maxJsonBytes(env));
  const namespace = validatePackageIdent(String(body["namespace"] ?? ""), "namespace");
  const matchType = requireOneOf(String(body["match_type"] ?? "exact"), ["exact", "prefix", "typosquat"], "invalid_reserved_match_type");
  const reason = requireNonEmptyAdminString(body["reason"], "reason");
  const record = await store.upsertReservedNamespace({
    namespace,
    match_type: matchType,
    reason,
    request_id: requestId,
    admin_actor: adminActor,
  });
  return json({ request_id: requestId, ...record }, 200, headers);
}

async function handleAdminAuditEvents(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
): Promise<Response> {
  await requireAdminActor(request, env);
  const params = new URL(request.url).searchParams;
  const eventType = optionalAuditParam(params, "event_type");
  const principalType = optionalAuditParam(params, "principal_type");
  const principalId = optionalAuditParam(params, "principal_id");
  const namespaceRaw = optionalAuditParam(params, "namespace");
  const nameRaw = optionalAuditParam(params, "name");
  const versionRaw = optionalAuditParam(params, "version");
  const beforeRaw = optionalAuditParam(params, "before");
  const limit = auditLimit(params);
  if (principalType && !isPrincipalType(principalType)) {
    throw new ApiError(400, "invalid_audit_filter", "principal_type filter is unsupported");
  }
  const before = beforeRaw ? parseAuditBefore(beforeRaw) : undefined;
  const namespace = namespaceRaw ? validatePackageIdent(namespaceRaw, "namespace") : undefined;
  const name = nameRaw ? validatePackageIdent(nameRaw, "name") : undefined;
  const version = versionRaw ? validateVersion(versionRaw) : undefined;
  const events = await store.listAuditEvents({
    ...(eventType ? { event_type: eventType } : {}),
    ...(principalType ? { principal_type: principalType } : {}),
    ...(principalId ? { principal_id: principalId } : {}),
    ...(namespace ? { namespace } : {}),
    ...(name ? { name } : {}),
    ...(version ? { version } : {}),
    ...(before ? { before } : {}),
    limit,
  });
  const nextBefore = events.length === limit ? events[events.length - 1]?.created_at : undefined;
  return json(
    {
      request_id: requestId,
      events,
      ...(nextBefore ? { next_before: nextBefore } : {}),
    },
    200,
    headers,
  );
}

async function handleAdminVerificationQueue(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
): Promise<Response> {
  await requireAdminActor(request, env);
  const metrics = await store.getVerificationQueueMetrics();
  return json(
    {
      schema: "cellscript-registry-verification-queue-v1",
      request_id: requestId,
      ...metrics,
    },
    200,
    headers,
  );
}

async function handleAdminVerificationRetry(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
  jobIdFromPath: string,
): Promise<Response> {
  const adminActor = await requireAdminActor(request, env);
  const jobId = requireUuid(jobIdFromPath, "verification_job_id");
  const job = await store.retryVerificationJob({ job_id: jobId, request_id: requestId, admin_actor: adminActor });
  return json({ request_id: requestId, job }, 200, headers);
}

async function handleAdminNamespaceStatus(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  headers: Headers,
  namespaceFromPath: string,
): Promise<Response> {
  const adminActor = await requireAdminActor(request, env);
  const body = await readJson(request, maxJsonBytes(env));
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const status = requireOneOf(
    String(body["status"] ?? ""),
    ["active", "review_pending", "reserved", "rejected", "quarantined"],
    "invalid_namespace_status",
  );
  const reviewReason = typeof body["review_reason"] === "string" && body["review_reason"].trim() !== "" ? body["review_reason"].trim() : undefined;
  const record = await store.updateNamespaceStatus({
    namespace,
    status,
    ...(reviewReason ? { review_reason: reviewReason } : {}),
    request_id: requestId,
    admin_actor: adminActor,
  });
  return json({ request_id: requestId, ...record }, 200, headers);
}

async function handleAdminPackageVersionStatus(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  staticOrigin: string,
  deps: AppDeps,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
  versionFromPath: string,
): Promise<Response> {
  const adminActor = await requireAdminActor(request, env);
  const body = await readJson(request, maxJsonBytes(env));
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const version = validateVersion(versionFromPath);
  const status = requireOneOf(
    String(body["availability_status"] ?? ""),
    ["active", "deprecated", "yanked", "quarantined"],
    "invalid_availability_status",
  );
  const reason = typeof body["reason"] === "string" && body["reason"].trim() !== "" ? body["reason"].trim() : undefined;
  const directUrl = staticPackageVersionUrl(staticOrigin, namespace, name, version);
  const existing = await store.getPackageVersion(namespace, name, version);
  if (!existing) {
    throw new ApiError(404, "artifact_release_not_found", "artifact release is not known to the registry");
  }
  const snapshot = await requireSnapshot(store, existing);
  const evidence = await store.listPackageEvidence(namespace, name, version);
  if (isSuppressivePackageVersionStatus(status)) {
    await writeStaticRegistryVersionObject(
      env,
      deps,
      { ...existing, status: status === "active" ? existing.status : status, availability_status: status, direct_url: directUrl },
      snapshot,
      staticOrigin,
      evidence,
    );
  }
  const record = await store.updatePackageVersionStatus({
    namespace,
    name,
    version,
    status,
    ...(reason ? { reason } : {}),
    request_id: requestId,
    admin_actor: adminActor,
  });
  if (!isSuppressivePackageVersionStatus(status)) {
    await tryWriteStaticRegistryVersionObject(
      env,
      deps,
      store,
      requestId,
      { ...record, direct_url: directUrl },
      snapshot,
      staticOrigin,
      evidence,
    );
  }
  return json({ request_id: requestId, ...record }, 200, headers);
}

async function handleAdminPackageVersionPromotion(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  staticOrigin: string,
  deps: AppDeps,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
  versionFromPath: string,
): Promise<Response> {
  const adminActor = await requireAdminActor(request, env);
  const namespace = validatePackageIdent(namespaceFromPath, "namespace");
  const name = validatePackageIdent(nameFromPath, "name");
  const version = validateVersion(versionFromPath);
  const body = await readJson(request, Math.min(maxJsonBytes(env), 512 * 1024));
  const kind = requireOneOf(
    String(body["kind"] ?? ""),
    ["verified_build", "reproduced_build", "deployed", "on_chain_committed"],
    "invalid_evidence_kind",
  ) as PackageEvidenceKind;
  const existing = await store.getPackageVersion(namespace, name, version);
  if (!existing) {
    throw new ApiError(404, "artifact_release_not_found", "artifact release is not known to the registry");
  }
  const previousEvidence = await store.listPackageEvidence(namespace, name, version);
  if (kind === "deployed" && packageVersionRequiresReproduction(existing) && existing.verification_status !== "verified") {
    throw new ApiError(409, "reproduction_evidence_missing", "reproducible artifacts require accepted independent reproduction evidence before deployment");
  }
  const runtime = registryRuntimeConfig(env);
  let evidence = validatePromotionEvidence(body["evidence"], kind, existing, previousEvidence, runtime.network);
  if (kind === "reproduced_build") {
    evidence = {
      ...evidence,
      ...(await verifyAuthenticatedReproductionReports(env, deps, evidence)),
    };
  } else if (kind === "deployed") {
    if (existing.artifact.profile !== "ckb_executable") {
      throw new ApiError(409, "deployment_not_applicable", "only ckb_executable artifacts can record deployment evidence");
    }
    const rawOutPoint = assertPlainObject(evidence["out_point"], "invalid_deployment_out_point");
    const deploymentPayload: DeploymentPayload = {
      protocol: DEPLOYMENT_PROTOCOL,
      action: DEPLOYMENT_ACTION,
      registry_origin: env.REGISTRY_ORIGIN ?? DEFAULT_REGISTRY_ORIGIN,
      namespace,
      name,
      release: version,
      network: runtime.network,
      artifact_hash: String(evidence["artifact_hash"]),
      data_hash: String(evidence["data_hash"]),
      code_hash: String(evidence["code_hash"]),
      hash_type: evidence["hash_type"] as DeploymentPayload["hash_type"],
      dep_type: evidence["dep_type"] as DeploymentPayload["dep_type"],
      out_point: { tx_hash: String(rawOutPoint["tx_hash"]), index: Number(rawOutPoint["index"]) },
      capability_key_id: "admin-evidence-recovery",
      nonce: `0x${"00".repeat(32)}`,
      issued_at: String(evidence["generated_at"]),
      expires_at: String(evidence["generated_at"]),
      cli_version: "admin-evidence-recovery",
    };
    const deploymentVerifier = deps.verifyDeployment ?? deps.verifyMainnetDeployment;
    const chain = deploymentVerifier
      ? await deploymentVerifier(deploymentPayload)
      : await verifyDeployment(env, deploymentPayload);
    evidence = {
      ...evidence,
      chain_verification: "get_transaction+get_live_cell",
      ...(chain.block_hash ? { block_hash: chain.block_hash } : {}),
      ...(chain.block_number ? { block_number: chain.block_number } : {}),
      ...(chain.tip_block_number ? { observed_tip_block_number: chain.tip_block_number } : {}),
      ...(chain.confirmations !== undefined ? { confirmations: chain.confirmations } : {}),
      ...(chain.resolved_code_out_point ? { resolved_code_out_point: chain.resolved_code_out_point } : {}),
      ...(chain.dep_group_size !== undefined ? { dep_group_size: chain.dep_group_size } : {}),
    };
  } else if (kind === "on_chain_committed") {
    const deployed = latestEvidence(previousEvidence, "deployed");
    if (!deployed.evidence["chain_verification"]) {
      throw new ApiError(409, "deployment_chain_evidence_missing", "on-chain commitment requires RPC-verified deployment evidence");
    }
    const configuration = registryCommitmentConfiguration(env, true)!;
    await requireLiveRegistryCommitmentConfiguration(env, deps, configuration);
    const verifyCommitment = deps.verifyRegistryCommitment ?? deps.verifyMainnetCommitment;
    const chainEvidence = verifyCommitment
      ? await verifyCommitment(evidence, existing, deployed)
      : await verifyRegistryCommitment(env, evidence, existing, deployed);
    evidence = { ...evidence, ...chainEvidence };
  }
  const evidenceHash = `sha256:${await sha256Hex(canonicalJson(evidence))}`;
  const promotion = {
    namespace,
    name,
    version,
    kind,
    evidence_hash: evidenceHash,
    evidence,
    request_id: requestId,
    admin_actor: adminActor,
  };
  const promoted = kind === "deployed"
    ? await store.recordChainVerifiedDeployment(promotion)
    : await store.promotePackageVersion(promotion);
  const allEvidence = await store.listPackageEvidence(namespace, name, version);
  const snapshot = await requireSnapshot(store, promoted.version);
  await tryWriteStaticRegistryVersionObject(
    env,
    deps,
    store,
    requestId,
    { ...promoted.version, direct_url: staticPackageVersionUrl(staticOrigin, namespace, name, version) },
    snapshot,
    staticOrigin,
    allEvidence,
  );
  return json(
    {
      request_id: requestId,
      namespace,
      name,
      version,
      status: promoted.version.status,
      evidence: promoted.evidence,
    },
    200,
    headers,
  );
}

function isSuppressivePackageVersionStatus(status: string): boolean {
  return status === "deprecated" || status === "yanked" || status === "quarantined";
}

function getProductionStore(env: Env): RegistryStore {
  if (!env.HYPERDRIVE) {
    throw new ApiError(503, "registry_store_unconfigured", "HYPERDRIVE binding is required for production registry writes");
  }
  return new SqlRegistryStore(env.HYPERDRIVE);
}

function optionalStore(env: Env, deps: AppDeps): RegistryStore | undefined {
  if (deps.store) {
    return deps.store;
  }
  return env.HYPERDRIVE ? new SqlRegistryStore(env.HYPERDRIVE) : undefined;
}

async function handleCreateAuthorisationSession(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  now: Date,
  headers: Headers,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "authorisation_session_create", 30, 60, now);
  const body = await readJson(request, Math.min(maxJsonBytes(env), 64 * 1024));
  const capabilityPubkey = String(body["capability_pubkey"] ?? "").trim();
  if (!isCanonicalP256SpkiPublicKey(capabilityPubkey) || !await isImportableP256SpkiPublicKey(capabilityPubkey)) {
    throw new ApiError(400, "invalid_capability_pubkey", "capability_pubkey must be an importable canonical P-256 SPKI key");
  }
  const scopesValue = body["requested_scopes"];
  if (!Array.isArray(scopesValue) || scopesValue.length !== 1 || typeof scopesValue[0] !== "string") {
    throw new ApiError(400, "invalid_authorisation_session_scope", "browser authorisation requires one exact publish scope");
  }
  const scope = scopesValue[0].trim();
  const scopeMatch = scope.match(/^publish:([^/]+)\/([^/]+)$/);
  if (!scopeMatch) {
    throw new ApiError(400, "invalid_authorisation_session_scope", "browser authorisation requires publish:namespace/name");
  }
  const namespace = validatePackageIdent(scopeMatch[1] ?? "", "namespace");
  const name = validatePackageIdent(scopeMatch[2] ?? "", "name");
  const artifactKind = String(body["artifact_kind"] ?? "").trim() as ArtifactKind;
  if (!ARTIFACT_KINDS.includes(artifactKind)) {
    throw new ApiError(400, "invalid_artifact_kind", `artifact_kind must be one of ${ARTIFACT_KINDS.join(", ")}`);
  }
  const capabilityExpiresAt = String(body["capability_expires_at"] ?? "").trim();
  const capabilityExpiry = new Date(capabilityExpiresAt);
  if (!Number.isFinite(capabilityExpiry.getTime()) || capabilityExpiry.getTime() <= now.getTime()) {
    throw new ApiError(400, "invalid_capability_expiry", "capability_expires_at must be a future ISO timestamp");
  }
  if (capabilityExpiry.getTime() > now.getTime() + 366 * 24 * 60 * 60 * 1_000) {
    throw new ApiError(400, "capability_expiry_too_long", "browser-authorised capabilities may last no longer than 366 days");
  }
  const cliVersion = String(body["cli_version"] ?? "").trim();
  if (!cliVersion || cliVersion.length > 64) throw new ApiError(400, "invalid_cli_version", "cli_version is required");

  const sessionId = `auth_${crypto.randomUUID().replaceAll("-", "")}`;
  const pollToken = `poll_${crypto.randomUUID().replaceAll("-", "")}`;
  const browserToken = `browser_${crypto.randomUUID().replaceAll("-", "")}`;
  const expiresAt = new Date(now.getTime() + AUTHORISATION_SESSION_TTL_MINUTES * 60 * 1_000).toISOString();
  const websiteOrigin = registryWebsiteOrigin(env);
  const record = await store.createAuthorisationSession({
    session_id: sessionId,
    poll_token_hash: `sha256:${await sha256Hex(pollToken)}`,
    browser_token_hash: `sha256:${await sha256Hex(browserToken)}`,
    registry_origin: registryOrigin,
    website_origin: websiteOrigin,
    capability_pubkey: capabilityPubkey,
    requested_scopes: [scope],
    capability_expires_at: capabilityExpiry.toISOString(),
    cli_version: cliVersion,
    namespace,
    name,
    artifact_kind: artifactKind,
    status: "pending",
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    expires_at: expiresAt,
    request_id: requestId,
  });
  await store.appendAuditEvent({
    request_id: requestId,
    event_type: "authorisation_session.created",
    namespace,
    name,
    data: { session_id: record.session_id, capability_key_id: await capabilityKeyId(capabilityPubkey), expires_at: expiresAt },
  });
  return json({
    schema: "cellscript-registry-authorisation-session-v1",
    request_id: requestId,
    session_id: record.session_id,
    poll_token: pollToken,
    browser_url: `${websiteOrigin}/registry/submit#authorisation_session=${encodeURIComponent(record.session_id)}&browser_token=${encodeURIComponent(browserToken)}`,
    artifact: { namespace, name, kind: artifactKind },
    requested_scopes: record.requested_scopes,
    expires_at: record.expires_at,
  }, 201, headers);
}

async function handleGetAuthorisationSession(
  request: Request,
  store: RegistryStore,
  requestId: string,
  now: Date,
  headers: Headers,
  sessionIdFromPath: string,
): Promise<Response> {
  const sessionId = validateAuthorisationSessionId(sessionIdFromPath);
  const session = await requireReadableAuthorisationSession(store, sessionId, now);
  const authorization = request.headers.get("authorization");
  const token = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token) throw new ApiError(401, "authorisation_session_token_required", "authorisation session bearer token is required");
  const tokenHash = `sha256:${await sha256Hex(token)}`;
  const isCliPoll = await constantTimeSecretEqual(tokenHash, session.poll_token_hash);
  const isBrowser = await constantTimeSecretEqual(tokenHash, session.browser_token_hash);
  if (!isCliPoll && !isBrowser) {
    throw new ApiError(401, "invalid_authorisation_session_token", "authorisation session bearer token is invalid");
  }
  return json({
    schema: "cellscript-registry-authorisation-session-v1",
    request_id: requestId,
    session_id: session.session_id,
    status: session.status,
    artifact: { namespace: session.namespace, name: session.name, kind: session.artifact_kind },
    requested_scopes: session.requested_scopes,
    capability_expires_at: session.capability_expires_at,
    expires_at: session.expires_at,
    ...(isCliPoll && session.capability_key_id ? { capability_key_id: session.capability_key_id } : {}),
    ...(isCliPoll && session.namespace_status ? { namespace_status: session.namespace_status } : {}),
  }, 200, headers);
}

async function handlePrepareAuthorisationSession(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  now: Date,
  headers: Headers,
  sessionIdFromPath: string,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "authorisation_session_challenge", 60, 60, now);
  const sessionId = validateAuthorisationSessionId(sessionIdFromPath);
  const session = await requireReadableAuthorisationSession(store, sessionId, now);
  await requireAuthorisationBrowserToken(request, session.browser_token_hash);
  if (session.status !== "pending") {
    throw new ApiError(409, "authorisation_session_complete", "authorisation session has already completed");
  }
  if (session.registry_origin !== registryOrigin) {
    throw new ApiError(409, "authorisation_session_origin_mismatch", "authorisation session belongs to another Registry origin");
  }
  const body = await readJson(request, Math.min(maxJsonBytes(env), 16 * 1024));
  const issuedAt = now.toISOString();
  const challengeExpiresAt = new Date(Math.min(Date.parse(session.expires_at), now.getTime() + 10 * 60 * 1_000)).toISOString();
  const payload = validateCapabilityPayload({
    protocol: "cellscript-registry-auth-v1",
    action: "authorize_capability",
    registry_origin: registryOrigin,
    principal_type: body["principal_type"],
    principal_id: body["principal_id"],
    capability_pubkey: session.capability_pubkey,
    requested_scopes: session.requested_scopes,
    capability_expires_at: session.capability_expires_at,
    nonce: `0x${crypto.randomUUID().replaceAll("-", "")}`,
    issued_at: issuedAt,
    expires_at: challengeExpiresAt,
    cli_version: session.cli_version,
  }, registryOrigin, now);
  const challengeToken = `challenge_${crypto.randomUUID().replaceAll("-", "")}`;
  await store.prepareAuthorisationSession({
    session_id: sessionId,
    principal_type: payload.principal_type,
    principal_id: payload.principal_id,
    payload,
    challenge_token_hash: `sha256:${await sha256Hex(challengeToken)}`,
    request_id: requestId,
  });
  return json({
    schema: "cellscript-registry-authorisation-challenge-v1",
    request_id: requestId,
    session_id: sessionId,
    challenge_token: challengeToken,
    payload,
  }, 200, headers);
}

async function handleCompleteAuthorisationSession(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  now: Date,
  deps: AppDeps,
  headers: Headers,
  sessionIdFromPath: string,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "authorisation_session_complete", 40, 60, now);
  const sessionId = validateAuthorisationSessionId(sessionIdFromPath);
  const session = await requireReadableAuthorisationSession(store, sessionId, now);
  await requireAuthorisationBrowserToken(request, session.browser_token_hash);
  if (session.status !== "pending") {
    return json({
      schema: "cellscript-registry-authorisation-session-v1",
      request_id: requestId,
      session_id: session.session_id,
      status: session.status,
      ...(session.namespace_status ? { namespace_status: session.namespace_status } : {}),
    }, 200, headers);
  }
  if (!session.payload || !session.challenge_token_hash) {
    throw new ApiError(409, "authorisation_challenge_missing", "request a wallet challenge before completing this session");
  }
  const body = await readJson(request, Math.min(maxJsonBytes(env), 128 * 1024));
  const challengeToken = String(body["challenge_token"] ?? "").trim();
  const challengeTokenHash = `sha256:${await sha256Hex(challengeToken)}`;
  if (!challengeToken || !await constantTimeSecretEqual(challengeTokenHash, session.challenge_token_hash)) {
    throw new ApiError(401, "invalid_authorisation_challenge_token", "authorisation challenge token is invalid or stale");
  }
  const payload = validateCapabilityPayload(session.payload, registryOrigin, now);
  const signature = requirePrincipalSignature(body, payload.principal_type);
  await verifyPrincipalAuthorisationPayload(payload, signature, deps.joyidVerifier ?? productionJoyidVerifier());
  await throttle(store, requestId, `principal:${payload.principal_type}:${payload.principal_id}`, "capability", 8, 60 * 60, now);
  await throttle(store, requestId, `principal:${payload.principal_type}:${payload.principal_id}`, "namespace_claim", 12, 24 * 60 * 60, now);
  const existing = await store.getNamespace(session.namespace);
  if (existing && (existing.owner_principal_type !== payload.principal_type || existing.owner_principal_id !== payload.principal_id)) {
    throw new ApiError(409, "namespace_already_claimed", "namespace is already claimed by another principal");
  }
  const nonce = await signedNonceUse(requestId, {
    protocol: payload.protocol,
    action: `${payload.action}:capability_create`,
    nonce: payload.nonce,
    expires_at: payload.expires_at,
    principal_type: payload.principal_type,
    principal_id: payload.principal_id,
  });
  const completion = await store.finaliseAuthorisationSession({
    session_id: sessionId,
    expected_challenge_token_hash: challengeTokenHash,
    payload,
    principal_signature: signature,
    nonce: {
      ...nonce,
      principal_type: payload.principal_type,
      principal_id: payload.principal_id,
    },
    request_id: requestId,
    now_iso: now.toISOString(),
    namespace_claim_cooldown_seconds: namespaceClaimCooldownSeconds(env),
  });
  const completed = completion.session;
  const namespaceStatus = completed.namespace_status;
  if (!namespaceStatus) throw new Error("completed authorisation session did not record namespace status");
  return json({
    schema: "cellscript-registry-authorisation-session-v1",
    request_id: requestId,
    session_id: completed.session_id,
    status: completed.status,
    namespace_status: namespaceStatus,
  }, completion.replayed ? 200 : namespaceStatus === "active" ? 201 : 202, headers);
}

function validateAuthorisationSessionId(value: string): string {
  const sessionId = value.trim().toLowerCase();
  if (!/^auth_[0-9a-f]{32}$/.test(sessionId)) {
    throw new ApiError(400, "invalid_authorisation_session_id", "authorisation session ID is malformed");
  }
  return sessionId;
}

async function requireReadableAuthorisationSession(store: RegistryStore, sessionId: string, now: Date) {
  const session = await store.getAuthorisationSession(sessionId);
  if (!session) throw new ApiError(404, "authorisation_session_not_found", "authorisation session was not found");
  if (session.status === "pending" && Date.parse(session.expires_at) <= now.getTime()) {
    throw new ApiError(410, "authorisation_session_expired", "authorisation session has expired; start again from cellc");
  }
  return session;
}

async function requireAuthorisationBrowserToken(request: Request, expectedHash: string): Promise<void> {
  const authorization = request.headers.get("authorization");
  const token = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token || !token.startsWith("browser_")) {
    throw new ApiError(401, "authorisation_browser_token_required", "browser authorisation token is required");
  }
  if (!await constantTimeSecretEqual(`sha256:${await sha256Hex(token)}`, expectedHash)) {
    throw new ApiError(401, "invalid_authorisation_browser_token", "browser authorisation token is invalid");
  }
}

function registryWebsiteOrigin(env: Env): string {
  const configured = (env.REGISTRY_WEBSITE_ORIGIN ?? (
    registryRuntimeConfig(env).environment === "testnet-sandbox"
      ? "https://testnet.registry.cellscript.dev"
      : "https://cellscript.dev"
  )).trim().replace(/\/$/, "");
  let url: URL;
  try { url = new URL(configured); }
  catch { throw new ApiError(503, "invalid_registry_website_origin", "REGISTRY_WEBSITE_ORIGIN must be an absolute URL"); }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
    || !url.hostname || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new ApiError(503, "invalid_registry_website_origin", "REGISTRY_WEBSITE_ORIGIN must be a credential-free HTTPS origin (HTTP is allowed only on loopback)");
  }
  return url.origin;
}

async function handleCreateCapability(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  now: Date,
  deps: AppDeps,
  headers: Headers,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "capability_create", 120, 60, now);
  const body = await readJson(request, maxJsonBytes(env));
  const payload = validateCapabilityPayload(body["payload"], registryOrigin, now);
  const signature = requirePrincipalSignature(body, payload.principal_type);
  await verifyPrincipalAuthorisationPayload(payload, signature, deps.joyidVerifier ?? productionJoyidVerifier());
  await throttle(store, requestId, `principal:${payload.principal_type}:${payload.principal_id}`, "capability", 8, 60 * 60, now);
  const nonceKey = await consumeSignedNonce(store, requestId, {
    protocol: payload.protocol,
    action: `${payload.action}:capability_create`,
    nonce: payload.nonce,
    expires_at: payload.expires_at,
    principal_type: payload.principal_type,
    principal_id: payload.principal_id,
  });
  let capability;
  try {
    capability = await store.recordCapability({ payload, principal_signature: signature, request_id: requestId });
  } catch (error) {
    await store.releaseNonce({ nonce_key: nonceKey, request_id: requestId });
    throw error;
  }
  return json(
    {
      request_id: requestId,
      key_id: capability.key_id,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      scopes: capability.scopes,
      expires_at: capability.expires_at,
      status: "active",
    },
    201,
    headers,
  );
}

async function handleClaimNamespace(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  now: Date,
  deps: AppDeps,
  headers: Headers,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "namespace_claim", 40, 60 * 60, now);
  const body = await readJson(request, maxJsonBytes(env));
  const namespace = validatePackageIdent(String(body["namespace"] ?? ""), "namespace");
  const payload = validateCapabilityPayload(body["payload"], registryOrigin, now);
  const signature = requirePrincipalSignature(body, payload.principal_type);
  if (!payload.requested_scopes.some((scope) => scope.startsWith(`publish:${namespace}/`))) {
    throw new ApiError(403, "namespace_scope_missing", "namespace claim requires a publish scope for that namespace");
  }
  await verifyPrincipalAuthorisationPayload(payload, signature, deps.joyidVerifier ?? productionJoyidVerifier());
  await throttle(store, requestId, `principal:${payload.principal_type}:${payload.principal_id}`, "namespace_claim", 12, 24 * 60 * 60, now);
  const existing = await store.getNamespace(namespace);
  if (
    existing
    && (existing.owner_principal_type !== payload.principal_type || existing.owner_principal_id !== payload.principal_id)
  ) {
    throw new ApiError(409, "namespace_already_claimed", "namespace is already claimed by another principal");
  }
  if (existing) {
    return json(
      {
        request_id: requestId,
        namespace: existing.namespace,
        status: existing.status,
        ...(existing.review_reason ? { review_reason: existing.review_reason } : {}),
      },
      existing.status === "active" ? 201 : 202,
      headers,
    );
  }
  await enforceNamespaceClaimCooldown(store, requestId, payload.principal_type, payload.principal_id, now, namespaceClaimCooldownSeconds(env));
  const claim = await store.claimNamespace({
    namespace,
    principal_type: payload.principal_type,
    principal_id: payload.principal_id,
    request_id: requestId,
  });
  return json({ request_id: requestId, ...claim }, claim.status === "active" ? 201 : 202, headers);
}

async function handleCapabilityCheck(
  request: Request,
  store: RegistryStore,
  requestId: string,
  now: Date,
  headers: Headers,
  keyIdFromPath: string,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "capability_check", 240, 60, now);
  const keyId = keyIdFromPath.trim().toLowerCase();
  if (!/^cap_[0-9a-f]{32}$/.test(keyId)) {
    throw new ApiError(400, "invalid_capability_key_id", "capability key ID must use the canonical cap_<32 lowercase hex> form");
  }
  const url = new URL(request.url);
  const namespace = validatePackageIdent(url.searchParams.get("namespace") ?? "", "namespace");
  const name = validatePackageIdent(url.searchParams.get("name") ?? "", "name");
  const capability = await store.getCapability(keyId);
  if (!capability) {
    throw new ApiError(404, "capability_not_found", "capability key is not known to the registry");
  }

  const namespaceRecord = await store.getNamespace(namespace);
  const revoked = Boolean(capability.revoked_at);
  const expiry = new Date(capability.expires_at).getTime();
  const invalidExpiry = !Number.isFinite(expiry);
  const expired = invalidExpiry || expiry <= now.getTime();
  const active = !revoked && !expired;
  const ownsNamespace = Boolean(
    namespaceRecord
    && namespaceRecord.owner_principal_type === capability.principal_type
    && namespaceRecord.owner_principal_id === capability.principal_id,
  );
  const namespaceActive = namespaceRecord?.status === "active";
  const allows = {
    publish: scopeAllows(capability.scopes, "publish", namespace, name),
    deployment: scopeAllows(capability.scopes, "deployment", namespace, name),
    availability: scopeAllows(capability.scopes, "availability", namespace, name),
  };
  const reasons = [];
  if (revoked) reasons.push("capability_revoked");
  else if (invalidExpiry) reasons.push("capability_expiry_invalid");
  else if (expired) reasons.push("capability_expired");
  if (!allows.publish) reasons.push("publish_scope_missing");
  if (!namespaceRecord) reasons.push("namespace_not_claimed");
  else {
    if (!namespaceActive) reasons.push("namespace_not_active");
    if (!ownsNamespace) reasons.push("namespace_owner_mismatch");
  }

  return json(
    {
      schema: "cellscript-registry-capability-check-v1",
      request_id: requestId,
      key_id: capability.key_id,
      principal_type: capability.principal_type,
      scopes: capability.scopes,
      expires_at: capability.expires_at,
      status: revoked ? "revoked" : expired ? "expired" : "active",
      namespace: {
        name: namespace,
        status: namespaceRecord?.status ?? "unclaimed",
        owned_by_capability_principal: ownsNamespace,
      },
      artifact: { namespace, name },
      allows,
      usable_for_publish: active && allows.publish && namespaceActive && ownsNamespace,
      reasons,
    },
    200,
    headers,
  );
}

async function handleRevokeCapability(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  now: Date,
  deps: AppDeps,
  headers: Headers,
  keyIdFromPath: string,
): Promise<Response> {
  await throttleRequestSource(store, request, requestId, "capability_revoke", 60, 60 * 60, now);
  const body = await readJson(request, maxJsonBytes(env));
  const payload = validateCapabilityRevocationPayload(body["payload"], registryOrigin, now);
  if (payload.capability_key_id !== keyIdFromPath) {
    throw new ApiError(400, "route_payload_mismatch", "capability route and revocation payload do not match");
  }
  const capability = await store.getCapability(payload.capability_key_id);
  if (!capability) {
    throw new ApiError(404, "capability_not_found", "capability key is not known to the registry");
  }
  if (capability.principal_type !== payload.principal_type || capability.principal_id !== payload.principal_id) {
    throw new ApiError(403, "capability_owner_mismatch", "wallet principal does not own this capability");
  }
  const signature = requirePrincipalSignature(body, payload.principal_type);
  await verifyPrincipalPayloadSignature(payload, signature, deps.joyidVerifier ?? productionJoyidVerifier());
  await throttle(store, requestId, `principal:${payload.principal_type}:${payload.principal_id}`, "capability_revoke", 8, 60 * 60, now);
  const nonceKey = await consumeSignedNonce(store, requestId, {
    protocol: payload.protocol,
    action: payload.action,
    nonce: payload.nonce,
    expires_at: payload.expires_at,
    principal_type: payload.principal_type,
    principal_id: payload.principal_id,
    capability_key_id: capability.key_id,
  });
  const reason = typeof body["reason"] === "string" ? body["reason"] : undefined;
  let revoked;
  try {
    revoked = await store.revokeCapability({
      key_id: capability.key_id,
      principal_type: payload.principal_type,
      principal_id: payload.principal_id,
      request_id: requestId,
      ...(reason ? { reason } : {}),
    });
  } catch (error) {
    await store.releaseNonce({ nonce_key: nonceKey, request_id: requestId });
    throw error;
  }
  return json(
    {
      request_id: requestId,
      key_id: revoked.key_id,
      principal_type: revoked.principal_type,
      principal_id: revoked.principal_id,
      revoked_at: revoked.revoked_at,
      status: "revoked",
    },
    200,
    headers,
  );
}

async function handlePublishVersion(
  request: Request,
  env: Env,
  store: RegistryStore,
  requestId: string,
  registryOrigin: string,
  staticOrigin: string,
  now: Date,
  deps: AppDeps,
  headers: Headers,
  namespaceFromPath: string,
  nameFromPath: string,
): Promise<Response> {
  const runtime = registryRuntimeConfig(env);
  await throttleRequestSource(store, request, requestId, "publish", 80, 60 * 60, now);
  const body = await readJson(request, maxJsonBytes(env));
  const payload = validatePublishPayload(body["payload"], registryOrigin, now);
  if (payload.namespace !== validatePackageIdent(namespaceFromPath, "namespace") || payload.name !== validatePackageIdent(nameFromPath, "name")) {
    throw new ApiError(400, "route_payload_mismatch", "package route and publish payload do not match");
  }
  const signature = requireCapabilitySignature(body["capability_signature"]);
  const snapshot = validateSnapshot(body["source_snapshot"], payload, maxSnapshotBytes(env));
  const requestHash = await publishRequestHash(payload, signature, snapshot);
  const idempotencyKey = requestIdempotencyKey(request, "publish");
  if (idempotencyKey) {
    const replay = await idempotencyReplayResponse(store, idempotencyKey, requestHash, headers);
    if (replay) {
      return replay;
    }
  }
  const capability = await store.getCapability(payload.capability_key_id);
  if (!capability) {
    throw new ApiError(401, "capability_not_found", "capability key is not known to the registry");
  }
  if (capability.revoked_at) {
    throw new ApiError(401, "capability_revoked", "capability key is revoked");
  }
  if (new Date(capability.expires_at).getTime() <= now.getTime()) {
    throw new ApiError(401, "capability_expired", "capability key has expired");
  }
  if (!scopeAllows(capability.scopes, "publish", payload.namespace, payload.name)) {
    throw new ApiError(403, "capability_scope_denied", "capability scope does not allow this artifact publish");
  }
  const namespace = await store.getNamespace(payload.namespace);
  if (!namespace) {
    throw new ApiError(409, "namespace_not_claimed", "namespace must be claimed before publishing");
  }
  if (namespace.status !== "active") {
    throw new ApiError(409, "namespace_not_active", "namespace is not active");
  }
  if (namespace.owner_principal_id !== capability.principal_id || namespace.owner_principal_type !== capability.principal_type) {
    throw new ApiError(403, "namespace_owner_mismatch", "capability principal does not own this namespace");
  }

  const canonicalPayload = canonicalJson(payload);
  const verifier = deps.capabilityVerifier ?? new WebCryptoP256Verifier();
  if (!(await verifier.verify(canonicalPayload, capability.capability_pubkey, signature))) {
    throw new ApiError(401, "capability_signature_invalid", "capability signature verification failed");
  }
  await throttle(store, requestId, `capability:${capability.key_id}`, "publish", 60, 60 * 60, now);
  await throttle(store, requestId, `artifact:${payload.namespace}/${payload.name}`, "publish", 12, 60 * 60, now);
  if (runtime.environment === "testnet-sandbox") {
    await throttle(store, requestId, `sandbox-principal:${capability.principal_type}:${capability.principal_id}`, "sandbox_publish", 20, 24 * 60 * 60, now);
    await throttle(store, requestId, `sandbox-artifact:${payload.namespace}/${payload.name}`, "sandbox_publish", 5, 24 * 60 * 60, now);
  }
  if (await store.getPackageVersion(payload.namespace, payload.name, payload.version)) {
    throw new ApiError(409, "artifact_release_exists", "artifact release already exists and cannot be overwritten");
  }
  if (payload.artifact.profile === "cellscript_source") {
    const candidateInterface = payload.registry_entry.versions[0].interface;
    const previousVersions: PackageVersionRecord[] = [];
    for (let offset = 0; ; offset += 200) {
      const page = await store.listPackageVersions({
        namespace: payload.namespace,
        name: payload.name,
        limit: 200,
        offset,
      });
      previousVersions.push(...page);
      if (page.length < 200) break;
    }
    const predecessorVersion = interfacePredecessorVersion(previousVersions.map((version) => version.version), payload.version);
    const previousBound = previousVersions.find((version) => {
      const release = version.registry_entry.versions.find((entry) => entry.version === version.version);
      return version.version === predecessorVersion && release?.interface !== undefined;
    });
    if (predecessorVersion && !previousBound) {
      throw new ApiError(
        409,
        "missing_predecessor_interface",
        `cannot admit ${payload.version}: predecessor ${predecessorVersion} has no canonical interface`,
      );
    }
    if (previousBound) {
      const previousRelease = previousBound.registry_entry.versions.find((entry) => entry.version === previousBound.version);
      validateInterfaceUpgrade(previousRelease?.interface, candidateInterface);
    }
  }
  let idempotencyReserved = false;
  if (idempotencyKey) {
    const reservation = await store.reserveIdempotencyKey({
      key: idempotencyKey,
      request_hash: requestHash,
      request_id: requestId,
      expires_at: payload.expires_at,
    });
    if (reservation.state === "conflict") {
      throw new ApiError(409, "idempotency_key_conflict", "Idempotency-Key was already used for a different request");
    }
    if (reservation.state === "in_progress") {
      throw new ApiError(409, "idempotency_request_in_progress", "matching idempotent request is still being processed");
    }
    if (reservation.state === "completed") {
      return idempotencyResponse(reservation.record, headers);
    }
    idempotencyReserved = true;
  }

  let consumedNonceKey: string | undefined;
  try {
    consumedNonceKey = await consumeSignedNonce(store, requestId, {
      protocol: payload.protocol,
      action: payload.action,
      nonce: payload.nonce,
      expires_at: payload.expires_at,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      capability_key_id: capability.key_id,
    });

    const snapshotRecord = await writeSnapshot(env, deps, payload.namespace, payload.name, payload.version, snapshot);
    const sourceRepo = typeof payload.registry_entry["repository"] === "string" ? payload.registry_entry["repository"] : undefined;
    const packageInput = {
      namespace: payload.namespace,
      name: payload.name,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      ...(sourceRepo ? { source_repo: sourceRepo } : {}),
      request_id: requestId,
    };
    const directUrl = staticPackageVersionUrl(staticOrigin, payload.namespace, payload.name, payload.version);
    const publishedRegistryVersion = payload.registry_entry.versions[0];
    const states = initialArtifactStates(payload.artifact);
    const expiresAt = runtime.record_ttl_hours === null
      ? null
      : new Date(now.getTime() + runtime.record_ttl_hours * 60 * 60 * 1000).toISOString();
    const purgeAfter = expiresAt === null || runtime.object_purge_grace_hours === null
      ? null
      : new Date(Date.parse(expiresAt) + runtime.object_purge_grace_hours * 60 * 60 * 1000).toISOString();
    const versionInput = {
      namespace: payload.namespace,
      name: payload.name,
      version: payload.version,
      status: "source_published",
      artifact: payload.artifact,
      ...states,
      source_hash: payload.source_hash,
      manifest_hash: payload.manifest_hash,
      ...(publishedRegistryVersion.edition ? { edition: publishedRegistryVersion.edition } : {}),
      ...(publishedRegistryVersion.compatibility_profile_hash
        ? { compatibility_profile_hash: publishedRegistryVersion.compatibility_profile_hash }
        : {}),
      capability_key_id: capability.key_id,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      registry_entry: payload.registry_entry,
      snapshot_hash: snapshotRecord.snapshot_hash,
      direct_url: directUrl,
      created_at: now.toISOString(),
      registry_environment: runtime.environment,
      network: runtime.network,
      expires_at: expiresAt,
      purge_after: purgeAfter,
    } as const;
    const capabilityUsage = {
      key_id: capability.key_id,
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      request_id: requestId,
      action: "publish",
      namespace: payload.namespace,
      name: payload.name,
      version: payload.version,
    };
    const ipHash = await requestIpHash(request);
    const userAgent = request.headers.get("user-agent") ?? undefined;
    const auditEvent = {
      request_id: requestId,
      event_type: "publish.accepted",
      principal_type: capability.principal_type,
      principal_id: capability.principal_id,
      capability_key_id: capability.key_id,
      namespace: payload.namespace,
      name: payload.name,
      version: payload.version,
      ...(ipHash ? { ip_hash: ipHash } : {}),
      ...(userAgent ? { user_agent: userAgent } : {}),
      data: { artifact: payload.artifact, ...states, snapshot_hash: snapshotRecord.snapshot_hash, direct_url: directUrl },
    };
    const responseBody = {
      request_id: requestId,
      artifact: payload.artifact,
      ...states,
      direct_url: directUrl,
      snapshot_hash: snapshotRecord.snapshot_hash,
      verification: "queued",
      registry_environment: runtime.environment,
      network: runtime.network,
      expires_at: expiresAt,
      purge_after: purgeAfter,
    };
    await store.admitPackageVersion({
      package: packageInput,
      snapshot: snapshotRecord,
      version: versionInput,
      capability_usage: capabilityUsage,
      audit_event: auditEvent,
      ...(idempotencyKey
        ? {
            idempotency: {
              key: idempotencyKey,
              request_hash: requestHash,
              response_status: 202,
              response_body: responseBody,
            },
          }
        : {}),
    });
    await tryWriteStaticRegistryVersionObject(
      env,
      deps,
      store,
      requestId,
      versionInput,
      snapshotRecord,
      staticOrigin,
    );
    return json(responseBody, 202, headers);
  } catch (error) {
    if (consumedNonceKey) {
      await store.releaseNonce({ nonce_key: consumedNonceKey, request_id: requestId });
    }
    if (idempotencyKey && idempotencyReserved) {
      await store.releaseProcessingIdempotencyKey({ key: idempotencyKey, request_hash: requestHash });
    }
    throw error;
  }
}

async function publishRequestHash(payload: unknown, signature: CapabilitySignature, snapshot: SourceSnapshotInput): Promise<string> {
  return sha256Hex(canonicalJson({
    route: "publish_artifact_release",
    payload,
    capability_signature: signature,
    source_snapshot: snapshot,
  }));
}

function requestIdempotencyKey(request: Request, scope: string): string | undefined {
  const raw = request.headers.get("idempotency-key")?.trim();
  if (!raw) {
    return undefined;
  }
  if (raw.length < 16 || raw.length > 160 || !/^[A-Za-z0-9._:-]+$/.test(raw)) {
    throw new ApiError(400, "invalid_idempotency_key", "Idempotency-Key must be 16..160 visible token characters");
  }
  return `${scope}:${raw}`;
}

async function idempotencyReplayResponse(
  store: RegistryStore,
  idempotencyKey: string,
  requestHash: string,
  headers: Headers,
): Promise<Response | undefined> {
  const record = await store.getIdempotencyKey(idempotencyKey);
  if (!record) {
    return undefined;
  }
  if (record.request_hash !== requestHash) {
    throw new ApiError(409, "idempotency_key_conflict", "Idempotency-Key was already used for a different request");
  }
  if (record.status !== "completed") {
    throw new ApiError(409, "idempotency_request_in_progress", "matching idempotent request is still being processed");
  }
  return idempotencyResponse(record, headers);
}

function idempotencyResponse(record: IdempotencyRecord, headers: Headers): Response {
  if (record.response_status === undefined || !record.response_body) {
    throw new ApiError(500, "idempotency_response_incomplete", "stored idempotency response is incomplete");
  }
  const replayHeaders = new Headers(headers);
  replayHeaders.set("x-idempotency-status", "replayed");
  return json(record.response_body, record.response_status, replayHeaders);
}

type SignedNonceUseSource = {
  protocol: string;
  action: string;
  nonce: string;
  expires_at: string;
  principal_type?: PrincipalType;
  principal_id?: string;
  capability_key_id?: string;
};

async function signedNonceUse(requestId: string, input: SignedNonceUseSource) {
  const nonceKey = `nonce_${await sha256Hex(canonicalJson({
    protocol: input.protocol,
    action: input.action,
    nonce: input.nonce,
    principal_type: input.principal_type ?? null,
    principal_id: input.principal_id ?? null,
    capability_key_id: input.capability_key_id ?? null,
  }))}`;
  return {
    nonce_key: nonceKey,
    protocol: input.protocol,
    action: input.action,
    nonce: input.nonce,
    request_id: requestId,
    expires_at: input.expires_at,
    ...(input.principal_type ? { principal_type: input.principal_type } : {}),
    ...(input.principal_id ? { principal_id: input.principal_id } : {}),
    ...(input.capability_key_id ? { capability_key_id: input.capability_key_id } : {}),
  };
}

async function consumeSignedNonce(
  store: RegistryStore,
  requestId: string,
  input: SignedNonceUseSource,
): Promise<string> {
  const nonceUse = await signedNonceUse(requestId, input);
  const accepted = await store.consumeNonce(nonceUse);
  if (!accepted) {
    await store.appendAuditEvent({
      request_id: requestId,
      event_type: "nonce.replay_blocked",
      ...(input.principal_type ? { principal_type: input.principal_type } : {}),
      ...(input.principal_id ? { principal_id: input.principal_id } : {}),
      ...(input.capability_key_id ? { capability_key_id: input.capability_key_id } : {}),
      data: {
        protocol: input.protocol,
        action: input.action,
        nonce_key: nonceUse.nonce_key,
      },
    });
    throw new ApiError(409, "nonce_replay", "signed nonce has already been used");
  }
  return nonceUse.nonce_key;
}

async function writeStaticRegistryVersionObject(
  env: Env,
  deps: AppDeps,
  version: SnapshotPackageVersionRecord,
  snapshot: SnapshotRecord,
  staticOrigin: string,
  evidence: PackageEvidenceRecord[] = [],
): Promise<void> {
  const key = staticPackageVersionKey(version.namespace, version.name, version.version);
  const body = new TextEncoder().encode(`${JSON.stringify(staticRegistryVersionPayload(version, snapshot, staticOrigin, evidence), null, 2)}\n`);
  const writer = deps.snapshotWriter ?? r2SnapshotWriter(env);
  await writer.put(key, body, {
    contentType: "application/json; charset=utf-8",
    metadata: {
      namespace: version.namespace,
      name: version.name,
      version: version.version,
      status: version.status,
      source_hash: version.source_hash,
      snapshot_hash: version.snapshot_hash,
    },
  });
}

async function tryWriteStaticRegistryVersionObject(
  env: Env,
  deps: AppDeps,
  store: RegistryStore,
  requestId: string,
  version: SnapshotPackageVersionRecord,
  snapshot: SnapshotRecord,
  staticOrigin: string,
  evidence: PackageEvidenceRecord[] = [],
): Promise<void> {
  try {
    await writeStaticRegistryVersionObject(env, deps, version, snapshot, staticOrigin, evidence);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    await store.requestStaticSync({
      namespace: version.namespace,
      name: version.name,
      version: version.version,
      error_message: errorMessage,
    }).catch(() => undefined);
    await store.appendAuditEvent({
      request_id: requestId,
      event_type: "static_registry.sync_deferred",
      principal_type: version.principal_type,
      principal_id: version.principal_id,
      capability_key_id: version.capability_key_id,
      namespace: version.namespace,
      name: version.name,
      version: version.version,
      data: { error: errorMessage },
    }).catch(() => undefined);
  }
}

export async function syncStaticRegistryVersionObject(
  env: Env,
  deps: Pick<AppDeps, "snapshotWriter">,
  store: RegistryStore,
  version: PackageVersionRecord,
  staticOrigin: string,
): Promise<void> {
  const snapshot = await requireSnapshot(store, version);
  const evidence = await store.listPackageEvidence(version.namespace, version.name, version.version);
  await writeStaticRegistryVersionObject(
    env,
    deps,
    { ...version, direct_url: staticPackageVersionUrl(staticOrigin, version.namespace, version.name, version.version) },
    snapshot,
    staticOrigin,
    evidence,
  );
}

type SnapshotPackageVersionRecord = Awaited<ReturnType<RegistryStore["recordPackageVersion"]>>;

function staticRegistryVersionPayload(
  version: SnapshotPackageVersionRecord,
  snapshot: SnapshotRecord,
  staticOrigin: string,
  evidence: PackageEvidenceRecord[] = [],
): Record<string, unknown> {
  const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
  if (!signedRelease) {
    throw new ApiError(500, "registry_release_identity_missing", "signed Registry release identity is missing");
  }
  return {
    schema_version: REGISTRY_SCHEMA_VERSION,
    kind: "cellscript.registry.artifact_release",
    coordinate: `${version.namespace}/${version.name}@${version.version}`,
    namespace: version.namespace,
    name: version.name,
    release: version.version,
    artifact: version.artifact,
    verification_status: version.verification_status,
    deployment_status: version.deployment_status,
    availability_status: version.availability_status,
    source_hash: version.source_hash,
    manifest_hash: version.manifest_hash,
    ...(signedRelease.artifact_hash ? { artifact_hash: signedRelease.artifact_hash } : {}),
    ...(signedRelease.abi_hash ? { abi_hash: signedRelease.abi_hash } : {}),
    ...(signedRelease.build_recipe_hash ? { build_recipe_hash: signedRelease.build_recipe_hash } : {}),
    ...(signedRelease.profile_contract ? { profile_contract: signedRelease.profile_contract } : {}),
    ...(releaseLsIdlInterface(version) ? { interface: releaseLsIdlInterface(version) } : {}),
    ...(version.edition ? { edition: version.edition } : {}),
    ...(version.compatibility_profile_hash ? { compatibility_profile_hash: version.compatibility_profile_hash } : {}),
    capability_key_id: version.capability_key_id,
    principal_type: version.principal_type,
    principal_id: version.principal_id,
    registry_entry: version.registry_entry,
    snapshot_hash: version.snapshot_hash,
    immutable_bundle: sourceSnapshotPayload(snapshot, staticOrigin),
    direct_url: version.direct_url,
    created_at: version.created_at,
    registry_environment: version.registry_environment ?? "production",
    network: version.network ?? "mainnet",
    ...(version.expires_at ? { expires_at: version.expires_at } : {}),
    ...(version.purge_after ? { purge_after: version.purge_after } : {}),
    evidence,
  };
}

function releaseLsIdlInterface(version: PackageVersionRecord): Record<string, unknown> | null {
  const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
  const interfaceContract = signedRelease?.profile_contract?.["interface"];
  if (!interfaceContract || typeof interfaceContract !== "object" || Array.isArray(interfaceContract)) return null;
  const value = interfaceContract as Record<string, unknown>;
  if (value["format"] !== "ls-idl") return null;
  return {
    schema: value["schema"],
    format: "ls-idl",
    format_version: value["format_version"],
    content_type: value["content_type"],
    encoding: value["encoding"],
    commitment: value["commitment"],
  };
}

async function requireSnapshot(store: RegistryStore, version: SnapshotPackageVersionRecord): Promise<SnapshotRecord> {
  const snapshot = await store.getSnapshot(version.snapshot_hash);
  if (!snapshot || snapshot.source_hash !== version.source_hash) {
    throw new ApiError(503, "source_snapshot_unavailable", "package source snapshot metadata is unavailable or inconsistent");
  }
  return snapshot;
}

async function requireSnapshots(
  store: RegistryStore,
  versions: SnapshotPackageVersionRecord[],
): Promise<Map<string, SnapshotRecord>> {
  const snapshots = await store.getSnapshots(versions.map((version) => version.snapshot_hash));
  for (const version of versions) snapshotForVersion(snapshots, version);
  return snapshots;
}

function snapshotForVersion(
  snapshots: Map<string, SnapshotRecord>,
  version: SnapshotPackageVersionRecord,
): SnapshotRecord {
  const snapshot = snapshots.get(version.snapshot_hash);
  if (!snapshot || snapshot.source_hash !== version.source_hash) {
    throw new ApiError(503, "source_snapshot_unavailable", "package source snapshot metadata is unavailable or inconsistent");
  }
  return snapshot;
}

function sourceSnapshotPayload(snapshot: SnapshotRecord, staticOrigin: string): Record<string, unknown> {
  return {
    schema: "cellscript-registry-immutable-bundle",
    url: `${staticOrigin.replace(/\/+$/, "")}/${snapshot.r2_key}`,
    snapshot_hash: snapshot.snapshot_hash,
    source_hash: snapshot.source_hash,
    size_bytes: snapshot.size_bytes,
    content_type: snapshot.content_type,
  };
}

function staticPackageVersionKey(namespace: string, name: string, version: string): string {
  return `artifacts/${namespace}/${name}/releases/${version}.json`;
}

function staticPackageVersionUrl(staticOrigin: string, namespace: string, name: string, version: string): string {
  return `${staticOrigin.replace(/\/+$/, "")}/artifacts/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/releases/${encodeURIComponent(version)}.json`;
}

async function writeSnapshot(
  env: Env,
  deps: AppDeps,
  namespace: string,
  name: string,
  version: string,
  snapshot: SourceSnapshotInput,
): Promise<SnapshotRecord> {
  const bytes = base64ToBytes(snapshot.content_base64);
  if (bytes.byteLength !== snapshot.size_bytes) {
    throw new ApiError(400, "snapshot_size_mismatch", "snapshot size_bytes does not match decoded content");
  }
  const snapshotHash = `sha256:${await sha256Hex(bytes)}`;
  const extension = snapshotExtension(snapshot.content_type);
  const r2Key = `source-snapshots/${namespace}/${name}/${version}/${snapshotHash.slice("sha256:".length)}.${extension}`;
  const writer = deps.snapshotWriter ?? r2SnapshotWriter(env);
  await writer.put(r2Key, bytes, {
    contentType: snapshot.content_type,
    metadata: { source_hash: snapshot.source_hash, snapshot_hash: snapshotHash },
  });
  return {
    snapshot_hash: snapshotHash,
    r2_key: r2Key,
    source_hash: snapshot.source_hash,
    size_bytes: snapshot.size_bytes,
    content_type: snapshot.content_type,
  };
}

function snapshotExtension(contentType: string): "json" | "tar" | "tar.gz" | "bin" {
  if (contentType.includes("json")) {
    return "json";
  }
  if (contentType.includes("gzip")) {
    return "tar.gz";
  }
  if (contentType.includes("tar")) {
    return "tar";
  }
  return "bin";
}

function r2SnapshotWriter(env: Env): SnapshotWriter {
  const bucket = env.REGISTRY_OBJECTS ?? env.SOURCE_SNAPSHOTS;
  if (!bucket) {
    throw new ApiError(503, "registry_object_store_unconfigured", "REGISTRY_OBJECTS R2 binding is required for publish");
  }
  return {
    async put(key, body, options) {
      await bucket.put(key, body, {
        httpMetadata: { contentType: options.contentType },
        customMetadata: options.metadata,
      });
    },
    async delete(key) {
      await bucket.delete(key);
    },
  };
}

function r2RegistryObjectReader(env: Env): RegistryObjectReader {
  const bucket = env.REGISTRY_OBJECTS ?? env.SOURCE_SNAPSHOTS;
  if (!bucket) {
    throw new ApiError(503, "registry_object_store_unconfigured", "REGISTRY_OBJECTS R2 binding is required for registry reads");
  }
  return {
    async get(key) {
      const object = await bucket.get(key);
      if (!object) {
        return null;
      }
      const read: RegistryObjectRead = {
        body: object.body,
        etag: object.httpEtag,
      };
      if (object.httpMetadata?.contentType) {
        read.contentType = object.httpMetadata.contentType;
      }
      return read;
    },
  };
}

function productionJoyidVerifier(): JoyidVerifier {
  return {
    verifySignature(signature: SignChallengeResponseData) {
      return verifySignature(signature);
    },
  };
}

async function throttle(
  store: RegistryStore,
  requestId: string,
  quotaKey: string,
  bucket: string,
  limit: number,
  windowSeconds: number,
  now: Date,
): Promise<void> {
  const since = new Date(now.getTime() - windowSeconds * 1000).toISOString();
  const count = await store.countRecentQuotaEvents(quotaKey, bucket, since);
  if (count >= limit) {
    await store.appendAuditEvent({
      request_id: requestId,
      event_type: "rate_limit.blocked",
      data: { quota_key: quotaKey, bucket, limit, window_seconds: windowSeconds },
    });
    throw new ApiError(429, "rate_limited", "rate limit exceeded");
  }
  await store.recordQuotaEvent(quotaKey, bucket);
}

async function enforceNamespaceClaimCooldown(
  store: RegistryStore,
  requestId: string,
  principalType: string,
  principalId: string,
  now: Date,
  cooldownSeconds: number,
): Promise<void> {
  if (cooldownSeconds <= 0) {
    return;
  }
  const quotaKey = `principal:${principalType}:${principalId}`;
  const bucket = "namespace_claim_cooldown";
  const since = new Date(now.getTime() - cooldownSeconds * 1000).toISOString();
  const count = await store.countRecentQuotaEvents(quotaKey, bucket, since);
  if (count >= 1) {
    await store.appendAuditEvent({
      request_id: requestId,
      event_type: "namespace_claim.cooldown_blocked",
      principal_type: principalType,
      principal_id: principalId,
      data: { cooldown_seconds: cooldownSeconds },
    });
    throw new ApiError(429, "namespace_claim_cooldown", "namespace claim cooldown is active");
  }
  await store.recordQuotaEvent(quotaKey, bucket);
}

async function appendFailureAuditEvent(
  request: Request,
  env: Env,
  requestId: string,
  deps: AppDeps,
  error: unknown,
): Promise<void> {
  const status = error instanceof ApiError ? error.status : 500;
  const code = error instanceof ApiError ? error.code : "internal_error";
  const eventType = status === 401 || status === 403 ? "auth.failure" : "request.failed";
  const store = optionalStore(env, deps);
  if (!store) {
    return;
  }
  try {
    const url = new URL(request.url);
    const ipHash = await requestIpHash(request);
    const userAgent = request.headers.get("user-agent") ?? undefined;
    await store.appendAuditEvent({
      request_id: requestId,
      event_type: eventType,
      ...(ipHash ? { ip_hash: ipHash } : {}),
      ...(userAgent ? { user_agent: userAgent } : {}),
      data: {
        method: request.method,
        path: url.pathname,
        status,
        code,
      },
    });
  } catch {
    // Failure audit is best effort and must not replace the original response.
  }
}

async function throttleRequestSource(
  store: RegistryStore,
  request: Request,
  requestId: string,
  bucket: string,
  ipLimit: number,
  windowSeconds: number,
  now: Date,
): Promise<void> {
  const ipHash = await requestIpHash(request);
  if (ipHash) {
    await throttle(store, requestId, `ip:${ipHash}`, bucket, ipLimit, windowSeconds, now);
  }
  const asn = requestAsn(request);
  if (asn) {
    await throttle(store, requestId, `asn:${asn}`, bucket, ipLimit * 20, windowSeconds, now);
  }
}

async function readJson(request: Request, maxBytes: number): Promise<Record<string, unknown>> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > maxBytes) {
    throw new ApiError(413, "body_too_large", `JSON body exceeds ${maxBytes} bytes`);
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes) {
    throw new ApiError(413, "body_too_large", `JSON body exceeds ${maxBytes} bytes`);
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new ApiError(400, "invalid_json", "request body must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(400, "invalid_json", "request body is not valid JSON");
  }
}

function requirePrincipalSignature(body: Record<string, unknown>, principalType: PrincipalType): PrincipalSignature {
  const value = body["wallet_signature"] ?? body["joyid_signature"];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, "missing_wallet_signature", "wallet_signature is required");
  }
  if (principalType === JOYID_PRINCIPAL_TYPE) {
    return value as SignChallengeResponseData;
  }
  if (principalType !== CKB_SECP256K1_PRINCIPAL_TYPE) {
    throw new ApiError(400, "unsupported_principal_type", "wallet principal type is unsupported");
  }
  const signature = value as Record<string, unknown>;
  if (
    signature["scheme"] !== CKB_SECP256K1_PRINCIPAL_TYPE
    || typeof signature["challenge"] !== "string"
    || typeof signature["signature"] !== "string"
    || typeof signature["public_key"] !== "string"
  ) {
    throw new ApiError(
      400,
      "invalid_wallet_signature",
      "ckb_secp256k1 wallet_signature must include scheme, challenge, signature, and public_key",
    );
  }
  return signature as unknown as CkbSecp256k1Signature;
}

function requireCapabilitySignature(value: unknown): CapabilitySignature {
  if (!value || typeof value !== "object") {
    throw new ApiError(400, "missing_capability_signature", "capability_signature is required");
  }
  const algorithm = (value as Record<string, unknown>)["algorithm"];
  const signature = (value as Record<string, unknown>)["signature"];
  if (algorithm !== "p256-sha256" || typeof signature !== "string" || signature.trim() === "") {
    throw new ApiError(400, "invalid_capability_signature", "capability_signature must use p256-sha256");
  }
  return { algorithm, signature };
}

async function requireAdminActor(request: Request, env: Env): Promise<string> {
  const expected = env.REGISTRY_ADMIN_TOKEN?.trim();
  if (!expected) {
    throw new ApiError(503, "admin_unconfigured", "REGISTRY_ADMIN_TOKEN must be configured for admin operations");
  }
  const auth = request.headers.get("authorization") ?? "";
  const bearer = auth.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  const supplied = bearer || request.headers.get("x-registry-admin-token")?.trim() || "";
  if (!(await constantTimeSecretEqual(supplied, expected))) {
    throw new ApiError(401, "admin_unauthorized", "admin token is missing or invalid");
  }
  const actor = request.headers.get("x-registry-admin-actor")?.trim();
  return actor && actor.length <= 128 ? actor : "registry-admin";
}

async function constantTimeSecretEqual(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftDigest, rightDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftDigest);
  const rightBytes = new Uint8Array(rightDigest);
  let mismatch = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    mismatch |= leftBytes[index]! ^ rightBytes[index]!;
  }
  return mismatch === 0;
}

function requireNonEmptyAdminString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ApiError(400, "invalid_admin_field", `${field} is required`);
  }
  return value.trim();
}

function requireUuid(value: string, field: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new ApiError(400, `invalid_${field}`, `${field} must be a UUID`);
  }
  return value.toLowerCase();
}

function requireOneOf<const T extends readonly string[]>(value: string, allowed: T, code: string): T[number] {
  if (!allowed.includes(value)) {
    throw new ApiError(400, code, `value must be one of: ${allowed.join(", ")}`);
  }
  return value as T[number];
}

function optionalAuditParam(params: URLSearchParams, key: string): string | undefined {
  const value = params.get(key)?.trim();
  if (!value) {
    return undefined;
  }
  if (value.length > 256) {
    throw new ApiError(400, "invalid_audit_filter", `${key} filter is too long`);
  }
  return value;
}

function auditLimit(params: URLSearchParams): number {
  const raw = params.get("limit")?.trim();
  if (!raw) {
    return 50;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 200) {
    throw new ApiError(400, "invalid_audit_limit", "audit limit must be an integer from 1 to 200");
  }
  return value;
}

function parseAuditBefore(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new ApiError(400, "invalid_audit_before", "before must be an ISO timestamp");
  }
  return date.toISOString();
}

function optionalPublicQuery(params: URLSearchParams, name: string): string | undefined {
  const value = params.get(name)?.trim();
  if (!value) return undefined;
  if (value.length > 160 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ApiError(400, "invalid_public_query", `${name} query parameter is invalid`);
  }
  return value;
}

function publicListInteger(params: URLSearchParams, name: string, fallback: number, minimum: number, maximum: number): number {
  const value = params.get(name);
  if (value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ApiError(400, "invalid_public_query", `${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

export function validatePromotionEvidence(
  value: unknown,
  kind: PackageEvidenceKind,
  version: PackageVersionRecord,
  previous: PackageEvidenceRecord[],
  expectedNetwork: DeploymentPayload["network"] = "mainnet",
): Record<string, unknown> {
  const evidence = assertPlainObject(value, "invalid_promotion_evidence");
  if (evidence["schema"] !== "cellscript-registry-evidence") {
    throw new ApiError(400, "invalid_evidence_schema", "evidence.schema must be cellscript-registry-evidence");
  }
  if (evidence["kind"] !== kind) {
    throw new ApiError(400, "evidence_kind_mismatch", "evidence.kind must match the requested promotion kind");
  }
  requireEvidenceString(evidence, "producer", 1, 200);
  requireEvidenceTimestamp(evidence, "generated_at");
  if (evidence["verification_status"] !== "passed") {
    throw new ApiError(400, "evidence_not_passed", "evidence.verification_status must be passed");
  }
  requireMatchingEvidenceHash(evidence, "source_hash", version.source_hash);
  requireMatchingEvidenceHash(evidence, "manifest_hash", version.manifest_hash);
  if (version.compatibility_profile_hash) {
    requireMatchingEvidenceHash(evidence, "compatibility_profile_hash", version.compatibility_profile_hash);
  }

  if (kind === "verified_build") {
    const level = requireEvidenceString(evidence, "verification_level", 1, 80);
    if (!(["compiled", "hash_bound", "evidence_required", "structurally_verified"] as const).includes(level as any)) {
      throw new ApiError(400, "invalid_verification_level", "verification_level is not recognised");
    }
    if (version.artifact.profile !== "copy_material") {
      const artifactHash = requireEvidenceHash(evidence, "artifact_hash");
      const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
      if (signedRelease?.artifact_hash && !sameHash(artifactHash, signedRelease.artifact_hash)) {
        throw new ApiError(400, "verified_artifact_mismatch", "verified-build artifact_hash must match the signed Registry release");
      }
    }
    requireEvidenceHash(evidence, "metadata_hash");
    if (version.artifact.profile === "cellscript_source") requireEvidenceString(evidence, "compiler_version", 1, 80);
    if (level === "structurally_verified") {
      requireEvidenceString(evidence, "checker_version", 1, 80);
      requireEvidenceString(evidence, "checker_policy_schema", 1, 120);
      requireEvidenceHash(evidence, "checker_report_hash");
    }
    const protocolBundleFields = [
      evidence["protocol_bundle_schema"],
      evidence["protocol_bundle_artifact_binding_schema"],
      evidence["protocol_bundle_runtime_adapter"],
    ];
    if (protocolBundleFields.some((field) => field !== undefined)) {
      if (level !== "structurally_verified"
        || version.artifact.profile !== "ckb_executable"
        || evidence["artifact_format"] !== "ckb-vm-executable") {
        throw new ApiError(
          400,
          "protocol_bundle_evidence_insufficient",
          "ProtocolBundle discovery requires a structurally verified CKB ELF bundle with complete sidecars",
        );
      }
      if (protocolBundleFields[0] !== "cellscript-protocol-bundle-v1"
        || protocolBundleFields[1] !== "cellscript-protocol-bundle-artifact-binding-v1"
        || protocolBundleFields[2] !== "cellscript-ckb-adapter") {
        throw new ApiError(
          400,
          "protocol_bundle_contract_invalid",
          "ProtocolBundle discovery contract is incomplete or unrecognised",
        );
      }
    }
  } else if (kind === "reproduced_build") {
    const verified = latestEvidence(previous, "verified_build");
    requireEvidenceReference(evidence, "verified_build_evidence_hash", verified);
    if (!packageVersionRequiresReproduction(version)) {
      throw new ApiError(409, "reproduction_not_applicable", "this artifact does not declare a reproducible build contract");
    }
    if (requireEvidenceString(evidence, "verification_level", 1, 80) !== "reproduced") {
      throw new ApiError(400, "invalid_verification_level", "reproduced-build evidence must use verification_level reproduced");
    }
    const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
    const expectedArtifactHash = signedRelease?.artifact_hash;
    const expectedRecipeHash = signedRelease?.build_recipe_hash;
    if (!expectedArtifactHash || !expectedRecipeHash) {
      throw new ApiError(500, "reproduction_contract_incomplete", "signed reproducible release is missing artifact or build-recipe identity");
    }
    requireMatchingEvidenceHash(evidence, "artifact_hash", expectedArtifactHash);
    requireMatchingEvidenceHash(evidence, "build_recipe_hash", expectedRecipeHash);
    const verifiedArtifactHash = requireEvidenceHash(verified.evidence, "artifact_hash");
    if (!sameHash(verifiedArtifactHash, expectedArtifactHash)) {
      throw new ApiError(409, "verified_artifact_mismatch", "accepted build evidence does not match the signed reproducible artifact");
    }
    validateReproductionReports(evidence, version, expectedArtifactHash, expectedRecipeHash);
  } else if (kind === "deployed") {
    const verified = latestBuildEvidence(previous, version);
    requireEvidenceReference(evidence, "verified_build_evidence_hash", verified);
    const artifactHash = requireEvidenceHash(evidence, "artifact_hash");
    const verifiedArtifact = requireEvidenceHash(verified.evidence, "artifact_hash");
    if (!sameHash(artifactHash, verifiedArtifact)) {
      throw new ApiError(400, "deployment_artifact_mismatch", "deployed artifact_hash must match verified-build evidence");
    }
    if (requireEvidenceString(evidence, "network", 1, 80) !== expectedNetwork) {
      throw new ApiError(400, "unsupported_deployment_network", `Registry deployment evidence must use ${expectedNetwork}`);
    }
    const codeHash = requireEvidenceHash(evidence, "code_hash");
    const dataHash = requireEvidenceHash(evidence, "data_hash");
    if (!sameHash(dataHash, artifactHash)) {
      throw new ApiError(400, "deployment_data_hash_mismatch", "deployed data_hash must match the verified executable artifact_hash");
    }
    const hashType = requireEvidenceString(evidence, "hash_type", 1, 16);
    if (!("data data1 data2 type".split(" ").includes(hashType))) {
      throw new ApiError(400, "invalid_deployment_hash_type", "evidence.hash_type is not recognised");
    }
    if (hashType !== "type" && !sameHash(codeHash, dataHash)) {
      throw new ApiError(400, "deployment_code_hash_mismatch", "data hash deployments must use the executable data hash as code_hash");
    }
    const depType = requireEvidenceString(evidence, "dep_type", 1, 16);
    if (!("code dep_group".split(" ").includes(depType))) {
      throw new ApiError(400, "invalid_deployment_dep_type", "evidence.dep_type is not recognised");
    }
    requireDeploymentProfileContract(version, hashType, depType);
    const outPoint = assertPlainObject(evidence["out_point"], "invalid_deployment_out_point");
    requireEvidenceHash(outPoint, "tx_hash");
    const index = outPoint["index"];
    if (!Number.isSafeInteger(index) || Number(index) < 0 || Number(index) > 0xffff_ffff) {
      throw new ApiError(400, "invalid_deployment_out_point", "evidence.out_point.index must be a non-negative u32 integer");
    }
    if (evidence["deployment_status"] !== "live") {
      throw new ApiError(400, "deployment_not_live", "evidence.deployment_status must be live");
    }
  } else {
    const deployed = latestEvidence(previous, "deployed");
    requireEvidenceReference(evidence, "deployed_evidence_hash", deployed);
    if (requireEvidenceString(evidence, "network", 1, 80) !== expectedNetwork) {
      throw new ApiError(400, "unsupported_commitment_network", `Registry commitments must use ${expectedNetwork}`);
    }
    requireEvidenceHash(evidence, "commitment_tx_hash");
    requireEvidenceHash(evidence, "commitment_hash");
    requireEvidenceHash(evidence, "commitment_lock_hash");
    requireEvidenceHash(evidence, "registry_type_hash");
    const outPoint = assertPlainObject(evidence["commitment_out_point"], "invalid_commitment_out_point");
    const txHash = requireEvidenceHash(outPoint, "tx_hash");
    if (!sameHash(txHash, requireEvidenceHash(evidence, "commitment_tx_hash"))) {
      throw new ApiError(400, "commitment_out_point_mismatch", "commitment_out_point.tx_hash must match commitment_tx_hash");
    }
    const outputIndex = outPoint["index"];
    if (!Number.isSafeInteger(outputIndex) || Number(outputIndex) < 0 || Number(outputIndex) > 0xffff_ffff) {
      throw new ApiError(400, "invalid_commitment_out_point", "commitment_out_point.index must be a non-negative u32 integer");
    }
    requireEvidenceTimestamp(evidence, "observed_at");
    if (evidence["commitment_status"] !== "confirmed") {
      throw new ApiError(400, "commitment_not_confirmed", "evidence.commitment_status must be confirmed");
    }
  }
  return evidence;
}

function requireDeploymentProfileContract(
  version: PackageVersionRecord,
  hashType: string,
  depType: string,
): void {
  const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
  const profileContract = signedRelease?.profile_contract;
  const ckb = profileContract && typeof profileContract === "object" && !Array.isArray(profileContract)
    ? (profileContract as Record<string, unknown>)["ckb"]
    : undefined;
  if (!ckb || typeof ckb !== "object" || Array.isArray(ckb)) {
    throw new ApiError(500, "deployment_profile_contract_missing", "signed executable release has no CKB deployment contract");
  }
  const contract = ckb as Record<string, unknown>;
  if (contract["hash_type"] !== hashType) {
    throw new ApiError(400, "deployment_hash_type_contract_mismatch", "deployment hash_type does not match the signed profile contract");
  }
  if (contract["dep_type"] !== depType) {
    throw new ApiError(400, "deployment_dep_type_contract_mismatch", "deployment dep_type does not match the signed profile contract");
  }
}

function latestEvidence(records: PackageEvidenceRecord[], kind: PackageEvidenceKind): PackageEvidenceRecord {
  const record = records.filter((item) => item.kind === kind).at(-1);
  if (!record) {
    throw new ApiError(409, "evidence_dependency_missing", `${kind} evidence must exist before this promotion`);
  }
  return record;
}

function latestBuildEvidence(records: PackageEvidenceRecord[], version: PackageVersionRecord): PackageEvidenceRecord {
  if (packageVersionRequiresReproduction(version)) return latestEvidence(records, "reproduced_build");
  return latestEvidence(records, "verified_build");
}

function validateReproductionReports(
  evidence: Record<string, unknown>,
  version: PackageVersionRecord,
  expectedArtifactHash: string,
  expectedRecipeHash: string,
): void {
  const minimum = evidence["minimum_reproducers"];
  if (!Number.isSafeInteger(minimum) || Number(minimum) < 2 || Number(minimum) > 16) {
    throw new ApiError(400, "invalid_reproducer_threshold", "minimum_reproducers must be an integer between 2 and 16");
  }
  const reports = evidence["reproducers"];
  if (!Array.isArray(reports) || reports.length < Number(minimum) || reports.length > 16) {
    throw new ApiError(400, "insufficient_reproduction_evidence", "reproducers must contain the declared number of independent reports (maximum 16)");
  }
  const signedRelease = version.registry_entry.versions.find((entry) => entry.version === version.version);
  const reproduction = signedRelease?.profile_contract?.["reproduction"];
  const expectedEnvironment = reproduction && typeof reproduction === "object" && !Array.isArray(reproduction)
    ? (reproduction as Record<string, unknown>)["environment"]
    : undefined;
  const builderIds = new Set<string>();
  for (const rawReport of reports) {
    const report = assertPlainObject(rawReport, "invalid_reproduction_report");
    if (report["schema"] !== "cellscript-reproduction-report-v2") {
      throw new ApiError(400, "invalid_reproduction_report", "each reproducer report must use schema cellscript-reproduction-report-v2");
    }
    const builderId = requireEvidenceString(report, "builder_id", 1, 200);
    if (builderIds.has(builderId)) {
      throw new ApiError(400, "duplicate_reproducer", "reproducer reports must use distinct builder_id values");
    }
    builderIds.add(builderId);
    requireEvidenceString(report, "trust_domain", 1, 200);
    const builderPublicKey = requireEvidenceString(report, "builder_public_key", 32, 2_000);
    if (!builderPublicKey.startsWith("p256-spki:")) {
      throw new ApiError(400, "invalid_reproducer_public_key", "reproducer builder_public_key must use p256-spki");
    }
    const environment = requireEvidenceString(report, "environment", 1, 500);
    if (typeof expectedEnvironment !== "string" || environment !== expectedEnvironment) {
      throw new ApiError(400, "reproduction_environment_mismatch", "reproducer environment must match the signed reproduction contract");
    }
    requireMatchingEvidenceHash(report, "source_hash", version.source_hash);
    requireMatchingEvidenceHash(report, "build_recipe_hash", expectedRecipeHash);
    requireMatchingEvidenceHash(report, "artifact_hash", expectedArtifactHash);
    requireEvidenceHash(report, "build_log_hash");
    requireEvidenceTimestamp(report, "generated_at");
    const signature = assertPlainObject(report["signature"], "invalid_reproduction_signature");
    if (signature["algorithm"] !== "p256-sha256") {
      throw new ApiError(400, "invalid_reproduction_signature", "reproducer signature.algorithm must be p256-sha256");
    }
    requireEvidenceString(signature, "signature", 32, 2_000);
  }
}

interface ReproducerPolicyBuilder {
  builder_id: string;
  trust_domain: string;
  public_key: string;
}

interface ReproducerPolicy {
  minimum_trust_domains: number;
  builders: Map<string, ReproducerPolicyBuilder>;
}

function registryReproducerPolicy(env: Env, required: boolean): ReproducerPolicy | null {
  const raw = env.REGISTRY_REPRODUCER_POLICY_JSON?.trim();
  if (!raw) {
    if (required) {
      throw new ApiError(503, "reproducer_policy_unconfigured", "signed reproduction evidence is disabled until a trusted builder policy is configured");
    }
    return null;
  }
  const value = parseConfiguredJson(raw, "REGISTRY_REPRODUCER_POLICY_JSON");
  if (value["schema"] !== "cellscript-reproducer-policy-v1") {
    throw new ApiError(503, "reproducer_policy_misconfigured", "reproducer policy schema must be cellscript-reproducer-policy-v1");
  }
  const minimum = value["minimum_trust_domains"];
  if (!Number.isSafeInteger(minimum) || Number(minimum) < 2 || Number(minimum) > 16) {
    throw new ApiError(503, "reproducer_policy_misconfigured", "minimum_trust_domains must be an integer between 2 and 16");
  }
  if (!Array.isArray(value["builders"]) || value["builders"].length < Number(minimum) || value["builders"].length > 64) {
    throw new ApiError(503, "reproducer_policy_misconfigured", "reproducer policy must contain enough trusted builders (maximum 64)");
  }
  const builders = new Map<string, ReproducerPolicyBuilder>();
  const publicKeys = new Set<string>();
  const trustDomains = new Set<string>();
  for (const rawBuilder of value["builders"]) {
    const builder = assertPlainObject(rawBuilder, "reproducer_policy_misconfigured");
    const builderId = requireEvidenceString(builder, "builder_id", 1, 200);
    const trustDomain = requireEvidenceString(builder, "trust_domain", 1, 200);
    const publicKey = requireEvidenceString(builder, "public_key", 32, 2_000);
    if (!isCanonicalP256SpkiPublicKey(publicKey) || builders.has(builderId) || publicKeys.has(publicKey)) {
      throw new ApiError(503, "reproducer_policy_misconfigured", "trusted builders require unique ids and p256-spki public keys");
    }
    builders.set(builderId, { builder_id: builderId, trust_domain: trustDomain, public_key: publicKey });
    publicKeys.add(publicKey);
    trustDomains.add(trustDomain);
  }
  if (trustDomains.size < Number(minimum)) {
    throw new ApiError(503, "reproducer_policy_misconfigured", "trusted builder policy does not span the required number of trust domains");
  }
  return { minimum_trust_domains: Number(minimum), builders };
}

async function verifyAuthenticatedReproductionReports(
  env: Env,
  deps: AppDeps,
  evidence: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const policy = registryReproducerPolicy(env, true)!;
  const reports = evidence["reproducers"];
  if (!Array.isArray(reports)) {
    throw new ApiError(400, "invalid_reproduction_report", "reproducers must be an array");
  }
  const verifier = deps.capabilityVerifier ?? new WebCryptoP256Verifier();
  const trustDomains = new Set<string>();
  const publicKeys = new Set<string>();
  for (const rawReport of reports) {
    const report = assertPlainObject(rawReport, "invalid_reproduction_report");
    const builderId = String(report["builder_id"]);
    const trusted = policy.builders.get(builderId);
    if (!trusted
      || report["trust_domain"] !== trusted.trust_domain
      || report["builder_public_key"] !== trusted.public_key) {
      throw new ApiError(403, "untrusted_reproducer", `reproducer '${builderId}' is not an active trusted builder`);
    }
    if (publicKeys.has(trusted.public_key)) {
      throw new ApiError(400, "duplicate_reproducer", "reproduction evidence repeats one trusted builder key");
    }
    const signatureObject = assertPlainObject(report["signature"], "invalid_reproduction_signature");
    const signature = {
      algorithm: signatureObject["algorithm"] as "p256-sha256",
      signature: String(signatureObject["signature"]),
    };
    const signedPayload = { ...report };
    delete signedPayload["signature"];
    if (!(await verifier.verify(canonicalJson(signedPayload), trusted.public_key, signature))) {
      throw new ApiError(401, "reproduction_signature_invalid", `reproducer '${builderId}' signature verification failed`);
    }
    publicKeys.add(trusted.public_key);
    trustDomains.add(trusted.trust_domain);
  }
  if (trustDomains.size < policy.minimum_trust_domains) {
    throw new ApiError(
      409,
      "insufficient_reproducer_trust_domains",
      `reproduction evidence requires ${policy.minimum_trust_domains} independent trust domains`,
    );
  }
  const policyIdentity = {
    schema: "cellscript-reproducer-policy-v1",
    minimum_trust_domains: policy.minimum_trust_domains,
    builders: [...policy.builders.values()].sort((left, right) => left.builder_id.localeCompare(right.builder_id)),
  };
  return {
    reproducer_policy: {
      schema: "cellscript-reproducer-policy-acceptance-v1",
      policy_hash: `sha256:${await sha256Hex(canonicalJson(policyIdentity))}`,
      minimum_trust_domains: policy.minimum_trust_domains,
    },
  };
}

function requireEvidenceReference(evidence: Record<string, unknown>, key: string, expected: PackageEvidenceRecord): void {
  const value = requireEvidenceString(evidence, key, 71, 71);
  if (value !== expected.evidence_hash) {
    throw new ApiError(400, "evidence_reference_mismatch", `${key} does not reference the accepted ${expected.kind} evidence`);
  }
}

function requireMatchingEvidenceHash(evidence: Record<string, unknown>, key: string, expected: string): void {
  const value = requireEvidenceHash(evidence, key);
  if (!sameHash(value, expected)) {
    throw new ApiError(400, "evidence_identity_mismatch", `evidence.${key} does not match the published package identity`);
  }
}

function requireEvidenceHash(evidence: Record<string, unknown>, key: string): string {
  const value = requireEvidenceString(evidence, key, 64, 66);
  if (!/^(?:0x)?[0-9a-fA-F]{64}$/.test(value)) {
    throw new ApiError(400, "invalid_evidence_hash", `evidence.${key} must be a 32-byte hex hash`);
  }
  return value;
}

function sameHash(left: string, right: string): boolean {
  return left.replace(/^0x/i, "").toLowerCase() === right.replace(/^0x/i, "").toLowerCase();
}

function requireEvidenceString(
  evidence: Record<string, unknown>,
  key: string,
  minimumLength: number,
  maximumLength: number,
): string {
  const value = evidence[key];
  if (typeof value !== "string" || value.trim() !== value || value.length < minimumLength || value.length > maximumLength) {
    throw new ApiError(400, "invalid_evidence_field", `evidence.${key} is invalid`);
  }
  return value;
}

function requireEvidenceTimestamp(evidence: Record<string, unknown>, key: string): string {
  const value = requireEvidenceString(evidence, key, 20, 40);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || timestamp > Date.now() + 5 * 60 * 1000) {
    throw new ApiError(400, "invalid_evidence_timestamp", `evidence.${key} must be a non-future ISO timestamp`);
  }
  return new Date(timestamp).toISOString();
}

function maxJsonBytes(env: Env): number {
  return Number(env.MAX_JSON_BODY_BYTES ?? DEFAULT_MAX_JSON_BODY_BYTES);
}

function maxSnapshotBytes(env: Env): number {
  return Number(env.MAX_SNAPSHOT_BYTES ?? DEFAULT_MAX_SNAPSHOT_BYTES);
}

function quotaEventRetentionHours(env: Env): number {
  const value = Number(env.CLEANUP_QUOTA_EVENT_RETENTION_HOURS ?? DEFAULT_QUOTA_EVENT_RETENTION_HOURS);
  return Number.isFinite(value) && value >= 1 ? value : DEFAULT_QUOTA_EVENT_RETENTION_HOURS;
}

function namespaceClaimCooldownSeconds(env: Env): number {
  const value = Number(env.NAMESPACE_CLAIM_COOLDOWN_SECONDS ?? DEFAULT_NAMESPACE_CLAIM_COOLDOWN_SECONDS);
  return Number.isFinite(value) && value >= 0 ? value : DEFAULT_NAMESPACE_CLAIM_COOLDOWN_SECONDS;
}

async function requestIpHash(request: Request): Promise<string | undefined> {
  const ip = request.headers.get("cf-connecting-ip") ?? request.headers.get("x-forwarded-for");
  return ip ? `sha256:${await sha256Hex(ip)}` : undefined;
}

function requestAsn(request: Request): string | undefined {
  const cf = (request as Request & { cf?: { asn?: number | string } }).cf;
  const asn = cf?.asn ?? request.headers.get("cf-asn");
  return asn === undefined || asn === null || `${asn}`.trim() === "" ? undefined : `${asn}`.trim();
}

function corsHeaders(requestId: string): Headers {
  return new Headers({
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization,idempotency-key,x-registry-admin-token,x-registry-admin-actor",
    "access-control-expose-headers": "x-request-id,x-idempotency-status,etag,x-ls-idl-format-version,x-ls-idl-sha256,x-ls-idl-coordinate,x-ls-idl-commitment,x-ls-idl-verification",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "permissions-policy": "camera=(), geolocation=(), microphone=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-permitted-cross-domain-policies": "none",
    "x-request-id": requestId,
  });
}

function json(value: unknown, status: number, headers: Headers): Response {
  const out = new Headers(headers);
  out.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(value, null, 2), { status, headers: out });
}

function errorResponse(error: unknown, requestId: string): Response {
  const headers = corsHeaders(requestId);
  const status = error instanceof ApiError ? error.status : 500;
  const code = error instanceof ApiError ? error.code : "internal_error";
  const message = error instanceof Error ? error.message : "internal error";
  return json({ request_id: requestId, error: { code, message } }, status, headers);
}

export default createApp();

export { MemoryRegistryStore };
