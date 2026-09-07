import { createHash, randomUUID } from "node:crypto";
import { access, lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { hostname } from "node:os";
import { dirname, resolve } from "node:path";
import type { ChildProcess } from "node:child_process";

import { ApiError, canonicalJson, sha256Hex } from "./domain";
import { FilesystemObjectStore } from "./filesystem-object-store";
import { syncStaticRegistryVersionObject, validatePromotionEvidence, type Env } from "./index";
import { SqlRegistryStore } from "./sql-store";
import type { PackageVersionRecord, VerificationJobRecord } from "./store";
import { executeVerifierSubprocess } from "./verifier-subprocess";

const databaseUrl = requiredEnv("DATABASE_URL");
const objectRoot = resolve(requiredEnv("REGISTRY_OBJECTS_DIR"));
const verifierBinary = process.env["REGISTRY_VERIFIER_BINARY"]?.trim() || "/usr/local/bin/cellscript-registry-verify";
const artifactVerifierBinary = process.env["REGISTRY_ARTIFACT_VERIFIER_BINARY"]?.trim()
  || "/usr/local/bin/cellscript-registry-artifact-verify";
const workerId = process.env["REGISTRY_VERIFIER_WORKER_ID"]?.trim() || `${hostname()}:${process.pid}:${randomUUID()}`;
const pollIntervalMs = integerEnv("REGISTRY_VERIFIER_POLL_INTERVAL_MS", 2_000, 100, 60_000);
const jobTimeoutSeconds = integerEnv("REGISTRY_VERIFIER_JOB_TIMEOUT_SECONDS", 180, 5, 1_800);
const leaseSeconds = integerEnv("REGISTRY_VERIFIER_LEASE_SECONDS", 300, jobTimeoutSeconds + 30, 3_600);
const healthFile = resolve(process.env["REGISTRY_VERIFIER_HEALTH_FILE"]?.trim() || "/tmp/registry-verifier-ready");
const sharedHeartbeatFile = resolve(
  process.env["REGISTRY_VERIFIER_SHARED_HEARTBEAT"]?.trim() || `${objectRoot}/.health/verifier-ready`,
);
const staticOrigin = process.env["STATIC_REGISTRY_ORIGIN"]?.trim() || "https://registry.cellscript.dev";

const store = new SqlRegistryStore({ connectionString: databaseUrl });
const objectStore = new FilesystemObjectStore(objectRoot);
const env: Env = { STATIC_REGISTRY_ORIGIN: staticOrigin, ENVIRONMENT: process.env["ENVIRONMENT"] ?? "production" };

let stopping = false;
let activeChild: ChildProcess | undefined;

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    log("verifier.stopping", { signal });
    activeChild?.kill("SIGTERM");
  });
}

async function initialize(): Promise<void> {
  const snapshotRoot = resolve(objectRoot, "source-snapshots");
  const packageRoot = resolve(objectRoot, "packages");
  await mkdir(snapshotRoot, { recursive: true, mode: 0o750 });
  await mkdir(packageRoot, { recursive: true, mode: 0o750 });
  await access(snapshotRoot, fsConstants.R_OK);
  await access(packageRoot, fsConstants.R_OK | fsConstants.W_OK);
  await access(verifierBinary, fsConstants.X_OK);
  await access(artifactVerifierBinary, fsConstants.X_OK);
  await mkdir(dirname(sharedHeartbeatFile), { recursive: true, mode: 0o750 });
  await store.healthCheck();
  await store.getVerificationQueueMetrics();
  await markHealthy();
  log("verifier.started", {
    worker_id: workerId,
    lease_seconds: leaseSeconds,
    job_timeout_seconds: jobTimeoutSeconds,
    poll_interval_ms: pollIntervalMs,
  });
}

async function runLoop(): Promise<void> {
  while (!stopping) {
    try {
      const job = await store.claimVerificationJob({
        worker_id: workerId,
        lease_seconds: leaseSeconds,
        now_iso: new Date().toISOString(),
      });
      await markHealthy();
      if (!job) {
        await delay(pollIntervalMs);
        continue;
      }
      await processJob(job);
      await markHealthy();
    } catch (error) {
      log("verifier.poll_failed", { error: safeErrorMessage(error) });
      await delay(Math.max(pollIntervalMs, 5_000));
    }
  }
  log("verifier.stopped", { worker_id: workerId });
}

async function processJob(job: VerificationJobRecord): Promise<void> {
  const requestId = `verification:${job.id}:${job.attempt_count}`;
  log("verification.claimed", {
    request_id: requestId,
    job_id: job.id,
    coordinate: `${job.namespace}/${job.name}@${job.version}`,
    attempt_count: job.attempt_count,
    phase: job.evidence_hash ? "static_sync" : "build",
  });
  try {
    let version: PackageVersionRecord;
    if (job.evidence_hash && job.evidence) {
      const existing = await store.getPackageVersion(job.namespace, job.name, job.version);
      if (!existing || !["verified", "hash_bound", "evidence_required"].includes(existing.verification_status)) {
        throw new Error("verification job has promoted evidence but package version is not promoted");
      }
      version = existing;
    } else {
      const existing = await store.getPackageVersion(job.namespace, job.name, job.version);
      if (!existing) throw new Error("verification job package version disappeared");
      const result = await runBuildVerification(job, existing);
      const previous = await store.listPackageEvidence(job.namespace, job.name, job.version);
      const evidence = validatePromotionEvidence(
        {
          schema: "cellscript-registry-evidence",
          kind: "verified_build",
          producer: result.compiler_version
            ? `cellscript-registry-verifier/${result.compiler_version}`
            : result.checker_version
              ? `cellscript-registry-artifact-verifier/${result.checker_version}`
              : `cellscript-registry-verifier/${job.artifact.profile}`,
          generated_at: new Date().toISOString(),
          verification_status: "passed",
          verification_level: result.verification_level,
          source_hash: result.source_hash,
          manifest_hash: result.manifest_hash,
          ...(result.compatibility_profile_hash ? { compatibility_profile_hash: result.compatibility_profile_hash } : {}),
          ...(result.artifact_hash ? { artifact_hash: result.artifact_hash } : {}),
          metadata_hash: result.metadata_hash,
          ...(result.compiler_version ? { compiler_version: result.compiler_version } : {}),
          ...(result.checker_version ? { checker_version: result.checker_version } : {}),
          ...(result.checker_policy_schema ? { checker_policy_schema: result.checker_policy_schema } : {}),
          ...(result.checker_report_hash ? { checker_report_hash: result.checker_report_hash } : {}),
          ...(result.protocol_bundle_schema ? {
            protocol_bundle_schema: result.protocol_bundle_schema,
            protocol_bundle_artifact_binding_schema: result.protocol_bundle_artifact_binding_schema,
            protocol_bundle_runtime_adapter: result.protocol_bundle_runtime_adapter,
          } : {}),
          artifact_format: result.artifact_format,
          snapshot_hash: job.snapshot_hash,
          verification_job_id: job.id,
        },
        "verified_build",
        existing,
        previous,
      );
      const evidenceHash = `sha256:${await sha256Hex(canonicalJson(evidence))}`;
      const promoted = await store.promoteVerifiedBuildForJob({
        job_id: job.id,
        worker_id: workerId,
        evidence_hash: evidenceHash,
        evidence,
        request_id: requestId,
        admin_actor: `verification-worker:${workerId}`,
      });
      version = promoted.version;
    }

    await syncStaticRegistryVersionObject(env, { snapshotWriter: objectStore }, store, version, staticOrigin);
    const completed = await store.completeVerificationJob({ job_id: job.id, worker_id: workerId });
    log("verification.succeeded", {
      request_id: requestId,
      job_id: job.id,
      coordinate: `${job.namespace}/${job.name}@${job.version}`,
      attempt_count: completed.attempt_count,
      evidence_hash: completed.evidence_hash,
    });
  } catch (error) {
    const retryable = !(error instanceof VerificationRejected);
    const errorCode = error instanceof VerificationRejected ? error.code : error instanceof ApiError ? error.code : "verification_infrastructure_error";
    const retryAfterSeconds = Math.min(300, 5 * 2 ** Math.max(0, job.attempt_count - 1));
    try {
      const failed = await store.failVerificationJob({
        job_id: job.id,
        worker_id: workerId,
        error_code: errorCode,
        error_message: safeErrorMessage(error),
        retryable,
        retry_after_seconds: retryAfterSeconds,
        request_id: requestId,
      });
      log(failed.status === "dead_letter" ? "verification.dead_lettered" : "verification.retry_scheduled", {
        request_id: requestId,
        job_id: job.id,
        coordinate: `${job.namespace}/${job.name}@${job.version}`,
        attempt_count: failed.attempt_count,
        error_code: errorCode,
        error: safeErrorMessage(error),
        ...(failed.status === "retry_wait" ? { retry_after_seconds: retryAfterSeconds } : {}),
      });
    } catch (leaseError) {
      log("verification.failure_not_recorded", {
        request_id: requestId,
        job_id: job.id,
        error: safeErrorMessage(error),
        record_error: safeErrorMessage(leaseError),
      });
    }
  }
}

interface BuildVerificationResult {
  status: "passed";
  verification_level: "compiled" | "hash_bound" | "evidence_required" | "structurally_verified";
  artifact_hash?: string;
  metadata_hash: string;
  compiler_version?: string;
  source_hash: string;
  manifest_hash: string;
  compatibility_profile_hash?: string;
  artifact_format: string;
  checker_version?: string;
  checker_policy_schema?: string;
  checker_report_hash?: string;
  protocol_bundle_schema?: "cellscript-protocol-bundle-v1";
  protocol_bundle_artifact_binding_schema?: "cellscript-protocol-bundle-artifact-binding-v1";
  protocol_bundle_runtime_adapter?: "cellscript-ckb-adapter";
}

async function runBuildVerification(job: VerificationJobRecord, version: PackageVersionRecord): Promise<BuildVerificationResult> {
  const expectedContentType = job.artifact.profile === "cellscript_source"
    ? "application/vnd.cellscript.source-snapshot+json"
    : "application/vnd.cellscript.artifact-bundle+json";
  if (job.snapshot_content_type !== expectedContentType) {
    throw new VerificationRejected(
      "unsupported_snapshot_content_type",
      `${job.artifact.profile} verification requires ${expectedContentType}, got ${job.snapshot_content_type}`,
    );
  }
  const snapshotPath = objectStore.pathFor(job.snapshot_object_key);
  const metadata = await lstat(snapshotPath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new VerificationRejected("invalid_snapshot_object", "source snapshot object is not a regular file");
  }
  if (metadata.size !== job.snapshot_size_bytes || metadata.size <= 0 || metadata.size > 5 * 1024 * 1024) {
    throw new VerificationRejected("snapshot_size_mismatch", "source snapshot object size does not match the admitted descriptor");
  }
  const snapshot = await readFile(snapshotPath);
  const snapshotHash = `sha256:${createHash("sha256").update(snapshot).digest("hex")}`;
  if (snapshotHash.toLowerCase() !== job.snapshot_hash.toLowerCase()) {
    throw new VerificationRejected("snapshot_hash_mismatch", "source snapshot object does not match its admitted SHA-256 identity");
  }

  const published = version.registry_entry.versions[0];
  const verifierArgs = [
    "--snapshot",
    snapshotPath,
    "--namespace",
    job.namespace,
    "--name",
    job.name,
    "--version",
    job.version,
    "--source-hash",
    job.source_hash,
    "--manifest-hash",
    job.manifest_hash,
    "--artifact-kind",
    job.artifact.kind,
    "--profile",
    job.artifact.profile,
  ];
  if (job.compatibility_profile_hash) verifierArgs.push("--compatibility-profile-hash", job.compatibility_profile_hash);
  if (published.interface_hash) verifierArgs.push("--interface-hash", published.interface_hash);
  if (published.artifact_hash) verifierArgs.push("--artifact-hash", published.artifact_hash);
  if (published.abi_hash) verifierArgs.push("--abi-hash", published.abi_hash);
  if (published.build_recipe_hash) verifierArgs.push("--build-recipe-hash", published.build_recipe_hash);
  let result: Awaited<ReturnType<typeof executeVerifierSubprocess>>;
  try {
    result = await executeVerifierSubprocess(
      job.artifact.profile === "ckb_executable" ? artifactVerifierBinary : verifierBinary,
      verifierArgs,
      {
        cwd: "/tmp",
        env: {
          PATH: process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin",
          HOME: process.env["HOME"] ?? "/tmp/verifier-home",
          XDG_CACHE_HOME: process.env["XDG_CACHE_HOME"] ?? "/tmp/verifier-cache",
          CELLSCRIPT_REGISTRY_API_URL: process.env["CELLSCRIPT_REGISTRY_API_URL"] ?? "https://api.registry.cellscript.dev",
          NO_COLOR: "1",
        },
        timeoutMs: jobTimeoutSeconds * 1_000,
        onSpawn: (child) => { activeChild = child; },
      },
    );
  } finally {
    activeChild = undefined;
  }

  let payload: unknown;
  try {
    payload = JSON.parse(result.stdout);
  } catch {
    if (result.timedOut) throw new Error("CellScript verifier timed out");
    throw new Error(`CellScript verifier returned invalid JSON (exit ${result.exitCode ?? "signal"})`);
  }
  if (result.timedOut) throw new Error("CellScript verifier timed out");
  if (result.exitCode !== 0) {
    const failure = plainObject(payload);
    const code = safeToken(failure?.["error_code"]);
    if (!code) throw new Error("CellScript verifier failure output omitted a stable error_code");
    const message = safeString(failure?.["message"]) ?? "CellScript package verification failed";
    throw new VerificationRejected(code, message);
  }
  const output = plainObject(payload);
  if (!output || output["status"] !== "passed") {
    throw new Error("CellScript verifier success output is malformed");
  }
  const protocolBundleCapability = optionalProtocolBundleCapability(output);
  const parsed: BuildVerificationResult = {
    status: "passed",
    verification_level: requiredVerificationLevel(output),
    ...(optionalHash(output, "artifact_hash") ? { artifact_hash: optionalHash(output, "artifact_hash")! } : {}),
    metadata_hash: requiredHash(output, "metadata_hash"),
    ...(safeString(output["compiler_version"]) ? { compiler_version: requiredOutputString(output, "compiler_version", 80) } : {}),
    source_hash: requiredHash(output, "source_hash"),
    manifest_hash: requiredHash(output, "manifest_hash"),
    ...(optionalHash(output, "compatibility_profile_hash")
      ? { compatibility_profile_hash: optionalHash(output, "compatibility_profile_hash")! }
      : {}),
    artifact_format: requiredOutputString(output, "artifact_format", 80),
    ...(safeString(output["checker_version"]) ? { checker_version: requiredOutputString(output, "checker_version", 80) } : {}),
    ...(safeString(output["checker_policy_schema"])
      ? { checker_policy_schema: requiredOutputString(output, "checker_policy_schema", 120) }
      : {}),
    ...(optionalHash(output, "checker_report_hash") ? { checker_report_hash: optionalHash(output, "checker_report_hash")! } : {}),
    ...protocolBundleCapability,
  };
  requireSameHash(parsed.source_hash, job.source_hash, "source_hash");
  requireSameHash(parsed.manifest_hash, job.manifest_hash, "manifest_hash");
  if (job.compatibility_profile_hash) {
    if (!parsed.compatibility_profile_hash) throw new VerificationRejected("compatibility_profile_hash_missing", "verifier omitted compatibility_profile_hash");
    requireSameHash(parsed.compatibility_profile_hash, job.compatibility_profile_hash, "compatibility_profile_hash");
  }
  if (parsed.verification_level === "structurally_verified"
    && (!parsed.checker_version || !parsed.checker_policy_schema || !parsed.checker_report_hash)) {
    throw new VerificationRejected("checker_identity_missing", "artifact verifier omitted checker version, policy, or report hash");
  }
  if (parsed.protocol_bundle_schema) {
    if (parsed.verification_level !== "structurally_verified"
      || job.artifact.profile !== "ckb_executable"
      || parsed.artifact_format !== "ckb-vm-executable") {
      throw new VerificationRejected(
        "protocol_bundle_evidence_insufficient",
        "ProtocolBundle discovery requires a structurally verified CKB ELF bundle with complete sidecars",
      );
    }
  }
  return parsed;
}

function optionalProtocolBundleCapability(value: Record<string, unknown>): Partial<BuildVerificationResult> {
  const fields = [
    value["protocol_bundle_schema"],
    value["protocol_bundle_artifact_binding_schema"],
    value["protocol_bundle_runtime_adapter"],
  ];
  if (fields.every((field) => field == null)) return {};
  if (fields[0] !== "cellscript-protocol-bundle-v1"
    || fields[1] !== "cellscript-protocol-bundle-artifact-binding-v1"
    || fields[2] !== "cellscript-ckb-adapter") {
    throw new VerificationRejected(
      "protocol_bundle_contract_invalid",
      "verifier ProtocolBundle discovery contract is incomplete or unrecognised",
    );
  }
  return {
    protocol_bundle_schema: "cellscript-protocol-bundle-v1",
    protocol_bundle_artifact_binding_schema: "cellscript-protocol-bundle-artifact-binding-v1",
    protocol_bundle_runtime_adapter: "cellscript-ckb-adapter",
  };
}

class VerificationRejected extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

function requiredHash(value: Record<string, unknown>, key: string): string {
  const hash = requiredOutputString(value, key, 66);
  if (!/^(?:0x)?[0-9a-f]{64}$/i.test(hash)) throw new Error(`CellScript verifier ${key} is not a 32-byte hex hash`);
  return hash;
}

function optionalHash(value: Record<string, unknown>, key: string): string | undefined {
  if (value[key] == null) return undefined;
  return requiredHash(value, key);
}

function requiredVerificationLevel(value: Record<string, unknown>): BuildVerificationResult["verification_level"] {
  const level = requiredOutputString(value, "verification_level", 80);
  if (level !== "compiled" && level !== "hash_bound" && level !== "evidence_required" && level !== "structurally_verified") {
    throw new Error("CellScript verifier verification_level is not recognised");
  }
  return level;
}

function requiredOutputString(value: Record<string, unknown>, key: string, maximum: number): string {
  const item = value[key];
  if (typeof item !== "string" || item.length === 0 || item.length > maximum || item.trim() !== item) {
    throw new Error(`CellScript verifier ${key} is invalid`);
  }
  return item;
}

function requireSameHash(actual: string, expected: string, field: string): void {
  const normalize = (value: string) => value.replace(/^0x/i, "").toLowerCase();
  if (normalize(actual) !== normalize(expected)) throw new VerificationRejected(`${field}_mismatch`, `${field} does not match the signed package identity`);
}

function plainObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function safeString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return normalized ? normalized.slice(0, 2_000) : undefined;
}

function safeToken(value: unknown): string | undefined {
  return typeof value === "string" && /^[a-z][a-z0-9_]{0,79}$/.test(value) ? value : undefined;
}

function safeErrorMessage(error: unknown): string {
  return safeString(error instanceof Error ? error.message : String(error)) ?? "unknown error";
}

async function markHealthy(): Promise<void> {
  const heartbeat = `${new Date().toISOString()}\n`;
  await writeFile(healthFile, heartbeat, { mode: 0o600 });
  await writeFile(sharedHeartbeatFile, heartbeat, { mode: 0o640 });
}

async function delay(milliseconds: number): Promise<void> {
  const deadline = Date.now() + milliseconds;
  while (!stopping && Date.now() < deadline) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, Math.min(250, deadline - Date.now())));
  }
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integerEnv(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function log(event: string, data: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), event, ...data })}\n`);
}

await initialize();
await runLoop();
