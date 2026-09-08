# CellScript Registry API

Typed production API for the public CellScript artifact Registry. The same
application runs as a Cloudflare Worker or through the bundled Node HTTP
adapter.

- `https://api.registry.cellscript.dev` is the authenticated write and dynamic
  read boundary.
- `https://registry.cellscript.dev` serves immutable bundles and static release
  JSON independently from the write database.

The Pudge test environment is a separate, ephemeral service:

- `https://api.testnet.registry.cellscript.dev` is the sandbox API;
- `https://objects.testnet.registry.cellscript.dev` is its object origin;
- `https://testnet.registry.cellscript.dev/registry` is its `noindex` UI.

It uses a different Postgres volume, object volume, signing origin, wallet
storage key, RPC identity, and Compose project. Do not put a network selector in
the production Registry. `REGISTRY_ENVIRONMENT=testnet-sandbox` requires the
dedicated origins and accepts only a Pudge/Testnet RPC. Unknown environments
fail closed.

Postgres is authoritative for publisher capabilities, namespace ownership,
artifact releases, orthogonal release states, evidence, jobs, idempotency, and
audit events. R2 or the filesystem adapter stores immutable content and static
read objects.

## Artifact Contract

The API has one public resource family: `/v1/artifacts`. Every release declares
an artifact descriptor:

```ts
{
  kind: "source_library" | "profile_library" | "runtime_verifier" |
        "deployable_contract" | "reproducible_binary" | "template";
  profile: "cellscript_source" | "ckb_executable" |
           "reproducible_build" | "copy_material";
  consumption_mode: "dependency" | "deployment" | "tcb" | "copy";
  language: "cellscript" | "rust" | "c" | "javascript" |
            "other" | "unspecified";
}
```

Profile/kind/language/consumption combinations are closed and validated. The
single extension point is the exported
`cellscript-registry-profile-catalog-v1`: every profile names a versioned
validator, allowed kind/language/consumption contracts, whether a profile
contract is required, and a `dependency` or `non_resolving` capability. Only
`cellscript_source` is dependency-resolving. Unknown profiles and attempts to
use CKB executables, reproducible builds, or copy material as dependencies fail
closed.

The
generic profiles additionally carry a closed
`cellscript-registry-profile-contract-v1` object. Admission, the publisher CLI,
and the isolated verifier independently canonicalize it, bind its hash, reject
unknown fields, and verify the typed build/security/CKB/verifier/reproduction
or copy fields against immutable object hashes. The independent verifier then
applies a profile-specific object contract:

- `cellscript_source`: compile the canonical CellScript snapshot;
- `ckb_executable`: hash-bind source, executable, ABI, and any optional
  reproducible build recipe; when a CellScript bundle supplies one verified
  sidecar, require the complete metadata/lowering-record/source-map set and run
  the compiler-independent structural checker;
- `reproducible_build`: hash-bind source, executable, and build recipe, then
  require external reproducibility evidence;
- `copy_material`: hash-bind a `cellscript-template-file-map-v1` source and
  never treat it as a dependency.

A deployable `ckb_executable` Lock Script may additionally carry the closed
`cellscript-registry-ls-idl-interface-v1` contract. Admission requires exactly
one ABI object, validates the bounded LS-IDL 0.1 document, hashes the original
ABI bytes with SHA-256, and checks that digest against both the interface
contract and the executable's final 32 bytes. The response path returns those
stored bytes directly; it does not parse and reserialise JSON. See
[`docs/CELLSCRIPT_LS_IDL_REGISTRY_PROFILE.md`](../../docs/CELLSCRIPT_LS_IDL_REGISTRY_PROFILE.md).

Release state is split across:

```text
verification_status = pending | hash_bound | verified | evidence_required | rejected
deployment_status   = not_applicable | undeployed | deployed | chain_verified
availability_status = active | deprecated | yanked | quarantined
```

Publisher input can create only the initial states. Verification and deployment
states are derived from accepted evidence. Availability is the operator safety
axis and does not rewrite identity or evidence.

Legacy `status` values such as `source_published` and `verified_build` are a
compatibility projection of those three axes, not an additional trust claim.
New clients must read `verification_status`, `deployment_status`, and
`availability_status` independently; in particular, `hash_bound` means object
integrity only, not semantic correctness or security review.

For a reproducible profile, `verified_build` with level `evidence_required` is
only the hash-bound predecessor. An admin promotion to `reproduced_build`
requires two to sixteen P-256-signed `cellscript-reproduction-report-v2`
reports. Each builder ID, public key, and trust domain must be distinct; every
builder must match `REGISTRY_REPRODUCER_POLICY_JSON`; and the reports must span
the policy's minimum number of trust domains. Reports bind the signed
environment, source hash, build-recipe hash, artifact hash, build-log hash,
timestamp, and predecessor evidence. Deployment admission rejects a
reproducible artifact until this transition succeeds. Accepted evidence also
stores the canonical policy SHA-256 and the minimum trust-domain threshold used
at acceptance time.

Trust-domain independence is an operator-governance fact, not something the API
can infer from two different strings. Production policy must use builders under
separate administrative control and separate private-key custody. Two keys
created or controlled by the same Registry operator must not be labelled as two
independent trust domains. `/ready` validates policy shape, key importability,
and configured threshold only; it is not an organizational-independence
attestation.

Each independent operator can create its own key and public enrollment record
without contacting the Registry write API:

```bash
cellc auth reproducer create \
  --builder-id <stable-id> \
  --trust-domain <independent-domain> \
  --json > builder-enrollment.json
```

The operator sends only `policy_builder` to the Registry administrator. By
default the private key remains in that builder's OS keychain. The explicit
`--private-key-output <new-file>` mode exists on Unix for transfer into that
builder's CI secret manager; it creates a new mode-0600 PKCS#8-base64 file and
refuses to overwrite an existing path.

## Endpoints

```text
GET  /health
GET  /ready
GET  /artifacts/:namespace/:name/releases/:release.json
GET  /v1/artifacts
GET  /v1/artifacts/:namespace/:name
GET  /v1/artifacts/:namespace/:name/releases/:release/evidence
GET  /v1/artifacts/:namespace/:name/releases/:release/commitment
GET  /v1/ckb/scripts/:code_hash/interfaces/ls-idl?network=:network&hash_type=:hash_type[&data_hash=:data_hash]
GET  /idl/:code_hash
POST /v1/artifacts/:namespace/:name/releases
POST /v1/artifacts/:namespace/:name/releases/:release/deployments
POST /v1/artifacts/:namespace/:name/releases/:release/availability

POST /v1/capabilities
GET  /v1/capabilities/:key_id/check?namespace=:namespace&name=:name
POST /v1/capabilities/:key_id/revoke
POST /v1/namespaces/claim
POST /v1/authorisation-sessions
GET  /v1/authorisation-sessions/:session_id
POST /v1/authorisation-sessions/:session_id/challenge
POST /v1/authorisation-sessions/:session_id/complete

GET  /v1/admin/audit-events
GET  /v1/admin/verification-queue
POST /v1/admin/verification-jobs/:job_id/retry
POST /v1/admin/reserved-namespaces
POST /v1/admin/namespaces/:namespace/status
POST /v1/admin/artifacts/:namespace/:name/releases/:release/availability
POST /v1/admin/artifacts/:namespace/:name/releases/:release/promote
```

List filters are `q`, `namespace`, `kind`, `verification`, `deployment`,
`availability`, `limit`, and `offset`. Quarantined releases are absent from
public detail and evidence reads.

The canonical LS-IDL lookup returns
`application/vnd.ckb.ls-idl+json` plus digest, coordinate, commitment, and
verification headers. `data_hash` is required for `hash_type=type`; ambiguous
matches return `409`. `/idl/:code_hash` is a compatibility route for existing
clients and returns the same exact raw bytes.

## Publisher Authorisation

Wallet-rooted capability authorisation supports:

- JoyID signatures under `principal_type = joyid_ckb`;
- recoverable CKB secp256k1 message signatures under
  `principal_type = ckb_secp256k1`.

The signature public key is bound to `principal_id`; a display address is not
an ACL key. The delegated P-256 capability is expiring, revocable, and stored
separately from the wallet root. Namespace ownership must match the capability
principal. Each write family has its own exact-coordinate or namespace-wide
scope:

- `publish:namespace/name` admits immutable releases;
- `deployment:namespace/name` attaches verified CKB deployment evidence;
- `availability:namespace/name` deprecates, yanks, or restores a release.

Each form also accepts `namespace/*`. Possessing one action does not imply either
of the others.

`POST /v1/authorisation-sessions/:session_id/complete` is idempotent after a
successful completion. Its first successful call commits nonce use, capability
registration, namespace claim or review state, session completion, and audit
events in one store transaction. A concurrent call returns the committed
session instead of creating a second capability use. Expired sessions, stale
challenge tokens, and conflicting namespace owners leave the session pending
and create none of those records. The 15-minute expiry applies only while a
session is pending. `authorised` and `review_pending` results remain readable
to the polling CLI for 24 hours, then cleanup removes them; this lets a CLI
recover a wallet approval committed immediately before the approval window
closed.

For an interactive first publish, `cellc publish --authorise` creates a
15-minute, exact-coordinate browser session and opens the matching Registry
site. The CLI generates the delegated P-256 key first and keeps its private key
in the OS keychain as pending before opening the browser, then promotes it to
active only after `authorised` or `review_pending` returns the same key ID.
Only Registry-confirmed cancellation or pending-session expiry removes the
pending entry. A local polling deadline performs one final Registry read and
otherwise leaves the pending key recoverable through the key ID printed before
the browser opens. The API stores only the public key plus hashes of separate
one-time CLI-polling and browser-approval tokens. The browser token travels in
the URL fragment, not the query string, so it is absent from HTTP logs and
Referer headers; browser reads never return the polling token or resulting
capability key ID. After the wallet approves the
server-built challenge, the Registry records the capability, claims the
namespace, and the polling CLI continues the original publish automatically.
Use `--no-open` to print the browser URL without launching it.

The explicit commands below remain the auditable/manual route for CI, external
wallet signing, and recovery:

```bash
cellc auth capability create --principal-type <principal_type> --principal-id <principal_id> \
  --scope publish:ns/name \
  --expires 90d --json > capability-payload.json
# Sign the canonical payload in a supported CKB wallet.
cellc auth capability submit --payload capability-payload.json --wallet-signature wallet-signature.json
cellc auth namespace claim --namespace ns --payload capability-payload.json --wallet-signature wallet-signature.json
```

The browser defaults to the single exact `publish:ns/name` scope. Add
`deployment:ns/name` or `availability:ns/name` only when the delegated key must
perform those later maintenance actions; they are not required to publish a
release.

The read-only capability check returns public status, expiry and scopes plus an
artifact-specific evaluation of publish/deployment/availability access and
namespace ownership. It never returns the delegated public key, wallet
signature or capability signature. The Submit UI uses this endpoint before it
reveals a publish command for either a newly authorised or existing cellc key.

Capability registration does not silently claim a namespace. Publish remains
blocked until the claim is active. Signed nonces are one-use; publish requests
also use an `Idempotency-Key` so exact retries replay safely and conflicting
content fails.

The browser wallet directory lists Neuron, JoyID, imToken, CKBull, SafePal,
Ledger, imKey, OneKey, UTXO Global, Rei Wallet, Gate, and QuantumPurse. Runtime
connectivity is determined by CCC discovery. Directory entries without a live
connector use the external signed-payload handoff and never bypass backend
signature verification. Production accepts only mainnet authorisation and
deployment evidence. The isolated Pudge Sandbox accepts only testnet evidence;
the two origins make wallet challenges and capability signatures non-replayable
across environments.

## Pudge Sandbox Retention

Every sandbox release stores `registry_environment = testnet-sandbox`,
`network = testnet`, `expires_at = created_at + 72h`, and
`purge_after = expires_at + 24h`. Public SQL and in-memory reads filter by
`expires_at` even if maintenance is delayed. At expiry, the version-addressed
static JSON is deleted; after the grace period, a source object is deleted only
when no non-expired release references its snapshot hash. Database identity and
audit rows remain as tombstones so abuse and replay investigations are not
erased. Reads never extend TTL.

The sandbox additionally limits a wallet principal to 20 accepted publish
attempts per 24 hours and one package coordinate to five; the ordinary IP,
capability, namespace-cooldown, request-size, and snapshot-size controls still
apply.

This policy cannot delete Pudge chain history or consume a deployed code Cell.
It only removes the Registry index and its off-chain object bytes.

## Release Admission

Daily publish signs canonical JSON for:

```text
cellscript-registry-publish-v1 / publish
```

Admission requires:

- an active, unexpired, unrevoked capability with matching scope;
- an active namespace owned by the same principal;
- matching route, signed payload, artifact descriptor, coordinate, release,
  source hash, manifest hash, and single-release nested entry;
- a valid capability signature and unused nonce;
- a new release coordinate;
- a non-empty immutable snapshot/bundle no larger than 5 MiB;
- successful immutable-bundle and initial static-object writes.

Generic artifact profile contracts are closed and hash-bound. In particular,
an `audited` security declaration requires an immutable `audit_report` bundle
object bound by `security.audit_report_hash`; the isolated verifier recomputes
that hash before it emits evidence.

An LS-IDL profile also requires `artifact.kind = deployable_contract`,
`artifact.profile = ckb_executable`, `consumption_mode = deployment`, and
`profile_contract.ckb.script_role = lock`. Both the compiler-backed worker and
the artifact-only verifier recompute the raw ABI SHA-256 and executable suffix;
neither accepts a detached or JSON-equivalent-but-byte-different interface.

The database transaction stores the release, job, capability use, audit event,
nonce, and completed idempotency record. The verifier job is created in the
same transaction. An admission response does not claim verification.

CellScript packages publish with `cellc publish`; profile libraries add
`--artifact-kind profile_library`. Other artifacts publish with:

```bash
cellc publish --artifact-manifest Artifact.toml --dry-run
cellc publish --artifact-manifest Artifact.toml
```

`CELLSCRIPT_REGISTRY_API_URL` overrides the API base URL.
`CELLSCRIPT_CAPABILITY_PRIVATE_KEY_PKCS8_B64` supplies the delegated key in CI.
`CELLSCRIPT_REGISTRY_IDEMPOTENCY_KEY` pins the exact retry key.

## Network-Bound Deployment Evidence

Executable publication begins at `deployment_status = undeployed`. A publisher
records a deployment by signing canonical JSON for:

```text
cellscript-registry-deployment / record_deployment
```

The request must identify the network fixed by the Registry environment
(`mainnet` in production, `testnet` in the Pudge Sandbox), the published
executable hash, equal Cell data hash, code hash, hash type, dep type, and
OutPoint. Prior verified-build evidence is mandatory.

The API confirms the configured RPC chain identity, calls
`get_live_cell(out_point, true, false)` to prove the OutPoint is live, then
reads `get_transaction(tx_hash).tx_status` to require a committed creation
transaction and obtain the block hash used for confirmation counting. It fails
closed unless the Cell is live and its data hash equals the published
executable. For `hash_type = type`, it serializes the returned Type Script with
Molecule and verifies its CKB Script hash against `code_hash`. Data-hash modes
require `code_hash` to equal the data hash. The service does not depend on the
proxy-specific `get_live_cell.block_hash` extension. Success appends
hash-addressed evidence and sets only `deployment_status = chain_verified`.

`CKB_RPC_URL` configures the environment RPC. `CKB_MAINNET_RPC_URL` remains a
production compatibility alias. The Docker deployment sets
`CKB_RPC_MAX_RESPONSE_BYTES=8388608`: canonical secp256k1 DepGroup validation
must read the genesis data Cell, whose JSON-RPC hex encoding exceeds the
conservative 2 MiB library default. The API still enforces its 8 MiB hard
ceiling and bounded RPC timeout.

## Registry Chain Commitments

After deployment evidence exists, the public commitment endpoint returns the
canonical payload, `CSREGv1 || commitment_hash` Cell data, and—when fully
configured—a mainnet transaction intent containing the fixed output Lock, Type
Script, data, and both required code CellDeps. The publisher's wallet supplies
capacity, inputs, change, fee, witnesses, signatures, and broadcast.

The four Script configuration values are all-or-nothing:

```text
REGISTRY_TYPE_SCRIPT_JSON
REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON
REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON
REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON
```

In `ENVIRONMENT=production`, configuration is additionally pinned to the
tracked immutable Registry Type Script release in
`contracts/registry-type-script/release-manifest.json`. Its Type args must be
the CKB Script hash of the complete custody Lock, the custody Lock must be the
mainnet `secp256k1_blake160_sighash_all` Script with 20-byte signer args, and
its CellDep must be the canonical genesis DepGroup. The Type Script requires a
custody-locked input for creation as well as update/destruction, so merely
creating an output addressed to the Registry cannot forge an official
commitment.

`CKB_REGISTRY_SCAN_MAX_CELLS` bounds the scheduled indexer scan (default 1000,
allowed range 100–10000). `CKB_MIN_CONFIRMATIONS` defaults to 24 and applies to
deployment Cells, commitment Cells, and both configured Script code CellDeps.
Maintenance queries exact Type Script matches with a `CSREGv1` data prefix,
verifies the configured commitment Lock, and reconciles current lifecycle
state. A matching sufficiently confirmed live Cell promotes to
`on_chain_committed`; a spent or immature commitment returns to `deployed`; and
a stale deployment returns to `verification_status = verified` with
`deployment_status = undeployed` (projected as `verified_build`). Historical
evidence is retained.

Leaving all four Script values unset deliberately disables transaction-intent
construction and chain reconciliation; maintenance then clears any prior
current-commitment pointer because it can no longer re-observe that claim.
Setting only some of them is a service misconfiguration. Invalid, spent, or insufficiently confirmed code CellDeps
also fail readiness. Deploying and pinning the canonical mainnet Registry Type
and commitment Lock Scripts remains an operator action; checked-in code does
not itself prove that a public commitment exists.

### Commitment custody boundary and incident response

The currently pinned production policy uses one standard
`secp256k1_blake160_sighash_all` custody Lock. This is deliberately simple, but
it is a single-key trust boundary: whoever can satisfy that Lock can create,
replace, or destroy commitment Cells. The Type Script has no independent
multisig, timelock, or revocation mechanism, and the API never holds that
private key. Do not describe a commitment as consensus over Registry
operators; it is an attributable statement by the configured custody key.

Operators must keep the custody key outside the API and verifier hosts, review
the complete transaction intent in the signing wallet, monitor the configured
Type Script for unexpected spends, and retain the prior commitment evidence in
the Registry audit store. On suspected compromise, stop issuing commitment
intents, remove the four commitment configuration values from traffic-serving
instances, preserve the last observed Cells and audit events, rotate to a new
custody Lock and therefore a new Type Script identity, and publish that
transition explicitly. Rotating the 20-byte signer args changes the custody
Script hash embedded in Type args; it is not an in-place key revocation.

## Verification Worker

The leased Postgres queue uses `FOR UPDATE SKIP LOCKED`, three-attempt bounded
retry/dead-letter handling, crash recovery, and a static-publication checkpoint.
The verifier subprocess has timeout, output, CPU, memory, process, capability,
filesystem, and temporary-storage bounds.

Verifier rejection output uses stable machine-readable codes. Current boundary
codes include `invalid_arguments`, `snapshot_unavailable`, `snapshot_invalid`,
`snapshot_authentication_failed`, `unsupported_profile`,
`artifact_identity_mismatch`, `identity_hash_mismatch`,
`cellscript_compilation_failed`, `artifact_bundle_invalid`,
`profile_contract_invalid`, `manifest_invalid`, and
`verifier_internal_error`. The Node worker preserves terminal verifier codes in
the job record; transport, timeout, malformed-output, and store failures remain
retryable infrastructure errors.

For CellScript source, the verifier compiles the authenticated snapshot using
the current real compiler. Source publication requires both
`compiler_requirement`, copied from `[package].cellscript_version`, and the
exact build `cellscript_version`; the resolver uses the former while
reproducible build evidence owns the latter. For generic artifact bundles it validates the
coordinate/profile and required objects, recomputes all hashes, and emits the
profile-specific verification level. Generic CKB bundles remain `hash_bound`.
A CKB bundle that supplies the complete compile metadata, lowering record, and
source map is processed by the separate least-privilege artifact worker and
may become `structurally_verified`; checker version, policy, and report hash
are persisted. Partial sidecar sets fail closed. Evidence insertion and the job
publishing checkpoint commit atomically; a crash after that point retries only
the static object write.

Queue operations require the admin token:

```text
GET  /v1/admin/verification-queue
POST /v1/admin/verification-jobs/:job_id/retry
```

## Admin Boundary

Admin requests require `Authorization: Bearer <REGISTRY_ADMIN_TOKEN>` or
`x-registry-admin-token`. `x-registry-admin-actor` is stored in audit events.

The generic availability endpoint accepts only `active`, `deprecated`,
`yanked`, or `quarantined`. It cannot manufacture verification or deployment
claims. Evidence-specific promotions validate required hashes and predecessor
evidence. Ordinary verified-build promotion is performed by the automatic
worker; the token-gated promotion path is for attributable recovery and
operations.

Audit events support filters for event type, principal, namespace, name,
release, time cursor, and bounded limit.

## Self-hosted Production

The checked-in stack uses Postgres 17, the Node 22 adapter, an isolated Rust
verification worker, a shared object volume, and read-only nginx. TLS is
terminated outside the compose stack. Build immutable linux/amd64 API and
verifier images before transferring them to production; do not compile the
full Rust verifier on a resource-shared production host.

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
docker compose --env-file deploy/.env -f deploy/docker-compose.production.yml config
docker compose --env-file deploy/.env -f deploy/docker-compose.production.yml up -d --no-build
```

Required runtime configuration:

```text
DATABASE_URL
REGISTRY_OBJECTS_DIR
REGISTRY_ADMIN_TOKEN
REGISTRY_ORIGIN
STATIC_REGISTRY_ORIGIN
REGISTRY_API_IMAGE
REGISTRY_VERIFIER_IMAGE
```

Mainnet deployment checks use `CKB_MAINNET_RPC_URL`. Chain commitments remain
disabled unless `REGISTRY_TYPE_SCRIPT_JSON`,
`REGISTRY_TYPE_SCRIPT_CELL_DEP_JSON`, `REGISTRY_COMMITMENT_LOCK_SCRIPT_JSON`,
and `REGISTRY_COMMITMENT_LOCK_CELL_DEP_JSON` are supplied together. Set
`REGISTRY_REPRODUCER_POLICY_JSON` before accepting reproduction promotions and
use `CKB_MIN_CONFIRMATIONS` to raise or lower the default 24-block confirmation
floor. The Node adapter, production Compose file, and Worker example pass the
same settings.

The API container applies tracked additive migrations before serving traffic.
`0001_initial.sql` is the frozen deployed baseline. `0002` adds the verifier
queue; `0003` adds multi-wallet principals; `0004` converts an empty legacy
release table to the artifact/state model and intentionally fails if rows exist
so operators cannot perform a lossy implicit migration; `0005` separates
hash-integrity evidence from semantic verification with `hash_bound`; and
`0006` admits the independent `reproduced_build` evidence kind; and `0007`
renames historical chain evidence, adds the current-commitment pointer and
status projection constraints, and deliberately demotes legacy current claims
until the mainnet indexer re-observes a sufficiently confirmed live Cell.
`0008` adds isolated sandbox retention, `0009` adds wallet-authorisation
sessions, and `0010` adds the bounded partial lookup index used to resolve
LS-IDL from active public chain-verified deployment evidence. Apply `0010`
before enabling either LS-IDL read route.

`GET /health` is process liveness and is the Compose container healthcheck.
`GET /ready` is the traffic and operator gate: it checks store/object access,
admin configuration, CKB/commitment dependencies, and—when
`REQUIRE_REGISTRY_VERIFIER_READY=true`—a fresh verifier heartbeat. External
load balancers and deployment automation should use `/ready`; a transient RPC,
database, object-store, or verifier dependency failure must not be mistaken for
a dead Node process by the container runtime.

## Backups

`deploy/backup.sh` creates a Postgres custom dump, object archive, Postgres
image identity, and SHA-256 manifest under the bounded retention policy.

```bash
(cd /data/cellscript-registry/backups/<timestamp> && sha256sum --check SHA256SUMS)
docker run --rm --network none \
  -v /data/cellscript-registry/backups/<timestamp>:/backup:ro \
  postgres:17-alpine pg_restore --list /backup/postgres.dump > /dev/null
tar -tzf /data/cellscript-registry/backups/<timestamp>/objects.tar.gz > /dev/null
```

Restore rehearsals use new empty database/object volumes and require `/ready`
plus static artifact reads before traffic cut-over. Never overwrite live
volumes with an untested restore.

## Cloudflare

The Worker and the isolated verifier are different processes. Cloudflare
Workers cannot spawn the Rust verifier binary. A Worker-only deployment can
serve the API, write R2 objects, and enqueue Postgres jobs, but it cannot advance
those jobs to `hash_bound` or `verified`; releases will remain pending.

The checked-in Node verifier currently consumes a Postgres queue and a shared
filesystem object store. It does not yet include an R2/S3 object adapter.
Therefore the supported production write topology is the self-hosted Node API +
Rust verifier Compose stack above. Treat the Worker configuration as an edge/API
deployment template until an external verifier is given both the same database
and an implemented immutable R2 object adapter. Do not route production publish
traffic to a Worker deployment that has no queue consumer.

For an API-only or development Worker deployment, configure Neon, R2,
Hyperdrive, the scheduled cleanup trigger, and `REGISTRY_ADMIN_TOKEN`; then
apply migrations and deploy:

```bash
DATABASE_URL='postgres://...' npm run migrate
npm install
npm run check
npm test
npm run build
npx wrangler deploy --config wrangler.toml
```

The checked-in `wrangler.example.toml` contains no secret. Re-running
`npm run migrate` is safe because applied migration filenames are recorded in
`schema_migrations`.

## Local Verification

```bash
npm run check
npm test
npm run build
npm run build:node
cargo test --locked --manifest-path ../registry-verifier/Cargo.toml
cargo clippy --locked --manifest-path ../registry-verifier/Cargo.toml --all-targets -- -D warnings
```

The repository-wide `dev` and `ci` gates exercise these surfaces together with
the compiler, CLI, website, and independent verifier. None of the commands in
this section deploys production.
