# Restricted Compose model guard v1

This is an offline source component, **not an operational recovery package or
service-start permission**. It adds real pinned Compose library rendering/schema
checks to both existing forward input barriers. No live daemon, CLIProxy management
API, installation, credential, producer execution or release-pin operation exists
in this interface.

## Renderer identity and supported model

`compose-go/v2@v2.16.2:single-file-model-v1` binds the canonical Compose library at
`github.com/compose-spec/compose-go/v2 v2.16.2`, source
`ddbe099a5404149d75fe774b30de7bd0befd3bd3`, module checksum
`h1:pTp1DqQwJzFd85GzlWsSszKA1ABrV/ySqsClujIcWA8=`. The repository module/checksum
files bind its transitive dependencies. This dependency requires the shared logrus
upgrade from 1.9.3 to 1.10.1; it is not hidden as a renderer-only change.

`inputguard.RenderCompose`:

1. Applies the existing strict YAML parser, with no duplicate keys, anchors,
   merges, aliases, multiple documents, unsupported scalar types or ambiguous
   numeric spellings. Passes the parsed native map to the actual Compose loader;
   it does not reinterpret the raw YAML under another dialect.
2. Uses an explicit project name and **closed** string environment map. Copies the
   map, never uses `os.LookupEnv`, `.env`, working-directory discovery, Compose CLI
   configuration or a tool found through PATH. A source `name`, if present, and an
   explicit `COMPOSE_PROJECT_NAME`, if present, must equal the approved project.
   The library derives the same project environment value if it was omitted.
3. Runs the pinned library's interpolation, Compose JSON schema, canonicalization,
   defaults, model validation and normalization. Bare missing variables and missing
   required expressions refuse; literal defaults/alternatives and `$$` are supported.
   Nested substitutions inside braced expressions are deliberately unsupported.
   The pinned template matcher is constrained to the first closing brace so an
   adjacent expression cannot bypass the strict missing-variable callback through
   upstream recursive suffix substitution.
4. Resolves service pass-through variables only from the captured map. Inspects
   unresolved entries **before** normalization can erase list-form entries. Missing
   map/list variables refuse. No later runtime may fill an uncaptured variable.
5. Disables path resolution and uses a non-nil in-memory Config. Recursively rejects
   keys `include`, `extends`, `env_file`, `label_file` and `build`, including inside
   extensions. These features are rejected, not silently omitted. Resource-level
   environment loading for configs/secrets is unsupported. File/volume references
   that remain in the model are opaque strings: their existence, content, access,
   image/build availability and runtime behavior are **not** validated here.
6. Serializes a deterministic restricted JSON model, subject to the strict
   output depth/node/byte limits. The model may contain secrets and is not public
   output. Only the fixed verification receipt may be published.

This is **not `docker compose config` compatibility proof**. In particular it does
not resolve relative paths to an installation directory, load include/override/env
files, select a runtime service graph, perform Docker deployment validation or
validate plugin options. It intentionally supports less than the complete Compose
language. Frozen models must be provisioned for this exact renderer/options,
not relabeled Docker CLI output. Operational deployment-tool equivalence or an
explicitly reviewed consuming adapter remains required. No CLI/container/systemd
was invoked to obtain these component passes.

The input/output limits remain 4 MiB per document, depth 64 and 65,536 nodes.
Environments are non-null JSON objects of at most 256 distinct ASCII variable
names, 128 bytes per name, 4,096 UTF-8 bytes per value and 64 KiB total; NUL and
non-string values refuse. Each encoded environment is also limited to 64 KiB.
Interpolation lookups have a cumulative 4 MiB expansion allowance. These are
component bounds, not a hard memory/time guarantee for a library parser. The
outer helper transport enforces the original inclusive deadline; process death
is never complete manager/daemon quiescence.

## Protected capture and transport

`ProtectedComposeSnapshot` wraps `ProtectedInputSnapshot` with two independently
pinned private JSON files for original/proposed interpolation maps. The caller
must retain the **same installation lock**, complete writer fence and independently
authenticated policy/role approvals. There is no new lock, policy discovery or
approval authority. All nine file roles must be distinct. It opens protected roots
and retained no-follow file descriptors, verifies byte pins, captures the existing
seven-file bundle, serializes the envelope, rehashes the interpolation descriptors,
recaptures the base bundle and rehashes/revalidates the environment again. Errors
are fixed-code and secret-free. Every call is fresh; no frozen approval/receipt is
reused after drift.

The `composecmd` helper reads one exact JSON object from stdin:

- `schema`: `host-recovery-compose-request-v1`;
- `renderer`: the exact identity above;
- `project_name`: explicit lowercase `[a-z0-9][a-z0-9_-]{0,127}`;
- `inputs`: the existing `host-recovery-input-request-v1` bundle;
- `before_environment`, `after_environment`: closed JSON string objects.

All fields are mandatory; extra, duplicate, differently cased, null or trailing
objects refuse. Existing strict/raw-pin/exact-delta checks and host application
validation must pass first. The helper renders **both** source snapshots and
compares their semantic models with the separately raw-pinned corresponding frozen
models. It does not re-interpolate frozen output: an escaped dollar must stay a
literal dollar, not acquire a second runtime meaning. Source and rendered exact
deltas remain separate policies. An approved raw hash alone cannot make a
noncorresponding frozen model valid.

`ComposeInputGate` requires this distinct success receipt:

```json
{"schema":"host-recovery-compose-result-v1","matched":true,"application_validated":true,"compose_validated":true,"start_authorized":false}
```

Failure sets all three validation flags false and keeps start authorization false.
No model, source key/path, environment value, schema diagnostic or filename is
emitted. The executable is independently pinned and executed through the existing
retained descriptor/pipe transport; logs are discarded in the dedicated command.
The entire envelope's request hash remains independently approved.

`GuardedBoundary` already accepts this gate through its `ExactInputGate` base.
Rendering runs freshly after existing admission checks and stopped revalidation,
with post-helper source/environment/helper recapture and original deadlines.
Recovery remains a separate delegated path: bad candidate inputs do not prevent
baseline restoration, and this forward guard cannot grant old-service start.

## Evidence and limitations

Go tests exercise actual library interpolation/schema/model loading, independent
expected synthetic normalized fields/model, both environment/model sides, exact
image delta and unrelated-value refusal, literal dollars, unsupported-file and
remote references, schema/type/port errors, duplicate inputs and protocol downgrade.
Actual built-helper/protected-file Python tests cover both coordinator barriers,
before-arm/stopped rendering refusal, post-helper source/environment drift,
retained byte rehash with deliberately suppressed metadata differences, storage
faults and independent alert attempts when disk receipt persistence fails.

The first implementation's nested-default and unresolved pass-through false greens
and its later adjacent-default false green have retained reached red regressions
and exact before-source files. The final implementation refuses them. A Python
fault hook initially reached the base policy checksum rather than an environment
checksum; the corrected test delegates base checks and asserts the exact reached
environment hook. That fixture error is not claimed as environment fault coverage.

Synthetic approvals are replaced in the stopped-render regression deliberately to
reach actual rendering rather than early hash refusal. That is **test-only fault
injection**, not permission to repin an armed attempt or evidence of authenticated
operational provisioning. Host manager/daemon/fence/oracle/alert boundaries remain
scripted. Component `candidate_verified`/`baseline_restored` receipts retain
`production_acceptance: false` and a start fence. No actual recovery, external
notification, phase-cap measurement, downtime or production compatibility is proved.

Remaining work includes plugin-specific schemas/full approved stanza, authenticated
installation/input-role provisioning, deployment tool/path equivalence, persistent
supervisor/worker/outcome reconciliation, a complete independently enforced
boot/internal-restart/start/writer/pending-operation fence, full independent
baseline/image/replay/no-plugin oracle, genuine two-turn source coverage/drain and
the approved full-system disposable matrix. Existing code reviews and parent
integrated acceptance remain unstarted. Historical artifact/release pins are unchanged.
