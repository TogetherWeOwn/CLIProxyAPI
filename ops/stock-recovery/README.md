# Stock journal-aware recovery source packet

**PARTIAL / HOLD — source binding only. Not an installer, recovery approval, or
permission to execute the retained scripts.** No runnable replacement wrapper is
provided in this checkpoint. The legacy wrapper is retained only as inert review
material. Adaptation and functional qualification remain mandatory before this
packet can progress beyond draft.

## Lineage and limitations

This output reuses the operator-delivered detached `auto.sh`, `probe.py`, and
`authcount.py` lineage observed on 2026-11-07. The observed originals have these
SHA-256 hashes (not proof of the historically executed bytes):

| Original | Bytes | SHA-256 |
| --- | ---: | --- |
| auto.sh | 9955 | 77857c9507f9c89cdffe3b4a418ed1fdd3054b38827dfe5ce0a1dc2cae0524e5 |
| probe.py | 4210 | e8a54f696ee48a453e2c6f4e9c68f800c85bc2f46ca7ed01342665967d569f03 |
| authcount.py | 414 | 49400aa3a26b4b8cf159fd4002f177bf3d2ed7d95918c7ff17a36ad1f0d5b3e2 |

`retained/*.source.txt` are **inert, redacted review copies**, not the byte-identical
originals or executable candidates. Redactions replace the original host stack
path with `/path/to/stack`, replace the loopback probe URL with
`http://example.invalid`, and remove the internal tracker reference from the probe
docstring. `lineage.json` records the original identity, exact substitutions, and
review-copy identity separately. No named authorship is established or reassigned;
credit remains with the retained operator-delivered lineage. Do not invoke these
files with Bash or Python, rename them to executable extensions, or copy their
launch/manual recovery instructions into a production runbook.

This is separate from any custom producer/replay controller. The retained custom
producer's evidence failure is not repaired or accepted here. No core/SDK change,
custom auth conversion, replay migration, or upstream publication is included.

## Typed candidate artifact

The official registry's v8.0.60 index was inspected read-only. The reported digest
is the **index**, not Docker's local `.Id`:

| Role | Frozen value |
| --- | --- |
| Registry | docker.io/eceasy/cli-proxy-api |
| OCI index | sha256:873ec3df3b673a82f7d956d4636c7736b0c961dc6ee28f9fb403238b2898dc0d |
| Selected test platform | linux/amd64 |
| Platform manifest | sha256:8472aae0903a964412b8e73dd11d95d7a9932d8645789f77e8e162daa401474a |
| Config / expected Docker image ID | sha256:f47991389017dd92a46f5d28fbb822bbce55392a70eb570231714ab2de5c0098 |
| Reported upstream source reference | 91e0dee827abf476f9f86246f68c500a112f7155 |

`oci/` contains the exact public registry index, selected manifest and config bytes,
individually digest-bound in `manifest.json`. The registry index also lists arm64;
that is not this frozen test platform. **The actual host platform remains unknown.**
The image config has no source labels; their absence is neither source/binary
attestation nor evidence that this image was installed. The reported source
reference is context, not a verified binary/source binding.

The legacy script compares the index digest above to `docker image inspect .Id`.
That check conflates different identities. A future wrapper must compare each
artifact using its correct role, including the observed running config ID and
selected manifest, without accepting a mutable tag as identity.

Known-served stock .60 is only a recovery candidate. Restarting the same image with
the complete current credential/journal state is **service recovery**, not rollback
of an uncertain grant, and cannot cure a defective binary. No .58/.51 fallback is
allowed after a journal-aware runtime can have touched state.

## Offline source inspection in GitHub Actions

The standard-library-only source inspector reads the packet and hashes the bounded
regular-file inputs. It does not execute the archived source, access Docker,
read a credential store, use sudo, contact a provider, or grant deployment authority.

Actions runs:

```sh
python3 -I ops/stock-recovery/test_packet.py -v
python3 -I ops/stock-recovery/packet.py ops/stock-recovery/manifest.json
```

The inspector's success means **source_binding=BOUND**, while its report always
retains **qualification=HOLD**, **service_recovery=NOT_TESTED**, and
**execution_authorized=false**. Removing an unresolved gate is a packet error,
not a way to qualify execution. A future reviewed receipt verifier must establish
acceptance; a list of asserted booleans is not evidence. The packet digest and
GitHub Actions head/run/job identities bind this source-only checkpoint. Do not
interpret the workflow's green status as functional recovery proof.

No dependencies are installed for this inspector. Tests execute only in Actions;
no local full suite or CI mirror is part of this runbook.

## Probe acceptance adaptation — parser only

`service_evidence.py` adapts the retained probe's `/v1/messages` acceptance
checks without network calls, credentials, dependencies or runtime authority.
The synthetic contract requires a fresh 128-bit request nonce, exact model and
assistant response identity, expected text and `end_turn`. Streams must contain
ordered message/block events, completed blocks, terminal reason and final
`message_stop`; an EOF, substring, error, truncated prefix, foreign block or late
event fails. Tool checks construct a result correlated to the observed tool-use
ID and nonce, and require a distinct final answer after the caller sends it.

These are **parser controls, not service observations**. The future wrapper must
bind actual requests/responses to the attempt and runtime, submit the correlated
tool result, and prove the stock runtime traversed the intended synthetic provider.
A fabricated response transcript cannot establish that. This helper intentionally
has no network/CLI entrypoint and cannot authorize execution. It covers the retained
Messages probe format only; any additional API/provider format needs its own real
runtime qualification. Run `python3 -I ops/stock-recovery/test_service_evidence.py -v`
in Actions for positive and negative parser controls. Its green check still means
service recovery NOT_TESTED, and it does not clear any packet gate.

## Wrapper ownership and attempt records — primitives only

`attempt.py` supplies Linux-local primitives for the retained wrapper adaptation,
not a second wrapper, scheduler or state authority. No CLI, runtime mutation,
credential/journal read, daemon call or successful terminal receipt exists.

All future forward, watchdog and manual recovery entrants must share **one stable
private resource directory**, not one lock per attempt. The helper refuses
concurrent owners using one persistent `flock` inode; it never deletes or truncates
that lock. The caller must provide a pre-existing mode-0700 directory owned by the
caller, with trusted ancestors and stable placement on a supported local filesystem.
Symlink inputs, public/hardlinked locks, replaced lock inodes and stale handles
are rejected. Cooperative same-user exclusion is not a hostile-user security
boundary. A successful lock acquisition is **not** descendant/daemon quiescence.

Attempts have a fresh 128-bit nonce and exact package digest. Identity and records
are bounded private files, published without overwriting, with file and directory
sync before acknowledgement. Existing attempt nonces cannot be recreated and a
different package cannot adopt them. The current record types are only `armed`,
`stop-intent` and `failure`, each referencing a digest-bound observation. They are
storage primitives, **not verification of that observation**. In particular an
`armed` record alone does not prove a living independent watchdog, and a `failure`
record does not prove that the operator can observe it when storage is unavailable.
All sync/readback errors must abort the caller's action; visible bytes after a
failed sync do not acknowledge durability. Neither a missing result nor a parsed
record is success. Power-loss durability is not established by these tests.

Actions runs `python3 -I ops/stock-recovery/test_attempt.py -v` using disposable
local directories only. Tests cover separate-process exclusion and release,
identity binding, nonce reuse, immutable publication, symlink/hardlink/public-mode
rejection, stale descriptors and injected sync failures. These do not exercise a
watchdog, runtime, journal, grant, process-kill barrier or recovery path. **The
primitives are not integrated into a runnable replacement wrapper yet.** Every
acceptance gate in `manifest.json` remains unresolved.

## Frozen runtime preparation — not functional qualification

`runtime_artifact.py` prepares the actual frozen linux/amd64 OCI runtime for
Actions-only tests, rather than building a replacement from this older repository
baseline. It verifies the source packet, config descriptor, every compressed layer
size/digest and every uncompressed rootfs diff ID. It interprets only the final
`CLIProxyAPI/CLIProxyAPI` regular-file member plus the frozen loader set
(`ld-linux-x86-64.so.2`, `libc.so.6`, `libm.so.6`, `libdl.so.2`,
`libpthread.so.0`, `libgcc_s.so.1`, `etc/ld.so.cache`) from the same image
layers. It never extracts an archive tree or executes downloaded scripts.
Target/ancestor links, frozen-library links, relevant whiteouts, unsafe archive
paths, missing runtime/loader members and bounded-size violations fail closed.
All layers must validate before an executable or library is published. Each
invocation requires a new nonexistent download directory; existing inputs are
never overwritten.

The first bootstrap attempt failed with exit 127 (`chroot: failed to run
command '/CLIProxyAPI': No such file or directory`). The binary is dynamically
linked (`PT_INTERP /lib64/ld-linux-x86-64.so.2`, `DT_NEEDED libc.so.6`), so an
empty root without the frozen loader fails before the binary starts. The fix
materializes the frozen loader set from the same image layers and recreates the
image's merged-usr topology (`/lib64 -> usr/lib64`, `/lib -> usr/lib`, loader
symlink) in the disposable root. No host libraries are used. This remains a
lineage smoke test, not functional qualification.

The public pull token is acquired without workspace or production credentials and
is stripped from CDN redirects. No package dependencies, Docker daemon or installed
runtime are used. Actions retains the manifest/config/binary identities and exact
head/run/job evidence. This establishes registry-artifact lineage, **not** a
binary-to-source attestation. The binary has not become an accepted recovery target.

The `runtime-bootstrap` job attempts only `--help`, with an empty environment,
unprivileged UID/GID, new empty chroot (plus the frozen loader set above) and
network/PID namespaces on a disposable hosted runner. No host credentials/state/
config or provider is mounted, and no network interface is brought up. A missing
namespace capability is a failing prerequisite, not a reason to run on the shared
host or default daemon. `bootstrap_root.py` (stdlib-only, offline) creates the
root and installs the frozen binary/loader set with the merged-usr topology
(`/lib64 -> usr/lib64`, `/lib -> usr/lib`, loader symlink), failing closed
before creation on a missing, symlinked, non-regular or oversized source and
never overwriting an existing root; `test_bootstrap_root.py` covers it with
positive and negative controls. `help_identity.py` (stdlib-only, offline) then fails
closed unless the retained help output identifies the frozen candidate
(version/commit self-report plus usage and core flags), so an exit code with
empty or wrong output cannot pass; `test_help_identity.py` covers it with
positive and negative controls. `bootstrap_smoke.py` (stdlib-only, offline)
runs only the fixed help smoke — `sudo unshare --net --pid --fork
--kill-child env -i` with a minimal `PATH`, then `chroot --userspec=65534:65534`
on the disposable root — capturing stdout and stderr into the retained help
log and propagating the child exit code, failing closed on a missing,
relative, shallow, symlinked or non-directory root and on a symlinked output
path; `test_bootstrap_smoke.py` covers it with positive and negative
controls (the command itself is mocked in tests, never executed). `actions_identity.py` (stdlib-only, offline)
writes each job's `actions-identity.json`, binding the exact head, run and job
while retaining HOLD/NOT_TESTED/NOT_RUN; `test_actions_identity.py` covers it
with positive and negative controls. `disposable_cleanup.py` (stdlib-only, offline)
removes the allocated download/test roots on success or failure with checked
removal: absolute paths of sufficient depth only, absence is an idempotent
no-op, and a symlinked or regular-file path fails closed and preserves its
target, with each removal verified afterwards; `test_disposable_cleanup.py`
covers it with positive and negative controls. `disposable_locations.py`
(stdlib-only, offline) allocates the download/test roots under the runner
temp as the two `GITHUB_ENV` lines, failing closed on a missing, relative,
shallow, symlinked or non-directory base and on a missing, malformed or
oversized run/attempt identifier, so an unset base cannot silently produce
a filesystem-root child path; `test_disposable_locations.py` covers it
with positive and negative controls. `stdout_evidence.py` (stdlib-only,
offline) captures each evidence command's stdout into its retained file
(`source-binding.json`, `artifact.json`, `root.json`), creating the
evidence directory with parents exactly as the old `mkdir -p` plus `>`
redirect did, but failing closed on a symlinked or non-directory evidence
path, on a non-bare output name, and on a symlinked output; the command
itself is mocked in tests, never executed; `test_stdout_evidence.py`
covers it with positive and negative controls. `source_report.py`
(stdlib-only, offline) composes the source-packet HOLD report — the packet
capture into `source-binding.json`, then the actions identity into
`actions-identity.json` — with fixed argv token-identical to the former
two-line workflow shell, propagating child exit codes fail-fast so a
failing packet never writes an identity; the child commands are mocked in
tests, never executed; `test_source_report.py` covers it with positive
and negative controls. `prevalidation.py`
(stdlib-only, offline) prevalidates wrapper-adaptation item 1 — it compares
an observed identity bundle against the packet's frozen candidate by role
(index, manifest, config, image ID, recovery target, platform, repository)
and fails closed on mismatch, malformed or missing identities, on tag-as-identity,
and on secret-shaped keys — including nested keys, so a secret-shaped
host identity cannot hide one level down under a clean name. An optional
`source_digests` bundle, where
supplied, must name frozen packet files and match their stored digests
exactly by name; unknown names, empty/non-object bundles, tag values and
secret-shaped keys fail closed. An optional `provider_artifacts` bundle,
where supplied, must name only the supported configuration channels
(vertex, aistudio, antigravity, claude, codex, kimi, xai, meta) with
digest values; unknown or secret-shaped channels fail closed. An optional
`compose_config` bundle, where supplied, must name exactly the Compose-file
and rendered-config roles with digest values; a partial bundle conflates
roles and fails closed. An optional `authoritative_store` bundle, where
supplied, must name exactly one supported store backend (file, git,
objectstore, postgres — mirroring the auth source kinds) with a digest
value identifying its canonical scope; naming two backends conflates which
store wins and fails closed. An optional `policy` bundle, where supplied,
must name exactly the three cloak booleans mirrored from
`config.example.yaml` (`disable_codex_cloaking`,
`disable_claude_cloak_mode`, `disable_cloaking_model_list`) with boolean
values; a partial or role-swapped bundle conflates which provider's
cloaking is claimed and fails closed. An optional `quota_cooling`
bundle, where supplied, must name exactly the two quota-cooling
booleans mirrored from `config.example.yaml` (codex
`model-level-cooling` and claude `model-level-cooling`, role-named
with the provider prefix the config sections provide) with boolean
values; a partial or role-swapped bundle conflates which provider's
quota cooling is claimed and fails closed. An optional
`disabled_providers` bundle, where supplied, must name secret-screened
provider names with boolean values (the openai-compatibility
`disabled` flag is per-provider with config-defined names, so there is
no closed key list to mirror); string/digest values and secret-shaped
or malformed names fail closed. An optional `cooldown` bundle, where
supplied, must name exactly the two global-cooldown booleans under
`routing.cooldown` in `config.example.yaml` (`disable-cooling`,
`save-cooldown-status`) with boolean values; per-auth and per-provider
`disable-cooling` overrides are open names like `disabled_providers`,
so this bundle covers only the global section, and the section's
transient-error cooldown duration is not a boolean policy identity —
a partial or role-swapped bundle conflates which cooldown behavior is
claimed and fails closed. An optional `routing` bundle, where
supplied, must name exactly the three routing booleans under the
top-level `routing` section in `config.example.yaml`
(`session-affinity`, `session-affinity-subagents`,
`force-model-prefix`) with boolean values; the section's strategy,
session-affinity-ttl and session-affinity-rebind-on are strings, not
boolean policy identities — a partial or role-swapped bundle conflates
which routing behavior is claimed and fails closed. An optional
`management` bundle, where supplied, must name exactly the three
management booleans under the top-level `management` section in
`config.example.yaml` (`allow-remote`, `disable-control-panel`,
`disable-auto-update-panel`) with boolean values; the section's
secret-key is a secret string, not a boolean policy identity, and
base-url / panel-github-repository are strings — a partial or
role-swapped bundle conflates which management behavior is claimed and
fails closed. An optional `server` bundle, where supplied, must name
exactly the five server booleans under the top-level `server` section
in `config.example.yaml` (`commercial-mode`, `tls.enable`,
`response-compression.enabled`, `discovery.enabled`,
`discovery.auth-required`) with boolean values; the section's host,
port, trusted-proxies, github-token, tls cert/key, compression
min-bytes and discovery service-name/type/subtypes/interfaces are
strings, lists, paths or ints, and `discovery.advertise-management` is
deprecated and ignored — none are named here — a partial or
role-swapped bundle conflates which server behavior is claimed and
fails closed. An optional `client` bundle, where supplied, must name
exactly the four client booleans under the top-level `client` section
in `config.example.yaml` (`codex.enable-apply-patch`,
`codex.optimize-multi-agent-v2`, `codex.web-search-result-cache.
enabled`, `claude.show-codex-commentary`, confirmed in
`internal/config/sdk_config.go`) with boolean values; the
web-search-result-cache ttl and limit are a duration string and an
int, none named here — a partial or role-swapped bundle conflates
which client behavior is claimed and fails closed. An optional
`observability` bundle, where supplied, must name exactly the five
observability booleans under the top-level `observability` section
in `config.example.yaml` (`logs.debug`, `logs.logging-to-file`,
`logs.request-log`, `usage.usage-statistics-enabled`,
`pprof.enable`, confirmed in `internal/config/config.go` and
`internal/config/sdk_config.go`) with boolean values; the
logs-max-total-size-mb and error-logs-max-files are ints, the
redis-usage-queue-retention-seconds is an int, and pprof.addr is a
host:port string — none are named here — a partial or role-swapped
bundle conflates which observability behavior is claimed and fails
closed. An optional `upstream_codex` bundle, where supplied, must
name exactly the five upstream codex booleans under the top-level
`upstream.codex` section in `config.example.yaml`
(`response-steering`, `upstream-request-compression`,
`websocket-compression`, `stream-bootstrap-buffering`,
`orphan-delegation-compatibility`, confirmed in
`internal/config/config_types.go`) with boolean values; the section's
upstream-request-compression-min-bytes is an int and
stream-bootstrap-timeout is a duration string, and
disable-codex-cloaking / model-level-cooling are already bound by the
policy and quota_cooling bundles — none are named here — a partial or
role-swapped bundle conflates which upstream codex behavior is
claimed and fails closed. An optional
`upstream_claude` bundle, where supplied, must name exactly the
upstream claude boolean under the top-level `upstream.claude`
section in `config.example.yaml` (`tool-search`, confirmed in
`internal/config/config_types.go`) with a boolean value; the
section's model-level-cooling, disable-claude-cloak-mode and
disable-cloaking-model-list are already bound by the quota_cooling
and policy bundles, and session-date-pin-days is an int — none are
named here — a partial or role-swapped bundle conflates which
upstream claude behavior is claimed and fails closed. An optional
`plugins` bundle, where supplied, must name exactly the plugins
boolean under the top-level `plugins` section in
`config.example.yaml` (`enabled`, confirmed in
`internal/config/config_types.go`) with a boolean value; the
section's dir is a string, store-sources / store-auth are lists,
auth-revision is an int and configs is an open per-plugin map —
none are named here — a partial or role-swapped bundle conflates
which plugins behavior is claimed and fails closed. Optional
host-only identities are validated only
where supplied; absence leaves the named gate unresolved rather than
defaulting. A match is still BOUND/HOLD with execution not authorized, so it
is an identity gate, not recovery proof; `test_prevalidation.py` covers it
with positive and negative controls. The `Test for deprecated APIs` step re-runs the whole
suite under `-W error::DeprecationWarning` so a version-gated API removal
(host Python 3.12 tolerates what Actions Python 3.13 rejects) fails in
Actions even if a local pre-push on an older interpreter missed it; pre-push
must run that flag locally and must run the workflow test invocations in
direct `python3 -I ...` form, not discover-only. After this extraction no multi-line inline shell
remains in the workflow — every step is a single module invocation. The bootstrap-identity step also dropped its now
redundant `mkdir -p`, which `actions_identity.py` always performed itself
before writing. Hosted-job teardown owns
cancellation cleanup. There is no
persistent preview or recurring idle runtime. Help output is **not service,
journal, watchdog, quiescence, restart, or recovery proof**. All source packet
gates remain unresolved.

### Completed one-shot interrupt diagnostic

At source head `6194ec233e22b68dcdd774cbf3aa5ca78ef38802`, the standard
[Go vet/test/build job passed](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42428321214/job/128571365597).
The previously observed interrupt failure was reproduced separately 20 times on
both pinned sources: `TestResponsesInterruptStopsHTTPUpstream` reported "http
upstream was not canceled" in
[11/20 approved-base executions](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42428321293/job/128571364978)
and [7/20 head executions](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42428321293/job/128571365010).
This establishes pre-existing intermittent failure, not its root cause or a fix.
Those one-shot diagnostic jobs are concluded and no longer run on every source
change. The normal full Go CI remains unchanged and required on every new head;
no SDK/core fix, test skip, continue-on-error or acceptance waiver is included.

## Required wrapper adaptation — orchestration NOT IMPLEMENTED

Continue within this single detached, self-testing wrapper lineage, not a second
installer, scheduler, daemon, journal, or state authority:

1. Prevalidate all source/helper/runbook/parameter, OCI, Compose/config, six provider
   artifact and policy identities without secrets. Unknown host-only values are
   gates. No optional health-check bypass or production default is acceptable.
2. Hold one effective ownership boundary for forward, watchdog and manual recovery.
   Before any recovery write, prove old workers and descendants are terminal and
   queued daemon effects cannot land later. Killing a client process, a fixed
   sleep, or a recovery-only lock is insufficient. A usable native containment and
   daemon-reconciliation mechanism remains unproved.
3. Persist an attempt/package-bound watchdog **ARMED** acknowledgement before stop.
   Launching a watchdog alone is not readiness. Recovery must be independent of
   inference and remain observable if its terminal write fails.
4. Preserve current credentials, the complete latest authoritative journal and
   other required current state as one unit. Never replay an old backup, move away
   `kv.db`, delete claims, or restore only a journal or credentials. Confirm actual
   backend/canonical mount and durability; do not assume a file-store mirror is
   authoritative.
5. Use the exact qualified journal-aware target against current state. Every
   post-stop exit must produce verified adequate service recovery or explicit
   functional failure. Failure to recover is never converted to success by a
   model list, listening port, readiness log, silence, or process restart.
6. Persist a durable package/attempt-bound terminal result with independently
   observable failure if persistence is unavailable. Do not reuse the legacy
   mutable `verified`/`rolledback` string as a receipt.

## Required synthetic qualification matrix — NOT RUN

Generated fake credentials/provider and disposable state only, in Actions. No
production credentials, grants, credential copies, management APIs, default daemon,
second refresh instance, live faults, production backups/restores, install,
host/config/pin changes, or new spend.

| Boundary | Required oracle |
| --- | --- |
| Claim before exchange | Restart never resubmits a claimed grant; provider-call count bounded |
| Exchange before receipt | Uncertainty remains denied; never infer exchange did not occur |
| Receipt before adoption | Valid durable owner receipt adopted without another exchange |
| Later rotation | Latest receipt chain followed; no stale credential/journal replay |
| Pending/expired/malformed/cyclic receipt | Fail closed, no extra provider call |
| Write/sync/rename/durable-binding failure | No exchange before durable claim; no unsafe fallback |
| Competing owners / manual recovery | Common ownership, no concurrent mutation |
| Hang/timeout/SIGKILL/descendant/late daemon effect | Terminal quiescence before recovery writes |
| Missing watchdog readiness | Abort before stop |
| Watchdog/readiness/terminal persistence fault | Adequate verified recovery or independently observable explicit failure |
| Nonstreaming, streaming, tool continuation | Validate useful response content, completed stream, correlated tool result and final continuation, not HTTP 200 alone |
| Disabled providers, cloak, quota resets | Disabled remains disabled; cloak OFF and quota-auto-reset OFF unchanged |
| Codex and local SIWC, where applicable | Actual stock journal behavior, not a duplicate mock algorithm |
| Required service blocked by uncertain grant / defective target | Functional FAIL; route a compatible alternative target decision, never call restart rollback |

Source-inspector unit tests are **not** any of these runtime or journal tests.
Process-kill tests cannot claim power-loss durability. The frozen .60 runtime and
released protocol must be exercised rather than silently substituting the older
repository baseline or a private core backport.

## Release and operations boundary

Source merge is not install acceptance. Exact-artifact Release Manager acceptance
and separately authorized detached host execution remain independent gates. Native
Security then QA/council, exact-head Actions, required checks, Devin, CodeQL,
rulesets, and fresh-context review remain required before source merge. If a merge
has an automatic production path it additionally requires exact-head production
merge approval.

Staging/preview tests must run on demand or scale to zero. Any future environment
must inventory all runtimes, use pipeline-owned startup/readiness bound to the
SHA/environment and a bounded active window, and retain native cleanup/expiry
on success, failure and cancellation. No keep-alive, alarm, schedule, or database
compute may sustain idle recurring runtime cost without a dated explicit spending
exception. This packet provisions no runtime and changes no production resource.

Unproved evidence means HOLD, not permission to repeat an old host drill. If useful
service cannot recover, return functional FAIL and the concrete alternative-target
choice for Engineering through the existing package owner; never select a stale
state or journal-unaware target to meet a deadline.
