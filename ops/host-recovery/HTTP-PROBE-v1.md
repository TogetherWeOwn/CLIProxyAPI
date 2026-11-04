# Request-origin HTTP tool probe — component contract

**Offline source, not live-probe permission or replay acceptance.** The supplied
transport connects only to an explicitly selected literal loopback port and fixed
`/v1/messages` route. No server, producer, container or host unit is installed or
started by this module. Tests start their own synthetic ephemeral HTTP fixture;
they do not address a live CLIProxy listener. Do not point this transport at an
existing host listener. A later authorized runtime endpoint/credential boundary
and source/artifact/manager integration remain required.

## Two real requests, not normalized log IDs

`host_recovery.probe.TwoTurnProbe` creates fresh UUIDs for the probe, the two
requests and the first-turn tool nonce. It refuses identity collisions and can run
only once. Both POSTs carry the exact five reviewed `X-CPA-Recovery-*` fields;
the second request has its own request ID and the first request's ID as parent.
The requested model remains identical in both bodies. Diagnostic IDs are not
credentials and never select auth.

The supported wire shape is a strict nonstream Messages subset. Turn one must
return exactly one `cpa_recovery_echo` tool use, with the actual nonce and a bounded
valid tool ID. Unknown blocks, coercions, duplicate JSON fields, truncated JSON,
wrong tools/arguments, extra calls, non-200 status and unsupported stop reasons
refuse. Admitted text/thinking/signature/redacted-thinking/tool-use blocks are
copied unchanged into turn two; the probe invents no reasoning/signature content.
Unsupported valid provider features still refuse: this is not a general-purpose
Messages client or permission to alter accepted policy to fit this subset.

After receiving and persisting the first response, the local probe generates a
**fresh confirmation value absent from the initial prompt/tool input**. It returns
the nonce and confirmation as a `tool_result` referencing the exact observed tool
ID. Turn two must end with the exact confirmation text and no further tool call.
Repeating the initial nonce without the actual tool-result value cannot pass.
This establishes observed HTTP/tool conversation linkage in this client; it does
not prove the provider's internal reasoning, replay decisions or source identity.

## Persistence and deadline handling

`ProbeSpool` borrows an already-open empty private directory descriptor. The caller
must retain the installation lock, independently approve ancestry and exclude
writers through its `check(deadline=...)` boundary. The spool creates six restricted
artifacts: separate diagnostic carrier, exact request body and exact response body
for each turn. Authorization is never put into the carrier artifact. Body data is
restricted: do not attach raw bodies from a real runtime to public receipts; an
untrusted server can echo sensitive data in its response.

Each artifact is written/fsynced/renamed/directory-fsynced/read back before the next
phase. All earlier artifact hashes/ownership/modes and the exact entry set are
rechecked. Failure/ambiguity poisons the instance and preserves files/staging for
reconciliation, not retry or overwrite. A failed first response persistence cannot
send turn two. This is raw capture, not a durable recovery terminal/alert receipt.

`LoopbackMessages` uses a fresh isolated Python helper per POST, clean environment,
`cwd=/`, stdin-only request/optional explicit synthetic token, bounded input/output
and no shell, proxy, redirect or retry. It never reads credentials/config from
files, environment or management APIs. Only literal IPv4/IPv6 loopback is supported;
no caller-supplied URL, path or DNS resolution is accepted. JSON media type and
unambiguous bounded framing are required. The helper sets no established-upstream
socket timeout; the parent meters its local pipe/process wait against the original
inclusive monotonic deadline and kills the helper on ambiguity/expiry. Helper death
**does not cancel inference or prove server/cgroup quiescence, log delivery or
producer drain**. Pending child handles are retained for later bounded reaping;
manager-owned cgroup/descendant cleanup and package/interpreter authentication are
not implemented by this transport. No new network timeout in a server executor is
introduced. This subprocess path is a synthetic test transport, not the missing
operational supervisor or narrow privileged dispatch.

## Receipt boundaries

The secret-free `host-recovery-http-probe-v1` receipt contains IDs, requested model,
observed HTTP response models, two statuses, monotonic request intervals, raw
artifact hashes, tool/nonce/confirmation hashes and explicit source/artifact pins.
These pins are supplied comparison inputs, **not authenticated installation or
source-to-artifact observations**. An HTTP response's model field is not relabeled
as the producer's prepared upstream `resolved_model`.

`http_tool_linkage_observed` may be true. These remain **false**:

- `source_artifacts_authenticated`
- `producer_drained`
- `collection_complete`
- `replay_accepted`
- `production_acceptance`

The probe does not create producer events, attach current IDs to arbitrary logs,
construct container provenance, satisfy retained replay/model policy, infer drain
from HTTP completion or unlock startup. The existing prefix collector/verifier
remains non-accepting. Real ingress/executor/RPC/merged-producer/container mapping,
all declared source coverage and a genuine asynchronous completion boundary must
be integrated separately. No current producer package was loaded/executed for
these tests. Persistent recovery, the complete boot/internal-restart/start/writer/
pending-operation fence and the independent full baseline/start oracle remain due.

## Retained negative evidence

The first implementation accepted a second response repeating the nonce already
present in the initial prompt. A reached regression demonstrated that false green;
exact pre-fix source/test and raw red/green output are retained with this checkpoint.
The fix generates the separate tool-result confirmation only after turn one. This
is a new-path defect/fix, not evidence that the prior recovery/producer packages
were run or changed.
