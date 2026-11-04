# Raw availability observations — v1 component

`host_recovery/availability.py` records independently supplied point probes into
one explicit private evidence directory. It has no network client, endpoint,
credential acquisition, live defaults, background sampler, schedule or recovery
permission. It is not yet wired to a persistent supervisor or a full-system drill.
The disposable HTTP test uses only a newly created synthetic child listener.

## Capture and ownership

Construct `AvailabilityRecorder` with an already-open empty directory descriptor,
an attempt ID, two SHA-256 pins (`probe_revision` and `target_sha256`), and explicit
monotonic clock/boot-ID readers. `probe_revision` identifies exact probe source
bytes, not a tag. `target_sha256` identifies an independently approved restricted
target/artifact descriptor; the descriptor and its secrets are not written here.
These pins establish correspondence only, not authenticated approval or proof that
the supplied probe measures that target. Actual artifact/container/source binding
and approved runtime probe authority remain integration prerequisites.

The directory must be private (0700), owned by the calling numeric UID/GID, have
no unsupported xattrs and contain no entries. The caller retains its descriptor,
protects its ancestry and excludes competing writers through its evidence-owner
boundary. This is **not another installation lock**. Never use the installation
journal, baseline, content, live config or credential directory as this evidence
root. No directory, permission or existing artifact is modified at construction.
A new `availability.json` is written only after these checks; an already populated
root refuses rather than overwriting an earlier trace.

`observe(probe)` captures start/end times around one synchronous invocation.
Exactly `True` means an observed available result; exactly `False` means an
observed unavailable result. `None`, any other return value or an ordinary probe
exception means **unknown**, not green or an observed outage. Exception messages,
return payloads, paths, endpoint strings, bodies and credentials are not retained.
The caller must define and authenticate the probe's availability semantics.

Every update uses the existing restricted atomic write, file fsync, rename,
directory fsync and readback primitive. Saved bytes, in-memory prior observations,
root identity, ownership and inventory are revalidated around probes and clocks.
Boot/clock continuity is checked after persistence as well as around probes.
Observed drift, reentrancy, ambiguous storage or the 4096-sample limit permanently
revokes the instance. There is no automatic retry, reopening or new epoch. A
process killed inside a probe leaves its earlier prefix with an open sampling
window; it does not invent a successful or failed result for the unfinished call.

`finish()` explicitly closes the sampling window and returns the exact trace
hash **only after** successful final persistence/readback and continuity checks.
The window-end timestamp is the explicit end-of-observation boundary before that
final write, not the end of fsync/receipt delivery or recovery. A visible closed
file alone cannot prove its directory fsync succeeded: a post-rename failure can
leave those bytes without any successful completion receipt. Keep the successful
receipt separately with the drill's authenticated evidence ledger. The hash is
not a signature and a caller-constructed matching receipt supplies no authority.

This component does not interrupt a wedged probe/filesystem or enforce a phase
cap. The actual manager-owned sampler must enforce its inclusive deadline and
record interrupted/unobservable tails, rather than assume a callback is bounded.
Capture persistence itself must be charged in the integrated timing ledger. No
probe deadline changes are made to inference or upstream networking.

## Summary and censoring

`summarize(raw_bytes)` strictly validates the schema, pins, finite positive clock
values, sequence, non-overlapping ordered observations and explicit window
boundaries. Duplicate JSON keys, nonfinite numbers, booleans in numeric fields,
unknown fields/outcomes and reordered/overlapping samples refuse. It describes
raw evidence only; it does not authenticate the trace's origin or persistence.

The summary contains:

- Available/unavailable/**unknown** observation counts, exact window start/end,
  maximum completed probe duration and largest **observed** unsampled gap. An
  unfinished window also has `unsampled_tail_unbounded: true`; the reported finite
  maximum never bounds that open tail.
- Runs of consecutive observed unavailable samples, with first/last sequence and
  completion times, surrounding observed-available completion times where known,
  and explicit left/right censor flags. A closed observation window is not a
  recovery observation; its last negative streak remains right-censored.
- Unknown samples break negative streaks and discard an earlier available bracket.
  A later green cannot erase the unknown interval or retroactively close the
  earlier right-censored streak.
- **No continuous downtime estimate.** Discrete failures do not prove an
  uninterrupted outage between samples, and two green samples can hide an outage.
  Thus `continuous_coverage_proven` is false and `continuous_downtime_seconds` is
  null, even for a closed/all-green trace. Each negative run has only the trivial
  duration lower bound zero and **null** upper bound, including bracketed runs.
  Brackets are observation windows, not accepted outage-duration confidence bounds.
  A separately justified continuity model must be explicit in later analysis;
  this component does not silently assume one.

Monotonic values never cross boots. A changed boot refuses and retains the
original prefix; no epoch is reset to make time appear shorter. Host-down
wall-clock observations require a separate independent source and stay unknown
here. Suite duration, HTTP loopback time and observation-window duration are not
recovery time, alert time, full-service downtime or production ceilings.

All raw records, summaries and completion receipts have
`production_acceptance: false`. They grant no start, restoration, settlement,
source-completeness/drain, notification or release authority.

## Verification boundary

Tests use deterministic clocks for ordering/censoring and real private files for
persistence. Fresh contexts assert reached EIO/ENOSPC hooks at begin, observation
and final completion (create/write/file-fsync/rename/directory-fsync/readback).
A final-write boot change cannot produce a completion receipt, even when closed
bytes are visible. Actual subprocess SIGKILL retains an open prefix. A disposable
HTTP child produces a real success/failure/success sequence with raw timestamps.
These are sampling/filesystem component tests, **not a systemd/Docker recovery
matrix, source-bound producer test, measured phase allocation or downtime proof**.
Persistent orchestration, independently enforced probe deadlines, operational
source/role binding and full-system availability evidence remain due.
