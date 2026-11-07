# Recovery-only daemon authorization decision engine v1

**Source component, not an installed or complete host fence.** No service, Docker
plugin, credential, daemon configuration or host permission is installed/changed.
The module does not expose an HTTP/Unix listener and has not been exercised against
an actual Docker daemon. Only repository-owned synthetic protocol objects and
fresh private temporary directories are used by its tests.

## Scope

`host_recovery/fence.py` implements a deny-first subset of the Docker authorization
plugin request/response decision interface. It addresses a specific gap in the
existing adapters: killing a Docker CLI helper or a systemd mutator does not cancel
a daemon-owned operation, and a callback claiming `True` is not a start fence.

This engine has **no start, create, restart, update, exec, archive, remove, rename,
attach, generic command, installation or unrestricted API grant**. Unknown routes,
API versions, methods, schemas, users, duplicate/case-conflicting headers, bodies,
query variants, shortened IDs and encoded/traversing paths fail closed. It must not
be enabled on a shared or production daemon as a way to test it: denying unknown
operations would disrupt unrelated workloads.

## Internal supervisor surface

The installation-lock owner serializes every method and supplies an existing
private Journal, pinned TLS principal, exact API version and same-boot clock.
Package/manifest approval, old-image pin authentication and actual manager identity
must already have been verified by admission; this engine does not authenticate
those approvals merely by hashing their values.

1. `bind`: accept the full old-object/old-image pins plus candidate records already
   durably registered in the current journal. No candidate discovery, label-only
   authorization, short ID or implicit current-container lookup.
2. `prepare_kill`: require durable arm and revoked forward eligibility, then a
   strict projected inspection of a running bound object with exact image and
   candidate ownership, no restart/auto-remove, no paused/restarting/dead state.
   Allocate a single bounded-deadline exact `POST`/full-ID/`signal=KILL` operation.
   Preparation is **not** a daemon permission or a stop acknowledgment.
3. `request`: before allowing that exact request, consume the plan, record a
   pending operation with fsync/rename/directory-fsync/readback, and recheck its
   inclusive deadline. Never allow another mutation while pending or uncertain.
4. `response`: correlate the authenticated request callback and durably record
   return. Neither a 2xx nor an error response establishes stopped state or clears
   pending work. Raw daemon bodies/headers are not retained in these receipts.
5. `reconcile_stopped`: require that return plus a new strict inspection of the
   same full object/image/ownership, now stopped. Durably record that observation
   before clearing in-memory pending work. This remains an injected observation
   in component tests, not proof of an actual daemon stop.
6. `seal`: irreversibly revoke unconsumed plans/new kill admission. It cannot cancel
   or discard an authorized operation. Local `pending_drained` is possible only
   after sealing and separately reconciling any pending operation, with no journal,
   clock, receipt or boot uncertainty. It is **not** a host start/restore grant.

The operation header is a correlation ID, **not a credential**. Authority comes
from the pinned principal in authenticated daemon-supplied `User` and
`UserAuthNMethod=TLS` fields, conveyed over a trusted plugin channel. An empty Unix
API user, a header alone, and arbitrary caller-supplied JSON do not authenticate a
supervisor. This source provides no TLS setup, certificate creation, rotation or
fallback to broad local socket permissions.

Only bound full-ID `GET .../json` inspection is also allowed for that principal.
The intended narrow host broker must consume/project this restricted inspection;
the engine is not a general-purpose read proxy and does not publish inspection
bodies. CLI negotiation/list/discovery routes are not silently allowed. The
existing CLI-based daemon adapter is **not wired to this decision engine**.

## Failure and restart semantics

- Every pending/return/observed-stop persistence fault, including destination bytes
  visible after rename but failed directory-fsync/readback, retains pending/unknown
  state and closes mutation admission. Independent notification is still a
  supervisor responsibility; the authorizer does not pretend it delivered one.
- A late/lost response cannot become success by repeating the request. Callback
  loss is not daemon cancellation. There is no timeout-based pending-state deletion.
- Original intent and operation evidence remain. A new engine cannot overwrite
  another engine's operation evidence or adopt completed-looking receipts to
  reopen admission. Missing/unexpected operation files also close admission.
- Clock regression/boot discontinuity closes admission without resetting a budget.
  Reopening a Journal always requires separate recovery reconciliation. There is
  no implemented protocol to adopt rediscovered candidates, retire the latch,
  grant original/candidate start or resume forward promotion after restart.
- Persistence helpers can block on an unavailable filesystem. Returned local
  deadlines are accounting, not a hard-real-time manager watchdog. No on-time
  recovery or availability measurement is inferred from test runtime.

## Prerequisites that remain unsatisfied

A deployed daemon authorization plugin can independently deny HTTP API starts only
when its trusted service, exhaustive daemon registration and fail-closed lifecycle
are actually established. This component does **not** prove or provide them.
Docker daemon-internal restore/restart paths may not call HTTP authorization.
Neither `restart=no` nor a deny-all HTTP start policy alone proves the boot fence.

Still required: persistent manager-owned supervisor/recovery service; trusted
bounded plugin transport; authenticated narrow broker dispatch; complete exclusion
of every alternate daemon endpoint/manager/writer; daemon-internal restart/boot
interlock and pending-request reconciliation; safe settlement/continuation; and
full stopped-baseline semantic verification before any separately authorized old
start. Do not substitute this source or its `pending_drained` flag for the existing
adapters' independently enforced start-fence prerequisite.

Every status retains `daemon_configuration_verified: false`,
`internal_restart_fenced: false`, `installation_start_fence_proven: false` and
`production_acceptance: false`. Actual disposable daemon callback compatibility,
startup races, lost replies, daemon restart, manager/cgroup and full-package timing
must be tested later in an approved environment, never on the live host.

**REA angle:** use the daemon's existing authorization decision boundary rather
than pretend CLI process ownership contains daemon work. Source-only protocol and
persistence tests establish conservative component behavior; they do not establish
that the daemon invokes that boundary on every relevant path.
