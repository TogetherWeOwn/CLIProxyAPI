"""Offline fixture controller for one CLIProxy release cutover.

The controller drives only the adapter object it is given. This module has no
host, network, process, file or environment access. The tests supply fakes.
"""

import json

import preflight

# Both ingress instances and direct backend callers, then every modeled writer.
PATHS = ("fixture-ingress-public", "fixture-ingress-direct", "fixture-backend-direct")
WRITERS = ("fixture-management", "fixture-config-writer", "fixture-plugin-writer", "fixture-reload")
GATES = PATHS + WRITERS
DRAIN_LIMIT = 60
WATCH_SECONDS = 1800
# The watchdog deadline covers the drain, the post-reopen watch and recovery.
WATCHDOG_DELAY = 3600


def fenced(host, token):
    """Close every gate, continuing past failures, then judge only by every gate's readback."""
    for gate in GATES:
        try:
            host.close(gate, token)
        except Exception:
            pass
    try:
        return [host.state(gate) for gate in GATES] == ["closed"] * len(GATES)
    except Exception:
        return False


def drained(host, clock, token):
    """Close every gate, then require an ack bound to this lease and this drain from each."""
    deadline = clock.now() + DRAIN_LIMIT
    if not fenced(host, token):
        return False
    drain = host.drain(token)
    acks = [host.ack(gate, token, drain) for gate in GATES]
    expected = [{"gate": gate, "closed": True, "active": 0, "token": token, "drain": drain} for gate in GATES]
    # Canonical JSON keeps a boolean from standing in for an integer lease or drain id.
    return [preflight.canonical(ack) for ack in acks] == [preflight.canonical(ack) for ack in expected] and (
        clock.now() <= deadline)


def healthy(host, token, bundle):
    """Exact readback, readiness and a fresh isolated probe request on every path."""
    if host.readback(token) != bundle or host.health(token) is not True:
        return False
    return all(host.fresh(path, token) is True for path in PATHS)


def reopened(host, token, bundle):
    """Reopen request paths only while every writer reads back fenced, recheck, then reopen writers."""
    for writer in WRITERS:
        host.close(writer, token)
    if [host.state(writer) for writer in WRITERS] != ["closed"] * len(WRITERS):
        return False
    for path in PATHS:
        host.open(path, token)
    if [host.state(path) for path in PATHS] != ["open"] * len(PATHS) or host.readback(token) != bundle:
        return False
    for writer in WRITERS:
        host.open(writer, token)
    return [host.state(gate) for gate in GATES] == ["open"] * len(GATES) and host.readback(token) == bundle


def unlock(host, token, outcome):
    """Release the lease, which also disarms the watchdog in one host transition."""
    try:
        host.release(token)
        return outcome
    except Exception:
        # The armed watchdog still owns recovery; an unconfirmed release is never a success.
        host.alert(token, "fixture-unlock-failed")
        return "fixture-unlock-failed"


def recover(host, clock, token, rollback, phase):
    """Recover from the lease phase: admitted, fenced (gates closed) or mutated (backend written).

    An admitted attempt touched nothing. A fenced one reopens an untouched backend. A mutated
    one fences first and restores the exact rollback. The lease, watchdog and fence stay in
    place unless recovery readback proves the result. An unknown phase stays fenced.
    """
    if phase == "admitted":
        return unlock(host, token, "fixture-unchanged")
    try:
        if phase == "fenced":
            # An undrained writer may change the backend; serve it only if healthy and unchanged.
            current = host.readback(token)
            if healthy(host, token, current) and reopened(host, token, current):
                return unlock(host, token, "fixture-restored")
        elif phase == "mutated" and drained(host, clock, token):
            if host.readback(token) != rollback:
                # Only release-owned files are written, so live auth and KV stay current.
                host.apply(rollback, token)
            if healthy(host, token, rollback) and reopened(host, token, rollback):
                return unlock(host, token, "fixture-rolled-back")
    except Exception:
        pass
    outcome = "fixture-recovery-fenced" if fenced(host, token) else "fixture-fence-breached"
    host.alert(token, outcome)
    return outcome


def lease_phase(host, token):
    """The host's record of the lease phase; an unreadable phase is unknown and stays fenced."""
    try:
        return host.phase(token)
    except Exception:
        return None


def watchdog(host, clock, owner):
    """Independent recovery. The host grants a fencing takeover only after the armed deadline.

    Recovery then follows the lease phase the host recorded for gate closes and backend writes.
    """
    try:
        claim = host.takeover(owner)
    except Exception:
        host.alert(None, "fixture-watchdog-failed")
        return "fixture-watchdog-failed"
    if claim is None:
        return "fixture-watchdog-idle"
    token, rollback = claim
    return recover(host, clock, token, rollback, lease_phase(host, token))


class Controller:
    def __init__(self, host, clock, owner):
        self.host, self.clock, self.owner = host, clock, owner
        self.used = False

    def run(self, raw, attempt):
        if self.used:
            return "fixture-controller-reused"
        self.used = True
        if preflight.verify(raw, attempt) != "fixture-match":
            return "fixture-admission-rejected"
        manifest = json.loads(raw.decode("ascii"))["manifest"]
        rollback = manifest["rollback"]
        # The host grants the lease only when it is free and every gate is open, and the grant
        # atomically arms the watchdog with the exact rollback. Recovery may therefore reopen
        # any gate it closed without lifting a fence that predates the attempt.
        token = self.host.acquire(self.owner, self.clock.now() + WATCHDOG_DELAY, rollback)
        if token is None:
            return "fixture-lease-refused"
        try:
            outcome = self.cutover(token, attempt, manifest["candidate"], rollback)
        except Exception:
            outcome = None
        if outcome is None:
            # Recover from the host's record, not local intent.
            return recover(self.host, self.clock, token, rollback, lease_phase(self.host, token))
        return unlock(self.host, token, outcome)

    def cutover(self, token, attempt, candidate, rollback):
        host = self.host
        if not host.consume(attempt, token):
            return "fixture-attempt-replayed"
        if host.readback(token) != rollback or host.snapshot(token) != rollback:
            return "fixture-incumbent-drift"
        # Recheck after quiescence: a writer may have changed the incumbent during the drain.
        if not drained(host, self.clock, token) or host.readback(token) != rollback:
            return None
        host.apply(candidate, token)
        if healthy(host, token, candidate) and reopened(host, token, candidate):
            if host.watch(token, WATCH_SECONDS) is True:
                return "fixture-released"
        return None
