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


def drained(host, clock, token):
    """Close every gate, then require a fresh, lease-bound quiescence ack from each."""
    deadline = clock.now() + DRAIN_LIMIT
    for gate in GATES:
        host.close(gate, token)
    acks = [host.ack(gate, token) for gate in GATES]
    expected = [{"gate": gate, "closed": True, "active": 0, "token": token} for gate in GATES]
    return acks == expected and clock.now() <= deadline


def healthy(host, token, bundle):
    """Exact readback, readiness and a fresh isolated probe request on every path."""
    if host.readback(token) != bundle or host.health(token) is not True:
        return False
    return all(host.fresh(path, token) is True for path in PATHS)


def reopened(host, token):
    for gate in reversed(GATES):
        host.open(gate, token)
    return all(host.state(gate) == "open" for gate in GATES)


def unlock(host, token, outcome):
    host.disarm(token)
    host.release(token)
    return outcome


def recover(host, clock, token, rollback):
    """Restore the exact rollback and keep the lease and fence unless readback proves it."""
    try:
        outcome = "fixture-restored"
        if host.readback(token) != rollback:
            outcome = "fixture-rolled-back" if drained(host, clock, token) else None
            if outcome:
                # Only release-owned files are written, so live auth and KV stay current.
                host.apply(rollback, token)
        if outcome and healthy(host, token, rollback) and reopened(host, token):
            return unlock(host, token, outcome)
    except Exception:
        pass
    host.alert(token, "fixture-recovery-fenced")
    return "fixture-recovery-fenced"


def watchdog(host, clock, owner):
    """Independent recovery. The host grants a fencing takeover only after the armed deadline."""
    claim = host.takeover(owner)
    return "fixture-watchdog-idle" if claim is None else recover(host, clock, *claim)


class Controller:
    def __init__(self, host, clock, owner):
        self.host, self.clock, self.owner, self.used = host, clock, owner, False

    def run(self, raw, attempt):
        if self.used:
            return "fixture-controller-reused"
        self.used = True
        if preflight.verify(raw, attempt) != "fixture-match":
            return "fixture-admission-rejected"
        manifest = json.loads(raw.decode("ascii"))["manifest"]
        rollback = manifest["rollback"]
        # The lease grant atomically arms the watchdog with the exact rollback.
        token = self.host.acquire(self.owner, self.clock.now() + WATCHDOG_DELAY, rollback)
        if token is None:
            return "fixture-lease-busy"
        try:
            outcome = self.cutover(token, attempt, manifest["candidate"], rollback)
        except Exception:
            outcome = None
        if outcome is None:
            return recover(self.host, self.clock, token, rollback)
        return unlock(self.host, token, outcome)

    def cutover(self, token, attempt, candidate, rollback):
        host = self.host
        if not host.consume(attempt, token):
            return "fixture-attempt-replayed"
        if host.readback(token) != rollback or host.snapshot(token) != rollback:
            return "fixture-incumbent-drift"
        if not drained(host, self.clock, token):
            return None
        host.apply(candidate, token)
        if healthy(host, token, candidate) and reopened(host, token):
            if host.watch(token, WATCH_SECONDS) is True:
                return "fixture-released"
        return None
