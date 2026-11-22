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
    """Close every gate, continuing past failures, then verify every gate reads back closed."""
    closed = True
    for gate in GATES:
        try:
            host.close(gate, token)
        except Exception:
            closed = False
    try:
        return closed and all(host.state(gate) == "closed" for gate in GATES)
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
    # Releasing the lease also disarms the watchdog in one host transition.
    host.release(token)
    return outcome


def recover(host, clock, token, rollback, mutated):
    """Reopen an untouched backend. Otherwise fence first, then restore the exact rollback.

    The lease, watchdog and fence stay in place unless recovery readback proves the result.
    """
    try:
        if not mutated:
            # A writer may have changed the backend before quiescence; serve it only if healthy.
            if healthy(host, token, host.readback(token)) and reopened(host, token):
                return unlock(host, token, "fixture-restored")
        elif drained(host, clock, token):
            if host.readback(token) != rollback:
                # Only release-owned files are written, so live auth and KV stay current.
                host.apply(rollback, token)
            if healthy(host, token, rollback) and reopened(host, token):
                return unlock(host, token, "fixture-rolled-back")
    except Exception:
        pass
    outcome = "fixture-recovery-fenced" if fenced(host, token) else "fixture-fence-breached"
    host.alert(token, outcome)
    return outcome


def watchdog(host, clock, owner):
    """Independent recovery. The host grants a fencing takeover only after the armed deadline.

    The claim says whether any backend write began under the lease.
    """
    claim = host.takeover(owner)
    return "fixture-watchdog-idle" if claim is None else recover(host, clock, *claim)


class Controller:
    def __init__(self, host, clock, owner):
        self.host, self.clock, self.owner = host, clock, owner
        self.used = self.mutated = False

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
            return recover(self.host, self.clock, token, rollback, self.mutated)
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
        self.mutated = True
        host.apply(candidate, token)
        if healthy(host, token, candidate) and reopened(host, token):
            if host.watch(token, WATCH_SECONDS) is True:
                return "fixture-released"
        return None
