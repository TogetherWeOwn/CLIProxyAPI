"""Fake adapters and focused state-machine tests for the fixture controller."""

import ast
import copy
import unittest

import controller as c
import preflight as p
from test_preflight import attempt, envelope

LIVE = {"auth": "fixture-auth-2", "kv": "fixture-kv-2"}
# The fake's own inventory, independent of the controller's tuples.
PATHS = ("fixture-ingress-public", "fixture-ingress-direct", "fixture-backend-direct")
GATES = PATHS + ("fixture-management", "fixture-config-writer", "fixture-plugin-writer", "fixture-reload")


class Fenced(Exception):
    pass


class Interrupted(BaseException):
    """Models process death: the controller must not catch it."""


class Clock:
    def __init__(self):
        self.time = 1000

    def now(self):
        return self.time


class Host:
    """Fake host adapter that referees every safety invariant it can observe."""

    def __init__(self, clock, rollback, candidate):
        self.clock, self.bundle, self.snap = clock, copy.deepcopy(rollback), copy.deepcopy(rollback)
        self.good = [copy.deepcopy(rollback), copy.deepcopy(candidate)]
        self.live = {"auth": "fixture-auth-1", "kv": "fixture-kv-1"}
        self.gates = dict.fromkeys(GATES, "open")
        self.acked, self.active, self.no_ack, self.no_close, self.no_open = set(), {}, set(), set(), set()
        self.stale_ack = set()
        self.token, self.armed, self.issued, self.consumed = None, None, 0, set()
        self.corrupt, self.stale, self.regress = set(), set(), False
        self.calls, self.hooks, self.violations, self.alerts = [], {}, [], []

    def guard(self, verb, token):
        self.calls.append(verb)
        hook = self.hooks.pop((verb, self.calls.count(verb)), None)
        if hook:
            hook()
        if token is None or token != self.token:
            raise Fenced

    def acquire(self, owner, deadline, rollback):
        self.calls.append("acquire")
        if self.token is not None:
            return None
        self.issued += 1
        self.token, self.armed = self.issued, (deadline, copy.deepcopy(rollback))
        return self.token

    def takeover(self, owner):
        if self.armed is None or self.clock.now() < self.armed[0]:
            return None
        self.issued += 1
        self.token, self.armed = self.issued, (self.clock.now() + c.WATCHDOG_DELAY, self.armed[1])
        return self.token, copy.deepcopy(self.armed[1])

    def consume(self, attempt, token):
        self.guard("consume", token)
        unused = attempt not in self.consumed
        self.consumed.add(attempt)
        return unused

    def readback(self, token):
        self.guard("readback", token)
        return copy.deepcopy(self.bundle)

    def snapshot(self, token):
        self.guard("snapshot", token)
        return copy.deepcopy(self.snap)

    def close(self, gate, token):
        self.guard("close", token)
        if gate not in self.no_close:
            self.gates[gate] = "closed"

    def ack(self, gate, token):
        self.guard("ack", token)
        closed, active = self.gates[gate] == "closed", self.active.get(gate, 0)
        if gate in self.no_ack:
            return None
        if gate in self.stale_ack:
            # An ack replayed from an earlier lease generation.
            return {"gate": gate, "closed": closed, "active": active, "token": token - 1}
        if closed and active == 0:
            self.acked.add(gate)
        return {"gate": gate, "closed": closed, "active": active, "token": token}

    def apply(self, bundle, token):
        self.guard("apply", token)
        if set(self.gates.values()) != {"closed"} or self.acked != set(GATES):
            self.violations.append("unquiesced-apply")
        if bundle.keys() != self.bundle.keys():
            self.violations.append("non-release-write")
        self.bundle = copy.deepcopy(bundle)
        if p.digest(bundle) in self.corrupt:
            self.bundle["config"] = p.digest("fixture-partial-write")

    def health(self, token):
        self.guard("health", token)
        return self.bundle in self.good

    def fresh(self, path, token):
        self.guard("fresh", token)
        return self.bundle in self.good and (p.digest(self.bundle), path) not in self.stale

    def open(self, gate, token):
        self.guard("open", token)
        if self.bundle not in self.good:
            self.violations.append("unsafe-reopen")
        if gate not in self.no_open:
            self.gates[gate] = "open"
            self.acked.discard(gate)

    def state(self, gate):
        return self.gates[gate]

    def watch(self, token, seconds):
        self.guard("watch", token)
        self.clock.time += seconds
        return not self.regress

    def disarm(self, token):
        self.guard("disarm", token)
        self.armed = None

    def release(self, token):
        self.guard("release", token)
        if self.armed or set(self.gates.values()) != {"open"} or self.bundle not in self.good:
            self.violations.append("unsafe-unlock")
        self.token = None

    def alert(self, token, outcome):
        self.alerts.append(outcome)


def refresh(host):
    host.live.update(LIVE)


def fixture(number=1):
    data = envelope(number)
    manifest = data["manifest"]
    clock = Clock()
    return p.canonical(data), clock, Host(clock, manifest["rollback"], manifest["candidate"]), manifest


class ControllerTests(unittest.TestCase):
    def run_fixture(self, setup=None, number=1):
        raw, clock, host, manifest = fixture()
        if setup:
            setup(host, manifest)
        outcome = c.Controller(host, clock, "fixture-controller").run(raw, attempt(number))
        return outcome, clock, host, manifest

    def assertUnlocked(self, host):
        self.assertEqual(host.violations, [])
        self.assertEqual((host.token, host.armed), (None, None))
        self.assertEqual(set(host.gates.values()), {"open"})
        self.assertIn(host.bundle, host.good)

    def assertFenced(self, host):
        # Lease ownership and the armed watchdog survive until recovery readback succeeds.
        self.assertEqual(host.violations, [])
        self.assertIsNotNone(host.token)
        self.assertIsNotNone(host.armed)
        self.assertIn("closed", host.gates.values())
        self.assertEqual(host.alerts, ["fixture-recovery-fenced"])
        self.assertNotIn("release", host.calls)

    def assertWatchdogRecovers(self, clock, host, manifest, expected):
        self.assertEqual(c.watchdog(host, clock, "fixture-watchdog"), "fixture-watchdog-idle")
        stale = host.token
        clock.time = host.armed[0]
        self.assertEqual(c.watchdog(host, clock, "fixture-watchdog"), expected)
        self.assertUnlocked(host)
        self.assertEqual(host.bundle, manifest["rollback"])
        with self.assertRaises(Fenced):
            host.apply(manifest["candidate"], stale)
        self.assertEqual(host.bundle, manifest["rollback"])

    def test_release_drains_everything_before_one_apply(self):
        self.assertGreater(c.WATCHDOG_DELAY, c.DRAIN_LIMIT + c.WATCH_SECONDS)
        outcome, _, host, manifest = self.run_fixture()
        self.assertEqual(outcome, "fixture-released")
        self.assertUnlocked(host)
        self.assertEqual(host.bundle, manifest["candidate"])
        n = len(GATES)
        self.assertEqual(host.calls[:4 + 2 * n], ["acquire", "consume", "readback", "snapshot"]
                         + ["close"] * n + ["ack"] * n)
        self.assertEqual(host.calls[4 + 2 * n:], ["apply", "readback", "health"] + ["fresh"] * len(PATHS)
                         + ["open"] * n + ["watch", "disarm", "release"])

    def test_admission_is_exclusive_single_use_and_drift_checked(self):
        for setup, number, expected, calls in (
            (None, 2, "fixture-admission-rejected", []),
            (lambda host, _: setattr(host, "token", 99), 1, "fixture-lease-busy", ["acquire"]),
            (lambda host, _: host.consumed.add(attempt(1)), 1, "fixture-attempt-replayed", None),
            (lambda host, m: host.good.append(host.bundle) or host.bundle.update(image=p.digest("fixture-drift")), 1,
             "fixture-incumbent-drift", None),
            (lambda host, m: host.snap.update(config=p.digest("fixture-drift")), 1, "fixture-incumbent-drift", None),
        ):
            with self.subTest(expected=expected, calls=calls):
                outcome, _, host, _ = self.run_fixture(setup, number)
                self.assertEqual(outcome, expected)
                self.assertFalse({"close", "apply", "open"} & set(host.calls))
                self.assertEqual(host.violations, [])
                if calls is not None:
                    self.assertEqual(host.calls, calls)
                else:
                    self.assertEqual((host.token, host.armed, host.calls[-2:]), (None, None, ["disarm", "release"]))
        raw, clock, host, _ = fixture()
        controller = c.Controller(host, clock, "fixture-controller")
        self.assertEqual(controller.run(raw, attempt(1)), "fixture-released")
        self.assertEqual(controller.run(raw, attempt(1)), "fixture-controller-reused")
        self.assertEqual(c.Controller(host, clock, "fixture-other").run(raw, attempt(1)), "fixture-attempt-replayed")

    def test_missing_or_late_drain_ack_restores_untouched_backend(self):
        cases = [(gate, fault) for gate in GATES for fault in ("no_ack", "stale_ack", "active", "no_close")]
        for gate, fault in cases + [(None, "late")]:
            def setup(host, _):
                if fault == "active":
                    host.active[gate] = 1
                elif fault == "late":
                    host.hooks[("ack", len(GATES))] = lambda: setattr(host.clock, "time", 1000 + c.DRAIN_LIMIT + 1)
                else:
                    getattr(host, fault).add(gate)
            with self.subTest(gate=gate, fault=fault):
                outcome, _, host, manifest = self.run_fixture(setup)
                self.assertEqual(outcome, "fixture-restored")
                self.assertNotIn("apply", host.calls)
                self.assertUnlocked(host)
                self.assertEqual(host.bundle, manifest["rollback"])

    def test_failed_candidate_rolls_back_exactly_and_keeps_live_state(self):
        def unhealthy(host, m):
            host.good.remove(m["candidate"])
        cases = [("unhealthy", unhealthy),
                 ("partial-write", lambda host, m: host.corrupt.add(p.digest(m["candidate"]))),
                 ("regression", lambda host, _: setattr(host, "regress", True))]
        cases += [(path, lambda host, m, path=path: host.stale.add((p.digest(m["candidate"]), path)))
                  for path in PATHS]
        for name, fault in cases:
            def setup(host, m, fault=fault):
                fault(host, m)
                host.hooks[("apply", 1)] = lambda: refresh(host)
            with self.subTest(name=name):
                outcome, _, host, manifest = self.run_fixture(setup)
                self.assertEqual(outcome, "fixture-rolled-back")
                self.assertUnlocked(host)
                self.assertEqual((host.bundle, host.live), (manifest["rollback"], LIVE))
                self.assertEqual(host.calls.count("apply"), 2)
                self.assertEqual(host.calls.count("ack"), 2 * len(GATES))

    def test_unsafe_rollback_or_reopen_keeps_lease_until_watchdog_readback(self):
        def failed_apply():
            raise RuntimeError
        rolled_back = "fixture-rolled-back"
        cases = (
            ("rollback-partial-write", lambda host, m: host.corrupt.add(p.digest(m["rollback"])), 2, rolled_back),
            ("rollback-apply-error", lambda host, _: host.hooks.update({("apply", 2): failed_apply}), 2, rolled_back),
            ("recovery-drain-ack-missing", lambda host, _: host.hooks.update(
                {("ack", len(GATES) + 1): lambda: host.no_ack.add(GATES[0])}), 1, "fixture-rolled-back"),
            ("reopen-blocked", lambda host, _: host.no_open.add(GATES[0]), 2, "fixture-restored"),
        )
        for name, fault, applies, recovered in cases:
            def setup(host, m, fault=fault):
                if name != "reopen-blocked":
                    host.good.remove(m["candidate"])
                fault(host, m)
                host.hooks[("apply", 1)] = lambda: refresh(host)
            with self.subTest(name=name):
                outcome, clock, host, manifest = self.run_fixture(setup)
                self.assertEqual(outcome, "fixture-recovery-fenced")
                self.assertFenced(host)
                self.assertEqual(host.calls.count("apply"), applies)
                host.corrupt.clear()
                host.no_ack.clear()
                host.no_open.clear()
                self.assertWatchdogRecovers(clock, host, manifest, recovered)
                self.assertEqual(host.live, LIVE)

    def test_watchdog_recovers_interrupts_and_fences_stale_controller(self):
        for verb, count, recovered in (
            ("consume", 1, "fixture-restored"), ("close", 3, "fixture-restored"),
            ("ack", len(GATES), "fixture-restored"), ("apply", 1, "fixture-restored"),
            ("health", 1, "fixture-rolled-back"), ("open", 4, "fixture-rolled-back"),
            ("watch", 1, "fixture-rolled-back"), ("disarm", 1, "fixture-rolled-back"),
        ):
            def setup(host, _):
                def interrupt():
                    raise Interrupted
                host.hooks[(verb, count)] = interrupt
            with self.subTest(verb=verb):
                raw, clock, host, manifest = fixture()
                setup(host, manifest)
                with self.assertRaises(Interrupted):
                    c.Controller(host, clock, "fixture-controller").run(raw, attempt(1))
                self.assertNotIn("release", host.calls)
                self.assertIsNotNone(host.token)
                self.assertWatchdogRecovers(clock, host, manifest, recovered)
        watchdog = []

        def takeover(host):
            host.clock.time = host.armed[0]
            watchdog.append(c.watchdog(host, host.clock, "fixture-watchdog"))
        outcome, _, host, manifest = self.run_fixture(
            lambda host, _: host.hooks.update({("health", 1): lambda: takeover(host)}))
        self.assertEqual(outcome, "fixture-recovery-fenced")
        self.assertEqual((watchdog, host.alerts), (["fixture-rolled-back"], ["fixture-recovery-fenced"]))
        self.assertUnlocked(host)
        self.assertEqual(host.bundle, manifest["rollback"])

    def test_controller_source_has_no_host_reach(self):
        with open(c.__file__, encoding="ascii") as source:
            tree = ast.parse(source.read())
        nodes = list(ast.walk(tree))
        imports = {alias.name for node in nodes if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imports, {"json", "preflight"})
        self.assertFalse([node for node in nodes if isinstance(node, ast.ImportFrom)])
        names = {node.id for node in nodes if isinstance(node, ast.Name)}
        self.assertFalse(names & {"open", "eval", "exec", "compile", "__import__", "getattr", "globals", "__name__"})


if __name__ == "__main__":
    # Hosted logs report a fixed verdict without test data or exception details.
    result = unittest.defaultTestLoader.loadTestsFromTestCase(ControllerTests).run(unittest.TestResult())
    passed = result.testsRun > 0 and result.wasSuccessful() and not (result.skipped or result.expectedFailures)
    print("fixture-controller-pass" if passed else "fixture-controller-fail")
    raise SystemExit(0 if passed else 1)
