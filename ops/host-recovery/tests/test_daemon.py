"""Scripted daemon CLI responses only; no Docker socket or daemon is used."""
import unittest

from host_recovery import commands, daemon, durable
from test_recovery_state import intent


def row(object_id="a" * 64, running=False):
    value = intent()
    return {"object_id": object_id, "image_id": "sha256:" + ("e" * 64 if object_id == value["old_object_id"] else value["candidate_image_id"]),
            "running": running, "paused": False, "restarting": False, "dead": False,
            "status": "running" if running else "exited", "restart_policy": "no", "restart_retries": 0,
            "auto_remove": False, "installation_id": value["installation_id"], "ownership_id": value["attempt_id"]}


class ScriptedDocker:
    def __init__(self):
        self.calls = []
        self.lists = [["a" * 64], ["a" * 64]]
        self.rows = {"a" * 64: row(), intent()["old_object_id"]: row(intent()["old_object_id"])}
        self.failure = None
        self.after_kill = None

    def run(self, argv, *, deadline):
        if deadline != 50:
            raise AssertionError("inclusive deadline lost")
        self.calls.append(argv)
        if self.failure:
            raise self.failure
        if "ls" in argv:
            return ("\n".join(self.lists.pop(0)) + "\n").encode() if self.lists[0] else self._empty_list()
        if "inspect" in argv:
            value = self.rows[argv[-1]]
            return value if type(value) is bytes else durable.canonical(value)
        if "kill" in argv:
            object_id = argv[-1]
            if self.after_kill:
                self.after_kill(self, object_id)
            else:
                self.rows[object_id] = {**self.rows[object_id], "running": False, "status": "exited"}
            return (object_id + "\n").encode()
        raise AssertionError("unexpected operation")

    def _empty_list(self):
        self.lists.pop(0)
        return b""


class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.value = intent()
        self.transport = ScriptedDocker()
        self.fences = [True, True]
        self.time = 1
        self.engine = daemon.DockerObjects(docker="/accepted/docker", endpoint="unix:///accepted/disposable.sock",
                                           commands=self.transport, intent=self.value, old_image_id="e" * 64,
                                           start_fence=lambda: self.fences.pop(0), clock=lambda: self.time)

    def test_exact_full_ids_and_both_ownership_filters_are_used(self):
        got = self.engine.owned_candidates(deadline=50)
        self.assertEqual(got, [{"object_id": "a" * 64, "image_id": self.value["candidate_image_id"],
                                "ownership_id": self.value["attempt_id"], "running": False, "restart_policy": "no"}])
        listing, inspection, again = self.transport.calls
        self.assertEqual(listing[:2], ("/accepted/docker", "--host=unix:///accepted/disposable.sock"))
        self.assertIn("--no-trunc", listing)
        self.assertIn("--filter=label=" + daemon.INSTALLATION_LABEL + "=" + self.value["installation_id"], listing)
        self.assertIn("--filter=label=" + daemon.ATTEMPT_LABEL + "=" + self.value["attempt_id"], listing)
        self.assertEqual(inspection[-1], "a" * 64)
        self.assertEqual(listing, again)
        self.assertNotIn("Env", inspection[-2])
        self.assertNotIn("Mounts", inspection[-2])

    def test_stopped_old_and_all_candidates_are_checked_without_mutation(self):
        self.assertTrue(self.engine.quiesce(deadline=50))
        self.assertFalse(any("kill" in argv for argv in self.transport.calls))
        self.assertEqual(sum("inspect" in argv for argv in self.transport.calls), 4)

    def test_old_and_daemon_owned_candidate_are_killed_and_reinspected(self):
        for object_id in self.transport.rows:
            self.transport.rows[object_id] = row(object_id, running=True)
        self.assertTrue(self.engine.quiesce(deadline=50))
        kills = [argv for argv in self.transport.calls if "kill" in argv]
        self.assertEqual({argv[-1] for argv in kills}, set(self.transport.rows))
        self.assertTrue(all(argv[-2] == "--signal=KILL" for argv in kills))
        self.assertFalse(any(token in argv for argv in self.transport.calls
                             for token in ("start", "restart", "update", "rm", "create", "run")))

    def test_main_helper_success_is_not_container_quiescence(self):
        self.transport.rows["a" * 64] = row(running=True)
        self.transport.after_kill = lambda *_: None
        self.assertFalse(self.engine.quiesce(deadline=50))

    def test_lost_daemon_kill_reply_is_uncertain_not_stopped(self):
        self.transport.rows["a" * 64] = row(running=True)
        def lost(transport, object_id):
            transport.rows[object_id] = row(object_id)
            raise commands.CommandUncertain("command-deadline-missed")
        self.transport.after_kill = lost
        with self.assertRaises(commands.CommandUncertain):
            self.engine.quiesce(deadline=50)

    def test_empty_candidate_list_is_explicit_and_old_is_still_inspected(self):
        self.transport.lists = [[], []]
        self.assertEqual(self.engine.owned_candidates(deadline=50), [])
        self.transport.lists = [[], []]
        self.assertTrue(self.engine.quiesce(deadline=50))
        inspections = [argv for argv in self.transport.calls if "inspect" in argv]
        self.assertEqual([argv[-1] for argv in inspections], [self.value["old_object_id"]] * 2)

    def test_all_owned_candidates_are_quiesced_even_after_ambiguous_multiple_create(self):
        self.transport.rows["b" * 64] = row("b" * 64, running=True)
        self.transport.lists = [["a" * 64, "b" * 64], ["b" * 64, "a" * 64]]
        self.assertTrue(self.engine.quiesce(deadline=50))
        self.assertEqual([argv[-1] for argv in self.transport.calls if "kill" in argv], ["b" * 64])

    def test_short_duplicate_foreign_old_or_unbounded_ids_are_not_ownership(self):
        for rows in (["short"], ["a" * 64, "a" * 64], [self.value["old_object_id"]], ["0" * 63 + str(i % 10) for i in range(17)], [""]):
            with self.subTest(rows=rows):
                self.setUp()
                self.transport.lists = [rows]
                with self.assertRaises(durable.Rejected):
                    self.engine.owned_candidates(deadline=50)
                self.assertEqual(len(self.transport.calls), 1)

    def test_ownership_change_during_collection_or_quiescence_fails_closed(self):
        for method in ("owned_candidates", "quiesce"):
            with self.subTest(method=method):
                self.setUp()
                self.transport.lists = [["a" * 64], ["b" * 64]]
                with self.assertRaises(durable.Rejected):
                    getattr(self.engine, method)(deadline=50)

    def test_unproven_fence_or_lost_fence_is_not_daemon_safety(self):
        for fences in ([False], [1], [True, False]):
            with self.subTest(fences=fences):
                self.setUp()
                self.fences = fences
                with self.assertRaises(durable.Rejected):
                    self.engine.quiesce(deadline=50)
                if len(fences) == 0:
                    self.assertFalse(any("kill" in argv for argv in self.transport.calls))

    def test_final_fence_overrun_or_clock_regression_cannot_acknowledge_quiescence(self):
        for value in (50, 0):
            with self.subTest(value=value):
                self.setUp()
                calls = []
                def fence():
                    calls.append(True)
                    if len(calls) == 2:
                        self.time = value
                    return True
                self.engine.start_fence = fence
                with self.assertRaises(commands.CommandUncertain):
                    self.engine.quiesce(deadline=50)

    def test_foreign_ownership_or_changed_image_is_rejected_before_any_kill(self):
        for update in ({"ownership_id": "foreign"}, {"installation_id": "foreign"}, {"image_id": "sha256:" + "0" * 64},
                       {"object_id": "b" * 64}):
            with self.subTest(update=update):
                self.setUp()
                self.transport.rows[self.value["old_object_id"]] = row(self.value["old_object_id"], running=True)
                self.transport.rows["a" * 64].update(update)
                with self.assertRaises(durable.Rejected):
                    self.engine.quiesce(deadline=50)
                self.assertFalse(any("kill" in argv for argv in self.transport.calls))

    def test_changed_old_image_blocks_all_stops(self):
        self.transport.rows[self.value["old_object_id"]]["image_id"] = "sha256:" + "0" * 64
        with self.assertRaises(durable.Rejected):
            self.engine.quiesce(deadline=50)
        self.assertFalse(any("kill" in argv for argv in self.transport.calls))

    def test_restart_removal_and_ambiguous_states_fail_closed(self):
        for update in ({"restart_policy": "always"}, {"restart_policy": "unless-stopped"}, {"restart_retries": True},
                       {"auto_remove": True}, {"running": 0}, {"paused": True}, {"restarting": True},
                       {"dead": True}, {"status": "removing"}, {"status": "running"},
                       {"image_id": "sha256:short"}, {"image_id": True}, {"ownership_id": ["invalid"]},
                       {"status": False}, {"extra": "private"}):
            with self.subTest(update=update):
                self.setUp()
                self.transport.rows["a" * 64].update(update)
                with self.assertRaises(durable.Rejected):
                    self.engine.inspect("a" * 64, deadline=50)

    def test_malformed_duplicate_truncated_or_missing_daemon_response_fails_closed(self):
        for raw in (b"{}", b'{"object_id":"a","object_id":"b"}', b'{"object_id":', b"", b"private daemon error"):
            with self.subTest(raw=raw):
                self.setUp()
                self.transport.rows["a" * 64] = raw
                with self.assertRaises(durable.Rejected) as caught:
                    self.engine.inspect("a" * 64, deadline=50)
                self.assertNotIn("private", str(caught.exception))

    def test_short_inspect_id_does_not_call_daemon(self):
        with self.assertRaises(durable.Rejected):
            self.engine.inspect("short", deadline=50)
        self.assertEqual(self.transport.calls, [])

    def test_no_ambient_or_network_daemon_endpoint_is_allowed(self):
        for endpoint in ("", "tcp://localhost:2375", "unix:///run/../docker.sock", "unix:///run//docker.sock", "unix:///run/docker.sock/"):
            with self.subTest(endpoint=endpoint), self.assertRaises(durable.Rejected):
                daemon.DockerObjects(docker="/accepted/docker", endpoint=endpoint, commands=self.transport,
                                     intent=self.value, old_image_id="e" * 64, start_fence=lambda: True)
