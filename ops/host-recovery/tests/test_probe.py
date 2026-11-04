"""Actual synthetic loopback HTTP/tool linkage, not producer/recovery acceptance."""
import copy
from dataclasses import replace
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from host_recovery import durable, probe


def first_response(body):
    value = durable.decode(body)
    nonce = re.search(r"with nonce ([a-f0-9-]+)\.", value["messages"][0]["content"][0]["text"])[1]
    return {"id": "msg_first", "type": "message", "role": "assistant", "model": "observed-model",
            "content": [{"type": "thinking", "thinking": "synthetic thinking", "signature": "opaque-signature"},
                        {"type": "redacted_thinking", "data": "opaque-redaction"},
                        {"type": "tool_use", "id": "toolu_fixture", "name": probe.TOOL, "input": {"nonce": nonce}}],
            "stop_reason": "tool_use", "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 2}}


def second_response(body):
    value = durable.decode(body)
    nonce = durable.decode(value["messages"][-1]["content"][0]["content"].encode())["confirmation"]
    return {"id": "msg_second", "type": "message", "role": "assistant", "model": "observed-model",
            "content": [{"type": "text", "text": "recovery-tool-confirmed:" + nonce}],
            "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 3, "output_tokens": 4}}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "spool"
        self.path.mkdir(mode=0o700)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.now, self.calls, self.checks = 100.0, [], []
        self.mutate = lambda value, turn: value
        self.before_exchange = lambda: None
        self.sources = probe.ProbeSources(*["a" * 40, "b" * 40, "c" * 40, "d" * 40,
                                            "e" * 64, "f" * 64, "0" * 64])
        self.spool = probe.ProbeSpool(self.fd, check=self.check, clock=lambda: self.now)

    def check(self, *, deadline):
        self.checks.append(deadline)
        return True

    def exchange(self, headers, body, *, deadline):
        self.before_exchange()
        self.calls.append((copy.deepcopy(headers), body, deadline))
        turn = len(self.calls)
        value = first_response(body) if turn == 1 else second_response(body)
        value = self.mutate(value, turn)
        return 200, value if type(value) is bytes else durable.canonical(value)

    def make(self, **kwargs):
        values = dict(attempt_id="synthetic-attempt", requested_model="requested-alias", sources=self.sources,
                      transport=SimpleNamespace(exchange=self.exchange), spool=self.spool, clock=lambda: self.now)
        values.update(kwargs)
        return probe.TwoTurnProbe(**values)

    def test_ids_originate_in_requests_and_exact_tool_and_thinking_blocks_survive(self):
        result = self.make().run(deadline=110)
        self.assertEqual(len(self.calls), 2)
        first, second = [durable.decode(row[1]) for row in self.calls]
        original = first_response(self.calls[0][1])
        self.assertEqual(second["messages"][1], {"role": "assistant", "content": original["content"]})
        self.assertEqual(second["messages"][2]["content"][0]["tool_use_id"], "toolu_fixture")
        returned = durable.decode(second["messages"][2]["content"][0]["content"].encode())
        self.assertEqual(returned["nonce"], original["content"][-1]["input"]["nonce"])
        self.assertEqual(uuid.UUID(returned["confirmation"]).version, 4)
        self.assertNotIn(returned["confirmation"].encode(), self.calls[0][1])
        self.assertEqual(result["tool_linkage"]["confirmation_sha256"], durable.digest(returned["confirmation"].encode()))
        self.assertEqual(first["model"], "requested-alias")
        self.assertEqual(second["model"], "requested-alias")
        self.assertEqual(first["tool_choice"], {"type": "tool", "name": probe.TOOL})
        self.assertEqual(second["tool_choice"], {"type": "none"})
        h1, h2 = [row[0] for row in self.calls]
        self.assertEqual(h1["X-CPA-Recovery-Parent-Request-ID"], "")
        self.assertEqual(h2["X-CPA-Recovery-Parent-Request-ID"], h1["X-CPA-Recovery-Request-ID"])
        self.assertNotEqual(h2["X-CPA-Recovery-Request-ID"], h1["X-CPA-Recovery-Request-ID"])
        for turn, headers in zip(result["turns"], (h1, h2)):
            self.assertEqual(turn["request_id"], headers["X-CPA-Recovery-Request-ID"])
            self.assertEqual(result["probe_id"], headers["X-CPA-Recovery-Probe-ID"])
            self.assertEqual(turn["observed_response_model"], "observed-model")
        self.assertEqual(result["sources"], probe.asdict(self.sources))
        self.assertTrue(result["http_tool_linkage_observed"])
        for name in ("source_artifacts_authenticated", "producer_drained", "collection_complete", "replay_accepted",
                     "production_acceptance"):
            self.assertIs(result[name], False)
        raw = durable.canonical(result)
        for restricted in (b"opaque-signature", b"opaque-redaction", b"synthetic thinking", b"toolu_fixture"):
            self.assertNotIn(restricted, raw)
        self.assertNotIn(b"resolved_model", raw)
        self.assertTrue(all(deadline == 110 for deadline in self.checks))

    def test_model_cannot_pass_by_repeating_initial_nonce_without_tool_result(self):
        initial_nonce = None
        def shortcut(value, turn):
            nonlocal initial_nonce
            if turn == 1:
                initial_nonce = value["content"][-1]["input"]["nonce"]
            else:
                value["content"][0]["text"] = "recovery-tool-confirmed:" + initial_nonce
            return value
        self.mutate = shortcut
        with self.assertRaises(durable.Rejected):
            self.make().run(deadline=110)
        self.assertEqual(len(self.calls), 2)

    def test_six_raw_artifacts_are_durable_hashed_and_private(self):
        result = self.make().run(deadline=110)
        self.assertEqual(len(list(self.path.iterdir())), 6)
        for row in result["turns"]:
            for kind in ("carrier", "request", "response"):
                path = self.path / f"turn{row['turn']}-{kind}.json"
                self.assertEqual(durable.digest(path.read_bytes()), row[kind + "_sha256"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(durable.Rejected):
            probe.ProbeSpool(self.fd, check=self.check)

    def test_second_turn_is_not_sent_after_ambiguous_response_persistence(self):
        reached = []
        def fault(point):
            if len(self.calls) == 1:
                reached.append(point)
                if point == "directory-fsync":
                    raise OSError(errno.EIO, "synthetic")
        self.spool.fault = fault
        run = self.make()
        with self.assertRaises(durable.Rejected):
            run.run(deadline=110)
        self.assertEqual(reached[-1], "directory-fsync")
        self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.path / "turn1-response.json").exists())
        self.assertFalse((self.path / "turn2-request.json").exists())
        with self.assertRaises(durable.Rejected):
            run.run(deadline=110)

    def test_each_reached_spool_fault_refuses_before_any_network_call(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point), tempfile.TemporaryDirectory() as temp:
                    os.chmod(temp, 0o700)
                    with durable.directory(temp, private=True) as fd:
                        reached = []
                        def fail(hook):
                            reached.append(hook)
                            if hook == point:
                                raise OSError(code, "synthetic")
                        spool = probe.ProbeSpool(fd, check=self.check, clock=lambda: self.now, fault=fail)
                        with self.assertRaises(durable.Rejected):
                            self.make(spool=spool).run(deadline=110)
                        self.assertEqual(reached[-1], point)
                        self.assertEqual(self.calls, [])
                        with self.assertRaises(durable.Rejected):
                            spool.verify(deadline=110)

    def test_first_turn_wrong_tool_nonce_or_multiple_calls_prevents_second(self):
        cases = [lambda v: v["content"][-1].update(name="other"),
                 lambda v: v["content"][-1].update(input={"nonce": "other"}),
                 lambda v: v["content"][-1].update(input={"nonce": True}),
                 lambda v: v["content"].append(copy.deepcopy(v["content"][-1])),
                 lambda v: v.update(stop_reason="max_tokens"),
                 lambda v: v["content"][-1].update(id="unsafe\r\n"),
                 lambda v: v["content"][-1].update(input={"nonce": "other", "extra": 1})]
        for change in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                with durable.directory(temp, private=True) as fd:
                    self.calls.clear()
                    self.mutate = lambda v, turn: change(v) or v
                    with self.assertRaises(durable.Rejected):
                        self.make(spool=probe.ProbeSpool(fd, check=self.check, clock=lambda: self.now)).run(deadline=110)
                    self.assertEqual(len(self.calls), 1)

    def test_second_turn_must_confirm_actual_nonce_and_finish_without_more_tools(self):
        cases = [lambda v: v["content"][0].update(text="recovery-tool-confirmed:other"),
                 lambda v: v.update(stop_reason="tool_use"),
                 lambda v: v.update(id="msg_first"),
                 lambda v: v["content"].append({"type": "tool_use", "id": "other", "name": probe.TOOL, "input": {}})]
        for change in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                with durable.directory(temp, private=True) as fd:
                    self.calls.clear()
                    self.mutate = lambda v, turn: (change(v) or v) if turn == 2 else v
                    with self.assertRaises(durable.Rejected):
                        self.make(spool=probe.ProbeSpool(fd, check=self.check, clock=lambda: self.now)).run(deadline=110)
                    self.assertEqual(len(self.calls), 2)

    def test_duplicate_keys_partial_json_unknown_blocks_and_coercions_refuse(self):
        cases = [lambda v: b'{"id":"a","id":"b"}', lambda v: b'{"id":',
                 lambda v: v.update(extra="not-supported"), lambda v: v.update(usage=[]),
                 lambda v: v.update(role="user"), lambda v: v.update(content=[]),
                 lambda v: v["content"].append({"type": "unknown"}),
                 lambda v: v["content"][0].update(signature=""),
                 lambda v: v["content"][1].update(data=False)]
        for change in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                with durable.directory(temp, private=True) as fd:
                    self.calls.clear()
                    self.mutate = lambda v, turn: change(v) or v
                    with self.assertRaises(durable.Rejected):
                        self.make(spool=probe.ProbeSpool(fd, check=self.check, clock=lambda: self.now)).run(deadline=110)
                    self.assertEqual(len(self.calls), 1)

    def test_non200_and_boolean_status_refuse_without_retry(self):
        for status in (True, 201, 302, 401, 500):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                with durable.directory(temp, private=True) as fd:
                    self.calls.clear()
                    def exchange(*args, **kwargs):
                        _, raw = self.exchange(*args, **kwargs)
                        return status, raw
                    with self.assertRaises(durable.Rejected):
                        self.make(transport=SimpleNamespace(exchange=exchange),
                            spool=probe.ProbeSpool(fd, check=self.check, clock=lambda: self.now)).run(deadline=110)
                    self.assertEqual(len(self.calls), 1)

    def test_mutating_previous_artifact_on_second_exchange_prevents_receipt(self):
        def change():
            if self.calls:
                (self.path / "turn1-response.json").write_bytes(b"changed")
        self.before_exchange = change
        with self.assertRaises(durable.Rejected):
            self.make().run(deadline=110)
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(self.spool.failed)

    def test_boundary_loss_and_unexpected_spool_entry_prevent_network(self):
        for check in (lambda **kw: False, lambda **kw: 1):
            with tempfile.TemporaryDirectory() as temp:
                with durable.directory(temp, private=True) as fd:
                    with self.assertRaises(durable.Rejected):
                        self.make(spool=probe.ProbeSpool(fd, check=check)).run(deadline=time.monotonic() + 5)
        (self.path / "unexpected").write_bytes(b"x")
        with self.assertRaises(durable.Rejected):
            self.make().run(deadline=110)
        self.assertEqual(self.calls, [])

    def test_generated_collision_and_reuse_are_refused(self):
        with patch.object(probe.uuid, "uuid4", return_value=uuid.UUID("12345678-1234-4234-8234-123456789abc")):
            run = self.make()
            with self.assertRaises(durable.Rejected):
                run.run(deadline=110)
        with self.assertRaises(durable.Rejected):
            run.run(deadline=110)
        self.assertEqual(self.calls, [])

    def test_deadline_expiry_between_turns_never_gets_fresh_allowance(self):
        self.mutate = lambda v, turn: setattr(self, "now", 110.0) or v
        with self.assertRaises(durable.Rejected):
            self.make().run(deadline=110)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.path / "turn2-carrier.json").exists())

    def test_explicit_source_transport_and_private_spool_policy(self):
        for field in probe.asdict(self.sources):
            with self.subTest(field=field), self.assertRaises(durable.Rejected):
                replace(self.sources, **{field: "not-a-pin"})
        for kwargs in ({"attempt_id": "unsafe\n"}, {"requested_model": "unsafe\n"}, {"sources": None},
                       {"transport": None}, {"spool": None}):
            with self.subTest(kwargs=kwargs), self.assertRaises(durable.Rejected):
                self.make(**kwargs)
        for kwargs in ({"port": True}, {"port": 0}, {"port": 65536}, {"port": 80, "ipv6": 1},
                       {"port": 80, "token": "secret\n"}, {"port": 80, "token": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(durable.Rejected):
                probe.LoopbackMessages(**kwargs)
        os.chmod(self.path, 0o755)
        with self.assertRaises(durable.Rejected):
            probe.ProbeSpool(self.fd, check=self.check)


class LoopbackTests(unittest.TestCase):
    def setUp(self):
        self.rows, self.mode = [], "healthy"
        self.entered, self.release = threading.Event(), threading.Event()
        test = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                test.rows.append((self.path, dict(self.headers), body))
                test.entered.set()
                if test.mode == "stall":
                    test.release.wait(10)
                    return
                value = first_response(body) if self.headers["X-CPA-Recovery-Turn"] == "1" else second_response(body)
                raw = durable.canonical(value)
                self.send_response(302 if test.mode == "redirect" else 200)
                self.send_header("Content-Type", "text/plain" if test.mode == "content-type" else "application/json")
                if test.mode == "duplicate-type":
                    self.send_header("Content-Type", "application/json")
                if test.mode == "encoding":
                    self.send_header("Content-Encoding", "gzip")
                if test.mode == "duplicate-encoding":
                    self.send_header("Content-Encoding", "identity")
                    self.send_header("Content-Encoding", "gzip")
                if test.mode == "length":
                    self.send_header("Content-Length", str(probe.MAX_BODY + 1))
                elif test.mode == "duplicate-length":
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Content-Length", str(len(raw)))
                elif test.mode == "partial":
                    self.send_header("Content-Length", str(len(raw) + 10))
                elif test.mode != "overflow":
                    self.send_header("Content-Length", str(len(raw)))
                if test.mode == "redirect":
                    self.send_header("Location", "http://127.0.0.1:1/never-follow")
                self.end_headers()
                try:
                    self.wfile.write(b"x" * (probe.MAX_BODY + 1) if test.mode == "overflow" else raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.start()
        self.addCleanup(self.cleanup_server)
        self.transport = probe.LoopbackMessages(port=self.server.server_port, token="synthetic-only-token")
        self.addCleanup(self.cleanup_helpers)
        self.body = durable.canonical({"messages": [{"content": [{"text": "Call with nonce 12345678-1234-4234-8234-123456789abc."}]}]})
        self.headers = {"X-CPA-Recovery-Attempt-ID": "attempt", "X-CPA-Recovery-Probe-ID": "probe",
                        "X-CPA-Recovery-Request-ID": "request1", "X-CPA-Recovery-Parent-Request-ID": "",
                        "X-CPA-Recovery-Turn": "1"}

    def cleanup_server(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())

    def cleanup_helpers(self):
        for proc in self.transport.pending:
            proc.wait(timeout=5)

    def test_real_http_two_turns_include_carrier_auth_and_exact_preserved_content(self):
        with tempfile.TemporaryDirectory() as temp:
            with durable.directory(temp, private=True) as fd:
                sources = probe.ProbeSources(*(["a" * 40] * 4 + ["b" * 64] * 3))
                run = probe.TwoTurnProbe(attempt_id="actual-http-fixture", requested_model="requested-alias", sources=sources,
                    transport=self.transport, spool=probe.ProbeSpool(fd, check=lambda **kw: True))
                result = run.run(deadline=time.monotonic() + 10)
                self.assertTrue(result["http_tool_linkage_observed"])
                self.assertFalse(result["replay_accepted"])
                self.assertEqual(len(self.rows), 2)
                for path, headers, body in self.rows:
                    self.assertEqual(path, "/v1/messages")
                    self.assertEqual(headers["Authorization"], "Bearer synthetic-only-token")
                    self.assertEqual(headers["X-CPA-Recovery-Attempt-ID"], "actual-http-fixture")
                    self.assertEqual(headers["X-CPA-Recovery-Probe-ID"], result["probe_id"])
                    self.assertEqual(durable.decode(body)["model"], "requested-alias")
                self.assertEqual(durable.decode(self.rows[1][2])["messages"][1]["content"],
                                 first_response(self.rows[0][2])["content"])
                self.assertNotIn(b"synthetic-only-token", durable.canonical(result))
                for path in Path(temp).iterdir():
                    self.assertNotIn(b"synthetic-only-token", path.read_bytes())

    def test_response_framing_content_type_overflow_and_partial_body_refuse(self):
        for mode in ("content-type", "duplicate-type", "encoding", "duplicate-encoding", "length", "duplicate-length", "partial", "overflow"):
            self.mode = mode
            with self.subTest(mode=mode), self.assertRaises(durable.Rejected):
                self.transport.exchange(self.headers, self.body, deadline=time.monotonic() + 10)
        self.assertEqual(len(self.rows), 8)

    def test_redirect_is_observed_once_never_followed(self):
        self.mode = "redirect"
        status, _ = self.transport.exchange(self.headers, self.body, deadline=time.monotonic() + 10)
        self.assertEqual(status, 302)
        self.assertEqual(len(self.rows), 1)

    def test_stalled_server_is_reached_and_local_helper_is_killed_without_retry(self):
        self.mode = "stall"
        with self.assertRaises(durable.Rejected):
            self.transport.exchange(self.headers, self.body, deadline=time.monotonic() + 3)
        self.assertTrue(self.entered.is_set())
        self.assertEqual(len(self.rows), 1)
        self.assertEqual(len(self.transport.pending), 1)
        self.transport.pending[0].wait(timeout=5)
        self.assertLess(self.transport.pending[0].returncode, 0)

    def test_missing_synthetic_listener_refuses_without_retry(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            missing = probe.LoopbackMessages(port=reserved.getsockname()[1])
            with self.assertRaises(durable.Rejected):
                missing.exchange(self.headers, self.body, deadline=time.monotonic() + 5)
            for proc in missing.pending:
                proc.wait(timeout=5)
        self.assertEqual(self.rows, [])

    def test_unknown_header_and_injected_identity_never_reach_http(self):
        for headers in ({**self.headers, "Authorization": "unexpected"},
                        {**self.headers, "X-CPA-Recovery-Request-ID": "request\r\nInjected: x"},
                        {**self.headers, "X-CPA-Recovery-Turn": "02"}):
            with self.subTest(headers=headers), self.assertRaises(durable.Rejected):
                self.transport.exchange(headers, self.body, deadline=time.monotonic() + 5)
        self.assertEqual(self.rows, [])
