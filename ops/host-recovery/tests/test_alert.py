"""Real disposable local IPC plus deterministic protocol/deadline negatives.

No host unit, daemon, credential, external alert route or human notification.
"""
import copy
import errno
import multiprocessing
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from host_recovery import alert, durable

NOTICE = {"schema": "host-recovery-notice-v1", "attempt_id": "00000000-0000-4000-8000-000000000001",
          "original_cause": "forward-stop-failed", "recovery_error": "recovery-quiescence-failed",
          "outcome": "recovery_unresolved", "start_fenced": True}


def independent_listener(path, ready, output, stop_fd):
    listener = alert.AlertListener(path, "synthetic-route", sender_uid=os.geteuid(),
                                   capacity=2, max_peers=4, peer_seconds=1)
    try:
        ready.set()
        listener.serve(stop_fd)
        output.send([listener.drain(), listener.drain()])
    finally:
        listener.close()
        output.close()


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="alert-ipc-")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "listener.sock")
        self.listener = alert.AlertListener(self.path, "synthetic-route", sender_uid=os.geteuid(),
                                             capacity=2, max_peers=4, peer_seconds=1)
        self.addCleanup(self.listener.close)
        self.client = alert.AlertClient(self.path, "synthetic-route", listener_uid=os.geteuid())
        self.thread = None

    def start(self):
        stop_read, stop_write = os.pipe()
        self.stop_read, self.stop_write = stop_read, stop_write
        self.thread = threading.Thread(target=self.listener.serve, args=(stop_read,), daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.thread is not None:
            os.write(self.stop_write, b"stop")
            self.thread.join(5)
            self.assertFalse(self.thread.is_alive(), "listener loop did not stop")
            os.close(self.stop_read)
            os.close(self.stop_write)
            self.thread = None

    def preflight(self):
        return self.client.preflight(deadline=time.monotonic() + 5)

    def deliver(self, value=None):
        return self.client.deliver(NOTICE if value is None else value, deadline=time.monotonic() + 5)

    def request(self, kind="challenge"):
        value = {"schema": "host-alert-request-v1", "kind": kind,
                 "route_id": "synthetic-route", "nonce": "synthetic-nonce"}
        if kind == "notice":
            value.update(instance_id=self.listener.instance_id, notice=copy.deepcopy(NOTICE))
        return value

    def test_real_challenge_and_notice_receipts_are_not_durable_or_human(self):
        self.start()
        response = self.preflight()
        self.assertFalse(response["durable"])
        self.assertFalse(response["human_acknowledged"])
        self.assertEqual(response["instance_id"], self.listener.instance_id)
        self.assertTrue(self.deliver())
        self.stop()
        self.assertEqual(self.listener.drain(), NOTICE)
        self.assertIsNone(self.listener.drain())

    def test_disk_failure_does_not_prevent_actual_local_transport(self):
        self.start()
        self.preflight()
        for code in (errno.EIO, errno.ENOSPC):
            def fail(_):
                raise OSError(code, "synthetic")
            result = durable.notify(NOTICE, fail, lambda value: self.deliver(value))
            self.assertFalse(result["receipt_persisted"])
            self.assertTrue(result["transport_delivered"])
            self.assertFalse(result["human_acknowledged"])
        self.stop()
        self.assertEqual([self.listener.drain(), self.listener.drain()], [NOTICE, NOTICE])

    def test_missing_listener_refuses_preflight(self):
        client = alert.AlertClient(str(Path(self.temp.name) / "absent.sock"), "synthetic-route", listener_uid=os.geteuid())
        with self.assertRaises(OSError):
            client.preflight(deadline=time.monotonic() + 5)
        self.assertIsNone(client.instance_id)

    def test_listener_loss_after_preflight_reports_delivery_failure(self):
        self.start()
        self.preflight()
        self.stop()
        self.listener.close()
        result = durable.notify(NOTICE, lambda _: None, lambda value: self.deliver(value))
        self.assertFalse(result["transport_delivered"])
        self.assertEqual(result["transport_error"], "alert-transport-failed")

    def test_unpreflighted_notice_is_refused(self):
        with self.assertRaises(durable.Rejected):
            self.deliver()

    def test_full_inbox_refuses_new_notice_and_preflight(self):
        self.start()
        self.preflight()
        self.deliver()
        self.deliver()
        with self.assertRaises((durable.Rejected, OSError)):
            self.deliver()
        with self.assertRaises((durable.Rejected, OSError)):
            self.preflight()
        self.assertIsNone(self.client.instance_id)
        self.stop()
        self.assertEqual(len(self.listener.inbox), 2)

    def test_wrong_instance_never_admits_notice(self):
        value = self.request("notice")
        value["instance_id"] = "replaced"
        with self.assertRaises(durable.Rejected):
            self.listener._request(value)
        self.assertFalse(self.listener.inbox)

    def test_route_mismatch_never_admits(self):
        for kind in ("challenge", "notice"):
            value = self.request(kind)
            value["route_id"] = "different"
            with self.subTest(kind=kind), self.assertRaises(durable.Rejected):
                self.listener._request(value)
        self.assertFalse(self.listener.inbox)

    def test_unknown_fields_kinds_and_nonce_are_rejected(self):
        for key, item in (("extra", "opaque"), ("schema", "unknown"), ("kind", "unknown"), ("nonce", "bad\nnonce")):
            value = self.request()
            value[key] = item
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                self.listener._request(value)

    def test_notice_rejects_unbounded_or_unreviewed_content(self):
        for key, item in (("extra", "opaque"), ("original_cause", "credentials=opaque"),
                          ("recovery_error", "x" * 97), ("attempt_id", "not-uuid"),
                          ("outcome", "healthy"), ("start_fenced", 1), ("schema", "unknown")):
            value = copy.deepcopy(NOTICE)
            value[key] = item
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                alert.validate_notice(value)

    def test_admission_notice_without_attempt_can_report_prearm_failure(self):
        value = copy.deepcopy(NOTICE)
        value.update(attempt_id=None, recovery_error=None, outcome="fenced")
        alert.validate_notice(value)

    def test_receipt_mismatch_and_extra_fields_never_deliver(self):
        self.client.instance_id = self.listener.instance_id
        def exchange(value, _):
            response = self.listener._request(value)
            response["notice_sha256"] = "0" * 64
            return response
        with patch.object(self.client, "_exchange", side_effect=exchange), self.assertRaises(durable.Rejected):
            self.deliver()

    def test_challenge_must_have_strict_boolean_ack_fields(self):
        def exchange(value, _):
            response = self.listener._request(value)
            response["durable"] = 0
            return response
        with patch.object(self.client, "_exchange", side_effect=exchange), self.assertRaises(durable.Rejected):
            self.preflight()
        self.assertIsNone(self.client.instance_id)

    def test_deadline_rejected_before_connection(self):
        for deadline in (True, 0, -1, float("nan"), float("inf")):
            with self.subTest(deadline=deadline), self.assertRaises(durable.Rejected):
                self.client.preflight(deadline=deadline)

    def test_deadline_does_not_reset_at_each_wait(self):
        self.start()
        self.client.clock = lambda: 10
        with patch.object(alert.selectors.EpollSelector, "select", return_value=[]), self.assertRaises(durable.Rejected):
            self.client.preflight(deadline=11)
        self.assertIsNone(self.client.instance_id)

    def test_wrong_kernel_peer_uid_is_rejected(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with left, right, self.assertRaises(durable.Rejected):
            alert.peer(left, os.geteuid() + 1)

    def test_sender_peer_refusal_closes_without_receipt(self):
        self.listener.uid = os.geteuid() + 1
        self.start()
        with self.assertRaises((durable.Rejected, OSError)):
            self.preflight()
        self.assertIsNone(self.client.instance_id)

    def test_socket_mode_and_symlink_are_rejected(self):
        Path(self.path).chmod(0o666)
        with self.assertRaises(durable.Rejected):
            self.preflight()
        link = Path(self.temp.name) / "link.sock"
        link.symlink_to(self.path)
        client = alert.AlertClient(str(link), "synthetic-route", listener_uid=os.geteuid())
        with self.assertRaises(durable.Rejected):
            client.preflight(deadline=time.monotonic() + 5)

    def test_existing_endpoint_is_not_replaced_or_removed(self):
        before = os.lstat(self.path)
        with self.assertRaises(OSError):
            alert.AlertListener(self.path, "synthetic-route", sender_uid=os.geteuid(),
                                capacity=2, max_peers=4, peer_seconds=1)
        self.listener.close()
        self.assertEqual(os.lstat(self.path).st_ino, before.st_ino)

    def test_packet_truncation_partial_json_and_duplicate_keys_fail_closed(self):
        for raw in (b"x" * (alert.MAX_PACKET + 1), b'{"schema":', b'{"k":1,"k":2}'):
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with self.subTest(size=len(raw)), left, right:
                left.send(raw)
                with self.assertRaises(durable.Rejected):
                    alert.packet(right)

    def test_ancillary_descriptors_are_closed_and_rejected(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        read_fd, write_fd = os.pipe()
        try:
            with left, right:
                left.sendmsg([b"{}"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, alert.struct.pack("i", read_fd))])
                real_close = os.close
                closed = []
                def close(fd):
                    closed.append(fd)
                    real_close(fd)
                with patch.object(alert.os, "close", side_effect=close), self.assertRaises(durable.Rejected):
                    alert.packet(right)
                self.assertEqual(len(closed), 1)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_idle_peer_expiry_uses_controllable_clock(self):
        self.listener.clock = lambda: 10
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(conn.close)
        conn.connect(self.path)
        self.listener.poll()
        self.assertEqual(len(self.listener.peers), 1)
        self.listener.clock = lambda: 11
        self.listener.poll()
        self.assertFalse(self.listener.peers)
        self.assertEqual(conn.recv(1), b"")

    def test_peer_capacity_is_bounded(self):
        self.listener.max_peers = 1
        peers = [socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) for _ in range(2)]
        for conn in peers:
            self.addCleanup(conn.close)
            conn.connect(self.path)
            self.listener.poll()
        self.assertEqual(len(self.listener.peers), 1)
        self.assertEqual(peers[1].recv(1), b"")

    def test_lost_ack_leaves_admitted_notice_but_no_success(self):
        self.start()
        self.preflight()
        real_send = alert.send
        def lose_notice_ack(sock, value):
            if value.get("schema") == "host-alert-receipt-v1" and value.get("kind") == "notice":
                raise OSError(errno.EPIPE, "synthetic")
            return real_send(sock, value)
        with patch.object(alert, "send", side_effect=lose_notice_ack), self.assertRaises((durable.Rejected, OSError)):
            self.deliver()
        self.stop()
        self.assertEqual(self.listener.drain(), NOTICE)
        self.assertIsNone(self.listener.drain())

    def test_real_separate_process_admits_without_disk_receipt(self):
        path = str(Path(self.temp.name) / "process.sock")
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        output, child_output = context.Pipe(duplex=False)
        stop_read, stop_write = os.pipe()
        process = context.Process(target=independent_listener, args=(path, ready, child_output, stop_read))
        process.start()
        try:
            self.assertTrue(ready.wait(5))
            client = alert.AlertClient(path, "synthetic-route", listener_uid=os.geteuid())
            client.preflight(deadline=time.monotonic() + 5)
            def fail(_):
                raise OSError(errno.ENOSPC, "synthetic")
            result = durable.notify(NOTICE, fail, lambda value: client.deliver(value, deadline=time.monotonic() + 5))
            self.assertTrue(result["transport_delivered"])
            self.assertFalse(result["receipt_persisted"])
            os.write(stop_write, b"stop")
            self.assertTrue(output.poll(5))
            self.assertEqual(output.recv(), [NOTICE, None])
            process.join(5)
            self.assertEqual(process.exitcode, 0)
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            process.close()
            output.close()
            child_output.close()
            os.close(stop_read)
            os.close(stop_write)

    def test_valid_but_late_receipt_cannot_pass_deadline(self):
        self.start()
        values = iter([10, 10, 10, 11])
        self.client.clock = lambda: next(values)
        with self.assertRaises(durable.Rejected):
            self.client.preflight(deadline=11)
        self.assertIsNone(self.client.instance_id)

    def test_sigkill_of_separate_listener_is_not_delivery(self):
        path = str(Path(self.temp.name) / "killed.sock")
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        output, child_output = context.Pipe(duplex=False)
        stop_read, stop_write = os.pipe()
        process = context.Process(target=independent_listener, args=(path, ready, child_output, stop_read))
        process.start()
        try:
            self.assertTrue(ready.wait(5))
            client = alert.AlertClient(path, "synthetic-route", listener_uid=os.geteuid())
            client.preflight(deadline=time.monotonic() + 5)
            process.kill()
            process.join(5)
            self.assertEqual(process.exitcode, -9)
            result = durable.notify(NOTICE, lambda _: None,
                                    lambda value: client.deliver(value, deadline=time.monotonic() + 5))
            self.assertFalse(result["transport_delivered"])
            self.assertIsNone(client.delivery_receipt)
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            process.close()
            output.close()
            child_output.close()
            os.close(stop_read)
            os.close(stop_write)

    def test_clock_regression_cannot_extend_client_deadline(self):
        values = iter([10, 9])
        self.client.clock = lambda: next(values)
        self.assertEqual(self.client._remaining(11), 1)
        with self.assertRaises(durable.Rejected):
            self.client._remaining(11)

    def test_listener_bad_clock_refuses_work(self):
        self.listener.clock = lambda: 10
        self.listener.poll()
        for value in (9, float("nan"), float("inf"), True):
            self.listener.clock = lambda: value
            with self.subTest(value=value), self.assertRaises(durable.Rejected):
                self.listener.poll()

    def test_old_challenge_cannot_authorize_replacement_listener(self):
        self.start()
        self.preflight()
        self.stop()
        self.listener.close()
        # Deliberate reconciliation is restricted to this disposable test root.
        Path(self.path).unlink()
        self.listener = alert.AlertListener(self.path, "synthetic-route", sender_uid=os.geteuid(),
                                             capacity=2, max_peers=4, peer_seconds=1)
        self.addCleanup(self.listener.close)
        self.start()
        with self.assertRaises((durable.Rejected, OSError)):
            self.deliver()
        self.preflight()
        self.assertTrue(self.deliver())
        self.stop()
        self.assertEqual(self.listener.drain(), NOTICE)
        self.assertIsNone(self.listener.drain())

    def test_replayed_receipt_nonce_cannot_deliver(self):
        self.client.instance_id = self.listener.instance_id
        def exchange(value, _):
            response = self.listener._request(value)
            response["nonce"] = "stale-nonce"
            return response
        with patch.object(self.client, "_exchange", side_effect=exchange), self.assertRaises(durable.Rejected):
            self.deliver()
        self.assertIsNone(self.client.delivery_receipt)

    def test_listener_policy_has_no_implicit_capacity_or_deadline(self):
        for key, item in (("capacity", 0), ("max_peers", 0), ("peer_seconds", 0), ("peer_seconds", float("nan"))):
            values = {"sender_uid": os.geteuid(), "capacity": 2, "max_peers": 4, "peer_seconds": 1}
            values[key] = item
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                alert.AlertListener(self.path, "synthetic-route", **values)
