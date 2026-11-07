"""Real synthetic root restoration; task/daemon boundary is scripted here."""
import errno
import time
import unittest

import docker_baseline_fixture as fixture
from host_recovery import durable
from test_installation import approve
import test_write_set as write_set_tests


class DockerBaselineRecoveryTests(unittest.TestCase):
    setUp = write_set_tests.WriteSetTests.setUp
    put = staticmethod(write_set_tests.WriteSetTests.put)
    mutate = write_set_tests.WriteSetTests.mutate
    assert_baseline = write_set_tests.WriteSetTests.assert_baseline

    def inputs(self):
        return {"backup": approve(self.backup), "roots": self.approvals, "pin": self.pin}

    def restore(self, **kwargs):
        return fixture.restore_stopped(self.inputs(), object_id="a" * 64,
            check=lambda **_: self.fenced, deadline=time.monotonic() + 60, **kwargs)

    def test_actual_restore_and_fresh_observer_cover_all_roots_without_start_grant(self):
        self.mutate()
        with self.restore() as receipt:
            self.assert_baseline()
            self.assertEqual(receipt["schema"], "host-recovery-write-set-observed-v1")
            self.assertEqual((receipt["roots"], receipt["selected"], receipt["disabled"], receipt["enabled"]),
                             (3, 9, 7, 2))
            self.assertIs(receipt["filesystem_verified"], True)
            for flag in ("start_permission", "semantic_start_oracle_proven", "production_acceptance"):
                self.assertIs(receipt[flag], False)
        self.assert_baseline()

    def test_every_reached_storage_failure_prevents_yield_and_fresh_retry_restores(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.mutate()
                    reached, yielded = [], False
                    def fault(stage):
                        if stage == point:
                            reached.append(stage)
                            raise OSError(code, "synthetic storage failure")
                    with self.assertRaises(OSError):
                        with self.restore(fault=fault):
                            yielded = True
                    self.assertEqual(reached, [point])
                    self.assertFalse(yielded)
                    with self.restore():
                        self.assert_baseline()

    def test_stopped_boundary_loss_refuses_before_restore(self):
        self.mutate()
        original = (self.paths["config"] / "config.yaml").read_bytes()
        self.fenced = False
        with self.assertRaises(durable.Rejected):
            with self.restore():
                self.fail("lost stopped boundary yielded a restored receipt")
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), original)

    def test_post_yield_mutation_is_not_hidden_by_restorer_progress(self):
        self.mutate()
        with self.assertRaises(durable.Rejected):
            with self.restore():
                self.put(self.paths["config"] / "config.yaml", b"changed after fresh observation")
