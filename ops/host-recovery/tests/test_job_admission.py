"""Scripted admission signals, not activation exclusion or manager qualification."""
from unittest.mock import patch
import unittest

from host_recovery import durable, manager_bus as bus
from test_manager_bus import ScriptedConnection
import test_manager_bus as session_fixture
import test_masked_forward_stop as forward_fixture
import test_masked_runtime_stop as runtime_fixture


class JobAdmissionTests(unittest.TestCase):
    setUp = session_fixture.ManagerSessionTests.setUp
    session = session_fixture.ManagerSessionTests.session

    def watched(self):
        session = self.session()
        session._watch_fixed_jobs()
        self.assertIn("member='JobNew'", self.connection.matches[2][0])
        return session

    def stop(self, session, role='dockerd', number=41, cookie=10, *, completion=True):
        self.connection.number = self.connection.reply_number = number
        self.connection.cookie = cookie
        self.connection.mode = 'done' if completion else 'absent'
        def hook(method):
            if method == 'StopUnit':
                self.connection.queue.append(lambda:self.connection.admission(
                    role=role, number=number, cookie=cookie-1))
        self.connection.call_hook = hook
        return session.stop(role)

    def test_original_stops_have_distinct_admissions_completions_and_absence(self):
        session = self.watched()
        self.stop(session)
        self.stop(session, 'containerd', 42, 12)
        self.assertEqual(session._fixed_jobs_absent(),
            dict(fixed_stop_admission_count=2, fixed_jobs_absent_observed=True))
        self.assertEqual(session._created, session._submitted)

    def test_unexpected_job_before_any_stop_revokes_before_dispatch(self):
        session = self.watched()
        self.connection.queue.append(lambda:self.connection.admission())
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertTrue(session.failed)
        self.assertFalse(any(method=='StopUnit' for _,method,_ in self.connection.calls))

    def test_duplicate_admission_revokes_even_when_identical(self):
        session = self.watched(); self.stop(session)
        self.connection.queue.append(lambda:self.connection.admission(cookie=11))
        with self.assertRaises(durable.Rejected): session.identity()
        self.assertTrue(session.failed)

    def test_other_fixed_role_during_stop_is_not_adopted(self):
        session = self.watched()
        self.connection.call_hook = lambda method:self.connection.queue.append(
            lambda:self.connection.admission(role='containerd')) if method=='StopUnit' else None
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(session._created, {})

    def test_early_admission_must_match_the_returned_stop_path(self):
        session = self.watched()
        self.connection.call_hook = lambda method:self.connection.queue.append(
            lambda:self.connection.admission(number=42, cookie=9)) if method=='StopUnit' else None
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertTrue(session.failed)

    def test_missing_admission_does_not_infer_one_from_completion(self):
        session = self.watched()
        self.connection.wait_hook = lambda:setattr(self, 'now', 1090.)
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(session._created, {})
        self.assertEqual(session._events[41]['result'], 'done')

    def test_admission_without_completion_cannot_report_absence(self):
        session = self.watched()
        self.stop(session, completion=False)
        self.stop(session, 'containerd', 42, 12)
        with self.assertRaises(durable.Rejected): session._fixed_jobs_absent()
        self.assertTrue(session.failed)

    def test_remaining_fixed_job_refuses_despite_both_completions(self):
        session = self.watched(); self.stop(session); self.stop(session, 'containerd', 42, 12)
        self.connection.inventory = [[99, session.units['dockerd'].unit, 'start', 'waiting',
            bus.JOB_PREFIX+'99', bus.MANAGER_PATH+'/unit/dockerd']]
        with self.assertRaises(durable.Rejected): session._fixed_jobs_absent()

    def test_missing_role_and_unwatched_sessions_cannot_report_absence(self):
        for watched in (False, True):
            with self.subTest(watched=watched):
                session = self.watched() if watched else self.session()
                if watched: self.stop(session)
                with self.assertRaises(durable.Rejected): session._fixed_jobs_absent()

    def test_malformed_or_unauthenticated_admission_revokes(self):
        for change in (dict(sender=':1.8'), dict(path='/other'), dict(interface='other'),
                dict(member='Other'), dict(signature='s'), dict(cookie=0),
                dict(fields=[41, bus.JOB_PREFIX+'42', 'fixture-dockerd.service'])):
            with self.subTest(change=change):
                session = self.watched()
                self.connection.queue.append(lambda:self.connection.admission(**change))
                with self.assertRaises(durable.Rejected): session.identity()
                self.assertTrue(session.failed)

    def test_unrelated_jobs_are_not_adopted_but_overflow_revokes(self):
        session = self.watched()
        self.connection.queue.append(lambda:self.connection.admission(
            fields=[99, bus.JOB_PREFIX+'99', 'other.service']))
        session.identity()
        self.assertEqual(session._created, {})
        session._event_count = bus.MAX_EVENTS
        self.connection.queue.append(lambda:self.connection.admission(
            fields=[100, bus.JOB_PREFIX+'100', 'other.service'], cookie=11))
        with self.assertRaises(durable.Rejected): session.identity()

    def test_match_must_be_installed_and_cannot_be_restarted(self):
        session = self.session()
        original = ScriptedConnection.match
        def match(connection, rule, function):
            if "member='JobNew'" in rule:
                connection.wait_hook = lambda:setattr(self, 'now', 1090.)
                return []
            return original(connection, rule, function)
        with patch.object(ScriptedConnection, 'match', match):
            with self.assertRaises(durable.Rejected): session._watch_fixed_jobs()
        self.now = 1000.
        session = self.watched()
        with self.assertRaises(durable.Rejected): session._watch_fixed_jobs()
        self.assertTrue(session.failed)


class ForwardAdmissionTests(unittest.TestCase):
    setUp = forward_fixture.MaskedForwardStopTests.setUp
    make = forward_fixture.MaskedForwardStopTests.make
    current = forward_fixture.MaskedForwardStopTests.current
    apply = forward_fixture.MaskedForwardStopTests.apply
    effects = forward_fixture.MaskedForwardStopTests.effects

    def test_unexpected_job_during_reload_prevents_stop(self):
        reached = []
        def hook(method):
            if method == 'Reload':
                reached.append(method)
                self.connection.queue.append(lambda:self.connection.admission(role='forward', number=99, cookie=99))
        self.effect_hook = lambda method, args:hook(method)
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['Reload'])
        self.assertEqual(self.effects(), ['Cancel', 'Reload'])
        self.assertFalse(self.sequence.completed)
        self.assertNotIn('contain_forward', self.journal._returned)


class RuntimeAdmissionTests(unittest.TestCase):
    setUp = runtime_fixture.MaskedRuntimeStopTests.setUp
    make = runtime_fixture.MaskedRuntimeStopTests.make
    make_sequence = runtime_fixture.MaskedRuntimeStopTests.make_sequence
    apply = runtime_fixture.MaskedRuntimeStopTests.apply

    def test_admission_after_empty_publication_revokes_without_cold_return(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync' and (self.path_state/'operation-02-runtime-kill-empty.json').exists():
                reached.append(point)
                self.connection.queue.append(lambda:self.connection.admission(number=99, cookie=999))
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertFalse(self.sequence.completed)
        self.assertTrue(self.session.failed and self.journal._failed)
        self.assertNotIn('cold_quiesce_runtime', self.journal._returned)
        self.witness.close.assert_called_once()
