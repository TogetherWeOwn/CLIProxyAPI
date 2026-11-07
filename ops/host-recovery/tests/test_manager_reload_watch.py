"""Post-reload signal refusal; scripted ABI/manager, never a reload interlock."""
import ctypes as C
import unittest
from unittest.mock import Mock, patch

from host_recovery import durable, manager_bus as bus
from test_manager_bus import ScriptedConnection
import test_manager_bus as session_fixture
import test_masked_forward_stop as forward_fixture
import test_masked_runtime_stop as runtime_fixture


def reloading(connection, **overrides):
    message = dict(signature='b', member='Reloading', cookie=999, fields=[True])
    message.update(overrides)
    callback = next(function for rule, function in connection.matches if "member='Reloading'" in rule)
    connection.queue.append(lambda:callback(message))


class ReloadWatchTests(unittest.TestCase):
    setUp = session_fixture.ManagerSessionTests.setUp
    session = session_fixture.ManagerSessionTests.session

    def watched(self):
        session = self.session()
        session._retain_fixed_units()
        session._watch_referenced_units()
        self.assertTrue(any("member='Reloading'" in rule for rule, _ in self.connection.matches))
        return session

    def test_both_reload_edges_revoke_without_adopting_reconstructed_units(self):
        for active in (True, False):
            with self.subTest(active=active):
                self.setUp(); session = self.watched()
                original = dict(session._fixed_unit_paths)
                reloading(self.connection, fields=[active])
                with self.assertRaises(durable.Rejected): session.identity()
                self.assertIs(session._reload_change_seen, active)
                self.assertEqual(session._fixed_unit_paths, original)
                self.assertTrue(session.failed)
                with self.assertRaises(durable.Rejected): session.stop('dockerd')
                self.assertFalse(any(method in ('Reload', 'StopUnit', 'KillUnit')
                    for _, method, _ in self.connection.calls))

    def test_reloading_match_must_be_acknowledged_before_stop(self):
        session = self.session(); session._retain_fixed_units()
        original = ScriptedConnection.match
        reached = []
        def match(connection, rule, callback):
            if "member='Reloading'" in rule:
                reached.append(rule)
                connection.wait_hook = lambda:setattr(self, 'now', 1090.)
                return []
            return original(connection, rule, callback)
        with patch.object(ScriptedConnection, 'match', match):
            with self.assertRaises(durable.Rejected): session._watch_referenced_units()
        self.assertEqual(len(reached), 1)
        self.assertTrue(session.failed)
        self.assertFalse(any(method == 'StopUnit' for _, method, _ in self.connection.calls))

    def test_bad_identity_signature_boolean_or_cookie_refuses(self):
        for change in (dict(sender=':1.8'), dict(path='/other'), dict(interface='other.Manager'),
                dict(member='Other'), dict(signature='u'), dict(fields=[1]), dict(fields=[]),
                dict(fields=[True, False]), dict(cookie=0)):
            with self.subTest(change=change):
                self.setUp(); session = self.watched()
                reloading(self.connection, **change)
                with self.assertRaises(durable.Rejected): session.identity()
                self.assertTrue(session.failed)
                self.assertIsNone(session._reload_change_seen)

    def test_overflow_or_stale_cookie_never_becomes_an_accepted_reload(self):
        for change in ('overflow', 'cookie'):
            with self.subTest(change=change):
                self.setUp(); session = self.watched()
                if change == 'overflow': session._event_count = bus.MAX_EVENTS
                else: session._last_cookie = 999
                reloading(self.connection)
                with self.assertRaises(durable.Rejected): session.identity()
                self.assertTrue(session.failed)
                self.assertIsNone(session._reload_change_seen)

    def test_reload_signal_during_match_installation_revokes_before_return(self):
        session = self.session(); session._retain_fixed_units()
        original = ScriptedConnection.match
        reached = []
        def match(connection, rule, callback):
            result = original(connection, rule, callback)
            if "member='Reloading'" in rule:
                reached.append(rule)
                reloading(connection)
            return result
        with patch.object(ScriptedConnection, 'match', match):
            with self.assertRaises(durable.Rejected): session._watch_referenced_units()
        self.assertEqual(len(reached), 1)
        self.assertIs(session._reload_change_seen, True)
        self.assertTrue(session.failed)


class BooleanABITests(unittest.TestCase):
    def decode(self, value, *, signature=b'b', result=1, trailing=False):
        connection = object.__new__(bus._Connection)
        native = Mock()
        connection.lib = native
        native.sd_bus_message_get_signature.return_value = signature
        native.sd_bus_message_at_end.return_value = int(not trailing)
        def read(message, kind, pointer):
            self.assertEqual(kind, b'b')
            C.cast(pointer, C.POINTER(C.c_int))[0] = value
            return result
        native.sd_bus_message_read_basic.side_effect = read
        return connection.fields(None, 'b')

    def test_native_boolean_uses_int_pointer_and_preserves_both_values(self):
        self.assertEqual(self.decode(0), [False])
        self.assertEqual(self.decode(1), [True])
        self.assertIs(type(self.decode(1)[0]), bool)

    def test_unknown_boolean_missing_field_wrong_signature_and_tail_refuse(self):
        for value, options in ((2, {}), (-1, {}), (1, dict(result=0)),
                (1, dict(signature=b'u')), (1, dict(trailing=True))):
            with self.subTest(value=value, options=options):
                with self.assertRaises(durable.Rejected): self.decode(value, **options)


class ForwardReloadWatchTests(unittest.TestCase):
    setUp = forward_fixture.MaskedForwardStopTests.setUp
    make = forward_fixture.MaskedForwardStopTests.make
    current = forward_fixture.MaskedForwardStopTests.current
    publish = forward_fixture.MaskedForwardStopTests.publish
    apply = forward_fixture.MaskedForwardStopTests.apply
    effects = forward_fixture.MaskedForwardStopTests.effects

    def test_reload_after_durable_return_prevents_any_fixed_stop(self):
        original = ScriptedConnection.match
        reached = []
        def match(connection, rule, callback):
            result = original(connection, rule, callback)
            if "member='Reloading'" in rule:
                self.assertTrue((self.path_state/'operation-01-mask-reload-return.json').is_file())
                reached.append(rule)
                reloading(connection)
            return result
        with patch.object(ScriptedConnection, 'match', match):
            with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(len(reached), 1)
        self.assertEqual(self.effects(), ['Cancel', 'Reload'])
        self.assertFalse(self.sequence.completed)
        self.assertTrue(self.journal._failed and self.session.failed)
        self.assertNotIn('contain_forward', self.journal._returned)


class RuntimeReloadWatchTests(unittest.TestCase):
    setUp = runtime_fixture.MaskedRuntimeStopTests.setUp
    make = runtime_fixture.MaskedRuntimeStopTests.make
    make_sequence = runtime_fixture.MaskedRuntimeStopTests.make_sequence
    apply = runtime_fixture.MaskedRuntimeStopTests.apply

    def test_reload_during_empty_publication_refuses_without_outer_return(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync' and (self.path_state/'operation-02-runtime-kill-empty.json').exists():
                reached.append(point)
                reloading(self.connection)
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertIs(self.session._reload_change_seen, True)
        self.assertFalse(self.sequence.completed)
        self.assertTrue(self.journal._failed and self.session.failed)
        self.assertNotIn('cold_quiesce_runtime', self.journal._returned)
        self.witness.close.assert_called_once()
