"""Scripted native ABI/session tests; no bus or shared library is opened here."""
import ctypes as C
import unittest
from unittest.mock import Mock, patch

from host_recovery import durable, manager_bus as bus
from host_recovery.protected_file import ProtectedFile
from test_manager import binding, observed


def units():
    return {role: binding(observed('fixture-'+role+'.service', 'd'*32, '/fixture/'+role))
            for role in ('dockerd', 'containerd')}


class ScriptedConnection:
    def __init__(self, library, address):
        self.address, self.lib = address, self
        self.calls, self.matches, self.queue = [], [], []
        self.error, self.closed, self.mode = None, False, 'done'
        self.owner, self.uid, self.pid = ':1.7', 0, 1
        self.cookie, self.number, self.reply_number, self.result = 10, 41, 41, 'done'
        self.job_units, self.inventory = units(), []
        self.client_name, self.references = ':1.99', {}
        self.call_hook = lambda method: None
        self.wait_hook = lambda: None

    def close(self): self.closed = True
    def unique_name(self):
        self.current()
        return self.client_name
    def current(self):
        if self.closed or self.error: raise durable.Rejected('scripted-connection-lost')
    def process(self):
        self.current()
        if not self.queue: return 0
        try: self.queue.pop(0)()
        except Exception as exc: self.error = exc
        self.current()
        return 1
    def wait(self, usec): self.wait_hook()
    def match(self, rule, function):
        self.matches.append((rule,function))
        return [True]
    def finish_call(self, slot, callback): pass
    def call(self, destination, interface, method, signature, args, response, **kwargs):
        self.calls.append((destination,method,args))
        self.call_hook(method)
        value = {'GetId':['a'*32], 'GetNameOwner':[self.owner], 'GetConnectionUnixUser':[self.uid],
                 'GetConnectionUnixProcessID':[self.pid], 'Subscribe':[], 'ListJobs':[self.inventory], 'RefUnit':[]}
        if method == 'GetUnit':
            role = next(role for role,unit in self.job_units.items() if unit.unit == args[0])
            value[method] = [bus.MANAGER_PATH + '/unit/' + role + '_service']
        if method == 'Get' and args == (bus.MANAGER + '.Unit', 'Refs'):
            role = kwargs['path'].rsplit('/', 1)[1].removesuffix('_service')
            value[method] = [self.references.get(self.job_units[role].unit, [])]
        result = []
        if method == 'RefUnit':
            def referenced():
                self.references.setdefault(args[0], []).append(self.client_name)
                result.append([])
            self.queue.append(referenced)
        elif method == 'StopUnit':
            role = next(role for role,unit in self.job_units.items() if unit.unit == args[0])
            if self.mode != 'absent': self.queue.append(lambda: self.event(role=role))
            self.queue.append(lambda: result.append([bus.JOB_PREFIX+str(self.reply_number)]))
        elif self.mode != 'stall': self.queue.append(lambda: result.append(value[method]))
        return result, None, None
    def fields(self, message, signature):
        if message.get('signature', 'uoss') != signature: raise durable.Rejected('scripted-signature')
        return message['fields']
    def sd_bus_message_get_sender(self, message): return message.get('sender', self.owner).encode()
    def sd_bus_message_get_path(self, message): return message.get('path', bus.MANAGER_PATH).encode()
    def sd_bus_message_get_interface(self, message): return message.get('interface', bus.MANAGER+'.Manager').encode()
    def sd_bus_message_get_member(self, message): return message.get('member', 'JobRemoved').encode()
    def sd_bus_message_get_cookie(self, message, pointer):
        C.cast(pointer, C.POINTER(C.c_uint64))[0] = message.get('cookie', self.cookie)
        return 1
    def event(self, role='dockerd', **overrides):
        message = dict(fields=[self.number,bus.JOB_PREFIX+str(self.number),self.job_units[role].unit,self.result])
        message.update(overrides)
        self.matches[0][1](message)
    def admission(self, role='dockerd', number=41, **overrides):
        message = dict(fields=[number,bus.JOB_PREFIX+str(number),self.job_units[role].unit],
                       signature='uos', member='JobNew')
        message.update(overrides)
        next(function for rule,function in self.matches if "member='JobNew'" in rule)(message)


class ManagerSessionTests(unittest.TestCase):
    def setUp(self):
        self.now, self.check_hook = 1000., lambda: None
        self.library = Mock(spec=ProtectedFile)
        self.library.uid = self.library.gid = 0
        self.library.fd = 99
        self.library.checksum.return_value = 'a'*64
        self.connection = None
        self.native_patch = patch.object(bus, '_Library', return_value=object())
        self.native_patch.start(); self.addCleanup(self.native_patch.stop)
        def connect(library, address):
            self.connection = ScriptedConnection(library,address)
            return self.connection
        self.connection_patch = patch.object(bus, '_Connection', side_effect=connect)
        self.connect_mock = self.connection_patch.start(); self.addCleanup(self.connection_patch.stop)

    def session(self):
        result = bus.ManagerJobSession(library=self.library,library_sha256='a'*64,units=units(),
            deadline=1090.,clock=lambda:self.now,check=lambda:self.check_hook())
        self.addCleanup(result.close)
        return result

    def test_one_fixed_system_connection_subscribes_before_any_stop(self):
        session = self.session()
        self.assertEqual(self.connection.address,b'unix:path=/run/dbus/system_bus_socket')
        self.assertEqual(len(self.connection.matches),2)
        self.assertIn('JobRemoved',self.connection.matches[0][0])
        self.assertIn('NameOwnerChanged',self.connection.matches[1][0])
        self.assertFalse(any(method == 'StopUnit' for _,method,_ in self.connection.calls))
        session.stop('dockerd')
        self.assertEqual(session.completions()['dockerd']['result'],'done')
        self.assertEqual([item for item in self.connection.calls if item[1]=='StopUnit'],
                         [(':1.7','StopUnit',('fixture-dockerd.service','fail'))])

    def test_disappearance_without_signal_never_manufactures_completion(self):
        session = self.session(); self.connection.mode = 'absent'
        session.stop('dockerd')
        self.assertEqual(session.jobs(),{})
        self.assertEqual(session.completions(),{})

    def test_early_signal_must_match_actual_returned_job_identity(self):
        session = self.session(); self.connection.reply_number = 42
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertTrue(session.failed)
        self.assertEqual(session._events[41]['job_id'],41)

    def test_failed_and_canceled_results_are_not_success(self):
        for result in ('failed','canceled','timeout','dependency'):
            with self.subTest(result=result):
                session = self.session(); self.connection.result = result
                session.stop('dockerd')
                self.assertEqual(session.completions()['dockerd']['result'],result)

    def test_duplicate_signal_revokes_even_if_bytes_match(self):
        session = self.session(); session.stop('dockerd')
        self.connection.queue.append(lambda:self.connection.event())
        with self.assertRaises(durable.Rejected): session.completions()
        self.assertTrue(session.failed)

    def test_unknown_completion_for_fixed_unit_refuses_before_stop(self):
        session = self.session()
        self.connection.queue.append(lambda:self.connection.event())
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertFalse(any(method == 'StopUnit' for _,method,_ in self.connection.calls))

    def test_wrong_sender_path_interface_member_signature_and_result_revoke(self):
        for change in (dict(sender=':1.8'),dict(path='/other'),dict(interface='other.Manager'),
                       dict(member='Other'),dict(signature='s'),dict(fields=[41,bus.JOB_PREFIX+'41',
                       'fixture-dockerd.service','unknown'])):
            with self.subTest(change=change):
                session = self.session(); self.connection.mode = 'absent'; session.stop('dockerd')
                self.connection.queue.append(lambda:self.connection.event(**change))
                with self.assertRaises(durable.Rejected): session.completions()

    def test_wrong_job_path_or_reused_cookie_is_not_completion(self):
        for change in (dict(fields=[41,bus.JOB_PREFIX+'42','fixture-dockerd.service','done']),dict(cookie=0)):
            with self.subTest(change=change):
                session = self.session(); self.connection.mode = 'absent'; session.stop('dockerd')
                self.connection.queue.append(lambda:self.connection.event(**change))
                with self.assertRaises(durable.Rejected): session.completions()

    def test_bus_disconnect_is_sticky_and_never_reconnects(self):
        session = self.session(); self.connection.close()
        with self.assertRaises(durable.Rejected): session.identity()
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(self.connect_mock.call_count,1)

    def test_owner_loss_and_reacquisition_revokes_same_unique_name(self):
        session = self.session()
        message = dict(sender=bus.DBUS,signature='sss',fields=[bus.MANAGER,':1.7',':1.7'])
        self.connection.queue.append(lambda:self.connection.matches[1][1](message))
        with self.assertRaises(durable.Rejected): session.identity()
        self.assertTrue(session.failed)

    def test_owner_point_drift_also_refuses(self):
        session = self.session(); self.connection.owner = ':1.8'
        with self.assertRaises(durable.Rejected): session.identity()

    def test_root_pid_one_is_required_not_just_a_service_name(self):
        for field,value in (('uid',1000),('pid',123)):
            with self.subTest(field=field):
                session = self.session(); setattr(self.connection,field,value)
                with self.assertRaises(durable.Rejected): session.stop('dockerd')
                self.assertFalse(any(method=='StopUnit' for _,method,_ in self.connection.calls))

    def test_no_retry_after_returned_or_ambiguous_stop(self):
        session = self.session(); session.stop('dockerd')
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(sum(method=='StopUnit' for _,method,_ in self.connection.calls),1)

    def test_no_arbitrary_unit_start_or_cancel_method(self):
        session = self.session()
        with self.assertRaises(durable.Rejected): session.stop('unrelated.service')
        self.assertFalse(any(method in ('StopUnit','StartUnit','CancelJob') for _,method,_ in self.connection.calls))

    def test_deadline_expansion_rollback_nan_and_expiry_revoke(self):
        for action in ('expand','backwards','nan','expired'):
            with self.subTest(action=action):
                self.now = 1000.; session = self.session()
                if action=='expand': session.deadline = 1200.
                else: self.now = dict(backwards=999.,nan=float('nan'),expired=1090.)[action]
                with self.assertRaises(durable.Rejected): session.stop('dockerd')

    def test_lost_authority_while_waiting_for_reply_revokes(self):
        session = self.session(); self.connection.mode = 'stall'
        self.connection.wait_hook = lambda:setattr(self,'check_hook',lambda:(_ for _ in ()).throw(durable.Rejected('peer-lost')))
        with self.assertRaises(durable.Rejected): session.identity()
        self.assertTrue(session.failed)

    def test_authority_check_cannot_spend_deadline_and_still_send(self):
        session = self.session(); self.check_hook = lambda:setattr(self,'now',1090.)
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertFalse(any(method=='StopUnit' for _,method,_ in self.connection.calls))

    def test_unit_configuration_mutation_refuses(self):
        session = self.session(); session.units = units(); session.units.pop('dockerd')
        with self.assertRaises(durable.Rejected): session.stop('containerd')

    def test_library_hash_or_protected_metadata_failure_prevents_connection(self):
        self.library.checksum.return_value = 'b'*64
        with self.assertRaises(durable.Rejected): self.session()
        self.assertIsNone(self.connection)
        self.library.checksum.return_value = 'a'*64
        self.library.validate.side_effect = durable.Rejected('changed')
        with self.assertRaises(durable.Rejected): self.session()
        self.assertIsNone(self.connection)

    def test_completion_values_are_copied_not_borrowed(self):
        session = self.session(); session.stop('dockerd')
        value = session.completions(); value['dockerd']['result'] = 'failed'
        self.assertEqual(session.completions()['dockerd']['result'],'done')

    def test_unrelated_event_is_not_adopted_as_runtime_completion(self):
        session = self.session(); self.connection.mode = 'absent'; session.stop('dockerd')
        self.connection.queue.append(lambda:self.connection.event(fields=[99,bus.JOB_PREFIX+'99','other.service','done']))
        self.assertEqual(session.completions(),{})

    def test_event_or_dispatch_overflow_fails_closed(self):
        session = self.session(); session._event_count = bus.MAX_EVENTS
        self.connection.mode = 'absent'; session.stop('dockerd')
        self.connection.queue.append(lambda:self.connection.event())
        with self.assertRaises(durable.Rejected): session.completions()

    def test_match_installation_must_be_acknowledged_before_subscribe_or_stop(self):
        def unacknowledged(connection, rule, function):
            connection.wait_hook = lambda:setattr(self,'now',1090.)
            return []
        with patch.object(ScriptedConnection,'match',unacknowledged):
            with self.assertRaises(durable.Rejected): self.session()
        self.assertFalse(any(method in ('Subscribe','StopUnit') for _,method,_ in self.connection.calls))
        self.assertTrue(self.connection.closed)

    def test_trailing_authority_read_cannot_change_fixed_configuration(self):
        session = self.session()
        self.check_hook = lambda:session.units.pop('dockerd',None)
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertFalse(any(method=='StopUnit' for _,method,_ in self.connection.calls))

    def test_same_job_id_cannot_be_reused_for_second_fixed_role(self):
        session = self.session(); session.stop('dockerd')
        self.connection.mode = 'absent'
        with self.assertRaises(durable.Rejected): session.stop('containerd')
        self.assertEqual(sum(method=='StopUnit' for _,method,_ in self.connection.calls),2)


class FixedUnitReferenceTests(unittest.TestCase):
    setUp = ManagerSessionTests.setUp
    session = ManagerSessionTests.session

    def removal(self, session, **overrides):
        if not session._referenced_units_watched: session._watch_referenced_units()
        message = dict(signature='so', member='UnitRemoved', cookie=20,
            fields=[session.units['dockerd'].unit, bus.MANAGER_PATH + '/unit/dockerd_service'])
        message.update(overrides)
        callback = next(function for rule,function in self.connection.matches if "member='UnitRemoved'" in rule)
        self.connection.queue.append(lambda:callback(message))

    def test_exact_fixed_references_and_acknowledged_own_sender_readback(self):
        session = self.session()
        paths = session._retain_fixed_units()
        self.assertEqual(set(paths), set(session.units))
        self.assertEqual([args for _,method,args in self.connection.calls if method == 'RefUnit'],
                         [(unit.unit,) for unit in session.units.values()])
        self.assertEqual(self.connection.references, {unit.unit:[':1.99'] for unit in session.units.values()})
        for role,path in paths.items(): session._fixed_unit_reference(role, path)
        self.assertFalse(any(method in ('StopUnit','Reload','UnrefUnit') for _,method,_ in self.connection.calls))
        paths.clear()
        self.assertEqual(len(session._fixed_unit_paths), 2)

    def test_duplicate_reference_attempt_never_redispatches(self):
        session = self.session(); session._retain_fixed_units()
        with self.assertRaises(durable.Rejected): session._retain_fixed_units()
        self.assertEqual(sum(method == 'RefUnit' for _,method,_ in self.connection.calls), 2)
        self.assertTrue(session.failed)

    def test_lost_reference_reply_retains_failure_without_retry_or_unref(self):
        session = self.session()
        original = ScriptedConnection.call
        def call(connection, destination, interface, method, signature, args, response, **kwargs):
            result = original(connection, destination, interface, method, signature, args, response, **kwargs)
            if method == 'RefUnit':
                def lost():
                    self.now = 1090.
                connection.queue.append(lost)
                connection.queue[0] = lambda:connection.references.setdefault(args[0], []).append(connection.client_name)
            return result
        with patch.object(ScriptedConnection, 'call', call):
            with self.assertRaises(durable.Rejected): session._retain_fixed_units()
        self.assertEqual(sum(method == 'RefUnit' for _,method,_ in self.connection.calls), 1)
        self.assertTrue(self.connection.references)
        self.assertTrue(session.failed)
        session.close()
        self.assertTrue(self.connection.closed)
        self.assertFalse(any(method == 'UnrefUnit' for _,method,_ in self.connection.calls))

    def test_unit_removal_revokes_even_if_same_name_and_path_reappear(self):
        session = self.session(); session._retain_fixed_units()
        self.removal(session)
        with self.assertRaises(durable.Rejected): session.identity()
        self.assertTrue(session.failed)

    def test_post_reload_removal_match_requires_acknowledgment(self):
        session = self.session(); session._retain_fixed_units()
        def unacknowledged(connection, rule, callback):
            self.assertIn("member='UnitRemoved'", rule)
            connection.wait_hook = lambda:setattr(self, 'now', 1090.)
            return []
        with patch.object(ScriptedConnection, 'match', unacknowledged):
            with self.assertRaises(durable.Rejected): session._watch_referenced_units()
        self.assertTrue(session.failed)
        self.assertFalse(any(method == 'StopUnit' for _,method,_ in self.connection.calls))

    def test_other_unit_removal_is_not_adopted_or_a_fixed_removal(self):
        session = self.session(); session._retain_fixed_units()
        self.removal(session, fields=['other.service', bus.MANAGER_PATH + '/unit/other_service'])
        self.assertEqual(session.identity(), ('a'*32, ':1.7'))
        self.assertEqual(session._events, {})

    def test_reference_from_another_sender_or_duplicate_own_reference_refuses(self):
        for refs in ([], [':1.100'], [':1.99', ':1.99'], ['not-a-unique-name'], (':1.99',)):
            with self.subTest(refs=refs):
                self.setUp(); session = self.session(); paths = session._retain_fixed_units()
                self.connection.references[session.units['dockerd'].unit] = refs
                with self.assertRaises(durable.Rejected): session._fixed_unit_reference('dockerd', paths['dockerd'])
                self.assertTrue(session.failed)

    def test_client_identity_or_bound_unit_path_drift_refuses(self):
        for drift in ('sender', 'path'):
            with self.subTest(drift=drift):
                self.setUp(); session = self.session(); paths = session._retain_fixed_units()
                if drift == 'sender': self.connection.client_name = ':1.100'
                path = paths['dockerd'] if drift == 'sender' else bus.MANAGER_PATH + '/unit/other_service'
                with self.assertRaises(durable.Rejected): session._fixed_unit_reference('dockerd', path)
                self.assertTrue(session.failed)

    def test_malformed_or_unauthenticated_removal_refuses(self):
        for overrides in ({'sender':':1.8'}, {'member':'UnitNew'}, {'signature':'ss'}, {'cookie':0},
                          {'fields':['other.service','/unexpected/path']}):
            with self.subTest(overrides=overrides):
                self.setUp(); session = self.session(); session._retain_fixed_units()
                self.removal(session, **overrides)
                with self.assertRaises(durable.Rejected): session.identity()
                self.assertTrue(session.failed)

    def test_reference_requires_unused_original_session(self):
        session = self.session(); session._watch_fixed_jobs()
        with self.assertRaises(durable.Rejected): session._retain_fixed_units()
        self.assertFalse(any(method == 'RefUnit' for _,method,_ in self.connection.calls))


class ClientNameABITests(unittest.TestCase):
    def connection(self, name, result=0):
        connection = object.__new__(bus._Connection)
        connection.bus, connection.error, connection.lib = C.c_void_p(1), None, Mock()
        connection.lib.sd_bus_is_open.return_value = 1
        def get_name(handle, pointer):
            C.cast(pointer, C.POINTER(C.c_char_p))[0] = name
            return result
        connection.lib.sd_bus_get_unique_name.side_effect = get_name
        return connection

    def test_native_client_name_uses_typed_output_pointer(self):
        self.assertEqual(self.connection(b':1.99').unique_name(), ':1.99')

    def test_failed_missing_or_nonunique_client_name_refuses(self):
        for name, result in ((b':1.99', -5), (None, 0), (b'org.freedesktop.systemd1', 0), (b':1.99\xff', 0)):
            with self.subTest(name=name, result=result):
                with self.assertRaises((durable.Rejected, UnicodeError)):
                    self.connection(name, result).unique_name()


class ExecutionTimestampABITests(unittest.TestCase):
    def connection(self, number):
        connection = object.__new__(bus._Connection)
        connection.lib = Mock()
        connection.lib.sd_bus_message_get_signature.return_value = b'v'
        connection.lib.sd_bus_message_enter_container.return_value = 1
        connection.lib.sd_bus_message_exit_container.return_value = 1
        connection.lib.sd_bus_message_at_end.return_value = 1
        def read(message, kind, pointer):
            self.assertEqual(kind, b't')
            C.cast(pointer, C.POINTER(C.c_uint64))[0] = number
            return 1
        connection.lib.sd_bus_message_read_basic.side_effect = read
        return connection

    def test_uint64_variant_preserves_values_larger_than_uint32(self):
        for value in (0, 2**32+123, 2**63+321, 2**64-1):
            with self.subTest(value=value):
                connection = self.connection(value)
                self.assertEqual(connection.fields(None, 'v:t'), [value])
                connection.lib.sd_bus_message_enter_container.assert_called_once_with(None, b'v', b't')

    def test_timestamp_variant_mismatch_or_missing_basic_refuses(self):
        connection = self.connection(123)
        connection.lib.sd_bus_message_enter_container.return_value = 0
        with self.assertRaises(durable.Rejected): connection.fields(None, 'v:t')
        connection.lib.sd_bus_message_read_basic.assert_not_called()
        connection = self.connection(123)
        connection.lib.sd_bus_message_read_basic.side_effect = None
        connection.lib.sd_bus_message_read_basic.return_value = 0
        with self.assertRaises(durable.Rejected): connection.fields(None, 'v:t')

    def test_timestamp_variant_trailing_data_refuses(self):
        connection = self.connection(123)
        connection.lib.sd_bus_message_at_end.return_value = 0
        with self.assertRaises(durable.Rejected): connection.fields(None, 'v:t')


class EmptyExitStatusABITests(unittest.TestCase):
    def connection(self):
        connection = object.__new__(bus._Connection)
        connection.lib = Mock()
        connection.lib.sd_bus_message_get_signature.return_value = b'v'
        connection.lib.sd_bus_message_enter_container.return_value = 1
        connection.lib.sd_bus_message_exit_container.return_value = 1
        connection.lib.sd_bus_message_at_end.return_value = 1
        return connection

    def test_two_explicit_empty_exit_status_arrays_are_required(self):
        connection = self.connection()
        self.assertEqual(connection.fields(None, 'v:(aiai)'), [[[], []]])
        self.assertEqual([call.args for call in connection.lib.sd_bus_message_enter_container.call_args_list],
            [(None, b'v', b'(aiai)'), (None, b'r', b'aiai'), (None, b'a', b'i'), (None, b'a', b'i')])
        connection.lib.sd_bus_message_read_basic.assert_not_called()
        self.assertEqual(connection.lib.sd_bus_message_exit_container.call_count, 4)

    def test_nonempty_or_uncertain_exit_status_array_refuses_without_reading_codes(self):
        for result in (0, -1):
            for position in (0, 1):
                with self.subTest(result=result, position=position):
                    connection = self.connection()
                    connection.lib.sd_bus_message_at_end.side_effect = [1] * position + [result]
                    with self.assertRaises(durable.Rejected): connection.fields(None, 'v:(aiai)')
                    connection.lib.sd_bus_message_read_basic.assert_not_called()

    def test_missing_variant_struct_or_either_array_refuses(self):
        for position in range(4):
            with self.subTest(position=position):
                connection = self.connection()
                connection.lib.sd_bus_message_enter_container.side_effect = [1] * position + [0]
                with self.assertRaises(durable.Rejected): connection.fields(None, 'v:(aiai)')

    def test_trailing_struct_or_message_data_refuses(self):
        for position in (2, 3):
            with self.subTest(position=position):
                connection = self.connection()
                connection.lib.sd_bus_message_at_end.side_effect = [1] * position + [0]
                with self.assertRaises(durable.Rejected): connection.fields(None, 'v:(aiai)')


class EmptyCommandListABITests(unittest.TestCase):
    def connection(self):
        connection = object.__new__(bus._Connection)
        connection.lib = Mock()
        connection.lib.sd_bus_message_get_signature.return_value = b'v'
        connection.lib.sd_bus_message_enter_container.return_value = 1
        connection.lib.sd_bus_message_exit_container.return_value = 1
        connection.lib.sd_bus_message_at_end.return_value = 1
        return connection

    def test_exact_empty_exec_list_abi_is_read_without_any_command_field(self):
        connection = self.connection()
        self.assertEqual(connection.fields(None, 'v:a(sasbttttuii)'), [[]])
        self.assertEqual([call.args for call in connection.lib.sd_bus_message_enter_container.call_args_list],
                         [(None, b'v', b'a(sasbttttuii)'), (None, b'a', b'(sasbttttuii)')])
        connection.lib.sd_bus_message_read_basic.assert_not_called()
        self.assertEqual(connection.lib.sd_bus_message_exit_container.call_count, 2)

    def test_nonempty_or_uncertain_array_refuses_without_decoding_argv(self):
        for code in (0, -1):
            with self.subTest(code=code):
                connection = self.connection()
                connection.lib.sd_bus_message_at_end.return_value = code
                with self.assertRaises(durable.Rejected): connection.fields(None, 'v:a(sasbttttuii)')
                connection.lib.sd_bus_message_read_basic.assert_not_called()

    def test_missing_variant_or_array_refuses(self):
        for returns in ((0,), (1, 0)):
            with self.subTest(returns=returns):
                connection = self.connection()
                connection.lib.sd_bus_message_enter_container.side_effect = returns
                with self.assertRaises(durable.Rejected): connection.fields(None, 'v:a(sasbttttuii)')

    def test_empty_array_does_not_hide_trailing_message_data(self):
        connection = self.connection()
        connection.lib.sd_bus_message_at_end.side_effect = [1, 0]
        with self.assertRaises(durable.Rejected): connection.fields(None, 'v:a(sasbttttuii)')

    def test_unknown_exec_array_shape_is_not_coerced_to_empty(self):
        connection = self.connection()
        with self.assertRaises(durable.Rejected): connection.fields(None, 'v:a(sasasttttuii)')
        connection.lib.sd_bus_message_enter_container.assert_not_called()
