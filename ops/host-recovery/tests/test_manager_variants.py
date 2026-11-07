"""Typed native decoder with scripted ABI calls; no native library or bus."""
import ctypes as C
import unittest
from unittest.mock import Mock

from host_recovery import durable, manager_bus as bus


class VariantLibrary:
    def __init__(self, kind, values, *, signature=b'v'):
        self.kind, self.values, self.signature = kind, list(values), signature
        self.exits, self.entered = 0, []
        self.trailing = False

    def sd_bus_message_get_signature(self, message, complete): return self.signature
    def sd_bus_message_enter_container(self, message, container, contents):
        self.entered.append((container, contents))
        return int(container != b'v' or contents.decode() == self.kind)
    def sd_bus_message_exit_container(self, message):
        self.exits += 1
        return 0 if not self.values else -1
    def sd_bus_message_at_end(self, message, complete):
        return int(not self.values and not (complete and self.trailing))
    def sd_bus_message_read_basic(self, message, kind, pointer):
        if not self.values: return 0
        value = self.values.pop(0)
        if kind == b'y': C.cast(pointer, C.POINTER(C.c_uint8))[0] = value
        elif kind == b'u': C.cast(pointer, C.POINTER(C.c_uint32))[0] = value
        else: C.cast(pointer, C.POINTER(C.c_char_p))[0] = value
        return 1


class ManagerArgumentTests(unittest.TestCase):
    def encode(self, signature, args, *, method='KillUnit', interface=bus.MANAGER+'.Manager'):
        connection = object.__new__(bus._Connection)
        native = Mock()
        connection.lib, connection.bus = native, C.c_void_p(1)
        connection.error, connection.callbacks = None, []
        native.sd_bus_is_open.return_value = 1
        native.sd_bus_message_new_method_call.return_value = 1
        native.sd_bus_call_async.return_value = 1
        self.appended = []
        def append(message, kind, pointer):
            self.appended.append((kind, C.cast(pointer, C.POINTER(C.c_int32))[0]
                                  if kind == b'i' else C.cast(pointer, C.c_char_p).value))
            return 1
        native.sd_bus_message_append_basic.side_effect = append
        connection.call(':1.7', interface, method, signature, args, '', usec=1000)
        return native

    def test_fixed_whole_unit_sigkill_is_encoded_as_signed_int32(self):
        native = self.encode('ssi', ('fixture.service','all',9))
        self.assertEqual(self.appended, [(b's',b'fixture.service'),(b's',b'all'),(b'i',9)])
        self.assertEqual(native.sd_bus_call_async.call_count, 1)

    def test_other_integer_values_types_methods_or_interfaces_never_dispatch(self):
        for value, overrides in [(True,{}),(15,{}),(9.,{}),(9,dict(method='Other')),
                                 (9,dict(interface='other.Manager'))]:
            with self.subTest(value=value, overrides=overrides):
                with self.assertRaises(durable.Rejected):
                    self.encode('ssi', ('fixture.service','all',value), **overrides)
                self.assertFalse(any(kind == b'i' for kind, _ in self.appended))
        with self.assertRaises(durable.Rejected): self.encode('ssi', ('fixture.service','main',9))

    def test_argument_count_mismatch_does_not_silently_zip_truncate(self):
        for signature, args in [('ssi',('fixture.service','all')), ('ss',('fixture.service','all',9))]:
            with self.subTest(signature=signature):
                with self.assertRaises(durable.Rejected): self.encode(signature, args)
                self.assertEqual(self.appended, [])


class ManagerVariantTests(unittest.TestCase):
    def decode(self, kind, values, *, response=None, signature=b'v', trailing=False):
        connection = object.__new__(bus._Connection)
        native = VariantLibrary(kind, values, signature=signature)
        native.trailing = trailing
        connection.lib = native
        return connection.fields(None, 'v:'+(response or kind)), native

    def test_scalar_string_uint_and_job_tuple_require_exact_variant_types(self):
        for kind, raw, expected in [('s',[b'masked'],['masked']), ('u',[123],[123]),
                                    ('(uo)',[0,b'/'],[(0,'/')])]:
            with self.subTest(kind=kind):
                result, native = self.decode(kind,raw)
                self.assertEqual(result, expected)
                self.assertEqual(native.entered[0], (b'v',kind.encode()))
                self.assertEqual(native.exits, 2 if kind=='(uo)' else 1)

    def test_invocation_byte_array_is_not_a_display_string_or_truncated_identity(self):
        result, native = self.decode('ay',range(16))
        self.assertEqual(result, [bytes(range(16))])
        self.assertEqual(native.entered, [(b'v',b'ay'),(b'a',b'y')])
        # Length <16 is decodable but the mask reader must reject it. Never pad.
        self.assertEqual(self.decode('ay',[1,2])[0], [b'\x01\x02'])
        with self.assertRaises(durable.Rejected): self.decode('ay',range(17))

    def test_string_arrays_are_complete_and_bounded_including_empty(self):
        self.assertEqual(self.decode('as',[])[0], [[]])
        self.assertEqual(self.decode('as',[b'/one',b'/two'])[0], [['/one','/two']])
        with self.assertRaises(durable.Rejected): self.decode('as',[b'/one']*(bus.MAX_EVENTS+1))

    def test_wrong_top_signature_variant_type_unknown_kind_or_trailing_data_refuses(self):
        for kind, raw, overrides in [('s',[b'masked'],dict(signature=b's')),
                                     ('s',[b'masked'],dict(response='u')),
                                     ('b',[1],{}), ('s',[b'masked'],dict(trailing=True)),
                                     ('(uo)',[0,b'/',b'extra'],{})]:
            with self.subTest(kind=kind, overrides=overrides):
                with self.assertRaises(durable.Rejected): self.decode(kind,raw,**overrides)

    def test_missing_scalar_or_nonascii_text_is_never_defaulted(self):
        for kind, raw in [('s',[]), ('u',[]), ('(uo)',[0]), ('s',[b'\xff'])]:
            with self.subTest(kind=kind,raw=raw):
                with self.assertRaises((durable.Rejected,UnicodeError)): self.decode(kind,raw)
