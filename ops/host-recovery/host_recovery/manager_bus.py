"""One non-reconnecting sd-bus connection for fixed stop-job witnesses.

This embedding transport is not an installed broker, activation interlock or cold
barrier. The caller retains the original authority/journal and protected library
handle. Fixed forward OR runtime StopUnit calls and the separate journaled
mask_reload and waiting-start cancellation phases use it; no arbitrary dispatch
or numeric job cancellation is exposed. Completion delivery and reload return do
not prove runtime drain.
"""
import ctypes as C
import math
import re
import threading

from .durable import Rejected, canonical, decode
from .manager import INVOCATION, UnitBinding
from .manager_jobs import JOB_PREFIX, MANAGER, MANAGER_PATH, UNIQUE, fixed_roles, job_path, jobs_reply
from .protected_file import ProtectedFile

SYSTEM_ADDRESS = b"unix:path=/run/dbus/system_bus_socket"
DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
MAX_EVENTS = 256
RESULTS = frozenset(("done", "canceled", "timeout", "failed", "dependency", "skipped",
                     "invalid", "assert", "unsupported", "collected", "once"))
CALLBACK = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p)


class _Library:
    """Small typed libsystemd ABI; construction never connects to any bus."""
    def __init__(self, path):
        self.lib = C.CDLL(path)
        pointer, integer, text = C.c_void_p, C.c_int, C.c_char_p
        self._declare("sd_bus_new", integer, C.POINTER(pointer))
        self._declare("sd_bus_set_address", integer, pointer, text)
        self._declare("sd_bus_set_bus_client", integer, pointer, integer)
        self._declare("sd_bus_start", integer, pointer)
        self._declare("sd_bus_is_open", integer, pointer)
        self._declare("sd_bus_get_unique_name", integer, pointer, C.POINTER(text))
        self._declare("sd_bus_process", integer, pointer, C.POINTER(pointer))
        self._declare("sd_bus_wait", integer, pointer, C.c_uint64)
        self._declare("sd_bus_close", None, pointer)
        self._declare("sd_bus_unref", pointer, pointer)
        self._declare("sd_bus_slot_unref", pointer, pointer)
        self._declare("sd_bus_message_unref", pointer, pointer)
        self._declare("sd_bus_message_new_method_call", integer, pointer, C.POINTER(pointer), text, text, text, text)
        self._declare("sd_bus_message_append_basic", integer, pointer, C.c_char, pointer)
        self._declare("sd_bus_message_read_basic", integer, pointer, C.c_char, pointer)
        self._declare("sd_bus_message_enter_container", integer, pointer, C.c_char, text)
        self._declare("sd_bus_message_exit_container", integer, pointer)
        self._declare("sd_bus_message_at_end", integer, pointer, integer)
        self._declare("sd_bus_message_get_signature", text, pointer, integer)
        self._declare("sd_bus_message_get_sender", text, pointer)
        self._declare("sd_bus_message_get_path", text, pointer)
        self._declare("sd_bus_message_get_interface", text, pointer)
        self._declare("sd_bus_message_get_member", text, pointer)
        self._declare("sd_bus_message_get_cookie", integer, pointer, C.POINTER(C.c_uint64))
        self._declare("sd_bus_message_is_method_error", integer, pointer, text)
        self._declare("sd_bus_call_async", integer, pointer, C.POINTER(pointer), pointer, CALLBACK, pointer, C.c_uint64)
        self._declare("sd_bus_add_match_async", integer, pointer, C.POINTER(pointer), text, CALLBACK, CALLBACK, pointer)

    def _declare(self, name, result, *args):
        function = getattr(self.lib, name)
        function.restype, function.argtypes = result, args
        setattr(self, name, function)


def _ok(result):
    if result < 0:
        # Native errors may contain peer-supplied text. Keep public errors fixed.
        raise Rejected("manager-bus-native-call-unconfirmed")
    return result


def _text(value):
    if value is None or len(value) > 4096:
        raise Rejected("manager-bus-text-limit")
    return value.decode("ascii")


class _Connection:
    """Internal typed transport. No reconnect, environment address or bus fallback."""
    def __init__(self, library, address):
        self.lib, self.bus = library, C.c_void_p()
        self.slots, self.callbacks = [], []
        self.error = None
        try:
            _ok(library.sd_bus_new(C.byref(self.bus)))
            _ok(library.sd_bus_set_address(self.bus, address))
            _ok(library.sd_bus_set_bus_client(self.bus, 1))
            _ok(library.sd_bus_start(self.bus))
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.bus:
            self.lib.sd_bus_close(self.bus)
            for slot in self.slots:
                self.lib.sd_bus_slot_unref(slot)
            self.slots.clear()
            self.lib.sd_bus_unref(self.bus)
            self.bus = C.c_void_p()
        # Callbacks must outlive every native slot referencing them.
        self.callbacks.clear()

    def _callback(self, function):
        def callback(message, userdata, error):
            try:
                function(message)
            except BaseException:
                self.error = Rejected("manager-bus-callback-unconfirmed")
            return 1
        value = CALLBACK(callback)
        self.callbacks.append(value)
        return value

    def current(self):
        if self.error is not None or not self.bus or self.lib.sd_bus_is_open(self.bus) <= 0:
            raise Rejected("manager-bus-connection-lost")

    def unique_name(self):
        self.current()
        name = C.c_char_p()
        _ok(self.lib.sd_bus_get_unique_name(self.bus, C.byref(name)))
        value = _text(name.value)
        if UNIQUE.fullmatch(value) is None:
            raise Rejected("manager-bus-client-name-unconfirmed")
        self.current()
        return value

    def process(self):
        self.current()
        result = _ok(self.lib.sd_bus_process(self.bus, None))
        self.current()
        return result

    def wait(self, usec):
        self.current()
        _ok(self.lib.sd_bus_wait(self.bus, usec))
        self.current()

    def basic(self, message, kind):
        value = (C.c_uint8() if kind == "y" else C.c_uint32() if kind == "u" else
                 C.c_uint64() if kind == "t" else C.c_int() if kind == "b" else C.c_char_p())
        if self.lib.sd_bus_message_read_basic(message, kind.encode(), C.byref(value)) <= 0:
            raise Rejected("manager-bus-message-field-required")
        if kind == "b":
            if value.value not in (0, 1):
                raise Rejected("manager-bus-boolean-unconfirmed")
            return bool(value.value)
        return value.value if kind in ("u", "y", "t") else _text(value.value)

    def fields(self, message, signature):
        expected = "v" if signature.startswith("v:") else signature
        if _text(self.lib.sd_bus_message_get_signature(message, 1)) != expected:
            raise Rejected("manager-bus-message-signature")
        if signature.startswith("v:"):
            kind = signature[2:]
            if kind not in ("s", "u", "t", "as", "ay", "(uo)"):
                raise Rejected("manager-bus-fixed-variant-required")
            if self.lib.sd_bus_message_enter_container(message, b"v", kind.encode()) <= 0:
                raise Rejected("manager-bus-property-type-required")
            if kind in ("as", "ay"):
                element = kind[1:]
                if self.lib.sd_bus_message_enter_container(message, b"a", element.encode()) <= 0:
                    raise Rejected("manager-bus-property-array-required")
                items = []
                while self.lib.sd_bus_message_at_end(message, 0) == 0:
                    if len(items) >= (16 if kind == "ay" else MAX_EVENTS):
                        raise Rejected("manager-bus-property-array-limit")
                    items.append(self.basic(message, element))
                _ok(self.lib.sd_bus_message_exit_container(message))
                values = [bytes(items) if kind == "ay" else items]
            elif kind == "(uo)":
                if self.lib.sd_bus_message_enter_container(message, b"r", b"uo") <= 0:
                    raise Rejected("manager-bus-property-job-required")
                values = [(self.basic(message, "u"), self.basic(message, "o"))]
                _ok(self.lib.sd_bus_message_exit_container(message))
            else:
                values = [self.basic(message, kind)]
            _ok(self.lib.sd_bus_message_exit_container(message))
        elif signature == "a(usssoo)":
            _ok(self.lib.sd_bus_message_enter_container(message, b"a", b"(usssoo)"))
            result = []
            while self.lib.sd_bus_message_at_end(message, 0) == 0:
                if len(result) >= MAX_EVENTS:
                    raise Rejected("manager-bus-job-inventory-limit")
                if self.lib.sd_bus_message_enter_container(message, b"r", b"usssoo") <= 0:
                    raise Rejected("manager-bus-job-row-required")
                result.append([self.basic(message, kind) for kind in "usssoo"])
                _ok(self.lib.sd_bus_message_exit_container(message))
            _ok(self.lib.sd_bus_message_exit_container(message))
            values = [result]
        else:
            if any(kind not in "soub" for kind in signature):
                raise Rejected("manager-bus-fixed-signature-required")
            values = [self.basic(message, kind) for kind in signature]
        if self.lib.sd_bus_message_at_end(message, 1) != 1:
            raise Rejected("manager-bus-message-trailing-data")
        return values

    def call(self, destination, interface, method, signature, args, response, *, usec, path=MANAGER_PATH):
        self.current()
        message, slot, result = C.c_void_p(), C.c_void_p(), []
        callback = None
        try:
            _ok(self.lib.sd_bus_message_new_method_call(self.bus, C.byref(message), destination.encode(),
                path.encode(), interface.encode(), method.encode()))
            if len(signature) != len(args):
                raise Rejected("manager-bus-fixed-argument-count")
            for kind, value in zip(signature, args):
                if kind == "s" and type(value) is str:
                    pointer = C.cast(C.c_char_p(value.encode()), C.c_void_p)
                elif (kind == "i" and type(value) is int and value == 9
                        and interface == MANAGER + ".Manager" and method == "KillUnit"
                        and signature == "ssi" and args[1] == "all"):
                    number = C.c_int32(value)
                    pointer = C.cast(C.byref(number), C.c_void_p)
                else:
                    raise Rejected("manager-bus-fixed-argument-required")
                _ok(self.lib.sd_bus_message_append_basic(message, kind.encode(), pointer))
            def returned(reply):
                if self.lib.sd_bus_message_is_method_error(reply, None) != 0:
                    raise Rejected("manager-bus-method-return-unconfirmed")
                sender = _text(self.lib.sd_bus_message_get_sender(reply))
                if sender != destination:
                    raise Rejected("manager-bus-method-sender-changed")
                result.append(self.fields(reply, response))
            callback = self._callback(returned)
            _ok(self.lib.sd_bus_call_async(self.bus, C.byref(slot), message, callback, None, usec))
            # Retained only while the call is outstanding. The caller's pump
            # checks original peer/lock/input/deadline authority between dispatches.
            return result, slot, callback
        except BaseException:
            if slot:
                self.lib.sd_bus_slot_unref(slot)
            if callback is not None:
                self.callbacks.remove(callback)
            raise
        finally:
            if message:
                self.lib.sd_bus_message_unref(message)

    def finish_call(self, slot, callback):
        self.lib.sd_bus_slot_unref(slot)
        self.callbacks.remove(callback)

    def match(self, rule, function):
        installed, slot = [], C.c_void_p()
        callback = self._callback(function)
        def ready(message):
            if (self.lib.sd_bus_message_is_method_error(message, None) != 0
                    or _text(self.lib.sd_bus_message_get_sender(message)) != DBUS):
                raise Rejected("manager-bus-match-not-installed")
            self.fields(message, "")
            installed.append(True)
        ready_callback = self._callback(ready)
        _ok(self.lib.sd_bus_add_match_async(self.bus, C.byref(slot), rule.encode(), callback, ready_callback, None))
        self.slots.append(slot)
        return installed


class ManagerJobSession:
    """Original authority and authenticated manager signals on ONE connection.

    The embedding broker supplies a protected independently pinned libsystemd
    handle and its internal authority barrier, never IPC parameters/callbacks.
    Opening/subscribing is non-mutating. stop() is only for a journaled fixed
    runtime stop and must be called after durable pending publication.
    """
    def __init__(self, *, library, library_sha256, units, deadline, clock, check):
        if (not isinstance(library, ProtectedFile) or library.uid != 0 or library.gid != 0
                or not fixed_roles(units)
                or any(not isinstance(unit, UnitBinding) for unit in units.values())
                or len({unit.unit for unit in units.values()}) != len(units)):
            raise Rejected("manager-bus-protected-fixed-boundaries-required")
        from .loading import pin
        from dataclasses import asdict
        pin(library_sha256)
        self.library, self.library_sha256, self.units = library, library_sha256, dict(units)
        self._units = canonical({role: asdict(unit) for role, unit in units.items()})
        self.deadline, self.clock, self.check = deadline, clock, check
        self._original_deadline = deadline
        self._thread, self._last_clock, self._connection = threading.get_ident(), None, None
        self.failed, self.owner, self.bus_id = False, None, None
        self._attempted, self._submitted, self._events, self._inflight = set(), {}, {}, None
        self._event_count, self._last_cookie = 0, 0
        self._cancel_targets, self._cancel_events, self._cancel_attempted = {}, {}, set()
        self._cancel_watched = False
        self._kill_attempted = set()
        self._fixed_jobs_watched, self._created = False, {}
        self._reference_attempted, self._fixed_unit_paths, self._referenced_units_watched = False, {}, False
        self._reload_change_seen = None
        try:
            self._current()
            if library.checksum() != library_sha256:
                raise Rejected("manager-bus-library-pin-changed")
            native = _Library("/proc/self/fd/%d" % library.fd)
            library.validate()
            if library.checksum() != library_sha256:
                raise Rejected("manager-bus-library-pin-changed")
            self._current()
            self._connection = _Connection(native, SYSTEM_ADDRESS)
            self.bus_id = self._bus_call("GetId", "", (), "s")[0]
            if INVOCATION.fullmatch(self.bus_id) is None:
                raise Rejected("manager-bus-generation-unconfirmed")
            self.owner = self._bus_call("GetNameOwner", "s", (MANAGER,), "s")[0]
            if UNIQUE.fullmatch(self.owner) is None:
                raise Rejected("manager-bus-owner-unconfirmed")
            self._credentials()
            rule = "type='signal',sender='%s',path='%s',interface='%s.Manager',member='JobRemoved'" % (
                self.owner, MANAGER_PATH, MANAGER)
            self._until(self._connection.match(rule, self._job_removed))
            rule = ("type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/DBus',"
                    "interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.systemd1'")
            self._until(self._connection.match(rule, self._owner_changed))
            self._call(self.owner, MANAGER+".Manager", "Subscribe", "", (), "")
            self.identity()
        except BaseException:
            self.failed = True
            self.close()
            raise Rejected("manager-bus-session-unconfirmed") from None

    def _current(self):
        from dataclasses import asdict
        now = self.clock()
        if (self.failed or self._thread != threading.get_ident()
                or type(now) not in (float, int) or not math.isfinite(now)
                or self.deadline != self._original_deadline
                or type(self.deadline) not in (float, int) or not math.isfinite(self.deadline)
                or now <= 0 or now >= self.deadline
                or self._last_clock is not None and now < self._last_clock
                or self._units != canonical({role: asdict(unit) for role, unit in self.units.items()})):
            self.failed = True
            raise Rejected("manager-bus-original-boundary-lost")
        self._last_clock = now
        self.library.validate()
        self.check()
        # The authority check itself can consume the last allowance.
        after = self.clock()
        if type(after) not in (float, int) or not math.isfinite(after) or after < now or after >= self.deadline:
            self.failed = True
            raise Rejected("manager-bus-deadline-lost")
        self._last_clock = after
        self.library.validate()
        if (self.deadline != self._original_deadline
                or self._units != canonical({role: asdict(unit) for role, unit in self.units.items()})):
            self.failed = True
            raise Rejected("manager-bus-trailing-configuration-changed")
        # ProtectedFile validation also invokes the supplied root/deadline guard.
        final = self.clock()
        if type(final) not in (float, int) or not math.isfinite(final) or final < after or final >= self.deadline:
            self.failed = True
            raise Rejected("manager-bus-trailing-deadline-lost")
        self._last_clock = final
        if self._connection is not None:
            self._connection.current()

    def _until(self, result):
        while not result:
            self._current()
            if self._connection.process() == 0:
                remaining = self.deadline - self.clock()
                if remaining <= 0:
                    raise Rejected("manager-bus-deadline-lost")
                self._connection.wait(max(1, min(50000, int(remaining * 1000000))))
        self._current()

    def _call(self, destination, interface, method, signature, args, response, *, path=MANAGER_PATH):
        self._current()
        result, slot, callback = self._connection.call(destination, interface, method, signature, args, response,
            usec=max(1, int((self.deadline-self.clock()) * 1000000)), path=path)
        try:
            self._until(result)
            return result[0]
        finally:
            self._connection.finish_call(slot, callback)

    def _bus_call(self, method, signature, args, response):
        return self._call(DBUS, DBUS, method, signature, args, response, path=DBUS_PATH)

    def _credentials(self):
        uid = self._bus_call("GetConnectionUnixUser", "s", (self.owner,), "u")[0]
        pid = self._bus_call("GetConnectionUnixProcessID", "s", (self.owner,), "u")[0]
        if uid != 0 or pid != 1:
            raise Rejected("manager-bus-root-system-manager-required")

    def _owner_changed(self, message):
        connection = self._connection
        if (_text(connection.lib.sd_bus_message_get_sender(message)) != DBUS
                or connection.fields(message, "sss")[0] != MANAGER):
            raise Rejected("manager-bus-owner-signal-unconfirmed")
        # Even a disappearance followed by reacquisition revokes this session.
        raise Rejected("manager-bus-owner-changed")

    def _job_removed(self, message):
        connection = self._connection
        if (_text(connection.lib.sd_bus_message_get_sender(message)) != self.owner
                or _text(connection.lib.sd_bus_message_get_path(message)) != MANAGER_PATH
                or _text(connection.lib.sd_bus_message_get_interface(message)) != MANAGER+".Manager"
                or _text(connection.lib.sd_bus_message_get_member(message)) != "JobRemoved"):
            raise Rejected("manager-bus-job-sender-unconfirmed")
        number, path, unit, result = connection.fields(message, "uoss")
        self._event_count += 1
        cookie = C.c_uint64()
        _ok(connection.lib.sd_bus_message_get_cookie(message, C.byref(cookie)))
        if (self._event_count > MAX_EVENTS or cookie.value <= self._last_cookie
                or type(number) is not int or number != job_path(path) or result not in RESULTS):
            raise Rejected("manager-bus-job-event-unconfirmed")
        self._last_cookie = cookie.value
        roles = [role for role, binding in self.units.items() if unit == binding.unit]
        if not roles:
            return
        role = roles[0]
        target = self._cancel_targets.get(role)
        if target is not None and number == target[0]:
            if (path != target[4] or role not in self._cancel_attempted or role in self._cancel_events):
                raise Rejected("manager-bus-cancellation-identity-conflict")
            self._cancel_events[role] = {"job_id": number, "job_path": path, "unit": unit, "result": result,
                                         "sender_cookie": cookie.value}
            return
        if number in self._events or role not in self._attempted:
            raise Rejected("manager-bus-untracked-or-duplicate-completion")
        expected = self._submitted.get(role)
        if (expected is None and self._inflight != role
                or expected is not None and expected != (number, path)):
            raise Rejected("manager-bus-job-identity-conflict")
        self._events[number] = {"job_id": number, "job_path": path, "unit": unit, "result": result,
                                "sender_cookie": cookie.value}

    def pump(self):
        try:
            for _ in range(MAX_EVENTS + 1):
                self._current()
                if self._connection.process() == 0:
                    self._current()
                    return
            raise Rejected("manager-bus-dispatch-overflow")
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-witness-unconfirmed") from None

    def identity(self):
        try:
            self.pump()
            if self._bus_call("GetNameOwner", "s", (MANAGER,), "s")[0] != self.owner:
                raise Rejected("manager-bus-owner-changed")
            self._credentials()
            self.pump()
            return self.bus_id, self.owner
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-identity-unconfirmed") from None

    def jobs(self):
        try:
            self.identity()
            rows = self._call(self.owner, MANAGER+".Manager", "ListJobs", "", (), "a(usssoo)")
            result = jobs_reply(canonical({"type": "a(usssoo)", "data": rows}))
            self.identity()
            return result
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-inventory-unconfirmed") from None

    def _retain_fixed_units(self):
        """Retain loaded objects on this connection, never activation authority.

        RefUnit prevents ordinary unit garbage collection from resetting sampled
        execution state. The manager owns these sender references until connection
        closure. No retry/UnrefUnit is attempted after an ambiguous reply.
        """
        try:
            self.identity()
            if self._reference_attempted or self._fixed_jobs_watched or self._attempted or self._cancel_watched:
                raise Rejected("manager-bus-fixed-unit-reference-exhausted")
            self._reference_attempted = True
            self._reference_owner = self._connection.unique_name()
            for role, unit in self.units.items():
                self._call(self.owner, MANAGER + ".Manager", "RefUnit", "s", (unit.unit,), "")
                self.identity()
                path = self._call(self.owner, MANAGER + ".Manager", "GetUnit", "s", (unit.unit,), "o")[0]
                if (type(path) is not str
                        or re.fullmatch(MANAGER_PATH + r"/unit/[A-Za-z0-9_]{1,1024}", path) is None
                        or path in self._fixed_unit_paths.values()):
                    raise Rejected("manager-bus-fixed-unit-reference-path-unconfirmed")
                self._fixed_unit_paths[role] = path
                self._fixed_unit_reference(role, path)
            self.identity()
            return dict(self._fixed_unit_paths)
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-fixed-unit-reference-unconfirmed") from None

    def _fixed_unit_reference(self, role, path):
        try:
            self.identity()
            if (not self._reference_attempted or role not in self.units
                    or self._fixed_unit_paths.get(role) != path
                    or self._connection.unique_name() != self._reference_owner):
                raise Rejected("manager-bus-original-unit-reference-required")
            refs = self._call(self.owner, "org.freedesktop.DBus.Properties", "Get", "ss",
                (MANAGER + ".Unit", "Refs"), "v:as", path=path)[0]
            if (type(refs) is not list or len(refs) > MAX_EVENTS
                    or any(type(name) is not str or UNIQUE.fullmatch(name) is None for name in refs)
                    or refs.count(self._reference_owner) != 1):
                raise Rejected("manager-bus-own-unit-reference-unconfirmed")
            self.identity()
            if self._connection.unique_name() != self._reference_owner:
                raise Rejected("manager-bus-unit-reference-connection-changed")
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-unit-reference-lost") from None

    def _watch_referenced_units(self):
        """After deliberate reload, watch the retained stop-phase objects.

        Manager Reload itself reconstructs units. Never label pre/post reference
        readback as uninterrupted object lifetime across that transition.
        """
        try:
            self.identity()
            if (not self._reference_attempted or self._referenced_units_watched or self._attempted
                    or set(self._fixed_unit_paths) != set(self.units)):
                raise Rejected("manager-bus-reference-watch-original-units-required")
            self._referenced_units_watched = True
            rule = "type='signal',sender='%s',path='%s',interface='%s.Manager',member='UnitRemoved'" % (
                self.owner, MANAGER_PATH, MANAGER)
            self._until(self._connection.match(rule, self._unit_removed))
            rule = "type='signal',sender='%s',path='%s',interface='%s.Manager',member='Reloading'" % (
                self.owner, MANAGER_PATH, MANAGER)
            self._until(self._connection.match(rule, self._manager_reloading))
            for role, path in self._fixed_unit_paths.items():
                self._fixed_unit_reference(role, path)
            self.identity()
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-reference-watch-unconfirmed") from None

    def _manager_reloading(self, message):
        # Either edge is unexpected after the deliberate Reload return. A false
        # edge alone cannot establish that no reconstruction happened in a gap.
        connection = self._connection
        if (not self._referenced_units_watched
                or _text(connection.lib.sd_bus_message_get_sender(message)) != self.owner
                or _text(connection.lib.sd_bus_message_get_path(message)) != MANAGER_PATH
                or _text(connection.lib.sd_bus_message_get_interface(message)) != MANAGER + ".Manager"
                or _text(connection.lib.sd_bus_message_get_member(message)) != "Reloading"):
            raise Rejected("manager-bus-reload-sender-unconfirmed")
        active, = connection.fields(message, "b")
        cookie = C.c_uint64()
        _ok(connection.lib.sd_bus_message_get_cookie(message, C.byref(cookie)))
        self._event_count += 1
        if (type(active) is not bool or self._event_count > MAX_EVENTS or cookie.value <= self._last_cookie):
            raise Rejected("manager-bus-reload-event-unconfirmed")
        self._last_cookie = cookie.value
        self._reload_change_seen = active
        raise Rejected("manager-bus-unexpected-reload-transition")

    def _unit_removed(self, message):
        connection = self._connection
        if (not self._referenced_units_watched
                or _text(connection.lib.sd_bus_message_get_sender(message)) != self.owner
                or _text(connection.lib.sd_bus_message_get_path(message)) != MANAGER_PATH
                or _text(connection.lib.sd_bus_message_get_interface(message)) != MANAGER + ".Manager"
                or _text(connection.lib.sd_bus_message_get_member(message)) != "UnitRemoved"):
            raise Rejected("manager-bus-unit-removal-sender-unconfirmed")
        unit, path = connection.fields(message, "so")
        cookie = C.c_uint64()
        _ok(connection.lib.sd_bus_message_get_cookie(message, C.byref(cookie)))
        self._event_count += 1
        if (self._event_count > MAX_EVENTS or cookie.value <= self._last_cookie
                or type(unit) is not str or type(path) is not str
                or re.fullmatch(MANAGER_PATH + r"/unit/[A-Za-z0-9_]{1,1024}", path) is None):
            raise Rejected("manager-bus-unit-removal-unconfirmed")
        self._last_cookie = cookie.value
        if (unit in {binding.unit for binding in self.units.values()}
                or path in self._fixed_unit_paths.values()):
            raise Rejected("manager-bus-referenced-unit-removed")

    def _watch_fixed_jobs(self):
        """Observe fixed-unit admissions before the masked shutdown sequence.

        This revokes on unexpected jobs; it cannot prevent the manager executing
        them. Only this session's one-shot StopUnit admissions are supported.
        Existing waiting starts are separately inventoried/canceled, not adopted
        from JobNew signals. No watcher survives connection or process loss.
        """
        try:
            self.identity()
            if self._fixed_jobs_watched or self._attempted or self._cancel_watched:
                raise Rejected("manager-bus-fixed-job-watch-exhausted")
            self._fixed_jobs_watched = True
            rule = "type='signal',sender='%s',path='%s',interface='%s.Manager',member='JobNew'" % (
                self.owner, MANAGER_PATH, MANAGER)
            self._until(self._connection.match(rule, self._job_new))
            self.identity()
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-fixed-job-watch-unconfirmed") from None

    def _job_new(self, message):
        connection = self._connection
        if (not self._fixed_jobs_watched
                or _text(connection.lib.sd_bus_message_get_sender(message)) != self.owner
                or _text(connection.lib.sd_bus_message_get_path(message)) != MANAGER_PATH
                or _text(connection.lib.sd_bus_message_get_interface(message)) != MANAGER + ".Manager"
                or _text(connection.lib.sd_bus_message_get_member(message)) != "JobNew"):
            raise Rejected("manager-bus-job-admission-sender-unconfirmed")
        number, path, unit = connection.fields(message, "uos")
        cookie = C.c_uint64()
        _ok(connection.lib.sd_bus_message_get_cookie(message, C.byref(cookie)))
        self._event_count += 1
        if (self._event_count > MAX_EVENTS or cookie.value <= self._last_cookie
                or type(number) is not int or number != job_path(path)):
            raise Rejected("manager-bus-job-admission-unconfirmed")
        self._last_cookie = cookie.value
        roles = [role for role, binding in self.units.items() if unit == binding.unit]
        if not roles:
            return
        role = roles[0]
        expected = self._submitted.get(role)
        if (role in self._created or role not in self._attempted
                or any(number == target[0] for target in self._cancel_targets.values())
                or any(number == target[0] for target in self._created.values())
                or expected is None and self._inflight != role
                or expected is not None and expected != (number, path)):
            raise Rejected("manager-bus-unexpected-fixed-job-admission")
        self._created[role] = (number, path)

    def _fixed_jobs_absent(self):
        """Final bounded observation, not all-manager retirement or a start grant."""
        try:
            self.identity()
            if (not self._fixed_jobs_watched or set(self._submitted) != set(self.units)
                    or self._created != self._submitted):
                raise Rejected("manager-bus-fixed-job-admissions-required")
            rows = self.jobs()
            if any(row[1] in {unit.unit for unit in self.units.values()} for row in rows.values()):
                raise Rejected("manager-bus-fixed-job-still-present")
            if (any(self._events.get(number, {}).get("result") != "done"
                    for number, _ in self._submitted.values())
                    or any(self._cancel_events.get(role, {}).get("result") != "canceled"
                           for role in self._cancel_targets)):
                raise Rejected("manager-bus-fixed-job-completions-required")
            self.identity()
            return {"fixed_stop_admission_count": len(self._created), "fixed_jobs_absent_observed": True}
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-fixed-job-absence-unconfirmed") from None

    def _watch_waiting_starts(self):
        """Internal cancellation phase only; never adopt caller-supplied job IDs."""
        try:
            if self._cancel_watched or self._attempted:
                raise Rejected("manager-bus-cancellation-watch-exhausted")
            self._cancel_watched = True
            rows = self.jobs()
            for role, unit in self.units.items():
                selected = [row for row in rows.values() if row[1] == unit.unit]
                if selected:
                    row = selected[0]
                    if row[2:4] != ("start", "waiting"):
                        raise Rejected("manager-bus-only-waiting-start-supported")
                    self._cancel_targets[role] = row
            self.identity()
            return dict(self._cancel_targets)
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-waiting-start-watch-unconfirmed") from None

    def _cancel_waiting_start(self, role, *, check):
        """Call only after the embedding phase durably publishes exact pending."""
        try:
            target = self._cancel_targets.get(role)
            if target is None or role in self._cancel_attempted:
                raise Rejected("manager-bus-fixed-cancellation-exhausted")
            rows = self.jobs()
            if rows.get(target[0]) != target:
                raise Rejected("manager-bus-original-waiting-start-lost")
            check()
            self._current()
            self._cancel_attempted.add(role)
            self._call(self.owner, MANAGER + ".Job", "Cancel", "", (), "", path=target[4])
            self.identity()
            check()
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-cancellation-unconfirmed") from None

    def _cancellation(self, role):
        try:
            self.identity()
            if role not in self._cancel_attempted:
                raise Rejected("manager-bus-original-cancellation-required")
            value = self._cancel_events.get(role)
            return None if value is None else decode(canonical(value))
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-cancellation-completion-unconfirmed") from None

    def stop(self, role):
        try:
            self.identity()
            if role not in self.units or role in self._attempted:
                raise Rejected("manager-bus-fixed-stop-exhausted")
            self._attempted.add(role)
            self._inflight = role
            path = self._call(self.owner, MANAGER+".Manager", "StopUnit", "ss", (self.units[role].unit, "fail"), "o")[0]
            number = job_path(path)
            if (any(number == item[0] for item in self._submitted.values())
                    or any(number == item[0] for item in self._cancel_targets.values())):
                raise Rejected("manager-bus-job-identity-reused")
            self._submitted[role] = (number, path)
            if self._fixed_jobs_watched:
                while role not in self._created:
                    self.pump()
                    self._current()
                    if role not in self._created:
                        remaining = self.deadline - self.clock()
                        if remaining <= 0:
                            raise Rejected("manager-bus-job-admission-deadline")
                        self._connection.wait(max(1, min(50000, int(remaining * 1000000))))
                if self._created[role] != (number, path):
                    raise Rejected("manager-bus-stop-admission-identity-conflict")
            # JobRemoved can precede the StopUnit reply; do not discard it or
            # substitute a later job with the same unit/ID.
            events = [event for event in self._events.values() if event["unit"] == self.units[role].unit]
            if len(events) > 1 or events and (events[0]["job_id"], events[0]["job_path"]) != (number, path):
                raise Rejected("manager-bus-early-job-identity-conflict")
            self._inflight = None
            self.identity()
            return path
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-stop-unconfirmed") from None

    def _kill_stopping_unit(self, role, *, check):
        """Internal fixed whole-unit KILL after a separately journaled stop.

        The embedding sequence retains its original pending operation and masks.
        A KillUnit reply is not a stop completion or cgroup/activation fence.
        """
        try:
            self.identity()
            if role not in self._submitted or role in self._kill_attempted:
                raise Rejected("manager-bus-fixed-kill-exhausted")
            check()
            self._current()
            self._kill_attempted.add(role)
            self._call(self.owner, MANAGER + ".Manager", "KillUnit", "ssi",
                       (self.units[role].unit, "all", 9), "")
            self.identity()
            check()
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-kill-unconfirmed") from None

    def completions(self):
        try:
            self.identity()
            value = {role: self._events[number] for role, (number, _) in self._submitted.items()
                     if number in self._events}
            return decode(canonical(value))
        except BaseException:
            self.failed = True
            raise Rejected("manager-bus-completion-unconfirmed") from None

    def close(self):
        self.failed = True
        if self._connection is not None:
            self._connection.close()
