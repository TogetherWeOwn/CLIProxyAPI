"""One non-reconnecting sd-bus connection for fixed runtime stop-job witnesses.

This embedding transport is not an installed broker, activation interlock or cold
barrier. The caller retains the original authority/journal and protected library
handle. Only the two fixed StopUnit calls exist; no arbitrary dispatch or numeric
job cancellation is exposed. Completion delivery does not prove runtime drain.
"""
import ctypes as C
import math
import threading

from .durable import Rejected, canonical, decode
from .manager import INVOCATION, UnitBinding
from .manager_jobs import JOB_PREFIX, MANAGER, MANAGER_PATH, UNIQUE, job_path, jobs_reply
from .protected_file import ProtectedFile
from .topology import RUNTIME_ROLES

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
        value = C.c_uint32() if kind == "u" else C.c_char_p()
        if self.lib.sd_bus_message_read_basic(message, kind.encode(), C.byref(value)) <= 0:
            raise Rejected("manager-bus-message-field-required")
        return value.value if kind == "u" else _text(value.value)

    def fields(self, message, signature):
        if _text(self.lib.sd_bus_message_get_signature(message, 1)) != signature:
            raise Rejected("manager-bus-message-signature")
        if signature == "a(usssoo)":
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
            if any(kind not in "sou" for kind in signature):
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
            for kind, value in zip(signature, args):
                if kind != "s" or type(value) is not str:
                    raise Rejected("manager-bus-fixed-argument-required")
                _ok(self.lib.sd_bus_message_append_basic(message, b"s", C.cast(C.c_char_p(value.encode()), C.c_void_p)))
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
                or type(units) is not dict or set(units) != set(RUNTIME_ROLES)
                or any(not isinstance(unit, UnitBinding) for unit in units.values())
                or len({unit.unit for unit in units.values()}) != len(RUNTIME_ROLES)):
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

    def stop(self, role):
        try:
            self.identity()
            if role not in self.units or role in self._attempted:
                raise Rejected("manager-bus-fixed-stop-exhausted")
            self._attempted.add(role)
            self._inflight = role
            path = self._call(self.owner, MANAGER+".Manager", "StopUnit", "ss", (self.units[role].unit, "fail"), "o")[0]
            number = job_path(path)
            if any(number == item[0] for item in self._submitted.values()):
                raise Rejected("manager-bus-job-identity-reused")
            self._submitted[role] = (number, path)
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
