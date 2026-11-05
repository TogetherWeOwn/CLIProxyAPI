"""Synthetic systemd D-Bus peer ONLY on a caller-created disposable session bus.

No system bus, host manager, cgroup, daemon or service is contacted. This is a
native ABI/protocol test peer, not a systemd implementation or qualification.
"""
import ctypes as C
import os
from pathlib import Path
import select
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_recovery import manager_bus as bus


def main():
    address = os.environ['DBUS_SESSION_BUS_ADDRESS']
    if not address.startswith('unix:') or address == bus.SYSTEM_ADDRESS.decode():
        raise RuntimeError('private-session-bus-required')
    native = bus._Library(sys.argv[1])
    pointer, integer, text = C.c_void_p, C.c_int, C.c_char_p
    native._declare('sd_bus_request_name',integer,pointer,text,C.c_uint64)
    native._declare('sd_bus_release_name',integer,pointer,text)
    native._declare('sd_bus_add_object',integer,pointer,C.POINTER(pointer),text,bus.CALLBACK,pointer)
    native._declare('sd_bus_reply_method_return',integer,pointer,text)
    native._declare('sd_bus_emit_signal',integer,pointer,text,text,text,text)
    native._declare('sd_bus_flush',integer,pointer)
    connection = bus._Connection(native,address.encode())
    mode, subscribed, stopped = sys.argv[2], False, []
    object_slot = C.c_void_p()
    def signal(unit, number=41):
        result = b'failed' if mode=='failed' else b'canceled' if mode=='canceled' else b'done'
        if mode=='malformed':
            bus._ok(native.sd_bus_emit_signal(connection.bus,bus.MANAGER_PATH.encode(),
                (bus.MANAGER+'.Manager').encode(),b'JobRemoved',b's',b'wrong-shape'))
        else:
            bus._ok(native.sd_bus_emit_signal(connection.bus,bus.MANAGER_PATH.encode(),
                (bus.MANAGER+'.Manager').encode(),b'JobRemoved',b'uoss',C.c_uint32(number),
                (bus.JOB_PREFIX+str(number)).encode(),unit.encode(),result))
        bus._ok(native.sd_bus_flush(connection.bus))
    def method(message, userdata, error):
        nonlocal subscribed
        try:
            interface = bus._text(native.sd_bus_message_get_interface(message))
            member = bus._text(native.sd_bus_message_get_member(message))
            if interface != bus.MANAGER+'.Manager':
                return 0
            if member=='Subscribe':
                subscribed = True
                bus._ok(native.sd_bus_reply_method_return(message,b''))
            elif member=='ListJobs':
                rows = stopped if mode=='pending' else []
                arguments = [C.c_uint(len(rows))]
                for unit in rows:
                    number = 41 if unit=='fixture-dockerd.service' else 42
                    arguments.extend((C.c_uint32(number),unit.encode(),b'stop',b'running',
                        (bus.JOB_PREFIX+str(number)).encode(),(bus.MANAGER_PATH+'/unit/fixture_service').encode()))
                bus._ok(native.sd_bus_reply_method_return(message,b'a(usssoo)',*arguments))
            elif member=='StopUnit':
                unit, policy = connection.fields(message,'ss')
                if not subscribed or policy!='fail' or unit not in ('fixture-dockerd.service','fixture-containerd.service'):
                    raise RuntimeError('unexpected-fixed-stop')
                stopped.append(unit)
                number = 41 if unit=='fixture-dockerd.service' else 42
                if mode not in ('absent','pending'): signal(unit,number)
                if mode=='duplicate': signal(unit,number)
                returned = number+100 if mode=='wrong-id' else number
                bus._ok(native.sd_bus_reply_method_return(message,b'o',(bus.JOB_PREFIX+str(returned)).encode()))
            else:
                return 0
            return 1
        except BaseException:
            connection.error = RuntimeError('synthetic-peer-callback-failed')
            return 1
    callback = bus.CALLBACK(method)
    try:
        bus._ok(native.sd_bus_add_object(connection.bus,C.byref(object_slot),bus.MANAGER_PATH.encode(),callback,None))
        bus._ok(native.sd_bus_request_name(connection.bus,bus.MANAGER.encode(),0))
        print('ready',flush=True)
        while True:
            while connection.process(): pass
            readable,_,_ = select.select([sys.stdin],[],[],0)
            if readable:
                command = sys.stdin.readline().strip()
                if command=='release':
                    bus._ok(native.sd_bus_release_name(connection.bus,bus.MANAGER.encode()))
                    print('released',flush=True)
                elif command=='counts': print(str(len(stopped)),flush=True)
                elif command in ('quit',''): break
                else: raise RuntimeError('unknown-peer-command')
            connection.wait(10000)
    finally:
        if object_slot: native.sd_bus_slot_unref(object_slot)
        connection.close()


if __name__=='__main__': main()
