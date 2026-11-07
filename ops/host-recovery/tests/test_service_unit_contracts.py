"""Reached renderer/runtime contracts with scripted manager data, not systemd."""
from dataclasses import replace
from pathlib import Path
import unittest

from host_recovery import durable, manager, service_units
import test_bootstrap

ROOT = Path(__file__).resolve().parent.parent


class RenderedContractTests(unittest.TestCase):
    def unit(self, **changes):
        value = service_units.ServiceUnit("supervisor", "cpa-supervisor.service", "/usr/bin/python3",
            str(ROOT), "/etc/cpa-recovery/supervisor.json", 1000, 1000, (), ())
        return replace(value, **changes)

    def test_rendered_supervisor_reaches_authenticated_bootstrap(self):
        fixture = test_bootstrap.BootstrapTests()
        fixture.setUp()
        unit = self.unit(uid=fixture.binding.uid, gid=fixture.binding.gid)
        raw = unit.render()
        rows = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line)
        for key in manager.STATIC - {"ExecStart"}:
            if key in rows:
                fixture.row[key] = rows[key]
        command = rows["ExecStart"]
        fixture.row["ExecStart"] = ("{ path=" + unit.python + " ; argv[]=" + command
            + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")
        fixture.engine.binding = replace(fixture.binding, fragment_sha256=durable.digest(raw),
            properties_sha256=durable.digest(durable.canonical(manager.static_properties(fixture.row))))
        fixture.engine.read_fragment_hash = lambda _: durable.digest(raw)
        result = fixture.start()
        self.assertEqual(result["owner"]["unit"], unit.unit)
        self.assertEqual(len(fixture.calls), 2)

    def test_supervisor_names_must_fit_the_durable_owner_protocol(self):
        for name in ("supervisor@one.service", "a" * 121 + ".service"):
            with self.subTest(name=name), self.assertRaisesRegex(durable.Rejected, "owner-name"):
                self.unit(unit=name)

    def test_rendered_fragment_cannot_exceed_the_runtime_reader_limit(self):
        paths = tuple("/input/" + str(n) + "/" + "a" * 2200 for n in range(32))
        with self.assertRaisesRegex(durable.Rejected, "fragment-size"):
            self.unit(read_only=paths).render()
