"""First adoption under the production lock and a separately approved site binding."""

import http.client
import subprocess

from production import DRAIN_SECONDS, ReleaseError, SAFE_ENV, read_json, save_json

SITE_OPERATIONS = {
    "legacy": 40,
    "isolate": 125,
    "isolated": 30,
    "undo-isolate": 35,
    "restore": 100,
    "resume": 30,
}
TRANSACTION_ERRORS = (ReleaseError, OSError, ValueError, TypeError,
                      http.client.HTTPException, subprocess.SubprocessError)


class Site:
    """Fixed root-owned operations for the old listeners, ingress and writers."""

    def __init__(self, executable):
        self.executable = executable

    def __call__(self, verb, digest, binding):
        if verb not in SITE_OPERATIONS:
            raise ReleaseError("invalid first adoption operation")
        result = subprocess.run(
            [str(self.executable), verb, digest, binding],
            check=False, env=SAFE_ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=SITE_OPERATIONS[verb],
        )
        if result.returncode:
            raise ReleaseError(f"first adoption binding refused {verb}")


def transact(gate, adapter, site, journal, release_journal, action, digest, binding,
             drain_seconds=DRAIN_SECONDS):
    """Run once, or resume the separately journaled undo after interruption."""
    prior = read_json(journal) if journal.exists() else None
    record = {"digest": digest, "binding": binding, "phase": "changing"}
    if release_journal.exists():
        raise ReleaseError("first adoption requires an unused release pair")
    if action == "adopt":
        if prior is not None:
            raise ReleaseError("first adoption was already attempted")
        adapter("prepared", digest, "baseline")
        site("legacy", digest, binding)
        save_json(journal, record)
        try:
            # The old listener bypasses the gate. The site must block new
            # work and prove drain before it stops the old container.
            site("isolate", digest, binding)
            closed = gate.read()
            if not closed["closed"] or closed["active"]:
                raise ReleaseError("first adoption requires closed, empty admission")
            site("isolated", digest, binding)
            gate.require(closed, empty=True)
            adapter("switch", digest, "baseline", fence=closed)
            adapter("ready", digest, "baseline")
            site("isolated", digest, binding)
            gate.change(gate.require(closed, empty=True), False)
            save_json(journal, dict(record, phase="adopted"))
        except TRANSACTION_ERRORS:
            undo(gate, site, journal, record, drain_seconds)
            raise ReleaseError("first adoption failed and legacy ingress was restored") from None
        return

    if (action != "undo-adoption"
            or prior not in (record, *(dict(record, phase=p) for p in ("adopted", "undoing", "undone")))):
        raise ReleaseError("no matching first adoption to undo")
    if prior["phase"] != "undone":
        undo(gate, site, journal, record, drain_seconds)


def undo(gate, site, journal, record, drain_seconds):
    digest, binding = record["digest"], record["binding"]
    save_json(journal, dict(record, phase="undoing"))
    # A host-side fence covers both layouts, including before the gate
    # exists and after it has released the original published sockets.
    site("undo-isolate", digest, binding)
    try:
        state = gate.read()
    except (FileNotFoundError, ConnectionRefusedError):
        state = None
    if state is not None:
        closed = state if state["closed"] else gate.change(state, True)
        gate.wait(closed, drain_seconds)
        gate.require(closed, empty=True)
    site("restore", digest, binding)
    site("resume", digest, binding)
    save_json(journal, dict(record, phase="undone"))
