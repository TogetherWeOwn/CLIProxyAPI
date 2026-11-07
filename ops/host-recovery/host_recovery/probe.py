"""Request-origin, two-turn Messages probe; never replay/drain acceptance.

Only an explicit synthetic loopback HTTP transport is supplied here. Production
credentials, endpoint authorization, manager ownership and artifact approval are
separate prerequisites. Raw bodies stay in an explicitly private spool, not the
public receipt. Thinking/signature blocks are relayed unchanged, not synthesized.
"""
import base64
import copy
from dataclasses import dataclass, asdict
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import uuid

from .commands import Deadline
from .durable import Rejected, atomic_write, canonical, decode, digest, read_file
from .journal import identity
from .loading import REVISION, pin
from .replay import model

MAX_BODY = 1024 * 1024
MAX_WIRE = 2 * MAX_BODY
TOOL = "cpa_recovery_echo"
TOOL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z", re.ASCII)


@dataclass(frozen=True)
class ProbeSources:
    package_revision: str
    probe_revision: str
    candidate_revision: str
    producer_revision: str
    candidate_image_sha256: str
    plugin_archive_sha256: str
    plugin_library_sha256: str

    def __post_init__(self):
        for name, value in asdict(self).items():
            if name.endswith("revision"):
                if type(value) is not str or REVISION.fullmatch(value) is None:
                    raise Rejected("probe-source-revision-required")
            else:
                pin(value)


class ProbeSpool:
    """Borrow an empty private directory descriptor under the caller's same lock.

    check must retain/revalidate that lock, approved directory ancestry and writer
    exclusion. This class supplies no such authority. Ambiguous writes poison the
    instance and leave evidence; a new instance cannot overwrite an existing run.
    """
    def __init__(self, fd, *, check, clock=time.monotonic, fault=None):
        if type(fd) is not int or fd < 0 or not callable(check):
            raise Rejected("probe-private-spool-required")
        self.fd, self.check, self.clock, self.fault = fd, check, clock, fault
        self.failed, self.rows = False, {}
        self._metadata()
        self.inode = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        if os.listdir(fd):
            raise Rejected("probe-empty-spool-required")

    def _metadata(self):
        st = os.fstat(self.fd)
        if (not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid) != (os.geteuid(), os.getegid())
                or stat.S_IMODE(st.st_mode) != 0o700 or os.listxattr(self.fd)):
            raise Rejected("probe-private-spool-required")

    def verify(self, *, deadline):
        try:
            if self.failed:
                raise Rejected("probe-spool-unavailable")
            timer = Deadline(self.clock, deadline)
            timer.remaining()
            if self.check(deadline=deadline) is not True:
                raise Rejected("probe-spool-boundary-unconfirmed")
            self._metadata()
            if ((os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino) != self.inode
                    or set(os.listdir(self.fd)) != set(self.rows)):
                raise Rejected("probe-spool-changed")
            for name, expected in self.rows.items():
                raw, st = read_file(self.fd, name, limit=MAX_BODY)
                if ((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (os.geteuid(), os.getegid(), 0o600)
                        or digest(raw) != expected):
                    raise Rejected("probe-spool-changed")
            timer.remaining()
        except BaseException:
            self.failed = True
            raise

    def save(self, name, raw, *, deadline):
        try:
            self.verify(deadline=deadline)
            if (name not in {"turn1-request.json", "turn1-response.json", "turn2-request.json", "turn2-response.json",
                             "turn1-carrier.json", "turn2-carrier.json"}
                    or name in self.rows or type(raw) is not bytes or not 0 < len(raw) <= MAX_BODY):
                raise Rejected("probe-artifact-shape")
            checksum = atomic_write(self.fd, name, raw, fault=self.fault)
            self.rows[name] = checksum
            self.verify(deadline=deadline)
            return checksum
        except BaseException:
            self.failed = True
            raise


class LoopbackMessages:
    """One helper per POST, killed on the caller's inclusive local deadline.

    No socket timeout, proxy, redirect, retry, environment credential or config
    scrape. The helper is trusted package code run with Python -I and cwd '/'.
    Killing it does NOT cancel inference or establish service quiescence/drain.
    Interpreter/package installation approval and complete cgroup cleanup remain
    the manager's responsibility. Only literal loopback, not DNS names, is allowed.
    """
    def __init__(self, *, port, ipv6=False, token=None, clock=time.monotonic):
        if (type(port) is not int or not 1 <= port <= 65535 or type(ipv6) is not bool
                or token is not None and (type(token) is not str or not 1 <= len(token) <= 8192
                                          or any(not 33 <= ord(c) <= 126 for c in token))):
            raise Rejected("probe-explicit-loopback-transport-required")
        self.port, self.ipv6, self.token, self.clock = port, ipv6, token, clock
        self.pending = []

    def exchange(self, headers, body, *, deadline):
        if type(headers) is not dict or set(headers) != {
                "X-CPA-Recovery-Attempt-ID", "X-CPA-Recovery-Probe-ID", "X-CPA-Recovery-Request-ID",
                "X-CPA-Recovery-Parent-Request-ID", "X-CPA-Recovery-Turn"}:
            raise Rejected("probe-correlation-headers-required")
        if type(body) is not bytes or not 0 < len(body) <= MAX_BODY:
            raise Rejected("probe-request-limit")
        raw = canonical({"port": self.port, "ipv6": self.ipv6, "token": self.token,
                         "headers": headers, "body_b64": base64.b64encode(body).decode("ascii")})
        if len(raw) > MAX_WIRE:
            raise Rejected("probe-request-limit")
        remaining = Deadline(self.clock, deadline).remaining
        remaining()
        self.pending = [proc for proc in self.pending if proc.poll() is None]
        proc = None
        try:
            helper = Path(__file__).resolve().parent.parent / "probe_http.py"
            proc = subprocess.Popen((sys.executable, "-I", str(helper)), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, cwd="/",
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            os.set_blocking(proc.stdin.fileno(), False)
            os.set_blocking(proc.stdout.fileno(), False)
            sent, output = 0, bytearray()
            with selectors.DefaultSelector() as wait:
                wait.register(proc.stdin, selectors.EVENT_WRITE)
                wait.register(proc.stdout, selectors.EVENT_READ)
                while wait.get_map():
                    for key, _ in wait.select(remaining()):
                        if key.fileobj is proc.stdin:
                            sent += os.write(key.fd, memoryview(raw)[sent:sent + 65536])
                            if sent == len(raw):
                                wait.unregister(proc.stdin)
                                proc.stdin.close()
                        else:
                            block = os.read(key.fd, min(65536, MAX_WIRE + 1 - len(output)))
                            if not block:
                                wait.unregister(proc.stdout)
                            else:
                                output.extend(block)
                                if len(output) > MAX_WIRE:
                                    raise Rejected("probe-response-limit")
                code = proc.wait(timeout=remaining())
            remaining()
            if sent != len(raw) or code != 0:
                raise Rejected("probe-http-unconfirmed")
            value = decode(bytes(output))
            if (set(value) != {"status", "body_b64"} or type(value["status"]) is not int
                    or not 100 <= value["status"] <= 599 or type(value["body_b64"]) is not str):
                raise Rejected("probe-http-unconfirmed")
            response = base64.b64decode(value["body_b64"], validate=True)
            if not 0 < len(response) <= MAX_BODY:
                raise Rejected("probe-response-limit")
            remaining()
            return value["status"], response
        except Exception:
            raise Rejected("probe-http-unconfirmed") from None
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    self.pending.append(proc)
                proc.stdin.close()
                proc.stdout.close()


def response(raw, *, first, nonce, confirmation=None):
    """Strict nonstream Messages subset, preserving every admitted assistant block."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BODY:
        raise Rejected("probe-response-limit")
    value = decode(raw)
    fields = {"id", "type", "role", "model", "content", "stop_reason", "stop_sequence", "usage"}
    if (set(value) != fields or not identity(value["id"]) or value["type"] != "message"
            or value["role"] != "assistant" or not model(value["model"])
            or value["stop_sequence"] is not None or type(value["usage"]) is not dict
            or type(value["content"]) is not list or not 1 <= len(value["content"]) <= 32
            or value["stop_reason"] != ("tool_use" if first else "end_turn")):
        raise Rejected("probe-response-shape")
    tools, texts = [], []
    for block in value["content"]:
        if type(block) is not dict:
            raise Rejected("probe-content-shape")
        kind = block.get("type")
        if kind == "text" and set(block) == {"type", "text"} and type(block["text"]) is str:
            texts.append(block["text"])
        elif (kind == "thinking" and set(block) == {"type", "thinking", "signature"}
              and type(block["thinking"]) is str and type(block["signature"]) is str and block["signature"]):
            pass
        elif kind == "redacted_thinking" and set(block) == {"type", "data"} and type(block["data"]) is str and block["data"]:
            pass
        elif (first and kind == "tool_use" and set(block) == {"type", "id", "name", "input"}
              and type(block["id"]) is str and TOOL_ID.fullmatch(block["id"]) is not None
              and block["name"] == TOOL and type(block["input"]) is dict
              and block["input"] == {"nonce": nonce}):
            tools.append(block["id"])
        else:
            raise Rejected("probe-content-shape")
    if (first and len(tools) != 1
            or not first and (not identity(confirmation) or "".join(texts) != "recovery-tool-confirmed:" + confirmation)):
        raise Rejected("probe-tool-linkage-unconfirmed")
    # HTTP model is observed, not used as an assertion of the producer's actual
    # prepared upstream mapping. requested_model remains the original request.
    return value, tools[0] if first else None


class TwoTurnProbe:
    def __init__(self, *, attempt_id, requested_model, sources, transport, spool, clock=time.monotonic):
        if (not identity(attempt_id) or not model(requested_model) or not isinstance(sources, ProbeSources)
                or not callable(getattr(transport, "exchange", None)) or not isinstance(spool, ProbeSpool)):
            raise Rejected("probe-explicit-inputs-required")
        self.attempt_id, self.requested_model, self.sources = attempt_id, requested_model, sources
        self.transport, self.spool, self.clock, self.attempted = transport, spool, clock, False

    def run(self, *, deadline):
        if self.attempted:
            raise Rejected("probe-already-attempted")
        self.attempted = True
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        probe_id, request1, request2, nonce = (str(uuid.uuid4()) for _ in range(4))
        if len({probe_id, request1, request2, nonce, self.attempt_id}) != 5:
            raise Rejected("probe-generated-identity-collision")
        tools = [{"name": TOOL, "description": "Echo the nonce and generate a fresh confirmation value.", "input_schema": {
            "type": "object", "properties": {"nonce": {"type": "string"}}, "required": ["nonce"],
            "additionalProperties": False}}]
        prompt = ("Call cpa_recovery_echo exactly once with nonce " + nonce + ". After its tool result, "
                  "reply with exactly recovery-tool-confirmed: followed by the confirmation value from that result "
                  "and no other text.")
        messages = [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
        rows, message_ids, confirmation = [], [], None
        try:
            for turn, request_id in ((1, request1), (2, request2)):
                self.spool.verify(deadline=deadline)
                headers = {"X-CPA-Recovery-Attempt-ID": self.attempt_id, "X-CPA-Recovery-Probe-ID": probe_id,
                    "X-CPA-Recovery-Request-ID": request_id, "X-CPA-Recovery-Parent-Request-ID": "" if turn == 1 else request1,
                    "X-CPA-Recovery-Turn": str(turn)}
                body = canonical({"model": self.requested_model, "max_tokens": 2048, "stream": False,
                    "tools": tools, "tool_choice": {"type": "tool", "name": TOOL} if turn == 1 else {"type": "none"},
                    "messages": messages})
                carrier_hash = self.spool.save(f"turn{turn}-carrier.json", canonical(headers), deadline=deadline)
                request_hash = self.spool.save(f"turn{turn}-request.json", body, deadline=deadline)
                timer.remaining()
                start = timer.last
                status, raw = self.transport.exchange(copy.deepcopy(headers), body, deadline=deadline)
                timer.remaining()
                end = timer.last
                response_hash = self.spool.save(f"turn{turn}-response.json", raw, deadline=deadline)
                if type(status) is not int or status != 200:
                    raise Rejected("probe-http-status-unconfirmed")
                value, tool_id = response(raw, first=turn == 1, nonce=nonce, confirmation=confirmation)
                if value["id"] in message_ids:
                    raise Rejected("probe-response-identity-reused")
                message_ids.append(value["id"])
                rows.append({"turn": turn, "request_id": request_id, "parent_request_id": "" if turn == 1 else request1,
                    "http_status": status, "observed_response_model": value["model"], "request_sha256": request_hash,
                    "carrier_sha256": carrier_hash,
                    "response_sha256": response_hash, "start_monotonic": start, "end_monotonic": end})
                if turn == 1:
                    # Not present in the initial prompt or tool input: a model
                    # repeating those values cannot satisfy the second turn.
                    confirmation = str(uuid.uuid4())
                    if confirmation in {probe_id, request1, request2, nonce, self.attempt_id}:
                        raise Rejected("probe-generated-identity-collision")
                    messages.extend([{"role": "assistant", "content": copy.deepcopy(value["content"])},
                        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_id,
                            "content": canonical({"nonce": nonce, "confirmation": confirmation}).decode("ascii").strip()}]}])
                    linkage = {"tool_name": TOOL, "tool_use_id_sha256": digest(tool_id.encode("ascii")),
                               "nonce_sha256": digest(nonce.encode("ascii")),
                               "confirmation_sha256": digest(confirmation.encode("ascii"))}
            self.spool.verify(deadline=deadline)
            timer.remaining()
            return {"schema": "host-recovery-http-probe-v1", "attempt_id": self.attempt_id, "probe_id": probe_id,
                "requested_model": self.requested_model, "sources": asdict(self.sources), "turns": rows,
                "tool_linkage": linkage, "http_tool_linkage_observed": True, "source_artifacts_authenticated": False,
                "producer_drained": False, "collection_complete": False, "replay_accepted": False,
                "production_acceptance": False}
        except Exception:
            raise Rejected("probe-unconfirmed") from None
