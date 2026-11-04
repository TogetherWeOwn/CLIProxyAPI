"""Manager-bound worker claim acquisition, not restoration or service startup.

The installed package must supply independently approved pins and unit bindings
through a restricted boundary. The optional journal factory reads original inputs
from a trusted, already-open locked root; it cannot authenticate its own code or
discover approval in that directory. A self-consistent digest is not an approval.
Manager-command and kernel reads are explicit trusted dependencies.
"""
import copy
import os
import time

from .bootstrap import BOOT, SupervisorBinding, SystemdSupervisorIdentity, kernel_boot_id
from .commands import Deadline
from .dispatch import validate_request
from .durable import Rejected, canonical
from .inventory import HASH
from .jobs import RecoveryJobBinding, SystemdRecoveryJobs, process_cgroup
from .journal import identity
from .loading import load_recovery
from .manager import fragment_hash
from .worker import WorkerClient


class SystemdWorkerBootstrap:
    """One claim against the original request owner, using live peer rechecks.

    Initial MainPID discovery is only a connection hint. The connected peer must
    be held by SO_PEERPIDFD and observed as that same pinned running supervisor
    before sending the claim request and after receiving its reply. A restarted
    supervisor is not adopted. Both local worker observations and the supervisor
    identity must remain unchanged. No retry, environment authority or grant.
    """
    def __init__(self, *, systemctl, commands, supervisor_binding, worker_binding,
                 request, intent_sha256, installation_id, attempt_id, clock=time.monotonic,
                 boot_id=kernel_boot_id, read_fragment_hash=fragment_hash, read_process_cgroup=process_cgroup):
        if not isinstance(supervisor_binding, SupervisorBinding) or not isinstance(worker_binding, RecoveryJobBinding):
            raise Rejected("worker-bootstrap-bindings-required")
        if (not identity(installation_id) or not identity(attempt_id)
                or type(intent_sha256) is not str or HASH.fullmatch(intent_sha256) is None):
            raise Rejected("worker-bootstrap-intent-required")
        self.request = copy.deepcopy(request)
        self.intent_sha256, self.installation_id, self.attempt_id = intent_sha256, installation_id, attempt_id
        self.binding, self.boot_id = worker_binding, boot_id
        self.supervisor = SystemdSupervisorIdentity(systemctl=systemctl, commands=commands,
            binding=supervisor_binding, clock=clock, boot_id=boot_id,
            read_fragment_hash=read_fragment_hash, read_process_cgroup=read_process_cgroup)
        self.clock = self.supervisor._now
        self.jobs = SystemdRecoveryJobs(systemctl=systemctl, commands=commands, binding=worker_binding,
            boot_id=boot_id, clock=self.clock, read_fragment_hash=read_fragment_hash,
            read_process_cgroup=read_process_cgroup)
        self.attempted = False
        self.worker, self.discovered, self.end = None, None, None
        self.result_receipt = None

    @classmethod
    def from_journal(cls, fd, *, approval, supervisor_owner, systemctl, commands,
                     supervisor_binding, worker_binding, clock=time.monotonic, boot_id=kernel_boot_id,
                     read_fragment_hash=fragment_hash, read_process_cgroup=process_cgroup):
        """Load original inputs through the retained installation-owned handle.

        Approval, root-handle acquisition and lock exclusion remain the caller's
        trusted boundary. No index discovered beside these records is authority.
        Manager/peer revalidation still runs at claim time; loading grants nothing.
        """
        inputs = load_recovery(fd, approval=approval, binding=worker_binding,
                               supervisor_owner=supervisor_owner, boot_id=boot_id(), now=clock())
        return cls(systemctl=systemctl, commands=commands, supervisor_binding=supervisor_binding,
                   worker_binding=worker_binding, request=inputs.request,
                   intent_sha256=approval.intent_sha256, installation_id=approval.installation_id,
                   attempt_id=approval.attempt_id, clock=clock, boot_id=boot_id,
                   read_fragment_hash=read_fragment_hash, read_process_cgroup=read_process_cgroup)

    def _request(self):
        boot = self.boot_id()
        if type(boot) is not str or BOOT.fullmatch(boot) is None:
            raise Rejected("worker-bootstrap-boot-required")
        validate_request(self.request, self.binding, boot, self.clock())
        owner = self.request["owner"]
        if (owner["unit"] != self.supervisor.binding.unit
                or owner["installation_id"] != self.installation_id or owner["attempt_id"] != self.attempt_id
                or self.request["intent_sha256"] != self.intent_sha256):
            raise Rejected("worker-bootstrap-request-unbound")
        return boot

    def _worker(self, deadline):
        if os.geteuid() <= 0 or os.getegid() <= 0:
            raise Rejected("worker-bootstrap-unprivileged-owner-required")
        return self.jobs.observe_worker(self.binding.request_id, pid=os.getpid(), deadline=deadline,
                                        uid=os.geteuid(), gid=os.getegid())

    def _supervisor(self, deadline, pid=None):
        row = self.supervisor._row(deadline=deadline, pid=pid)
        if (row["invocation_id"] != self.request["owner"]["invocation_id"] or row["pid"] == os.getpid()
                or row["invocation_id"] == self.worker["invocation_id"] or row["cgroup"] == self.worker["cgroup"]):
            raise Rejected("worker-bootstrap-separate-owner-required")
        return row

    def _verify_peer(self, *, peer, peer_alive, deadline):
        if deadline != self.end or peer_alive() is not True:
            raise Rejected("worker-bootstrap-peer-unconfirmed")
        Deadline(self.clock, deadline).remaining()
        boot = self._request()
        if (peer != {key: self.discovered[key] for key in ("pid", "uid", "gid")}
                or canonical(self._worker(deadline)) != canonical(self.worker)):
            raise Rejected("worker-bootstrap-identity-changed")
        group = self.supervisor.read_process_cgroup(peer["pid"])
        before = self._supervisor(deadline, peer["pid"])
        after = self._supervisor(deadline, peer["pid"])
        if (before != self.discovered or after != before or group != before["cgroup"]
                or self.supervisor.read_process_cgroup(peer["pid"]) != group
                or canonical(self._worker(deadline)) != canonical(self.worker)
                or self._request() != boot or peer_alive() is not True):
            raise Rejected("worker-bootstrap-identity-changed")
        Deadline(self.clock, deadline).remaining()
        return copy.deepcopy(self.worker)

    def claim(self, path, *, deadline, result_provider=None):
        if result_provider is not None and not callable(result_provider):
            raise Rejected("worker-result-provider-required")
        if self.attempted:
            raise Rejected("worker-bootstrap-exhausted")
        self.attempted = True
        # Every query, connection and reply uses one inclusive caller/original
        # reserve. Discovery grants nothing and cannot renew an expired request.
        Deadline(self.clock, deadline).remaining()
        boot = self._request()
        self.end = min(deadline, self.request["deadline"])
        self.worker = self._worker(self.end)
        self.discovered = self._supervisor(self.end)
        if (canonical(self._worker(self.end)) != canonical(self.worker) or self._request() != boot):
            raise Rejected("worker-bootstrap-identity-changed")
        client = WorkerClient(path, supervisor_uid=self.discovered["uid"], supervisor_pid=self.discovered["pid"],
            supervisor_owner=self.request["owner"], request_id=self.binding.request_id,
            intent_sha256=self.intent_sha256, clock=self.clock, verify_identity=self._verify_peer)
        if result_provider is None:
            return client.claim(deadline=self.end)
        result = client.claim(deadline=self.end, result_provider=result_provider)
        self.result_receipt = copy.deepcopy(client.result_receipt)
        return result
