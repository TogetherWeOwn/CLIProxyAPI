"""Real protected launch/IPC/evidence; SCRIPTED manager/cgroup/fence/oracle."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from host_recovery import broker, durable, jobs, launch, manager, outcomes, worker
from test_bootstrap import BOOT
import test_broker
from test_installation import approve
from test_manager import observed

ROOT = Path(__file__).resolve().parent.parent
SOURCE = r'''
import fcntl,json,os,sys
sys.path.insert(0,sys.argv[1])
from host_recovery import durable,launch,worker_bootstrap,worker_runtime
from host_recovery.installation import DirectoryApproval
settings=json.loads(sys.argv[2])
approval=launch.parse_launch(durable.canonical(settings['launch']))
endpoint=DirectoryApproval(**settings['endpoint'])
evidence=DirectoryApproval(**settings['evidence'])
owner=settings['owner']
rows=settings['rows']
rows[1]['MainPID']=str(os.getpid())
class Commands:
 def run(self,argv,*,deadline):
  row=rows[0] if argv[-1]==rows[0]['Id'] else rows[1]
  return ('\n'.join(k+'='+row[k] for k in sorted(row))+'\n').encode()
class Bootstrap(worker_bootstrap.SystemdWorkerBootstrap):
 def __init__(self,**kwargs):
  super().__init__(**kwargs,read_fragment_hash=lambda _:'f'*64,
      read_process_cgroup=lambda pid:rows[1 if pid==os.getpid() else 0]['ControlGroup'])
worker_runtime.SystemdWorkerBootstrap=Bootstrap
class Boundary:
 def __getattr__(self,name):
  def call(*args,deadline,check):
   check(deadline=deadline)
   with durable.directory(settings['journal'],private=True) as fd:
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:pass
    else:raise ValueError('supervisor lock absent')
   if name=='restore_complete':print('REACHED_RESTORE',flush=True)
   if name=='restore_complete' and settings['drift']:
    with open(settings['content']+'/settings.json','wb') as file:file.write(b'changed')
   check(deadline=deadline)
   if name=='verify_baseline_stopped':
    intent=args[0]
    return {'baseline_sha256':intent['baseline_sha256'],'object_id':intent['old_object_id'],
      'original_image':True,'original_replay':True,'new_plugin_absent':True,
      'complete_write_set':True,'metadata_verified':True,'all_writers_stopped':True}
   if name=='start_old':print('SCRIPTED_START',flush=True)
   return True
  return call
try:
 result=worker_runtime.run_worker(approval,endpoint=endpoint,evidence=evidence,boundary=Boundary(),
    persist_alert=lambda _:None,transport_alert=lambda _:True,deadline=1170.,clock=lambda:1005.,
    boot_id=lambda:owner['boot_id'],commands=Commands())
 print(json.dumps(result),flush=True)
 sys.stdin.readline()
except Exception:
 print('REFUSED',flush=True)
 sys.exit(2)
'''


class WorkerRuntimeIPCTests(unittest.TestCase):
    def setUp(self):
        self.case = test_broker.BrokerTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        fixture = self.case.fixture
        self.root = self.case.installation
        intent_path = self.root.journal / 'intent.json'
        intent = durable.decode(intent_path.read_bytes())
        intent['owner']['boot_id'] = BOOT
        raw = durable.canonical(intent)
        intent_path.write_bytes(raw)
        arm_path = self.root.journal / 'arm.json'
        arm = durable.decode(arm_path.read_bytes())
        arm['arm']['boot_id'] = BOOT
        arm['intent_sha256'] = durable.digest(raw)
        arm_path.write_bytes(durable.canonical(arm))
        request_path = self.root.journal / 'reconcile-request.json'
        request = durable.decode(request_path.read_bytes())
        request.update(original_arm=arm['arm'], intent_sha256=durable.digest(raw), detection_upper_bound_seconds=5.)
        request['owner']['boot_id'] = BOOT
        request.pop('request_id')
        request['request_id'] = durable.digest(durable.canonical(request))
        request_path.write_bytes(durable.canonical(request))
        self.case.owner = request['owner']
        fixture.observer.bootstrap.return_value = {'owner': self.case.owner}
        fixture.observer.observe_owner.return_value = self.case.owner
        fixture.now = 1005.
        supervisor_row = observed(self.case.owner['unit'], self.case.owner['invocation_id'], '/scripted/supervisor.service')
        worker_row = observed(jobs.recovery_unit(request['request_id']), self.case.invocation, '/synthetic/worker.service')
        for row in (supervisor_row, worker_row):
            row.update(User=str(os.geteuid()), Group=str(os.getegid()))
        supervisor_row.update(MainPID=str(os.getpid()), Restart='on-failure')
        fixture.approval = replace(fixture.approval,
            recovery=replace(fixture.approval.recovery, intent_sha256=durable.digest(raw)),
            supervisor=replace(fixture.approval.supervisor, fragment_path=supervisor_row['FragmentPath'],
                fragment_sha256='f'*64, properties_sha256=durable.digest(durable.canonical(manager.static_properties(supervisor_row)))),
            job=replace(fixture.approval.job, request_id=request['request_id'], fragment_path=worker_row['FragmentPath'],
                fragment_sha256='f'*64, properties_sha256=durable.digest(durable.canonical(manager.static_properties(worker_row)))))
        self.evidence = self.root.root / 'evidence'
        self.evidence.mkdir(mode=0o700)
        self.settings = {'launch': {'schema': 'host-recovery-launch-v1', **asdict(fixture.approval)},
            'endpoint': asdict(self.case.endpoint_approval), 'evidence': asdict(approve(self.evidence)),
            'owner': self.case.owner, 'rows': [supervisor_row, worker_row], 'journal': str(self.root.journal),
            'content': str(self.root.content), 'drift': False}
        self.children = []
        def cleanup():
            for child in self.children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
        self.addCleanup(cleanup)

    def serve(self):
        def listener(path, **kwargs):
            result = worker.WorkerListener(path, **kwargs)
            child = subprocess.Popen([sys.executable, '-I', '-c', SOURCE, str(ROOT), json.dumps(self.settings)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(child)
            self.case.pid = child.pid
            return result
        with patch.object(launch, 'SystemdSupervisorIdentity', return_value=self.case.identity), \
                patch.object(broker, 'SystemdRecoveryJobs', return_value=self.case.job), \
                patch.object(broker, 'WorkerListener', side_effect=listener):
            return broker.serve_claim(self.case.fixture.approval, endpoint=self.case.endpoint_approval,
                deadline=1170., fence=self.case.fence, persist_alert=lambda _: None,
                transport_alert=lambda _: True, clock=lambda:1005., boot_id=lambda:BOOT,
                result_oracle=lambda intent, report, **kwargs: outcomes.expected_oracle(intent, report))

    def test_separate_runtime_loads_claims_executes_and_reports_under_supervisor_lock(self):
        result = self.serve()
        output, errors = self.children[0].communicate(input=b'release\n', timeout=5)
        self.assertEqual(self.children[0].returncode, 0, errors)
        lines = output.splitlines()
        self.assertEqual(lines[:2], [b'REACHED_RESTORE', b'SCRIPTED_START'])
        receipt = json.loads(lines[2])
        self.assertEqual(receipt['state'], 'report_acknowledged_unsettled')
        self.assertTrue(receipt['result_receipt']['observed'])
        self.assertFalse(receipt['recovery_completed'])
        self.assertTrue(result['worker_result_observed'])
        self.assertEqual(len(list(self.evidence.iterdir())), 1)
        self.assertFalse((self.root.journal / 'recovery-outcome.json').exists())

    def test_separate_runtime_detects_source_drift_inside_restoration_before_scripted_start(self):
        self.settings['drift'] = True
        with self.assertRaises(durable.Rejected):
            self.serve()
        output, errors = self.children[0].communicate(timeout=5)
        self.assertEqual(self.children[0].returncode, 2, errors)
        self.assertEqual(output.splitlines(), [b'REACHED_RESTORE', b'REFUSED'])
        self.assertEqual(list(self.evidence.iterdir()), [])
        self.assertFalse((self.root.journal / 'reconcile-result.json').exists())
        self.assertTrue((self.root.journal / 'reconcile-worker.json').exists())
