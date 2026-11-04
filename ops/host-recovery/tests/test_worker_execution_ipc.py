"""Actual worker/IPC/tree/evidence/lock composition; SCRIPTED host authority."""
import copy
import errno
import json
import os
from pathlib import Path
import unittest

from host_recovery import durable, inventory
import test_dispatch_broker


SOURCE = r'''
import copy,fcntl,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from host_recovery import alert,durable,inventory,jobs,loading,restore
from host_recovery.installation import DirectoryApproval
from host_recovery.worker import WorkerClient
from host_recovery.worker_recovery import WorkerEvidence,WorkerRecovery
settings=SETTINGS
intent,request=settings['intent'],settings['request']
now=lambda:1005.
root=Path(settings['root'])
st=root.stat()
evidence=WorkerEvidence(DirectoryApproval(str(root),st.st_dev,st.st_ino,st.st_uid,st.st_gid,0o700),
    request['request_id'],clock=now)
if settings['fault']:
 def fault(hook):
  if hook=='directory-fsync':
   print('REACHED_DIRECTORY_FSYNC',flush=True)
   raise OSError(settings['fault'],'injected')
 evidence.fault=fault
worker={'schema':'host-recovery-job-observation-v1','request_id':request['request_id'],
    'boot_id':request['owner']['boot_id'],'unit':jobs.recovery_unit(request['request_id']),
    'invocation_id':'b'*32,'state':'running','job_id':0,'pid':os.getpid(),'cgroup':'/synthetic/recovery.service'}
active_check=None
class Boundary:
 def authorize_worker_recovery(self,intent,request,claim,*,deadline,check):
  global active_check
  active_check=check
  with durable.directory(settings['journal'],private=True) as fd:
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:pass
   else:raise ValueError('supervisor lock absent')
  return check(deadline=deadline)
 def fence(self,intent,*,deadline,check):return check(deadline=deadline)
 def quiesce(self,intent,*,deadline,check):return check(deadline=deadline)
 def validate_recovery(self,intent,*,deadline,check):return check(deadline=deadline)
 def restore_complete(self,intent,*,deadline,check):
  with durable.directory(settings['tree'],private=True) as fd:
   restore.restore_tree(fd,settings['baseline'],{settings['blob_sha256']:b'original-baseline-config'}, {},
                      check=lambda:check(deadline=deadline))
  return True
 def verify_baseline_stopped(self,intent,*,deadline,check):
  check(deadline=deadline)
  with durable.directory(settings['tree'],private=True) as fd:
   if inventory.snapshot(fd,uid=os.geteuid(),gid=os.getegid())[0]!=settings['baseline']:return None
  return {'baseline_sha256':intent['baseline_sha256'],'object_id':intent['old_object_id'],
    'original_image':True,'original_replay':True,'new_plugin_absent':True,'complete_write_set':True,
    'metadata_verified':True,'all_writers_stopped':True}
 def start_old(self,intent,receipt,*,deadline,check):
  check(deadline=deadline)
  if settings['worker_kill']:
   os.kill(os.getpid(),9)
  if settings['identity_loss']:
   worker['invocation_id']='c'*32
   check(deadline=deadline)
  # Only a scripted start marker, never a daemon/container start.
  print('SCRIPTED_START',flush=True)
  return True
 def old_ready(self,intent,*,deadline,check):return check(deadline=deadline)
keys=('package_sha256','manifest_sha256','baseline_sha256','policy_sha256','installation_id','attempt_id')
approval=loading.RecoveryApproval(request['intent_sha256'],**{k:intent[k] for k in keys},uid=os.geteuid(),gid=os.getegid())
binding=jobs.RecoveryJobBinding(request['request_id'],'/synthetic/unit','f'*64,'e'*64)
def transport(notice):
 alert.validate_notice(notice)
 print('ALERT_ATTEMPTED',flush=True)
 return True
provider=WorkerRecovery(approval=approval,binding=binding,intent=intent,request=request,boundary=Boundary(),
    evidence=evidence,persist_alert=lambda _:None,transport_alert=transport,clock=now,
    boot_id=lambda:request['owner']['boot_id'])
client=WorkerClient(sys.argv[2],supervisor_uid=os.geteuid(),supervisor_pid=int(sys.argv[3]),
    supervisor_owner=request['owner'],request_id=request['request_id'],intent_sha256=request['intent_sha256'],
    clock=now,verify_identity=lambda **kw:copy.deepcopy(worker))
execution_check=None
def execute(claim,*,deadline,check):
 global execution_check
 execution_check=check
 return provider(claim,deadline=deadline,check=check)
try:
 client.claim(deadline=request['deadline'],recovery_provider=execute)
 for expired in (active_check,execution_check):
  try:expired(deadline=request['deadline'])
  except durable.Rejected:pass
  else:raise ValueError('execution lease escaped provider')
 print(json.dumps(client.result_receipt),flush=True)
 sys.stdin.readline()
except Exception:
 print('REFUSED',flush=True)
 sys.exit(2)
'''


class WorkerExecutionIPCTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_dispatch_broker.DispatchBrokerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.case.now = 1005.
        self.tree = self.fixture.endpoint / 'tree'
        self.tree.mkdir(mode=0o700)
        self.file = self.tree / 'config.yaml'
        self.file.write_bytes(b'original-baseline-config')
        self.file.chmod(0o600)
        with durable.directory(str(self.tree), private=True) as fd:
            self.baseline, blobs = inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid())
        self.blob_sha256 = next(iter(blobs))
        self.file.write_bytes(b'partial-candidate')
        self.evidence = self.fixture.endpoint / 'evidence'
        self.evidence.mkdir(mode=0o700)
        self.fixture.case.value['baseline_sha256'] = durable.digest(durable.canonical(self.baseline))
        original = durable.canonical(self.fixture.case.value)
        (self.fixture.case.root / 'intent.json').write_bytes(original)
        self.fixture.case.original = original
        # Repin the arm's correspondence to this newly created synthetic intent.
        arm = durable.decode((self.fixture.case.root / 'arm.json').read_bytes())
        arm['intent_sha256'] = durable.digest(original)
        (self.fixture.case.root / 'arm.json').write_bytes(durable.canonical(arm))
        self.fault, self.worker_kill, self.identity_loss = None, False, False
        self.fixture.on_start = self.source
        self.fixture.on_oracle = self.oracle
        self.observed_report = None

    def source(self, process):
        settings = {'intent': process.log.intent, 'request': self.fixture.request, 'root': str(self.evidence),
                    'journal': str(self.fixture.case.root), 'tree': str(self.tree), 'baseline': self.baseline,
                    'blob_sha256': self.blob_sha256, 'fault': self.fault, 'worker_kill': self.worker_kill,
                    'identity_loss': self.identity_loss}
        self.fixture.source = SOURCE.replace('SETTINGS', repr(settings), 1)

    def oracle(self, process):
        result = durable.decode((self.fixture.case.root / 'reconcile-result.json').read_bytes())
        raw = (self.evidence / ('worker-evidence-' + self.fixture.request['request_id'] + '.json')).read_bytes()
        self.assertEqual(durable.digest(raw), result['evidence_sha256'])
        report = durable.decode(raw)
        self.assertEqual(report['claim_sha256'], durable.digest(durable.canonical(process.worker_claim)))
        self.assertEqual(report['request_id'], self.fixture.request['request_id'])
        self.assertEqual(report['intent_sha256'], process.intent_sha256)
        self.assertEqual(report['status']['outcome'], 'baseline_restored')
        with durable.directory(str(self.tree), private=True) as fd:
            self.assertEqual(inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid())[0], self.baseline)
        self.observed_report = report

    def test_real_worker_restores_under_original_supervisor_lock_and_reports_on_same_peer(self):
        with self.fixture.case.open() as process:
            self.fixture.configure(process)
            result = self.fixture.serve(process)
            self.assertTrue(result['worker_result_observed'])
            self.assertFalse(result['installation_settled'])
            self.fixture.locked()
            child = self.fixture.children[0]
            lines = child.communicate(input=b'release\n', timeout=5)[0].splitlines()
            self.assertEqual(lines[:2], [b'SCRIPTED_START', b'ALERT_ATTEMPTED'])
            self.assertEqual(child.returncode, 0)
            receipt = json.loads(lines[2])
            self.assertTrue(receipt['observed'])
            self.assertFalse(receipt['start_permission'])
            self.assertTrue(self.observed_report['worker_report_only'])
            self.assertEqual(self.file.read_bytes(), b'original-baseline-config')
            self.assertFalse((self.fixture.case.root / 'recovery-outcome.json').exists())
            self.assertEqual(len(self.fixture.starts()), 1)
            print(durable.canonical({"schema": "worker-execution-ipc-test-v1", "boundary_kind": "scripted-manager-fence-daemon-oracle",
                "actual_file_restoration": True, "supervisor_lock_retained": True, "worker_exit": child.returncode,
                "worker_evidence": self.observed_report, "result_receipt": receipt,
                "full_system_recovery_proven": False}).decode(), flush=True)

    def test_replaced_scripted_worker_identity_is_detected_inside_start_barrier(self):
        self.identity_loss = True
        with self.fixture.case.open() as process:
            self.fixture.configure(process)
            with self.assertRaises(durable.Rejected):
                self.fixture.serve(process)
            output = self.fixture.children[0].communicate(timeout=5)[0]
            self.assertNotIn(b'SCRIPTED_START', output)
            self.assertIn(b'ALERT_ATTEMPTED', output)
            self.assertIn(b'REFUSED', output)
            self.assertFalse((self.fixture.case.root / 'reconcile-result.json').exists())
            self.assertEqual(list(self.evidence.iterdir()), [])
            self.fixture.locked()

    def test_worker_sigkill_after_restoration_before_start_retains_claim_and_original_intent(self):
        self.worker_kill = True
        with self.fixture.case.open() as process:
            self.fixture.configure(process)
            with self.assertRaises(durable.Rejected):
                self.fixture.serve(process)
            child = self.fixture.children[0]
            self.assertEqual(child.wait(timeout=5), -9)
            self.assertEqual(self.file.read_bytes(), b'original-baseline-config')
            self.assertTrue((self.fixture.case.root / 'reconcile-worker.json').exists())
            self.assertFalse((self.fixture.case.root / 'reconcile-result.json').exists())
            self.assertFalse((self.fixture.case.root / 'recovery-outcome.json').exists())
            self.assertEqual((self.fixture.case.root / 'intent.json').read_bytes(), self.fixture.case.original)
            self.assertEqual(list(self.evidence.iterdir()), [])
            self.assertFalse(process.result_observed)
            self.fixture.locked()
            self.assertEqual(len(self.fixture.starts()), 1)

    def test_reached_final_evidence_fsync_fault_does_not_send_success_result(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code):
                self.setUp()
                self.fault = code
                with self.fixture.case.open() as process:
                    self.fixture.configure(process)
                    with self.assertRaises(durable.Rejected):
                        self.fixture.serve(process)
                    child = self.fixture.children[0]
                    output = child.communicate(timeout=5)[0]
                    self.assertIn(b'REACHED_DIRECTORY_FSYNC\n', output)
                    self.assertIn(b'ALERT_ATTEMPTED\n', output)
                    self.assertIn(b'REFUSED\n', output)
                    self.assertIsNone(process.worker_result)
                    self.assertFalse(process.result_observed)
                    self.assertFalse((self.fixture.case.root / 'reconcile-result.json').exists())
                    self.fixture.locked()
                    self.assertEqual(len(self.fixture.starts()), 1)
