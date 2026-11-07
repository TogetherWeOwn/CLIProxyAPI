"""Real private records/original peer/flock; SCRIPTED bus/manager/cgroup boundary."""
import errno
import unittest
from unittest.mock import Mock, patch

from host_recovery import broker_history, durable, manager_bus, manager_jobs, topology
from host_recovery.protected_file import ProtectedFile
import test_manager_jobs as fixture
from test_manager_bus import ScriptedConnection


class CompletionJournalTests(unittest.TestCase):
    line = fixture.RuntimeJobTrackingTests.line
    connect = fixture.RuntimeJobTrackingTests.connect
    command = fixture.RuntimeJobTrackingTests.command
    write = fixture.RuntimeJobTrackingTests.write
    run_command = fixture.RuntimeJobTrackingTests.run_command
    make_engine = fixture.RuntimeJobTrackingTests.make_engine
    make_adapter = fixture.RuntimeJobTrackingTests.make_adapter
    run_effect = fixture.RuntimeJobTrackingTests.run_effect
    contain = fixture.RuntimeJobTrackingTests.contain
    refused = fixture.RuntimeJobTrackingTests.refused
    records = fixture.RuntimeJobTrackingTests.records

    def setUp(self):
        fixture.RuntimeJobTrackingTests.setUp(self)
        library = Mock(spec=ProtectedFile)
        library.uid = library.gid = 0; library.fd = 99
        library.checksum.return_value = 'a'*64
        outer = self
        class Connection(ScriptedConnection):
            def call(self, destination, interface, method, signature, args, response, **kwargs):
                if method=='StopUnit':
                    role = next(role for role,unit in outer.units.items() if unit.unit==args[0])
                    name,_ = manager_jobs.record_names(2,role)
                    self.number = self.reply_number = 41+topology.RUNTIME_ROLES.index(role)
                    self.cookie += 1
                    pending = durable.decode((outer.state/name).read_bytes())
                    self.assert_pending = pending['unit']==args[0]
                    if not self.assert_pending: raise AssertionError('fixed pending not reached')
                    outer.effects.append(args[0])
                    outer.rows[role].update(ActiveState='inactive',SubState='dead',MainPID='0',Job='0')
                return super().call(destination,interface,method,signature,args,response,**kwargs)
        def connection(library,address):
            value = Connection(library,address)
            value.job_units = outer.units
            outer.connection = value
            return value
        for patcher in (patch.object(manager_bus,'_Library',return_value=object()),
                        patch.object(manager_bus,'_Connection',side_effect=connection)):
            patcher.start();self.addCleanup(patcher.stop)
        self.session = manager_bus.ManagerJobSession(library=library,library_sha256='a'*64,units=self.units,
            deadline=1090.,clock=lambda:self.now,check=lambda:self.engine.observe(deadline=1090.))
        self.addCleanup(self.session.close)
        self.jobs = manager_jobs.RuntimeStopJobs(journal=self.operations,units=self.units,busctl='/accepted/busctl',
            busctl_sha256='d'*64,commands=self.transport,read_helper_hash=lambda _:'d'*64,session=self.session)
        self.adapter = self.make_adapter(jobs=self.jobs)

    def test_session_submission_and_durable_completion_do_not_grant_retirement_or_start(self):
        receipt = self.contain()
        self.assertEqual(self.bus_calls,[],'single-connection mode must never fall back to busctl')
        self.assertEqual(receipt['manager_job_observations'],{role:'completion_done_observed' for role in topology.RUNTIME_ROLES})
        for role in topology.RUNTIME_ROLES:
            name = manager_jobs.completion_name(2,role)
            value = durable.decode((self.state/name).read_bytes())
            self.assertEqual(value['manager_owner'],self.session.owner)
            self.assertEqual(value['bus_id'],self.session.bus_id)
            self.assertEqual(value['unit'],self.units[role].unit)
            self.assertFalse(value['retirement_proven'])
        for field in ('manager_jobs_retired','activation_exclusion_proven','pending_drained','start_allowed'):
            self.assertFalse(receipt[field])

    def test_single_connection_missing_completion_keeps_absent_not_retired(self):
        self.connection.mode = 'absent'
        receipt = self.contain()
        self.assertEqual(receipt['manager_job_observations'],{role:'absent_not_retired' for role in topology.RUNTIME_ROLES})
        self.assertFalse(any('completion' in name for name in self.records()))

    def test_failed_result_is_durable_but_never_quiescence(self):
        self.connection.result = 'failed'
        receipt = self.contain()
        self.assertEqual(receipt['manager_job_observations']['dockerd'],'completion_failed_observed')
        self.assertFalse(receipt['runtime_empty_observed'])
        self.assertFalse(receipt['pending_drained'])

    def test_reached_completion_publication_faults_leave_pending_and_skip_kernel_kill(self):
        for point in ('create','write','file-fsync','rename','directory-fsync','readback'):
            for code in (errno.EIO,errno.ENOSPC):
                with self.subTest(point=point,code=code):
                    self.setUp();reached=[]
                    actual = self.operations._write
                    def fault(here):
                        if here==point:
                            reached.append(here);raise OSError(code,'restricted')
                    def write(name,value):
                        if name==manager_jobs.completion_name(2,'dockerd'): self.operations.fault=fault
                        return actual(name,value)
                    with patch.object(self.operations,'_write',side_effect=write): self.refused()
                    self.assertEqual(reached,[point])
                    self.assertEqual(len(self.effects),1)
                    self.assertEqual(self.kill_file.read_bytes(),b'')
                    self.assertTrue((self.state/'operation-02-job-01-return.json').exists())

    def test_history_classifies_witnesses_without_reviving_session(self):
        self.contain()
        records = broker_history._capture(self.operations.fd,uid=self.operations._owner[0],gid=self.operations._owner[1])
        _,operations = broker_history._classify(records,binding=self.binding)
        self.assertEqual([job['classification'] for job in operations[-1]['manager_jobs']],['completion_done_observed']*2)
        self.assertTrue(all(job['retirement_proven'] is False for job in operations[-1]['manager_jobs']))
        self.session.close()
        with self.assertRaises(durable.Rejected): self.jobs.observe(deadline=1090.,check=lambda:None)
        self.assertEqual(self.records(),records)

    def test_history_rejects_tampered_or_orphan_completion(self):
        self.contain();original=self.records()
        name = manager_jobs.completion_name(2,'dockerd')
        for key,value in (('return_sha256','b'*64),('manager_owner',':1.8'),('bus_id','b'*32),
                          ('job_id',True),('job_path',manager_jobs.JOB_PREFIX+'99'),('unit','other.service'),
                          ('result','unknown'),('sender_cookie',True),('retirement_proven',True)):
            with self.subTest(key=key):
                records=dict(original);event=durable.decode(records[name]);event[key]=value
                records[name]=durable.canonical(event)
                with self.assertRaises(durable.Rejected):broker_history._classify(records,binding=self.binding)
        for missing in ('operation-02-job-01-pending.json','operation-02-job-01-return.json'):
            records=dict(original);records.pop(missing)
            with self.assertRaises(durable.Rejected):broker_history._classify(records,binding=self.binding)

    def test_peer_loss_during_single_connection_wait_prevents_stop(self):
        reached=[]
        def lose(method):
            if method=='ListJobs' and not reached:
                reached.append(method);self.command(self.child,'close')
        self.connection.call_hook=lose
        self.refused()
        self.assertEqual(reached,['ListJobs'])
        self.assertEqual(self.effects,[])
        self.assertEqual(self.kill_file.read_bytes(),b'')
