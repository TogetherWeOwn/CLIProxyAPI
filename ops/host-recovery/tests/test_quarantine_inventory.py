"""Original real peer/flock/private records; SCRIPTED daemon/ctr/manager reads.

No runtime relaunch, actual daemon/task/shim inventory, host bus or qualification.
"""
import errno
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import daemon, durable, quarantine_inventory as inventory, topology
import test_broker_authority as fixture
from test_topology import manifest


class QuarantineInventoryTests(unittest.TestCase):
    line = fixture.BrokerAuthorityTests.line
    connect = fixture.BrokerAuthorityTests.connect
    command = fixture.BrokerAuthorityTests.command
    write = fixture.BrokerAuthorityTests.write
    run_command = fixture.BrokerAuthorityTests.run_command
    make_engine = fixture.BrokerAuthorityTests.make_engine

    def setUp(self):
        fixture.BrokerAuthorityTests.setUp(self)
        value = manifest()
        intent = self.inputs.intent
        value['installation_id'] = intent['installation_id']
        for target, source in (('candidate_image_sha256','candidate_image_id'),
                               ('baseline_sha256','baseline_sha256'), ('policy_sha256','policy_sha256')):
            value['pins'][target] = intent[source]
        self.topology = topology.Topology(durable.canonical(value))
        self.binding['topology_sha256'] = self.topology.sha256
        self.engine = self.make_engine()
        self.old, self.candidate = intent['old_object_id'], '9'*64
        self.registration = dict(object_id=self.candidate, image_id=intent['candidate_image_id'],
            ownership_id=intent['candidate_ownership_id'], running=False, restart_policy='no')
        self.register()
        self.resources = value['resources']
        self.namespace = self.resources['containerd_namespace']
        self.ids = [self.old,self.candidate]
        self.spaces, self.containers, self.tasks = [self.namespace], [self.old,self.candidate], []
        self.rows = {}
        for object_id in self.ids:
            self.rows[object_id] = dict(object_id=object_id,
                image_id='sha256:'+(value['pins']['rollback_image_sha256'] if object_id==self.old else intent['candidate_image_id']),
                running=False, paused=False, restarting=False, dead=False, status='exited',
                restart_policy='no', restart_retries=0, auto_remove=False,
                installation_id=intent['installation_id'], ownership_id=intent['attempt_id'])
        self.reads, self.read_hook, self.hash_hook = [], lambda _: None, lambda _: None
        self.hashes = {'/accepted/docker':'d'*64, '/accepted/ctr':'e'*64}
        self.adapter = self.make_adapter()

    def register(self):
        self.write('object-'+self.candidate+'.json', durable.canonical(self.registration))

    def make_adapter(self, **overrides):
        args = dict(authority=self.engine, topology=self.topology, docker='/accepted/docker', ctr='/accepted/ctr',
            docker_sha256='d'*64, ctr_sha256='e'*64, commands=SimpleNamespace(run=self.runtime_read),
            read_helper_hash=self.helper_hash)
        args.update(overrides)
        return inventory.QuarantineInventory(**args)

    def helper_hash(self, path):
        result = self.hashes[path]
        self.hash_hook(path)
        return result

    @staticmethod
    def listed(values):
        return ''.join(value+'\n' for value in values).encode('ascii')

    def runtime_read(self, argv, *, deadline):
        self.assertEqual(deadline,1090.)
        self.reads.append(argv)
        docker = ('/accepted/docker','--host=unix://'+self.resources['dockerd_socket'])
        ctr = ('/accepted/ctr','--address='+self.resources['containerd_socket'])
        if argv==docker+('container','ls','--all','--no-trunc','--format={{.ID}}'):
            raw = self.listed(self.ids)
        elif argv in tuple(docker+('container','inspect','--format='+daemon.INSPECT_FORMAT, key) for key in self.rows):
            raw = durable.canonical(self.rows[argv[-1]])
        elif argv==ctr+('namespaces','list','--quiet'):
            raw = self.listed(self.spaces)
        elif argv==ctr+('--namespace='+self.namespace,'containers','list','--quiet'):
            raw = self.listed(self.containers)
        elif argv==ctr+('--namespace='+self.namespace,'tasks','list','--quiet'):
            raw = self.listed(self.tasks)
        else:
            self.fail('unexpected command')
        self.read_hook(argv)
        return raw

    def observe(self):
        return self.adapter.observe(deadline=1090.)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected,'^quarantine-inventory-unconfirmed$'):
            self.observe()
        self.assertTrue(self.adapter.failed)
        before = list(self.reads)
        with self.assertRaises(durable.Rejected):self.observe()
        self.assertEqual(before,self.reads)

    def assert_denies(self, result):
        for key in ('old_epoch_retired','activation_exclusion_proven','shim_containment_proven',
                    'quarantine_reconciled','pending_drained','complete_fence_proven',
                    'recovery_execution_allowed','start_allowed','settlement_allowed','production_acceptance'):
            self.assertIs(result[key],False)

    def test_full_inventory_reads_every_object_without_label_filter_or_mutation(self):
        before = {path.name:path.read_bytes() for path in self.journal.iterdir()}
        result = self.observe()
        self.assertEqual(result['object_count'],2)
        self.assertEqual(result['registered_candidate_count'],1)
        self.assertIs(result['whole_daemon_inventory_observed'],True)
        self.assertIs(result['containerd_no_tasks_observed'],True)
        self.assert_denies(result)
        self.assertEqual(before,{path.name:path.read_bytes() for path in self.journal.iterdir()})
        self.assertEqual(len([args for args in self.reads if 'inspect' in args]),4)
        self.assertFalse(any('--filter' in arg for args in self.reads for arg in args))
        public = durable.canonical(result)
        for private in (self.old,self.candidate,self.namespace,self.resources['dockerd_socket']):
            self.assertNotIn(private.encode(),public)
        self.assertFalse(hasattr(self.adapter,'run'))

    def test_old_only_empty_namespace_observation_does_not_register_or_grant_drain(self):
        (self.journal/('object-'+self.candidate+'.json')).unlink()
        self.ids, self.spaces, self.containers = [self.old], [], []
        result = self.observe()
        self.assertEqual(result['object_count'],1)
        self.assertEqual(result['registered_candidate_count'],0)
        self.assertEqual(len([args for args in self.reads if 'tasks' in args]),2)
        self.assert_denies(result)

    def test_absent_namespace_does_not_skip_actual_task_service_query(self):
        self.spaces,self.containers,self.tasks=[],[],[self.old]
        self.refused()
        self.assertEqual(len([args for args in self.reads if 'tasks' in args]),1)

    def test_unknown_full_daemon_object_is_not_hidden_by_labels(self):
        self.ids.append('8'*64)
        self.refused()
        self.assertEqual(len(self.reads),1)

    def test_missing_registered_object_refuses(self):
        self.ids = [self.old]
        self.refused()
        self.assertEqual(len(self.reads),1)

    def test_lost_create_unregistered_matching_candidate_is_not_adopted(self):
        (self.journal/('object-'+self.candidate+'.json')).unlink()
        before = set(os.listdir(self.journal))
        self.refused()
        self.assertEqual(before,set(os.listdir(self.journal)))
        self.assertEqual(len(self.reads),1)

    def test_running_candidate_refuses_after_reached_inspection(self):
        self.rows[self.candidate].update(running=True,status='running')
        self.refused()
        self.assertTrue(any(args[-1]==self.candidate and 'inspect' in args for args in self.reads))

    def test_restart_policy_drift_refuses_after_reached_inspection(self):
        self.rows[self.candidate]['restart_policy']='always'
        self.refused()
        self.assertTrue(any(args[-1]==self.candidate and 'inspect' in args for args in self.reads))

    def test_image_drift_refuses_after_reached_inspection(self):
        self.rows[self.old]['image_id']='sha256:'+'8'*64
        self.refused()
        self.assertTrue(any(args[-1]==self.old and 'inspect' in args for args in self.reads))

    def test_unknown_namespace_refuses_before_querying_its_tasks(self):
        self.spaces.append('foreign')
        self.refused()
        self.assertTrue(any('namespaces' in args for args in self.reads))
        self.assertFalse(any('tasks' in args for args in self.reads))

    def test_known_task_is_not_stopped_merely_because_docker_inspect_says_so(self):
        self.tasks=[self.old]
        self.refused()
        self.assertTrue(any('tasks' in args for args in self.reads))

    def test_unknown_containerd_metadata_refuses_without_task_start(self):
        self.containers=['7'*64]
        self.refused()
        self.assertTrue(any('containers' in args for args in self.reads))

    def test_registration_path_content_conflict_refuses_before_runtime_reads(self):
        self.registration['object_id']='8'*64
        self.register()
        self.refused()
        self.assertEqual(self.reads,[])

    def test_multiple_registration_records_refuse_before_runtime_reads(self):
        other={**self.registration,'object_id':'8'*64}
        self.write('object-'+'8'*64+'.json',durable.canonical(other))
        self.refused()
        self.assertEqual(self.reads,[])

    def test_staged_registration_refuses_before_runtime_reads(self):
        self.write('.stage-object-'+self.candidate+'.json',durable.canonical(self.registration))
        self.refused()
        self.assertEqual(self.reads,[])

    def test_original_lock_loss_during_inspect_revokes_read(self):
        reached=[]
        def lose(argv):
            if 'inspect' in argv and not reached:
                reached.append(argv);self.command(self.child,'unlock')
        self.read_hook=lose
        self.refused()
        self.assertEqual(len(reached),1)
        self.assertEqual(len(self.reads),2)

    def test_peer_close_during_containerd_query_revokes_read(self):
        reached=[]
        def lose(argv):
            if 'tasks' in argv:
                reached.append(argv);self.command(self.child,'close')
        self.read_hook=lose
        self.refused()
        self.assertEqual(len(reached),1)

    def test_expiry_during_helper_rehash_prevents_any_runtime_read(self):
        reached=[]
        def expire(path):
            if path=='/accepted/ctr': reached.append(path);self.now=1090.
        self.hash_hook=expire
        self.refused()
        self.assertEqual(reached,['/accepted/ctr'])
        self.assertEqual(self.reads,[])

    def test_helper_drift_during_read_revokes_observation(self):
        self.read_hook=lambda _:self.hashes.update({'/accepted/ctr':'0'*64})
        self.refused()
        self.assertEqual(len(self.reads),1)

    def test_inventory_change_between_snapshots_refuses(self):
        reached=[]
        def change(argv):
            if 'tasks' in argv and not reached:
                reached.append(argv);self.rows[self.old]['status']='created'
        self.read_hook=change
        self.refused()
        self.assertEqual(len(reached),1)
        self.assertEqual(len([args for args in self.reads if 'inspect' in args]),4)

    def test_registration_replacement_with_identical_bytes_between_snapshots_refuses(self):
        reached=[]
        def replace(argv):
            if 'tasks' in argv and not reached:
                reached.append(argv)
                target=self.journal/('object-'+self.candidate+'.json')
                temp=self.journal/'replacement.json'
                temp.write_bytes(target.read_bytes());temp.chmod(0o600);temp.replace(target)
        self.read_hook=replace
        self.refused()
        self.assertEqual(len(reached),1)
        self.assertEqual(len([args for args in self.reads if 'inspect' in args]),2)

    def test_reached_registry_io_failure_preserves_bytes_and_never_reads_runtime(self):
        before={path.name:path.read_bytes() for path in self.journal.iterdir()}
        actual=inventory.read_file
        for code in (errno.EIO,errno.ENOSPC):
            reached=[]
            def fail(fd,name,**kwargs):
                if name.startswith('object-'):
                    reached.append(name);raise OSError(code,'restricted')
                return actual(fd,name,**kwargs)
            self.adapter=self.make_adapter()
            with self.subTest(code=code),patch.object(inventory,'read_file',side_effect=fail):self.refused()
            self.assertEqual(reached,['object-'+self.candidate+'.json'])
            self.assertEqual(self.reads,[])
            self.assertEqual(before,{path.name:path.read_bytes() for path in self.journal.iterdir()})

    def test_corrupt_registration_and_unsupported_mode_refuse_before_runtime_reads(self):
        target=self.journal/('object-'+self.candidate+'.json')
        for raw,mode in ((b'{}',0o600),(durable.canonical(self.registration),0o644)):
            target.write_bytes(raw);target.chmod(mode)
            self.adapter=self.make_adapter()
            with self.subTest(mode=mode):self.refused()
            self.assertEqual(self.reads,[])

    def test_constructor_requires_original_topology_and_distinct_pinned_helpers(self):
        value=self.topology.manifest();value['installation_id']='foreign'
        for kwargs in ({'topology':topology.Topology(durable.canonical(value))},
                       {'ctr':'/accepted/docker'},{'docker_sha256':'not-a-pin'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(durable.Rejected):self.make_adapter(**kwargs)


class InventoryFramingTests(unittest.TestCase):
    def test_only_complete_unique_full_id_lines_are_accepted(self):
        self.assertEqual(inventory.lines(b'',pattern=inventory.OBJECT_ID,limit=2),[])
        self.assertEqual(inventory.lines(('b'*64+'\n'+'a'*64+'\n').encode(),
                                        pattern=inventory.OBJECT_ID,limit=2),['a'*64,'b'*64])
        good=b'a'*64
        for raw in (good,good+b'\r\n',good+b'\v\n',good+b'\n\n',b' '+good+b'\n',b'a'*12+b'\n',
                    good+b'\n'+good+b'\n',b'\xff\n',b'\0\n',b'a'*65537):
            with self.subTest(raw=raw[:70]),self.assertRaises(durable.Rejected):
                inventory.lines(raw,pattern=inventory.OBJECT_ID,limit=2)
