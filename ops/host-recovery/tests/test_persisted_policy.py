"""Real protected files/original peer/flock; SCRIPTED manager, no Docker run."""
from dataclasses import replace
import errno
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import durable, persisted_policy as policy, topology
from host_recovery.installation import DirectoryApproval
from fixture_home import fixture_home
import test_privileged_broker as peer_fixture
from test_topology import manifest


def make_policy(test, peer, units=None):
    temp = tempfile.TemporaryDirectory(prefix='recovery-policy-', dir=fixture_home())
    test.addCleanup(temp.cleanup)
    data = Path(temp.name) / 'docker'
    data.mkdir(mode=0o700)
    path = data / 'containers'
    path.mkdir(mode=0o700)
    value = manifest()
    intent = peer.inputs.intent
    value['installation_id'] = intent['installation_id']
    value['resources']['data_root'] = str(data)
    value['tools']['dockerd']['source_revision'] = policy.SOURCE
    if units is not None:
        value['runtime'].update(slice='runtime.slice',cgroup_path='/runtime.slice',
            units={role:{'unit':unit.unit,'effective_sha256':unit.properties_sha256} for role,unit in units.items()})
    for target, source in (('candidate_image_sha256','candidate_image_id'),
                           ('baseline_sha256','baseline_sha256'), ('policy_sha256','policy_sha256')):
        value['pins'][target] = intent[source]
    top = topology.Topology(durable.canonical(value))
    peer.binding['topology_sha256'] = top.sha256
    peer.engine = peer.make_engine()
    old = intent['old_object_id']
    directory = path / old
    directory.mkdir(mode=0o700)
    host = {'RestartPolicy':{'Name':'no','MaximumRetryCount':0}, 'AutoRemove':False,
            'Privileged':False, 'CgroupParent':value['runtime']['slice'], 'Binds':None}
    config = {'ID':old,'Image':'sha256:'+value['pins']['rollback_image_sha256'],
              'State':{'Running':True,'Restarting':True}}
    # Deliberately stale state must never be read as task-death evidence.
    for name, item in (('hostconfig.json',host), ('config.v2.json',config)):
        target = directory / name
        target.write_bytes(durable.canonical(item))
        target.chmod(0o600)
    st = path.stat()
    approved = DirectoryApproval(str(path),st.st_dev,st.st_ino,st.st_uid,st.st_gid,0o700)
    hosts = durable.canonical({old:durable.digest((directory/'hostconfig.json').read_bytes())})
    adapter = policy.PersistedObjectPolicy(authority=peer.engine,topology=top,directory=approved,approved_hosts=hosts)
    return SimpleNamespace(adapter=adapter,topology=top,root=path,path=directory,host=host,config=config,hosts=hosts)


class PersistedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.peer = peer_fixture.BrokerProtocolTests()
        self.addCleanup(self.peer.doCleanups)
        self.peer.setUp()
        self.fx = make_policy(self,self.peer)
        self.checks = []

    def observe(self):
        return self.fx.adapter.observe(deadline=1090.,check=lambda:self.checks.append(True))

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected,'^persisted-policy-observation-unconfirmed$'):
            self.observe()
        self.assertTrue(self.fx.adapter.failed)
        before = len(self.checks)
        with self.assertRaises(durable.Rejected):self.observe()
        self.assertEqual(len(self.checks),before)

    def write(self,name,value):
        path=self.fx.path/name
        path.write_bytes(value if type(value) is bytes else durable.canonical(value))
        path.chmod(0o600)

    def test_reads_original_full_inventory_without_runtime_contact_or_mutation(self):
        before={p:p.read_bytes() for p in self.fx.path.iterdir()}
        result=self.observe()
        self.assertTrue(result['restart_disabled_policy_observed'])
        self.assertEqual(result['object_count'],1)
        self.assertEqual(before,{p:p.read_bytes() for p in self.fx.path.iterdir()})
        for key in ('ownership_history_proven','runtime_relaunch_allowed','pending_drained',
                    'start_allowed','complete_fence_proven','production_acceptance'):
            self.assertIs(result[key],False)
        self.assertNotIn(str(self.fx.root),str(result))
        self.assertNotIn(self.peer.inputs.intent['old_object_id'],str(result))
        self.assertEqual(result,self.observe())

    def test_exact_registered_candidate_is_checked_with_old_and_never_adopted(self):
        intent=self.peer.inputs.intent
        candidate='9'*64
        self.peer.write('object-'+candidate+'.json',durable.canonical(dict(object_id=candidate,
            image_id=intent['candidate_image_id'],ownership_id=intent['candidate_ownership_id'],
            running=False,restart_policy='no')))
        path=self.fx.root/candidate;path.mkdir(mode=0o700)
        for name,item in (('hostconfig.json',self.fx.host),('config.v2.json',
                {**self.fx.config,'ID':candidate,'Image':'sha256:'+intent['candidate_image_id']})):
            target=path/name;target.write_bytes(durable.canonical(item));target.chmod(0o600)
        hosts=durable.decode(self.fx.hosts)
        hosts[candidate]=durable.digest((path/'hostconfig.json').read_bytes())
        self.fx.adapter=policy.PersistedObjectPolicy(authority=self.peer.engine,topology=self.fx.topology,
            directory=self.fx.adapter.directory,approved_hosts=durable.canonical(hosts))
        result=self.observe()
        self.assertEqual(result['object_count'],2)
        self.assertIs(result['runtime_relaunch_allowed'],False)

    def test_python_only_bom_and_utf16_json_are_not_moby_policy(self):
        raw=durable.canonical(self.fx.config)
        for data in (b'\xef\xbb\xbf'+raw,raw.decode().encode('utf-16'),raw.decode().encode('utf-32')):
            with self.subTest(encoding=data[:4]):
                self.setUp();self.write('config.v2.json',data);self.refused()

    def test_empty_or_unsupported_source_approval_refuses_construction(self):
        for hosts in (b'{}',durable.canonical({}),durable.canonical({'short':'a'*64})):
            with self.subTest(hosts=hosts),self.assertRaises(durable.Rejected):
                policy.PersistedObjectPolicy(authority=self.peer.engine,topology=self.fx.topology,
                    directory=self.fx.adapter.directory,approved_hosts=hosts)
        value=self.fx.topology.manifest()
        value['tools']['dockerd']['source_revision']='a'*40
        top=topology.Topology(durable.canonical(value))
        self.peer.binding['topology_sha256']=top.sha256
        engine=self.peer.make_engine()
        with self.assertRaises(durable.Rejected):
            policy.PersistedObjectPolicy(authority=engine,topology=top,directory=self.fx.adapter.directory,
                approved_hosts=self.fx.hosts)

    def test_wrong_root_inode_or_path_is_not_discovered_or_adopted(self):
        old=self.fx.adapter.directory
        for directory in (replace(old,inode=old.inode+1),replace(old,path=str(self.fx.path))):
            with self.subTest(path=directory.path),self.assertRaises(durable.Rejected):
                adapter=policy.PersistedObjectPolicy(authority=self.peer.engine,topology=self.fx.topology,
                    directory=directory,approved_hosts=self.fx.hosts)
                adapter.observe(deadline=1090.,check=lambda:None)

    def test_restart_modes_missing_fields_and_boolean_retries_refuse(self):
        for change in ({'Name':'always'},{'Name':'unless-stopped'},{'Name':'on-failure'},
                       {'Name':''},{'MaximumRetryCount':True},{'MaximumRetryCount':0.0}):
            with self.subTest(change=change):
                self.setUp()
                host=self.fx.host.copy()
                host['RestartPolicy']={**host['RestartPolicy'],**change}
                self.write('hostconfig.json',host)
                # Repin the synthetic approved hash to reach semantic rejection,
                # not just hash drift. This is not operational approval.
                hosts=durable.canonical({self.peer.inputs.intent['old_object_id']:
                    durable.digest((self.fx.path/'hostconfig.json').read_bytes())})
                self.fx.adapter=policy.PersistedObjectPolicy(authority=self.peer.engine,topology=self.fx.topology,
                    directory=self.fx.adapter.directory,approved_hosts=hosts)
                self.refused()

    def test_approved_host_hash_drift_refuses_without_learning_new_hash(self):
        self.write('hostconfig.json',{**self.fx.host,'Binds':['unexpected']})
        self.refused()

    def test_missing_hostconfig_never_uses_moby_empty_default(self):
        (self.fx.path/'hostconfig.json').unlink()
        self.refused()

    def test_malformed_duplicate_or_case_aliased_json_refuses(self):
        for raw in (b'{',b'{"ID":"a","ID":"b"}',
                    b'{"ID":"a","id":"b"}',b'{"RestartPolicy":{"Name":"no","name":"always"}}'):
            with self.subTest(raw=raw):
                self.setUp();self.write('config.v2.json',raw);self.refused()

    def test_wrong_persisted_id_or_image_refuses(self):
        for change in ({'ID':'8'*64},{'Image':'sha256:'+'8'*64}):
            with self.subTest(change=change):
                self.setUp();self.write('config.v2.json',{**self.fx.config,**change});self.refused()

    def test_partial_or_unregistered_create_directory_is_not_ignored(self):
        (self.fx.root/('9'*64)).mkdir(mode=0o700)
        self.refused()

    def test_registered_candidate_missing_from_metadata_refuses(self):
        intent=self.peer.inputs.intent
        self.peer.write('object-'+'9'*64+'.json',durable.canonical(dict(object_id='9'*64,
            image_id=intent['candidate_image_id'],ownership_id=intent['candidate_ownership_id'],
            running=False,restart_policy='no')))
        self.refused()

    def test_symlink_hardlink_fifo_and_group_writable_policy_refuse(self):
        for kind in ('symlink','hardlink','fifo','mode'):
            with self.subTest(kind=kind):
                self.setUp();path=self.fx.path/'hostconfig.json'
                if kind=='mode':path.chmod(0o660)
                else:
                    raw=path.read_bytes();path.unlink()
                    if kind=='symlink':path.symlink_to('config.v2.json')
                    elif kind=='fifo':os.mkfifo(path,0o600)
                    else:
                        source=self.fx.root.parent/'other';source.write_bytes(raw);source.chmod(0o600);os.link(source,path)
                self.refused()

    def test_object_directory_replacement_during_read_refuses(self):
        original=policy.read_file;reached=[]
        def read(fd,name,**kwargs):
            value=original(fd,name,**kwargs)
            if name=='hostconfig.json' and not reached:
                reached.append(name)
                self.fx.path.rename(self.fx.root/'replaced')
                self.fx.path.mkdir(mode=0o700)
            return value
        with patch.object(policy,'read_file',side_effect=read):self.refused()
        self.assertEqual(reached,['hostconfig.json'])

    def test_same_inode_content_change_during_recheck_is_not_metadata_only_proof(self):
        original=policy.read_file;reached=[]
        def read(fd,name,**kwargs):
            value=original(fd,name,**kwargs)
            if name=='hostconfig.json' and not reached:
                reached.append(name);self.write('config.v2.json',{**self.fx.config,'Image':'sha256:'+'8'*64})
            return value
        with patch.object(policy,'read_file',side_effect=read):self.refused()
        self.assertEqual(reached,['hostconfig.json'])

    def test_storage_faults_reach_policy_files_and_revoke_instance(self):
        original=policy.read_file
        for code in (errno.EIO,errno.ENOSPC):
            with self.subTest(code=code):
                self.setUp();reached=[]
                def read(fd,name,**kwargs):
                    if name=='hostconfig.json':
                        reached.append(name);raise OSError(code,'synthetic read failure')
                    return original(fd,name,**kwargs)
                with patch.object(policy,'read_file',side_effect=read):self.refused()
                self.assertEqual(reached,['hostconfig.json'])

    def test_original_lock_loss_during_policy_read_revokes_without_daemon_contact(self):
        original=policy.read_file;reached=[]
        def read(fd,name,**kwargs):
            value=original(fd,name,**kwargs)
            if name=='hostconfig.json' and not reached:
                reached.append(name);self.peer.command(self.peer.child,'unlock')
            return value
        with patch.object(policy,'read_file',side_effect=read):self.refused()
        self.assertEqual(reached,['hostconfig.json'])

    def test_deadline_expiry_during_read_is_not_fresh_observation(self):
        original=policy.read_file;reached=[]
        def read(fd,name,**kwargs):
            value=original(fd,name,**kwargs)
            if name=='hostconfig.json':reached.append(name);self.peer.now=1090.
            return value
        with patch.object(policy,'read_file',side_effect=read):self.refused()
        self.assertEqual(reached,['hostconfig.json'])


if __name__=='__main__':unittest.main()
