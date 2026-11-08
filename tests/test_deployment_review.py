"""Observed deployment handling with inert bytes; never load a specimen."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import deployment_review as deployment
import family_analysis as family
import png_tail_analysis as tail
import worm_recovery as recovery
from test_cleanup_audit import inert_cleaner
from test_family_analysis import inert_pe
from test_png_tail_analysis import carrier,dll


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.loader=dll(b'INERT observed DLL'+bytes(10))
        self.image=dll(b'INERT packed companion')
        self.host=inert_pe(b'INERT signed host fixture')
        patches=[patch.object(tail,'LOADER_BYTES',len(self.loader)),
                 patch.object(tail,'LOADER_PREFIX_SHA256',hashlib.sha256(self.loader[:-4]).hexdigest()),
                 patch.object(tail,'HOST_BYTES',len(self.host)),
                 patch.object(tail,'HOST_SHA256',hashlib.sha256(self.host).hexdigest()),
                 patch.object(tail,'KNOWN_PAYLOADS',{hashlib.sha256(self.image).hexdigest():{
                     'bytes':len(self.image),'confirmed':False,'signature':'WR_PNG_Tail_Packed_Companion',
                     'family':'INERT companion','basis':'inert_fixture'}})]
        for p in patches:p.start();self.addCleanup(p.stop)
        self.paths=[]
        for name,data in [('XPSPLOG.dll',self.loader),('renamed.data',carrier(self.image)),('random.exe',self.host)]:
            path=self.root/name;path.write_bytes(data);self.paths.append(path)
        self.unrelated=self.root/'ordinary.txt';self.unrelated.write_bytes(b'INERT unrelated document')

    def discover(self):
        rows=[];observations=[]
        for path in self.paths:
            if not path.exists():continue
            result=recovery.inspect_file_content(path,path.stat())
            rows.extend(result['findings']);observations.extend(result.get('family_observations',[]))
        return deployment.correlate(rows,observations)

    def cleaner(self):
        c=inert_cleaner();c.findings=self.discover()
        c.approved_deployment_groups=set(deployment.groups(c.findings))
        return c

    def test_all_three_members_visible_but_not_false_malicious_code_proof(self):
        rows=self.discover();self.assertEqual(len(rows),3)
        self.assertEqual({row['deployment_role'] for row in rows},{'observed_loader','packed_carrier','signed_host'})
        self.assertTrue(all(not recovery.is_confirmed(row) for row in rows))
        self.assertEqual(len(deployment.groups(rows)),1)
        self.assertNotIn(str(self.unrelated),{row['path'] for row in rows})

    def test_host_alone_and_host_with_generic_same_named_dll_not_reported(self):
        self.paths[1].unlink();self.assertEqual(self.discover(),[])
        self.paths[0].write_bytes(dll(b'INERT ordinary DLL'))
        self.assertEqual(self.discover(),[])
        self.assertEqual(recovery.inspect_file_content(self.paths[2],self.paths[2].stat())['findings'],[])

    def test_renamed_loader_groups_by_content_but_does_not_implicate_host(self):
        renamed=self.root/'renamed.bin';self.paths[0].rename(renamed);self.paths[0]=renamed
        rows=self.discover();self.assertEqual(len(rows),2)
        self.assertNotIn('signed_host',{row['deployment_role'] for row in rows})

    def test_changed_companion_and_cross_directory_cannot_form_group(self):
        self.paths[1].write_bytes(carrier(self.image[:-1]+b'!'));self.assertEqual(self.discover(),[])
        self.paths[1].write_bytes(carrier(self.image))
        folder=self.root/'separate';folder.mkdir()
        renamed=folder/'image.data';self.paths[1].rename(renamed);self.paths[1]=renamed
        self.assertEqual(self.discover(),[])

    def test_trailer_and_carrier_encoding_changes_preserve_group_detection(self):
        self.paths[0].write_bytes(self.loader[:-4]+b'ABCD')
        self.paths[1].write_bytes(carrier(self.image,255,b'different metadata'))
        self.assertEqual(len(self.discover()),3)

    def test_no_explicit_group_approval_never_calls_remove_or_releases_locks(self):
        c=self.cleaner();c.approved_deployment_groups=set();c.repair_reviewed_deployments()
        c.remove_confirmed_file.assert_not_called();c.close_locks.assert_not_called()

    def test_changed_missing_protected_or_hardlinked_member_blocks_entire_group(self):
        for boundary in ('changed','missing','protected','hardlink','reparse'):
            with self.subTest(boundary=boundary):
                c=self.cleaner();path=self.paths[0];original=path.read_bytes()
                if boundary=='changed':path.write_bytes(b'INERT replacement')
                if boundary=='missing':path.unlink()
                if boundary=='protected':c.protected=[path]
                stat=path.stat() if path.exists() else None
                try:
                    with patch.object(recovery,'file_attributes',return_value=0x400 if boundary=='reparse' else 0):
                        if boundary=='hardlink':
                            import os
                            link=self.root/'inert-link';os.link(path,link)
                        c.repair_reviewed_deployments()
                    c.remove_confirmed_file.assert_not_called();c.close_locks.assert_not_called();self.assertEqual(len(c.errors),1)
                finally:
                    if boundary=='hardlink':link.unlink()
                    path.write_bytes(original)

    def test_approved_group_removes_exact_members_only_with_no_backup(self):
        c=self.cleaner()
        def remove(path,reason,expected=None,deployment_group=None):
            self.assertEqual(recovery.digest_file(path),expected)
            Path(path).unlink();c.events.append({'kind':'removed','path':str(path),'sha256':expected,
                'deployment_group':deployment_group,'backup_created':False})
        c.remove_confirmed_file.side_effect=remove;c.repair_reviewed_deployments()
        self.assertEqual(c.errors,[]);self.assertEqual(c.remove_confirmed_file.call_count,3)
        self.assertTrue(self.unrelated.exists());self.assertFalse(any(path.exists() for path in self.paths))
        self.assertFalse((self.root/'quarantine').exists())

    def test_mid_group_failure_is_visible_and_retry_requires_same_session_evidence(self):
        c=self.cleaner();original=list(c.findings);calls=[]
        def remove(path,reason,expected=None,deployment_group=None):
            if calls:raise OSError('INERT locked fixture')
            Path(path).unlink();calls.append(path)
            c.events.append({'kind':'removed','path':str(path),'sha256':expected,'deployment_group':deployment_group})
        c.remove_confirmed_file.side_effect=remove;c.repair_reviewed_deployments()
        self.assertEqual(len(c.errors),1);self.assertEqual(len(calls),1)
        c.initial_findings=original;c.findings=[]
        for path in self.paths:
            if path.exists():c.findings.extend(recovery.inspect_file_content(path,path.stat())['findings'])
        c.review_deployment_groups()
        self.assertEqual(len(c.findings),2);self.assertTrue(all(row.get('partial_deployment') for row in c.findings))
        c.remove_confirmed_file.reset_mock();c.remove_confirmed_file.side_effect=None
        c.repair_reviewed_deployments();self.assertEqual(c.remove_confirmed_file.call_count,2)
        c.remove_confirmed_file.reset_mock();c.events=[];c.repair_reviewed_deployments()
        c.remove_confirmed_file.assert_not_called()

    def test_secondary_engines_are_not_started_for_already_grouped_content(self):
        import secondary_analysis
        c=self.cleaner()
        with patch('engine_assets.prepare_optional_engines',side_effect=AssertionError('no engine wait')):
            secondary_analysis.enrich_reviews(c)
        self.assertEqual(c.secondary_dispatch['candidates'],0)

    def test_scan_forms_group_before_optional_engine_dispatch(self):
        c=recovery.Cleaner(report_dir=self.root/'reports',emit=lambda _:None)
        c.secondary_enabled=True
        def check_group(cleaner):
            self.assertEqual(len(deployment.groups(cleaner.findings)),1)
            self.assertEqual(len(cleaner.findings),3)
            self.assertTrue(all(row['kind']=='review_deployment' for row in cleaner.findings))
        with patch('secondary_analysis.enrich_reviews',side_effect=check_group) as dispatch:
            c.scan([str(self.root)],workers=1)
        dispatch.assert_called_once_with(c)
        self.assertEqual(c.errors,[])

    def test_stopped_scan_correlates_completed_files_without_engine_wait(self):
        c=recovery.Cleaner(report_dir=self.root/'reports',emit=lambda _:None)
        original=c.record_file_result
        def record(path,result):
            original(path,result)
            if c.count==4:c.cancel.set()
        with patch.object(c,'record_file_result',side_effect=record), \
             patch('secondary_analysis.enrich_reviews',side_effect=AssertionError('stopped scan cannot start engines')):
            c.scan([str(self.root)],workers=1)
        self.assertTrue(c.cancel.is_set())
        self.assertEqual(c.count,4)
        self.assertEqual(len(deployment.groups(c.findings)),1)
        self.assertEqual(len(c.findings),3)

    def test_group_discovery_is_idempotent(self):
        c=self.cleaner();c.initial_findings=list(c.findings)
        c.review_deployment_groups();c.review_deployment_groups()
        self.assertEqual(len(c.findings),3)

    def test_real_inert_group_delete_records_group_and_no_backup(self):
        c=self.cleaner()
        c.remove_confirmed_file=lambda *args,**kwargs:recovery.Cleaner.remove_confirmed_file(c,*args,**kwargs)
        c.repair_reviewed_deployments()
        self.assertEqual(c.errors,[])
        removed=[event for event in c.events if event['kind']=='removed']
        self.assertEqual(len(removed),3)
        self.assertTrue(all(event['deployment_group'] in c.approved_deployment_groups for event in removed))
        self.assertTrue(all(event['backup_created'] is False for event in removed))
        self.assertEqual([p.name for p in self.root.iterdir()],['ordinary.txt'])

    def test_group_survives_post_scan_without_claiming_clean_verification(self):
        c=self.cleaner();c.initial_findings=list(c.findings);c.approved_deployment_groups=set()
        c.scan.return_value=c.findings
        c.repair_reviewed_deployments();result=c.verify()
        self.assertFalse(result['known_family_clear'])
        self.assertEqual(len(result['unresolved_deployment_groups']),1)
        self.assertEqual(result['review_count'],3)

    def test_stopped_verification_keeps_unresolved_group_visible(self):
        c=self.cleaner();c.cancel.set()
        result=c.verify()
        c.scan.assert_not_called()
        self.assertFalse(result['known_family_clear'])
        self.assertEqual(len(result['unresolved_deployment_groups']),1)


if __name__=='__main__':unittest.main()
