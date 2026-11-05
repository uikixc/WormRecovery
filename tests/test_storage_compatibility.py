import base64
import copy
import json
import struct
import tempfile
from pathlib import Path
import types
import unittest
from unittest.mock import Mock,patch

import device_scope as ds
import powershell_output
import windows_storage
import worm_recovery as wr
from operation_capture import capture_preflight_failure


def volume(letter,number,bus='NVMe',kind=3):
    return {'letter':letter,'disks':[number] if number is not None else [],'drive_type':kind,
            'bus':bus,'removable':kind==2,'volume':'volume-'+letter,'issues':[]}


def disk(number,letters,bus='SCSI'):
    return {'number':number,'model':'fixture disk','pnp':'fixture-pnp-'+str(number),
            'serial':str(number),'bus':bus,'partitions':[{'letter':x,'volume':''} for x in letters]}


class StorageCompatibilityTests(unittest.TestCase):
    def fallback(self,primary,legacy,volumes,protection=None):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'device-protection.json'
            if protection:path.write_text(json.dumps(protection),encoding='utf-8')
            with patch.object(ds,'protection_path',return_value=path),patch.object(ds,'mounted_volumes',return_value=volumes):
                ps=Mock(side_effect=[primary,legacy])
                catalog=ds.DeviceCatalog.discover(ps)
        self.assertEqual(ps.call_count,2)
        return catalog

    def test_idv_disk_without_partition_does_not_abort_other_disks(self):
        primary={'devices':[disk(0,[]),disk(2,['C'])],'issues':[],'unmapped_roots':[]}
        with tempfile.TemporaryDirectory() as temp,patch.object(ds,'protection_path',return_value=Path(temp)/'none'),patch.object(ds,'mounted_volumes',return_value=[volume('C',2)]) as native:
            catalog=ds.DeviceCatalog.discover(Mock(return_value=primary))
        self.assertEqual(catalog.select()['roots'],['C:\\'])
        native.assert_called_once_with()
        self.assertEqual(catalog.select()['devices'][0]['partition_status'],'no_partitions')
        self.assertNotIn('Get-Partition -DiskNumber',ds.INVENTORY_SCRIPT)

    def test_msft_provider_failure_uses_native_mapping(self):
        c=self.fallback(RuntimeError('Get-Partition query failed'),{'devices':[disk(0,['C'])]},[volume('C',0)])
        result=c.select()
        self.assertEqual(result['roots'],['C:\\'])
        self.assertEqual(result['devices'][0]['discovery_source'],'native_volume_extents')
        self.assertEqual(result['discovery_issues'][0]['category'],'primary_inventory_failed')

    def test_empty_cim_volume_inventory_is_checked_against_native_volumes(self):
        c=self.fallback({'devices':[],'unmapped_roots':[]},{'devices':[disk(0,['C'])]},[volume('C',0)])
        self.assertEqual(c.select()['roots'],['C:\\'])

    def test_native_metadata_detects_usb_misclassified_by_provider(self):
        primary={'devices':[disk(3,['E','G'],'SCSI')],'unmapped_roots':[]}
        with tempfile.TemporaryDirectory() as temp,patch.object(ds,'protection_path',return_value=Path(temp)/'none'),patch.object(ds,'mounted_volumes',return_value=[volume('E',3,'USB'),volume('G',3,'USB')]):
            c=ds.DeviceCatalog.discover(Mock(return_value=primary))
        self.assertEqual(c.select()['roots'],[])
        self.assertEqual(set(c.select('removable')['roots']),{'E:\\','G:\\'})

    def test_inconsistent_provider_numbers_use_actual_volume_extents(self):
        primary={'devices':[disk(0,[])],'unmapped_roots':['C:']}
        c=self.fallback(primary,{'devices':[disk(7,['C'])]},[volume('C',7)])
        self.assertEqual(c.devices[0]['number'],7)
        self.assertEqual(c.select()['roots'],['C:\\'])

    def test_native_virtual_volume_without_partition_association(self):
        c=self.fallback(RuntimeError('fixture MSFT unavailable'),{'devices':[]},[volume('C',None,'Virtual')])
        self.assertEqual(c.select()['roots'],['C:\\'])
        self.assertEqual(c.select()['devices'][0]['discovery_source'],'native_virtual_volume')

    def test_legacy_association_supports_volume_without_extents(self):
        c=self.fallback(RuntimeError('fixture'),{'devices':[disk(1,['E','G'],'USB')]},
                        [volume('E',None,'USB',2),volume('G',None,'USB',2)])
        self.assertEqual(set(c.select('manual',['E:/documents'])['roots']),{'E:\\','G:\\'})
        self.assertEqual(c.select()['roots'],[])

    def test_external_fixed_type_and_all_usb_partitions_are_classified(self):
        c=self.fallback(RuntimeError('fixture'),{'devices':[disk(0,['C']),disk(3,['E','G'])]},
                        [volume('C',0),volume('E',3,'USB'),volume('G',3,'USB')])
        self.assertEqual(c.select()['roots'],['C:\\'])
        self.assertEqual(set(c.select('removable')['roots']),{'E:\\','G:\\'})
        self.assertEqual(c.select('removable')['external_volumes'],{'E:\\':'volume-E','G:\\':'volume-G'})

    def test_protected_usb_identifier_applies_to_all_partition_letters(self):
        usb=disk(3,['E','G'],'USB')
        c=self.fallback(RuntimeError('fixture'),{'devices':[usb]},[volume('E',3,'USB'),volume('G',3,'USB')],
                        {'identifiers':ds.identifiers(usb)})
        self.assertEqual(c.select('removable')['roots'],[])
        with self.assertRaises(PermissionError):c.select('manual',['E:/'])

    def test_modern_unique_protection_survives_native_fallback(self):
        modern=disk(3,[],'USB');modern['unique']='retained-modern-id'
        c=self.fallback({'devices':[modern],'unmapped_roots':['E:']},{'devices':[disk(3,[],'USB')]},
                        [volume('E',3,'USB')],{'identifiers':ds.identifiers(modern)[:1]})
        self.assertTrue(c.devices[0]['protected'])

    def test_protected_volume_identifies_device_when_cim_unavailable(self):
        c=self.fallback(RuntimeError('fixture'),RuntimeError('fixture CIM unavailable'),
                        [volume('E',3,'USB'),volume('G',3,'USB')],{'volumes':['volume-E']})
        self.assertEqual(c.select('removable')['roots'],[])
        self.assertEqual(len(c.select()['excluded_roots']),2)

    def test_unidentified_volume_is_reported_and_blocks_incomplete_scan(self):
        c=self.fallback(RuntimeError('fixture'),{'devices':[]},[volume('C',None,None)])
        with self.assertRaises(ds.DiscoveryError) as ctx:c.select()
        self.assertEqual(ctx.exception.details['unmapped_roots'],['C:'])
        self.assertEqual(ctx.exception.details['issues'][-1]['category'],'volume_mapping_unresolved')

    def test_native_failure_preserves_both_query_errors(self):
        with patch.object(ds,'mounted_volumes',side_effect=OSError('fixture native unavailable')):
            with self.assertRaises(ds.DiscoveryError) as ctx:
                ds.compatible_inventory(Mock(side_effect=RuntimeError('fixture legacy unavailable')),{},[{'category':'primary_failed'}])
        self.assertIn('fixture native unavailable',ctx.exception.details['native_error'])
        self.assertEqual(len(ctx.exception.details['issues']),2)

    def test_extent_parser_handles_multiple_disks_and_rejects_truncation(self):
        raw=struct.pack('<I4x',2)+struct.pack('<I4xqq',7,0,4096)+struct.pack('<I4xqq',9,0,4096)
        self.assertEqual(windows_storage.decode_extents(raw),[7,9])
        for invalid in (b'',raw[:-1],struct.pack('<I4x',1000),struct.pack('<I4x',0)):
            with self.assertRaises(ValueError):windows_storage.decode_extents(invalid)


class PowerShellOutputTests(unittest.TestCase):
    def test_progress_is_removed_and_only_error_stream_is_shown(self):
        raw='#< CLIXML\n<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress"><S>已完成 1/1</S></Obj><S S="Error">Get-Partition：没有分区_x000D__x000A_</S><S S="Error">磁盘 0</S></Objs>'
        self.assertEqual(powershell_output.error_text(raw.encode('utf-8')),'Get-Partition：没有分区\r\n磁盘 0')

    def test_plain_utf16_and_malformed_clixml(self):
        self.assertEqual(powershell_output.error_text('访问被拒绝'.encode('utf-16')),'访问被拒绝')
        self.assertNotIn('<Obj',powershell_output.error_text('#< CLIXML\n<Objs>invalid'))
        self.assertEqual(powershell_output.error_text('plain error'),'plain error')

    def test_powershell_suppresses_progress_and_decodes_error(self):
        result=types.SimpleNamespace(returncode=1,stderr=b'#< CLIXML\n<Objs><S S="Error">expected failure</S></Objs>',stdout=b'')
        with patch.object(wr.subprocess,'run',return_value=result) as run:
            with self.assertRaisesRegex(RuntimeError,'^expected failure$'):wr.powershell('Get-Disk')
        script=base64.b64decode(run.call_args.args[0][-1]).decode('utf-16le')
        self.assertIn("$ProgressPreference='SilentlyContinue'",script)


class PreflightCaptureTests(unittest.TestCase):
    def test_scope_failure_produces_independent_failed_scan_bundle(self):
        import diagnostic_bundle
        error=ds.DiscoveryError('fixture storage failure',{'unmapped_roots':['C:']})
        with tempfile.TemporaryDirectory() as temp,patch.dict('os.environ',{'LOCALAPPDATA':temp}),patch('diagnostic_client.collect') as collect,patch('diagnostic_client.schedule') as schedule:
            path=capture_preflight_failure(error,'1.7.6','internal')
            report=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(report['operation']['status'],'failed')
            self.assertFalse(report['operation']['mutations_allowed'])
            self.assertEqual(report['files'],0)
            self.assertEqual(report['errors'][0]['details']['unmapped_roots'],['C:'])
            self.assertTrue(path.with_name('journal.jsonl').is_file())
            collect.assert_called_once_with(path,upload=False);schedule.assert_called_once_with()
            bundle,_=diagnostic_bundle.build_bundle(path,state=Path(temp)/'state')
            self.assertEqual(bundle['operation']['stage'],'storage_discovery')
            self.assertEqual(bundle['summary']['errors'],1)

    def test_ui_and_cli_scope_entry_point_captures_original_failure(self):
        original=ds.DiscoveryError('fixture original failure',{})
        with patch.object(ds,'resolve_scope',side_effect=original),patch('operation_capture.capture_preflight_failure') as capture:
            with self.assertRaises(ds.DiscoveryError) as ctx:wr.resolve_scan_scope('internal')
        self.assertIs(ctx.exception,original)
        capture.assert_called_once_with(original,wr.VERSION,'internal',None)

    def test_reporting_failure_does_not_hide_discovery_failure(self):
        with patch.object(ds,'resolve_scope',side_effect=ValueError('fixture original failure')),patch('operation_capture.capture_preflight_failure',side_effect=OSError('fixture full disk')):
            with self.assertRaisesRegex(ValueError,'fixture original failure'):wr.resolve_scan_scope()


if __name__=='__main__':unittest.main(verbosity=2)
