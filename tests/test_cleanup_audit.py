"""Inert persistence and no-VBA regression cases; no real host cleanup."""
import base64
import json
import subprocess
import unittest
from unittest.mock import patch

from persistence_inventory import disable_task_script, disable_service_script, select_confirmed
from office_fixtures import compound, plain_workbook
from office_analysis import _legacy_bytes


class LegacyWithoutVbaTests(unittest.TestCase):
    def test_plain_workbook_retains_complete_structure(self):
        result=_legacy_bytes(compound({'Workbook':plain_workbook()}))
        self.assertEqual(result['status'],'clean')
        self.assertEqual(result['legacy_structure']['status'],'complete')
        self.assertFalse(result['active_content_unresolved'])

    def test_formula_unknown_and_truncated_workbooks_cannot_disappear(self):
        for data in (plain_workbook((0x0006,b'inert formula')),
                     plain_workbook((0x7777,b'inert unknown')),plain_workbook()[:-1]):
            with self.subTest(data=data):
                result=_legacy_bytes(compound({'Workbook':data}))
                self.assertFalse(result['macro'])
                self.assertEqual(result['status'],'review')
                self.assertTrue(result['active_content_unresolved'])
                self.assertIn('legacy_structure',result)


class PersistenceSnapshotTests(unittest.TestCase):
    def run_fixture(self, script, values, fixture):
        # Every system-facing command used by the generated scripts is a local
        # fixture function. No task, service or process on the host is changed.
        encoded=base64.b64encode(json.dumps(values).encode()).decode()
        source="$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'))|ConvertFrom-Json;\n"
        source+="$ops=[Collections.Generic.List[string]]::new();$failure=$null;\n"+fixture
        source+="\ntry {\n"+script+"\n}catch {$failure=$_.Exception.Message};@{operations=@($ops.ToArray());failure=$failure}|ConvertTo-Json -Compress"
        command=base64.b64encode(source.encode('utf-16le')).decode()
        completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',command],capture_output=True,timeout=15)
        self.assertEqual(completed.returncode,0,completed.stderr.decode(errors='replace'))
        return json.loads(completed.stdout.decode('utf-8-sig'))

    task_fixture="""
function Get-ScheduledTask { $fixture.task }
function Export-ScheduledTask {param($InputObject) $fixture.xml}
function Disable-ScheduledTask {param($InputObject,$ErrorAction) $ops.Add('disable-task')}
"""
    service_fixture="""
function Get-CimInstance {param($ClassName) $fixture.service}
function Invoke-CimMethod {param($InputObject,$MethodName,$Arguments,$ErrorAction)
  $ops.Add($MethodName);if($MethodName -eq 'Change'){@{ReturnValue=$fixture.change_result}}else{@{ReturnValue=$fixture.stop_result}}
}
"""

    def test_changed_task_definition_does_not_disable_replacement(self):
        task={'name':'Fixture[*]','path':'\\','xml':'<Task>old</Task>'}
        values={'task':{'TaskName':task['name'],'TaskPath':task['path']},'xml':'<Task>new</Task>'}
        result=self.run_fixture(disable_task_script(task),values,self.task_fixture)
        self.assertEqual(result['operations'],[])
        self.assertIn('definition changed',result['failure'])
        values['xml']=task['xml']
        result=self.run_fixture(disable_task_script(task),values,self.task_fixture)
        self.assertEqual(result['operations'],['disable-task'])
        self.assertIsNone(result['failure'])

    def test_service_configuration_change_prevents_mutation(self):
        expected={'Name':'Fixture[*]','PathName':'C:/inert/old.exe','StartName':'LocalSystem','ServiceType':'Own Process'}
        values={'service':{**expected,'PathName':'C:/inert/replacement.exe'},'change_result':0,'stop_result':0}
        result=self.run_fixture(disable_service_script(expected),values,self.service_fixture)
        self.assertEqual(result['operations'],[])
        self.assertIn('configuration changed',result['failure'])
        values['service']=expected
        result=self.run_fixture(disable_service_script(expected),values,self.service_fixture)
        self.assertEqual(result['operations'],['Change','StopService'])
        self.assertIsNone(result['failure'])

    def test_failed_service_disable_does_not_continue_and_is_reported(self):
        expected={'Name':'Fixture','PathName':'C:/inert/a.exe','StartName':'LocalSystem','ServiceType':'Own Process'}
        values={'service':expected,'change_result':2,'stop_result':0}
        result=self.run_fixture(disable_service_script(expected),values,self.service_fixture)
        self.assertEqual(result['operations'],['Change'])
        self.assertIn('disable failed',result['failure'])

    def test_multi_action_task_is_disabled_only_once(self):
        first={'name':'Fixture','path':'\\','xml':'<Task/>','execute':'first.exe'}
        second={**first,'execute':'second.exe'}
        result=select_confirmed({'tasks':[first,second]},lambda _:True)
        self.assertEqual(len(result['tasks']),1)
        with self.assertRaises(ValueError):
            select_confirmed({'tasks':[first,{**second,'xml':'<Task>changed</Task>'}]},lambda _:True)

    def test_missing_identity_is_rejected(self):
        for function in (disable_task_script,disable_service_script):
            with self.assertRaises(ValueError):function({})



from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock
import threading
import worm_recovery as recovery
from persistence_inventory import reconcile_snapshot
from test_family_analysis import inert_controller


def inert_cleaner():
    cleaner=recovery.Cleaner.__new__(recovery.Cleaner)
    cleaner.policy=SimpleNamespace(mutation=MagicMock(),check=MagicMock())
    cleaner.findings=[];cleaner.initial_findings=None;cleaner.events=[];cleaner.errors=[]
    cleaner.cancel=threading.Event();cleaner.inspection_failed=False;cleaner.protected=[]
    cleaner.scan_roots=['C:/inert'];cleaner.skipped=[];cleaner.force_close=True
    cleaner.log=lambda kind,**values:cleaner.events.append({'kind':kind,**values})
    cleaner.error=lambda path,ex:cleaner.errors.append({'path':str(path),'error':str(ex)})
    cleaner.emit=MagicMock();cleaner.save=MagicMock();cleaner.security_settings=MagicMock()
    cleaner.registry=MagicMock(return_value=[]);cleaner.system_persistence=MagicMock(return_value={})
    cleaner.firewall=MagicMock(return_value=[]);cleaner.contain=MagicMock(return_value=[])
    cleaner.close_locks=MagicMock();cleaner.scan=MagicMock(return_value=[])
    cleaner.quarantine_file=MagicMock();cleaner.replace=MagicMock()
    return cleaner


class RepairBoundaryTests(unittest.TestCase):
    def test_all_old_findings_revalidate_before_any_lock_release(self):
        kinds=('infected_office','infected_executable','worm_payload','worm_hook','worm_runtime',
               'worm_script','worm_residue','malicious_shortcut')
        with TemporaryDirectory() as directory:
            path=Path(directory)/'replacement.bin';path.write_bytes(b'innocent replacement bytes')
            for kind in kinds:
                with self.subTest(kind=kind):
                    c=inert_cleaner();c.findings=[{'kind':kind,'path':str(path)}]
                    c.repair()
                    c.close_locks.assert_not_called();c.quarantine_file.assert_not_called()
                    self.assertTrue(c.errors)
                    self.assertEqual(path.read_bytes(),b'innocent replacement bytes')

    def test_payload_named_infected_host_always_uses_restore_path(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/'._cache_host.exe';path.write_bytes(b'inert host')
            c=inert_cleaner();c.findings=[{'kind':'infected_executable','path':str(path)}]
            c.revalidate_finding=MagicMock(return_value='fixture hash');c.restore_executable=MagicMock()
            actions=[]
            c.registry.side_effect=lambda apply:actions.append(('registry',apply)) or []
            c.system_persistence.side_effect=lambda apply:actions.append(('system',apply)) or {}
            c.contain.side_effect=lambda apply:actions.append(('contain',apply)) or []
            c.repair()
            c.restore_executable.assert_called_once_with(path,expected='fixture hash')
            c.quarantine_file.assert_not_called();c.close_locks.assert_not_called()
            self.assertLess(actions.index(('system',True)),actions.index(('contain',True)))
            self.assertEqual(actions.count(('contain',True)),2)

    def test_zero_recoverable_layers_preserves_original_and_never_replaces_itself(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/'host.exe';path.write_bytes(b'inert unparseable wrapper')
            c=inert_cleaner()
            with patch.object(recovery,'is_stub',return_value=False),self.assertRaises(ValueError):
                c.restore_executable(path)
            c.replace.assert_not_called();c.close_locks.assert_not_called()
            self.assertEqual(path.read_bytes(),b'inert unparseable wrapper')
            self.assertEqual(list(Path(directory).glob('.wormrepair-*')),[])

    def test_extracted_miner_is_retained_in_wrapper_and_never_committed(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/'host.exe';path.write_bytes(b'inert wrapper')
            class Resource:
                def __init__(self,*args):pass
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def resource(self,name):return (0,2048)
                def extract_resource(self,resource,destination):destination.write_bytes(inert_controller())
            c=inert_cleaner()
            with patch.object(recovery,'is_stub',side_effect=lambda p:Path(p)==path),patch.object(recovery,'PEView',Resource):
                with self.assertRaisesRegex(ValueError,'已知恶意代码'):c.restore_executable(path)
            c.replace.assert_not_called();c.close_locks.assert_not_called()
            self.assertEqual(path.read_bytes(),b'inert wrapper')
            self.assertEqual(list(Path(directory).glob('.wormrepair-*')),[])

    def test_backup_of_changed_file_does_not_release_app_locks(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/'file.bin';path.write_bytes(b'inert replacement')
            c=inert_cleaner();c.backup=MagicMock(return_value=('changed',Path(directory)/'backup',path.stat()))
            with self.assertRaises(RuntimeError):
                recovery.Cleaner.quarantine_file(c,path,'fixture',expected='scanned')
            c.close_locks.assert_not_called();self.assertTrue(path.exists())

    def test_size_limited_programs_and_scripts_are_review_and_counted(self):
        from family_analysis import MAX_INPUT,MAX_CARRIER
        with TemporaryDirectory() as directory:
            for name,size,kind in (('fixture.exe',MAX_INPUT+1,'review_binary'),('fixture.ps1',MAX_CARRIER+1,'review_script')):
                path=Path(directory)/name
                with path.open('wb') as stream:stream.write(b'inert');stream.seek(size-1);stream.write(b'!')
                result=recovery.inspect_file_content(path,path.stat())
                self.assertEqual(result['engine_checks']['family_size_limited'],1)
                self.assertIn(kind,{row['kind'] for row in result['findings']})
        c=inert_cleaner();c.engine_checks={'family_size_limited':1}
        result=c.verify();self.assertFalse(result['known_family_clear']);self.assertEqual(result['size_limited_files'],1)

    def test_regenerated_runtime_requires_verified_quarantine_companion_bytes(self):
        import hashlib
        with TemporaryDirectory() as directory:
            root=Path(directory);runtime=root/'fixture.exe';runtime.write_bytes(b'inert runtime')
            c=inert_cleaner();c.quarantine=root/'quarantine';c.quarantine.mkdir()
            expected=hashlib.sha256(runtime.read_bytes()).hexdigest();peers=[];analyses={}
            for suffix,signature in (('.dat','WR_Encrypted_Project_Loader'),('.png','WR_Miner_Controller_Code')):
                missing=runtime.with_suffix(suffix);data=('inert companion '+suffix).encode()
                sha=hashlib.sha256(data).hexdigest();backup=c.quarantine/(suffix[1:]+'.backup');backup.write_bytes(data)
                c.events.append({'kind':'quarantined','path':str(missing),'sha256':sha,'backup':str(backup)})
                peers.append({'path':str(missing),'sha256':sha})
                analyses[data]={'status':'detected','detections':[{'signature':signature}],
                                'decodings':[{'method':'png_prefix64_rc4'}] if suffix=='.png' else []}
            c.initial_findings=[{'kind':'malware_deployment','path':str(runtime),'sha256':expected,'related_evidence':peers}]
            c.family_observations=[{'path':str(runtime),'sha256':expected,'role':'observed_trueupdate_runtime'}]
            with patch('family_analysis.KNOWN_RUNTIME',expected),patch('family_analysis.inspect',side_effect=lambda data:analyses[data]):
                c.recheck_deployment_observations()
                self.assertEqual(len(c.findings),1)
                self.assertEqual(c.findings[0]['kind'],'malware_deployment')
                c.findings=[];backup.write_bytes(b'tampered backup')
                c.recheck_deployment_observations()
                self.assertEqual([row['kind'] for row in c.findings],['review_binary'])


class ProcessIdentityTests(unittest.TestCase):
    def process(self,created=10):
        p=MagicMock();p.pid=123456;p.create_time.return_value=created;p.exe.return_value='C:/inert/fixture.exe'
        p.name.return_value='fixture.exe';p.is_running.return_value=True
        return p

    def test_pid_reuse_and_image_changes_never_kill_replacement(self):
        for created,exe in ((9,'C:/inert/fixture.exe'),(10,'C:/inert/other.exe')):
            c=inert_cleaner();p=self.process()
            with patch.object(recovery.psutil,'Process') as reopen,self.assertRaises(PermissionError):
                c.stop_pid(p.pid,'inert fixture',process=p,expected_created=created,expected_exe=exe)
            reopen.assert_not_called();p.kill.assert_not_called()

    def test_same_observed_process_object_is_used_for_termination(self):
        c=inert_cleaner();p=self.process()
        with patch.object(recovery.psutil,'Process') as reopen:
            c.stop_pid(p.pid,'inert fixture',process=p,expected_created=10,expected_exe=p.exe())
        reopen.assert_not_called();p.kill.assert_called_once();p.wait.assert_called_once_with(10)

    def test_restart_manager_creation_time_protects_reused_pid(self):
        c=inert_cleaner();p=self.process(created=20)
        with patch.object(recovery,'lock_holders',return_value=[{'pid':p.pid,'created':10}]),patch.object(recovery.psutil,'Process',return_value=p):
            with self.assertRaises(PermissionError):recovery.Cleaner.close_locks(c,'C:/inert/file')
        p.kill.assert_not_called()


class PersistenceVerificationTests(unittest.TestCase):
    def inventory(self):
        task={'name':'Fixture','path':'\\','execute':'C:/inert/missing.exe','arguments':'/fixture',
              'xml':'<Task><Actions><Exec>fixture</Exec></Actions><Settings><Enabled>true</Enabled></Settings></Task>'}
        service={'Name':'Fixture','PathName':'C:/inert/missing.exe','StartName':'LocalSystem',
                 'ServiceType':'Own Process','StartMode':'Auto','State':'Running'}
        return {'tasks':[task],'services':[service],'wmi':[]}

    def test_missing_payload_does_not_hide_surviving_persistence(self):
        inventory=self.inventory();snapshot=select_confirmed(inventory,lambda command:True)
        c=inert_cleaner();c.persistence_snapshot=snapshot;c.confirmed_command=MagicMock(return_value=False)
        with patch.object(recovery,'powershell',return_value=inventory):
            c.system_persistence=lambda apply:recovery.Cleaner.system_persistence(c,apply)
            result=c.verify()
        self.assertFalse(result['known_family_clear'])
        self.assertEqual(len(result['active_tasks']),1);self.assertEqual(len(result['active_services']),1)
        self.assertEqual(result['active_tasks'][0]['confirmation_basis'],'exact_pre_repair_snapshot')

    def test_disabled_entries_are_visible_separately_and_changed_xml_blocks_pass(self):
        inventory=self.inventory();snapshot=select_confirmed(inventory,lambda command:True)
        inventory['tasks'][0]['xml']=inventory['tasks'][0]['xml'].replace('true','false')
        inventory['services'][0].update(StartMode='Disabled',State='Stopped')
        c=inert_cleaner();c.persistence_snapshot=snapshot;c.confirmed_command=MagicMock(return_value=False)
        with patch.object(recovery,'powershell',return_value=inventory):
            c.system_persistence=lambda apply:recovery.Cleaner.system_persistence(c,apply)
            result=c.verify()
            self.assertTrue(result['known_family_clear'])
            self.assertEqual(len(result['disabled_tasks']),1);self.assertEqual(len(result['disabled_services']),1)
            inventory['tasks'][0]['xml']=inventory['tasks'][0]['xml'].replace('fixture','replacement')
            result=c.verify()
        self.assertFalse(result['known_family_clear']);self.assertTrue(result['persistence_changes'])

    def test_surviving_registry_command_is_reported_after_payload_disappears(self):
        c=inert_cleaner();key=MagicMock();key.__enter__.return_value=key
        sub=recovery.registry_paths()[0];value='C:/inert/missing.exe'
        c.registry_snapshot=[{'hive':'HKLM','key':sub,'view':recovery.winreg.KEY_WOW64_64KEY,
                              'name':'Fixture','value':value,'type':recovery.winreg.REG_SZ,'confirmed':True}]
        c.confirmed_command=MagicMock(return_value=False)
        def enum_value(key,index):
            if index:raise OSError('end')
            return 'Fixture',value,recovery.winreg.REG_SZ
        with patch.object(recovery.winreg,'EnumKey',side_effect=OSError('end')),patch.object(recovery,'registry_paths',return_value=(sub,)),             patch.object(recovery.winreg,'OpenKey',return_value=key),patch.object(recovery.winreg,'EnumValue',side_effect=enum_value):
            result=recovery.Cleaner.registry(c,False)
        self.assertEqual(len(result),1);self.assertEqual(result[0]['snapshot_status'],'exact')

    def test_main_uses_bound_task_and_service_mutation_scripts(self):
        inventory=self.inventory();c=inert_cleaner();c.confirmed_command=MagicMock(return_value=True)
        def powershell(script):return inventory if script==recovery.INVENTORY_SCRIPT else None
        with patch.object(recovery,'powershell',side_effect=powershell) as calls:
            recovery.Cleaner.system_persistence(c,True)
        scripts=[call.args[0] for call in calls.call_args_list]
        self.assertTrue(any('Scheduled task definition changed' in script for script in scripts))
        self.assertTrue(any('Service configuration changed' in script for script in scripts))
        self.assertFalse(any('Stop-Service' in script or '-Force' in script for script in scripts))




class CarrierGateAndRuntimeTests(unittest.TestCase):
    def test_ordinary_large_png_and_zip_do_not_become_family_reviews(self):
        import struct,zlib,zipfile
        from family_analysis import MAX_CARRIER
        def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
        with TemporaryDirectory() as directory:
            root=Path(directory);image=root/'ordinary.png';archive=root/'ordinary.zip'
            image.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))+
                chunk(b'tEXt',b'Comment\0'+b'A'*MAX_CARRIER)+chunk(b'IDAT',zlib.compress(b'\0\0\0\0'))+chunk(b'IEND',b''))
            with zipfile.ZipFile(archive,'w') as z:z.writestr('ordinary.txt',b'Z'*(MAX_CARRIER+1))
            for path in (image,archive):
                result=recovery.inspect_file_content(path,path.stat())
                self.assertEqual(result['findings'],[])
                self.assertNotIn('family_size_limited',result['engine_checks'])

    def test_identified_png_and_encrypted_project_still_report_decode_limit(self):
        import struct,zipfile
        from family_analysis import MAX_CARRIER,PNG_KEY,rc4
        from test_family_analysis import inert_pe
        with TemporaryDirectory() as directory:
            root=Path(directory);image=root/'candidate.png';archive=root/'candidate.dat'
            prefix=inert_pe(b'inert header')[:64]
            image.write_bytes(b'\x89PNG\r\n\x1a\n'+b'\0'*56+rc4(prefix,PNG_KEY)+b'X'*MAX_CARRIER)
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as z:
                z.writestr('_TUProj.dat',b'inert encrypted placeholder'+b'Z'*MAX_CARRIER)
            data=bytearray(archive.read_bytes());central=data.index(b'PK\x01\x02')
            struct.pack_into('<H',data,6,1);struct.pack_into('<H',data,central+8,1);archive.write_bytes(data)
            for path in (image,archive):
                result=recovery.inspect_file_content(path,path.stat())
                self.assertEqual([r['kind'] for r in result['findings']],['review_binary'])
                self.assertEqual(result['engine_checks']['family_size_limited'],1)

    def test_encrypted_project_directory_allows_observed_trailing_padding(self):
        import io,struct,zipfile
        from carrier_probe import zip_directory
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as z:z.writestr('_TUProj.dat',b'inert encrypted fixture')
        data=bytearray(output.getvalue());central=data.index(b'PK\x01\x02')
        struct.pack_into('<H',data,6,1);struct.pack_into('<H',data,central+8,1)
        data.extend(b'\0'*15)
        result=zip_directory(io.BytesIO(data),len(data))
        self.assertEqual(result['status'],'complete');self.assertTrue(result['encrypted_project'])

    def test_unbounded_zip_directory_is_not_allocated_or_called_family(self):
        import io,struct
        from carrier_probe import zip_directory,MAX_DIRECTORY
        data=b'PK\x03\x04'+struct.pack('<4sHHHHIIH',b'PK\x05\x06',0,0,1,1,MAX_DIRECTORY+1,0,0)
        with patch('carrier_probe.zipfile.ZipFile',side_effect=AssertionError('directory allocation forbidden')):
            self.assertEqual(zip_directory(io.BytesIO(data),len(data))['status'],'limited')

    def test_runtime_name_never_authorizes_quarantine_without_paired_script(self):
        import hashlib
        data=b'inert runtime'+b'\0'*(750320-len(b'inert runtime'));pin=hashlib.sha256(data).hexdigest()
        script=b'inert known-script fixture';script_pin=hashlib.sha256(script).hexdigest()
        with TemporaryDirectory() as directory,patch.object(recovery,'AUTOIT_EXE_SHA256',pin),patch.object(recovery,'AUTOIT_A3X_SHA256',script_pin):
            root=Path(directory)
            for name in ('AutoIt.exe','._cache_AutoIt.exe'):
                path=root/name;path.write_bytes(data)
                result=recovery.inspect_file_content(path,path.stat())
                self.assertEqual(result['findings'],[])
            (root/'unrelated.a3x').write_bytes(script)
            result=recovery.inspect_file_content(path,path.stat());self.assertEqual(result['findings'],[])
            (root/'AutoIt.a3x').write_bytes(script)
            result=recovery.inspect_file_content(path,path.stat())
            self.assertEqual([r['kind'] for r in result['findings']],['worm_runtime'])
            c=inert_cleaner();c.quarantine=root/'quarantine';c.quarantine.mkdir()
            record=result['findings'][0];backup=c.quarantine/'script.backup';backup.write_bytes(script)
            (root/'AutoIt.a3x').unlink()
            c.events.append({'kind':'quarantined','path':str(root/'AutoIt.a3x'),'sha256':script_pin,'backup':str(backup)})
            self.assertTrue(c.confirmed_autoit_runtime(record))
            backup.write_bytes(b'changed');self.assertFalse(c.confirmed_autoit_runtime(record))


class StructuralRepairXmlTests(unittest.TestCase):
    def parts(self):
        from test_office_package import OfficePackageTests
        fixture=OfficePackageTests('test_sanitizer_preserves_worksheet_formulas_and_styles')
        fixture.setUp()
        try:return dict(fixture.parts)
        finally:fixture.tearDown();fixture.doCleanups()

    def sanitize(self,root,parts):
        import zipfile
        source=root/'source.xlsm';dest=root/'restored.xlsx'
        with zipfile.ZipFile(source,'w') as z:
            for name,value in parts.items():z.writestr(name,value)
        recovery.sanitized_xlsx(source,dest)
        return zipfile.ZipFile(dest)

    def test_single_quotes_and_prefixed_elements_remove_all_macro_references(self):
        from xml.etree import ElementTree as ET
        with TemporaryDirectory() as directory:
            root=Path(directory);parts=self.parts()
            for name in ('[Content_Types].xml','xl/_rels/workbook.xml.rels','xl/workbook.xml'):
                parts[name]=parts[name].replace(b'"',b"'")
            parts['xl/_rels/workbook.xml.rels']=parts['xl/_rels/workbook.xml.rels'].replace(b'<Relationships xmlns=',b'<p:Relationships xmlns:p=').replace(b'</Relationships>',b'</p:Relationships>').replace(b'<Relationship ',b'<p:Relationship ')
            with self.sanitize(root,parts) as z:
                for name in ('[Content_Types].xml','xl/_rels/workbook.xml.rels'):
                    self.assertNotIn(b'vbaProject',z.read(name));ET.fromstring(z.read(name))
                self.assertEqual(z.read('xl/worksheets/sheet1.xml'),parts['xl/worksheets/sheet1.xml'])

    def test_qname_attribute_namespace_bindings_survive_structural_edits(self):
        import io
        from xml.etree import ElementTree as ET
        parts=self.parts();parts['xl/workbook.xml']=parts['xl/workbook.xml'].replace(b'<workbook ',
            b'<workbook xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" mc:Ignorable="x14ac" ')
        with TemporaryDirectory() as directory:
            with self.sanitize(Path(directory),parts) as z:
                data=z.read('xl/workbook.xml');names=dict(value for event,value in ET.iterparse(io.BytesIO(data),events=('start-ns',)))
                self.assertEqual(names['x14ac'],'http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac')
                self.assertIn(b'Ignorable="x14ac"',data)

    def test_dangling_nonmacro_target_prevents_recovery_success(self):
        parts=self.parts();parts['xl/_rels/workbook.xml.rels']=parts['xl/_rels/workbook.xml.rels'].replace(b'worksheets/sheet1.xml',b'worksheets/missing.xml')
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'缺失的关系目标'):self.sanitize(Path(directory),parts)


if __name__=='__main__':unittest.main()
