import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

from document_formats import inspect_plain_document
from document_verdict import assess_document
from office_triage import decide_after_engines
from vba_inventory import source_inventory,inspect_legacy_workbook
from office_fixtures import compound,vba_streams,plain_workbook


def row():
    return {'kind':'review_office','path':'C:/documents/test.xlsm','macro':False,
        'secondary_analysis':{'status':'no_known_match','clamav':{'status':'no_match'},
                              'office_parser':{'status':'analyzed'},'yara_x':{'matches':[]}}}


class DocumentContentTests(unittest.TestCase):
    def test_text_content_recognized_independently_of_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'unrelated.doc'
            for content in (b'Python debugger help\r\nUse <stdin> to read input.',
                            '普通文本正文'.encode('utf-16')):
                path.write_bytes(content);result=inspect_plain_document(path)
                self.assertTrue(result['passive_text_verified'])
                self.assertEqual(result['format_sha256'],hashlib.sha256(content).hexdigest())
                self.assertEqual(path.read_bytes(),content)

    def test_active_formats_binary_and_partial_text_never_cleared(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'pdb.doc'
            for content in (b'<html>text</html>',b'<html\n><script\n>unknown',b'<script',b'<?xml version="1.0"?><root/>',b'{\\rtf1 text}',
                b'MIME-Version: 1.0\r\n',b'ID;P\r\n',b'text\x00binary',b'\xffinvalid',b'   '):
                with self.subTest(content=content):path.write_bytes(content);self.assertIsNone(inspect_plain_document(path))
            path=path.with_suffix('.docx');path.write_bytes(b'ordinary text')
            self.assertIsNone(inspect_plain_document(path))

    def test_text_verdict_requires_matching_snapshot_hash_and_all_checks(self):
        candidate=row();candidate.update(passive_text_verified=True,format_sha256='a'*64,analysis_sha256='a'*64)
        self.assertEqual(assess_document(candidate)['rule'],'passive_text_document')
        for field,value in (('format_sha256','b'*64),('macro',True),('analysis_error',True),
                            ('structural_evidence',[{'kind':'dde_field'}])):
            changed=copy.deepcopy(candidate);changed[field]=value
            self.assertNotEqual(assess_document(changed)['classification'],'informational')

    def test_empty_file_is_data_loss_and_does_not_claim_recovery(self):
        candidate=row();candidate.update(document_format='empty',analysis_sha256=hashlib.sha256(b'').hexdigest(),
                                        data_integrity_issue='empty_document')
        candidate['secondary_analysis']['clamav']['status']='no_content'
        decide_after_engines(candidate)
        self.assertEqual(candidate['assessment'],'empty_document_data_loss')
        self.assertIn('历史原件',candidate['action']);self.assertIn('正文缺失',candidate['reason'])
        self.assertNotIn('无需删除',candidate['action'])

    def test_empty_label_cannot_override_nonempty_hash_or_detection(self):
        candidate=row();candidate.update(document_format='empty',analysis_sha256='a'*64)
        self.assertNotEqual(assess_document(candidate)['classification'],'informational')
        candidate['analysis_sha256']=hashlib.sha256(b'').hexdigest()
        candidate['secondary_analysis']['clamav']['status']='detected'
        self.assertEqual(assess_document(candidate)['classification'],'detected')
        candidate['secondary_analysis']['clamav']['status']='no_content'
        candidate['structural_evidence']=[{'kind':'dde_field'}]
        self.assertNotEqual(assess_document(candidate)['classification'],'informational')

    def test_cid_is_typed_image_only_with_complete_checks(self):
        for relation,target,positive in [('image','cid:image008.jpg@01D39F44.F2250020',True),
            ('image','cid:x.png.exe@id',False),('attachedtemplate','cid:x.jpg@id',False),
            ('image','cid:x.jpg@id%0A',False),('image','cid:../x.jpg@id',False),
            ('image','cid:x.jpg@id?cmd=run',False),('image','cid:x.jpg@id\n',False)]:
            with self.subTest(target=target):
                candidate=row();candidate['structural_evidence']=[{'kind':'external_relationship','relationship_type':relation,'target':target}]
                self.assertEqual(assess_document(candidate)['classification']=='informational',positive)
                candidate['analysis_error']=True
                self.assertNotEqual(assess_document(candidate)['classification'],'informational')


class VbaInventoryTests(unittest.TestCase):
    def test_source_only_empty_bodies_are_positive_but_unsupported_code_is_not(self):
        self.assertTrue(source_inventory('Attribute VB_Name = "M"\nOption Explicit\nPrivate Sub Workbook_Open()\nEnd Sub')['empty_bodies_verified'])
        for source in ('Sub A(): Debug.Print "fixture": End Sub','Sub A()\nDebug.Print "fixture"\nEnd Sub',
                       'Sub A()','End Sub','#If VBA7 Then\n#End If','Dim handler As New Object',
                       'Private Declare Sub Example Lib "unknown" ()','Sub A(x = Other())\nEnd Sub',
                       'Attribute VB_Name = "unterminated','Sub A()\nFunction B()\nEnd Function\nEnd Sub'):
            with self.subTest(source=source):self.assertFalse(source_inventory(source)['empty_bodies_verified'])

    def inspect(self,streams):
        import contextlib,io
        from office_analysis import inspect_project
        with contextlib.redirect_stdout(io.StringIO()):return inspect_project(compound(streams))

    def test_real_strict_parser_proves_cache_free_project(self):
        result=self.inspect(vba_streams())
        self.assertEqual(result['pcode_status'],'cache_absent')
        inventory=result['module_inventory']
        self.assertEqual(inventory['status'],'complete',inventory)
        self.assertTrue(inventory['empty_project_verified'],inventory)
        self.assertEqual(inventory['modules'][0]['cache_bytes'],0)
        self.assertEqual(inventory['modules'][0]['source']['procedure_count'],1)

    def test_real_parser_does_not_call_executable_source_empty(self):
        result=self.inspect(vba_streams('Attribute VB_Name = "Fixture"\r\nSub A()\r\nDebug.Print "fixture"\r\nEnd Sub\r\n'))
        self.assertFalse(result['module_inventory']['empty_project_verified'])

    def test_missing_project_identifier_table_preserves_source_without_false_parser_failure(self):
        result=self.inspect(vba_streams(cache=b'inert cached bytes',source='Attribute VB_Name = "Fixture"\r\nSub A()\r\nDebug.Print "fixture"\r\nEnd Sub\r\n'))
        self.assertTrue(result['source_sha256'])
        self.assertEqual(result['pcode_status'],'incomplete')
        self.assertEqual(result['pcode_analysis']['modules'][0]['status'],'incomplete')
        self.assertFalse(result['pcode_family_match'])
        self.assertFalse(result['module_inventory']['empty_project_verified'])

    def test_source_only_module_is_never_disassembled_as_cache(self):
        import contextlib,io
        from office_analysis import inspect_pcode,LimitedText
        inventory={'status':'complete','modules':[{'stream':'VBA/One','cache_bytes':0},
                                                 {'stream':'VBA/Two','cache_bytes':16}]}
        parser=type('Parser',(),{'find_vba_projects':lambda self:[('','PROJECT','VBA/dir')],
                                'ole_file':type('Ole',(),{'openstream':lambda self,path:io.BytesIO(b'inert cached project information')})()})()
        with contextlib.redirect_stdout(io.StringIO()),patch('pcodedmp.pcodedmp.processDir',return_value=(b'dir',['One','Two'],False)),patch('pcodedmp.pcodedmp.getTheIdentifiers',return_value=[]),patch('pcodedmp.pcodedmp.pcodeDump') as disassemble:
            result=inspect_pcode(parser,inventory,LimitedText(1000))
        self.assertEqual(disassemble.call_count,1)
        self.assertEqual([row['status'] for row in result['modules']],['not_present','analyzed'])

    def test_empty_module_with_library_reference_needs_dependency_check(self):
        import struct
        name=b'FixtureLibrary';libid=b'*\\G{00000000-0000-0000-0000-000000000001}#1.0#0#C:\\fixture\\library.tlb#Fixture'
        reference=struct.pack('<HI',0x16,len(name))+name+struct.pack('<HI',0x3E,len(name)*2)+name.decode().encode('utf-16-le')
        reference+=struct.pack('<HII',0x0D,len(libid)+10,len(libid))+libid+b'\0'*6
        inventory=self.inspect(vba_streams(references=reference))['module_inventory']
        self.assertEqual(inventory['status'],'complete',inventory)
        self.assertTrue(inventory['compiled_cache_absent'])
        self.assertEqual(inventory['project_references'][0]['status'],'dependencies_not_verified')
        self.assertFalse(inventory['empty_project_verified'])

    def test_unknown_streams_and_project_caches_disqualify_positive_proof(self):
        for extra in ({'VBA/__SRP_0':b'cache'},{'VBA/Unknown':b'unknown'},
                      {'VBA/_VBA_PROJECT':b'\xcc\x61\xff\xff\0\0\0cache'},
                      {'ObjectPool/object':b'inert object'}):
            with self.subTest(extra=list(extra)):
                inventory=self.inspect(vba_streams(extra=extra))['module_inventory']
                self.assertFalse(inventory['empty_project_verified'])

    def test_orphan_module_is_not_covered_by_declared_project(self):
        from office_fixtures import compressed_literals
        with self.assertRaisesRegex(ValueError,'解析未完成'):
            self.inspect(vba_streams(extra={'VBA/Orphan':compressed_literals(b'Attribute VB_Name = "Orphan"\r\n')}))

    def test_real_container_and_independent_checks_required_for_positive_verdict(self):
        result=self.inspect(vba_streams());candidate=row()
        candidate.update(macro=True,macro_analysis=result,document_format='ooxml',package_structure_checked=True,
                         analysis_sha256='a'*64,snapshot_analysis_sha256='a'*64)
        self.assertEqual(assess_document(candidate)['rule'],'empty_vba_project')
        for change in ({'package_structure_checked':False},{'active_content_unresolved':True},
                       {'has_family_macro':True},{'document_format':'ole'},{'snapshot_analysis_sha256':'b'*64}):
            altered=copy.deepcopy(candidate);altered.update(change)
            self.assertNotEqual(assess_document(altered)['classification'],'informational')
        altered=copy.deepcopy(candidate);altered['macro_analysis']['module_inventory']['compiled_cache_absent']=False
        altered['macro_analysis']['module_inventory']['empty_project_verified']=False
        self.assertNotEqual(assess_document(altered)['classification'],'informational')

    def test_biff_unknown_formula_macro_and_malformed_records_block_positive_rule(self):
        import olefile
        for extra in (None,(0x0006,b'inert formula'),(0x01AE,b'inert external'),(0x0018,b'name'),(0x7777,b'unknown')):
            with self.subTest(extra=extra):
                data=compound(vba_streams(extra={'Workbook':plain_workbook(extra)}))
                with olefile.OleFileIO(data) as ole:result=inspect_legacy_workbook(ole)
                self.assertEqual(result['status'],'complete',result)
                self.assertEqual(result['active_or_unclassified_features']==[],extra is None)
        data=plain_workbook()[:-1]
        with olefile.OleFileIO(compound({'Workbook':data})) as ole:
            self.assertEqual(inspect_legacy_workbook(ole)['status'],'partial')

    def test_real_ooxml_parser_retains_empty_project_proof(self):
        import worm_recovery as recovery
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'ordinary.xlsm'
            with zipfile.ZipFile(path,'w') as package:
                package.writestr('[Content_Types].xml','<Types/>')
                package.writestr('xl/workbook.xml','<workbook/>')
                package.writestr('xl/vbaProject.bin',compound(vba_streams()))
            before=path.read_bytes();result=recovery.office_check(path)
            self.assertFalse(result.get('analysis_error'),result)
            self.assertTrue(result['macro_analysis']['module_inventory']['empty_project_verified'])
            self.assertEqual(path.read_bytes(),before)

    def test_snapshot_change_cannot_reuse_an_old_empty_project_verdict(self):
        from types import SimpleNamespace
        import threading
        from secondary_analysis import enrich_reviews
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'changed.xlsm'
            nonempty=vba_streams('Attribute VB_Name = "Fixture"\r\nSub A()\r\nDebug.Print "fixture"\r\nEnd Sub\r\n')
            with zipfile.ZipFile(path,'w') as package:
                package.writestr('[Content_Types].xml','<Types/>')
                package.writestr('xl/workbook.xml','<workbook/>')
                package.writestr('xl/vbaProject.bin',compound(nonempty))
            candidate=row();candidate.update(path=str(path),macro=True,macro_analysis=self.inspect(vba_streams()),
                                             document_format='ooxml',package_structure_checked=True)
            cleaner=SimpleNamespace(findings=[candidate],cancel=threading.Event(),run=root,
                policy=SimpleNamespace(check=lambda _:None),protected_path=lambda _:False,
                emit=lambda _:None,log=lambda *a,**kw:None,error=lambda *a:None,inspection_failed=False)
            def scan(paths,work,**kwargs):return {str(path):{'status':'no_match'} for path in paths},{}
            with patch('secondary_analysis.clam_batch',side_effect=scan):enrich_reviews(cleaner)
            self.assertEqual(candidate['kind'],'review_office')
            self.assertFalse(candidate['macro_analysis']['module_inventory']['empty_project_verified'])


if __name__=='__main__':unittest.main()
