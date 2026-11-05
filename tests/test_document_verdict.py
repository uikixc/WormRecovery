import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from document_verdict import assess_document, local_reference
from office_triage import decide_after_engines,REVIEWED_COMPONENTS,installation_component
import worm_recovery as recovery


class DocumentDecisionTests(unittest.TestCase):
    def row(self,relation='image',target='file:///C:/images/photo.png'):
        return {'kind':'review_office','path':'E:/documents/example.pptx','macro':False,
                'structural_evidence':[{'kind':'external_relationship','member':'ppt/_rels/p.xml.rels','relationship_type':relation,'target':target}],
                'secondary_analysis':{'status':'no_known_match','clamav':{'status':'no_match'},'office_parser':{'status':'analyzed'},'yara_x':{'matches':[]}}}

    def test_local_image_is_automatically_classified_with_engine_evidence(self):
        row=self.row();decision=decide_after_engines(row)
        self.assertEqual(decision['classification'],'informational')
        self.assertEqual(row['kind'],'info_document');self.assertIn('本地图片',row['reason'])

    def test_no_match_alone_never_clears_unknown_macro(self):
        row=self.row();row.pop('macro');row['macro_analysis']={'modules':[{'name':'unknown'}]}
        self.assertEqual(assess_document(row)['classification'],'unresolved')

    def test_remote_templates_network_paths_and_executable_images_stay_unresolved(self):
        for relation,target in [('image','https://site.test/image.png'),('image','file://server/share/pic.png'),('image','file:///C:/images/pic.png.exe'),('image','file:///C:/images/pic.png:payload'),('attachedtemplate','file:///C:/template.dotm')]:
            with self.subTest(target=target):self.assertEqual(assess_document(self.row(relation,target))['classification'],'unresolved')

    def test_every_target_is_assessed_not_just_first_relationship(self):
        row=self.row();row['structural_evidence'].append({'kind':'external_relationship','member':'ppt/_rels/p.xml.rels','relationship_type':'image','target':'file:///C:/payload.exe'})
        self.assertEqual(assess_document(row)['classification'],'unresolved')

    def test_external_workbook_requires_typed_external_book_without_dde(self):
        row=self.row('externallinkpath','file:///D:/data/source.xlsx')
        row['structural_evidence'].append({'kind':'external_data','member':'xl/externalLinks/externalLink1.xml'})
        self.assertEqual(assess_document(row)['classification'],'unresolved')
        row['structural_evidence'].append({'kind':'external_book_link','member':'xl/externalLinks/externalLink1.xml'})
        self.assertEqual(assess_document(row)['classification'],'informational')
        row['structural_evidence'].append({'kind':'external_executable_link','link_type':'ddeLink'})
        self.assertEqual(assess_document(row)['classification'],'unresolved')

    def test_failures_and_detections_take_precedence(self):
        for state,expected in [('incomplete','incomplete'),('detected','detected')]:
            row=self.row();row['secondary_analysis']['clamav']['status']=state
            row['secondary_analysis']['status']=state
            self.assertEqual(assess_document(row)['classification'],expected)

    def test_content_rule_hit_or_missing_engine_cannot_clear(self):
        row=self.row();row['secondary_analysis']['yara_x']['matches']=['family']
        self.assertEqual(assess_document(row)['classification'],'unresolved')
        row['secondary_analysis'].pop('yara_x')
        self.assertEqual(assess_document(row)['classification'],'unresolved')

    def test_truncated_target_or_unrelated_external_book_stays_unresolved(self):
        row=self.row();row['structural_evidence'][0]['target_truncated']=True
        self.assertEqual(assess_document(row)['classification'],'unresolved')
        row=self.row('externallinkpath','file:///C:/source.xlsx')
        row['structural_evidence'].extend([{'kind':'external_data','member':'xl/externalLinks/externalLink2.xml'},
                                          {'kind':'external_book_link','member':'xl/externalLinks/externalLink1.xml'}])
        self.assertEqual(assess_document(row)['classification'],'unresolved')

    def test_mounted_office_component_requires_pin_and_correct_directory(self):
        digest=next(k for k,v in REVIEWED_COMPONENTS.items() if v[0]=='SOLVER.XLAM')
        path='E:/Program Files/Microsoft Office/Office16/Library/SOLVER/SOLVER.XLAM'
        self.assertTrue(installation_component(path))
        row=self.row();row.update(path=path,analysis_sha256=digest,macro_analysis={'modules':[]});row.pop('structural_evidence')
        self.assertEqual(assess_document(row)['classification'],'informational')
        row['analysis_sha256']='0'*64
        self.assertEqual(assess_document(row)['classification'],'unresolved')
        row.update(analysis_sha256=digest,path='E:/Users/Test/SOLVER.XLAM')
        self.assertEqual(assess_document(row)['classification'],'unresolved')

    def test_large_word_structure_streams_and_still_detects_dde(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'large.docx'
            xml=b'<document><p>'+b'x'*(9*1024*1024)+b'</p><instrText>DDEAUTO fixture</instrText></document>'
            with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as package:
                package.writestr('[Content_Types].xml','<Types/>');package.writestr('word/document.xml',xml)
            before=hashlib.sha256(target.read_bytes()).hexdigest();result=recovery.office_check(target)
            self.assertFalse(result.get('analysis_error'));self.assertEqual(result['status'],'review')
            self.assertTrue(any(x['kind']=='dde_field' for x in result['structural_evidence']))
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),before)

    def test_multiple_relationship_targets_are_preserved(self):
        from office_structure import inspect_package
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'relations.xlsx'
            with zipfile.ZipFile(target,'w') as package:
                package.writestr('xl/_rels/workbook.xml.rels','<Relationships><Relationship Type="x/image" TargetMode="External" Target="file:///C:/a.png"/><Relationship Type="x/image" TargetMode="External" Target="file:///C:/b.exe"/></Relationships>')
            with zipfile.ZipFile(target) as package:rows=inspect_package(package)
            self.assertEqual(len(rows),2)

    def test_plain_local_workbook_link_and_dde_are_distinguished_by_parser(self):
        from secondary_analysis import enrich_reviews
        from types import SimpleNamespace
        import threading
        for content,expected in [('<externalLink><externalBook/></externalLink>','info_document'),('<externalLink><ddeLink/></externalLink>','review_office')]:
            with self.subTest(content=content),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);path=root/'data.xlsx'
                with zipfile.ZipFile(path,'w') as package:
                    package.writestr('[Content_Types].xml','<Types/>')
                    package.writestr('xl/workbook.xml','<workbook/>')
                    package.writestr('xl/externalLinks/externalLink1.xml',content)
                    package.writestr('xl/externalLinks/_rels/externalLink1.xml.rels','<Relationships><Relationship Type="x/externalLinkPath" TargetMode="External" Target="file:///D:/source.xlsx"/></Relationships>')
                parsed=recovery.office_check(path);before=path.read_bytes()
                row=dict(parsed,kind='review_office',path=str(path))
                cleaner=SimpleNamespace(findings=[row],cancel=threading.Event(),run=root,
                    policy=SimpleNamespace(check=lambda _:None),protected_path=lambda _:False,emit=lambda _:None,
                    log=lambda *a,**kw:None,error=lambda *a:None,inspection_failed=False)
                def scan(paths,work,**kwargs):return {str(p):{'status':'no_match'} for p in paths},{}
                with patch('secondary_analysis.clam_batch',side_effect=scan):enrich_reviews(cleaner)
                self.assertEqual(row['kind'],expected);self.assertEqual(path.read_bytes(),before)

    def test_empty_or_misnamed_documents_are_not_reported_as_unknown_macros(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);empty=root/'empty.docx';empty.touch()
            result=recovery.office_check(empty)
            self.assertEqual(result['document_format'],'empty');self.assertTrue(result['analysis_error'])
            rtf=root/'rtf.docx';rtf.write_bytes(b'{\\rtf1 Hello plain text}')
            result=recovery.office_check(rtf)
            self.assertEqual(result['document_format'],'rtf');self.assertFalse(result.get('analysis_error'))
            self.assertTrue(result['rtf_controls_checked'])
            unknown=root/'invalid.docx';unknown.write_bytes(b'unrecognized data')
            self.assertTrue(recovery.office_check(unknown)['analysis_error'])


if __name__=='__main__':unittest.main()
