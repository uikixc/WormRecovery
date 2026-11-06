import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from embedded_analysis import inspect
from document_verdict import assess_document
from office_fixtures import compound,plain_workbook,vba_streams


def package(extra=None,root='xl/workbook.xml'):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml','<Types/>');archive.writestr(root,'<document/>')
        for name,body in (extra or {}).items():archive.writestr(name,body)
    return output.getvalue()


class EmbeddedTests(unittest.TestCase):
    def test_embedded_directory_is_not_counted_as_an_active_object(self):
        from office_structure import inspect_package
        data=package({'ppt/embeddings/':b''})
        with zipfile.ZipFile(io.BytesIO(data)) as archive:self.assertEqual(inspect_package(archive),[])

    def test_nested_macro_free_workbook_gets_a_typed_result(self):
        body=package();data=package({'ppt/embeddings/a.xlsx':body},'ppt/presentation.xml')
        result=inspect(data)
        self.assertEqual(result['status'],'analyzed');self.assertTrue(result['all_passive'])
        self.assertEqual(result['objects'][0]['format'],'ooxml_excel')
        self.assertEqual(result['objects'][0]['sha256'],hashlib.sha256(body).hexdigest())

    def test_macro_program_and_external_template_are_not_cleared(self):
        variants=[package({'xl/vbaProject.bin':compound(vba_streams())}),b'MZinert program',
            package({'word/_rels/document.xml.rels':'<Relationships><Relationship Type="x/attachedTemplate" TargetMode="External" Target="file:///C:/fixture.dotm"/></Relationships>'},'word/document.xml')]
        for body in variants:
            with self.subTest(prefix=body[:8]):
                result=inspect(package({'ppt/embeddings/a.bin':body}))
                self.assertFalse(result['all_passive'])

    def test_unknown_ole_formula_is_identified_without_trusting_it(self):
        result=inspect(package({'ppt/embeddings/a.bin':compound({'Equation Native':b'inert equation bytes'})}))
        self.assertEqual(result['objects'][0]['format'],'equation_object');self.assertFalse(result['all_passive'])

    def test_ole_package_payload_is_parsed_without_opening_recorded_path(self):
        body=package();native=struct.pack('<H',2)+b'fixture.xlsx\0C:\\missing\\source.xlsx\0'+b'\0'*8+b'C:\\missing\\temp.xlsx\0'+struct.pack('<I',len(body))+body
        native=struct.pack('<I',len(native))+native
        result=inspect(package({'ppt/embeddings/a.bin':compound({'\x01Ole10Native':native})}))
        self.assertTrue(result['all_passive'],result)
        self.assertEqual(result['objects'][0]['format'],'ole_package')

    def test_legacy_plain_workbook_accepted_but_formula_remains_unresolved(self):
        for extra,passive in ((None,True),((6,b'inert formula'),False)):
            result=inspect(package({'ppt/embeddings/a.bin':compound({'Workbook':plain_workbook(extra)})}))
            self.assertEqual(result['all_passive'],passive)

    def test_nested_object_limit_is_an_explicit_incomplete_result(self):
        body=package()
        for _ in range(6):body=package({'xl/embeddings/a.xlsx':body})
        result=inspect(body);self.assertEqual(result['status'],'incomplete');self.assertFalse(result['all_passive'])

    def test_object_verdict_requires_same_container_and_every_member(self):
        data=package({'ppt/embeddings/a.xlsx':package()});analysis=inspect(data)
        row={'kind':'review_office','path':'C:/fixture.pptx','macro':False,'active_content_unresolved':True,
             'analysis_sha256':hashlib.sha256(data).hexdigest(),
             'structural_evidence':[{'kind':'embedded_object','member':'ppt/embeddings/a.xlsx'}],
             'secondary_analysis':{'status':'no_known_match','clamav':{'status':'no_match'},'office_parser':{'status':'analyzed'},'yara_x':{'matches':[]},'embedded_content':analysis}}
        self.assertEqual(assess_document(row)['classification'],'informational')
        row['structural_evidence'].append({'kind':'embedded_object','member':'ppt/embeddings/unread.bin'})
        self.assertEqual(assess_document(row)['classification'],'unresolved')
        row['structural_evidence'].pop();row['analysis_sha256']='0'*64
        self.assertEqual(assess_document(row)['classification'],'unresolved')


if __name__=='__main__':unittest.main()
