import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from metadata_formats import appledouble,recycle_index,inspect_metadata
from document_verdict import assess_document
from worm_recovery import office_check


def apple(resource=b''):
    header=struct.pack('>II16sH',0x51607,0x20000,b'Mac OS X        ',2)
    return header+struct.pack('>III',9,50,32)+struct.pack('>III',2,82,len(resource))+b'\0'*32+resource


def recycle(version=2):
    text='C:\\Users\\Fixture\\Documents\\ordinary.docx\0'.encode('utf-16-le')
    header=struct.pack('<QQQ',version,1234,133000000000000000)
    return header+(text.ljust(520,b'\0') if version==1 else struct.pack('<I',len(text)//2)+text)


class MetadataTests(unittest.TestCase):
    def test_appledouble_is_identified_by_complete_bytes_not_name(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'arbitrary.pptx';path.write_bytes(apple());before=path.read_bytes()
            result=office_check(path)
            self.assertEqual(result['document_format'],'appledouble');self.assertTrue(result['passive_metadata_verified'])
            self.assertEqual(path.read_bytes(),before)
            candidate={**result,'kind':'review_office','path':str(path),'analysis_sha256':hashlib.sha256(before).hexdigest(),
                'secondary_analysis':{'clamav':{'status':'no_match'},'yara_x':{'matches':[]},'office_parser':{'status':'analyzed'}}}
            self.assertEqual(assess_document(candidate)['rule'],'verified_metadata_container')
            candidate['analysis_sha256']='0'*64
            self.assertNotEqual(assess_document(candidate)['classification'],'informational')

    def test_resource_fork_is_not_assumed_passive(self):
        self.assertFalse(appledouble(apple(b'inert nonempty resource'))['passive'])

    def test_appledouble_overlaps_out_of_range_duplicate_and_slack_rejected(self):
        bad=[]
        raw=bytearray(apple());struct.pack_into('>I',raw,30,40);bad.append(raw)
        raw=bytearray(apple());struct.pack_into('>I',raw,34,9999);bad.append(raw)
        raw=bytearray(apple());struct.pack_into('>I',raw,38,9);bad.append(raw)
        bad.extend((apple()+b'inert appended data',apple()[:25],b'\0'*82))
        for value in bad:
            with self.subTest(value=value[:35]),self.assertRaises(ValueError):appledouble(value)

    def test_both_recycle_record_versions_are_structurally_checked(self):
        for version in (1,2):
            result=recycle_index(recycle(version));self.assertTrue(result['passive']);self.assertEqual(result['original_extension'],'.docx')

    def test_recycle_invalid_lengths_paths_and_extra_content_rejected(self):
        raw=bytearray(recycle());struct.pack_into('<I',raw,24,9999)
        bad=[raw,recycle()+b'extra',recycle()[:-2]]
        raw=bytearray(recycle());raw[28:30]=b'X\0';raw[30:32]=b'X\0';bad.append(raw)
        for value in bad:
            with self.subTest(value=value[:28]),self.assertRaises(ValueError):recycle_index(value)

    def test_recycle_filename_alone_never_bypasses_document_parser(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'$IABCDEF.docx';path.write_bytes(recycle())
            self.assertIsNone(inspect_metadata(path,path.read_bytes()[:16]))
            directory=Path(temp)/'$Recycle.Bin/S-1-5-21-1';directory.mkdir(parents=True)
            path=directory/'$IABCDEF.docx';path.write_bytes(recycle())
            result=office_check(path);self.assertEqual(result['document_format'],'recycle_index')
            self.assertFalse(result.get('analysis_error'))
            path.write_bytes(b'inert random bytes')
            self.assertTrue(office_check(path)['analysis_error'])


if __name__=='__main__':unittest.main()
