"""Office package regressions using inert, synthetic data only."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import xml.etree.ElementTree as ET

import worm_recovery as w


class OfficePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.macro = b'Inert VBA fingerprint fixture; contains no executable code.'
        self.parts = {
            '[Content_Types].xml': b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/><Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>',
            'xl/workbook.xml': b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><bookViews><workbookView activeTab="2" firstSheet="1"/></bookViews><sheets><sheet name="Data" sheetId="1" state="veryHidden"/></sheets></workbook>',
            'xl/_rels/workbook.xml.rels': b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="macro" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/><Relationship Id="sheet" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            'xl/worksheets/sheet1.xml': b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1"><v>42</v></c><c r="B1"><f>A1*2</f><v>84</v></c></row></sheetData></worksheet>',
            'xl/styles.xml': b'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
            'xl/vbaProject.bin': self.macro,
            'xl/vbaProjectSignature.bin': b'Inert signature fixture',
            'xl/vbaData.xml': b'<fixture/>',
        }
        self.source = self.root / 'workbook.xlsm'
        self.write_package(self.source, self.parts)

    @staticmethod
    def write_package(path, parts):
        with zipfile.ZipFile(path, 'w') as package:
            for name, value in parts.items():
                package.writestr(name, value)

    def test_sanitizer_preserves_worksheet_formulas_and_styles(self):
        dest = self.root / 'workbook.xlsx'
        before = w.digest_file(self.source)
        result = w.sanitized_xlsx(self.source, dest)
        self.assertTrue(result['worksheet_bytes_preserved'])
        self.assertEqual(w.digest_file(self.source), before)
        with zipfile.ZipFile(dest) as package:
            for name in ('xl/worksheets/sheet1.xml', 'xl/styles.xml'):
                self.assertEqual(package.read(name), self.parts[name])
            self.assertFalse(any('vba' in name.lower() for name in package.namelist()))
            self.assertNotIn(b'macroEnabled', package.read('[Content_Types].xml'))
            self.assertNotIn(b'/vbaProject', package.read('xl/_rels/workbook.xml.rels'))
            workbook = ET.fromstring(package.read('xl/workbook.xml'))
            self.assertTrue(all('state' not in node.attrib for node in workbook.iter() if node.tag.endswith('}sheet')))

    def test_sanitizer_does_not_overwrite_existing_destination(self):
        dest = self.root / 'existing.xlsx'
        dest.write_bytes(b'Existing user data')
        with self.assertRaises(FileExistsError):
            w.sanitized_xlsx(self.source, dest)
        self.assertEqual(dest.read_bytes(), b'Existing user data')

    def test_known_fingerprint_is_detected_in_excel_structure(self):
        fingerprint = hashlib.sha256(self.macro).hexdigest()
        with patch.object(w, 'BAD_VBA_HASHES', {fingerprint}):
            result = w.office_check(self.source)
        self.assertEqual(result['status'], 'infected')
        self.assertEqual(result['vba_part'], 'xl/vbaProject.bin')

    def test_known_fingerprint_in_other_document_structure_requires_review(self):
        path = self.root / 'document.docm'
        self.write_package(path, {'word/vbaProject.bin': self.macro})
        with patch.object(w, 'BAD_VBA_HASHES', {hashlib.sha256(self.macro).hexdigest()}):
            self.assertEqual(w.office_check(path)['status'], 'review')

    def test_macro_free_package_is_unchanged(self):
        path = self.root / 'clean.xlsx'
        parts = {name: value for name, value in self.parts.items() if 'vba' not in name.lower()}
        self.write_package(path, parts)
        before = w.digest_file(path)
        self.assertEqual(w.office_check(path), {'status': 'clean', 'macro': False})
        self.assertEqual(w.digest_file(path), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
