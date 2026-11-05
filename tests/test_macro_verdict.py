import unittest
from macro_verdict import constant_integer,inspect_behavior


class MacroBehaviorTests(unittest.TestCase):
    def test_chr_constant_folding_is_restricted(self):
        self.assertEqual(constant_integer('84-17'),67)
        with self.assertRaises(ValueError):constant_integer('__import__("os").system("ignored")')

    def test_autorun_downloader_execution_combination(self):
        source='Sub Workbook_Open()\nSet x = CreateObject("MSXML2.XMLHTTP")\nShell "cmd.exe /c inert"\nEnd Sub'
        self.assertIn('autorun_download_execute',inspect_behavior(source)['rules'])

    def test_benign_single_keywords_do_not_form_high_risk_verdict(self):
        self.assertEqual(inspect_behavior('Sub Workbook_Open()\nCreateObject("Scripting.Dictionary")\nEnd Sub')['rules'],[])

    def test_replication_requires_combined_modification_and_save(self):
        source='Workbook_Open VBProject VBComponents CodeModule AddFromString SaveAs'
        self.assertIn('autorun_vba_replication',inspect_behavior(source)['rules'])
        self.assertEqual(inspect_behavior(source.replace('SaveAs',''))['rules'],[])

    def test_pcode_supplies_static_behavior_evidence(self):
        result=inspect_behavior('',pcode='Workbook_Open URLDownloadToFile Shell')
        self.assertEqual(result['classification'],'suspicious')


if __name__=='__main__':unittest.main()
