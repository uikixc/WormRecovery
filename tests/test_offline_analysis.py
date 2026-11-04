"""Offline analysis regressions; synthetic packages and mocked content only."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import office_analysis as analysis
import office_triage as triage
from persistence_inventory import INVENTORY_SCRIPT, select_confirmed, remove_consumer_script, registry_paths
import worm_recovery as w


class OfficeActiveContentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def package(self, extra=None):
        path = self.root / 'fixture.xlsx'
        parts = {'[Content_Types].xml': '<Types/>', 'xl/workbook.xml': '<workbook/>'}
        parts.update(extra or {})
        with zipfile.ZipFile(path, 'w') as out:
            for name, value in parts.items():
                out.writestr(name, value)
        return path

    def test_xlm_without_vba_cannot_be_reported_clean(self):
        path = self.package({'xl/macrosheets/sheet1.xml': '<macrosheet/>'})
        result = w.office_check(path)
        self.assertEqual(result['status'], 'review')
        self.assertEqual(result['structural_evidence'][0]['kind'], 'xlm_macro_sheet')
        self.assertFalse(result.get('has_family_macro', False))

    def test_renamed_macro_sheet_content_type_is_detected(self):
        path = self.package({'[Content_Types].xml': '<Types><Override PartName="/xl/data.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>'})
        self.assertEqual(w.office_check(path)['status'], 'review')

    def test_embedding_prevents_automatic_vba_only_repair(self):
        macro = b'inert fingerprint fixture'
        path = self.package({'xl/vbaProject.bin': macro, 'xl/embeddings/obj.bin': b'inert object'})
        with patch.object(w, 'BAD_VBA_HASHES', {hashlib.sha256(macro).hexdigest()}):
            result = w.office_check(path)
        self.assertEqual(result['status'], 'review')
        self.assertTrue(result['has_family_macro'])
        with self.assertRaisesRegex(ValueError, '额外活动内容'):
            w.sanitized_xlsx(path, self.root / 'output.xlsx')
        self.assertFalse((self.root / 'output.xlsx').exists())

    def test_regular_hyperlink_alone_is_not_reported_as_infection(self):
        path = self.package({'xl/_rels/workbook.xml.rels': '<Relationships><Relationship Type="http://example.test/hyperlink" TargetMode="External" Target="https://example.test/"/></Relationships>'})
        self.assertEqual(w.office_check(path), {'status': 'clean', 'macro': False})

    def test_external_template_is_not_ignored(self):
        path = self.package({'word/_rels/settings.xml.rels': '<Relationships><Relationship Type="http://example.test/attachedTemplate" TargetMode="External" Target="file:///C:/fixture.dotm"/></Relationships>'})
        result = w.office_check(path)
        self.assertEqual(result['status'], 'review')
        self.assertEqual(result['structural_evidence'][0]['relationship_type'], 'attachedtemplate')

    def test_dde_field_and_auto_macro_names_are_detected(self):
        for member, value, kind in (
                ('word/document.xml', '<document><instrText>DDEAUTO fixture</instrText></document>', 'dde_field'),
                ('xl/workbook.xml', '<workbook><definedName name="_xlnm.Auto_Open">Sheet1!A1</definedName></workbook>', 'auto_macro_name')):
            with self.subTest(kind=kind):
                result = w.office_check(self.package({member: value}))
                self.assertEqual(result['status'], 'review')
                self.assertEqual(result['structural_evidence'][0]['kind'], kind)

    def test_xml_entities_and_traversal_paths_fail_closed(self):
        for extra in ({'xl/workbook.xml': '<!DOCTYPE a [<!ENTITY x "fixture">]><workbook>&x;</workbook>'},
                      {'../payload.bin': b'inert'}, {'xl/workbook.xml': '<invalid'}):
            with self.subTest(extra=list(extra)):
                result = w.office_check(self.package(extra))
                self.assertEqual(result['status'], 'review')
                self.assertTrue(result['analysis_error'])

    def test_structure_cannot_be_suppressed_by_component_hash(self):
        known = next(iter(triage.REVIEWED_COMPONENTS))
        result = {'status': 'review', 'active_content_unresolved': True,
                  'structural_evidence': [{'kind': 'xlm_macro_sheet', 'member': 'fixture'}]}
        with patch.object(triage, 'content_hash', side_effect=AssertionError('must not trust')):
            self.assertEqual(triage.assess_office('C:/Program Files/Microsoft Office/Office16/Library/EUROTOOL.XLAM', result)['status'], 'review')

    def test_family_source_without_matching_pcode_is_not_auto_removed(self):
        path = self.package({'xl/vbaProject.bin': b'inert VBA fixture'})
        result = {'family_modules': ['ThisWorkbook'], 'other_modules': [], 'pcode_family_match': False}
        with patch.object(analysis, 'analyze_project', return_value=result):
            actual = w.office_check(path)
        self.assertEqual(actual['status'], 'review')
        self.assertTrue(actual['has_family_macro'])

    def test_both_source_and_pcode_family_evidence_use_established_repair(self):
        path = self.package({'xl/vbaProject.bin': b'inert VBA fixture'})
        result = {'family_modules': ['ThisWorkbook'], 'other_modules': [], 'pcode_family_match': True}
        with patch.object(analysis, 'analyze_project', return_value=result):
            actual = w.office_check(path)
        self.assertEqual(actual['status'], 'infected')
        self.assertEqual(actual['vba_part'], 'xl/vbaProject.bin')

    def test_analysis_timeout_is_uncompleted_not_clean(self):
        path = self.package({'xl/vbaProject.bin': b'inert VBA fixture'})
        with patch.object(analysis, 'analyze_project', side_effect=subprocess.TimeoutExpired('worker', 1)):
            actual = w.office_check(path)
        self.assertTrue(actual['analysis_error'])
        self.assertEqual(actual['status'], 'review')


class AnalysisTransportTests(unittest.TestCase):
    def test_graphical_build_uses_companion_with_pipes(self):
        response = {'ok': True, 'result': {'family_modules': [], 'other_modules': []}}
        data = b'isolated graphical transport fixture'
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / 'WormRecovery.exe'
            helper = executable.with_name('WormRecovery-Analysis.exe')
            helper.write_bytes(b'inert test placeholder')
            with patch.object(analysis.sys, 'frozen', True, create=True), patch.object(analysis.sys, 'executable', str(executable)), patch.object(analysis.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b'')) as run:
                analysis.analyze_project(data)
            self.assertEqual(run.call_args.args[0], [str(helper)])
            self.assertEqual(run.call_args.kwargs['stdout'], subprocess.PIPE)

    def test_graphical_build_missing_companion_is_explicit_error(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(analysis.sys, 'frozen', True, create=True), patch.object(analysis.sys, 'executable', str(Path(temp) / 'WormRecovery.exe')):
                with self.assertRaisesRegex(FileNotFoundError, '内部分析组件缺失'):
                    analysis.analyze_project(b'missing helper fixture')

    def test_worker_reports_invalid_project_without_executing_content(self):
        with self.assertRaises(ValueError):
            analysis.analyze_project(b'inert invalid OLE project', timeout=15)

    def test_worker_timeout_and_output_errors_are_not_suppressed(self):
        with patch.object(analysis.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixture', 1)):
            with self.assertRaises(subprocess.TimeoutExpired):
                analysis.analyze_project(b'inert')
        with patch.object(analysis.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'not json', stderr=b'')):
            with self.assertRaisesRegex(ValueError, '无效结果'):
                analysis.analyze_project(b'inert')

    def test_source_and_pcode_output_limits_are_enforced(self):
        output = analysis.LimitedText(4)
        output.write('abcd')
        with self.assertRaises(ValueError):
            output.write('e')


class PersistenceInventoryTests(unittest.TestCase):
    def test_renamed_targets_are_examined_by_content(self):
        inventory = {'tasks': [{'execute': 'C:/Data/renamed.exe', 'arguments': '', 'name': 'Ordinary Name'}],
                     'services': [{'Name': 'Normal', 'PathName': 'C:/Data/renamed.exe'}],
                     'wmi': [], 'filters': [], 'bindings': []}
        result = select_confirmed(inventory, lambda text: 'renamed.exe' in text)
        self.assertEqual(len(result['tasks']), 1)
        self.assertEqual(len(result['services']), 1)

    def test_vendor_names_alone_do_not_authorize_cleanup(self):
        inventory = {'tasks': [{'execute': 'C:/GoogleChrome/GoogleChrome.exe', 'name': 'GoogleChrome'}]}
        self.assertEqual(select_confirmed(inventory, lambda _: False)['tasks'], [])

    def test_new_registry_locations_and_wmi_classes_are_enumerated(self):
        self.assertTrue(any('Winlogon' in path for path in registry_paths()))
        self.assertIn('ActiveScriptEventConsumer', INVENTORY_SCRIPT)
        self.assertIn('__FilterToConsumerBinding', INVENTORY_SCRIPT)
        self.assertNotIn('$rx', INVENTORY_SCRIPT)

    def test_invalid_inventory_does_not_return_empty_success(self):
        with self.assertRaises(ValueError):
            select_confirmed(None, lambda _: False)

    def test_wmi_mutation_requires_identity_and_rechecks_content(self):
        with self.assertRaises(ValueError):
            remove_consumer_script({'class': 'InvalidClass'})
        script = remove_consumer_script({'class': 'CommandLineEventConsumer', 'object_path': 'fixture', 'Name': 'fixture', 'command': 'fixture'})
        self.assertIn('WMI consumer path changed', script)
        self.assertIn('WMI command changed', script)
        self.assertIn('Remove-CimInstance -InputObject $binding', script)
        self.assertNotIn('ClassName __EventFilter | Remove', script)


if __name__ == '__main__':
    unittest.main(verbosity=2)
