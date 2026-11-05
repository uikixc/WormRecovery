"""Single-file bundles resolve only their private components."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bundled_components as bundle
import engine_assets


class BundledComponentTests(unittest.TestCase):
    def test_nested_worker_temp_is_contained_in_parent_work_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(bundle.sys, '_MEIPASS', temp, create=True), patch.dict(engine_assets.os.environ, {}, clear=True):
                environment=engine_assets.subprocess_environment()
            expected=str(Path(temp)/'worker-temp')
            self.assertEqual(environment['TEMP'],expected)
            self.assertEqual(environment['TMP'],expected)
            self.assertEqual(environment['WORMRECOVERY_WORK_ROOT'],expected)
            self.assertTrue(Path(expected).is_dir())

    def test_embedded_component_takes_priority_over_sibling(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unpacked = root / 'private'
            (unpacked / 'engines').mkdir(parents=True)
            internal = unpacked / 'engines/WormRecovery-Analysis.exe'
            internal.write_bytes(b'inert internal fixture')
            (root / 'WormRecovery-Analysis.exe').write_bytes(b'inert sibling fixture')
            with patch.object(bundle.sys, 'frozen', True, create=True), patch.object(bundle.sys, '_MEIPASS', str(unpacked), create=True), patch.object(bundle.sys, 'executable', str(root / 'WormRecovery.exe')):
                self.assertEqual(bundle.component_path('WormRecovery-Analysis.exe'), internal)

    def test_analysis_directory_takes_priority_over_legacy_onefile_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);directory=root/'engines/analysis';directory.mkdir(parents=True)
            worker=directory/'WormRecovery-Analysis.exe';worker.write_bytes(b'inert fixture')
            (root/'engines/WormRecovery-Analysis.exe').write_bytes(b'legacy fixture')
            with patch.object(bundle.sys,'frozen',True,create=True),patch.object(bundle.sys,'_MEIPASS',str(root),create=True):
                self.assertEqual(bundle.component_path('WormRecovery-Analysis.exe'),worker)

    def test_independent_worker_resets_bootloader_state(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(engine_assets.os.environ,{'_PYI_PARENT_PROCESS_LEVEL':'1','_PYI_ARCHIVE_FILE':'old','_MEIPASS2':'old','WORMRECOVERY_WORK_ROOT':temp},clear=True):
            environment=engine_assets.subprocess_environment(independent=True)
            self.assertEqual(environment['PYINSTALLER_RESET_ENVIRONMENT'],'1')
            self.assertFalse(any(k.startswith('_PYI_') for k in environment))
            self.assertNotIn('_MEIPASS2',environment)
            self.assertEqual(environment['TEMP'],temp)

    def test_only_expected_internal_names_are_accepted(self):
        for name in ('../payload.exe', 'cmd.exe', 'C:/payload.exe'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.component_path(name)

    def test_missing_internal_component_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(bundle.sys, 'frozen', True, create=True), patch.object(bundle.sys, '_MEIPASS', temp, create=True), patch.object(bundle.sys, 'executable', str(Path(temp) / 'WormRecovery.exe')):
                with self.assertRaises(FileNotFoundError):
                    bundle.component_path('WormRecovery-CLI.exe')


if __name__ == '__main__':
    unittest.main(verbosity=2)
