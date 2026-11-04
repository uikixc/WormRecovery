"""Single-file bundles resolve only their private components."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bundled_components as bundle


class BundledComponentTests(unittest.TestCase):
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
