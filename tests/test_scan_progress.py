"""Scan coverage, volume inheritance and progress tests on inert files."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import worm_recovery as w


class ScanProgressTests(unittest.TestCase):
    def test_ordinary_directories_do_not_repeat_volume_queries(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'scan';root.mkdir()
            for i in range(12):
                folder=root/str(i);folder.mkdir();(folder/'data.txt').write_text('inert')
            c=w.Cleaner(emit=lambda s:None)
            with patch.object(w,'volume',wraps=w.volume) as query:
                c.scan([str(root)])
            self.assertEqual(c.count,12)
            self.assertEqual(c.dircount,13)
            self.assertEqual(query.call_count,1)
            self.assertFalse(c.scan_active)
            self.assertTrue(c.current_path)
            self.assertEqual(c.errors,[])

    def test_only_explicitly_removed_roots_may_disappear(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'removed'
            c=w.Cleaner(emit=lambda s:None)
            c.events.append({'kind':'empty_payload_directory_removed','path':str(root)})
            self.assertEqual(c.scan([str(root)]),[])
            other=Path(temp)/'missing'
            with self.assertRaises(ValueError):c.scan([str(other)])


if __name__=='__main__':
    unittest.main(verbosity=2)
