import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import coverage_errors
import worm_recovery as w


class CoverageErrorTests(unittest.TestCase):
    def test_only_registered_pagefile_is_identified_as_active(self):
        error=PermissionError('permission denied')
        result=coverage_errors.describe_read_error('C:/pagefile.sys',error,{'C:/pagefile.sys'})
        self.assertEqual(result['category'],'active_pagefile_unreadable')
        self.assertFalse(result['content_inspected'])
        self.assertEqual(coverage_errors.describe_read_error('C:/Data/pagefile.sys',error,{'C:/pagefile.sys'}),{})
        self.assertEqual(coverage_errors.describe_read_error('D:/pagefile.sys',error,{'C:/pagefile.sys'}),{})

    def test_swap_path_is_limited_to_system_root_and_stays_unverified(self):
        with patch.dict(coverage_errors.os.environ,{'SystemRoot':'C:/Windows'}):
            result=coverage_errors.describe_read_error('C:/swapfile.sys',PermissionError(),{'C:/pagefile.sys'})
            self.assertEqual(result['category'],'system_swap_path_unreadable')
            self.assertFalse(result['content_inspected'])
            self.assertEqual(coverage_errors.describe_read_error('C:/Data/swapfile.sys',PermissionError(),{'C:/pagefile.sys'}),{})
            self.assertEqual(coverage_errors.describe_read_error('C:/swapfile.sys',PermissionError(),set()),{})

    def test_non_permission_error_is_not_reclassified(self):
        self.assertEqual(coverage_errors.describe_read_error('C:/pagefile.sys',FileNotFoundError('missing'),{'C:/pagefile.sys'}),{})

    def test_explained_read_limit_remains_in_error_list(self):
        with tempfile.TemporaryDirectory() as temp:
            c=w.Cleaner(report_dir=Path(temp)/'reports',emit=lambda _:None)
            with patch('coverage_errors.active_pagefiles',return_value={'c:\\pagefile.sys'}):
                c.error('C:/pagefile.sys',PermissionError('permission denied'))
            self.assertEqual(len(c.errors),1)
            self.assertFalse(c.errors[0]['content_inspected'])
            self.assertEqual(c.errors[0]['category'],'active_pagefile_unreadable')
            self.assertIn('permission denied',c.errors[0]['error'])


if __name__=='__main__':unittest.main()
