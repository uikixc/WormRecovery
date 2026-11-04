"""Do not confuse an assessed component, an unknown macro and infection."""
import unittest
from unittest.mock import patch

import office_triage as triage
import worm_recovery as w


class OfficeTriageTests(unittest.TestCase):
    def setUp(self):
        self.path='C:/Program Files/Microsoft Office/Office16/Library/SOLVER/SOLVER.XLAM'
        self.digest=next(d for d,(name,_) in triage.REVIEWED_COMPONENTS.items() if name=='SOLVER.XLAM')
        self.review={'status':'review','has_family_macro':False,'other_modules':['SolverCode.bas'],'reason':'macro'}

    def test_reviewed_component_requires_complete_matching_file_hash(self):
        with patch.object(triage,'content_hash',return_value=self.digest):result=triage.assess_office(self.path,self.review)
        self.assertEqual(result['status'],'info');self.assertEqual(result['assessment'],'reviewed_office_component')
        self.assertIn('无需删除',result['action']);self.assertEqual(result['file_sha256'],self.digest)

    def test_modified_component_remains_unconfirmed(self):
        with patch.object(triage,'content_hash',return_value='modified'):result=triage.assess_office(self.path,self.review)
        self.assertEqual(result['status'],'review');self.assertEqual(result['assessment'],'unrecognized_macro')
        self.assertIn('不要直接删除',result['action'])

    def test_matching_name_and_install_directory_are_insufficient(self):
        with patch.object(triage,'content_hash',return_value='unknown'):result=triage.assess_office(self.path,self.review)
        self.assertNotEqual(result['status'],'info')

    def test_copy_in_user_documents_is_not_auto_trusted(self):
        with patch.object(triage,'content_hash',side_effect=AssertionError('not an installation component')):
            result=triage.assess_office('C:/Users/Test/Documents/SOLVER.XLAM',self.review)
        self.assertEqual(result['status'],'review')

    def test_wrong_file_name_never_matches_hash_assessment(self):
        with patch.object(triage,'content_hash',return_value=self.digest):
            result=triage.assess_office(self.path.replace('SOLVER.XLAM','other.xlam'),self.review)
        self.assertEqual(result['status'],'review')

    def test_confirmed_infection_always_takes_precedence(self):
        infected={'status':'infected','family':'fixture'}
        with patch.object(triage,'content_hash',side_effect=AssertionError('infection must not be suppressed')):
            self.assertEqual(triage.assess_office(self.path,infected),infected)

    def test_parser_failure_is_not_reclassified_as_component(self):
        with patch.object(triage,'content_hash',side_effect=AssertionError('failure must not be suppressed')):
            result=triage.assess_office(self.path,{**self.review,'analysis_error':True})
        self.assertEqual(result['status'],'review');self.assertEqual(result['assessment'],'analysis_incomplete')

    def test_mixed_family_macro_requires_specialist_review(self):
        result=triage.assess_office(self.path,{**self.review,'has_family_macro':True})
        self.assertEqual(result['assessment'],'mixed_family_macro')
        self.assertIn('不能直接删除全部宏',result['action'])

    def test_informational_rows_never_authorize_repair(self):
        self.assertFalse(triage.is_confirmed({'kind':'info_office'}))
        self.assertFalse(triage.is_confirmed({'kind':'review_office'}))
        self.assertTrue(triage.is_confirmed({'kind':'infected_office'}))

    def test_parser_return_is_enriched_with_component_guidance(self):
        with patch.object(w,'_office_check',return_value=self.review),patch.object(triage,'content_hash',return_value=self.digest):
            result=w.office_check(self.path)
        self.assertEqual(result['status'],'info');self.assertIn('action',result)


if __name__=='__main__':unittest.main(verbosity=2)
