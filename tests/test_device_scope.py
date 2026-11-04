import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import device_scope as ds
import worm_recovery as wr

def disk(number,bus,letters,identity):
    return {'number':number,'bus':bus,'unique':identity,'pnp':'device-'+identity,'serial':identity,
            'model':'Disk '+str(number),'offline':False,'partitions':[{'letter':letter,'volume':'volume-'+identity+'-'+letter,'partition':i+1} for i,letter in enumerate(letters)]}

class DeviceScopeTests(unittest.TestCase):
    def setUp(self):
        self.rows=[disk(0,'NVMe',['C','F'],'internal'),disk(1,'USB',['E','G'],'usb-one'),disk(2,'USB',['H'],'usb-two')]
    def test_internal_scope_excludes_external(self):
        selection=ds.DeviceCatalog(self.rows).select('internal')
        self.assertEqual({x[:2] for x in selection['roots']},{'C:','F:'})
        self.assertEqual(selection['external_volumes'],{})
    def test_device_selection_includes_all_partition_letters(self):
        selection=ds.DeviceCatalog(self.rows).select('manual',['E:/documents'])
        self.assertEqual({x[:2] for x in selection['roots']},{'E:','G:'})
        self.assertEqual(set(selection['external_volumes'].values()),{'volume-usb-one-E','volume-usb-one-G'})
        self.assertNotIn('H:',{x[:2] for x in selection['roots']})
    def test_removable_button_scans_all_connected_devices(self):
        selection=ds.DeviceCatalog(self.rows).select('removable')
        self.assertEqual({x[:2] for x in selection['roots']},{'E:','G:','H:'})
    def test_preserved_device_remains_excluded_when_letters_change(self):
        profile={'identifiers':ds.identifiers(self.rows[1]),'volumes':[]}
        rows=[disk(0,'NVMe',['C'],'internal'),disk(4,'USB',['I','J'],'usb-one'),self.rows[2]]
        catalog=ds.DeviceCatalog(rows,profile)
        self.assertEqual({x[:2] for x in catalog.select('removable')['roots']},{'H:'})
        with self.assertRaises(PermissionError):catalog.select('manual',['J:/'])
    def test_no_letter_partition_is_reported_not_silently_claimed(self):
        row=disk(2,'USB',['E','\x00'],'split')
        selection=ds.DeviceCatalog([row]).select('removable')
        self.assertEqual(selection['devices'][0]['partitions_without_letters'],1)
        self.assertEqual({x[:2] for x in selection['roots']},{'E:'})
    def test_empty_scope_does_not_fall_back_to_entire_pc(self):
        with patch.object(ds.DeviceCatalog,'discover',return_value=ds.DeviceCatalog([self.rows[0]])):
            with self.assertRaises(ValueError):ds.resolve_scope(lambda s:None,'removable')
    def test_external_volume_identity_is_checked_again_after_hot_swap(self):
        policy=wr.VolumePolicy({'E:/':'volume-one'})
        with patch.object(wr,'volume',return_value='E:\\'),patch.object(wr.kernel,'GetDriveTypeW',return_value=2),patch.object(wr,'storage_info',return_value={'bus':7,'removable':True}),patch.object(wr,'volume_identity',return_value='volume-one'):
            self.assertTrue(policy.check('E:/data')['allowed'])
        with patch.object(wr,'volume',return_value='E:\\'),patch.object(wr,'volume_identity',return_value='different-device'):
            with self.assertRaises(PermissionError):policy.mutation('E:/data')
    def test_defaults_are_enabled(self):
        import inspect
        parameters=inspect.signature(wr.Cleaner).parameters
        self.assertTrue(parameters['force_close'].default)
        self.assertTrue(parameters['restore_history'].default)
    def test_pe_access_error_is_not_reported_as_clean(self):
        with patch('builtins.open',side_effect=PermissionError('locked')):
            with self.assertRaises(PermissionError):wr.is_stub('C:/locked.exe',strict=True)

if __name__=='__main__':
    unittest.main(verbosity=2)
