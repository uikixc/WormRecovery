"""Inert content and adversarial boundaries; never execute a specimen."""
import io
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

import family_analysis as family
import worm_recovery as recovery


def inert_pe(body,machine=0x14c):
    header=bytearray(512);header[:2]=b'MZ';struct.pack_into('<I',header,60,128)
    header[128:132]=b'PE\0\0';optlen=224 if machine==0x14c else 240
    struct.pack_into('<HH',header,132,machine,1);struct.pack_into('<H',header,148,optlen)
    struct.pack_into('<H',header,152,0x10b if machine==0x14c else 0x20b)
    struct.pack_into('<I',header,168,4096);struct.pack_into('<I',header,212,512)
    section=152+optlen;header[section:section+8]=b'.fixture'
    struct.pack_into('<IIII',header,section+8,len(body),4096,len(body),512)
    struct.pack_into('<I',header,section+36,0x60000020)
    return bytes(header)+body


def inert_controller():
    # Three short signature fragments, separated by text. This is neither a
    # complete function nor a runnable DLL and contains no actual payload.
    return inert_pe(b'INERT TEST PluginMe\0'+bytes.fromhex(
        '69c90d661900b88510420881c15ff36e3cf7e18bc12bc2d1e803c2')+b'INERT'+bytes.fromhex(
        'c745f834b79548c745fcc15d2898')+b'INERT'+bytes.fromhex(
        'c745f84a392680c745fc7d83aa53')+b'INERT'+bytes.fromhex(
        'c745e80150671ec745ec41293bbb')+b'INERT'+bytes.fromhex(
        'c745e8604e37fdc745ecdb8150fa'))


class FamilyContentTests(unittest.TestCase):
    def test_names_common_mining_strings_and_apis_never_confirm(self):
        for content in (b'C5KJLUXP gubT4QNB Synaptics GoogleChrome MozillaFirefox',
                        inert_pe(b'RandomX Monero stratum+tcp:// Pool miner hashrate'),
                        inert_pe(b'PluginMe VirtualAlloc CreateThread RegSetValueExA'),
                        b'PNG\0signed TrueUpdate Client _TUProj.dat'):
            self.assertEqual(family.inspect(content)['status'],'no_known_match')

    def test_controller_requires_all_three_independent_code_fragments(self):
        content=inert_controller()
        result=family.inspect(content)
        self.assertEqual(result['status'],'detected');self.assertFalse(result['name_used_for_verdict'])
        for pattern in ('69c90d661900','c745f834b79548','c745e80150671e'):
            fragment=bytes.fromhex(pattern);changed=content.replace(fragment,b'\x00'*len(fragment))
            self.assertEqual(family.inspect(changed)['status'],'no_known_match')

    def test_valid_pe_structure_and_code_are_distinct_evidence(self):
        content=inert_controller()
        with self.assertRaises(ValueError):family.PE(content[:-5])
        self.assertFalse(family.inspect(b'just a name')['detections'])

    def test_embedded_code_in_overlay_or_resource_does_not_condemn_outer_host(self):
        child=inert_controller()
        overlay=inert_pe(b'INERT normal host code')+child
        resource=inert_pe(b'INERT normal host code'+child)
        # Even an executable section containing an embedded complete image has
        # separate image ownership; a parent cannot borrow the child's proof.
        for data in (overlay,resource):
            result=family.inspect(data)
            self.assertFalse(result['detections'])
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'ordinary-host.exe';path.write_bytes(data)
                rows=recovery.inspect_file_content(path,path.stat())['findings']
                self.assertTrue(rows)
                self.assertFalse(any(recovery.is_confirmed(row) for row in rows))

    def test_confirmed_code_in_nonexecutable_section_is_not_mutation_authority(self):
        data=bytearray(inert_controller());struct.pack_into('<I',data,152+224+36,0x40000040)
        self.assertFalse(family.inspect(bytes(data))['detections'])

    def test_image_decryption_and_extension_independent_scan(self):
        payload=inert_controller();png=b'\x89PNG\r\n\x1a\n'+b'\0'*56+family.rc4(payload,family.PNG_KEY)
        with tempfile.TemporaryDirectory() as directory:
            for name in ('unrelated.bin','document.xlsx','x','GoogleChrome.png'):
                path=Path(directory)/name;path.write_bytes(png)
                result=recovery.inspect_file_content(path,path.stat())
                self.assertEqual(result['findings'][0]['kind'],'malware_component')
                self.assertEqual(path.read_bytes(),png)
                self.assertEqual(result['findings'][0]['family_analysis']['decodings'][0]['method'],'png_prefix64_rc4')

    def test_renamed_pe_is_inspected_and_same_named_inert_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);positive=root/'harmless.txt';positive.write_bytes(inert_controller())
            negative=root/'gubT4QNB.exe';negative.write_bytes(b'inert known name')
            self.assertEqual(recovery.inspect_file_content(positive,positive.stat())['findings'][0]['kind'],'malware_component')
            self.assertEqual(recovery.inspect_file_content(negative,negative.stat())['findings'],[])

    def test_partial_carrier_does_not_become_a_confirmed_detection(self):
        payload=bytearray(128);payload[:2]=b'MZ';struct.pack_into('<I',payload,60,80)
        png=b'\x89PNG\r\n\x1a\n'+b'\0'*56+family.rc4(payload,family.PNG_KEY)
        result=family.inspect(png)
        self.assertEqual(result['status'],'incomplete');self.assertEqual(result['detections'],[])

    def test_regular_png_zip_and_unencrypted_project_are_not_infections(self):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:archive.writestr('_TUProj.dat','normal updater configuration')
        for content in (b'\x89PNG\r\n\x1a\n'+b'\0'*500,output.getvalue()):
            self.assertEqual(family.inspect(content)['status'],'no_known_match')

    def test_ooxml_is_routed_by_internal_structure_even_with_exe_suffix(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'unrelated.exe'
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('[Content_Types].xml','<Types/>')
                archive.writestr('xl/workbook.xml','<workbook/>')
            with patch.object(recovery,'office_check',return_value={'status':'infected','family':'inert regression'}) as office:
                result=recovery.inspect_file_content(path,path.stat())
            office.assert_called_once_with(path)
            self.assertEqual(result['findings'][0]['kind'],'infected_office')

    def test_other_upx_program_is_not_this_modified_miner(self):
        self.assertEqual(family.inspect(inert_pe(b'UPX! RandomX stratum+tcp://',0x8664))['status'],'no_known_match')

    def test_decoder_rejects_truncation_and_limits_without_starting_processes(self):
        from packed_content import decode_nrv2e
        for value in (b'',b'\xff'*8,b'\0'*16):
            with self.subTest(value=value),patch('subprocess.Popen',side_effect=AssertionError('execution forbidden')):
                with self.assertRaises(ValueError):decode_nrv2e(value,max_output=2,timeout=.01)

    def test_runtime_requires_both_selected_content_proven_peers(self):
        runtime={'path':'C:/fixture/ordinary.exe','sha256':family.KNOWN_RUNTIME,'role':'observed_trueupdate_runtime'}
        def row(name,signature):
            return {'path':'C:/fixture/'+name,'sha256':'0'*64,
                    'family_analysis':{'status':'detected','detections':[{'signature':signature}],
                                       'decodings':[{'method':'png_prefix64_rc4'}]}}
        project=row('ordinary.dat','WR_Encrypted_Project_Loader')
        payload=row('ordinary.png','WR_Miner_Controller_Code')
        self.assertEqual(family.correlate([],[runtime]),[])
        self.assertEqual(family.correlate([project],[runtime]),[])
        self.assertEqual(family.correlate([payload],[runtime]),[])
        result=family.correlate([payload,project],[runtime])
        self.assertEqual(result[0]['kind'],'malware_deployment')
        payload['path']='C:/fixture/unrelated.png'
        self.assertEqual(family.correlate([project,payload],[runtime]),[])
        payload['path']='C:/different-folder/payload.png'
        self.assertEqual(family.correlate([project,payload],[runtime]),[])

    def test_full_scan_cannot_filter_a_payload_with_an_unknown_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sample=root/'unrelated.cache';sample.write_bytes(inert_controller())
            cleaner=recovery.Cleaner(report_dir=root/'reports',emit=lambda _:None)
            with patch('secondary_analysis.enrich_reviews'):
                cleaner.scan([str(root)],workers=2)
            self.assertFalse(cleaner.errors)
            self.assertEqual(len(cleaner.findings),1)
            self.assertEqual(cleaner.findings[0]['kind'],'malware_component')
            self.assertEqual(cleaner.engine_checks['file_header'],1)
            self.assertEqual(sample.read_bytes(),inert_controller())

    def test_mutation_rechecks_content_before_allowing_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sample=root/'anything.exe';sample.write_bytes(inert_controller())
            c=recovery.Cleaner(report_dir=root/'reports',emit=lambda _:None)
            c.findings=recovery.inspect_file_content(sample,sample.stat())['findings']
            sample.write_bytes(b'normal replacement')
            with patch.object(c,'contain'),patch.object(c,'registry',return_value=[]),patch.object(c,'system_persistence',return_value={}),\
                 patch.object(c,'firewall'),patch.object(c,'security_settings'),patch.object(c,'close_locks'),\
                 patch.object(c,'quarantine_file') as quarantine:
                c.repair()
            quarantine.assert_not_called();self.assertTrue(c.errors)
            self.assertEqual(sample.read_bytes(),b'normal replacement')

    def test_infection_in_an_unusual_wrapper_layout_keeps_program_recovery(self):
        analysis={'status':'detected','source_sha256':'0'*64,'detections':[
            {'signature':'WR_Synaptics_Code_Section','family':'Synaptics'}]}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'host.exe';path.write_bytes(b'inert layout-recovery fixture')
            with patch('worm_recovery.is_stub',return_value=False),patch('family_analysis.inspect',return_value=analysis):
                result=recovery.inspect_file_content(path,path.stat())
            self.assertEqual(result['findings'][0]['kind'],'infected_executable')
            self.assertNotIn('malware_component',{r['kind'] for r in result['findings']})


if __name__=='__main__':unittest.main()
