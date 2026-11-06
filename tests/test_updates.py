"""Updater security, route selection, installation and offline behavior."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import ANY,patch
import urllib.request
import urllib.error

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import app_update as update
import update_install as install
import update_security as security


def signed_fixture(content=b'MZinert update fixture',version='1.5.1'):
    key=Ed25519PrivateKey.generate()
    public=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    payload={'schema':1,'repository':security.REPOSITORY,'version':version,'platform':'windows-x64',
             'asset':'WormRecovery.exe','bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}
    if len(content)<1024:
        content+=b' '*(1024-len(content));payload.update(bytes=len(content),sha256=hashlib.sha256(content).hexdigest())
    document={'payload':payload,'signature':base64.b64encode(key.sign(security.canonical(payload))).decode()}
    return content,document,public


class UpdateSecurityTests(unittest.TestCase):
    def test_semantic_versions_do_not_compare_lexicographically(self):
        self.assertGreater(security.version_tuple('1.10.0'),security.version_tuple('v1.9.9'))
        for invalid in ('1.5','1.5.0-beta','1.05.0','../1.0.0',None):
            with self.subTest(value=invalid),self.assertRaises(ValueError):security.version_tuple(invalid)

    def test_signed_metadata_accepts_only_matching_payload(self):
        _,document,key=signed_fixture()
        self.assertEqual(security.verify_manifest(document,key)['version'],'1.5.1')
        document['payload']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'签名'):security.verify_manifest(document,key)

    def test_wrong_public_key_is_rejected(self):
        _,document,_=signed_fixture();_,_,other=signed_fixture()
        with self.assertRaises(ValueError):security.verify_manifest(document,other)

    def test_private_route_never_contacts_public_accelerators(self):
        info={'private':True,'asset_id':123,'public_url':'https://github.com/private/repo/releases/download/v1/file.exe'}
        routes=update.routes_for(info)
        self.assertEqual(len(routes),1)
        self.assertTrue(routes[0][1].startswith('https://api.github.com/'))

    def test_token_cannot_be_sent_to_proxy(self):
        with self.assertRaisesRegex(update.UpdateError,'凭据'):
            update.open_url('https://ghfast.top/https://github.com/owner/repo',token='secret')

    def test_redirect_strips_token_before_cross_host_download(self):
        request=urllib.request.Request('https://api.github.com/repos/x/y/releases/assets/1',headers={'Authorization':'Bearer secret'})
        target=update.SafeRedirect().redirect_request(request,None,302,'Found',{},'https://release-assets.githubusercontent.com/test?signature=fixture')
        self.assertFalse(any(k.casefold()=='authorization' for k in target.headers))

    def test_untrusted_or_http_redirect_is_rejected(self):
        request=urllib.request.Request('https://api.github.com/repos/x/y')
        for url in ('http://github.com/file','https://attacker.example/file'):
            with self.subTest(url=url),self.assertRaises(update.UpdateError):
                update.SafeRedirect().redirect_request(request,None,302,'Found',{},url)

    def test_download_url_must_match_repository_and_tag(self):
        valid='https://github.com/'+security.REPOSITORY+'/releases/download/v1.5.1/WormRecovery.exe'
        self.assertEqual(update.validate_asset_url(valid,'v1.5.1'),valid)
        with self.assertRaises(update.UpdateError):update.validate_asset_url(valid.replace('v1.5.1','v1.5.0'),'v1.5.1')


class ServiceUpdateTests(unittest.TestCase):
    def test_service_success_does_not_load_device_credentials(self):
        expected={'available':False,'version':'1.8.3','private':False}
        with patch.object(update,'service_manifest_check',return_value=expected),patch.object(update,'load_token',side_effect=AssertionError('unnecessary token access')):
            self.assertEqual(update.check_update('1.8.3'),expected)

    def test_saved_token_still_uses_credential_free_signed_service(self):
        _,document,key=signed_fixture(version='1.8.3')
        with patch('update_trust.UPDATE_PUBLIC_KEY',key),patch.object(update,'read_json',return_value=document) as read,patch.object(update,'_api_check',side_effect=AssertionError('token bypassed service')):
            info=update.check_update('1.8.2',token='stale-device-token')
        self.assertEqual(info['version'],'1.8.3')
        self.assertTrue(all(call.kwargs.get('token')=='' for call in read.call_args_list))

    def test_metadata_race_has_wall_clock_deadline(self):
        import time
        release=threading.Event()
        try:
            started=time.monotonic()
            with self.assertRaisesRegex(update.UpdateError,'总时限'):
                update._first_verified([('hung','a')],lambda route:release.wait(2),timeout=.05)
            self.assertLess(time.monotonic()-started,.5)
        finally:release.set()

    def test_service_http_error_identifies_service(self):
        url=update.UPDATE_ORIGINS[0]+update.METADATA_PATH
        with patch.object(update,'open_url',side_effect=urllib.error.HTTPError(url,503,'unavailable',{},None)):
            with self.assertRaisesRegex(update.UpdateError,'自用更新服务.*503'):update.read_json(url)

    def test_http_service_is_fixed_and_rejects_redirects(self):
        valid=update.UPDATE_ORIGINS[0]+update.METADATA_PATH
        self.assertTrue(update.first_party_url(valid))
        for suffix in ('?token=x','#x','/../secret'):
            self.assertFalse(update.first_party_url(valid+suffix))
        self.assertFalse(update.first_party_url('http://attacker.example'+update.METADATA_PATH))
        self.assertFalse(update.first_party_url('http://user@10.205.103.120:10888'+update.METADATA_PATH))
        with self.assertRaises(update.UpdateError):
            update.SafeRedirect().redirect_request(urllib.request.Request(valid),None,302,'Found',{},valid)

    def test_service_explicitly_disables_all_proxy_discovery_and_credentials(self):
        url=update.UPDATE_ORIGINS[0]+update.METADATA_PATH
        with patch.object(update.urllib.request,'build_opener') as build:
            update.open_url(url)
            self.assertEqual(build.call_args.args[0].proxies,{})
        with self.assertRaises(update.UpdateError):update.open_url(url,token='private')
        with self.assertRaises(update.UpdateError):update.open_url(url,extra_headers={'Authorization':'secret'})

    def test_github_fallback_also_ignores_system_proxy(self):
        with patch.object(update.urllib.request,'build_opener') as build:
            update.open_url(update.API)
            self.assertEqual(build.call_args.args[0].proxies,{})

    def test_unavailable_service_falls_back_to_github(self):
        expected={'available':False,'version':'1.8.2','private':False}
        with patch.object(update,'service_manifest_check',side_effect=update.UpdateError('offline')),patch.object(update,'_api_check',return_value=expected) as github:
            self.assertEqual(update.check_update('1.8.2',token=''),expected)
            github.assert_called_once_with('1.8.2','',visibility=ANY)

    def test_no_token_prefers_signed_service_without_api_or_mirror_probe(self):
        content,document,key=signed_fixture(version='1.8.3')
        with patch('update_trust.UPDATE_PUBLIC_KEY',key),patch.object(update,'read_json',return_value=document),patch.object(update,'_api_check',side_effect=AssertionError('unnecessary API')):
            info=update.check_update('1.8.2',token='')
        self.assertTrue(info['available']);self.assertIn(info['service_origin'],update.UPDATE_ORIGINS)
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key),patch.object(update,'cache_root',return_value=Path(temp)),patch.object(update,'open_url',return_value=io.BytesIO(content)) as opened,patch.object(update,'probe_route',side_effect=AssertionError('unnecessary probe')):
            result=update.download_update(info,token='')
            self.assertEqual(result.read_bytes(),content)
            self.assertTrue(update.first_party_url(opened.call_args.args[0]))
            self.assertIsNone(opened.call_args.args[1])

    def test_bad_service_signature_cannot_be_accepted(self):
        with patch.object(update,'read_json',return_value={'payload':{},'signature':'bad'}):
            with self.assertRaises(update.UpdateError):update.service_manifest_check('1.8.2')

    def test_success_does_not_wait_for_slow_route(self):
        import time
        slow_started=threading.Event();release=threading.Event()
        def fetch(route):
            if route[0]=='slow':slow_started.set();release.wait(2);return 'slow'
            slow_started.wait(1);return 'fast'
        try:
            started=time.monotonic();route,result=update._first_verified([('slow','a'),('fast','b')],fetch)
            self.assertEqual(result,'fast');self.assertLess(time.monotonic()-started,.5)
        finally:release.set()


class UpdateFlowTests(unittest.TestCase):
    def setUp(self):
        # These tests exercise GitHub only after both first-party routes fail.
        service=patch.object(update,'service_manifest_check',side_effect=update.UpdateError('fixture offline'))
        service.start();self.addCleanup(service.stop)

    def test_hung_public_api_falls_back_after_total_deadline(self):
        release=threading.Event();race=update._first_verified
        expected={'available':False,'version':'1.8.3','private':False}
        def hung(*args,**kwargs):release.wait(2);raise update.UpdateError('late')
        try:
            with patch.object(update,'_api_check',side_effect=hung),patch.object(update,'_first_verified',side_effect=lambda routes,fetch,**kw:race(routes,fetch,timeout=.05)),patch.object(update,'public_manifest_check',return_value=expected) as fallback:
                self.assertEqual(update.check_update('1.8.3',token='fixture'),expected)
            fallback.assert_called_once()
        finally:release.set()

    def test_private_visibility_survives_api_deadline_without_public_probe(self):
        release=threading.Event();race=update._first_verified
        def read(url,*args,**kwargs):
            if url==update.API:return {'private':True}
            release.wait(2);raise update.UpdateError('late')
        try:
            with patch.object(update,'read_json',side_effect=read),patch.object(update,'_first_verified',side_effect=lambda routes,fetch,**kw:race(routes,fetch,timeout=.05)),patch.object(update,'public_manifest_check') as fallback:
                with self.assertRaisesRegex(update.UpdateError,'总时限') as error:update.check_update('1.8.3',token='fixture')
            self.assertTrue(error.exception.private);fallback.assert_not_called()
        finally:release.set()

    def test_private_invalid_signature_never_uses_public_metadata(self):
        release={'tag_name':'v1.8.4','assets':[
            {'name':'WormRecovery.exe','state':'uploaded','id':1},
            {'name':'update-manifest.json','state':'uploaded','id':2}]}
        with patch.object(update,'read_json',side_effect=[{'private':True},release,{'payload':{},'signature':'bad'}]),patch.object(update,'public_manifest_check') as fallback:
            with self.assertRaises(update.UpdateError) as error:update.check_update('1.8.3',token='fixture')
        self.assertTrue(error.exception.private);fallback.assert_not_called()

    def test_api_failure_uses_signed_public_metadata_without_sending_token(self):
        _,document,key=signed_fixture(version='1.6.0')
        def read(url,token=None,asset=False):
            if url==update.API:raise update.UpdateError('DNS 名称解析失败')
            self.assertEqual(token,'');self.assertIn('/releases/latest/download/update-manifest.json',url)
            return document
        with patch.object(update,'read_json',side_effect=read),patch('update_trust.UPDATE_PUBLIC_KEY',key):
            info=update.check_update('1.5.1',token='private-fixture')
        self.assertTrue(info['available']);self.assertFalse(info['private']);self.assertTrue(info['metadata_fallback'])

    def test_private_repository_failure_does_not_try_public_metadata(self):
        with patch.object(update,'read_json',side_effect=[{'private':True},update.UpdateError('denied')]),patch.object(update,'public_manifest_check') as fallback:
            with self.assertRaises(update.UpdateError):update.check_update('1.5.1',token='fixture')
        fallback.assert_not_called()

    def test_unsigned_fallback_metadata_cannot_be_used(self):
        with patch.object(update,'read_json',side_effect=lambda *a,**kw:{'payload':{},'signature':'invalid'}):
            with self.assertRaises(update.UpdateError):update.public_manifest_check('1.5.1','offline')

    def test_timeout_error_has_a_specific_reason(self):
        with patch.object(update,'open_url',side_effect=urllib.error.URLError(TimeoutError())):
            with self.assertRaisesRegex(update.UpdateError,'连接超时'):update.read_json(update.API)

    def test_release_check_verifies_signature_and_size(self):
        content,document,key=signed_fixture()
        release={'tag_name':'v1.5.1','draft':False,'prerelease':False,'assets':[
            {'name':'WormRecovery.exe','state':'uploaded','id':1,'size':len(content),'browser_download_url':'https://github.com/'+security.REPOSITORY+'/releases/download/v1.5.1/WormRecovery.exe'},
            {'name':'update-manifest.json','state':'uploaded','id':2,'size':400}]}
        with patch.object(update,'read_json',side_effect=[{'private':True},release,document]),patch('update_trust.UPDATE_PUBLIC_KEY',key):
            result=update.check_update('1.5.0',token='fixture')
        self.assertTrue(result['available']);self.assertTrue(result['private'])

    def test_current_release_does_not_download_manifest(self):
        with patch.object(update,'read_json',side_effect=[{'private':True},{'tag_name':'v1.5.0'}]) as call:
            self.assertFalse(update.check_update('1.5.0',token='fixture')['available'])
        self.assertEqual(call.call_count,2)

    def test_private_download_verifies_bytes_and_has_no_proxy_probe(self):
        content,document,key=signed_fixture()
        info={'private':True,'asset_id':1,'manifest':document}
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key),patch.object(update,'cache_root',return_value=Path(temp)),patch.object(update,'open_url',return_value=io.BytesIO(content)),patch.object(update,'probe_route',side_effect=AssertionError('private proxy leak')):
            result=update.download_update(info,token='fixture')
            self.assertEqual(result.read_bytes(),content)

    def test_corrupt_download_leaves_no_executable(self):
        content,document,key=signed_fixture()
        info={'private':True,'asset_id':1,'manifest':document}
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key),patch.object(update,'cache_root',return_value=Path(temp)),patch.object(update,'open_url',return_value=io.BytesIO(b'bad download')):
            with self.assertRaises(update.UpdateError):update.download_update(info,token='fixture')
            self.assertFalse(list(Path(temp).rglob('*.exe')))
            self.assertFalse(list(Path(temp).rglob('*.partial')))

    def test_cancelled_download_is_not_installed(self):
        _,document,key=signed_fixture();cancel=threading.Event();cancel.set()
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key),patch.object(update,'cache_root',return_value=Path(temp)):
            with self.assertRaises(InterruptedError):update.download_update({'private':True,'asset_id':1,'manifest':document},cancel=cancel,token='fixture')

    def test_successful_install_preserves_original_backup(self):
        content,document,key=signed_fixture()
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key):
            root=Path(temp);source=root/'download.exe';target=root/'installed.exe'
            source.write_bytes(content);old=b'MZold inert program';target.write_bytes(old)
            backup=install.replace_verified(source,target,document,hashlib.sha256(old).hexdigest())
            self.assertEqual(target.read_bytes(),content);self.assertEqual(backup.read_bytes(),old)

    def test_cached_runtime_update_targets_outer_executable_and_waits_for_launcher(self):
        from types import SimpleNamespace
        import runtime_identity
        content,document,key=signed_fixture()
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key):
            root=Path(temp);source=root/'WormRecovery.exe';source.write_bytes(content)
            outer=root/'Portable.exe';outer.write_bytes(b'MZold outer')
            helper=root/'CLI.exe';helper.write_bytes(b'MZinert helper')
            launcher=SimpleNamespace(pid=501,exe=lambda:str(outer),create_time=lambda:12.5)
            current=SimpleNamespace(pid=502,exe=lambda:str(root/'cache'/'WormRecovery.exe'),parents=lambda:[launcher])
            with patch.object(install.sys,'frozen',True,create=True),patch.object(runtime_identity,'application_path',return_value=outer),patch('bundled_components.component_path',return_value=helper),patch.object(install.psutil,'Process',return_value=current),patch.object(install.subprocess,'Popen') as spawn:
                job_path=install.start_install(source,document)
            job=json.loads(job_path.read_text(encoding='utf8'))
            self.assertEqual(job['target'],str(outer))
            self.assertEqual(job['parents'],[{'pid':501,'created':12.5}])
            self.assertNotIn('WORMRECOVERY_RUNTIME_ROOT',spawn.call_args.kwargs['env'])

    def test_changed_original_refuses_replacement(self):
        content,document,key=signed_fixture()
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key):
            root=Path(temp);source=root/'download.exe';target=root/'installed.exe'
            source.write_bytes(content);target.write_bytes(b'MZdifferent')
            with self.assertRaisesRegex(ValueError,'原程序已变化'):install.replace_verified(source,target,document,'0'*64)
            self.assertEqual(target.read_bytes(),b'MZdifferent')

    def test_failed_replace_rolls_back_original(self):
        content,document,key=signed_fixture()
        with tempfile.TemporaryDirectory() as temp,patch('update_trust.UPDATE_PUBLIC_KEY',key):
            root=Path(temp);source=root/'download.exe';target=root/'installed.exe'
            source.write_bytes(content);old=b'MZold fixture';target.write_bytes(old)
            original=install.os.replace
            def replace(src,dest):
                if str(src).endswith('.update-new'):raise PermissionError('inert lock failure')
                return original(src,dest)
            with patch.object(install.os,'replace',side_effect=replace),self.assertRaises(PermissionError):
                install.replace_verified(source,target,document,hashlib.sha256(old).hexdigest())
            self.assertEqual(target.read_bytes(),old)


if __name__=='__main__':unittest.main()
