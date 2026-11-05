"""Inert fixtures only: local HTTP, bounded evidence, queue, and authorization."""
import copy
import gzip
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import collector_server as server
import diagnostic_bundle as bundle
import diagnostic_client as client
import diagnostic_transport as transport


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name)
        self.state=self.root/'client';self.state.mkdir()
        self.host=self.root/'server';server.initialize(self.host)
        self.config=json.loads((self.host/'collector-server.json').read_text())
        self.config['allow_anonymous_upload']=False
        self.enrollment=json.loads((self.host/'devices.enroll').read_text())
        self.report=self.root/'report.json'
        self.report.write_text(json.dumps({'version':'1.7.0','computer':'PRIVATE-PC','files':100,'errors':[],
            'findings':[{'kind':'review_office','path':'C:/Users/PrivateUser/private.xlsm','sha256':'a'*64,
                         'reason':'unknown macro','password':'NOT_FOR_UPLOAD','vba_source':'PRIVATE CONTENT'}],
            'events':[{'computer':'PRIVATE-PC','kind':'scan_complete'}]}),encoding='utf-8')
        (self.root/'journal.jsonl').write_text(json.dumps({'kind':'update_error','computer':'PRIVATE-PC',
            'detail':'Bearer SUPER_PRIVATE_TOKEN access_token=SECRET123','env':{'GH_TOKEN':'SECRET'}})+'\n',encoding='utf-8')
        self.state_patch=patch.object(client,'state_root',return_value=self.state);self.state_patch.start()
        self.receiver=None
    def tearDown(self):
        if self.receiver:self.receiver.shutdown();self.receiver.server_close();self.thread.join(3)
        self.state_patch.stop();self.temporary.cleanup()
    def start_receiver(self):
        self.receiver=server.Collector(('127.0.0.1',0),self.config)
        self.thread=threading.Thread(target=self.receiver.serve_forever,kwargs={'poll_interval':.02},daemon=True);self.thread.start()
        return 'http://127.0.0.1:'+str(self.receiver.server_port)
    def data(self):return bundle.build_bundle(self.report,state=self.state)
    def test_report_keeps_evidence_without_originals_or_secrets(self):
        before=self.report.read_bytes();record,compressed=self.data();text=gzip.decompress(compressed).decode()
        self.assertEqual(record['summary']['review_count'],1)
        self.assertEqual(record['report']['findings'][0]['sha256'],'a'*64)
        for private in ('PrivateUser','PRIVATE-PC','NOT_FOR_UPLOAD','PRIVATE CONTENT','SUPER_PRIVATE_TOKEN','SECRET123','GH_TOKEN'):
            self.assertNotIn(private,text)
        self.assertIn('[USER]',text);self.assertEqual(before,self.report.read_bytes())
        self.assertEqual(record['device_id'],self.data()[0]['device_id'])
    def test_oversized_report_refused_before_loading(self):
        with patch.object(bundle,'MAX_REPORT',2),self.assertRaises(ValueError):self.data()
    def test_http_upload_idempotency_and_conflict(self):
        endpoint=self.start_receiver();record,compressed=self.data()
        send=lambda value:transport.send(endpoint,value,self.enrollment['upload_token'],timeout=3)
        self.assertEqual(send(compressed)['receipt'],record['bundle_id']);send(compressed)
        self.assertEqual(len(list(Path(self.config['directory']).glob('*.json'))),1)
        changed=copy.deepcopy(record);changed['summary']['files']=200
        with self.assertRaisesRegex(ValueError,'409'):send(gzip.compress(json.dumps(changed).encode()))
        summary=server.summarize(self.config['directory']);self.assertEqual(summary['reports'],1)
        self.assertEqual(summary['review_groups'][0]['sha256'],'a'*64)
    def test_http_sends_raw_gzip_without_encryption_envelope(self):
        endpoint=self.start_receiver();record,compressed=self.data()
        with patch.object(http.client.HTTPConnection,'request',side_effect=RuntimeError('stop')) as request:
            with self.assertRaises(RuntimeError):transport.send(endpoint,compressed,self.enrollment['upload_token'])
        self.assertEqual(request.call_args.kwargs['body'],compressed)
        self.assertEqual(request.call_args.kwargs['headers']['Content-Type'],'application/gzip')
        self.assertEqual(gzip.decompress(compressed)[:1],b'{')
    def test_payload_checksum_failure_refused(self):
        endpoint=self.start_receiver();record,compressed=self.data()
        connection=http.client.HTTPConnection('127.0.0.1',self.receiver.server_port,timeout=3)
        connection.request('POST','/v1/diagnostics',body=compressed,headers={
            'Authorization':'Bearer '+self.enrollment['upload_token'],'X-Content-SHA256':'0'*64})
        self.assertEqual(connection.getresponse().status,400);connection.close()
        self.assertEqual(self.receiver.bytes_used,0)
    def test_wrong_token_refused_and_admin_data_separate(self):
        endpoint=self.start_receiver();record,data=self.data()
        with self.assertRaisesRegex(ValueError,'401'):
            transport.send(endpoint,data,'bad-token',timeout=3)
        self.assertEqual(self.receiver.bytes_used,0)
        connection=http.client.HTTPConnection('127.0.0.1',self.receiver.server_port,timeout=3)
        connection.request('GET','/v1/status',headers={'Authorization':'Bearer '+self.enrollment['upload_token']})
        self.assertEqual(connection.getresponse().status,401);connection.close()
    def test_enrollment_protected_at_rest_and_queue_survives_outage(self):
        client.enroll(self.host/'devices.enroll')
        protected=(self.state/'collector.dpapi').read_bytes()
        self.assertNotIn(self.enrollment['upload_token'].encode(),protected)
        with patch.object(client,'send',side_effect=OSError('offline')):
            result=client.collect(self.report)
        self.assertEqual(result['pending'],1)
        self.assertEqual(len(list((self.state/'queue').glob('*.wrdiag'))),1)
        endpoint=self.start_receiver();config=client.configuration();config['endpoints']=[endpoint]
        with patch.object(client,'configuration',return_value=config):result=client.retry()
        self.assertEqual(result['sent'],1);self.assertEqual(result['pending'],0)
        self.assertIn('receipt',json.loads((self.state/'receipts.jsonl').read_text()))
    def test_no_config_queues_automatically_and_pause_preserves_queue(self):
        with patch.object(client,'send') as send:
            self.assertEqual(client.collect(self.report,upload=False)['pending'],1);send.assert_not_called()
        client.enroll(self.host/'devices.enroll');client.collect(self.report,upload=False)
        client.disable();self.assertEqual(client.read_status()['pending'],1)
        self.assertFalse(client.read_status()['enabled'])
    def test_receipt_mismatch_keeps_queue(self):
        client.enroll(self.host/'devices.enroll')
        with patch.object(client,'send',return_value={'accepted':True,'receipt':'different'}):result=client.collect(self.report)
        self.assertEqual(result['pending'],1)
        self.assertEqual(result['delivery'],'pending')
        self.assertIn('接收凭据',result['message'])

    def test_empty_queue_cannot_claim_report_uploaded(self):
        client.enroll(self.host/'devices.enroll')
        with patch.object(client,'send',side_effect=AssertionError('empty queue must not upload')):
            result=client.retry()
        self.assertEqual(result['sent'],0);self.assertEqual(result['pending'],0)
        self.assertEqual(result['delivery'],'no_pending_reports')
        self.assertNotIn('已提交',result['message'])

    def test_success_includes_matching_receipt_and_selected_endpoint(self):
        client.enroll(self.host/'devices.enroll');endpoint=self.start_receiver()
        config=dict(self.enrollment,endpoints=[endpoint])
        with patch.object(client,'configuration',return_value=config):result=client.collect(self.report)
        self.assertEqual(result['delivery'],'acknowledged')
        self.assertEqual(result['last_endpoint'],endpoint)
        receipt=result['last_receipt']['receipt']
        self.assertTrue((Path(self.config['directory'])/(receipt+'.json')).is_file())
        records=[json.loads(line) for line in (self.host/'receiver-requests.jsonl').read_text().splitlines()]
        self.assertEqual(records[-1]['status'],201);self.assertEqual(records[-1]['receipt'],receipt)
        text=json.dumps(records)
        self.assertNotIn(self.enrollment['upload_token'],text)
        self.assertNotIn('PRIVATE CONTENT',text)

    def test_rejected_request_is_logged_without_authorization(self):
        endpoint=self.start_receiver();record,compressed=self.data()
        with self.assertRaisesRegex(ValueError,'401'):transport.send(endpoint,compressed,'private-bad-token')
        records=[json.loads(line) for line in (self.host/'receiver-requests.jsonl').read_text().splitlines()]
        self.assertEqual(records[-1]['status'],401)
        self.assertEqual(records[-1]['error'],'unauthorized')
        self.assertNotIn('private-bad-token',json.dumps(records))

    def test_read_only_connection_probe_verifies_service_and_upload_permission(self):
        endpoint=self.start_receiver();before=len(list(Path(self.config['directory']).glob('*.json')))
        result=transport.probe(endpoint,token=self.enrollment['upload_token'])
        self.assertTrue(result['reachable']);self.assertEqual(result['authorization'],'accepted')
        rejected=transport.probe(endpoint,token='wrong-token')
        self.assertTrue(rejected['reachable']);self.assertEqual(rejected['authorization'],'rejected')
        self.assertEqual(len(list(Path(self.config['directory']).glob('*.json'))),before)

    def test_connection_check_labels_routes_and_prefers_authorized_internal_route(self):
        config=dict(self.enrollment,endpoints=list(client.DEFAULT_ENDPOINTS))
        with patch.object(client,'configuration',return_value=config),patch.object(client,'probe',return_value={'reachable':True,'authorization':'accepted'}),patch.object(client,'send',side_effect=AssertionError('probe must not upload')):
            result=client.check_connection()
        self.assertTrue(result['upload_ready']);self.assertEqual(result['selected_route'],'内网')
        self.assertEqual([x['route'] for x in result['routes']],['内网','外网'])
        self.assertFalse((self.state/'queue').exists())

    def test_old_project_public_port_migrates_without_altering_other_servers(self):
        config=dict(self.enrollment,endpoints=['http://10.205.103.120:10888','http://8.134.112.170:10888/','http://192.168.1.10:10888','http://8.134.112.170:45000'])
        validated=client.validate_config(config)
        self.assertEqual(validated['endpoints'],['http://10.205.103.120:10888','http://8.134.112.170:35981','http://192.168.1.10:10888','http://8.134.112.170:45000'])
        self.assertEqual(validated['upload_token'],config['upload_token'])
        self.assertIn('http://8.134.112.170:10888/',config['endpoints'])

    def test_connection_check_uses_external_when_internal_is_unavailable(self):
        def check(endpoint,**kwargs):
            if '10.205.' in endpoint:raise ConnectionRefusedError('offline')
            return {'reachable':True,'authorization':'accepted'}
        config=dict(self.enrollment,endpoints=list(client.DEFAULT_ENDPOINTS))
        with patch.object(client,'configuration',return_value=config),patch.object(client,'probe',side_effect=check):
            result=client.check_connection()
        self.assertEqual(result['selected_route'],'外网');self.assertTrue(result['upload_ready'])
        self.assertFalse(result['routes'][0]['reachable'])

    def test_reachable_but_paused_cannot_claim_upload_ready(self):
        with patch.object(client,'configuration',return_value=None),patch.object(client,'probe',return_value={'reachable':True,'authorization':'rejected'}):
            result=client.check_connection()
        self.assertTrue(result['connected']);self.assertFalse(result['upload_ready'])
        self.assertIn('已暂停',result['message'])
    def test_busy_upload_still_enqueues_new_report(self):
        client.enroll(self.host/'devices.enroll');client.UPLOAD_LOCK.acquire()
        try:
            result=client.collect(self.report)
            self.assertEqual(len(list((self.state/'queue').glob('*.wrdiag'))),1)
            self.assertIn('队列',result['message'])
        finally:client.UPLOAD_LOCK.release()
    def test_active_upload_drains_reports_arriving_during_submission(self):
        client.enroll(self.host/'devices.enroll');calls=[]
        def flush(config):
            calls.append(True)
            if len(calls)==1:client.QUEUE_CHANGED.set()
            return {'sent':1,'pending':0}
        with patch.object(client,'flush_queue',side_effect=flush):client.retry()
        self.assertEqual(len(calls),2)
    def test_paused_queue_does_not_start_repeated_upload_threads(self):
        client.disable()
        client.QUEUE_CHANGED.set()
        with patch.object(client,'schedule') as schedule:
            result=client.retry()
        self.assertFalse(result['enabled']);schedule.assert_not_called()

    def test_automatic_delivery_needs_no_import_or_device_registration(self):
        self.config['allow_anonymous_upload']=True
        endpoint=self.start_receiver()
        with patch.object(client,'DEFAULT_ENDPOINTS',(endpoint,)):
            self.assertEqual(client.configuration()['upload_token'],'')
            self.assertTrue(client.check_connection()['upload_ready'])
            result=client.collect(self.report)
        self.assertEqual(result['sent'],1)
        self.assertEqual(result['delivery'],'acknowledged')
        self.assertFalse((self.state/'collector.dpapi').exists())
        connection=http.client.HTTPConnection('127.0.0.1',self.receiver.server_port,timeout=3)
        connection.request('GET','/v1/status');self.assertEqual(connection.getresponse().status,401);connection.close()

    def test_automatic_backfill_submits_saved_report_once(self):
        self.config['allow_anonymous_upload']=True;endpoint=self.start_receiver()
        before=self.report.read_bytes()
        with patch.object(client,'DEFAULT_ENDPOINTS',(endpoint,)),patch.object(client,'report_candidates',return_value=[self.report]):
            first=client.retry(backfill=True);second=client.retry(backfill=True)
        self.assertEqual(first['sent'],1);self.assertEqual(second['sent'],0)
        self.assertEqual(len(list(Path(self.config['directory']).glob('*.json'))),1)
        self.assertEqual(self.report.read_bytes(),before)

    def test_backfill_keeps_scan_and_repair_and_excludes_running_report(self):
        scan=self.root/'scan.json';repair=self.root/'repair.json';running=self.root/'running.json'
        for path,kind,status in ((scan,'scan','completed'),(repair,'repair','completed'),(running,'scan','running')):
            path.write_text(json.dumps({'version':'1.7.7','findings':[],'errors':[],'operation':{'type':kind,'status':status}}))
        with patch.object(client,'report_candidates',return_value=[scan,repair,running]):client.backfill_reports()
        records=[json.loads(gzip.decompress(p.read_bytes())) for p in (self.state/'queue').glob('*.wrdiag')]
        self.assertEqual({x['operation']['type'] for x in records},{'scan','repair'})
        self.assertEqual(len(records),2)

    def test_anonymous_delivery_still_checks_envelope_digest_and_size(self):
        self.config['allow_anonymous_upload']=True;endpoint=self.start_receiver()
        _,payload=self.data();connection=http.client.HTTPConnection('127.0.0.1',self.receiver.server_port,timeout=3)
        connection.request('POST','/v1/diagnostics',body=payload,headers={'X-Content-SHA256':'0'*64})
        self.assertEqual(connection.getresponse().status,400);connection.close()
        self.assertEqual(self.receiver.bytes_used,0)

    def test_report_discovery_prefers_operation_snapshots_and_includes_failures(self):
        programdata=self.root/'programdata';session=programdata/'WormRecovery/fixture-session'
        operation=session/'operations/fixture-operation';operation.mkdir(parents=True)
        (session/'report.json').write_text('{}');(operation/'report.json').write_text('{}')
        failure=self.state/'failures/fixture-failure';failure.mkdir(parents=True);(failure/'report.json').write_text('{}')
        with patch.dict('os.environ',{'PROGRAMDATA':str(programdata)}):paths=client.report_candidates()
        self.assertEqual(set(paths),{operation/'report.json',failure/'report.json'})

    def test_cached_backfill_does_not_reread_or_requeue_unchanged_reports(self):
        with patch.object(client,'report_candidates',return_value=[self.report]):
            client.backfill_reports()
            with patch.object(client,'read_bounded',side_effect=AssertionError('unchanged report must not be read again')):
                self.assertEqual(client.backfill_reports(),0)
        self.assertEqual(len(list((self.state/'queue').glob('*.wrdiag'))),1)

    def test_success_receipt_survives_idle_background_retry(self):
        self.config['allow_anonymous_upload']=True;endpoint=self.start_receiver()
        with patch.object(client,'DEFAULT_ENDPOINTS',(endpoint,)):
            first=client.collect(self.report);second=client.retry()
        self.assertEqual(first['last_receipt'],second['last_receipt'])
        self.assertEqual(second['delivery'],'acknowledged')
    def test_decompression_bomb_and_path_id_rejected(self):
        with self.assertRaises(ValueError):server.validate_bundle(gzip.compress(b'A'*(20*1024*1024+1)))
        record,data=self.data();record['bundle_id']='../../file'
        with self.assertRaises(ValueError):server.validate_bundle(gzip.compress(json.dumps(record).encode()))
    def test_retention_removes_only_expired_reports(self):
        import os,time
        directory=Path(self.config['directory']);directory.mkdir()
        old=directory/'old.json';old.write_text('{}');os.utime(old,(time.time()-91*86400,)*2)
        current=directory/'new.json';current.write_text('{}')
        self.start_receiver();self.assertFalse(old.exists());self.assertTrue(current.exists())
        self.assertEqual(self.receiver.bytes_used,2)
    def test_initialization_never_overwrites_keys(self):
        before=(self.host/'devices.enroll').read_bytes()
        with self.assertRaises(ValueError):server.initialize(self.host)
        self.assertEqual(before,(self.host/'devices.enroll').read_bytes())
    def test_http_migration_preserves_authorization_and_backup(self):
        old=dict(self.config,schema=1,certificate='old.pem',tls_key='old.key',encryption_private_key='retained-key')
        device=dict(self.enrollment,schema=1,endpoints=['https://10.205.103.120:10888'],certificate_sha256='f'*64,encryption_public_key='old-public')
        config_path=self.host/'collector-server.json';device_path=self.host/'devices.enroll'
        config_path.write_text(json.dumps(old));device_path.write_text(json.dumps(device))
        result=server.migrate_http(self.host)
        migrated=json.loads(config_path.read_text());enrollment=json.loads(device_path.read_text())
        self.assertTrue(result['changed']);self.assertEqual(migrated['schema'],2)
        self.assertEqual(enrollment['upload_token'],self.enrollment['upload_token'])
        self.assertEqual(enrollment['endpoints'],['http://10.205.103.120:10888'])
        self.assertNotIn('encryption_private_key',migrated)
        self.assertEqual(json.loads((self.host/'collector-server.json.v1-backup').read_text()),old)
        self.assertFalse(server.migrate_http(self.host)['changed'])


if __name__=='__main__':unittest.main(verbosity=2)
