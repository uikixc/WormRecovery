"""UI workflow checks with no real scan, process termination, or repair."""
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import modern_ui


class FakeCleaner:
    def __init__(self,**kwargs):
        self.cancel=threading.Event()
        self.count=0
        self.findings=[]
        self.events=[]
        self.errors=[]
        self.run=Path(tempfile.gettempdir())/'WormRecovery-UI-Test'
        self.emit=kwargs['emit']
        self.force_close=kwargs.get('force_close',False)
        self.restore_history=False
    def contain(self):return []
    def registry(self):return []
    def system_persistence(self):return {}
    def firewall(self):return []
    def scan(self,roots=None):
        self.count=4321
        self.findings=[{'kind':'infected_office','path':'C:/test/document.xlsm'},
                       {'kind':'review_office','path':'C:/test/legitimate.xlam'}]
        self.emit('测试扫描完成')
    def repair(self):
        self.events.append({'kind':'office_recovered'})
    def verify(self):
        self.findings=[r for r in self.findings if r['kind'].startswith('review_')]


class ModernUITests(unittest.TestCase):
    def test_unresponsive_update_check_does_not_hold_window_close(self):
        release=threading.Event();started=threading.Event()
        def check(version):
            started.set();release.wait(2)
            return {'available':False,'version':'1.8.3','private':False}
        try:
            with patch('app_update.check_update',side_effect=check):
                self.app.check_for_updates(True);self.assertTrue(started.wait(1))
                tick=[];self.app.root.after(0,lambda:tick.append(True));self.app.root.update()
                self.assertTrue(tick)
                with patch.object(self.app.root,'destroy',wraps=self.app.root.destroy) as destroy:
                    self.app.close()
                destroy.assert_called_once()
        finally:
            release.set();self.app.update_busy=False
            # tearDown still calls close; make that second close harmless.
            self.app.close=lambda:None

    def test_identified_tsco_remains_review_and_shows_content_basis(self):
        record={'kind':'review_binary','path':'C:/fixture/renamed.bin','reason':'TSCO 内容已识别，归属待核',
                'family_analysis':{'status':'identified','identifications':[{'identity':'TSCO_known_payload_container'}],
                                   'contained_payloads':[{'offset':512,'bytes':2048}]}}
        self.app.result_records=[record];self.app.select_filter('review')
        self.app.tree.selection_set('0');self.app.selected()
        text=self.app.selected_path.get()
        self.assertIn('4 条完整压缩流',text);self.assertIn('不判定父文件恶意',text)
        self.app.select_filter('confirmed');self.assertEqual(self.app.tree.get_children(),())

    def test_confirmed_carrier_displays_decoding_basis(self):
        record={'kind':'malware_component','path':'C:/fixture/anything.bin','reason':'已确认恶意代码',
                'family_analysis':{'status':'detected','detections':[],
                                   'decodings':[{'method':'png_prefix64_rc4'}]}}
        self.app.result_records=[record];self.app.select_filter('confirmed')
        self.app.tree.selection_set('0');self.app.selected()
        self.assertIn('已匹配恶意代码组合特征',self.app.selected_path.get())
        self.assertIn('已解密图片载荷',self.app.selected_path.get())

    def test_server_connection_button_checks_in_background_and_displays_route(self):
        result={'message':'日志服务器已连接 · 内网 · 上传授权有效。','routes':[
            {'route':'内网','endpoint':'http://10.205.103.120:10888','reachable':True,'authorization':'accepted','elapsed_ms':12},
            {'route':'外网','endpoint':'http://8.134.112.170:35981','reachable':False,'reason':'连接失败','elapsed_ms':30}]}
        with patch('diagnostic_client.check_connection',return_value=result):
            self.app.check_log_server();deadline=time.monotonic()+3
            while self.app.connection_busy and time.monotonic()<deadline:
                self.app.root.update();time.sleep(.01)
        self.assertFalse(self.app.connection_busy)
        self.assertIn('内网',self.app.connection_state.get())
        self.assertIn('上传授权有效',self.app.connection_state.get())
        self.assertIn('外网',self.app.log.get('1.0','end'))
        self.assertEqual(str(self.app.connection_button.cget('state')),'normal')

    def test_diagnostic_dialog_shows_scope_and_routes(self):
        self.app.diagnostic_settings();self.app.root.update()
        texts=[]
        def visit(widget):
            try:texts.append(str(widget.cget('text')))
            except Exception:pass
            for child in widget.winfo_children():visit(child)
        visit(self.app.root);combined='\n'.join(texts)
        for text in ('诊断资料收集','10.205.103.120:10888','8.134.112.170:35981','立即同步'):
            self.assertIn(text,combined)
        self.assertNotIn('导入采集配置',combined);self.assertNotIn('暂停自动提交',combined)

    def test_read_limit_is_visible_without_becoming_infection(self):
        record={'kind':'coverage_error','_coverage_error':True,'path':'C:/pagefile.sys',
                'category':'active_pagefile_unreadable','reason':'活动分页文件无法在线读取。',
                'action':'内容未检查。','error':'Permission denied'}
        self.app.result_records=[record]
        self.app.select_filter('errors')
        self.assertEqual(self.app.tree.item('0','values')[0],'读取受限')
        self.app.tree.selection_set('0');self.app.selected()
        self.assertIn('内容未检查',self.app.selected_path.get())
        self.assertIn('Permission denied',self.app.selected_path.get())
        self.app.select_filter('confirmed')
        self.assertEqual(self.app.tree.get_children(),())

    def test_parser_failure_after_read_is_not_labeled_read_permission_limit(self):
        record={'kind':'coverage_error','_coverage_error':True,'path':'C:/fixture.xlsx',
                'category':'document_analysis_failed','reason':'文件字节已经读取，后续解析未完成。',
                'error_details':{'source_bytes_read':True},'error':'inert process failure'}
        self.app.result_records=[record];self.app.select_filter('errors')
        self.assertEqual(self.app.tree.item('0','values')[0],'解析未完成')
        self.app.tree.selection_set('0');self.app.selected()
        self.assertIn('已成功读取',self.app.selected_path.get())
        self.assertEqual(modern_ui.coverage_state({'category':'inspection_process_start_failed'}),'组件启动失败')

    def test_secondary_results_have_distinct_visible_states(self):
        for result,state in (('detected','引擎检出'),('incomplete','分析未完成'),('suspicious','规则命中'),('no_known_match','无已知匹配')):
            with self.subTest(result=result):
                self.assertEqual(modern_ui.review_state({'secondary_analysis':{'status':result}}),state)

    def setUp(self):
        self.background_patch=patch('diagnostic_client.start_background');self.background_patch.start()
        self.app=modern_ui.ModernWindow(types.SimpleNamespace(VERSION='test',Cleaner=FakeCleaner,resolve_scan_scope=lambda **kwargs:{'roots':['C:/test'],'external_volumes':{},'excluded_roots':[]}))
        self.app.root.update()
    def tearDown(self):self.app.close();self.background_patch.stop()
    def test_background_update_check_does_not_disable_scan(self):
        a=self.app;release={'available':False,'version':'1.5.0','private':True}
        with patch('app_update.check_update',return_value=release):
            a.check_for_updates(automatic=True)
            a.launch('scan');self.wait()
            deadline=time.monotonic()+3
            while a.update_busy and time.monotonic()<deadline:
                a.root.update();time.sleep(.01)
        self.assertFalse(a.update_busy)
        self.assertEqual(a.metrics['files'].get(),'4,321')
        self.assertIn('1.5.0',a.update_state.get())

    def test_automatic_update_error_does_not_open_dialog(self):
        a=self.app;a.update_busy=True
        with patch.object(modern_ui.messagebox,'showinfo') as message:
            a.update_event('update_error',{'automatic':True,'message':'网络不可用'})
        message.assert_not_called();self.assertFalse(a.update_busy)
        self.assertIn('网络不可用',a.log.get('1.0','end'))

    def test_download_waits_for_active_file_task(self):
        a=self.app;a.busy=True
        payload={'path':'C:/update/WormRecovery.exe','info':{'manifest':{}}}
        a.update_event('update_downloaded',payload)
        self.assertEqual(a.update_pending_install,payload)
        self.assertIn('等待',a.update_state.get())
        a.busy=False

    def test_install_closes_after_current_event_callback(self):
        a=self.app
        with patch.object(modern_ui.sys,'frozen',True,create=True),patch.object(modern_ui.messagebox,'askyesno',return_value=True),patch('update_install.start_install') as install,patch.object(a.root,'after_idle') as idle:
            a.update_event('update_downloaded',{'path':'C:/update/WormRecovery.exe','info':{'manifest':{}}})
        install.assert_called_once();idle.assert_called_once_with(a.close)

    def test_manual_check_cancels_scheduled_startup_check(self):
        a=self.app;a.update_timer=a.root.after(60000,lambda:None);timer=a.update_timer
        with patch('app_update.check_update',return_value={'available':False,'version':'1.5.0'}):
            a.check_for_updates(automatic=True)
            deadline=time.monotonic()+3
            while a.update_busy and time.monotonic()<deadline:
                a.root.update();time.sleep(.01)
        self.assertNotIn(timer,a.root.tk.call('after','info'))
        self.assertIsNone(a.update_timer)
    def wait(self):
        deadline=time.monotonic()+3
        while self.app.busy and time.monotonic()<deadline:
            self.app.root.update();time.sleep(.02)
        self.assertFalse(self.app.busy)
    def test_scan_filter_repair_state_and_scope_invalidation(self):
        a=self.app
        self.assertIn('disabled',a.clean_button.state())
        a.launch('scan');self.wait()
        self.assertEqual(a.metrics['files'].get(),'4,321')
        self.assertEqual(a.metrics['confirmed'].get(),'1')
        self.assertEqual(a.metrics['review'].get(),'1')
        self.assertEqual(a.cleaner.operation['type'],'scan')
        self.assertFalse(a.cleaner.operation['mutations_allowed'])
        self.assertEqual(a.cleaner.events,[])
        self.assertNotIn('disabled',a.clean_button.state())
        a.select_filter('review')
        self.assertEqual(len(a.tree.get_children()),1)
        self.assertEqual(a.tree.item(a.tree.get_children()[0],'values')[0],'未确认感染')
        with patch.object(modern_ui.messagebox,'askokcancel',return_value=True),patch.object(modern_ui.ctypes.windll.shell32,'IsUserAnAdmin',return_value=True):
            a.launch('clean');self.wait()
        self.assertEqual(a.metrics['restored'].get(),'1')
        self.assertEqual(a.metrics['confirmed'].get(),'0')
        self.assertEqual(a.cleaner.operation['type'],'repair')
        self.assertTrue(a.cleaner.force_close)
        self.assertTrue(a.cleaner.restore_history)
        a.launch('scan');self.wait()
        a.scope.set('C:/different')
        self.assertIn('disabled',a.clean_button.state())
        self.assertFalse(a.scan_ready)
    def test_log_navigation_and_small_window_layout(self):
        a=self.app
        a.root.geometry('1000x760');a.root.update()
        self.assertGreater(a.tree.winfo_height(),60)
        self.assertLess(a.panel.winfo_rooty()+a.panel.winfo_height(),a.root.winfo_rooty()+a.root.winfo_height())
        self.assertEqual(set(a.scope_buttons),{'internal','removable','manual'})
        a.show_panel('log');a.root.update()
        self.assertTrue(a.log_frame.winfo_ismapped())
        self.assertFalse(a.results_frame.winfo_ismapped())
        a.append_log('中文日志与完整路径 C:/test')
        self.assertIn('中文日志',a.log.get('1.0','end'))
        a.show_panel('results');a.root.update()
        self.assertTrue(a.results_frame.winfo_ismapped())
    def test_scope_buttons_and_no_implementation_switches(self):
        a=self.app
        a.choose_scope('removable')
        self.assertEqual(a.scope_mode.get(),'removable')
        with patch.object(modern_ui.filedialog,'askdirectory',return_value='E:/reports'):
            a.choose_scope('manual')
        self.assertEqual(a.scope_mode.get(),'manual')
        self.assertEqual(a.scope.get(),'E:/reports')
        def widgets(parent):
            for child in parent.winfo_children():
                yield child
                yield from widgets(child)
        texts=[]
        for widget in widgets(a.root):
            if 'text' in widget.keys():texts.append(str(widget.cget('text')))
            self.assertNotIn('Checkbutton',widget.winfo_class())
        self.assertFalse(any('USB 样本' in t or '留空' in t for t in texts))
    def test_persistence_only_detection_allows_repair(self):
        self.app.cleaner=FakeCleaner(emit=lambda s:None)
        self.app.cleaner.events=[{'kind':'registry_inspection','hits':[{'name':'confirmed malicious startup'}]}]
        self.assertTrue(self.app.has_confirmed())
    def test_parser_failure_displays_reason(self):
        self.app.result_records=[{'kind':'review_office','path':'C:/test/document.xlsm','analysis_error':True,'reason':'文档解析未完成：测试异常'}]
        self.app.select_filter('all')
        self.app.render_results()
        values=self.app.tree.item(self.app.tree.get_children()[0],'values')
        self.assertEqual(values[0],'解析失败')
        self.assertIn('测试异常',values[1])
    def test_component_has_separate_filter_and_action_without_repair(self):
        c=FakeCleaner(emit=lambda s:None)
        item={'kind':'info_office','path':'C:/Office/SOLVER.XLAM','component':'规划求解加载项','reason':'已核对组件','action':'保留，无需删除。'}
        c.findings=[item];self.app.cleaner=c;self.app.result_records=[item]
        self.app.update_metrics()
        self.assertEqual(self.app.metrics['confirmed'].get(),'0')
        self.assertEqual(self.app.metrics['review'].get(),'0')
        self.assertFalse(self.app.has_confirmed())
        self.app.select_filter('review');self.assertEqual(len(self.app.tree.get_children()),0)
        self.app.select_filter('info');self.assertEqual(len(self.app.tree.get_children()),1)
        self.assertEqual(self.app.tree.item('0','values')[0],'保留，无需处理')
        self.app.tree.selection_set('0');self.app.selected()
        self.assertIn('无需删除',self.app.selected_path.get())
    def test_live_progress_shows_current_path_and_file_rate(self):
        c=FakeCleaner(emit=lambda s:None)
        c.count=500;c.scan_active=True;c.scan_started=time.monotonic()-5
        c.last_completed=time.monotonic()-6;c.current_path='C:/test/large.xlsm'
        self.app.cleaner=c;self.app.busy=True;self.app.started=c.scan_started
        self.app.root.after_cancel(self.app.timer)
        self.app.pump()
        self.assertIn('文件/秒',self.app.detail.get())
        self.assertIn('large.xlsm',self.app.detail.get())
        self.assertIn('当前项目处理',self.app.detail.get())
        self.app.busy=False

    def test_empty_document_shows_content_loss_instead_of_no_action(self):
        self.app.result_records=[{'kind':'info_document','path':'C:/docs/empty.docx',
            'data_integrity_issue':'empty_document','reason':'原有正文缺失','action':'需要历史原件或备份。'}]
        self.app.select_filter('all');self.app.render_results()
        self.assertEqual(self.app.tree.item('0','values')[0],'正文缺失')

    def test_review_progress_is_visible_after_file_count_stops(self):
        c=FakeCleaner(emit=lambda _:None);c.count=500;c.scan_active=False
        c.progress={'phase':'review','stage':'REA 程序结构分析','started':time.monotonic()-6,
                    'completed':2,'total':8,'timeout':25,'path':'C:/test/candidate.exe'}
        self.app.cleaner=c;self.app.busy=True;self.app.started=time.monotonic()-20
        self.app.root.after_cancel(self.app.timer);self.app.pump()
        self.assertEqual(self.app.status.get(),'正在离线复核')
        for text in ('2/8','25 秒','candidate.exe','文件遍历已结束'):
            self.assertIn(text,self.app.detail.get())
        self.assertEqual(self.app.metrics['files'].get(),'500')
        self.app.busy=False

    def test_stopping_review_keeps_stopping_status_visible(self):
        c=FakeCleaner(emit=lambda _:None)
        c.progress={'phase':'review','stage':'ClamAV 批量复核','started':time.monotonic(),
                    'completed':0,'total':5,'path':''}
        self.app.cleaner=c;self.app.busy=True;self.app.started=time.monotonic()
        self.app.stop();self.app.root.after_cancel(self.app.timer);self.app.pump()
        self.assertTrue(c.cancel.is_set());self.assertEqual(self.app.status.get(),'正在停止')
        self.app.busy=False


if __name__=='__main__':
    unittest.main(verbosity=2)
