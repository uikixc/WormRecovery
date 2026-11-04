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
    def setUp(self):
        self.app=modern_ui.ModernWindow(types.SimpleNamespace(VERSION='test',Cleaner=FakeCleaner,resolve_scan_scope=lambda **kwargs:{'roots':['C:/test'],'external_volumes':{},'excluded_roots':[]}))
        self.app.root.update()
    def tearDown(self):self.app.close()
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
        self.assertNotIn('disabled',a.clean_button.state())
        a.select_filter('review')
        self.assertEqual(len(a.tree.get_children()),1)
        self.assertEqual(a.tree.item(a.tree.get_children()[0],'values')[0],'未确认感染')
        with patch.object(modern_ui.messagebox,'askokcancel',return_value=True),patch.object(modern_ui.ctypes.windll.shell32,'IsUserAnAdmin',return_value=True):
            a.launch('clean');self.wait()
        self.assertEqual(a.metrics['restored'].get(),'1')
        self.assertEqual(a.metrics['confirmed'].get(),'0')
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


if __name__=='__main__':
    unittest.main(verbosity=2)
