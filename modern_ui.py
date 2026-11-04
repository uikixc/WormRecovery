"""Dependency-free desktop front end. Recovery decisions stay in the engine."""
import collections
import ctypes
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from office_triage import is_confirmed

BG='#F3F6FA'
NAV='#101C30'
INK='#18283F'
MUTED='#68788D'
LINE='#E4EAF1'
ACCENT='#087F8C'
FONT='Microsoft YaHei UI'
LABELS={
    'infected_office':'Excel 宏感染', 'infected_executable':'程序被包裹',
    'malicious_shortcut':'恶意快捷方式', 'worm_payload':'病毒载荷',
    'worm_script':'恶意 AutoIt 脚本', 'worm_runtime':'病毒缓存',
    'worm_hook':'病毒组件', 'worm_residue':'已确认家族残留', 'review_office':'Office 活动内容', 'info_office':'已核对的 Office 组件',
    'review_autoit':'AutoIt 脚本','review_script':'脚本行为','review_binary':'程序行为'}


def review_state(record):
    secondary=record.get('secondary_analysis',{})
    if secondary.get('status')=='detected':return '引擎检出'
    if record.get('analysis_error'):return '解析失败'
    if secondary.get('status')=='incomplete':return '分析未完成'
    if secondary.get('status')=='suspicious':return '规则命中'
    if secondary.get('status')=='no_known_match':return '无已知匹配'
    return '未确认感染'


class ModernWindow:
    def __init__(self,engine):
        self.engine=engine
        self.root=tk.Tk()
        self.root.title('WormRecovery · 蠕虫清理与原位恢复')
        self.root.configure(bg=BG)
        self.root.geometry('1160x850')
        self.root.minsize(1000,760)
        self.queue=queue.Queue()
        self.stop_requested=threading.Event()
        self.cleaner=None
        self.busy=False
        self.scan_ready=False
        self.generation=0
        self.started=0
        self.filter='all'
        self.displayed=0
        self.result_records=[]
        self.scope=tk.StringVar()
        self.scope_mode=tk.StringVar(value='internal')
        self.scope_description=tk.StringVar(value='本机全部内置磁盘')
        self.status=tk.StringVar(value='准备就绪')
        self.detail=tk.StringVar(value='请选择扫描范围，完成检测后执行修复。')
        self.elapsed=tk.StringVar(value='等待开始')
        self.metrics={k:tk.StringVar(value='—') for k in ('files','confirmed','review','restored')}
        self.scope.trace_add('write',self.scope_changed)
        self.style()
        self.build()
        self.root.protocol('WM_DELETE_WINDOW',self.close)
        self.timer=self.root.after(150,self.pump)

    def style(self):
        self.root.option_add('*Font',(FONT,10))
        s=ttk.Style(self.root)
        s.theme_use('clam')
        s.configure('.',font=(FONT,10),background=BG,foreground=INK)
        s.configure('Primary.TButton',background=ACCENT,foreground='white',borderwidth=0,
                    padding=(22,12),font=(FONT,10,'bold'))
        s.map('Primary.TButton',background=[('disabled','#C6D0DB'),('active','#066773')],
              foreground=[('disabled','#F7FAFC')])
        s.configure('Secondary.TButton',background='#E9EFF5',foreground=INK,borderwidth=0,padding=(18,12))
        s.map('Secondary.TButton',background=[('disabled','#F0F3F7'),('active','#DBE5EF')],
              foreground=[('disabled','#97A4B4')])
        s.configure('Small.TButton',background='#EEF3F8',foreground=INK,borderwidth=0,padding=(12,8))
        s.map('Small.TButton',background=[('active','#DEE8F1')])
        s.configure('Scope.TEntry',padding=(10,9),bordercolor=LINE,lightcolor=LINE,
                    darkcolor=LINE,fieldbackground='#F8FAFC',foreground=INK)
        s.configure('Option.TCheckbutton',background='white',foreground=INK,padding=(0,1))
        s.map('Option.TCheckbutton',background=[('active','white')],foreground=[('disabled','#A2ACB9')])
        s.configure('Modern.Horizontal.TProgressbar',background=ACCENT,troughcolor='#E7EEF4',
                    bordercolor='#E7EEF4',lightcolor=ACCENT,darkcolor=ACCENT,thickness=5)
        s.configure('Result.Treeview',background='white',fieldbackground='white',foreground=INK,
                    borderwidth=0,rowheight=35,font=(FONT,9))
        s.configure('Result.Treeview.Heading',background='#F5F8FB',foreground=MUTED,
                    borderwidth=0,padding=(10,8),font=(FONT,9,'bold'))
        s.map('Result.Treeview',background=[('selected','#DEEFF0')],foreground=[('selected',INK)])
        s.configure('Modern.Vertical.TScrollbar',background='#D6E0EB',troughcolor='white',
                    borderwidth=0,arrowsize=12)

    def label(self,parent,text,**kwargs):
        try:background=parent.cget('bg')
        except tk.TclError:background='white'
        return tk.Label(parent,text=text,bg=kwargs.pop('bg',background),
                        fg=kwargs.pop('fg',INK),font=kwargs.pop('font',(FONT,10)),**kwargs)

    def build(self):
        sidebar=tk.Frame(self.root,bg=NAV,width=192)
        sidebar.pack(side='left',fill='y')
        sidebar.pack_propagate(False)
        mark=tk.Canvas(sidebar,width=50,height=50,bg=NAV,highlightthickness=0)
        mark.pack(anchor='w',padx=25,pady=(30,12))
        mark.create_polygon(25,3,44,10,42,29,35,41,25,48,15,41,8,29,6,10,fill='#158D9A',outline='')
        mark.create_line(16,25,23,32,35,18,fill='white',width=3,capstyle='round',joinstyle='round')
        self.label(sidebar,'WormRecovery',fg='white',font=('Segoe UI',17,'bold')).pack(anchor='w',padx=24)
        self.label(sidebar,'文件恢复工作台',fg='#9DADC2',font=(FONT,10)).pack(anchor='w',padx=25,pady=(6,28))
        self.nav_scan=tk.Button(sidebar,text='  扫描与恢复',anchor='w',command=lambda:self.show_panel('results'),
            bg='#1E344C',fg='#E8F5F6',activebackground='#29465F',activeforeground='white',
            relief='flat',bd=0,padx=18,pady=12,font=(FONT,10,'bold'),cursor='hand2')
        self.nav_scan.pack(fill='x',padx=12,pady=4)
        self.nav_log=tk.Button(sidebar,text='  处理日志',anchor='w',command=lambda:self.show_panel('log'),
            bg=NAV,fg='#ACBED3',activebackground='#1E344C',activeforeground='white',
            relief='flat',bd=0,padx=18,pady=12,font=(FONT,10),cursor='hand2')
        self.nav_log.pack(fill='x',padx=12,pady=4)
        bottom=tk.Frame(sidebar,bg=NAV)
        bottom.pack(side='bottom',fill='x',padx=24,pady=24)
        self.label(bottom,'本地处理 · '+self.engine.VERSION,fg='#8094AD',font=(FONT,8)).pack(anchor='w')

        main=tk.Frame(self.root,bg=BG)
        main.pack(side='left',fill='both',expand=True,padx=28,pady=24)
        top=tk.Frame(main,bg=BG)
        top.pack(fill='x')
        self.label(top,'文件安全检测与原位恢复',font=(FONT,22,'bold')).pack(side='left')
        self.label(top,'管理员模式' if ctypes.windll.shell32.IsUserAnAdmin() else '只读扫描可用',
                   bg='#E0EFED',fg='#267268',font=(FONT,9),padx=12,pady=7).pack(side='right',padx=(10,0))
        self.label(main,'检测恶意文件与感染文档，验证修复结果并生成处理报告。',fg=MUTED).pack(anchor='w',pady=(7,19))

        cards=tk.Frame(main,bg=BG)
        cards.pack(fill='x',pady=(0,18))
        specs=[('files','已扫描文件',INK),('confirmed','确认感染','#BB5044'),
               ('review','待核查项','#9B701F'),('restored','已恢复文件',ACCENT)]
        for i,(key,title,color) in enumerate(specs):
            cards.grid_columnconfigure(i,weight=1,uniform='cards')
            card=tk.Frame(cards,bg='white',highlightbackground=LINE,highlightthickness=1,padx=17,pady=12)
            card.grid(row=0,column=i,sticky='nsew',padx=(0,10 if i<3 else 0))
            self.label(card,title,fg=MUTED,font=(FONT,9)).pack(anchor='w')
            tk.Label(card,textvariable=self.metrics[key],bg='white',fg=color,font=('Segoe UI',24,'bold')).pack(anchor='w',pady=(4,0))

        setup=tk.Frame(main,bg='white',highlightbackground=LINE,highlightthickness=1,padx=18,pady=15)
        setup.pack(fill='x',pady=(0,16))
        self.label(setup,'扫描范围',font=(FONT,10,'bold')).pack(anchor='w')
        row=tk.Frame(setup,bg='white')
        row.pack(fill='x',pady=(9,5))
        self.scope_buttons={}
        for key,title in [('internal','本机全盘'),('removable','可移动设备'),('manual','手动选择')]:
            button=ttk.Button(row,text=title,style='Primary.TButton' if key=='internal' else 'Secondary.TButton',command=lambda k=key:self.choose_scope(k))
            button.pack(side='left',padx=(0,10));self.scope_buttons[key]=button
        tk.Label(setup,textvariable=self.scope_description,bg='white',fg=MUTED,font=(FONT,9),anchor='w',wraplength=820).pack(fill='x',pady=(7,2))

        actions=tk.Frame(main,bg=BG)
        actions.pack(fill='x')
        self.scan_button=ttk.Button(actions,text='开始检测',style='Primary.TButton',command=lambda:self.launch('scan'))
        self.scan_button.pack(side='left')
        self.clean_button=ttk.Button(actions,text='修复并原位恢复',style='Secondary.TButton',command=lambda:self.launch('clean'),state='disabled')
        self.clean_button.pack(side='left',padx=10)
        self.stop_button=ttk.Button(actions,text='停止',style='Secondary.TButton',command=self.stop,state='disabled')
        self.stop_button.pack(side='left')
        self.report_button=ttk.Button(actions,text='打开报告  ↗',style='Small.TButton',command=self.open_report,state='disabled')
        self.report_button.pack(side='right')

        progressbox=tk.Frame(main,bg=BG)
        progressbox.pack(fill='x',pady=(16,14))
        row=tk.Frame(progressbox,bg=BG)
        row.pack(fill='x')
        tk.Label(row,textvariable=self.status,bg=BG,fg=INK,font=(FONT,10,'bold')).pack(side='left')
        tk.Label(row,textvariable=self.elapsed,bg=BG,fg=MUTED,font=('Segoe UI',9)).pack(side='right')
        tk.Label(progressbox,textvariable=self.detail,bg=BG,fg=MUTED,font=(FONT,9),anchor='w').pack(fill='x',pady=(5,8))
        self.progress=ttk.Progressbar(progressbox,style='Modern.Horizontal.TProgressbar',mode='indeterminate')
        self.progress.pack(fill='x')

        self.panel=tk.Frame(main,bg='white',highlightbackground=LINE,highlightthickness=1)
        self.panel.pack(fill='both',expand=True)
        toolbar=tk.Frame(self.panel,bg='white',padx=15,pady=10)
        toolbar.pack(fill='x')
        self.panel_title=self.label(toolbar,'扫描结果',font=(FONT,11,'bold'))
        self.panel_title.pack(side='left')
        self.filters={}
        for key,title in [('info','组件说明'),('review','需进一步检查'),('confirmed','确认感染'),('all','全部')]:
            b=tk.Button(toolbar,text=title,command=lambda k=key:self.select_filter(k),bg='white',fg=MUTED,
                        activebackground='#E9F3F4',activeforeground=ACCENT,relief='flat',bd=0,padx=10,pady=3,cursor='hand2')
            b.pack(side='right',padx=2)
            self.filters[key]=b
        self.filters['all'].configure(bg='#E4F1F2',fg=ACCENT)
        self.body=tk.Frame(self.panel,bg='white')
        self.body.pack(fill='both',expand=True)
        self.results_frame=tk.Frame(self.body,bg='white')
        self.results_frame.pack(fill='both',expand=True)
        table_frame=tk.Frame(self.results_frame,bg='white')
        table_frame.pack(fill='both',expand=True)
        self.tree=ttk.Treeview(table_frame,style='Result.Treeview',columns=('state','kind','path'),show='headings',selectmode='browse')
        for name,title,width in [('state','处理状态',105),('kind','发现类型',140),('path','文件位置',500)]:
            self.tree.heading(name,text=title,anchor='w')
            self.tree.column(name,width=width,minwidth=80,stretch=name=='path',anchor='w')
        scrollbar=ttk.Scrollbar(table_frame,orient='vertical',command=self.tree.yview,style='Modern.Vertical.TScrollbar')
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right',fill='y')
        self.tree.pack(fill='both',expand=True)
        self.tree.tag_configure('review',foreground='#927020')
        self.tree.tag_configure('confirmed',foreground='#AA453B')
        self.tree.tag_configure('info',foreground='#267268')
        self.tree.bind('<<TreeviewSelect>>',self.selected)
        self.empty=self.label(self.tree,'等待开始检测\n确认感染、待核查项会分别列出',fg=MUTED,font=(FONT,10),justify='center')
        self.empty.place(relx=.5,rely=.5,anchor='center')
        self.selected_path=tk.StringVar(value='选择结果可查看完整路径。')
        tk.Label(self.results_frame,textvariable=self.selected_path,bg='#F8FAFC',fg=MUTED,
                 anchor='w',justify='left',wraplength=820,padx=14,pady=8,font=(FONT,8)).pack(fill='x')
        self.log_frame=tk.Frame(self.body,bg='white')
        self.log=tk.Text(self.log_frame,wrap='word',relief='flat',bd=0,bg='white',fg='#43536A',
                         insertbackground=ACCENT,font=('Consolas',9),padx=16,pady=10,state='disabled')
        logbar=ttk.Scrollbar(self.log_frame,orient='vertical',command=self.log.yview,style='Modern.Vertical.TScrollbar')
        logbar.pack(side='right',fill='y')
        self.log.configure(yscrollcommand=logbar.set)
        self.log.pack(fill='both',expand=True)
        self.label(main,'未识别的宏、访问失败及未覆盖范围将列入报告。',fg=MUTED,font=(FONT,8)).pack(anchor='w',pady=(11,0))

    def scope_changed(self,*_):
        if self.busy:return
        if self.scan_ready:
            self.scan_ready=False
            self.clean_button.configure(state='disabled')
            self.detail.set('扫描范围已改变，请重新扫描后再修复。')

    def browse(self):
        path=filedialog.askdirectory(parent=self.root,title='选择扫描位置')
        if path:
            self.scope_mode.set('manual');self.scope.set(path);self.scope_description.set(path)
        return bool(path)

    def choose_scope(self,key):
        if self.busy:return
        if key=='manual' and not self.browse():return
        if key!='manual':
            self.scope_mode.set(key);self.scope.set('')
            self.scope_description.set('本机全部内置磁盘' if key=='internal' else '所有已连接的可移动设备及其全部盘符')
        self.scope_changed()
        for k,button in self.scope_buttons.items():button.configure(style='Primary.TButton' if k==self.scope_mode.get() else 'Secondary.TButton')

    def show_panel(self,name):
        self.results_frame.pack_forget()
        self.log_frame.pack_forget()
        (self.log_frame if name=='log' else self.results_frame).pack(fill='both',expand=True)
        self.panel_title.configure(text='处理日志' if name=='log' else '扫描结果')
        self.nav_scan.configure(bg=NAV if name=='log' else '#1E344C')
        self.nav_log.configure(bg='#1E344C' if name=='log' else NAV)
        for b in self.filters.values():
            if name=='log':b.pack_forget()
        if name!='log':
            for key in ('info','review','confirmed','all'):self.filters[key].pack(side='right',padx=2)

    def select_filter(self,key):
        self.filter=key
        self.show_panel('results')
        for k,b in self.filters.items():b.configure(bg='#E4F1F2' if k==key else 'white',fg=ACCENT if k==key else MUTED)
        self.render_results()

    def append_log(self,text):
        self.log.configure(state='normal')
        self.log.insert('end',text+'\n')
        if int(self.log.index('end-1c').split('.')[0])>2500:self.log.delete('1.0','250.0')
        self.log.see('end')
        self.log.configure(state='disabled')

    def selected(self,*_):
        selected=self.tree.selection()
        if selected:
            record=self.result_records[int(selected[0])]
            text=record['path']
            for key in ('reason','action','assessment_limit'):
                if record.get(key):text+='\n'+record[key]
            secondary=record.get('secondary_analysis',{})
            if secondary:
                names={'clamav':'ClamAV','yara_x':'YARA-X','autoit':'AutoIt 提取','xlm':'XLM 模拟','capa':'capa','rea':'REA'}
                statuses={'analyzed':'已分析','no_match':'未命中当前病毒库','detected':'引擎检出','incomplete':'未完成','unsupported':'格式不支持'}
                text+='\n离线复核：'+'；'.join(names[k]+' '+statuses.get(v.get('status'), '已执行规则检查') for k,v in secondary.items() if k in names and isinstance(v,dict))
                if secondary.get('clamav',{}).get('detections'):text+='\n检出名称：'+'、'.join(secondary['clamav']['detections'])
                if record.get('analysis_incomplete_engines'):text+='\n未完成引擎：'+ '、'.join(record['analysis_incomplete_engines'])
                for key in ('autoit','xlm','capa','rea'):
                    result=secondary.get(key,{})
                    if result.get('reason'):text+='\n'+names[key]+'：'+result['reason'][:220]
            self.selected_path.set(text)

    def set_busy(self,busy):
        self.busy=busy
        self.scan_button.configure(state='disabled' if busy else 'normal')
        self.clean_button.configure(state='normal' if not busy and self.scan_ready and self.has_confirmed() else 'disabled')
        self.stop_button.configure(state='normal' if busy else 'disabled')
        for widget in self.scope_buttons.values():widget.configure(state='disabled' if busy else 'normal')
        if busy:self.progress.start(14)
        else:self.progress.stop();self.progress['value']=0

    def has_confirmed(self):
        if not self.cleaner:return False
        if any(is_confirmed(r) for r in self.cleaner.findings):return True
        for event in self.cleaner.events:
            if event['kind']=='process_inspection' and event.get('processes'):return True
            if event['kind']=='registry_inspection' and event.get('hits'):return True
            if event['kind']=='firewall_inspection' and any(x.get('enabled')=='True' for x in event.get('rules',[])):return True
            if event['kind']=='system_persistence' and any((event.get('result') or {}).get(k) for k in ('tasks','services','wmi')):return True
        return False

    def launch(self,mode):
        if self.busy:return
        if mode=='clean' and not self.scan_ready:return
        if mode=='clean':
            if not ctypes.windll.shell32.IsUserAnAdmin():
                messagebox.showerror('需要管理员权限','请以管理员身份运行。',parent=self.root);return
            text='系统将备份已确认的感染文件，并执行原位修复。\n\n将关闭占用相关文件的应用，未保存内容可能丢失；存在可验证的同路径历史原件时优先恢复，当前内容将保留备份。'
            if not messagebox.askokcancel('开始原位恢复',text,parent=self.root):return
        selected=self.scope.get().strip()
        scope_mode=self.scope_mode.get()
        self.generation+=1
        generation=self.generation
        self.started=time.monotonic()
        self.stop_requested.clear()
        self.scan_ready=False
        if mode=='scan':
            self.cleaner=None
            self.result_records=[]
            self.render_results()
            for metric in self.metrics.values():metric.set('0')
        self.status.set('正在检测' if mode=='scan' else '正在修复')
        self.detail.set('正在识别扫描范围并执行文件检测。' if mode=='scan' else '正在备份、验证并修复感染文件。')
        self.set_busy(True)
        def output(text):self.queue.put((generation,'log',text))
        def worker():
            try:
                if mode=='scan':
                    scope=self.engine.resolve_scan_scope(mode=scope_mode,manual=[selected] if scope_mode=='manual' else None)
                    c=self.engine.Cleaner(emit=output,force_close=True,restore_history=True,external_volumes=scope['external_volumes'],excluded_roots=scope['excluded_roots'])
                    self.cleaner=c
                    c.scope_summary=scope
                    if self.stop_requested.is_set():c.cancel.set()
                    output('扫描位置：'+'、'.join(scope['roots']))
                    if not c.cancel.is_set():c.contain();c.registry();c.system_persistence();c.firewall()
                    c.scan(scope['roots'])
                else:
                    c=self.cleaner
                    c.cancel.clear();c.force_close=True;c.restore_history=True
                    c.repair()
                    self.queue.put((generation,'phase','正在复扫'))
                    c.verify()
                self.queue.put((generation,'done',mode))
            except Exception as ex:self.queue.put((generation,'error',str(ex)))
        threading.Thread(target=worker,daemon=True).start()

    def update_metrics(self):
        c=self.cleaner
        if not c:return
        findings=list(c.findings)
        self.metrics['files'].set(format(c.count,','))
        self.metrics['confirmed'].set(str(sum(is_confirmed(x) for x in findings)))
        self.metrics['review'].set(str(sum(x['kind'].startswith('review_') for x in findings)))
        restored=sum(e['kind'] in ('office_recovered','executable_recovered') for e in list(c.events))
        self.metrics['restored'].set(str(restored))

    def render_results(self):
        selected=self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        visible=0
        for i,r in enumerate(self.result_records):
            review=r['kind'].startswith('review_')
            informational=r['kind'].startswith('info_')
            if self.filter=='review' and not review or self.filter=='confirmed' and not is_confirmed(r) or self.filter=='info' and not informational:continue
            state='保留，无需处理' if informational else review_state(r) if review else '待修复'
            category=LABELS.get(r['kind'],r['kind'])
            if review and r.get('reason'):category+='：'+r['reason']
            if informational:category=r.get('component',category)
            self.tree.insert('',tk.END,iid=str(i),values=(state,category,r['path']),tags=('info' if informational else 'review' if review else 'confirmed',))
            visible+=1
        if visible:self.empty.place_forget()
        else:
            self.empty.configure(text='当前筛选条件下无记录' if self.result_records else '暂无检测记录\n检测完成后显示处理结果')
            self.empty.place(relx=.5,rely=.5,anchor='center')

    def pump(self):
        try:
            for _ in range(200):
                generation,kind,payload=self.queue.get_nowait()
                if generation!=self.generation:continue
                if kind=='log':self.append_log(payload)
                elif kind=='phase':self.status.set(payload);self.detail.set('重新检查文件和已知持久化位置，确认是否还有残留。')
                elif kind=='error':
                    if self.cleaner:
                        try:self.cleaner.save();self.report_button.configure(state='normal')
                        except Exception:pass
                    self.set_busy(False);self.status.set('操作未完成');self.detail.set(payload)
                    self.append_log('未完成：'+payload)
                    messagebox.showerror('操作未完成',payload,parent=self.root)
                elif kind=='done':
                    c=self.cleaner
                    self.scan_ready=payload=='scan' and not c.cancel.is_set()
                    self.result_records=list(c.findings)
                    self.render_results()
                    self.set_busy(False)
                    self.report_button.configure(state='normal')
                    confirmed=sum(is_confirmed(r) for r in c.findings)
                    review_count=sum(r['kind'].startswith('review_') for r in c.findings)
                    info_count=sum(r['kind'].startswith('info_') for r in c.findings)
                    if c.cancel.is_set():self.status.set('已停止');self.detail.set('已完成的文件事务已保存；重新扫描后再修复。')
                    elif payload=='scan':
                        self.status.set('检测完成')
                        self.detail.set('确认感染 %s 项，未确认文件 %s 项，已核对组件 %s 项，检查异常 %s 项。'%(confirmed,review_count,info_count,len(c.errors)))
                    else:
                        complete=(getattr(c,'verification',None) or {}).get('known_family_clear',False)
                        self.status.set('修复与复核完成' if complete else '已执行修复，存在未完成检查')
                        self.detail.set('确认残留 %s 项；未确认文件 %s 项；已核对组件 %s 项无需删除；检查异常 %s 项。'%(confirmed,review_count,info_count,len(c.errors)))
                    self.append_log('报告：'+str(c.run/'report.json'))
        except queue.Empty:pass
        self.update_metrics()
        if self.busy:
            elapsed=int(time.monotonic()-self.started)
            self.elapsed.set('%02d:%02d 已用时'%(elapsed//60,elapsed%60))
            c=self.cleaner
            if c and getattr(c,'scan_active',False):
                duration=max(.001,time.monotonic()-c.scan_started)
                pending=max(0,int(time.monotonic()-c.last_completed))
                text='已检查 %s 个文件 · 平均 %s 文件/秒'%(format(c.count,','),format(int(c.count/duration),','))
                workers=getattr(c,'scan_workers',1)
                if workers>1:text+=' · %s 个扫描线程'%workers
                if pending>=5:text+=' · 当前项目处理已用 %s 秒'%pending
                scanner=getattr(c,'file_scanner',None)
                path=(scanner.current() if scanner else '') or getattr(c,'current_path','')
                self.detail.set(text+' · '+(path if len(path)<=85 else '…'+path[-84:]))
        elif self.started:
            value=self.elapsed.get().replace(' 已用时','')
            self.elapsed.set(value+' 已结束' if '已结束' not in value else value)
        self.timer=self.root.after(150,self.pump)

    def stop(self):
        self.stop_requested.set()
        if self.cleaner:self.cleaner.cancel.set()
        self.status.set('正在停止')
        self.detail.set('等待当前文件事务完成，已完成的结果会保存。')

    def open_report(self):
        if self.cleaner:os.startfile(str(self.cleaner.run))

    def close(self):
        if self.busy:
            self.stop()
            self.detail.set('正在停止；请等待当前文件事务完成后再关闭。')
        else:
            self.root.after_cancel(self.timer)
            self.root.destroy()


def run(engine):
    try:ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (OSError,AttributeError):pass
    app=ModernWindow(engine)
    app.root.mainloop()
