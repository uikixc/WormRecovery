import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from clamav_batch import OutputMonitor,batch_deadline,scan,verdict
from engine_process import run


class ClamavBatchTests(unittest.TestCase):
    def inputs(self,root,count):
        db=root/'clamdb';db.mkdir()
        for name in ('main.cvd','daily.cvd','bytecode.cvd'):(db/name).write_bytes(b'ClamAV:date:1:2:fixture')
        paths=[root/('file-%s.doc'%index) for index in range(count)]
        for index,path in enumerate(paths):path.write_text('inert '+str(index))
        return paths

    def test_total_deadline_is_not_mistaken_for_per_file_timeout(self):
        self.assertGreater(batch_deadline(73),73*20)
        self.assertGreater(batch_deadline(73),batch_deadline(3))

    def test_partial_timeout_keeps_success_and_retries_only_unfinished_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=self.inputs(root,3);calls=[];events=[]
            def runner(command,**options):
                listing=Path(next(value.split('=',1)[1] for value in command if value.startswith('--file-list=')))
                selected=listing.read_text().splitlines();calls.append(selected)
                if len(calls)==1:
                    options['stdout'].write((str(paths[0])+': OK\n'+str(paths[1])+': Synthetic.Fixture FOUND\n'+'Scanning '+str(paths[2])+'\n').encode());options['stdout'].flush()
                    options['on_poll']()
                    raise subprocess.TimeoutExpired('inert engine',1)
                self.assertEqual(selected,[str(paths[2])])
                options['stdout'].write((str(paths[2])+': OK\n').encode())
                return SimpleNamespace(returncode=0)
            rows,_=scan(paths,root,lambda _:root/'engine',root,runner,{},progress=events.append)
            self.assertEqual([rows[str(path)]['status'] for path in paths],['no_match','detected','no_match'])
            self.assertEqual(len(calls),2);self.assertTrue(events)
            self.assertEqual(rows[str(paths[0])]['execution']['attempts'][0]['status'],'incomplete')

    def test_unrecoverable_last_input_does_not_discard_other_results(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=self.inputs(root,2)
            def runner(command,**options):
                options['stdout'].write((str(paths[0])+': OK\n').encode())
                raise subprocess.TimeoutExpired('inert engine',1)
            rows,_=scan(paths,root,lambda _:root/'engine',root,runner,{})
            self.assertEqual(rows[str(paths[0])]['status'],'no_match')
            self.assertEqual(rows[str(paths[1])]['status'],'incomplete')

    def test_no_progress_does_not_trigger_endless_database_reloads(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=self.inputs(root,2);calls=[]
            def runner(command,**options):calls.append(command);raise subprocess.TimeoutExpired('inert engine',1)
            rows,_=scan(paths,root,lambda _:root/'engine',root,runner,{})
            self.assertEqual(len(calls),1);self.assertTrue(all(row['status']=='incomplete' for row in rows.values()))

    def test_zero_bytes_are_independent_of_engine_startup_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=self.inputs(root,2);paths[0].write_bytes(b'')
            def runner(command,**options):raise OSError('inert startup failure')
            rows,_=scan(paths,root,lambda _:root/'engine',root,runner,{})
            self.assertEqual(rows[str(paths[0])]['status'],'no_content')
            self.assertFalse(rows[str(paths[0])]['engine_invoked'])
            self.assertEqual(rows[str(paths[1])]['status'],'incomplete')

    def test_identical_bytes_and_extension_share_one_verified_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=self.inputs(root,2);paths[1].write_bytes(paths[0].read_bytes())
            def runner(command,**options):
                listing=Path(next(value.split('=',1)[1] for value in command if value.startswith('--file-list=')))
                self.assertEqual(listing.read_text().splitlines(),[str(paths[0])])
                options['stdout'].write((str(paths[0])+': OK\n').encode());return SimpleNamespace(returncode=0)
            rows,_=scan(paths,root,lambda _:root/'engine',root,runner,{})
            self.assertEqual(rows[str(paths[1])]['status'],'no_match');self.assertEqual(rows[str(paths[1])]['identical_inputs'],2)

    def test_monitor_accepts_only_exact_inputs_and_complete_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'input';log=root/'output';events=[]
            log.write_bytes((str(path)+'-fake: OK\n'+str(path)+': O').encode())
            monitor=OutputMonitor(log,[path],events.append);monitor.poll()
            self.assertEqual(monitor.messages,{})
            with log.open('ab') as sink:sink.write(b'K\n')
            monitor.poll();self.assertEqual(monitor.messages[str(path)],['OK'])
            self.assertEqual(events[-1]['completed'],1)

    def test_limits_error_and_real_detection_are_never_cleared(self):
        self.assertEqual(verdict(['Heuristics.Limits.Exceeded.MaxScanTime FOUND'],True,None)['status'],'incomplete')
        self.assertEqual(verdict(['OK','inert ERROR'],True,None)['status'],'incomplete')
        self.assertEqual(verdict(['Heuristics.Limits.Exceeded.MaxScanTime FOUND','Fixture.Test FOUND'],True,None)['status'],'detected')

    def test_live_monitor_retains_results_when_owned_worker_is_stopped(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'inert.doc';output=root/'output';events=[]
            monitor=OutputMonitor(output,[path],events.append)
            code='import sys,time;print(sys.argv[1]+": OK",flush=True);time.sleep(20)'
            with output.open('wb') as sink,self.assertRaises(subprocess.TimeoutExpired):
                run([sys.executable,'-c',code,str(path)],stdout=sink,timeout=1,on_poll=monitor.poll)
            monitor.poll(final=True)
            self.assertEqual(monitor.messages[str(path)],['OK']);self.assertEqual(events[-1]['completed'],1)


if __name__=='__main__':unittest.main()
