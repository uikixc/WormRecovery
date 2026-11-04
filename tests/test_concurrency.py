"""Deterministic thread, backpressure and scanner equivalence tests."""
import hashlib
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scan_concurrency import FileScanner
import worm_recovery as w


class ConcurrentQueueTests(unittest.TestCase):
    def profiles(self,readers=4):return {'C:/':{'device':'disk-0','readers':readers}}
    def test_workers_overlap_but_results_are_collected_on_caller(self):
        barrier=threading.Barrier(2);caller=threading.get_ident();workers=set();accepted=[]
        def inspect(path,stat):
            workers.add(threading.get_ident());barrier.wait(timeout=3)
            return {'path':path}
        def accept(path,result,error):
            self.assertEqual(threading.get_ident(),caller);accepted.append((path,result,error))
        with FileScanner(inspect,accept,threading.Event(),self.profiles(),workers=2,batch_size=1) as scanner:
            for i in range(2):scanner.submit(str(i),None,'C:/')
        self.assertEqual(len(workers),2);self.assertEqual(len(accepted),2)
        self.assertTrue(all(row[2] is None for row in accepted))

    def test_queue_is_bounded_and_all_files_are_counted_once(self):
        rows=[]
        with FileScanner(lambda path,st:{'path':path},lambda path,result,error:rows.append(path),threading.Event(),self.profiles(),workers=2,batch_size=2) as scanner:
            for i in range(101):scanner.submit(str(i),None,'C:/')
        self.assertEqual(len(rows),101);self.assertEqual(len(set(rows)),101)
        self.assertLessEqual(scanner.peak_pending,scanner.queue_limit)

    def test_same_physical_hdd_partitions_share_one_reader(self):
        profiles={'C:/':{'device':'disk-0','readers':1},'F:/':{'device':'disk-0','readers':1}}
        active=0;peak=0;lock=threading.Lock();rows=[]
        def inspect(path,st):
            nonlocal active,peak
            with lock:active+=1;peak=max(peak,active)
            time.sleep(.005)
            with lock:active-=1
            return {}
        with FileScanner(inspect,lambda *row:rows.append(row),threading.Event(),profiles,workers=4,batch_size=1) as scanner:
            for i in range(12):scanner.submit(str(i),None,'C:/' if i%2 else 'F:/')
        self.assertEqual(peak,1);self.assertEqual(len(rows),12)

    def test_worker_failure_is_returned_as_error(self):
        def inspect(path,st):raise PermissionError('fixture denied')
        rows=[]
        with FileScanner(inspect,lambda *row:rows.append(row),threading.Event(),self.profiles(),workers=2,batch_size=1) as scanner:
            scanner.submit('file.exe',None,'C:/')
        self.assertEqual(rows,[('file.exe',None,'fixture denied')])

    def test_stop_drains_inflight_work_without_new_file_reads(self):
        cancel=threading.Event();seen=[];rows=[]
        def inspect(path,st):seen.append(path);cancel.set();return {}
        with FileScanner(inspect,lambda *row:rows.append(row),cancel,self.profiles(),workers=2,batch_size=4) as scanner:
            for i in range(40):scanner.submit(str(i),None,'C:/')
        self.assertTrue(cancel.is_set());self.assertLessEqual(len(seen),2)
        self.assertEqual(len(rows),len(seen));self.assertEqual(scanner.active,{})

    def test_changed_device_prevents_content_read(self):
        seen=[];rows=[]
        def validate(root):raise PermissionError('device changed')
        with FileScanner(lambda *args:seen.append(args),lambda *row:rows.append(row),threading.Event(),self.profiles(),workers=2,validate=validate,batch_size=1) as scanner:
            scanner.submit('file.exe',None,'C:/')
        self.assertEqual(seen,[]);self.assertEqual(rows[0][2],'device changed')

    def test_worker_range_is_validated(self):
        for value in (0,9,-1):
            with self.assertRaises(ValueError):FileScanner(None,None,threading.Event(),self.profiles(),workers=value)


class ScannerEquivalenceTests(unittest.TestCase):
    def test_serial_and_parallel_detection_match_without_file_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'scan';root.mkdir();fixture=b'Inert hash fixture; not executable'
            for i in range(75):(root/('file-%s.txt'%i)).write_text('keep')
            (root/'fixture.a3x').write_bytes(fixture)
            (root/'program.exe').write_bytes(b'Inert file; not a PE')
            arguments='/AutoIt3ExecuteScript C:/GoogleChrome/GoogleChrome.a3x'
            header=bytearray(76);header[:4]=bytes.fromhex('4c000000');header[4:20]=bytes.fromhex('0114020000000000c000000000000046');struct.pack_into('<I',header,20,32|128)
            (root/'fixture.lnk').write_bytes(header+struct.pack('<H',len(arguments))+arguments.encode('utf-16le'))
            before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
            profile={'device':'fixture-ssd','seek_penalty':False,'readers':4};results=[]
            with patch.object(w,'AUTOIT_A3X_SHA256',hashlib.sha256(fixture).hexdigest()),patch('scan_concurrency.storage_profile',return_value=profile):
                for workers in (1,4):
                    c=w.Cleaner(emit=lambda s:None);c.scan([str(root)],workers=workers)
                    results.append((c.count,sorted((x['kind'],x['path']) for x in c.findings),c.errors))
            self.assertEqual(results[0],results[1]);self.assertEqual(results[0][0],78)
            self.assertEqual({x[0] for x in results[0][1]},{'worm_script','malicious_shortcut'})
            self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()})


if __name__=='__main__':
    unittest.main(verbosity=2)
