"""Compile and execute only inert launcher fixtures; never research samples."""
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_runtime_launcher as builder
import runtime_identity

PYTHON = Path(__file__).resolve().parents[1]
COMPILER = Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')


class RuntimeIdentityTests(unittest.TestCase):
    def test_source_mode_ignores_launcher_environment(self):
        with patch.dict(os.environ, {'WORMRECOVERY_LAUNCHER_PATH':'C:/wrong.exe'}):
            self.assertEqual(runtime_identity.application_path(),Path(runtime_identity.__file__).resolve())

    def test_frozen_mode_rejects_runtime_outside_known_folder(self):
        with patch.object(runtime_identity.sys,'frozen',True,create=True),patch.dict(os.environ,{
                'WORMRECOVERY_RUNTIME_ROOT':'C:/untrusted/WormRecoveryRuntime/'+'a'*64,
                'WORMRECOVERY_LAUNCHER_PATH':'C:/wrong.exe','WORMRECOVERY_LAUNCHER_PID':str(os.getpid())}):
            self.assertEqual(runtime_identity.application_path(),Path(runtime_identity.sys.executable).resolve())


@unittest.skipUnless(os.name=='nt' and COMPILER.is_file() and ctypes.windll.shell32.IsUserAnAdmin(),
                     'Windows administrator and .NET Framework compiler required')
class RuntimeLauncherTests(unittest.TestCase):
    def test_cache_reuse_locks_and_full_hash_verification(self):
        cache_root=None
        with tempfile.TemporaryDirectory(prefix='wr-launcher-fixture-') as directory:
            temp=Path(directory);source=temp/'payload';source.mkdir();work=temp/'work'
            fixture=temp/'Fixture.cs'
            fixture.write_text(r'''using System; using System.IO; using System.Threading;
class Fixture { static int Main(string[] args) {
  Console.OutputEncoding = new System.Text.UTF8Encoding(false);
  Console.WriteLine("fixture:"+args[0]); Console.Out.Flush();
  Console.Error.WriteLine("inert-stderr");
  if(args[0]=="hold") { for(int i=0;i<200 && !File.Exists(args[1]);i++) Thread.Sleep(50); }
  return 0;
}}''',encoding='utf8')
            subprocess.run([str(COMPILER),'/nologo','/target:exe','/out:'+str(source/'WormRecovery.exe'),str(fixture)],check=True,capture_output=True)
            data=source/'data.bin';data.write_bytes((str(temp)+' inert fixture').encode())
            deep=source/('nested-'+'a'*45)/('nested-'+'b'*45)/('nested-'+'c'*45)/'deep.bin'
            deep.parent.mkdir(parents=True);deep.write_bytes(b'inert long-path payload')
            outer=builder.build_launcher(source,temp/'Portable.exe',work)
            identity=hashlib.sha256((work/'runtime-manifest.tsv').read_bytes()).hexdigest()
            known=ctypes.create_unicode_buffer(32768)
            self.assertEqual(ctypes.windll.shell32.SHGetFolderPathW(None,35,None,0,known),0)
            cache_root=Path(known.value)/'WormRecoveryRuntime'/identity
            try:
                for attempt in range(2):
                    result=subprocess.run([str(outer),'space 中文 quote" tail'+chr(92)],capture_output=True,timeout=30)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertIn(('fixture:space 中文 quote" tail'+chr(92)).encode('utf8'),result.stdout)
                    self.assertIn(b'inert-stderr',result.stderr)
                cached=cache_root/'data.bin';original=cached.read_bytes();stamp=cached.stat()
                process=subprocess.Popen([str(outer),'hold',str(temp/'done')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    self.assertIn(b'fixture:hold',process.stdout.readline())
                    with self.assertRaises(PermissionError):
                        with cached.open('r+b') as stream:stream.write(b'X')
                finally:
                    (temp/'done').touch();stdout,stderr=process.communicate(timeout=20)
                    self.assertEqual(process.returncode,0,stderr)
                cached.write_bytes(b'X'+original[1:]);os.utime(cached,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
                result=subprocess.run([str(outer),'probe'],capture_output=True,timeout=30)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn(b'fixture:',result.stdout)
                self.assertIn(b'verification failed',result.stderr)
            finally:
                # Only our digest-named fixture cache is removed, after its child exits.
                expected=(Path(known.value)/'WormRecoveryRuntime').resolve()
                if cache_root.exists():
                    self.assertEqual(cache_root.resolve().parent,expected)
                    self.assertEqual(cache_root.name,identity)
                    shutil.rmtree('\\\\?\\'+str(cache_root))


if __name__=='__main__':unittest.main()
