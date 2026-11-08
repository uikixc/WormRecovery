"""Build a single-file launcher around an immutable, hashed onedir runtime."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import zipfile


def create_payload(source, output, *, optional=False):
    source=Path(source).resolve();output=Path(output);output.mkdir(parents=True,exist_ok=True)
    files=[]
    for path in sorted(source.rglob('*')):
        if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:
            raise ValueError('Runtime payload must not contain reparse points: '+str(path))
        if path.is_file():
            relative=path.relative_to(source).as_posix()
            parts=relative.split('/')
            engine=len(parts)>2 and parts[:2]==['_internal','engines']
            extra=engine and parts[2] not in ('analysis','WormRecovery-CLI.exe','manifest.json')
            shared=engine and parts[2]=='manifest.json'
            if optional and not (extra or shared):continue
            if not optional and extra:continue
            if any(c in relative for c in '\t\r\n') or ':' in relative:raise ValueError('Invalid payload name')
            with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            files.append((relative,path.stat().st_size,digest,path))
    if not files and not optional:raise ValueError('Runtime payload is empty')
    prefix='optional' if optional else 'runtime'
    manifest=output/(prefix+'-manifest.tsv')
    manifest.write_text(''.join(f'{digest}\t{size}\t{name}\n' for name,size,digest,path in files),encoding='utf8',newline='\n')
    archive=output/(prefix+'.zip')
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,size,digest,path in files:z.write(path,name)
    return archive,manifest


def build_launcher(source, destination, work, entry='WormRecovery.exe'):
    archive,manifest=create_payload(source,work)
    optional_archive,optional_manifest=create_payload(source,work,optional=True)
    compiler=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    if not compiler.is_file():raise FileNotFoundError('Windows .NET Framework 4 compiler is required for the launcher build')
    repo=Path(__file__).resolve().parent
    destination=Path(destination).resolve();destination.parent.mkdir(parents=True,exist_ok=True)
    config=Path(work)/'LauncherConfig.cs'
    config.write_text('internal static class LauncherConfig { public const string Entry = "'+entry+'"; }',encoding='utf8')
    command=[str(compiler),'/nologo','/optimize+','/target:winexe','/platform:x64',
        '/reference:System.IO.Compression.dll','/reference:System.IO.Compression.FileSystem.dll',
        '/reference:System.Windows.Forms.dll','/win32manifest:'+str(repo/'runtime_launcher.manifest'),
        '/resource:'+str(archive)+',runtime.zip','/resource:'+str(manifest)+',runtime-manifest.tsv',
        '/resource:'+str(optional_archive)+',optional.zip','/resource:'+str(optional_manifest)+',optional-manifest.tsv',
        '/out:'+str(destination),str(repo/'runtime_launcher.cs'),str(config)]
    subprocess.run(command,check=True)
    return destination


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--destination',required=True);p.add_argument('--work',required=True)
    a=p.parse_args();print(build_launcher(a.source,a.destination,a.work))
