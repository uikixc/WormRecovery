"""Stage already acquired official tools and verified databases for offline build."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import time
from importlib.metadata import version


def prepare(tool_root, rea_root, database_root, destination):
    tools, rea, databases, dest = map(Path, (tool_root, rea_root, database_root, destination))
    dest.mkdir(parents=True, exist_ok=True)
    clam = next(tools.glob('clamav/**/clamscan.exe')).parent
    (dest / 'clamav').mkdir(exist_ok=True)
    for name in ['clamscan.exe', 'sigtool.exe']:
        shutil.copy2(clam / name, dest / 'clamav' / name)
    # Private DLL dependencies; debug symbols, static import libraries and updater
    # are not required at run time. No download occurs on the target computer.
    for path in clam.glob('*.dll'):
        if path.name != 'libfreshclam.dll':
            shutil.copy2(path, dest / 'clamav' / path.name)
    if (clam / 'certs').is_dir():
        shutil.copytree(clam / 'certs', dest / 'clamav/certs', dirs_exist_ok=True)
    db = dest / 'clamdb'
    db.mkdir(exist_ok=True)
    for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd'):
        shutil.copy2(databases / name, db / name)
    (dest / 'capa').mkdir(exist_ok=True)
    shutil.copy2(tools / 'capa/capa.exe', dest / 'capa/capa.exe')
    package = rea / 'npm/node_modules/rea-agents'
    shutil.copytree(package, dest / 'rea/package', dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('*.pdb', '*.map', '.git'))
    shutil.copy2(rea / 'node-v26.13.0-win-x64/node.exe', dest / 'rea/node.exe')
    notices = dest / 'notices'
    notices.mkdir(exist_ok=True)
    for prefix, directory in (('clamav', clam), ('node', rea / 'node-v26.13.0-win-x64')):
        for pattern in ('COPYING*', 'LICENSE*', 'NOTICE*'):
            for path in directory.glob(pattern):
                if path.is_file():
                    shutil.copy2(path, notices / (prefix + '-' + path.name))
    records = {}
    for path in dest.rglob('*'):
        if path.is_file() and path.name != 'manifest.json':
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            records[path.relative_to(dest).as_posix()] = {'bytes': path.stat().st_size, 'sha256': digest}
    manifest = {'created': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'versions': {'clamav': '1.5.4', 'capa': '10.0.0', 'rea': '6.8.0', 'node': '26.13.0',
                     **{name: version(name) for name in ('yara-x', 'oletools', 'pcodedmp', 'autoit-ripper', 'XLMMacroDeobfuscator')}},
        'rea_scope': 'Local static PE imports and certificate declarations; no Ghidra engine bundled',
        'files': records}
    (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'files': len(records), 'bytes': sum(x['bytes'] for x in records.values()), 'destination': str(dest)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('tool-root', 'rea-root', 'database-root', 'destination'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    prepare(args.tool_root, args.rea_root, args.database_root, args.destination)
