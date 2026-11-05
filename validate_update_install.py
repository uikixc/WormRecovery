"""Exercise the packaged updater on temporary inert targets, without launching them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from update_security import verify_manifest, verify_file


def validate(helper, executable, manifest, output):
    signed = json.loads(Path(manifest).read_text(encoding='utf-8'))
    payload = verify_manifest(signed)
    verify_file(Path(executable), payload)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='WormRecoveryUpdateValidation-') as temp:
        root = Path(temp)
        download = root / 'download'
        download.mkdir()
        source = download / 'WormRecovery.exe'
        target = root / 'installed.exe'
        old = b'MZ inert original validation target; never executed.'
        target.write_bytes(old)
        shutil.copyfile(executable, source)
        job_path = download / 'install-job.json'
        job = {'source': str(source), 'target': str(target), 'manifest': signed,
               'old_sha256': hashlib.sha256(old).hexdigest(), 'parents': [], 'relaunch': False}
        environment = os.environ.copy()
        environment['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
        for name in ('PYTHONHOME', 'PYTHONPATH', 'WORMRECOVERY_ENGINE_ROOT', 'WORMRECOVERY_WORK_ROOT'):
            environment.pop(name, None)
        job_path.write_text(json.dumps(job), encoding='utf-8')
        process = subprocess.run([str(Path(helper).resolve()), '--apply-update', str(job_path)],
                                 cwd=root, env=environment, capture_output=True, timeout=120,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        result = json.loads((download / 'install-result.json').read_text(encoding='utf-8'))
        assert process.returncode == 0 and result['success'], result
        verify_file(target, payload)
        assert Path(result['backup']).read_bytes() == old
        job['manifest'] = dict(signed, signature='A' * 88)
        job_path.write_text(json.dumps(job), encoding='utf-8')
        process = subprocess.run([str(Path(helper).resolve()), '--apply-update', str(job_path)],
                                 cwd=root, env=environment, capture_output=True, timeout=120,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        rejected = json.loads((download / 'install-result.json').read_text(encoding='utf-8'))
        assert process.returncode != 0 and not rejected['success'], rejected
        verify_file(target, payload)
        record = {'passed': True, 'version': payload['version'], 'bytes': payload['bytes'],
                  'sha256': payload['sha256'], 'original_backup_preserved': True,
                  'invalid_signature_rejected_without_replacing_target': True,
                  'targets_executed': False, 'elapsed_seconds': round(time.monotonic() - started, 3)}
    Path(output).write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps(record))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('helper', 'exe', 'manifest', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    validate(args.helper, args.exe, args.manifest, args.output)
