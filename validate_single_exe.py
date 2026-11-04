"""Copy only the distribution EXE and scan inert fixtures with a minimal PATH."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from tests.test_secondary_engines import write_xlm_fixture


def validate(executable, output):
    with tempfile.TemporaryDirectory(prefix='WormRecoveryPortable-') as temp:
        root = Path(temp)
        program, inputs, reports = (root / name for name in ('program', 'inputs', 'reports'))
        for folder in (program, inputs, reports):
            folder.mkdir()
        portable = program / 'WormRecovery.exe'
        shutil.copy2(executable, portable)
        write_xlm_fixture(inputs / 'inert-xlm.xlsm')
        (inputs / 'inert-unknown.a3x').write_bytes(b'Harmless unsupported AutoIt parser fixture.')
        binary = inputs / 'inert-family-combination.exe'
        shutil.copy2('C:/Windows/System32/where.exe', binary)
        with binary.open('ab') as stream:
            stream.write(b'\nSynaptics ~$cache1 RegKeySave Workbook_Open\n')
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs.iterdir()}
        env = os.environ.copy()
        for key in ('WORMRECOVERY_ENGINE_ROOT', 'PYTHONPATH', 'PYTHONHOME'):
            env.pop(key, None)
        env['PATH'] = 'C:/Windows/System32;C:/Windows'
        started = time.monotonic()
        result = subprocess.run([str(portable), '--scan', '--root', str(inputs), '--report-dir', str(reports), '--workers', '2'],
            cwd=program, env=env, capture_output=True, timeout=240,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        paths = list(reports.glob('*/report.json'))
        if len(paths) != 1:
            raise RuntimeError('Standalone EXE did not produce exactly one report: ' + result.stderr.decode('utf-8', 'replace'))
        scan = json.loads(paths[0].read_text(encoding='utf-8'))
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs.iterdir()}
        findings = {Path(row['path']).name: row for row in scan['findings']}
        xlm = findings.get('inert-xlm.xlsm', {}).get('secondary_analysis', {})
        pe = findings.get(binary.name, {}).get('secondary_analysis', {})
        autoit = findings.get('inert-unknown.a3x', {}).get('secondary_analysis', {})
        checks = {'single_exe_only': sorted(p.name for p in program.iterdir()) == ['WormRecovery.exe'],
                  'originals_unchanged': before == after,
                  'version': scan['version'] == '1.4.0',
                  'clamav_ran': all(row.get('secondary_analysis', {}).get('clamav', {}).get('status') == 'no_match' for row in findings.values()),
                  'xlm_ran': xlm.get('xlm', {}).get('status') == 'analyzed',
                  'capa_ran': pe.get('capa', {}).get('status') == 'analyzed',
                  'rea_ran': pe.get('rea', {}).get('status') == 'analyzed',
                  'autoit_unsupported_explicit': autoit.get('autoit', {}).get('status') == 'unsupported',
                  'unknowns_preserved': all(row['kind'].startswith('review_') for row in findings.values()),
                  'no_scan_errors': not scan['errors'],
                  'uncompleted_is_failure': scan['inspection_failed'] and result.returncode == 1}
        record = {'passed': all(checks.values()), 'checks': checks,
                  'elapsed_seconds': round(time.monotonic() - started, 2), 'exit_code': result.returncode,
                  'source_exe': str(Path(executable).resolve()), 'exe_bytes': portable.stat().st_size,
                  'exe_sha256': hashlib.sha256(portable.read_bytes()).hexdigest(), 'scan_report': scan}
    Path(output).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in record.items() if key != 'scan_report'}, ensure_ascii=False))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    raise SystemExit(validate(args.exe, args.output))
