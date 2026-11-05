"""Exercise packaged Office workers repeatedly using caller-selected benign projects.

No Office application or macro is executed. Only private fixture copies are scanned.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import zipfile

from engine_assets import subprocess_environment
from engine_process import run as run_engine
from office_analysis import decode_worker_result


def fingerprint(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate(executable, analysis, fixtures, output, rounds=3, workers=3):
    if not 1 <= rounds <= 20 or not 1 <= workers <= 4:
        raise ValueError('Validation rounds or worker count out of bounds.')
    executable, analysis = Path(executable).resolve(), Path(analysis).resolve()
    fixtures = [Path(path).resolve() for path in fixtures]
    originals = {str(path): fingerprint(path) for path in fixtures}
    started = time.monotonic()
    checks, results = {}, []
    with tempfile.TemporaryDirectory(prefix='WormRecoveryOfficeValidation-') as temporary:
        root = Path(temporary)
        inputs, program, reports = (root / name for name in ('inputs', 'program', 'reports'))
        for directory in (inputs, program, reports):
            directory.mkdir()
        environment = subprocess_environment(independent=True)
        environment['PATH'] = 'C:/Windows/System32;C:/Windows'
        environment['LOCALAPPDATA'] = str(root / 'localappdata')
        environment['WORMRECOVERY_WORK_ROOT'] = str(root / 'worker-temp')
        Path(environment['WORMRECOVERY_WORK_ROOT']).mkdir()
        environment['TEMP'] = environment['TMP'] = environment['WORMRECOVERY_WORK_ROOT']
        for name in ('PYTHONHOME', 'PYTHONPATH'):
            environment.pop(name, None)
        state = root / 'localappdata/WormRecovery/diagnostics'
        state.mkdir(parents=True)
        (state / 'paused').write_text('fixture-only', encoding='ascii')
        projects = []
        for index, source in enumerate(fixtures):
            with zipfile.ZipFile(source) as archive:
                project = archive.read('xl/vbaProject.bin')
            legacy = inputs / ('legacy-%02d.xls' % index)
            legacy.write_bytes(project)
            document = inputs / ('package-%02d.xlsm' % index)
            with zipfile.ZipFile(document, 'w') as archive:
                archive.writestr('[Content_Types].xml', '<Types/>')
                archive.writestr('xl/workbook.xml', '<workbook/>')
                archive.writestr('xl/vbaProject.bin', project)
            projects.append((source.name, project, legacy))
        before = {path.name: fingerprint(path) for path in inputs.iterdir()}

        def inspect(task):
            iteration, (name, project, legacy), mode = task
            payload = (base64.b64encode(project) if mode == 'vba'
                       else json.dumps({'mode': 'legacy_office', 'path': str(legacy)}).encode('utf-8'))
            tick = time.monotonic()
            try:
                completed = run_engine([str(analysis)], timeout=40, input=payload, env=environment)
                response = decode_worker_result(completed, 'Office validation')['result']
                macro = response if mode == 'vba' else response.get('macro_analysis', {})
                return {'fixture': name, 'round': iteration, 'mode': mode,
                        'passed': bool(macro.get('modules')) and bool(macro.get('source_sha256')),
                        'pcode_status': macro.get('pcode_status'),
                        'seconds': round(time.monotonic() - tick, 3)}
            except Exception as error:
                return {'fixture': name, 'round': iteration, 'mode': mode,
                        'passed': False, 'error': str(error),
                        'seconds': round(time.monotonic() - tick, 3)}

        tasks = [(iteration, project, mode) for iteration in range(rounds)
                 for project in projects for mode in ('vba', 'legacy_office')]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(inspect, tasks))
        checks['repeated_packaged_workers'] = bool(results) and all(row['passed'] for row in results)
        checks['analysis_uses_shared_directory_runtime'] = (analysis.parent / '_internal').is_dir()

        portable = program / 'WormRecovery.exe'
        shutil.copy2(executable, portable)
        scan_environment = environment.copy()
        scan_environment.pop('WORMRECOVERY_ENGINE_ROOT', None)
        scan = subprocess.run([str(portable), '--scan', '--root', str(inputs), '--report-dir', str(reports),
                               '--workers', str(workers)], cwd=program, env=scan_environment,
                              capture_output=True, timeout=240,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        report_paths = list(reports.glob('*/report.json'))
        checks['portable_report_produced'] = len(report_paths) == 1
        scan_summary = {'exit_code': scan.returncode}
        if len(report_paths) == 1:
            report = json.loads(report_paths[0].read_text(encoding='utf-8'))
            findings = {Path(row['path']).name: row for row in report['findings']}
            checks['all_fixture_macros_analyzed'] = all(
                name in findings and not findings[name].get('analysis_error')
                and bool(findings[name].get('macro_analysis', {}).get('modules')) for name in before)
            checks['no_scan_errors'] = not report['errors']
            checks['no_fixture_confirmed_infection'] = not any(
                not row['kind'].startswith(('review_', 'info_')) for row in findings.values())
            scan_summary.update(version=report['version'], files=report['files'],
                                findings=len(findings), errors=report['errors'])
        else:
            scan_summary['stderr'] = scan.stderr.decode('utf-8', 'replace')[-2000:]
        checks['single_distribution_exe'] = [path.name for path in program.iterdir()] == ['WormRecovery.exe']
        checks['private_fixtures_unchanged'] = before == {path.name: fingerprint(path) for path in inputs.iterdir()}
        checks['caller_originals_unchanged'] = originals == {str(path): fingerprint(path) for path in fixtures}
        checks['no_fixture_upload'] = not (state / 'receipts.jsonl').exists()
        record = {'passed': all(checks.values()), 'checks': checks, 'worker_launches': len(results),
                  'worker_results': results, 'portable_scan': scan_summary,
                  'source_exe': str(executable), 'exe_sha256': fingerprint(executable),
                  'elapsed_seconds': round(time.monotonic() - started, 3),
                  'scope': 'Static analysis of caller-selected benign VBA projects; no Office or macro execution'}
    Path(output).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({name: value for name, value in record.items() if name != 'worker_results'}, ensure_ascii=False))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('exe', 'analysis', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--fixture', action='append', required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--workers', type=int, default=3)
    args = parser.parse_args()
    raise SystemExit(validate(args.exe, args.analysis, args.fixture, args.output, args.rounds, args.workers))
