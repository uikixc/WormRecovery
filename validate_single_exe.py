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
import zipfile

from tests.test_secondary_engines import write_xlm_fixture


def validate(executable, output, vba_fixture=None):
    with tempfile.TemporaryDirectory(prefix='WormRecoveryPortable-') as temp:
        root = Path(temp)
        program, inputs, reports = (root / name for name in ('program', 'inputs', 'reports'))
        for folder in (program, inputs, reports):
            folder.mkdir()
        portable = program / 'WormRecovery.exe'
        shutil.copy2(executable, portable)
        write_xlm_fixture(inputs / 'inert-xlm.xlsm')
        if __import__('worm_recovery').VERSION>='1.6.0':
            with zipfile.ZipFile(inputs/'inert-linked-resource.pptx','w') as archive:
                archive.writestr('[Content_Types].xml','<Types/>')
                archive.writestr('ppt/presentation.xml','<presentation/>')
                archive.writestr('ppt/_rels/presentation.xml.rels','<Relationships><Relationship Type="x/image" TargetMode="External" Target="file:///C:/images/inert.png"/></Relationships>')
            with zipfile.ZipFile(inputs/'inert-external-data.xlsx','w') as archive:
                archive.writestr('[Content_Types].xml','<Types/>');archive.writestr('xl/workbook.xml','<workbook/>')
                archive.writestr('xl/externalLinks/externalLink1.xml','<externalLink><externalBook/></externalLink>')
                archive.writestr('xl/externalLinks/_rels/externalLink1.xml.rels','<Relationships><Relationship Type="x/externalLinkPath" TargetMode="External" Target="file:///C:/data/inert.xlsx"/></Relationships>')
        (inputs / 'inert-unknown.a3x').write_bytes(b'Harmless unsupported AutoIt parser fixture.')
        binary = inputs / 'inert-family-combination.exe'
        shutil.copy2('C:/Windows/System32/where.exe', binary)
        with binary.open('ab') as stream:
            stream.write(b'\nSynaptics ~$cache1 RegKeySave Workbook_Open\n')
        if vba_fixture:
            # Preserve only a caller-selected, nonexecuted VBA project inside a
            # private test container. No Office application opens this file.
            with zipfile.ZipFile(vba_fixture) as archive:
                project=archive.read('xl/vbaProject.bin')
            with zipfile.ZipFile(inputs/'static-vba-regression.xlsm','w') as archive:
                archive.writestr('[Content_Types].xml','<Types/>')
                archive.writestr('xl/workbook.xml','<workbook/>')
                archive.writestr('xl/vbaProject.bin',project)
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs.iterdir()}
        env = os.environ.copy()
        env['LOCALAPPDATA']=str(root/'test-userdata')
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
                  'version': scan['version'] == __import__('worm_recovery').VERSION,
                  'clamav_ran': all(row.get('secondary_analysis', {}).get('clamav', {}).get('status') == 'no_match' for row in findings.values()),
                  'xlm_ran': xlm.get('xlm', {}).get('status') == 'analyzed',
                  'capa_ran': pe.get('capa', {}).get('status') == 'analyzed',
                  'rea_ran': pe.get('rea', {}).get('status') == 'analyzed',
                  'autoit_unsupported_explicit': autoit.get('autoit', {}).get('status') == 'unsupported',
                  'unknowns_preserved': all(row['kind'].startswith('review_') for name,row in findings.items() if name not in ('inert-linked-resource.pptx','inert-external-data.xlsx')),
                  'no_scan_errors': not scan['errors'],
                  'uncompleted_is_failure': scan['inspection_failed'] and result.returncode == 1}
        if __import__('worm_recovery').VERSION>='1.5.1':
            phases=[row for row in scan['events'] if row.get('kind')=='scan_phase']
            checks['review_phase_has_total_and_current_file']=any(row.get('phase')=='review' and row.get('total',0)>0 and row.get('path') for row in phases)
            checks['review_completion_reported']=any(row.get('phase')=='review' and row.get('completed',0)==row.get('total') and row.get('total',0)>0 for row in phases)
            checks['engine_stages_reported']=any('ClamAV' in row.get('stage','') for row in phases) and any('REA' in row.get('stage','') for row in phases)
        if vba_fixture:
            macro=findings.get('static-vba-regression.xlsm',{})
            checks['real_vba_json_transport']=not macro.get('analysis_error') and macro.get('macro_analysis',{}).get('pcode_status')=='instructions_read'
        if __import__('worm_recovery').VERSION>='1.6.0':
            checks['resources_classified_inside_exe']=all(findings.get(name,{}).get('kind')=='info_document' for name in ('inert-linked-resource.pptx','inert-external-data.xlsx'))
            checks['vba_behavior_engine_ran']=bool(findings.get('static-vba-regression.xlsm',{}).get('macro_analysis',{}).get('behavior_analysis')) if vba_fixture else True
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
    parser.add_argument('--vba-fixture', help='Optional caller-selected known benign OOXML VBA fixture')
    args = parser.parse_args()
    raise SystemExit(validate(args.exe, args.output, args.vba_fixture))
