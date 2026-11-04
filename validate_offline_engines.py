"""Validate shipped engines against harmless fixtures; never run specimen code."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time

from tests.test_secondary_engines import write_xlm_fixture
from secondary_analysis import clam_batch, parser_request, pe_second_opinion
from engine_assets import manifest
from local_rules import scan_bytes


def validate(output):
    report = {'versions': manifest().get('versions', {}), 'checks': {}}
    with tempfile.TemporaryDirectory(prefix='WormRecoveryValidation-') as temp:
        root = Path(temp)
        document = root / 'inert-xlm.xlsm'
        write_xlm_fixture(document)
        inert = root / 'inert.txt'
        inert.write_text('Harmless offline engine validation.', encoding='utf-8')
        binary = root / 'windows-where-copy.exe'
        shutil.copy2(Path('C:/Windows/System32/where.exe'), binary)
        inputs = [document, inert, binary]
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
        started = time.monotonic()
        rows, database = clam_batch(inputs, root)
        report['checks']['clamav'] = {'seconds': round(time.monotonic()-started, 3),
            'results': {Path(p).name: value for p, value in rows.items()}, 'database': database}
        report['checks']['xlm'] = parser_request('xlm', document)
        report['checks']['autoit_unsupported'] = parser_request('autoit', inert)
        report['checks']['yara_x'] = scan_bytes(b'Synaptics ~$cache1 RegKeySave Workbook_Open')
        report['checks']['pe'] = pe_second_opinion(binary)
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
        report['originals_unchanged'] = before == after
        report['passed'] = report['originals_unchanged'] and all(row['status'] == 'no_match' for row in rows.values()) and report['checks']['xlm']['status'] == 'analyzed' and all(row['status'] == 'analyzed' for row in report['checks']['pe'].values())
    Path(output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'originals_unchanged': report['originals_unchanged'], 'engines': {k: v.get('status') for k,v in report['checks']['pe'].items()}}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    raise SystemExit(validate(parser.parse_args().output))
