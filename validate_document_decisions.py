"""Validate portable content decisions on generated inert Office fixtures."""
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

from tests.office_fixtures import compound,vba_streams,plain_workbook


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(executable,output):
    checks={};started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='WormRecoveryDecisions-') as temporary:
        root=Path(temporary);inputs=root/'inputs';inputs.mkdir()
        program=root/'program';program.mkdir();reports=root/'reports';reports.mkdir()
        def package(name,project=None,relationship=None,extra=None):
            with zipfile.ZipFile(inputs/name,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('[Content_Types].xml','<Types/>')
                archive.writestr('xl/workbook.xml' if name.endswith('.xlsm') else 'word/document.xml','<document/>')
                if project:archive.writestr('xl/vbaProject.bin',project)
                if relationship:archive.writestr('word/_rels/document.xml.rels',relationship)
                for path,data in (extra or {}).items():archive.writestr(path,data)
        project=compound(vba_streams())
        package('empty-project.xlsm',project)
        (inputs/'empty-project.xls').write_bytes(compound(vba_streams(extra={'Workbook':plain_workbook()})))
        package('nonempty-source.xlsm',compound(vba_streams('Attribute VB_Name = "Fixture"\r\nSub A()\r\nDebug.Print "inert fixture"\r\nEnd Sub\r\n')))
        package('embedded-object.xlsm',project,extra={'xl/embeddings/fixture.bin':b'inert object'})
        (inputs/'plain-text.doc').write_text('Debugger help. <stdin> represents the input stream.\n',encoding='utf-8')
        relation=lambda kind,target:'<Relationships><Relationship Type="x/'+kind+'" TargetMode="External" Target="'+target+'"/></Relationships>'
        package('cid-image.docx',relationship=relation('image','cid:image008.jpg@01D39F44.F2250020'))
        package('remote-image.docx',relationship=relation('image','https://example.invalid/fixture.jpg'))
        package('attached-template.docx',relationship=relation('attachedTemplate','file:///S:/templates/fixture.dot'))
        (inputs/'empty.pptx').touch()
        (inputs/'invalid-format.doc').write_bytes(b'\x00inert invalid document')
        before={path.name:fingerprint(path) for path in inputs.iterdir()}
        portable=program/'WormRecovery.exe';shutil.copy2(executable,portable)
        env=os.environ.copy();env['PATH']='C:/Windows/System32;C:/Windows'
        env['LOCALAPPDATA']=str(root/'localappdata');state=root/'localappdata/WormRecovery/diagnostics'
        state.mkdir(parents=True);(state/'paused').write_text('fixture-only',encoding='ascii')
        for name in ('PYTHONHOME','PYTHONPATH','WORMRECOVERY_ENGINE_ROOT'):env.pop(name,None)
        result=subprocess.run([str(portable),'--scan','--root',str(inputs),'--report-dir',str(reports),'--workers','2'],
            env=env,cwd=program,capture_output=True,timeout=240,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        paths=list(reports.glob('*/report.json'))
        checks['report_produced']=len(paths)==1
        decisions={};version=None;errors=[]
        if len(paths)==1:
            report=json.loads(paths[0].read_text(encoding='utf-8'));version=report['version'];errors=report['errors']
            rows={Path(row['path']).name:row for row in report['findings']}
            expected={'empty-project.xlsm':'empty_vba_project','empty-project.xls':'empty_vba_project',
                      'plain-text.doc':'passive_text_document','cid-image.docx':'ordinary_local_resource_links',
                      'empty.pptx':'empty_document_data_loss'}
            for name,rule in expected.items():
                row=rows.get(name,{})
                checks[name+'_classified']=row.get('kind')=='info_document' and row.get('decision',{}).get('rule')==rule
            for name in ('nonempty-source.xlsm','embedded-object.xlsm','remote-image.docx','attached-template.docx','invalid-format.doc'):
                checks[name+'_retained']=rows.get(name,{}).get('kind')=='review_office'
            checks['only_actual_format_error']=len(errors)==1 and Path(errors[0]['path']).name=='invalid-format.doc'
            checks['empty_file_content_loss_preserved']=rows.get('empty.pptx',{}).get('data_integrity_issue')=='empty_document' and '历史原件' in rows.get('empty.pptx',{}).get('action','')
            checks['all_files_reported']=len(rows)==len(before) and report['files']==len(before)
            checks['no_fixture_confirmed_infection']=all(row['kind'].startswith(('info_','review_')) for row in rows.values())
            checks['source_engine_telemetry_present']=report.get('offline_analysis',{}).get('engine_usage',{}).get('vba_source_analysis',{}).get('first_pass_files',0)>0
            decisions={name:{'kind':row['kind'],'rule':row.get('decision',{}).get('rule'),
                             'pcode':row.get('macro_analysis',{}).get('pcode_status')} for name,row in rows.items()}
        checks['fixture_contents_unchanged']=before=={path.name:fingerprint(path) for path in inputs.iterdir()}
        checks['single_distribution_exe']=[path.name for path in program.iterdir()]==['WormRecovery.exe']
        checks['no_fixture_upload']=not (state/'receipts.jsonl').exists()
        record={'passed':all(checks.values()),'checks':checks,'version':version,'decisions':decisions,
                'errors':len(errors),'exit_code':result.returncode,'elapsed_seconds':round(time.monotonic()-started,3),
                'stderr':result.stderr.decode('utf-8','replace')[-1000:],
                'scope':'Generated inert documents; static parsing only, no Office or macro execution, no cleanup or production uploads.'}
        Path(output).write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(record,ensure_ascii=True))
        return 0 if record['passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();raise SystemExit(validate(args.exe,args.output))
