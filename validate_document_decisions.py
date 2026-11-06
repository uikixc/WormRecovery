"""Validate portable content decisions on generated inert Office fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile

from tests.office_fixtures import compound,vba_streams,plain_workbook,record as vba_record


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
                main='ppt/presentation.xml' if name.endswith('.pptx') else 'xl/workbook.xml' if name.endswith(('.xlsm','.xlsx')) else 'word/document.xml'
                archive.writestr(main,'<document/>')
                if project:archive.writestr('xl/vbaProject.bin',project)
                if relationship:archive.writestr('word/_rels/document.xml.rels',relationship)
                for path,data in (extra or {}).items():archive.writestr(path,data)
        project=compound(vba_streams())
        package('empty-project.xlsm',project)
        dependency=b'*\\G{00000000-0000-0000-0000-000000000001}#1.0#0#C:\\fixture\\library.tlb#Fixture'
        reference=vba_record(0x0D,len(dependency).to_bytes(4,'little')+dependency+b'\0'*6)
        package('referenced-library.xlsm',compound(vba_streams(references=reference)))
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
        apple_header=struct.pack('>II16sH',0x51607,0x20000,b'Mac OS X        ',2)
        def apple(resource=b''):
            return apple_header+struct.pack('>III',9,50,32)+struct.pack('>III',2,82,len(resource))+b'\0'*32+resource
        (inputs/'arbitrary-name.pptx').write_bytes(apple())
        (inputs/'resource-fork.pptx').write_bytes(apple(b'inert unclassified resource'))
        deleted=inputs/'$Recycle.Bin/S-1-5-21-1';deleted.mkdir(parents=True)
        original='C:\\Users\\Fixture\\Documents\\original.docx\0'.encode('utf-16-le')
        for version in (1,2):
            data=struct.pack('<QQQ',version,1234,133000000000000000)
            data+=original.ljust(520,b'\0') if version==1 else struct.pack('<I',len(original)//2)+original
            (deleted/('$I00000'+str(version)+'.docx')).write_bytes(data)
        (deleted/'$I000003.docx').write_bytes(b'inert malformed index')
        inner=inputs/'inner.xlsx';package(inner.name);inner_data=inner.read_bytes();inner.unlink()
        package('nested-workbook.pptx',extra={'ppt/embeddings/':b'','ppt/embeddings/a.xlsx':inner_data})
        package('nested-biff.docx',extra={'word/embeddings/a.bin':compound({'Workbook':plain_workbook()})})
        native=struct.pack('<H',2)+b'fixture.xlsx\0C:\\missing\\source.xlsx\0'+b'\0'*8+b'C:\\missing\\temp.xlsx\0'+struct.pack('<I',len(inner_data))+inner_data
        native=struct.pack('<I',len(native))+native
        package('nested-package.docx',extra={'word/embeddings/a.bin':compound({'\x01Ole10Native':native})})
        package('nested-formula.docx',extra={'word/embeddings/a.bin':compound({'Equation Native':b'inert formula records'})})
        macro_inner=inputs/'inner.xlsm';package(macro_inner.name,project);macro_bytes=macro_inner.read_bytes();macro_inner.unlink()
        package('nested-macro.docx',extra={'word/embeddings/a.xlsm':macro_bytes})
        package('missing-cache-table.xlsm',compound(vba_streams(cache=b'inert compiled cache')))
        for index in range(73):
            (inputs/('batch-%02d.doc'%index)).write_text('Inert plain text document number '+str(index),encoding='utf-8')
        shutil.copy2(inputs/'batch-00.doc',inputs/'batch-copy.doc')
        def fingerprints():return {path.relative_to(inputs).as_posix():fingerprint(path) for path in inputs.rglob('*') if path.is_file()}
        before=fingerprints()
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
            rows={Path(row['path']).relative_to(inputs).as_posix():row for row in report['findings']}
            expected={'empty-project.xlsm':'empty_vba_project','empty-project.xls':'empty_vba_project',
                      'plain-text.doc':'passive_text_document','cid-image.docx':'ordinary_local_resource_links',
                      'empty.pptx':'empty_document_data_loss','arbitrary-name.pptx':'verified_metadata_container',
                      '$Recycle.Bin/S-1-5-21-1/$I000001.docx':'verified_metadata_container',
                      '$Recycle.Bin/S-1-5-21-1/$I000002.docx':'verified_metadata_container',
                      'nested-workbook.pptx':'ordinary_local_resource_links','nested-biff.docx':'ordinary_local_resource_links',
                      'nested-package.docx':'ordinary_local_resource_links'}
            for name,rule in expected.items():
                row=rows.get(name,{})
                checks[name+'_classified']=row.get('kind')=='info_document' and row.get('decision',{}).get('rule')==rule
            for name in ('nonempty-source.xlsm','referenced-library.xlsm','embedded-object.xlsm','remote-image.docx','attached-template.docx','invalid-format.doc'):
                checks[name+'_retained']=rows.get(name,{}).get('kind')=='review_office'
            checks['only_actual_format_errors']=len(errors)==2 and {Path(error['path']).name for error in errors}=={'invalid-format.doc','$I000003.docx'}
            checks['resource_fork_not_cleared']=rows.get('resource-fork.pptx',{}).get('kind')=='review_office'
            for name,kind in (('nested-formula.docx','equation_object'),('nested-macro.docx','ooxml_excel'),('embedded-object.xlsm','unknown_binary')):
                row=rows.get(name,{})
                content=row.get('secondary_analysis',{}).get('embedded_content',{})
                objects=content.get('objects',[])
                checks[name+'_typed_without_false_parser_error']=row.get('kind')=='review_office' and content.get('status')=='analyzed' and len(objects)==1 and objects[0].get('format')==kind
            cache=rows.get('missing-cache-table.xlsm',{})
            checks['missing_cache_table_keeps_source_evidence']=not cache.get('analysis_error') and bool(cache.get('macro_analysis',{}).get('source_sha256')) and cache.get('macro_analysis',{}).get('pcode_status')=='incomplete' and cache.get('kind')=='review_office'
            batched=[row for name,row in rows.items() if name.startswith('batch-')]
            checks['large_batch_has_independent_verdicts']=len(batched)==74 and all(row['kind']=='info_document' and row.get('secondary_analysis',{}).get('clamav',{}).get('status')=='no_match' for row in batched)
            checks['duplicate_content_uses_one_scan']=rows.get('batch-copy.doc',{}).get('secondary_analysis',{}).get('clamav',{}).get('identical_inputs')==2
            clams=[row.get('secondary_analysis',{}).get('clamav',{}) for row in rows.values()]
            attempts=next((row.get('execution',{}).get('attempts',[]) for row in clams if row.get('execution')),[])
            checks['batch_keeps_one_database_load']=len(attempts)==1 and attempts[0].get('status')=='completed' and attempts[0].get('results',0)>=len(rows)-2
            events=[json.loads(line) for line in paths[0].with_name('journal.jsonl').read_text(encoding='utf-8').splitlines()]
            progress=[event for event in events if event.get('kind')=='scan_phase' and event.get('stage')=='ClamAV 已返回文件结果']
            checks['per_file_engine_progress_retained']=len(progress)>=len(rows)-2 and progress[-1]['completed']==progress[-1]['total']
            checks['scan_stage_durations_retained']=report.get('file_scan_seconds',-1)>=0 and report.get('review_seconds',-1)>0
            checks['empty_file_content_loss_preserved']=rows.get('empty.pptx',{}).get('data_integrity_issue')=='empty_document' and '历史原件' in rows.get('empty.pptx',{}).get('action','')
            checks['all_files_reported']=len(rows)==len(before) and report['files']==len(before)
            checks['no_fixture_confirmed_infection']=all(row['kind'].startswith(('info_','review_')) for row in rows.values())
            checks['source_engine_telemetry_present']=report.get('offline_analysis',{}).get('engine_usage',{}).get('vba_source_analysis',{}).get('first_pass_files',0)>0
            decisions={name:{'kind':row['kind'],'rule':row.get('decision',{}).get('rule'),
                             'pcode':row.get('macro_analysis',{}).get('pcode_status')} for name,row in rows.items()}
        checks['fixture_contents_unchanged']=before==fingerprints()
        checks['single_distribution_exe']=[path.name for path in program.iterdir()]==['WormRecovery.exe']
        checks['no_fixture_upload']=not (state/'receipts.jsonl').exists()
        record={'passed':all(checks.values()),'checks':checks,'version':version,'decisions':decisions,
                'errors':len(errors),'fixture_files':len(before),'exit_code':result.returncode,'elapsed_seconds':round(time.monotonic()-started,3),
                'stderr':result.stderr.decode('utf-8','replace')[-1000:],
                'scope':'Generated inert documents; static parsing only, no Office or macro execution, no cleanup or production uploads.'}
        Path(output).write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(record,ensure_ascii=True))
        return 0 if record['passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();raise SystemExit(validate(args.exe,args.output))
