"""Bounded static identification of the frozen TSCO container and children.

Identity is separate from malware/cleanup authority. No Windows loader, target
execution, remote access or heuristic protector/API attribution is used.
"""
import hashlib
import lzma
import struct

from tsco_features import FEATURES

MAX_OUTPUT=2010624
MAX_CANDIDATES=32


def digest(data):
    return hashlib.sha256(data).hexdigest()


def section_offset(pe,rva,length):
    matches=[raw+rva-va for va,size,raw,_ in pe.sections
             if size and va<=rva and rva+length<=va+size]
    if len(matches)!=1:raise ValueError('TSCO 地址未落入唯一实际节字节范围。')
    return matches[0]


def child_identity(data,pe):
    if len(data) not in {blob['inner_pe_length'] for blob in FEATURES['blobs']}:return None
    offset=struct.unpack_from('<I',data,60)[0]
    if not struct.unpack_from('<H',data,offset+22)[0]&0x2000:return None
    sha=digest(data)
    for blob in FEATURES['blobs']:
        if pe.machine==blob['machine'] and len(data)==blob['inner_pe_length'] and sha==blob['inner_pe_sha256']:
            return {'identity':'TSCO_recovered_payload','sha256':sha,'bytes':len(data),
                    'machine':pe.machine,'basis':'complete_child_pe_sha256_and_structure'}
    return None


def root_identity(data,pe):
    if pe.machine!=0x14c:return None
    anchor=FEATURES['entry_anchor']
    try:entry=section_offset(pe,pe.entry,anchor['length'])
    except ValueError:return None
    if bytes(data[entry:entry+anchor['length']])!=bytes.fromhex(anchor['hex']):return None
    # Only this active entry authorizes the fixed current-build descriptor.
    # Invalid partial matches remain explicit, never a clean or confirmed result.
    descriptor=FEATURES['descriptor'];start=section_offset(pe,descriptor['rva'],descriptor['length'])
    if bytes(data[start:start+descriptor['length']])!=bytes.fromhex(descriptor['hex']):
        raise ValueError('TSCO 活动入口匹配，但描述表不符；变体待核。')
    props=FEATURES['props'];start=section_offset(pe,props['rva'],5)
    if bytes(data[start:start+5])!=bytes.fromhex(props['hex']):
        raise ValueError('TSCO LZMA 参数不符；未确认当前容器。')
    decoded=[];streams=[];total=0
    for spec in FEATURES['streams']:
        start=section_offset(pe,spec['source_rva'],spec['compressed_bytes'])
        source=bytes(data[start:start+spec['compressed_bytes']])
        if digest(source)!=spec['compressed_sha256']:raise ValueError('TSCO 压缩流截断或内容变化。')
        decoder=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[{
            'id':lzma.FILTER_LZMA1,'dict_size':props['dict_size'],
            'lc':props['lc'],'lp':props['lp'],'pb':props['pb']}])
        output=decoder.decompress(source,max_length=spec['decoded_bytes']+1)
        total+=len(output)
        if total>MAX_OUTPUT or len(output)!=spec['decoded_bytes'] or not decoder.eof or decoder.unused_data:
            raise ValueError('TSCO 解压长度、EOS 或输入消费边界不符。')
        if digest(output)!=spec['decoded_sha256']:raise ValueError('TSCO 解压内容身份不符。')
        decoded.append(output)
        streams.append({'source_offset':start,'compressed_bytes':len(source),'decoded_bytes':len(output),
                        'decoded_sha256':spec['decoded_sha256'],'eof':True})
    if total!=MAX_OUTPUT:raise ValueError('TSCO 总解压长度不符。')
    from family_analysis import PE
    children=[];data_section=decoded[2]
    for blob in FEATURES['blobs']:
        start=blob['source_data_offset'];end=start+blob['length']
        encoded=data_section[start:end]
        if len(encoded)!=blob['length'] or digest(encoded)!=blob['encoded_slice_sha256']:
            raise ValueError('TSCO 消费范围或编码载荷身份不符。')
        output=bytes((value-1)&255 for value in encoded)
        if digest(output)!=blob['decoded_slice_sha256']:raise ValueError('TSCO 减一变换身份不符。')
        start=blob['inner_pe_offset'];child=output[start:start+blob['inner_pe_length']]
        identity=child_identity(child,PE(child))
        if not identity:raise ValueError('TSCO 内部 PE 身份不符。')
        children.append({**identity,'decoded_data_offset':blob['source_data_offset'],
                         'transform':'u8_minus_one','inner_offset':start})
    return {'identity':'TSCO_known_payload_container','basis':'root_entry_descriptor_four_eos_streams_four_child_pe',
            'entry_offset':entry,'streams':streams,'children':children,
            'scope':'current_root_pe','attribution':'payload container; miner/document-worm role unproven'}


def identify(data,pe=None):
    """Report identities/partial evidence without granting processing authority."""
    from family_analysis import PE
    result={'identifications':[],'contained_payloads':[],'diagnostics':[]}
    if pe is not None:
        try:
            identity=child_identity(data,pe) or root_identity(data,pe)
            if identity:result['identifications'].append(identity)
        except (ValueError,lzma.LZMAError,struct.error) as ex:result['diagnostics'].append(str(ex))
    # A nested image is its own evidence node. It cannot make its parent an
    # identified root or confirmed malware. Candidate work and byte size bounded.
    cursor=data.find(b'MZ',64);examined=0
    while cursor>=0 and examined<MAX_CANDIDATES:
        examined+=1
        try:
            view=memoryview(data)[cursor:];child_pe=PE(view)
            end=max([child_pe.headers]+[raw+size for _,size,raw,_ in child_pe.sections])
            if end in {blob['inner_pe_length'] for blob in FEATURES['blobs']}:
                hit=child_identity(view[:end],child_pe)
            elif end==FEATURES['sample_bytes']:
                hit=root_identity(view[:end],child_pe)
            else:hit=None
            if hit:result['contained_payloads'].append({'offset':cursor,'bytes':end,**hit,'scope':'contained_pe_only'})
        except (ValueError,lzma.LZMAError,struct.error):pass
        finally:
            if 'view' in locals():view.release();del view
        cursor=data.find(b'MZ',cursor+2)
    if cursor>=0 and data.find(bytes.fromhex(FEATURES['entry_anchor']['hex']))>=0:
        result['diagnostics'].append('TSCO 嵌入 PE 候选超过 32 个，剩余内容未完成检查。')
    return result
