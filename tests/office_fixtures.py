"""Small inert MS-CFB/MS-OVBA fixtures, generated from source without Office."""
import math
import struct


def record(kind,data):
    return struct.pack('<HI',kind,len(data))+data


def compressed_literals(data):
    """MS-OVBA literal-only chunks; fixture data, not an executable compressor."""
    output=bytearray(b'\x01')
    for start in range(0,len(data),3000):
        chunk=data[start:start+3000];encoded=bytearray()
        for offset in range(0,len(chunk),8):encoded+=b'\0'+chunk[offset:offset+8]
        output+=struct.pack('<H',0xB000|(len(encoded)-1))+encoded
    return bytes(output)


def compound(streams):
    """Create a tiny CFB v3 with regular directory/FAT and miniature streams."""
    free=0xFFFFFFFF;end=0xFFFFFFFE
    names={'':0};entries=[{'name':'Root Entry','kind':5,'children':[]}]
    for path,data in sorted(streams.items()):
        parent=''
        for part in path.split('/')[:-1]:
            current=parent+'/'+part if parent else part
            if current not in names:
                names[current]=len(entries);entries.append({'name':part,'kind':1,'children':[]})
                entries[names[parent]]['children'].append(names[current])
            parent=current
        names[path]=len(entries);entries.append({'name':path.split('/')[-1],'kind':2,'data':data,'children':[]})
        entries[names[parent]]['children'].append(names[path])
    mini=bytearray();mini_fat=[]
    for entry in entries:
        if entry['kind']!=2:continue
        data=entry['data']
        if len(data)>=4096:raise ValueError('Fixture stream exceeds mini-stream limit')
        count=math.ceil(len(data)/64);entry['start']=len(mini_fat) if count else end
        first=len(mini_fat)
        mini_fat.extend([first+i+1 if i<count-1 else end for i in range(count)])
        mini+=data+b'\0'*(count*64-len(data))
    sectors=[];fat=[]
    def allocate(data):
        count=math.ceil(len(data)/512);start=len(sectors)
        for index in range(count):
            sectors.append(data[index*512:(index+1)*512].ljust(512,b'\0'))
            fat.append(start+index+1 if index<count-1 else end)
        return start if count else end,count
    mini_start,_=allocate(mini)
    mf_data=b''.join(struct.pack('<I',value) for value in mini_fat)
    mf_start,mf_count=allocate(mf_data.ljust(math.ceil(len(mf_data)/512)*512,b'\xff'))
    for entry in entries:
        children=sorted(entry['children'],key=lambda i:(len(entries[i]['name']),entries[i]['name'].upper()))
        def tree(items):
            if not items:return free
            mid=len(items)//2;node=items[mid]
            entries[node]['left']=tree(items[:mid]);entries[node]['right']=tree(items[mid+1:])
            return node
        entry['child']=tree(children)
    directory=bytearray()
    for entry in entries:
        item=bytearray(128);name=(entry['name']+'\0').encode('utf-16-le')
        item[:len(name)]=name;struct.pack_into('<HBBIII',item,64,len(name),entry['kind'],1,
            entry.get('left',free),entry.get('right',free),entry['child'])
        start=mini_start if entry['kind']==5 else entry.get('start',end)
        size=len(mini) if entry['kind']==5 else len(entry.get('data',b''))
        struct.pack_into('<IQ',item,116,start,size);directory+=item
    directory_start,_=allocate(directory)
    fat_sector=len(sectors);fat.append(0xFFFFFFFD)
    if len(fat)>128:raise ValueError('Fixture FAT too large')
    sectors.append(b''.join(struct.pack('<I',value) for value in fat).ljust(512,b'\xff'))
    header=bytearray(512);header[:8]=bytes.fromhex('d0cf11e0a1b11ae1')
    struct.pack_into('<HHHHH',header,24,0x3E,3,0xFFFE,9,6)
    struct.pack_into('<IIIIIIIII',header,40,0,1,directory_start,0,4096,mf_start,mf_count,end,0)
    header[76:]=struct.pack('<I',fat_sector)+b'\xff'*(512-80)
    return bytes(header)+b''.join(sectors)


def vba_streams(source=None,cache=b'',extra=None,references=b''):
    if source is None:source='Attribute VB_Name = "Fixture"\r\nOption Explicit\r\nPrivate Sub Workbook_Open()\r\nEnd Sub\r\n'
    u32=lambda value:struct.pack('<I',value)
    info=b''.join((record(1,u32(1)),record(2,u32(0x409)),record(0x14,u32(0x409)),
        record(3,struct.pack('<H',1252)),record(4,b'Fixture'),record(5,b''),record(0x40,b''),
        record(6,b''),record(0x3D,b''),record(7,u32(0)),record(8,u32(0)),
        record(9,u32(1))+b'\0\0',record(0x0C,b''),record(0x3C,b''),references,
        record(0x0F,struct.pack('<H',1)),record(0x13,b'\0\0')))
    module=b''.join((record(0x19,b'Fixture'),record(0x47,'Fixture'.encode('utf-16-le')),
        record(0x1A,b'Fixture'),record(0x32,'Fixture'.encode('utf-16-le')),
        record(0x1C,b''),record(0x48,b''),record(0x31,u32(len(cache))),record(0x1E,u32(0)),
        record(0x2C,b'\0\0'),record(0x21,b''),record(0x2B,b'')))
    streams={'PROJECT':b'Module=Fixture\r\nName="Fixture"\r\n',
             'VBA/_VBA_PROJECT':b'\xcc\x61\xff\xff\0\0\0',
             'VBA/dir':compressed_literals(info+module+record(0x10,b'')),
             'VBA/Fixture':cache+compressed_literals(source.encode('cp1252'))}
    streams.update(extra or {})
    return streams


def plain_workbook(extra_record=None):
    def biff(kind,data=b''):return struct.pack('<HH',kind,len(data))+data
    bof=lambda kind:biff(0x809,struct.pack('<HHHHII',0x600,kind,0xDBB,0x7CC,0x41,6))
    name=b'Sheet1'
    sheet_record=lambda offset:biff(0x85,struct.pack('<IBBBB',offset,0,0,len(name),0)+name)
    prefix=bof(5)+sheet_record(0)+biff(0x0A)
    prefix=bof(5)+sheet_record(len(prefix))+biff(0x0A)
    return prefix+bof(0x10)+(biff(*extra_record) if extra_record else b'')+biff(0x0A)
