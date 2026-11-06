"""Bounded header/directory probes; never decode arbitrary large carriers."""
import struct
import zipfile

MAX_DIRECTORY=4*1024*1024
MAX_ENTRIES=20000


def zip_directory(stream,size):
    # Classic EOCD fits in the final 65,557 bytes. Admission occurs before
    # ZipFile allocates the complete central directory. ZIP64 remains unknown.
    stream.seek(max(0,size-65557));tail=stream.read(65557)
    offset=tail.rfind(b'PK\x05\x06')
    if offset<0 or offset+22>len(tail):return {'status':'unavailable'}
    disk,central_disk,on_disk,count,length,start,comment=struct.unpack_from('<HHHHIIH',tail,offset+4)
    if offset+22+comment>len(tail):return {'status':'unavailable'}
    if offset>=20 and tail[offset-20:offset-16]==b'PK\x06\x07':return {'status':'limited'}
    if disk or central_disk or on_disk!=count or count==65535 or start==0xffffffff or length==0xffffffff:
        return {'status':'limited'}
    if count>MAX_ENTRIES or length>MAX_DIRECTORY:return {'status':'limited'}
    if start+length>size-len(tail)+offset:return {'status':'unavailable'}
    try:
        with zipfile.ZipFile(stream) as archive:
            entries=archive.infolist();names={entry.filename for entry in entries}
            return {'status':'complete','office':'[Content_Types].xml' in names and bool(names&{
                'xl/workbook.xml','word/document.xml','ppt/presentation.xml'}),
                'encrypted_project':any(entry.filename=='_TUProj.dat' and entry.flag_bits&1 for entry in entries)}
    except (zipfile.BadZipFile,ValueError):return {'status':'unavailable'}


def png_candidate(prefix):
    if len(prefix)<128:return False
    from family_analysis import rc4,PNG_KEY
    decoded=rc4(prefix[64:128],PNG_KEY)
    return decoded.startswith(b'MZ') and 64<=struct.unpack_from('<I',decoded,60)[0]<=1024*1024
