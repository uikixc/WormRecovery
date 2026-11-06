"""Bounded byte decoding of the observed modified NRV2E stream.

This is a data parser, not emulation: no native instructions, import resolution,
callbacks, file writes or specimen execution. The caller supplies the compressed
section resolved from the packer's RIP-relative instruction, not a file name.
"""
import time


def decode_nrv2e(data, max_output=16*1024*1024, timeout=3):
    source=memoryview(data);position=0;bits=0;remaining=0;steps=0
    output=bytearray();deadline=time.monotonic()+timeout

    def bit():
        nonlocal position,bits,remaining,steps
        steps+=1
        if steps%4096==0 and time.monotonic()>deadline:
            raise ValueError('静态解包达到时间上限。')
        if remaining==0:
            if position+4>len(source):raise ValueError('压缩位流被截断。')
            bits=int.from_bytes(source[position:position+4],'little');position+=4;remaining=32
        value=bits>>31;bits=(bits<<1)&0xffffffff;remaining-=1
        return value

    def byte():
        nonlocal position
        if position>=len(source):raise ValueError('压缩数据被截断。')
        value=source[position];position+=1
        return value

    last_offset=1
    while True:
        while bit():
            if len(output)>=max_output:raise ValueError('静态解包超过输出上限。')
            output.append(byte())
        offset=1
        while True:
            offset=offset*2+bit()
            if offset>0x1000002:raise ValueError('压缩偏移前缀无效。')
            if bit():break
            offset=(offset-1)*2+bit()
        if offset==2:
            offset=last_offset;length=bit()
        else:
            offset=(offset-3)*256+byte()
            if offset==0xffffffff:break
            length=(offset^0xffffffff)&1;offset=(offset>>1)+1;last_offset=offset
        if length:length=1+bit()
        elif bit():length=3+bit()
        else:
            length=1
            while True:
                length=length*2+bit()
                if length>=max_output:raise ValueError('压缩长度前缀无效。')
                if bit():break
            length+=3
        length+=offset>0x500
        count=length+1
        if offset>len(output) or len(output)+count>max_output:
            raise ValueError('压缩回溯引用无效或超过输出上限。')
        # Repeated back-references may overlap. Extend in bounded blocks rather
        # than running a Python loop once per decompressed byte.
        pattern=bytes(output[-offset:]);copies,tail=divmod(count,len(pattern))
        output.extend(pattern*copies+pattern[:tail])
        if time.monotonic()>deadline:raise ValueError('静态解包达到时间上限。')
    return bytes(output),position
