"""Bounded static recognition of the observed PNG trailing-PE deployment.

Only data is decoded. Exact payload fingerprints do not depend on filenames
or PNG metadata. Unknown executable tails and packed companions stay review
items; a signed host is not condemned by its neighbours.
"""
import hashlib
import io
import struct

PNG_MAGIC = bytes.fromhex('89504e470d0a1a0a')
MAX_PNG_CARRIER = 8 * 1024 * 1024
KNOWN_PAYLOADS = {
    '4f67662ae285337b17e537147e4783a6f307b25d61b362e7908b2595c4188f2a': {
        'bytes': 364544, 'confirmed': True,
        'signature': 'WR_PNG_Tail_Injection_Payload',
        'family': 'PNG-Tail-Injection',
        'basis': 'exact_pe_with_statically_verified_remote_injection_and_log_clearing'},
    '1f27d3a445205cedb55481d34d2a4c281606156aa6a84e9ee9ae39699383b2f3': {
        'bytes': 5194240, 'confirmed': False,
        'signature': 'WR_PNG_Tail_Packed_Companion',
        'family': 'PNG-Tail-Observed-Companion',
        'basis': 'exact_observed_packed_companion_content'},
}
LOADER_BYTES = 4812816
LOADER_PREFIX_SHA256 = '19962e185a6b2dfc6db0e082cb3c2cc2621bc1b3a1ddc68154482b9451ac14f5'
HOST_BYTES = 149320
HOST_SHA256 = '6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8'


def _xor(data, seed, index=0):
    return bytes(value ^ ((seed + index + i) & 255) for i, value in enumerate(data))


def probe(stream, size):
    """Read at most 81 bytes and restore the stream before full admission."""
    if size < 133:
        return False
    saved = stream.tell()
    try:
        stream.seek(0)
        if stream.read(8) != PNG_MAGIC:
            return False
        stream.seek(size - 5)
        trailer = stream.read(5)
        if len(trailer) != 5:
            return False
        start, seed = struct.unpack('<IB', trailer)
        if start < 32 or start % 16 or start + 128 > size - 5:
            return False
        stream.seek(start)
        header = _xor(stream.read(64), seed)
        if len(header) != 64 or header[:2] != b'MZ':
            return False
        offset = struct.unpack_from('<I', header, 60)[0]
        if not 64 <= offset <= min(1024 * 1024, size - 5 - start - 24):
            return False
        stream.seek(start + offset)
        return _xor(stream.read(4), seed, offset) == bytes.fromhex('50450000')
    finally:
        stream.seek(saved)


def identify_pe(data, pe):
    """Only the exact outer image can inherit its own payload identity."""
    result = {'detections': [], 'identifications': []}
    if len(data) == HOST_BYTES and hashlib.sha256(data).hexdigest() == HOST_SHA256:
        result.update(role='observed_png_tail_host', source_sha256=HOST_SHA256)
    if pe.machine != 0x14c or not pe.code_ranges:
        return result
    offset = struct.unpack_from('<I', data, 60)[0]
    if not struct.unpack_from('<H', data, offset + 22)[0] & 0x2000:
        return result
    if len(data) in {row['bytes'] for row in KNOWN_PAYLOADS.values()}:
        digest = hashlib.sha256(data).hexdigest()
        spec = KNOWN_PAYLOADS.get(digest)
        if spec and len(data) == spec['bytes']:
            hit = {key: value for key, value in spec.items() if key not in ('bytes', 'confirmed')}
            hit.update(sha256=digest, bytes=len(data), code_scope='exact_outer_pe_image')
            result['detections' if spec['confirmed'] else 'identifications'].append(hit)
    if len(data) == LOADER_BYTES and hashlib.sha256(memoryview(data)[:-4]).hexdigest() == LOADER_PREFIX_SHA256:
        result['identifications'].append({
            'signature': 'WR_PNG_Tail_Observed_Loader',
            'family': 'PNG-Tail-Observed-Loader',
            'basis': 'exact_observed_loader_except_four_byte_trailer',
            'sha256': hashlib.sha256(data).hexdigest(),
            'code_scope': 'exact_outer_pe_image_except_trailer'})
    return result


def inspect_carrier(data):
    """Validate PNG bounds, then decode the single bounded trailing image."""
    if not data.startswith(PNG_MAGIC) or not probe(io.BytesIO(data), len(data)):
        return None
    if len(data) > MAX_PNG_CARRIER:
        return {'status': 'incomplete', 'reason': 'PNG尾随PE载荷超过8MiB静态检查上限。'}
    start, seed = struct.unpack_from('<IB', data, len(data) - 5)
    cursor = 8
    for index in range(4096):
        if cursor + 12 > start:
            return {'status': 'incomplete', 'reason': 'PNG尾随PE候选的图片块不完整。'}
        length = struct.unpack_from('>I', data, cursor)[0]
        kind = data[cursor + 4:cursor + 8]
        end = cursor + 12 + length
        if end > start or (index == 0 and (kind != b'IHDR' or length != 13)):
            return {'status': 'incomplete', 'reason': 'PNG尾随PE候选的图片块范围无效。'}
        cursor = end
        if kind == b'IEND':
            if length or start != (end + 15) // 16 * 16:
                return {'status': 'incomplete', 'reason': 'PNG尾随PE候选的结束块或载荷偏移无效。'}
            break
    else:
        return {'status': 'incomplete', 'reason': 'PNG尾随PE候选超过图片块数量上限。'}
    decoded = _xor(data[start:-5], seed)
    from family_analysis import PE
    try:
        pe = PE(decoded)
    except (ValueError, struct.error):
        return {'status': 'incomplete', 'reason': 'PNG尾随数据解码为MZ，但PE结构未通过验证。'}
    identity = identify_pe(decoded, pe)
    status = 'detected' if identity['detections'] else 'identified' if identity['identifications'] else 'incomplete'
    return {**identity, 'status': status, 'decodings': [{
        'method': 'png_iend_incrementing_xor', 'png_end': cursor,
        'payload_offset': start, 'seed': seed, 'decoded_bytes': len(decoded),
        'decoded_sha256': hashlib.sha256(decoded).hexdigest(),
        'code_matches': identity['detections'], 'identifications': identity['identifications']}],
        'reason': '已验证PNG尾随编码PE载荷；已知恶意内容按完整指纹确认，其余配套或未知内容保留待核。'}
