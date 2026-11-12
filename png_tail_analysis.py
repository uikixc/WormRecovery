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
# R9 verified both deployments share their mapped bytes. Only timestamp,
# checksum and bytes outside the mapped image are omitted. All remaining
# headers, entry, directories, section layout, code and data must agree.
NORMALIZED_IMAGES = {
    '687387bf143765dc030b1ff3e65dcc04c966bf86f67b1d967471d879b964533f': {
        'mapped_bytes': 364544,
        'reference_sha256': '4f67662ae285337b17e537147e4783a6f307b25d61b362e7908b2595c4188f2a',
        **KNOWN_PAYLOADS['4f67662ae285337b17e537147e4783a6f307b25d61b362e7908b2595c4188f2a']},
    'aa3c1c8fc9383057eae37f34cb7b8a2f4db450f1a2c9998cf3f8d24dad09007b': {
        'mapped_bytes': 5194240,
        'reference_sha256': '1f27d3a445205cedb55481d34d2a4c281606156aa6a84e9ee9ae39699383b2f3',
        **KNOWN_PAYLOADS['1f27d3a445205cedb55481d34d2a4c281606156aa6a84e9ee9ae39699383b2f3']},
    '2d0888a30de66211ca097aa25a7d1422d524dbeedb693ebcd6622fa8bca970a9': {
        'mapped_bytes': 4812800,
        'reference_sha256': 'b161853e56f31aaa9a4ad4292953a43d5529e262136126da94f4a05277de033b',
        'confirmed': False, 'signature': 'WR_PNG_Tail_Observed_Loader',
        'family': 'PNG-Tail-Observed-Loader'},
}
# Byte-verified entry and three separated R9 sites. They identify only an
# observed code combination, not the unresolved consumer or API semantics.
LOADER_ENTRY_RVA = 0x689023
LOADER_CODE_ANCHORS = (
    (0x689023, bytes.fromhex('559cbdb24c8f5bf7c505063a00f7d58dac2d5f942dbb550f85e947c5ff')),
    (0x2DD830, bytes.fromhex('c7442408401e2830')),
    (0x5C628B, bytes.fromhex('e877b31000')),
    (0x6D1607, bytes.fromhex('894c24006834fa953ee9f8b40500')),
)
_XOR_TABLES = tuple(bytes(value ^ key for value in range(256)) for key in range(256))


def _xor(data, seed, index=0):
    if len(data) < 1024:
        return bytes(value ^ ((seed + index + i) & 255) for i, value in enumerate(data))
    # The key repeats every 256 bytes. translate performs each lane in C and
    # keeps allocation bounded by the admitted carrier; no target code runs.
    output = bytearray(len(data))
    for lane in range(256):
        output[lane::256] = data[lane::256].translate(_XOR_TABLES[(seed + index + lane) & 255])
    return bytes(output)


def normalized_image(data, pe):
    """Hash the outer mapped image, normalizing only two metadata fields."""
    end = max([pe.headers] + [raw + size for _, size, raw, _ in pe.sections if size])
    if end not in {spec['mapped_bytes'] for spec in NORMALIZED_IMAGES.values()} or end > len(data):
        return None
    offset = struct.unpack_from('<I', data, 60)[0]
    timestamp, checksum = offset + 8, offset + 88
    view = memoryview(data)
    try:
        fingerprint = hashlib.sha256(view[:timestamp])
        fingerprint.update(bytes(4))
        fingerprint.update(view[timestamp + 4:checksum])
        fingerprint.update(bytes(4))
        fingerprint.update(view[checksum + 4:end])
        digest = fingerprint.hexdigest()
        spec = NORMALIZED_IMAGES.get(digest)
        if not spec or spec['mapped_bytes'] != end:
            return None
        hit = {key: value for key, value in spec.items() if key not in ('bytes', 'confirmed')}
        hit.update(basis='normalized_outer_mapped_pe_content', normalized_sha256=digest,
                   sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                   code_scope='outer_mapped_pe_except_timestamp_checksum',
                   normalized_fields=['coff_timestamp', 'optional_header_checksum'],
                   excluded_overlay_bytes=len(data) - end)
        return spec['confirmed'], hit
    finally:
        view.release()


def loader_code_combination(data, pe):
    """Keep changed bodies as review-only evidence, outside exact groups."""
    if pe.entry != LOADER_ENTRY_RVA:
        return None
    matches = []
    for rva, anchor in LOADER_CODE_ANCHORS:
        try:
            offset = pe.rva(rva, len(anchor))
        except ValueError:
            return None
        if not any(start <= offset and offset + len(anchor) <= end for start, end in pe.code_ranges):
            return None
        if data[offset:offset + len(anchor)] != anchor:
            return None
        matches.append({'rva': rva, 'file_offset': offset, 'bytes': len(anchor)})
    return {'signature': 'WR_PNG_Tail_Loader_Code_Combination',
            'family': 'PNG-Tail-Observed-Loader-Code',
            'basis': 'active_entry_and_three_separated_executable_r9_anchors',
            'code_scope': 'four_outer_executable_ranges', 'pattern_hits': matches,
            'sha256': hashlib.sha256(data).hexdigest(),
            'consumer_chain_proven': False, 'automatic_cleanup': False}


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
    if not result['detections'] and not result['identifications']:
        normalized = normalized_image(data, pe)
        if normalized:
            confirmed, hit = normalized
            result['detections' if confirmed else 'identifications'].append(hit)
        else:
            combination = loader_code_combination(data, pe)
            if combination:
                result['identifications'].append(combination)
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
        'reason': '已验证PNG尾随编码PE载荷；已知恶意内容按完整或规范化映像指纹确认，其余配套或未知内容保留待核。'}
