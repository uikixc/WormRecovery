"""Content rules run locally; a hit supplies evidence, never write authority."""
import threading
import itertools

RULESET_VERSION = '2026.11.06.2'
# Confirmed combinations require recovered code, not a pathname, miner keyword,
# packer, signature publisher or a general-purpose API in isolation.
CONFIRMED_CODE_RULES = {
    'WR_Coinminer_Perfr_Code': 'Perfr-RandomX',
    'WR_Miner_Controller_Code': 'TrueUpdate-Miner-Controller',
    'WR_PNG_Memory_Loader_Code': 'TrueUpdate-PNG-Loader',
}
RULES = r'''
rule WR_Synaptics_Excel_Replication {
 strings:
  $a = "Synaptics" ascii wide nocase
  $b = "~$cache1" ascii wide nocase
  $c = "RegKeySave" ascii wide nocase
  $d = "Workbook_Open" ascii wide nocase
 condition: all of them
}
rule WR_AutoIt_Launch_Chain {
 strings:
  $a = "AutoIt3ExecuteScript" ascii wide nocase
  $b = "GoogleChrome.a3x" ascii wide nocase
  $c = "MozillaFirefox" ascii wide nocase
  $d = "cmd.exe" ascii wide nocase
 condition: $a and $b and ($c or $d)
}
rule WR_Macro_Propagation_Combination {
 strings:
  $a = "Workbook_Open" ascii wide nocase
  $b = "VBComponents" ascii wide nocase
  $c = "CodeModule" ascii wide nocase
  $d = "SaveAs" ascii wide nocase
  $e = "RegWrite" ascii wide nocase
  $f = "VBAWarnings" ascii wide nocase
 condition: $a and $b and $c and $d and ($e or $f)
}
rule WR_Coinminer_Perfr_Code {
 strings:
  $rx = "RandomX" ascii
  $stratum = "stratum+tcp://" ascii
  $pool = { 48 BE 78 9F A7 DF CD 6C E4 E2 48 B8 03 19 30 9C 00 37 78 68 }
  $update = { 48 BF 86 53 38 69 36 7F 69 32 [0-16] 48 BE 2D 75 49 F1 37 18 AE 66 }
 condition: $rx and $stratum and $pool and $update
}
rule WR_Miner_Controller_Code {
 strings:
  $export = "PluginMe" ascii
  $names = { 69 C9 0D 66 19 00 B8 85 10 42 08 81 C1 5F F3 6E 3C F7 E1 8B C1 2B C2 D1 E8 03 C2 }
  $uac = { C7 45 F8 34 B7 95 48 C7 45 FC C1 5D 28 98 [0-16] C7 45 F8 4A 39 26 80 C7 45 FC 7D 83 AA 53 }
  $deploy = { C7 45 E8 01 50 67 1E C7 45 EC 41 29 3B BB [0-16] C7 45 E8 60 4E 37 FD C7 45 EC DB 81 50 FA }
 condition: uint16(0) == 0x5a4d and all of them
}
rule WR_PNG_Memory_Loader_Code {
 strings:
  $k1 = { C7 45 C8 50 40 73 73 [0-8] C7 45 CC 77 30 33 64 C7 45 D0 00 DE 9C AB C7 45 D4 FE CC D0 12 }
  $png = { 81 38 89 50 4E 47 75 0C 83 C0 40 83 EF 40 }
  $map = { 0F B7 4F 16 F7 C1 02 20 00 00 }
 condition: all of them
}
'''
_rules = None
_lock = threading.Lock()
_local = threading.local()


def _scanner():
    global _rules
    import yara_x
    if _rules is None:
        with _lock:
            if _rules is None:
                _rules = yara_x.compile(RULES)
    if not hasattr(_local, 'scanner'):
        _local.scanner = yara_x.Scanner(_rules)
        _local.scanner.set_timeout(3)
    return _local.scanner


def _result(result):
    matching=list(result.matching_rules)
    patterns={}
    for rule in matching:
        if rule.identifier not in CONFIRMED_CODE_RULES:continue
        patterns[rule.identifier]={}
        for pattern in rule.patterns:
            matches=pattern.matches
            selected=list(itertools.islice(matches,64))
            patterns[rule.identifier][pattern.identifier]={
                'matches':[{'offset':m.offset,'length':m.length} for m in selected],
                'complete':len(selected)==len(matches)}
    return {'engine': 'YARA-X', 'ruleset_version': RULESET_VERSION,
            'scope': 'WormRecovery family rules; not a universal antivirus database',
            'matches': [rule.identifier for rule in matching], 'pattern_hits':patterns}


def scan_bytes(data):
    return _result(_scanner().scan(data))


def scan_file(path,*,timeout_seconds=3):
    # Initialize the per-thread scanner once; scan_file avoids copying a whole
    # executable into a second Python bytes allocation.
    if type(timeout_seconds) is not int or not 1<=timeout_seconds<=180:
        raise ValueError('规则扫描预算必须为 1 到 180 秒。')
    scanner=_scanner()
    scanner.set_timeout(timeout_seconds)
    try:return _result(scanner.scan_file(str(path)))
    finally:
        # YARA-X retains its last mapped input. Releasing this lightweight
        # per-thread scanner closes the file before repair can rename/delete
        # it; compiled rules stay globally cached. Do not leave an antivirus
        # scan holding the very file it must later restore.
        scanner.set_timeout(3)
        if getattr(_local,'scanner',None) is scanner:del _local.scanner
