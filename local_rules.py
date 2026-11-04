"""Content rules run locally; a hit supplies evidence, never write authority."""
import threading

RULESET_VERSION = '2026.11.05.1'
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
    return {'engine': 'YARA-X', 'ruleset_version': RULESET_VERSION,
            'scope': 'WormRecovery family rules; not a universal antivirus database',
            'matches': [rule.identifier for rule in result.matching_rules]}


def scan_bytes(data):
    return _result(_scanner().scan(data))


def scan_file(path):
    # Initialize the per-thread scanner once; scan_file avoids copying a whole
    # executable into a second Python bytes allocation.
    return _result(_scanner().scan_file(str(path)))
