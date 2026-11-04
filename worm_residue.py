"""Exact local residue identities; names alone never authorize deletion."""
import ntpath
import re

QUARANTINE_LINK_HASHES = frozenset({
    'fdd950eb7a0ffd7abacb80150d2bb33196efcefbaa4b760b577b0523b050e34f',
    'e4c2857a1528c1272ac86f8104cdd925107b5a17025c90cc0d93cd21b330c150',
    '8846c3f22f5ea55577549fef493df1f61f7066d3bd90e44d9c6fd9c5ba3c7620',
    'f474699c324729531ea21c15e784de1a4314620a7f20e83b65cb10f5e600de12',
})

def payload_root(path):
    path=ntpath.normpath(str(path))
    drive,tail=ntpath.splitdrive(path)
    if len(drive)!=2 or drive[1]!=':' or not tail.startswith('\\'):
        return None
    parts=tail.strip('\\').split('\\')
    if not parts or parts[0].casefold() not in ('googlechrome','mozillafirefox'):
        return None
    return drive+'\\'+parts[0]

def exact_script_root(path):
    root=payload_root(path)
    if root and ntpath.normcase(ntpath.normpath(str(path)))==ntpath.normcase(ntpath.join(root,'GoogleChrome.a3x')):
        return root
    return None

def exact_startup_root(command):
    """Recognize the observed full startup commands, not substring matches."""
    command=str(command).strip()
    single=command[1:-1] if command.startswith('"') and command.endswith('"') else command
    root=payload_root(single)
    if root and ntpath.normcase(single) in {ntpath.normcase(ntpath.join(root,n)) for n in ('WindowsUpdate.lnk','GoogleUpdate.lnk')}:
        return root
    match=re.fullmatch(r'("[^"]+"|[^\s"]+)\s+/AutoIt3ExecuteScript\s+("[^"]+"|[^\s"]+)',command,re.I)
    if not match:return None
    exe,script=(x.strip('"') for x in match.groups())
    root=exact_script_root(script)
    if root and ntpath.normcase(ntpath.normpath(exe))==ntpath.normcase(ntpath.join(root,'GoogleChrome.exe')):
        return root
    return None
