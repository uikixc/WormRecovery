"""Identify the outer portable application only through its live parent process."""
import os
from pathlib import Path
import re
import sys


def application_path():
    fallback=Path(sys.executable if getattr(sys,'frozen',False) else __file__).resolve()
    if not getattr(sys,'frozen',False):return fallback
    try:
        root=Path(os.environ['WORMRECOVERY_RUNTIME_ROOT']).resolve()
        # Read the Windows known folder rather than trusting a caller-supplied
        # PROGRAMDATA value when selecting an executable for replacement.
        import ctypes
        buffer=ctypes.create_unicode_buffer(32768)
        if ctypes.windll.shell32.SHGetFolderPathW(None,35,None,0,buffer)!=0:return fallback
        cache=(Path(buffer.value)/'WormRecoveryRuntime').resolve()
        if root.parent!=cache or not re.fullmatch('[0-9a-f]{64}',root.name):return fallback
        fallback.relative_to(root)
        launcher=Path(os.environ['WORMRECOVERY_LAUNCHER_PATH']).resolve()
        pid=int(os.environ['WORMRECOVERY_LAUNCHER_PID'])
        import psutil
        for parent in psutil.Process().parents():
            if parent.pid==pid and Path(parent.exe()).resolve()==launcher:return launcher
    except (KeyError,ValueError,OSError):pass
    except Exception:
        # Missing/denied process identity must never redirect an update target.
        pass
    return fallback
