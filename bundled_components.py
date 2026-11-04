"""Resolve private components from this executable's bundle, never from PATH."""
from pathlib import Path
import sys


def component_path(name):
    if name not in ('WormRecovery-Analysis.exe', 'WormRecovery-CLI.exe'):
        raise ValueError('未知内部组件。')
    roots = []
    if getattr(sys, '_MEIPASS', None):
        roots.append(Path(sys._MEIPASS) / 'engines')
    if getattr(sys, 'frozen', False):
        roots.append(Path(sys.executable).resolve().parent)
    for root in roots:
        candidate = root / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError('内部分析组件缺失或已损坏，请重新取得完整的 WormRecovery.exe。')
