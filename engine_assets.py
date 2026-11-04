"""Locate version-pinned offline engines shipped inside the single EXE."""
from pathlib import Path
import json
import functools
import os
import sys


def engine_root():
    if getattr(sys, '_MEIPASS', None):
        candidate = Path(sys._MEIPASS) / 'engines'
        if (candidate / 'manifest.json').is_file():
            return candidate
    inherited = os.environ.get('WORMRECOVERY_ENGINE_ROOT')
    if inherited and (Path(inherited) / 'manifest.json').is_file():
        return Path(inherited)
    return Path(__file__).parent / 'build/engine-assets/engines'


@functools.lru_cache(maxsize=4)
def _manifest(root):
    path = Path(root) / 'manifest.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}


def manifest():
    return _manifest(str(engine_root()))


def subprocess_environment():
    environment = os.environ.copy()
    environment['WORMRECOVERY_ENGINE_ROOT'] = str(engine_root())
    environment['PYTHONIOENCODING'] = 'utf-8'
    return environment
