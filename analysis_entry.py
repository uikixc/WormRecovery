"""Console transport for offline macro parsing; accepts bytes on stdin only."""
import os
import sys

for name in ('stdout', 'stderr'):
    if getattr(sys, name) is None:
        setattr(sys, name, open(os.devnull, 'w', encoding='utf-8', errors='replace'))

from office_analysis import worker_main

if __name__ == '__main__':
    raise SystemExit(worker_main())
