import sys

PY34_PLUS = sys.version_info[0] == 3 and sys.version_info[1] >= 4

if PY34_PLUS:
    from .daemon.daemon import Tourbillon
else:
    from daemon2.daemon import Tourbillon
