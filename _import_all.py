# PyInstaller runtime hook: runs BEFORE main script.
# Adds _MEIPASS to sys.path so bundled source modules are importable.
import sys, os

_meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
if _meipass not in sys.path:
    sys.path.insert(0, _meipass)
_internal = os.path.join(_meipass, '_internal')
if os.path.isdir(_internal) and _internal not in sys.path:
    sys.path.insert(0, _internal)
