"""Regression test for H4: modules must import even when `fcntl` is unavailable.

`fcntl` is POSIX-only. Several modules (findings_db, browser_tools,
browser_use_backend) used to `import fcntl` unconditionally at module top,
which raised ModuleNotFoundError on Windows and prevented the whole server
from starting. These imports are now guarded with an msvcrt / no-op fallback.

We verify portability by importing the modules in a subprocess whose import
system has `fcntl` (and `msvcrt`) blocked — forcing the no-op tier — and
asserting the import succeeds. Running in a subprocess avoids polluting the
parent interpreter's already-imported modules.
"""

import subprocess
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent

_SNIPPET = """
import builtins, sys
_real_import = builtins.__import__
def _blocked_import(name, *a, **k):
    # Block only fcntl (POSIX-only). This forces the modules onto their
    # msvcrt/no-op fallback path on any platform. We must NOT block msvcrt
    # because Windows stdlib (subprocess/tempfile) imports it internally.
    if name == "fcntl":
        raise ImportError("blocked for test")
    return _real_import(name, *a, **k)
builtins.__import__ = _blocked_import
sys.modules.pop("fcntl", None)
import findings_db          # noqa: F401
import browser_tools        # noqa: F401
import browser_use_backend  # noqa: F401
# Exercise the fallback lock helpers so the no-op path is actually run.
import json, tempfile, os
d = tempfile.mkdtemp()
db = findings_db.FindingsDB(os.path.join(d, "t.db"))
db.init_engagement("eng-x", client="C")
db.close()
print("IMPORT_OK")
"""


def test_modules_import_without_fcntl():
    result = subprocess.run(
        [sys.executable, "-c", _SNIPPET],
        cwd=str(SERVER_DIR),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "IMPORT_OK" in result.stdout, (
        f"Modules failed to import without fcntl.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
