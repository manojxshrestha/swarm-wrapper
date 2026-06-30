"""P-M4: the CDP dialog-event predicate used by capture_js_dialog()."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_dialog_msg_predicate():
    from browser_use_backend import _is_dialog_msg

    assert _is_dialog_msg('{"method":"Page.javascriptDialogOpening","params":{"message":"1"}}')
    assert not _is_dialog_msg('{"method":"Page.loadEventFired"}')
    assert not _is_dialog_msg("not json")
    assert not _is_dialog_msg("[]")
