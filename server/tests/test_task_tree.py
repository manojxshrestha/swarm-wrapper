"""M3: task tree mutations must be concurrency-safe (no lost updates)."""

import json
import os
import sys
import tempfile
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _atomic_write_json(filepath, data):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(filepath.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, str(filepath))


@pytest.fixture
def tt(tmp_path):
    import task_tree

    task_tree.configure(tmp_path, _atomic_write_json, lambda *a, **k: None)
    return task_tree


def test_concurrent_add_task_node_no_lost_updates(tt):
    eid = "concurrency-eng"
    tt.create_task_tree(eid)

    n = 25
    errors = []

    def add(i):
        try:
            tt.add_task_node(eid, "phase-0", f"task number {i}")
        except Exception as e:  # pragma: no cover
            errors.append(str(e))

    threads = [threading.Thread(target=add, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"add_task_node raised under concurrency: {errors}"

    tree = json.loads((tt.TASK_TREE_DIR / f"{eid}.json").read_text())
    phase0_children = tree["nodes"]["phase-0"]["children"]
    assert len(phase0_children) == n, f"Lost updates: expected {n} children, got {len(phase0_children)}"
    # All node ids referenced by phase-0 must exist in the nodes map.
    assert all(c in tree["nodes"] for c in phase0_children)
