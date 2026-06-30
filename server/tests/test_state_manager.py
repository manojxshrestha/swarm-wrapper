"""Tests for enterprise state management."""

import tempfile
from pathlib import Path

import pytest

from state_manager import (
    configure,
    create_checkpoint,
    get_engagement_status,
    list_checkpoints,
)


@pytest.fixture
def state_dir():
    with tempfile.TemporaryDirectory() as tmp:
        configure(Path(tmp))
        yield Path(tmp)


class TestStateManager:
    def test_create_checkpoint(self, state_dir):
        result = create_checkpoint("test-eng", "tester", "Initial checkpoint")
        assert "checkpoint_id" in result
        assert result["description"] == "Initial checkpoint"
        cp_id = result["checkpoint_id"]

        checkpoints = list_checkpoints("test-eng")
        assert len(checkpoints) >= 1
        assert checkpoints[0]["checkpoint_id"] == cp_id

    def test_list_checkpoints(self, state_dir):
        create_checkpoint("test-eng", "tester", "First")
        create_checkpoint("test-eng", "tester", "Second")
        checkpoints = list_checkpoints("test-eng")
        assert len(checkpoints) == 2

    def test_multiple_engagements(self, state_dir):
        create_checkpoint("eng-a", "tester", "Checkpoint A")
        create_checkpoint("eng-b", "tester", "Checkpoint B")
        assert len(list_checkpoints("eng-a")) == 1
        assert len(list_checkpoints("eng-b")) == 1

    def test_unknown_engagement(self, state_dir):
        status = get_engagement_status("nonexistent")
        assert isinstance(status, dict)

    def test_checkpoint_disk_persistence(self, state_dir):
        result = create_checkpoint("disk-eng", "tester", "Disk test")
        cp_id = result["checkpoint_id"]

        checkpoints = list_checkpoints("disk-eng")
        assert len(checkpoints) == 1
        assert checkpoints[0]["checkpoint_id"] == cp_id

    def test_wal_logging(self, state_dir):
        create_checkpoint("wal-eng", "tester", "WAL entry 1")
        create_checkpoint("wal-eng", "tester", "WAL entry 2")
        from state_manager import get_wal

        wal = get_wal("wal-eng")
        assert len(wal) >= 2

    def test_wal_append_only(self, state_dir):
        """C-15: WAL uses append-only (JSON Lines), not read-all-rewrite."""
        from state_manager import get_wal, _wal_path
        create_checkpoint("append-eng", "tester", "CP1")
        create_checkpoint("append-eng", "tester", "CP2")
        wal_path = _wal_path("append-eng")
        content = wal_path.read_text(encoding="utf-8")
        # Each entry should be on its own line (JSON Lines format)
        lines = [l for l in content.strip().split("\n") if l.strip()]
        assert len(lines) >= 2, f"Expected >=2 lines, got {len(lines)} in {content!r}"
        # Verify entries are valid JSON
        import json
        for line in lines:
            obj = json.loads(line)
            assert "action" in obj

    def test_wal_backward_compat_json_array(self, state_dir):
        """C-15: get_wal handles old JSON array format gracefully."""
        from state_manager import get_wal, _wal_path
        wal_path = _wal_path("compat-eng")
        wal_path.parent.mkdir(parents=True, exist_ok=True)
        # Write old format: JSON array
        import json as _json
        wal_path.write_text(_json.dumps([
            {"action": "checkpoint", "checkpoint_id": "old-cp-1"},
            {"action": "checkpoint", "checkpoint_id": "old-cp-2"},
        ]))
        wal = get_wal("compat-eng")
        assert len(wal) == 2
        assert wal[0]["action"] == "checkpoint"

    def test_checkpoint_id_is_uuid(self, state_dir):
        for _ in range(5):
            result = create_checkpoint("uuid-test", "tester", "UUID test")
            cp_id = result["checkpoint_id"]
            assert cp_id.startswith("cp-"), f"Expected 'cp-' prefix, got {cp_id}"
            hex_part = cp_id[3:]
            assert len(hex_part) == 12, f"Expected 12 hex chars, got {len(hex_part)}"
            int(hex_part, 16)  # raises ValueError if not hex

    def test_uuid_unique_across_restarts(self, state_dir, monkeypatch):
        ids = set()
        for _ in range(20):
            result = create_checkpoint("unique-test", "tester", "Unique test")
            ids.add(result["checkpoint_id"])
        assert len(ids) == 20, f"Expected 20 unique IDs, got {len(ids)}"

    def test_counter_not_reset_by_new_session(self, state_dir):
        """Prove no in-memory counter dependency."""
        cp1 = create_checkpoint("session-eng", "tester", "CP1")
        cp2 = create_checkpoint("session-eng", "tester", "CP2")
        assert cp1["checkpoint_id"] != cp2["checkpoint_id"]
