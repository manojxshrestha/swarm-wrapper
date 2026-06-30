"""Tests for response_diff baseline serialization and diff engine."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="module")
def rd():
    from response_diff import BaselineProfile, ResponseFingerprint, compare
    return BaselineProfile, ResponseFingerprint, compare


class TestBaselineSerialization:
    """Verify normalized_bodies survive JSON round-trip."""

    def test_serialize_roundtrip(self, rd):
        BaselineProfile, ResponseFingerprint, _ = rd
        bp = BaselineProfile(url="https://example.com", method="GET", request_body="")
        for i in range(3):
            fp = ResponseFingerprint(
                raw_status=200, raw_headers={}, raw_body=f"body{i}",
                body_length=100 + i, body_hash=f"hash{i}",
                normalized_body=f"<html>norm{i}</html>",
                normalized_length=18, timing_ms=50.0 + i,
                dom_skeleton=None, json_keys=None, entropy=4.5,
            )
            bp.add_sample(fp)

        assert len(bp.normalized_bodies) == 3
        raw = json.dumps(bp.to_dict())
        bp2 = BaselineProfile.from_dict(json.loads(raw))
        assert len(bp2.normalized_bodies) == 3
        assert bp2.normalized_bodies == bp.normalized_bodies

    def test_old_format_backward_compat(self, rd):
        BaselineProfile, _, _ = rd
        bp = BaselineProfile.from_dict({
            "url": "x", "method": "GET", "request_body": "",
            "sample_count": 3, "status_codes": ["200"],
            "body_lengths": [100, 102, 101],
        })
        assert bp.normalized_bodies == []

    def test_empty_normalized_bodies(self, rd):
        BaselineProfile, _, _ = rd
        bp = BaselineProfile.from_dict({
            "url": "x", "method": "GET", "request_body": "",
            "normalized_bodies": [],
        })
        assert bp.normalized_bodies == []


class TestDiffWithSerializedBaseline:
    """Verify diff engine uses persisted normalized_bodies."""

    def test_diff_detects_different_bodies(self, rd):
        BaselineProfile, ResponseFingerprint, compare = rd
        bp = BaselineProfile(url="https://example.com", method="GET", request_body="")
        bp.add_sample(ResponseFingerprint(
            raw_status=200, raw_headers={}, raw_body="hello",
            body_length=5, body_hash="a",
            normalized_body="hello world", normalized_length=11,
            timing_ms=50.0, dom_skeleton=None, json_keys=None, entropy=4.0,
        ))

        fp = ResponseFingerprint(
            raw_status=200, raw_headers={}, raw_body="injected!",
            body_length=9, body_hash="b",
            normalized_body="injected!!!", normalized_length=11,
            timing_ms=55.0, dom_skeleton=None, json_keys=None, entropy=5.0,
        )

        result = compare(bp, fp, payload_string="injected")
        assert result.normalized_similarity < 1.0
        assert result.reflection_count > 0

    def test_diff_matches_same_body(self, rd):
        BaselineProfile, ResponseFingerprint, compare = rd
        bp = BaselineProfile(url="https://example.com", method="GET", request_body="")
        bp.add_sample(ResponseFingerprint(
            raw_status=200, raw_headers={}, raw_body="hello",
            body_length=5, body_hash="a",
            normalized_body="same content", normalized_length=12,
            timing_ms=50.0, dom_skeleton=None, json_keys=None, entropy=4.0,
        ))

        fp = ResponseFingerprint(
            raw_status=200, raw_headers={}, raw_body="hello",
            body_length=5, body_hash="a",
            normalized_body="same content", normalized_length=12,
            timing_ms=51.0, dom_skeleton=None, json_keys=None, entropy=4.0,
        )

        result = compare(bp, fp)
        assert result.normalized_similarity == 1.0

    def test_serialized_diff(self, rd):
        """Full pipeline: serialize → deserialize → diff works."""
        BaselineProfile, ResponseFingerprint, compare = rd
        bp = BaselineProfile(url="https://example.com", method="GET", request_body="")
        for i in range(3):
            bp.add_sample(ResponseFingerprint(
                raw_status=200, raw_headers={}, raw_body=f"normal{i}",
                body_length=10, body_hash=f"h{i}",
                normalized_body="baseline content", normalized_length=17,
                timing_ms=50.0, dom_skeleton=None, json_keys=None, entropy=4.0,
            ))

        bp2 = BaselineProfile.from_dict(json.loads(json.dumps(bp.to_dict())))

        fp = ResponseFingerprint(
            raw_status=200, raw_headers={}, raw_body="malicious payload",
            body_length=17, body_hash="h99",
            normalized_body="malicious payload", normalized_length=17,
            timing_ms=200.0, dom_skeleton=None, json_keys=None, entropy=7.0,
        )

        result = compare(bp2, fp, payload_string="malicious")
        assert result.normalized_similarity < 1.0
        assert result.timing_anomaly is True
        assert result.reflection_count > 0


class TestH5VerdictWeighting:
    """H5: 404/403 no longer false-positive; reflection no longer false-negative."""

    @staticmethod
    def _fp(rd, status, body, timing=50.0):
        _, ResponseFingerprint, _ = rd
        return ResponseFingerprint(
            raw_status=status, raw_headers={}, raw_body=body,
            body_length=len(body), body_hash=str(hash(body)),
            normalized_body=body, normalized_length=len(body),
            timing_ms=timing, dom_skeleton=None, json_keys=None, entropy=4.0,
        )

    def test_benign_404_is_match_not_flagged(self, rd):
        BaselineProfile, _, compare = rd
        body = "<html><body>404 Not Found - the page was not found</body></html>"
        bp = BaselineProfile(url="x", method="GET", request_body="")
        for _ in range(3):
            bp.add_sample(self._fp(rd, 404, body))
        result = compare(bp, self._fp(rd, 404, body), payload_string="")
        assert not result.error_signatures_found, result.error_signatures_found
        assert result.verdict == "MATCH", f"benign 404 should be MATCH, got {result.verdict}"

    def test_reflected_payload_floors_to_suspicious(self, rd):
        BaselineProfile, _, compare = rd
        bp = BaselineProfile(url="x", method="GET", request_body="")
        for _ in range(3):
            bp.add_sample(self._fp(rd, 200, "<html>search results: none</html>"))
        attack = self._fp(rd, 200, "<html>search results: <script>alert(1)</script></html>")
        result = compare(bp, attack, payload_string="<script>alert(1)</script>")
        assert result.reflection_count > 0
        assert result.verdict in ("SUSPICIOUS", "DIFFERENT"), f"reflected payload must not be MATCH, got {result.verdict}"

    def test_error_signature_only_counts_when_new(self, rd):
        BaselineProfile, _, compare = rd
        # Baseline already emits a SQL error on every request → not evidence.
        body = "<html>Warning: SQL syntax error in query</html>"
        bp = BaselineProfile(url="x", method="GET", request_body="")
        for _ in range(3):
            bp.add_sample(self._fp(rd, 200, body))
        result = compare(bp, self._fp(rd, 200, body))
        assert not result.error_signatures_found, "baseline-present error must not count as new"

    def test_new_error_signature_is_flagged(self, rd):
        BaselineProfile, _, compare = rd
        bp = BaselineProfile(url="x", method="GET", request_body="")
        for _ in range(3):
            bp.add_sample(self._fp(rd, 200, "<html>normal page</html>"))
        attack = self._fp(rd, 200, "<html>You have an error in your SQL syntax near</html>")
        result = compare(bp, attack)
        assert result.error_signatures_found
        assert result.verdict in ("SUSPICIOUS", "DIFFERENT")


class TestM5DiffBlindSpots:
    """M5: tail differences are detected; empty baselines don't read as MATCH."""

    def test_tail_difference_detected(self, rd):
        from response_diff import _levenshtein_similarity

        head = "A" * 3000
        a = head + "normal ending"
        b = head + "LEAKED SECRET token=abcdef appended at the very bottom"
        sim = _levenshtein_similarity(a, b)
        assert sim < 1.0, f"Tail difference must lower similarity, got {sim}"

    def test_empty_baseline_is_not_match(self, rd):
        BaselineProfile, ResponseFingerprint, compare = rd
        empty = BaselineProfile(url="x", method="GET", request_body="")  # no samples
        fp = ResponseFingerprint(
            raw_status=200, raw_headers={}, raw_body="anything",
            body_length=8, body_hash="h", normalized_body="anything",
            normalized_length=8, timing_ms=10.0, dom_skeleton=None, json_keys=None, entropy=4.0,
        )
        result = compare(empty, fp)
        assert result.verdict != "MATCH", "Empty/failed baseline must not read as MATCH"
        assert result.verdict == "SUSPICIOUS"
