"""FP/FN benchmark — measures the consensus oracle's precision/recall over a
labeled corpus and gates merges on precision >= 0.90.

Precision = TP / (TP + FP)  — "when we say vulnerable, are we right?"  (the headline claim)
Recall    = TP / (TP + FN)  — "do we catch the real ones?"

Run: pytest tests/benchmark/  (prints the scoreboard regardless of pass/fail).
"""

import sys
from pathlib import Path

import pytest

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
sys.path.insert(0, str(_SERVER))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import CASES  # noqa: E402

PRECISION_GATE = 0.90
RECALL_FLOOR = 0.80  # informational; not a hard gate (recall tuning is ongoing)


def _evaluate():
    import server

    tp = fp = tn = fn = 0
    misses = []
    for c in CASES:
        got = bool(server._consensus_oracle(c["vuln_class"], c["payload"], c["resp"], c["control"]))
        want = c["vulnerable"]
        if got and want:
            tp += 1
        elif got and not want:
            fp += 1
            misses.append(f"FALSE POSITIVE: {c['name']}")
        elif not got and not want:
            tn += 1
        else:
            fn += 1
            misses.append(f"FALSE NEGATIVE: {c['name']}")
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, tp, fp, tn, fn, misses


def test_precision_recall_scoreboard():
    precision, recall, tp, fp, tn, fn, misses = _evaluate()
    print("\n-- Consensus Oracle Benchmark --")
    print(f"  cases={len(CASES)}  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  precision={precision:.3f} (gate >= {PRECISION_GATE})")
    print(f"  recall={recall:.3f} (floor {RECALL_FLOOR})")
    for m in misses:
        print(f"  ! {m}")
    assert precision >= PRECISION_GATE, f"precision {precision:.3f} < gate {PRECISION_GATE}: {misses}"
    # recall is reported but only warns below the floor (kept non-fatal on purpose)
    if recall < RECALL_FLOOR:
        print(f"  WARNING: recall {recall:.3f} below floor {RECALL_FLOOR}")
