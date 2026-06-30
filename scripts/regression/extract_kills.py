"""Extract FALSE_POSITIVE verdicts from exploitation queues for regression testing.

Outputs JSON test cases with curl commands, expected status, and match/no-match strings.
These are used by run_regression.py to replay against new agent versions.
"""

import json
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "server" / "data"
EXPLOITATION_QUEUE_DIR = DATA_DIR / "exploitation-queues"


def extract_kills(engagement_id: str = "") -> list[dict]:
    """Extract FALSE_POSITIVE verdicts from exploitation queues.

    Args:
        engagement_id: If provided, only extract from this engagement.
                       If empty, extract from all engagements.

    Returns:
        List of test case dicts with: command, expected_status,
        expected_match, expected_no_match, source, timestamp
    """
    if not EXPLOITATION_QUEUE_DIR.exists():
        return []

    queue_files = sorted(EXPLOITATION_QUEUE_DIR.glob("*.json"))
    if engagement_id:
        queue_files = [f for f in queue_files if f.stem.startswith(engagement_id)]

    test_cases = []
    for qf in queue_files:
        try:
            data = json.loads(qf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            if v.get("exploitation_status") == "false_positive":
                # Extract the original payload_example as the command
                payload = v.get("payload_example", "")
                endpoint = v.get("endpoint", "")
                evidence = v.get("evidence", "")
                param = v.get("parameter", "")

                test_case = {
                    "command": f"curl -s -D- '{endpoint}'",
                    "expected_status": "403",
                    "expected_match": "blocked",
                    "expected_no_match": payload[:50] if payload else "",
                    "source": f"{qf.stem}/{v.get('id', 'unknown')}",
                    "timestamp": v.get("exploitation_timestamp", ""),
                    "vuln_class": data.get("vuln_class", "unknown"),
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload,
                }
                test_cases.append(test_case)

    # Deduplicate by command
    seen = set()
    unique = []
    for tc in test_cases:
        key = tc["command"]
        if key not in seen:
            seen.add(key)
            unique.append(tc)

    return unique


def main():
    engagement_id = sys.argv[1] if len(sys.argv) > 1 else ""
    test_cases = extract_kills(engagement_id)
    output = json.dumps(test_cases, indent=2, default=str)
    print(output)

    if not test_cases:
        print("No FALSE_POSITIVE verdicts found.", file=sys.stderr)
        return

    print(f"Extracted {len(test_cases)} FALSE_POSITIVE test cases.", file=sys.stderr)


if __name__ == "__main__":
    main()
