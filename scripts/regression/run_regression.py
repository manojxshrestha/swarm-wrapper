"""Replay FP regression test cases against a target.

Reads test cases from extract_kills.py output, executes curl commands,
compares responses against expected patterns, and reports PASS/FAIL.
Exits non-zero if regression rate exceeds threshold.
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path


def _parse_status_code(response: str) -> str:
    """Extract HTTP status code from curl -D- output."""
    m = re.search(r"HTTP/\d+\.\d+\s+(\d+)", response)
    return m.group(1) if m else "000"


def load_test_cases(path: str | Path) -> list[dict]:
    """Load test cases from a JSON file."""
    p = Path(path)
    if not p.exists():
        print(f"ERROR: Test cases file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return json.loads(p.read_text(encoding="utf-8"))


def run_test_case(tc: dict, timeout: int = 30) -> dict:
    """Execute a single test case and return the result.

    Returns dict with:
        command, status_code, response_body, passed, error
    """
    command = tc.get("command", "")
    expected_status = tc.get("expected_status", "")
    expected_match = tc.get("expected_match", "")
    expected_no_match = tc.get("expected_no_match", "")

    result = {
        "command": command,
        "status_code": None,
        "response_body": "",
        "passed": False,
        "error": None,
    }

    if not command:
        result["error"] = "No command specified"
        return result

    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["status_code"] = _parse_status_code(proc.stdout)
        result["response_body"] = proc.stdout
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    # Evaluate expected status
    status_ok = True
    if expected_status:
        actual = str(result["status_code"])
        if expected_status.endswith("xx"):
            prefix = expected_status[:-2]
            status_ok = actual.startswith(prefix)
        else:
            status_ok = actual == expected_status

    # Evaluate expected match
    match_ok = True
    if expected_match and status_ok:
        match_ok = expected_match in result["response_body"]

    # Evaluate expected no-match
    no_match_ok = True
    if expected_no_match:
        no_match_ok = expected_no_match not in result["response_body"]

    result["passed"] = status_ok and match_ok and no_match_ok
    return result


def main():
    import argparse

    parser = argparse.ArgumentParser(description="FP Regression Test Runner")
    parser.add_argument("test_cases", help="Path to test cases JSON file")
    parser.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Max allowed FP regression rate %% (default: 1.0)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-test timeout in seconds (default: 30)",
    )
    parser.add_argument("--output", help="Output results to file (JSON)")
    args = parser.parse_args()

    test_cases = load_test_cases(args.test_cases)
    if not test_cases:
        print("No test cases to run.")
        return

    total = len(test_cases)
    passed = 0
    failed = 0
    errors = 0
    results = []

    print(f"Running {total} regression test cases...\n")

    for i, tc in enumerate(test_cases, 1):
        label = tc.get("source", f"case-{i}")
        print(f"  [{i}/{total}] {label}...", end=" ", flush=True)

        result = run_test_case(tc, timeout=args.timeout)
        results.append(result)

        if result.get("error"):
            errors += 1
            print(f"ERROR: {result['error']}")
        elif result["passed"]:
            passed += 1
            print("PASS")
        else:
            failed += 1
            print(
                f"FAIL (status={result['status_code']}, match={result.get('expected_match','')})"
            )

        time.sleep(0.5)  # Rate limiting

    # Summary
    regression_rate = (failed + errors) / total * 100
    print(f"\n{'='*50}")
    print(f"RESULTS: {total} tests, {passed} passed, {failed} failed, {errors} errors")
    print(f"REGRESSION RATE: {regression_rate:.2f}% (threshold: {args.threshold}%)")
    print(f"{'='*50}")

    if args.output:
        output_path = Path(args.output)
        summary = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "regression_rate": regression_rate,
            "threshold": args.threshold,
            "verdict": "PASS" if regression_rate <= args.threshold else "FAIL",
            "results": results,
        }
        output_path.write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        print(f"\nResults saved to: {args.output}")

    # Exit non-zero on regression
    if regression_rate > args.threshold:
        print(
            f"\nREGRESSION: Rate {regression_rate:.2f}% exceeds threshold {args.threshold}%"
        )
        sys.exit(1)

    print("\nAll tests within threshold.")


if __name__ == "__main__":
    main()
