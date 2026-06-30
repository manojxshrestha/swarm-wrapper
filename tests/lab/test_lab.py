"""End-to-end lab test (Phase 1): run the REAL Swarm verification engine against
a live vulnerable app (vuln) and a benign control (httpbin).

Skips cleanly when docker is unavailable, so the unit suite stays green. In CI
(make lab-test / the lab job) docker IS present and these run for real.

What it proves end-to-end:
  - against the vulnerable target, the consensus engine confirms a planted bug
  - against the benign target, the consensus engine produces NO false positive
"""

import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent / "server"))

VULN = "http://127.0.0.1:3000"
HTTPBIN = "http://127.0.0.1:8080"


def _docker():
    exe = shutil.which("docker")
    if not exe:
        return None
    # `docker compose` (v2) vs legacy `docker-compose`
    if subprocess.run([exe, "compose", "version"], capture_output=True).returncode == 0:
        return [exe, "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def _wait(url, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=3)
            return True
        except Exception:
            time.sleep(3)
    return False


@pytest.fixture(scope="module")
def lab():
    dc = _docker()
    if dc is None:
        pytest.skip("docker/compose not available — lab test skipped")
    compose = str(_HERE / "docker-compose.yml")
    subprocess.run(dc + ["-f", compose, "up", "-d", "--build"], check=True)
    try:
        if not _wait(f"{VULN}/safe?q=ok") or not _wait(f"{HTTPBIN}/status/200"):
            pytest.fail("lab targets did not become healthy in time")
        yield
    finally:
        subprocess.run(dc + ["-f", compose, "down", "-v"], check=False)


def test_consensus_confirms_planted_vuln(lab):
    import server

    # vuln server returns SQLITE_ERROR when a single-quote is injected.
    # NOTE: no __PAYLOAD__ marker here — we let _inject_payload_into_url
    # URL-encode the payload so curl sends valid HTTP.
    cmd = f'curl -s "{VULN}/sqli?q="'
    passed, successes, total, results = server._check_consensus(cmd, "sqli")
    assert passed, f"consensus should confirm SQLi on vuln server: {results}"


def test_no_false_positive_on_benign(lab):
    import server

    # httpbin echoes but does not execute — must NOT pass an injection class.
    cmd = f'curl -s "{HTTPBIN}/anything?q=__PAYLOAD__"'
    passed, successes, total, results = server._check_consensus(cmd, "sqli")
    assert not passed, f"benign target must not pass sqli consensus: {results}"
