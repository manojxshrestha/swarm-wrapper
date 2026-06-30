#!/usr/bin/env python3
"""Scope enforcement — is a target in scope? (Phase 6)

Library + CLI. Fail-closed: a host only passes if it matches a scope pattern.

CLI:  scope_checker.py <target> <scope_file>   # exit 0 = in scope, 1 = out
Patterns (one per line in scope_file, '#' comments ignored):
  example.com        → example.com and any subdomain
  *.example.com      → any subdomain (and the apex)
  app.example.com    → that exact host
"""

import fnmatch
import sys
from urllib.parse import urlsplit


def _host(target: str) -> str:
    """Reduce a URL or host[:port] to a bare lowercase hostname."""
    t = target.strip().lower()
    if "://" in t:
        t = urlsplit(t).netloc or t
    return t.split("@")[-1].split(":")[0].rstrip(".")


def in_scope(target: str, patterns) -> bool:
    host = _host(target)
    if not host:
        return False
    for raw in patterns:
        p = raw.strip().lower().lstrip("#").strip() if raw.strip().startswith("#") else raw.strip().lower()
        if not p or raw.strip().startswith("#"):
            continue
        p = p.rstrip(".")
        if p.startswith("*."):
            base = p[2:]
            if host == base or host.endswith("." + base):
                return True
        elif "*" in p or "?" in p:
            if fnmatch.fnmatch(host, p):
                return True
        else:
            # bare domain → exact host or any subdomain of it
            if host == p or host.endswith("." + p):
                return True
    return False


def _load(scope_file: str) -> list[str]:
    try:
        with open(scope_file, encoding="utf-8") as f:
            return [ln for ln in f.read().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        return []


def demo() -> None:
    pats = ["*.example.com", "test.org"]
    assert in_scope("https://app.example.com/login", pats)
    assert in_scope("example.com", pats)
    assert in_scope("sub.test.org", pats) and in_scope("test.org", pats)
    assert not in_scope("evil.com", pats)
    assert not in_scope("notexample.com", pats)
    assert not in_scope("example.com.evil.com", pats)  # suffix trick blocked
    assert not in_scope("anything", [])  # empty scope = fail-closed
    print("scope_checker demo OK")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--demo":
        demo()
        return 0
    if len(sys.argv) != 3:
        print("usage: scope_checker.py <target> <scope_file>", file=sys.stderr)
        return 2
    target, scope_file = sys.argv[1], sys.argv[2]
    patterns = _load(scope_file)
    if in_scope(target, patterns):
        return 0
    print(f"OUT OF SCOPE: {target} (scope: {scope_file})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
