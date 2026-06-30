#!/usr/bin/env python3
"""Agent/skill usage report (Phase 3) — surface candidates for pruning.

Cross-references every agent file (.opencode/agents/*.md) and skill
(skills/*/SKILL.md) against what actually got used: agents referenced in the
findings DB (vulns.tool_used / test_id) and in session_log.agent.

Prints USED vs NEVER-SEEN so a human can decide what to delete/merge. It does
NOT delete anything — pruning 100+ prompts with no run history would be
reckless; this gives the data to make that call after real engagements.

ponytail: report-only by design. Wire a `--delete-unused` flag once you trust
the usage data across N runs.
"""

import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def list_agents() -> set[str]:
    return {p.stem for p in (ROOT / ".opencode" / "agents").glob("*.md")}


def list_skills() -> set[str]:
    return {p.parent.name for p in (ROOT / "skills").glob("*/SKILL.md")}


def used_agent_ids(db_path: Path) -> set[str]:
    """Agent ids that appear in the findings DB (tool_used/test_id/session_log)."""
    if not db_path.exists():
        return set()
    used: set[str] = set()
    try:
        con = sqlite3.connect(str(db_path))
        for sql in (
            "SELECT DISTINCT tool_used FROM vulns",
            "SELECT DISTINCT test_id FROM vulns",
            "SELECT DISTINCT agent FROM session_log",
        ):
            try:
                for (v,) in con.execute(sql):
                    if v:
                        used.add(str(v).strip())
            except sqlite3.Error:
                pass
        con.close()
    except sqlite3.Error:
        pass
    return used


def classify(defined: set[str], used: set[str]) -> tuple[set[str], set[str]]:
    """Return (seen, never_seen). 'seen' = any used token mentions the name."""
    used_blob = " ".join(used).lower()
    seen = {n for n in defined if n.lower() in used_blob}
    return seen, defined - seen


def _report(db_path: Path) -> str:
    agents, skills = list_agents(), list_skills()
    used = used_agent_ids(db_path)
    seen_a, unseen_a = classify(agents, used)
    out = [
        "# Agent / Skill Usage Report",
        f"agents defined: {len(agents)} | skills defined: {len(skills)} | usage tokens in DB: {len(used)}",
        f"agents seen in findings/log: {len(seen_a)}",
        f"agents NEVER seen (prune candidates): {len(unseen_a)}",
        "",
        "NEVER-SEEN AGENTS (review before deleting — absence may just mean few runs):",
    ]
    out += [f"  - {n}" for n in sorted(unseen_a)] or ["  (none)"]
    if not used:
        out.append("\nNOTE: no usage data in DB yet — run real engagements before pruning.")
    return "\n".join(out)


def demo() -> None:
    seen, unseen = classify({"hunt-xss", "hunt-sqli", "dead-agent"}, {"hunt-xss", "Phase 6: hunt-sqli on x"})
    assert seen == {"hunt-xss", "hunt-sqli"} and unseen == {"dead-agent"}
    print("agent_usage_report demo OK")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        db = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "server" / "data" / "findings.db"
        print(_report(db))
