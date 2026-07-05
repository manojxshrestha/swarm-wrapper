"""OWASP WSTG Knowledge Base MCP Server.

Provides tools for looking up WSTG test cases, managing pentest findings,
and generating reports. Designed to work alongside the PortSwigger Burp Suite
MCP server for automated web application penetration testing.
"""

import functools
import hashlib
import inspect
import json
import logging
import math
import os
import re
import secrets
import shlex
import subprocess  # nosec B404
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

from browser_tools import (
    browser_act,
    browser_analyze,
    browser_auto_auth,
    browser_crawl,
    browser_extract_storage,
    browser_login,
    browser_screenshot,
)
from context_compression import (
    compress_phase_context as _cc_compress,
)
from context_compression import (
    configure as _cc_configure,
)
from context_compression import (
    get_engagement_summary as _cc_summary,
)
from endpoint_priority import (
    configure as _ep_configure,
)
from endpoint_priority import (
    get_priority_queue as _ep_get_queue,
)
from endpoint_priority import (
    prioritize_endpoints as _ep_prioritize,
)
from findings_db import FindingsDB as _FindingsDB
from findings_db import get_default_db_path as _fdb_path
from knowledge_graph import (
    add_graph_edge as _kg_add_edge,
)
from knowledge_graph import (
    add_graph_node as _kg_add_node,
)
from knowledge_graph import (
    configure as _kg_configure,
)
from knowledge_graph import (
    find_chains as _kg_find_chains,
)
from knowledge_graph import (
    get_graph_summary as _kg_summary,
)
from knowledge_graph import (
    query_graph as _kg_query,
)
from server_data import (
    _CODE_TO_NUM,
    CATEGORIES,
    CVSS_CAP_SEVERITY,
    CVSS_CONFIDENCE_CAPS,
    DELIVERABLE_TYPES,
    EVIDENCE_CHECKLISTS,
    EXHAUSTION_THRESHOLDS,
    PHASE_NAMES,
    PHASE_TEST_REQUIREMENTS,
    PHASE_TOOL_REQUIREMENTS,
    SLOT_TYPES,
    TOOL_REGISTRY,
    WITNESS_PAYLOADS,
)
from task_tree import (
    add_task_node as _tt_add,
)
from task_tree import (
    configure as _tt_configure,
)

# Tier 1 modules (Roadmap features)
from task_tree import (
    create_task_tree as _tt_create,
)
from task_tree import (
    get_subtree as _tt_subtree,
)
from task_tree import (
    get_task_summary as _tt_summary,
)
from task_tree import (
    get_task_tree as _tt_get,
)
from task_tree import (
    update_task_node as _tt_update,
)
from tool_parsers import (
    ingest_tool_file as _tp_ingest,
)
from tool_parsers import (
    parse_tool_output as _tp_parse,
)
from tool_verification import (
    configure as _tv_configure,
)
from tool_verification import (
    verify_tool_result as _tv_verify,
)
from waf_evasion import (
    configure as _waf_configure,
)
from waf_evasion import (
    get_waf_bypass as _waf_bypass,
)

# Tier 2 modules (Roadmap features)
from waf_evasion import (
    identify_waf as _waf_identify,
)
from waf_evasion import (
    list_waf_vendors as _waf_list,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("swarm-server")

mcp = FastMCP(
    "wstg-pentest",
    instructions=(
        "You are an OWASP WSTG penetration testing MCP server. "
        "Your workflow per test: detect → immediately exploit → track. "
        "Use Burp MCP for execution and WSTG MCP for methodology.\n\n"
        "=== PER-TEST WORKFLOW ===\n"
        "For each test in any category:\n"
        "1. get_wstg_test() to load methodology + payloads\n"
        "2. Execute via Burp: burp_repeater, burp_scanner, burp_intruder\n"
        "3. If vulnerability found:\n"
        "   a. log_finding() with evidence\n"
        "   b. create_exploitation_queue() — queue by class (xss, sqli, cmdi, ssti, ssrf, idor, path_traversal)\n"
        "   c. get_technique_guide() — load attack techniques + payloads\n"
        "   d. get_witness_payloads(sink_context) — context-aware PoC payloads\n"
        "   e. Execute exploit payloads via Burp\n"
        "   f. If blocked: get_waf_bypass(vendor, vuln_class)\n"
        "   g. mark_exploited() with classification:\n"
        "      - 'exploited' — reproducible impact\n"
        "      - 'potential' — blocked after exhaustive bypass\n"
        "      - 'failed' — inconclusive\n"
        "      - 'false_positive' — security feature withstands\n"
        "4. validate_poc() — EXECUTE every PoC command in real time to verify it actually works. "
        "Do NOT log findings with untested PoCs. If the PoC fails (wrong status, missing content, timeout), "
        "investigate and fix before proceeding.\n"
        "5. track_test() — record coverage\n"
        "6. After all tests: find_chains() for attack paths, update_finding() for severity upgrades, "
        "get_coverage() then generate_report()\n\n"
        "=== REPORTING ===\n"
        "1. get_coverage() — verify adequate test coverage before report\n"
        "2. get_engagement_status() — check overall progress\n"
        "3. generate_report() — produce full markdown report\n\n"
        "=== ADDITIONAL CAPABILITIES ===\n"
        "Source code analysis: start_code_analysis, save_code_analysis\n"
        "Checkpointing: save_checkpoint, resume_engagement, generate_resume_prompt\n"
        "Engagement config: load_engagement_config, get_engagement_config, get_engagement_rules\n"
        "Deliverables: save_deliverable, get_deliverable, list_deliverables\n"
        "Git checkpointing: git_checkpoint, git_rollback\n"
        "Monitoring: get_engagement_status, get_audit_log\n"
        "Task tree: create_task_tree, add_task_node, update_task_node, get_task_tree, get_subtree\n"
        "Endpoint prioritization: prioritize_endpoints, get_priority_queue\n"
        "Knowledge graph: add_graph_node, add_graph_edge, query_graph, find_chains\n"
        "PoC validation: validate_poc, validate_finding_poc\n"
        "Tool output: parse_tool_output, ingest_tool_file, verify_tool_result\n"
        "WAF evasion: identify_waf, get_waf_bypass, list_waf_vendors\n"
        "Context compression: compress_phase_context, get_engagement_summary\n"
        "Browser automation: browser_act, browser_analyze, browser_login, browser_auto_auth, browser_screenshot, browser_crawl, browser_extract_storage\n\n"
        "=== FINDINGS DATABASE (SQLite) ===\n"
        "Cross-session persistence. Use instead of JSON-based tools for structured queries:\n"
        "findings_init(), findings_add_host(), findings_add_vuln(), findings_add_credential(),\n"
        "findings_add_chain(), findings_log_action(), findings_list_hosts(), findings_list_vulns(),\n"
        "findings_stats(), findings_export(), findings_handoff()\n"
        "CLI: ./scripts/findings.sh <cmd>, ./scripts/handoff.sh <engagement_id>"
    ),
)

WSTG_DIR = Path(__file__).parent.parent / "knowledge" / "wstg"
DATA_DIR = Path(__file__).parent / "data"
TRACKING_DIR = DATA_DIR / "tracking"
TOOL_TRACKING_DIR = DATA_DIR / "tool-tracking"
GATE_TRACKING_DIR = DATA_DIR / "gate-tracking"
SCOPE_DIR = DATA_DIR / "scope"
JUDGE_TRACKING_DIR = DATA_DIR / "judge-tracking"
EVENTS_DIR = DATA_DIR / "events"
CODE_ANALYSIS_DIR = DATA_DIR / "code-analysis"
CHECKPOINTS_DIR = DATA_DIR / "checkpoints"
EXPLOITATION_QUEUE_DIR = DATA_DIR / "exploitation-queues"
CONFIG_DIR = DATA_DIR / "configs"
DELIVERABLES_DIR = DATA_DIR / "deliverables"
TASK_TREE_DIR = DATA_DIR / "task-trees"
PRIORITY_QUEUE_DIR = DATA_DIR / "priority-queues"
WAF_DATA_DIR = DATA_DIR / "waf-data"
GRAPH_DIR = DATA_DIR / "knowledge-graphs"
QA_TRACKING_DIR = DATA_DIR / "qa-tracking"
ENGAGEMENTS_DIR = Path(__file__).parent.parent / "engagements"
NUCLEI_TEMPLATES_DIR = Path(__file__).parent.parent / "wordlists" / "nuclei-templates"

# Vuln class → nuclei template subdirectory mapping
VULN_TO_NUCLEI_DIR: dict[str, str] = {
    "sqli": "sqli",
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "xss_dom": "xss",
    "xss": "xss",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "cmdi": "cmdi",
    "path_traversal": "path-traversal",
    "lfi": "path-traversal",
    "open_redirect": "open-redirect",
    "xxe": "xxe",
    "nosqli": "nosqli",
    "ldap_injection": "ldap-injection",
    "graphql_abuse": "graphql",
    "graphql": "graphql",
    "cors": "cors",
    "cors_misconfiguration": "cors",
    "csp": "csp",
    "clickjacking": "clickjacking",
    "csrf": "csrf",
    "prototype_pollution": "prototype-pollution",
    "host_header_injection": "misc",
}

TOOL_SUCCESS_MARKERS: dict[str, list[str]] = {
    "nuclei": ["[critical]", "[high]", "[medium]", "[low]"],
    "sqlmap": ["parameter.*appears to be", "injectable", "vulnerable"],
    "dalfox": ["Vulnerable", "POC"],
    "smuggler": ["Vulnerable", "CL.TE", "TE.CL", "TE.TE"],
    "http_smuggler": ["Vulnerable", "Smuggling"],
    "commix": ["Vulnerable", "confirmed"],
    "sstimap": ["Vulnerable", "confirmed"],
    "crlfuzz": ["Vulnerable", "CRLF"],
    "corscanner": ["Vulnerable", "misconfig"],
}


def _parse_wstg_file(filepath: Path) -> dict:
    """Parse a WSTG markdown file, extracting YAML frontmatter and body."""
    content = filepath.read_text(encoding="utf-8")
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            frontmatter = yaml.safe_load(parts[1]) or {}
            body = parts[2].strip()
            return {**frontmatter, "content": body, "filepath": str(filepath)}
    return {"content": content, "filepath": str(filepath)}


def _find_test_file(test_id: str) -> Path | None:
    """Find a WSTG test file by ID (e.g., WSTG-INPV-01)."""
    test_id_upper = test_id.upper().replace(" ", "")
    for md_file in WSTG_DIR.rglob("WSTG-*.md"):
        if md_file.stem.upper() == test_id_upper:
            return md_file
    # Fallback: partial match
    for md_file in WSTG_DIR.rglob("WSTG-*.md"):
        if test_id_upper in md_file.stem.upper():
            return md_file
    return None


# ── Crash-Safe I/O Helpers ────────────────────────────────────────

_write_lock = threading.Lock()


def _sanitize_id(raw: str, max_len: int = 100) -> str:
    """Sanitize an identifier (engagement_id, config name, etc.) for safe filesystem use.
    Allows alphanumeric, dots, hyphens, underscores. Rejects path traversal chars.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError(f"Invalid identifier (empty or wrong type): {raw!r}")
    safe = re.sub(r"[^a-zA-Z0-9._-]", "", raw[:max_len])
    safe = safe.lstrip(".")
    safe = safe[:max_len]
    if not safe:
        raise ValueError(f"Invalid identifier (empty after sanitization): {raw!r}")
    return safe


def _engagement_path(engagement_id: str) -> Path:
    """Get the engagement directory path, sanitizing the ID."""
    return ENGAGEMENTS_DIR / _sanitize_id(engagement_id)


def _atomic_write_json(filepath: Path, data: Any) -> None:
    """Crash-safe JSON write: write to temp file, then atomic rename."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(filepath.parent), suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        # os.replace atomically overwrites an existing destination on BOTH
        # POSIX and Windows (os.rename raises FileExistsError on Windows).
        os.replace(tmp_path, str(filepath))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _append_live_log(
    engagement_id: str,
    tool_name: str,
    args: dict,
    result: str,
    duration_ms: int = 0,
    is_error: bool = False,
) -> None:
    """Append a verbose human-readable entry to engagements/runtime/<eid>/logs.txt.

    This is the live logging file — designed for `tail -f` monitoring.
    Every MCP tool call is logged with full args and full result.
    """
    eng_dir = _engagement_path(engagement_id)
    eng_dir.mkdir(parents=True, exist_ok=True)
    log_file = eng_dir / "logs.txt"

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    status = "ERROR" if is_error else "OK"
    duration_str = f" ({duration_ms}ms)" if duration_ms > 0 else ""

    # Format args — redact long values (>500 chars) but show everything else
    formatted_args = {}
    for k, v in args.items():
        if k == "engagement_id":
            continue  # Redundant — it's in the header
        v_str = str(v)
        if len(v_str) > 500:
            formatted_args[k] = v_str[:500] + f"... ({len(v_str)} chars)"
        else:
            formatted_args[k] = v_str

    args_lines = ""
    if formatted_args:
        args_lines = "\n".join(f"    {k}: {v}" for k, v in formatted_args.items())

    # Truncate result for display (keep first 2000 chars)
    result_str = str(result)
    if len(result_str) > 2000:
        result_display = result_str[:2000] + f"\n    ... ({len(result_str)} chars total)"
    else:
        result_display = result_str

    # Format the entry as a clear, tail-f-friendly block
    entry_lines = [
        f"[{timestamp}] [{status}]{duration_str} {tool_name}",
    ]
    if args_lines:
        entry_lines.append("  ARGS:")
        entry_lines.append(args_lines)
    entry_lines.append("  RESULT:")
    # Indent each line of the result
    for rline in result_display.split("\n"):
        entry_lines.append(f"    {rline}")
    entry_lines.append("")  # Blank line separator

    entry = "\n".join(entry_lines) + "\n"

    with _write_lock:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(entry)
            f.flush()
            os.fsync(f.fileno())


def _make_logged_tool(original_tool_decorator):
    """Wrap FastMCP's @mcp.tool() to auto-log every tool call to logs.txt.

    Returns a replacement decorator that:
    1. Wraps the tool function with logging
    2. Extracts engagement_id from args (if present)
    3. Logs full args + result to engagements/runtime/<eid>/logs.txt
    4. Preserves function signature for FastMCP parameter inspection
    """

    def logged_tool(*deco_args, **deco_kwargs):
        real_decorator = original_tool_decorator(*deco_args, **deco_kwargs)

        def wrapper(func):
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())
            has_eid = "engagement_id" in param_names

            @functools.wraps(func)
            def logged_func(*args, **kwargs):
                # Extract engagement_id if present
                engagement_id = None
                if has_eid:
                    if "engagement_id" in kwargs:
                        engagement_id = kwargs["engagement_id"]
                    else:
                        eid_idx = param_names.index("engagement_id")
                        if eid_idx < len(args):
                            engagement_id = args[eid_idx]

                # Build full args dict for logging
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                all_args = dict(bound.arguments)

                start = time.monotonic()
                is_error = False
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    result = f"EXCEPTION: {type(e).__name__}: {e}"
                    is_error = True
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    if engagement_id:
                        try:
                            _append_live_log(
                                engagement_id,
                                func.__name__,
                                all_args,
                                str(result),
                                duration_ms=elapsed_ms,
                                is_error=is_error,
                            )
                        except Exception:
                            logger.debug("Logging failed (non-critical)", exc_info=True)

            # Preserve the original signature for FastMCP parameter extraction
            logged_func.__signature__ = sig
            return real_decorator(logged_func)

        return wrapper

    return logged_tool


# Replace mcp.tool with the logging wrapper — ALL subsequent @mcp.tool()
# calls will auto-log to logs.txt. This gives 100% coverage without
# touching individual tool functions.
_original_mcp_tool = mcp.tool
mcp.tool = _make_logged_tool(_original_mcp_tool)  # type: ignore[method-assign]

# ── Browser Tools Registration ──────────────────────────────────────
# (imports are at top of file)
mcp.tool()(browser_act)
mcp.tool()(browser_analyze)
mcp.tool()(browser_auto_auth)
mcp.tool()(browser_login)
mcp.tool()(browser_screenshot)
mcp.tool()(browser_crawl)
mcp.tool()(browser_extract_storage)
# ── End Browser Tools ──────────────────────────────────────────────


def _append_event(engagement_id: str, event: dict) -> None:
    """Append-only event logging. Each call adds one JSON line to the event log."""
    EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    event_file = EVENTS_DIR / f"{engagement_id}.jsonl"
    line = (
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **event,
            }
        )
        + "\n"
    )
    with _write_lock:
        with open(event_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())


def _fmt_severity_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{s}: {c}" for s, c in counts.items())


def _safe_code_fence(text: str) -> tuple[str, str]:
    """Return opening and closing fence markers that won't conflict with content.

    If the text contains triple backticks, we use a longer fence (4+ backticks)
    so the inner ``` don't break the markdown rendering.
    """
    # Find the longest run of consecutive backticks in the text
    runs = re.findall(r"`+", text)
    max_run = max((len(r) for r in runs), default=0)
    # Use at least 3 backticks, and always more than the longest run in the content
    fence_len = max(3, max_run + 1)
    fence = "`" * fence_len
    return fence, fence


def _append_finding_markdown(engagement_id: str, finding: dict) -> None:
    """Append a finding as human-readable markdown to engagements/runtime/<eid>/findings.md.

    This is an append-only crash-safe log. Even if the process dies mid-write,
    all previously written findings survive. This file is the user's insurance
    policy against lost progress.
    """
    eng_dir = _engagement_path(engagement_id)
    eng_dir.mkdir(parents=True, exist_ok=True)
    findings_md = eng_dir / "findings.md"

    # Write header if file doesn't exist
    if not findings_md.exists():
        header = f"# Findings — {engagement_id}\n\n" f"Auto-updated on every `log_finding()` call. " f"This file is append-only — safe against crashes.\n\n" f"---\n\n"
        with open(findings_md, "w", encoding="utf-8") as f:
            f.write(header)
            f.flush()
            os.fsync(f.fileno())

    # Format the finding as markdown
    param_line = f"- **Parameter**: {finding['affected_parameter']}\n" if finding.get("affected_parameter") else ""
    domain_line = f"- **Domain**: {finding['domain']}\n" if finding.get("domain") else ""
    evidence_fence, _ = _safe_code_fence(finding["evidence"])

    entry = (
        f"## {finding['id']}: {finding['title']}\n\n"
        f"- **Severity**: {finding['severity']}\n"
        f"- **Test**: {finding['test_id']}\n"
        f"- **URL**: {finding['affected_url']}\n"
        f"{param_line}"
        f"{domain_line}"
        f"- **Time**: {finding['timestamp']}\n\n"
        f"### Description\n\n{finding['description']}\n\n"
        f"### Evidence\n\n{evidence_fence}\n{finding['evidence']}\n{evidence_fence}\n\n"
        f"### Remediation\n\n{finding['remediation']}\n\n"
        f"---\n\n"
    )

    with _write_lock:
        with open(findings_md, "a", encoding="utf-8") as f:
            f.write(entry)
            f.flush()
            os.fsync(f.fileno())


def _append_progress_log(engagement_id: str, entry: str) -> None:
    """Append a one-line progress entry to engagements/runtime/<eid>/progress.log.

    This is an append-only timestamped log of all test completions, tool runs,
    and findings. Survives crashes. Human-readable at a glance.
    """
    eng_dir = _engagement_path(engagement_id)
    eng_dir.mkdir(parents=True, exist_ok=True)
    log_file = eng_dir / "progress.log"

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {entry}\n"

    with _write_lock:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())


def _safe_read_json(filepath: Path, default: Any = None) -> Any:
    """Read JSON file safely, returning default on corruption or missing file."""
    if not filepath.exists():
        return default
    try:
        return json.loads(filepath.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning(f"Corrupted or unreadable JSON file: {filepath}")
        return default


def _get_findings_from_sqlite(engagement_id: str) -> list[dict]:
    """Read findings from SQLite and return in the old JSON format.

    Returns findings as a list of dicts with the same shape as the
    legacy JSON files (id as FINDING-XXX, timestamp, title, etc).
    Falls back to empty list if no findings or engagement doesn't exist.
    """
    try:
        vulns = _fdb.list_vulns(engagement_id=engagement_id)
    except Exception:
        return []
    findings = []
    for v in vulns:
        findings.append(
            {
                "id": v.get("finding_ref", f"FINDING-{v['id']:03d}"),
                "test_id": v.get("test_id", ""),
                "title": v.get("title", ""),
                "severity": v.get("severity", "Medium"),
                "description": v.get("description", ""),
                "evidence": v.get("evidence", ""),
                "remediation": v.get("remediation", ""),
                "affected_url": v.get("affected_url", ""),
                "affected_parameter": v.get("affected_parameter", ""),
                "domain": v.get("domain", ""),
                "timestamp": v.get("created_at", ""),
                "confidence": v.get("confidence", "version_based"),
                "cvss": v.get("cvss", 0.0),
                "poc_token": v.get("poc_token", ""),
                "poc_output": v.get("poc_output", ""),
                "reproduced": bool(v.get("reproduced", 0)),
                "consensus_passed": bool(v.get("consensus_passed", 0)),
                "baseline_anomaly": bool(v.get("baseline_anomaly", 0)),
                "independent_engine": False,
            }
        )
    return findings


# ── Configure Tier 1 Modules ──────────────────────────────────────

_tt_configure(TASK_TREE_DIR, _atomic_write_json, _append_event)
_ep_configure(PRIORITY_QUEUE_DIR, _atomic_write_json, _append_event)
_waf_configure(WAF_DATA_DIR, _atomic_write_json, _append_event)
_kg_configure(GRAPH_DIR, _atomic_write_json, _append_event)
_tv_configure(DATA_DIR, _atomic_write_json, _append_event)
_cc_configure(DATA_DIR, _atomic_write_json, _append_event)


# ── Findings Database Tools (SQLite persistence) ────────────────────
# Cross-session persistence via SQLite. Stores engagements, hosts,
# services, vulns, credentials, attack chains, and session logs.
# Thread-safe, WAL mode, zero-token-cost queries.

_fdb = _FindingsDB(str(_fdb_path()))


@mcp.tool()
def findings_init(
    engagement_id: str,
    client: str = "",
    etype: str = "web",
    scope: str = "",
    notes: str = "",
) -> str:
    """Initialize a new engagement in the SQLite findings database.
    Creates the engagement record if it doesn't exist. Returns the engagement details.
    Idempotent — safe to call multiple times on the same engagement_id.

    Args:
        engagement_id: Unique identifier for this pentest engagement
        client: Client or target name (e.g. 'ACME Corp')
        etype: Engagement type: web, internal, external, cloud, mobile, wireless
        scope: Authorized scope (e.g. '*.example.com, 10.0.0.0/24')
        notes: Optional notes about the engagement
    """
    eng = _fdb.init_engagement(
        engagement_id=engagement_id,
        client=client,
        etype=etype,
        scope=scope,
        notes=notes,
    )
    _fdb.log_action(
        engagement_id=engagement_id,
        agent="swarm-server",
        action="engagement_init",
        summary=f"Engagement {engagement_id} initialized",
        detail=f"Client: {client}, Type: {etype}, Scope: {scope}",
    )
    return json.dumps(eng, indent=2, default=str)


@mcp.tool()
def findings_add_host(
    engagement_id: str,
    ip: str = "",
    hostname: str = "",
    os: str = "",
    role: str = "",
    discovered_by: str = "",
    notes: str = "",
) -> str:
    """Add a discovered host to the engagement findings database.

    Args:
        engagement_id: The engagement identifier
        ip: IP address of the host
        hostname: Hostname or FQDN
        os: Detected operating system
        role: Host role (e.g. 'DC', 'web server', 'database')
        discovered_by: Tool or method that discovered this host
        notes: Additional notes
    """
    host = _fdb.add_host(
        engagement_id=engagement_id,
        ip=ip,
        hostname=hostname,
        os=os,
        role=role,
        discovered_by=discovered_by,
        notes=notes,
    )
    _fdb.log_action(
        engagement_id=engagement_id,
        agent="swarm-server",
        action="add_host",
        summary=f"Host {ip or hostname} added",
        detail=f"OS: {os}, Role: {role}",
    )
    return json.dumps(host, indent=2, default=str)


@mcp.tool()
def findings_list_hosts(engagement_id: str) -> str:
    """List all hosts discovered in an engagement.

    Args:
        engagement_id: The engagement identifier
    """
    hosts = _fdb.list_hosts(engagement_id)
    if not hosts:
        return f"No hosts recorded for engagement '{engagement_id}'."
    return json.dumps(hosts, indent=2, default=str)


@mcp.tool()
def findings_add_service(
    engagement_id: str,
    host_ip_or_hostname: str,
    port: int,
    protocol: str = "tcp",
    service: str = "",
    version: str = "",
    banner: str = "",
    notes: str = "",
) -> str:
    """Add a service running on a discovered host.

    Args:
        engagement_id: The engagement identifier
        host_ip_or_hostname: IP or hostname of the host (matched against existing hosts)
        port: Port number
        protocol: Protocol (tcp, udp)
        service: Service name (e.g. 'HTTP', 'SSH', 'SMB')
        version: Service version string
        banner: Service banner
        notes: Additional notes
    """
    hosts = _fdb.list_hosts(engagement_id)
    host_id = None
    for h in hosts:
        if h["ip"] == host_ip_or_hostname or h["hostname"] == host_ip_or_hostname:
            host_id = h["id"]
            break
    if host_id is None:
        return f"Host '{host_ip_or_hostname}' not found in engagement '{engagement_id}'. Use findings_add_host first."
    svc = _fdb.add_service(
        host_id=host_id,
        port=port,
        protocol=protocol,
        service=service,
        version=version,
        banner=banner,
        notes=notes,
    )
    return json.dumps(svc, indent=2, default=str)


@mcp.tool()
def findings_add_vuln(
    engagement_id: str,
    title: str,
    severity: str = "medium",
    cvss: float = 0.0,
    cve: str = "",
    mitre_id: str = "",
    test_id: str = "",
    tool_used: str = "",
    affected_url: str = "",
    affected_parameter: str = "",
    description: str = "",
    evidence: str = "",
    poc_output: str = "",
    remediation: str = "",
    domain: str = "",
    poc_token: str = "",
    consensus_passed: bool = False,
    reproduced: bool = False,
    baseline_anomaly: bool = False,
    independent_engine: bool = False,
    response_body: str = "",
    confidence: str = "version_based",
) -> str:
    """Add a vulnerability finding to the findings database.
    This is the SQLite-backed alternative to log_finding(). Use this for
    structured queries and cross-session persistence.

    Args:
        engagement_id: The engagement identifier
        title: Short descriptive title for the finding
        severity: One of: Critical, High, Medium, Low, Informational
        cvss: CVSS score (0.0-10.0)
        cve: CVE identifier if applicable
        mitre_id: MITRE ATT&CK technique ID
        test_id: The WSTG test ID (e.g. WSTG-INPV-01)
        tool_used: Tool that discovered this finding
        affected_url: The URL where the vulnerability was found
        affected_parameter: The vulnerable parameter name
        description: Detailed description of the vulnerability
        evidence: HTTP request/response excerpts or other proof
        poc_output: The validated PoC command + response (output from validate_poc())
        remediation: Recommended fix
        domain: Domain this finding belongs to
        poc_token: PoC token from validate_poc() — REQUIRED when confidence=confirmed
        consensus_passed: Whether payload consensus was achieved
        reproduced: Whether reproducibility test passed
        baseline_anomaly: Whether response differs from baseline
        independent_engine: Whether found by an independent detection engine
        response_body: Response body for noise classification
        confidence: Evidence confidence: confirmed, version_based, speculative
    """
    valid_severities = {"Critical", "High", "Medium", "Low", "Informational"}
    if severity not in valid_severities:
        return f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(valid_severities))}"
    valid_confidence = {"confirmed", "version_based", "speculative"}
    if confidence not in valid_confidence:
        return f"Invalid confidence '{confidence}'. Must be one of: {', '.join(sorted(valid_confidence))}"

    # Enforce PoC token for confirmed findings
    if confidence == "confirmed" and not poc_token:
        return (
            "confidence='confirmed' requires a valid poc_token from validate_poc().\n"
            "1. Run validate_poc(engagement_id, command='curl ...', expected_match='...')\n"
            "2. Copy the PoC Token from the PASS output\n"
            "3. Pass it as poc_token=... to this call"
        )
    # H2: verify the token whenever one is supplied — auto-escalation to
    # 'confirmed' inside add_vuln (driven by consensus_passed/reproduced) must
    # not be able to rely on an unverified token.
    if poc_token and not _verify_poc_token(engagement_id, poc_token):
        return f"Invalid or expired poc_token (ends in '...{poc_token[-4:]}'). " f"The PoC evidence file was not found or token doesn't match.\n" f"Run validate_poc() to generate a fresh token."

    # Apply CVSS cap based on confidence
    capped_cvss = min(cvss, CVSS_CONFIDENCE_CAPS.get(confidence, 6.0))
    cap_severity = CVSS_CAP_SEVERITY.get(confidence, "keep")
    if capped_cvss < cvss:
        return (
            f"CVSS {cvss} exceeds confidence cap for '{confidence}' (max {capped_cvss}). "
            f"Either lower CVSS to {capped_cvss} or change confidence to 'confirmed'. "
            f"Use confidence='confirmed' only after running validate_poc()."
        )
    if cap_severity != "keep":
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        sev_rank_inv = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}
        current_rank = sev_rank.get(severity, 2)
        cap_rank = sev_rank.get(cap_severity, 2)
        if current_rank < cap_rank:
            severity = sev_rank_inv[cap_rank]
    vuln = _fdb.add_vuln(
        engagement_id=engagement_id,
        title=title,
        severity=severity,
        cvss=cvss,
        cve=cve,
        mitre_id=mitre_id,
        test_id=test_id,
        tool_used=tool_used,
        affected_url=affected_url,
        affected_parameter=affected_parameter,
        description=description,
        evidence=evidence,
        poc_output=poc_output,
        remediation=remediation,
        domain=domain,
        confidence=confidence,
        poc_token=poc_token,
        consensus_passed=consensus_passed,
        reproduced=reproduced,
        baseline_anomaly=baseline_anomaly,
        independent_engine=independent_engine,
        response_body=response_body,
    )
    _fdb.log_action(
        engagement_id=engagement_id,
        agent="swarm-server",
        action="findings_add_vuln",
        summary=f"Vuln #{vuln['id']}: {title} ({severity})",
        detail=f"URL: {affected_url}, Test: {test_id}",
    )

    # Auto-detect attack chains from this vuln
    try:
        chains = _fdb.detect_chains(engagement_id, new_vuln_id=vuln["id"])
        for chain in chains:
            stored = _fdb.add_auto_chain(engagement_id, chain)
            if stored:
                _append_event(
                    engagement_id,
                    {
                        "tool": "findings_add_vuln",
                        "args": {"chain_detected": chain["name"]},
                        "result": f"Auto-chain: {chain['name']} (score: {chain['score']})",
                    },
                )
        if chains:
            _fdb.log_action(
                engagement_id=engagement_id,
                agent="swarm-server",
                action="auto_chain_detection",
                summary=f"Detected {len(chains)} attack chain(s) from {vuln['finding_ref']}",
                detail=f"Chains: {', '.join(c['name'] for c in chains)}",
            )
    except Exception as e:
        logger.debug(f"Auto-chain detection failed (non-critical): {e}")

    # Truncate poc_token in response to avoid leaking full token
    if "poc_token" in vuln and vuln["poc_token"]:
        vuln = {**vuln, "poc_token": vuln["poc_token"][:8] + "..."}
    return json.dumps(vuln, indent=2, default=str)


# ── Browser Validation Gate (Phase E) ───────────────────────────────────────


@mcp.tool()
def mark_browser_verified(
    engagement_id: str,
    url: str,
    payload: str = "",
    screenshot_taken: bool = False,
    screenshot_path: str = "",
) -> str:
    """Record that browser-based validation was performed for a URL.
    Required for 'confirmed' confidence on XSS, CSRF, clickjacking, and
    other browser-dependent vulnerability classes.

    Call this AFTER running browser_screenshot() and confirming the payload
    executed in the browser. The gate is artifact-backed (H3): a real
    screenshot image on disk is required — a bare boolean is no longer enough.

    Args:
        engagement_id: The engagement identifier
        url: The URL that was verified in the browser
        payload: The payload that was confirmed to execute
        screenshot_taken: Whether a screenshot was captured as evidence
        screenshot_path: Path to the captured screenshot image (from
            browser_screenshot()). REQUIRED for the URL to count toward
            'confirmed' confidence — the file must exist and be a non-empty image.
    """
    # Validate the artifact up front so the agent gets clear feedback.
    artifact_ok = _FindingsDB._is_valid_screenshot(screenshot_path)
    if screenshot_path and not artifact_ok:
        return f"Screenshot path not usable as evidence: `{screenshot_path}`\n" "It must be an existing, non-empty image file (.png/.jpg/.jpeg/.webp/.gif).\n" "Run browser_screenshot() and pass the saved path."

    _fdb.mark_browser_verified(
        engagement_id=engagement_id,
        url=url,
        payload=payload,
        screenshot_taken=screenshot_taken,
        screenshot_path=screenshot_path,
    )
    gate_eligible = artifact_ok
    lines = [
        "## Browser Verification Recorded\n",
        f"**URL**: {url}",
        f"**Screenshot artifact**: {'`' + screenshot_path + '`' if artifact_ok else 'NONE (not gate-eligible)'}\n",
    ]
    if gate_eligible:
        lines += [
            'This URL is now eligible for `confidence="confirmed"` on browser-dependent',
            "vulnerability classes (XSS, CSRF, clickjacking, etc.).",
        ]
    else:
        lines += [
            '**Recorded for audit only** — NOT eligible for `confidence="confirmed"` until a',
            "real screenshot artifact is supplied via `screenshot_path` (see browser_screenshot()).",
        ]
    return "\n".join(lines)


# ── Independent Engine Check (Phase L — Tool Output / Nuclei) ────────────────


@mcp.tool()
def check_tool_output(
    engagement_id: str,
    tool_name: str = "",
    file_path: str = "",
    url: str = "",
    vuln_class: str = "",
    label: str = "",
) -> str:
    """Validate a finding using an independent security tool.

    PASSIVE MODE (tool_name + file_path) — for ANY supported tool:
      Parse an existing tool output file and check for success markers.
      Supported tools: nuclei, sqlmap, dalfox, smuggler, commix, sstimap, crlfuzz, corscanner

    ACTIVE MODE (url + vuln_class) — runs nuclei automatically:
      Selects the right template directory based on vuln_class and runs
      `nuclei -json -silent`. Only nuclei supports active mode.

    Either way, generates a poc_token on PASS that can be passed to
    add_vuln(confidence='confirmed', independent_engine=True).

    Args:
        engagement_id: The engagement identifier
        tool_name: Tool name for passive mode (nuclei/sqlmap/dalfox/smuggler/commix/etc.)
        file_path: Path to existing tool output file (passive mode only)
        url: Target URL (active mode only — runs nuclei)
        vuln_class: Vulnerability class for nuclei template selection (active mode only)
        label: Optional human-readable label
    """
    label_str = f" [{label}]" if label else ""

    # ── Active mode: run nuclei ──────────────────────────────────────────
    if url and vuln_class:
        template_dir = VULN_TO_NUCLEI_DIR.get(vuln_class, "")
        if not template_dir:
            return f"## Tool Output Check{label_str}: SKIPPED ⏭️\n\n" f"**URL**: {url}\n" f"**Vuln Class**: {vuln_class}\n\n" f"No nuclei templates available for this vuln class."
        templates_path = NUCLEI_TEMPLATES_DIR / template_dir
        if not templates_path.exists() or not any(templates_path.iterdir()):
            return f"## Tool Output Check{label_str}: SKIPPED ⏭️\n\n" f"**URL**: {url}\n" f"**Templates Dir**: {templates_path}\n\n" f"Template directory is empty or missing."

        try:
            start = time.time()
            result = subprocess.run(
                [
                    "nuclei",
                    "-u",
                    url,
                    "-t",
                    str(templates_path),
                    "-json",
                    "-silent",
                    "-timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            elapsed = time.time() - start
        except FileNotFoundError:
            return f"## Tool Output Check{label_str}: ERROR ❌\n\n" f"`nuclei` binary not found in PATH.\n" f"Install with: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`"
        except subprocess.TimeoutExpired:
            return f"## Tool Output Check{label_str}: TIMEOUT ⏱️\n\n" f"**URL**: {url}\n" f"Nuclei did not complete within 120 seconds."

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        findings: list[dict] = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not findings:
            return (
                f"## Tool Output Check{label_str}: NOT DETECTED ❌\n\n"
                f"**URL**: {url}\n"
                f"**Template Dir**: {template_dir}\n"
                f"**Time**: {elapsed:.1f}s\n"
                f"**Info**: {stderr[:500] if stderr else 'No findings'}\n\n"
                f"Nuclei ran {len(list(templates_path.glob('*.yaml')))} templates "
                f"— zero matches. This vulnerability was NOT independently confirmed."
            )

        # Generate poc_token from the nuclei findings
        poc_token = secrets.token_hex(16)
        ev_dir = ENGAGEMENTS_DIR / _sanitize_id(engagement_id) / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        ev_file = ev_dir / f"nuclei-{poc_token[:8]}.json"
        ev_file.write_text(
            json.dumps(
                {
                    "poc_token": poc_token,
                    "tool": "nuclei",
                    "vuln_class": vuln_class,
                    "target": url,
                    "findings": findings,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "template_dir": template_dir,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        lines = [
            f"## Tool Output Check{label_str}: PASS ✅\n",
            f"**URL**: {url}",
            "**Tool**: nuclei",
            f"**Templates**: {template_dir}/ ({len(findings)} findings)",
            f"**Time**: {elapsed:.1f}s",
            f"**PoC Token**: `{poc_token}`",
            "",
            "### Findings",
        ]
        for f in findings[:10]:
            template_id = f.get("template-id", "?")
            name = f.get("info", {}).get("name", "?")
            severity = f.get("info", {}).get("severity", "?")
            matched = f.get("matched-at", "")
            lines.append(f"- **{name}** [{severity}] — `{matched}` (template: {template_id})")
        if len(findings) > 10:
            lines.append(f"- ... and {len(findings) - 10} more findings")

        lines.append("")
        lines.append("**Next**: Pass `independent_engine=True` and `poc_token=...` to `add_vuln()`")
        _append_event(
            engagement_id,
            {
                "tool": "check_tool_output",
                "args": {"vuln_class": vuln_class, "url": url, "label": label},
                "result": f"PASS: {len(findings)} nuclei findings",
            },
        )
        return "\n".join(lines)

    # ── Passive mode: parse tool output file ─────────────────────────────
    if not tool_name or not file_path:
        return (
            "## Tool Output Check: USAGE\n\n"
            "Two modes:\n"
            "- ACTIVE: `url` + `vuln_class` — runs **nuclei** automatically\n"
            "- PASSIVE: `tool_name` + `file_path` — parses existing tool output\n\n"
            "Passive mode supports: " + ", ".join(sorted(TOOL_SUCCESS_MARKERS))
        )

    fp = Path(file_path)
    if not fp.exists():
        return f"## Tool Output Check{label_str}: ERROR ❌\n\n" f"**File not found**: `{file_path}`"

    try:
        content = fp.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"## Tool Output Check{label_str}: ERROR ❌\n\n" f"**File**: `{file_path}`\n" f"**Error reading file**: {e}"

    markers = TOOL_SUCCESS_MARKERS.get(tool_name, [])
    if not markers:
        return f"## Tool Output Check{label_str}: SKIPPED ⏭️\n\n" f"**Tool**: {tool_name}\n" f"No success markers defined for this tool. Supported: " + ", ".join(sorted(TOOL_SUCCESS_MARKERS))

    matches = []
    for marker in markers:
        for m in re.finditer(marker, content, re.IGNORECASE):
            line_ctx = _extract_context_line(content, m.start())
            matches.append((marker, line_ctx))

    if not matches:
        return (
            f"## Tool Output Check{label_str}: NOT DETECTED ❌\n\n"
            f"**Tool**: {tool_name}\n"
            f"**File**: `{file_path}` ({fp.stat().st_size:,} bytes)\n"
            f"None of the expected success markers were found in the output."
        )

    # Generate poc_token
    poc_token = secrets.token_hex(16)
    ev_dir = ENGAGEMENTS_DIR / _sanitize_id(engagement_id) / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ev_file = ev_dir / f"toolcheck-{poc_token[:8]}.json"
    ev_file.write_text(
        json.dumps(
            {
                "poc_token": poc_token,
                "tool": tool_name,
                "file_path": file_path,
                "matches": [(m[0], m[1]) for m in matches[:20]],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Deduplicate visible matches
    seen_markers: set[str] = set()
    unique_matches = []
    for marker, ctx in matches:
        if marker not in seen_markers:
            seen_markers.add(marker)
            unique_matches.append((marker, ctx))

    lines = [
        f"## Tool Output Check{label_str}: PASS ✅\n",
        f"**Tool**: {tool_name}",
        f"**File**: `{file_path}` ({fp.stat().st_size:,} bytes)",
        f"**PoC Token**: `{poc_token}`",
        "",
        f"### {len(matches)} success markers found ({len(unique_matches)} unique):",
    ]
    for marker, ctx in unique_matches[:15]:
        lines.append(f"- **`{marker}`** — `{ctx.strip()[:80]}`")
    if len(unique_matches) > 15:
        lines.append(f"- ... and {len(unique_matches) - 15} more")

    lines.append("")
    lines.append("**Next**: Pass `independent_engine=True` and `poc_token=...` to `add_vuln()`")
    _append_event(
        engagement_id,
        {
            "tool": "check_tool_output",
            "args": {"tool_name": tool_name, "file_path": file_path, "label": label},
            "result": f"PASS: {len(matches)} markers in {tool_name} output",
        },
    )
    return "\n".join(lines)


@mcp.tool()
def collect_baseline(
    engagement_id: str,
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    samples: int = 10,
    label: str = "",
) -> str:
    """Collect N normal responses from a URL and build a baseline fingerprint.
    Use this BEFORE sending attack payloads to establish what 'normal' looks like.
    The baseline ID can be passed to validate_poc(baseline_id=...) for smart diffing.

    Args:
        engagement_id: The engagement identifier
        url: The URL to collect baseline from
        method: HTTP method (GET, POST, etc.)
        headers: Raw HTTP headers (one per line)
        body: Request body for POST requests
        samples: Number of normal responses to collect (default 10)
        label: Optional human-readable label for this baseline
    """
    from response_diff import collect_baseline as _do_collect

    bp = _do_collect(url=url, method=method, headers=headers, body=body, samples=samples)

    # M5: surface a failed collection instead of silently saving an empty
    # baseline that later reads as MATCH ("not a vulnerability").
    if bp.sample_count == 0:
        return (
            f"## Baseline NOT Established: {label or url}\n\n"
            f"**URL**: {url}\n"
            f"All {samples} probe request(s) failed (DNS/connection/timeout). "
            "No baseline was saved — diffing against this target is not possible yet.\n\n"
            "Check connectivity/credentials and retry collect_baseline()."
        )

    profile_dict = bp.to_dict()
    baseline_data = {
        "id": "",
        "engagement_id": engagement_id,
        "url": url,
        "method": method,
        "request_body": body,
        "label": label,
        "profile": profile_dict,
        "sample_count": bp.sample_count,
    }
    baseline_id = _fdb.save_baseline(baseline_data)

    lines = [
        f"## Baseline Collected: {label or url}\n",
        f"**Baseline ID**: `{baseline_id}`\n",
        f"**URL**: {url}",
        f"**Method**: {method}",
        f"**Samples**: {bp.sample_count}",
        f"**Stable**: {bp.is_stable()}",
        f"**Status codes**: {bp.status_codes}",
    ]
    if bp.dom_skeletons:
        dom_sample = list(set(bp.dom_skeletons))[:3]
        lines.append(f"**DOM skeleton(s)**: {dom_sample}")
    if bp.timings:
        p50 = bp.timing_p50()
        p95 = bp.timing_p95()
        lines.append(f"**Timing**: p50={p50:.0f}ms p95={p95:.0f}ms")

    lines.append(f'\nUse this baseline ID in `validate_poc(..., baseline_id="{baseline_id}")`')
    lines.append("to automatically compare attack responses against this baseline.")
    return "\n".join(lines)


@mcp.tool()
def diff_response(
    engagement_id: str,
    baseline_id: str,
    attack_command: str,
    payload_string: str = "",
    vuln_id: int = 0,
) -> str:
    """Compare an attack response against a stored baseline.
    Returns a structured diff with verdict and confidence.

    Args:
        engagement_id: The engagement identifier
        baseline_id: The baseline ID from collect_baseline()
        attack_command: The curl command that sends the attack payload
        payload_string: The payload value to check for reflection
    """
    import shlex
    import subprocess as _sp

    from response_diff import ResponseFingerprint, compare

    # Load baseline
    baseline_data = _fdb.get_baseline(baseline_id)
    if not baseline_data:
        return f"Baseline '{baseline_id}' not found."

    from response_diff import BaselineProfile

    bp = BaselineProfile.from_dict(baseline_data.get("profile", {}))

    # Run attack command
    try:
        start = time.time()
        result = _sp.run(shlex.split(attack_command), capture_output=True, text=True, timeout=30)
        elapsed = (time.time() - start) * 1000
    except Exception as e:
        return f"## diff_response: ERROR\n\n**Error running attack command**: {e}"

    attack_fp = ResponseFingerprint.from_curl_output(result.stdout, elapsed)
    diff = compare(bp, attack_fp, payload_string=payload_string)

    lines = [diff.to_markdown()]
    # Auto-update baseline_anomaly on finding if vuln_id provided
    if vuln_id and diff.verdict in ("DIFFERENT", "SUSPICIOUS"):
        try:
            _fdb._execute(
                "UPDATE vulns SET baseline_anomaly = 1, updated_at = ? WHERE id = ? AND engagement_id = ?",
                (datetime.now(timezone.utc).isoformat(), vuln_id, engagement_id),
            )
            _fdb._get_conn().commit()
            lines.append(f"\n**Auto-updated** finding #{vuln_id}: baseline_anomaly=True")
        except Exception as e:
            lines.append(f"\n**Warning**: Failed to update finding #{vuln_id}: {e}")

    # Include verdict recommendation
    if diff.verdict == "DIFFERENT":
        lines.append("\n**Recommendation**: Likely valid finding — proceed with validate_poc()")
    elif diff.verdict == "SUSPICIOUS":
        lines.append("\n**Recommendation**: Review manually or run validate_poc() with consensus checks")
    elif diff.verdict == "MATCH":
        lines.append("\n**Recommendation**: Response matches baseline — likely NOT a vulnerability")
    else:
        lines.append("\n**Recommendation**: Minor differences — investigate further")

    return "\n".join(lines)


@mcp.tool()
def list_baselines(
    engagement_id: str,
    url: str = "",
) -> str:
    """List available baseline profiles for an engagement.

    Args:
        engagement_id: The engagement identifier
        url: Optional URL filter
    """
    baselines = _fdb.list_baselines(engagement_id, url=url)
    if not baselines:
        return f"No baselines found for engagement '{engagement_id}'." + (f" (filter: {url})" if url else "")

    lines = [f"## Baselines for {engagement_id}\n"]
    lines.append("| ID | Label | URL | Method | Samples | Created |")
    lines.append("|----|-------|-----|--------|---------|---------|")
    for b in baselines:
        bid = b.get("id", "")[:12]
        blabel = b.get("label", "")[:20] or "-"
        burl = b.get("url", "")[:40]
        bmethod = b.get("method", "GET")
        bsamples = b.get("sample_count", 0)
        bcreated = b.get("created_at", "")[:19]
        lines.append(f"| {bid} | {blabel} | {burl} | {bmethod} | {bsamples} | {bcreated} |")

    return "\n".join(lines)


@mcp.tool()
def findings_list_vulns(
    engagement_id: str = "",
    severity: str = "",
    status: str = "",
    tool_used: str = "",
) -> str:
    """List vulnerabilities from the findings database.
    Supports filtering by engagement, severity, status, and tool.

    Args:
        engagement_id: Filter by engagement (optional)
        severity: Filter by severity: Critical, High, Medium, Low, Informational
        status: Filter by status: open, confirmed, false_positive, fixed
        tool_used: Filter by discovery tool
    """
    vulns = _fdb.list_vulns(
        engagement_id=engagement_id,
        severity=severity,
        status=status,
        tool_used=tool_used,
    )
    if not vulns:
        return "No vulnerabilities match the given filters."
    return json.dumps(vulns, indent=2, default=str)


@mcp.tool()
def findings_add_credential(
    engagement_id: str,
    username: str,
    secret: str,
    secret_type: str = "password",  # nosec B107
    domain: str = "",
    access_level: str = "unknown",
    source: str = "",
    notes: str = "",
) -> str:
    """Add harvested credentials to the findings database.

    Args:
        engagement_id: The engagement identifier
        username: Username or account identifier
        secret: The secret value (password, hash, token, key)
        secret_type: Type: password, hash, token, key, cert
        domain: Domain or realm
        access_level: Access level: user, admin, domain_user, domain_admin, local_admin, unknown
        source: How the credential was obtained (e.g. 'responder', 'kerberoasting', 'phishing')
        notes: Additional notes
    """
    cred = _fdb.add_credential(
        engagement_id=engagement_id,
        username=username,
        secret=secret,
        secret_type=secret_type,
        domain=domain,
        access_level=access_level,
        source=source,
        notes=notes,
    )
    _fdb.log_action(
        engagement_id=engagement_id,
        agent="swarm-server",
        action="add_credential",
        summary=f"Credential for {username} ({secret_type})",
        detail=f"Domain: {domain}, Access: {access_level}",
    )
    return json.dumps(cred, indent=2, default=str)


@mcp.tool()
def findings_add_chain(
    engagement_id: str,
    name: str,
    score: float = 0.0,
    steps: str = "",
    mitre_ids: str = "",
    notes: str = "",
) -> str:
    """Record an attack chain that combines multiple findings.

    Args:
        engagement_id: The engagement identifier
        name: Chain name (e.g. 'Subdomain takeover → XSS → Session hijack')
        score: Chain severity score (0.0-10.0)
        steps: JSON array of step descriptions
        mitre_ids: Comma-separated MITRE ATT&CK technique IDs
        notes: Additional notes
    """
    steps_list = json.loads(steps) if steps else []
    chain = _fdb.add_chain(
        engagement_id=engagement_id,
        name=name,
        score=score,
        steps=steps_list,
        mitre_ids=mitre_ids,
        notes=notes,
    )
    return json.dumps(chain, indent=2, default=str)


@mcp.tool()
def findings_log_action(
    engagement_id: str,
    agent: str = "",
    action: str = "",
    summary: str = "",
    detail: str = "",
) -> str:
    """Record a session activity entry in the findings database.
    Use this to track what was done during a session for handoff purposes.

    Args:
        engagement_id: The engagement identifier
        agent: Agent or tool name (e.g. 'web-hunter', 'sqlmap', 'analyst')
        action: Action type (e.g. 'scan', 'exploit', 'analysis', 'report')
        summary: Brief summary of the action
        detail: Detailed description or command output
    """
    entry = _fdb.log_action(
        engagement_id=engagement_id,
        agent=agent,
        action=action,
        summary=summary,
        detail=detail,
    )
    return json.dumps(entry, indent=2, default=str)


@mcp.tool()
def findings_stats(engagement_id: str) -> str:
    """Get engagement statistics from the findings database.
    Shows counts for hosts, services, vulns (by severity), credentials, chains, and session entries.

    Args:
        engagement_id: The engagement identifier
    """
    stats = _fdb.stats(engagement_id)
    if not stats.get("engagement"):
        return f"No engagement found for '{engagement_id}'. Use findings_init() first."
    return json.dumps(stats, indent=2, default=str)


@mcp.tool()
def findings_export(engagement_id: str) -> str:
    """Export all findings database data for an engagement as JSON.
    Useful for report generation or data transfer between sessions.

    Args:
        engagement_id: The engagement identifier
    """
    data = _fdb.export_json(engagement_id)
    if not data or data == "{}":
        return f"No data found for engagement '{engagement_id}'."
    return data


@mcp.tool()
def findings_handoff(engagement_id: str) -> str:
    """Generate a structured Markdown handoff report for the next session.
    Includes engagement summary, hosts, vulns by severity, credentials,
    attack chains, recent activity, and suggested next steps.

    Args:
        engagement_id: The engagement identifier
    """
    report = _fdb.handoff_markdown(engagement_id)
    if not report:
        return f"No data found for engagement '{engagement_id}'."
    return report


# ── WSTG Lookup Tools ──────────────────────────────────────────────


@mcp.tool()
def list_wstg_categories() -> str:
    """List all OWASP WSTG test categories with their codes and available test counts.
    Use this to discover what categories of security tests are available."""
    lines = ["# OWASP WSTG Test Categories\n"]
    for num, cat in CATEGORIES.items():
        cat_dir = WSTG_DIR / cat["dir"]
        test_count = len(list(cat_dir.glob("WSTG-*.md"))) if cat_dir.exists() else 0
        lines.append(f"- **WSTG-{cat['code']}** ({cat['name']}): {test_count} tests available")
    return "\n".join(lines)


@mcp.tool()
def list_tests_in_category(category_code: str) -> str:
    """List all test cases available in a specific WSTG category.

    Args:
        category_code: The category code, e.g. INFO, INPV, ATHN, SESS, CONF
    """
    num = _CODE_TO_NUM.get(category_code.upper())
    if not num:
        return f"Unknown category code: {category_code}. Use list_wstg_categories() to see valid codes."

    cat = CATEGORIES[num]
    cat_dir = WSTG_DIR / cat["dir"]
    if not cat_dir.exists():
        return f"Category directory not found for {category_code}"

    tests = []
    for md_file in sorted(cat_dir.glob("WSTG-*.md")):
        parsed = _parse_wstg_file(md_file)
        test_id = parsed.get("id", md_file.stem)
        title = parsed.get("title", "No title")
        tests.append(f"- **{test_id}**: {title}")

    if not tests:
        return f"No tests found in category {category_code}. Markdown files can be added to {cat_dir}"

    return f"# Tests in {cat['name']} (WSTG-{cat['code']})\n\n" + "\n".join(tests)


@mcp.tool()
def get_wstg_test(test_id: str) -> str:
    """Retrieve the full content of a specific WSTG test case including
    test steps, Burp-specific actions, payloads, and detection criteria.

    Args:
        test_id: The WSTG test ID, e.g. WSTG-INPV-01, WSTG-ATHN-03
    """
    filepath = _find_test_file(test_id)
    if not filepath:
        return f"Test case {test_id} not found. " "Use list_wstg_categories() or list_tests_in_category() to discover available tests."
    parsed = _parse_wstg_file(filepath)
    header = ""
    if "id" in parsed:
        header = f"**ID**: {parsed['id']}\n"
    if "title" in parsed:
        header += f"**Title**: {parsed['title']}\n"
    if "severity_range" in parsed:
        header += f"**Severity Range**: {parsed['severity_range']}\n"
    if "owasp_ref" in parsed:
        header += f"**OWASP Reference**: {parsed['owasp_ref']}\n"
    if header:
        header += "\n---\n\n"
    return header + parsed.get("content", "No content found")


@mcp.tool()
def get_test_payloads(test_id: str) -> str:
    """Extract only the Payloads section from a WSTG test case.
    Useful when you already know the methodology and just need payloads to test with.

    Args:
        test_id: The WSTG test ID, e.g. WSTG-INPV-01
    """
    filepath = _find_test_file(test_id)
    if not filepath:
        return f"Test case {test_id} not found."

    content = filepath.read_text(encoding="utf-8")
    in_payloads = False
    payloads_lines = []
    for line in content.split("\n"):
        if line.strip().startswith("## Payloads"):
            in_payloads = True
            payloads_lines.append(line)
            continue
        if in_payloads:
            # Stop at the next ## section that isn't a sub-section of payloads
            if line.strip().startswith("## ") and "Payload" not in line:
                break
            payloads_lines.append(line)

    if payloads_lines:
        return "\n".join(payloads_lines)
    return f"No Payloads section found in {test_id}. The full test can be retrieved with get_wstg_test('{test_id}')."


@mcp.tool()
def search_wstg(query: str) -> str:
    """Search across all WSTG test cases for relevant content by keyword.
    Returns matching tests ranked by relevance.

    Args:
        query: Search query, e.g. 'SQL injection', 'session fixation', 'CORS', 'cookie'
    """
    results = []
    query_lower = query.lower()

    for md_file in sorted(WSTG_DIR.rglob("WSTG-*.md")):
        parsed = _parse_wstg_file(md_file)
        content_lower = parsed.get("content", "").lower()
        title_lower = parsed.get("title", "").lower()

        if query_lower in content_lower or query_lower in title_lower:
            count = content_lower.count(query_lower) + (10 if query_lower in title_lower else 0)
            results.append(
                {
                    "id": parsed.get("id", md_file.stem),
                    "title": parsed.get("title", md_file.stem),
                    "relevance": count,
                    "category": parsed.get("category", "Unknown"),
                }
            )

    results.sort(key=lambda x: x["relevance"], reverse=True)

    if not results:
        return f"No WSTG test cases found matching '{query}'"

    lines = [f"# Search Results for '{query}'\n"]
    for r in results[:10]:
        lines.append(f"- **{r['id']}**: {r['title']} ({r['category']})")
    return "\n".join(lines)


# ── Finding Management Tools ───────────────────────────────────────


@mcp.tool()
def log_finding(
    engagement_id: str,
    test_id: str,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    remediation: str,
    affected_url: str,
    affected_parameter: str = "",
    domain: str = "",
    poc_token: str = "",
    confidence: str = "version_based",
) -> str:
    """Log a security finding discovered during testing.

    Args:
        engagement_id: Unique identifier for this pentest engagement
        test_id: The WSTG test ID that found this, e.g. WSTG-INPV-01
        title: Short descriptive title for the finding
        severity: One of: Critical, High, Medium, Low, Informational
        description: Detailed description of the vulnerability
        evidence: HTTP request/response excerpts or other proof
        remediation: Recommended fix
        affected_url: The URL where the vulnerability was found
        affected_parameter: The vulnerable parameter name, if applicable
        domain: Domain this finding belongs to for cross-domain engagements (optional)
        poc_token: PoC token from validate_poc() — REQUIRED when confidence=confirmed
        confidence: Evidence confidence: confirmed, version_based, speculative
    """
    valid_severities = {"Critical", "High", "Medium", "Low", "Informational"}
    if severity not in valid_severities:
        return f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(valid_severities))}"
    valid_confidence = {"confirmed", "version_based", "speculative"}
    if confidence not in valid_confidence:
        return f"Invalid confidence '{confidence}'. Must be one of: {', '.join(sorted(valid_confidence))}"

    # Enforce PoC token for confirmed findings
    if confidence == "confirmed" and not poc_token:
        return (
            "confidence='confirmed' requires a valid poc_token from validate_poc().\n"
            "1. Run validate_poc(engagement_id, command='curl ...', expected_match='...')\n"
            "2. Copy the PoC Token from the PASS output\n"
            "3. Pass it as poc_token=... to this call"
        )
    # H2: verify the token whenever one is supplied — auto-escalation to
    # 'confirmed' inside add_vuln must not be able to rely on an unverified token.
    if poc_token and not _verify_poc_token(engagement_id, poc_token):
        return f"Invalid or expired poc_token (ends in '...{poc_token[-4:]}'). " f"Run validate_poc() to generate a fresh token."

    # Apply severity cap based on confidence (no CVSS in log_finding)
    cap_severity = CVSS_CAP_SEVERITY.get(confidence, "keep")
    if cap_severity != "keep":
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        sev_rank_inv = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}
        current_rank = sev_rank.get(severity, 2)
        cap_rank = sev_rank.get(cap_severity, 2)
        if current_rank < cap_rank:
            severity = sev_rank_inv[cap_rank]

    # ── Duplicate finding detection ───────────────────────────────
    existing = _get_findings_from_sqlite(engagement_id)
    duplicate_warnings = []
    title_lower = title.lower()
    vuln_keywords = {
        "xss",
        "sqli",
        "sql injection",
        "csrf",
        "ssrf",
        "ssti",
        "command injection",
        "cmdi",
        "path traversal",
        "idor",
        "clickjacking",
        "cors",
        "open redirect",
        "missing header",
        "security header",
        "cookie",
        "session",
        "information disclosure",
    }
    title_vuln_words = {kw for kw in vuln_keywords if kw in title_lower}

    for ef in existing:
        ef_title_lower = ef["title"].lower()
        ef_vuln_words = {kw for kw in vuln_keywords if kw in ef_title_lower}
        same_url = ef["affected_url"].rstrip("/") == affected_url.rstrip("/")
        same_param = ef.get("affected_parameter", "") == affected_parameter and affected_parameter != ""
        overlapping_vuln = bool(title_vuln_words & ef_vuln_words)
        if same_url and same_param and overlapping_vuln:
            duplicate_warnings.append(f"LIKELY DUPLICATE of {ef['id']} ({ef['title']}): " f"same URL, same parameter, similar vulnerability type")
        elif same_url and overlapping_vuln:
            duplicate_warnings.append(f"POSSIBLE DUPLICATE of {ef['id']} ({ef['title']}): " f"same URL, similar vulnerability type")

    # Store to SQLite
    vuln = _fdb.add_vuln(
        engagement_id=engagement_id,
        title=title,
        severity=severity,
        test_id=test_id,
        affected_url=affected_url,
        affected_parameter=affected_parameter,
        description=description,
        evidence=evidence,
        remediation=remediation,
        domain=domain,
        confidence=confidence,
        poc_token=poc_token,
    )
    finding_ref = vuln.get("finding_ref", f"FINDING-{vuln['id']:03d}")

    # Also write to human-readable findings markdown
    finding_md = {
        "id": finding_ref,
        "test_id": test_id,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "affected_url": affected_url,
        "affected_parameter": affected_parameter,
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _append_finding_markdown(engagement_id, finding_md)
    _append_progress_log(
        engagement_id,
        f"FINDING {finding_ref} [{severity}] {test_id}: {title} @ {affected_url}",
    )
    _append_event(
        engagement_id,
        {
            "tool": "log_finding",
            "args": {"test_id": test_id, "title": title, "severity": severity},
            "result": f"Logged {finding_ref}" + (f" (DUPLICATE WARNING: {len(duplicate_warnings)})" if duplicate_warnings else ""),
        },
    )

    result = f"Finding logged: {finding_ref} - {title} ({severity})\nAlso saved to: ./engagements/runtime/{engagement_id}/findings.md"
    if duplicate_warnings:
        result += "\n\n**DUPLICATE WARNINGS:**\n"
        for dw in duplicate_warnings:
            result += f"- {dw}\n"
        result += "\nConsider consolidating with existing findings instead of " "creating duplicates. Use update_finding() to enhance an existing " "finding with additional test_id references."
    return result


@mcp.tool()
def update_finding(
    engagement_id: str,
    finding_id: str,
    severity: str = "",
    description: str = "",
    remediation: str = "",
    evidence: str = "",
    poc_output: str = "",
    notes: str = "",
) -> str:
    """Update an existing finding's severity, description, or remediation.
    Used during Final Judge remediation to upgrade severities or improve finding quality.

    Args:
        engagement_id: The engagement identifier
        finding_id: The finding ID to update, e.g. FINDING-001
        severity: New severity (if changing). One of: Critical, High, Medium, Low, Informational
        description: Updated description (if changing)
        remediation: Updated remediation (if changing)
        evidence: Updated evidence with PoC request/response (if changing)
        poc_output: The validated PoC command + response (if changing, output from validate_poc())
        notes: Reason for the update (e.g., "Upgraded per Final Judge - chaining with FINDING-003")
    """
    vuln = _fdb.get_vuln_by_ref(engagement_id, finding_id.upper())
    if not vuln:
        existing = _get_findings_from_sqlite(engagement_id)
        known_ids = [f["id"] for f in existing]
        return f"Finding '{finding_id}' not found. Known IDs: {', '.join(known_ids)}"

    kwargs = {}
    if severity:
        valid_severities = {"Critical", "High", "Medium", "Low", "Informational"}
        if severity not in valid_severities:
            return f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(valid_severities))}"
        kwargs["severity"] = severity
    if description:
        kwargs["description"] = description
    if remediation:
        kwargs["remediation"] = remediation
    if evidence:
        kwargs["evidence"] = evidence
    if poc_output:
        kwargs["poc_output"] = poc_output

    if kwargs:
        _fdb.update_vuln(vuln["id"], **kwargs)

    _append_event(
        engagement_id,
        {
            "tool": "update_finding",
            "args": {"finding_id": finding_id, "severity": severity},
            "result": f"Updated {finding_id}",
        },
    )

    updated_fields = []
    if severity:
        updated_fields.append(f"severity={severity}")
    if description:
        updated_fields.append("description")
    if remediation:
        updated_fields.append("remediation")
    if evidence:
        updated_fields.append("evidence")
    if poc_output:
        updated_fields.append("poc_output")

    return f"Finding {finding_id} updated: {', '.join(updated_fields)}. Note: {notes}"


# ── Scope Management Tools ────────────────────────────────────────


@mcp.tool()
def register_scope(
    engagement_id: str,
    domain: str,
    domain_type: str = "app",
    eligibility: str = "eligible",
    app_id: str = "",
    notes: str = "",
) -> str:
    """Register a domain in the engagement scope. Call once per domain.
    Domains are used for grouping findings in the report and for
    cross-domain auth flow tracking.

    Args:
        engagement_id: The engagement identifier
        domain: Domain or asset name (e.g., app.example.com, com.example.app, 448142450)
        domain_type: One of: app, auth_provider, api, cdn, third_party,
                     android_app, ios_app, wildcard_domain
        eligibility: Eligibility level: eligible, ineligible, critical, high, medium, none
        app_id: App store ID (for android_app/ios_app types, e.g., "com.truecaller" or "448142450")
        notes: Optional notes (e.g., "Android: Play Store", "iOS App Store ID")
    """
    valid_types = {
        "app",
        "auth_provider",
        "api",
        "cdn",
        "third_party",
        "android_app",
        "ios_app",
        "wildcard_domain",
    }
    valid_eligibility = {"eligible", "ineligible", "critical", "high", "medium", "none"}
    if domain_type not in valid_types:
        return f"Invalid domain_type '{domain_type}'. Must be one of: {', '.join(sorted(valid_types))}"
    if eligibility not in valid_eligibility:
        return f"Invalid eligibility '{eligibility}'. Must be one of: {', '.join(sorted(valid_eligibility))}"

    SCOPE_DIR.mkdir(parents=True, exist_ok=True)
    scope_file = SCOPE_DIR / f"{engagement_id}.json"

    existing: list[dict] = []
    if scope_file.exists():
        existing = json.loads(scope_file.read_text(encoding="utf-8"))

    # Upsert: update existing entry or append new one
    updated = False
    for entry in existing:
        if entry["domain"] == domain:
            entry["domain_type"] = domain_type
            entry["eligibility"] = eligibility
            entry["app_id"] = app_id
            entry["notes"] = notes
            entry["timestamp"] = datetime.now(timezone.utc).isoformat()
            updated = True
            break

    if not updated:
        existing.append(
            {
                "domain": domain,
                "domain_type": domain_type,
                "eligibility": eligibility,
                "app_id": app_id,
                "notes": notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    _atomic_write_json(scope_file, existing)
    _append_event(
        engagement_id,
        {
            "tool": "register_scope",
            "args": {
                "domain": domain,
                "domain_type": domain_type,
                "eligibility": eligibility,
            },
            "result": f"Registered {domain}",
        },
    )
    return f"Scope registered: {domain} ({domain_type}, {eligibility}). Total entries: {len(existing)}"


@mcp.tool()
def get_scope(engagement_id: str) -> str:
    """Get all registered scope entries for an engagement, grouped by type.

    Args:
        engagement_id: The engagement identifier
    """
    scope_file = SCOPE_DIR / f"{engagement_id}.json"
    if not scope_file.exists():
        return "No scope registered for this engagement. Use register_scope() to add domains."

    scope_data = json.loads(scope_file.read_text(encoding="utf-8"))
    if not scope_data:
        return "Scope file exists but is empty."

    # Group by type
    by_type: dict[str, list[dict]] = {}
    for entry in scope_data:
        dt = entry["domain_type"]
        by_type.setdefault(dt, []).append(entry)

    lines = [f"# Engagement Scope ({len(scope_data)} entries)\n"]
    type_labels = {
        "app": "Web Application",
        "auth_provider": "Authentication Provider",
        "api": "API",
        "cdn": "CDN / Static Assets",
        "third_party": "Third Party",
        "android_app": "Android App",
        "ios_app": "iOS App",
        "wildcard_domain": "Wildcard Domain",
    }

    elig_labels = {
        "critical": "🔴 Critical",
        "high": "🟠 High",
        "medium": "🟡 Medium",
        "eligible": "🟢 Eligible",
        "ineligible": "⚪ Ineligible",
        "none": "⚪ None",
    }

    # Order by defined types
    for dtype, label in type_labels.items():
        if dtype not in by_type:
            continue
        lines.append(f"## {label}")
        for entry in by_type[dtype]:
            domain = entry["domain"]
            elig = entry.get("eligibility", "eligible")
            elig_str = elig_labels.get(elig, elig)
            note = f" — {entry['notes']}" if entry.get("notes") else ""
            app_id = f" (ID: {entry['app_id']})" if entry.get("app_id") else ""
            lines.append(f"- **{domain}**{app_id} — {elig_str}{note}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def register_scope_batch(engagement_id: str, entries: str) -> str:
    """Register multiple scope entries in a single call.

    Args:
        engagement_id: The engagement identifier
        entries: JSON string of scope entries. Each entry must have "domain" and optionally
                 "domain_type", "eligibility", "app_id", "notes".
                 Example: [{"domain": "*.example.com", "domain_type": "wildcard_domain", "eligibility": "critical"}]
    """
    try:
        parsed = json.loads(entries)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"

    if not isinstance(parsed, list):
        return "Entries must be a JSON array"

    SCOPE_DIR.mkdir(parents=True, exist_ok=True)
    scope_file = SCOPE_DIR / f"{engagement_id}.json"

    existing: list[dict] = []
    if scope_file.exists():
        existing = json.loads(scope_file.read_text(encoding="utf-8"))

    valid_types = {
        "app",
        "auth_provider",
        "api",
        "cdn",
        "third_party",
        "android_app",
        "ios_app",
        "wildcard_domain",
    }
    valid_eligibility = {"eligible", "ineligible", "critical", "high", "medium", "none"}
    timestamp = datetime.now(timezone.utc).isoformat()

    added = 0
    for entry in parsed:
        domain = entry.get("domain", "").strip()
        if not domain:
            continue

        domain_type = entry.get("domain_type", "app")
        eligibility = entry.get("eligibility", "eligible")
        app_id = entry.get("app_id", "")
        notes = entry.get("notes", "")

        if domain_type not in valid_types:
            domain_type = "app"
        if eligibility not in valid_eligibility:
            eligibility = "eligible"

        # Upsert
        found = False
        for existing_entry in existing:
            if existing_entry["domain"] == domain:
                existing_entry["domain_type"] = domain_type
                existing_entry["eligibility"] = eligibility
                existing_entry["app_id"] = app_id
                existing_entry["notes"] = notes
                existing_entry["timestamp"] = timestamp
                found = True
                break

        if not found:
            existing.append(
                {
                    "domain": domain,
                    "domain_type": domain_type,
                    "eligibility": eligibility,
                    "app_id": app_id,
                    "notes": notes,
                    "timestamp": timestamp,
                }
            )
        added += 1

    _atomic_write_json(scope_file, existing)
    _append_event(
        engagement_id,
        {
            "tool": "register_scope_batch",
            "args": {"entry_count": len(parsed)},
            "result": f"Registered {added} scope entries",
        },
    )
    return f"Registered {added} scope entries. Total: {len(existing)}"


@mcp.tool()
def parse_scope_table(engagement_id: str, table_text: str) -> str:
    """Parse a pasted bug bounty scope table into structured JSON entries.
    Use this when the user pastes their program's scope table.
    Returns JSON that can be passed directly to register_scope_batch().

    Args:
        engagement_id: The engagement identifier (for context)
        table_text: The raw pasted scope table text from the program page
    """
    try:
        from scripts.tools.scope_table_parser import parse_scope_table as _do_parse

        entries = _do_parse(table_text)
    except Exception as e:
        return f"Error parsing scope table: {e}"

    if not entries:
        return "No scope entries could be parsed from the provided text. Check the format."

    result = json.dumps(entries, indent=2, ensure_ascii=False)
    summary_parts = []
    for entry in entries:
        dt = entry.get("domain_type", "?")
        elig = entry.get("eligibility", "?")
        domain = entry.get("domain", "")
        summary_parts.append(f"  {domain} ({dt}, {elig})")

    return f"Parsed {len(entries)} scope entries:\n\n{result}\n\n" "To register all, call register_scope_batch() with the JSON above."


# ── Config Management Tools ──────────────────────────────────────


VALID_LOGIN_TYPES = {"form", "sso", "api", "manual", "none"}
VALID_RULE_TYPES = {"path", "endpoint", "feature", "parameter"}
VALID_SUCCESS_CONDITION_TYPES = {"url_contains", "cookie_present", "text_contains"}


@mcp.tool()
def load_engagement_config(
    engagement_id: str,
    config_yaml: str,
) -> str:
    """Parse and store a YAML engagement configuration.
    Call this at the beginning of a pentest to load target, credentials,
    auth flow, and focus/avoid rules from a YAML config file.

    Args:
        engagement_id: The engagement identifier
        config_yaml: The raw YAML content of the config file
    """
    try:
        config = yaml.safe_load(config_yaml)
    except yaml.YAMLError as e:
        return f"Invalid YAML: {e}"

    if not isinstance(config, dict):
        return "Config must be a YAML mapping (dict), not a scalar or list."

    # Validate target section
    target = config.get("target")
    if not target or not isinstance(target, dict):
        return "Missing required 'target' section with 'url' field."
    target_url = target.get("url", "")
    if not target_url or not isinstance(target_url, str):
        return "Missing required 'target.url' field."
    if not target_url.startswith(("http://", "https://")):
        return f"target.url must start with http:// or https://, got: {target_url}"

    # Validate authentication section
    auth = config.get("authentication", {})
    if auth:
        login_type = auth.get("login_type", "none")
        if login_type not in VALID_LOGIN_TYPES:
            return f"Invalid authentication.login_type '{login_type}'. " f"Must be one of: {', '.join(sorted(VALID_LOGIN_TYPES))}"
        if login_type in ("form", "sso", "api"):
            creds = auth.get("credentials", {})
            if not creds.get("username") or not creds.get("password"):
                return f"login_type '{login_type}' requires credentials.username and credentials.password."
        success_cond = auth.get("success_condition", {})
        if success_cond:
            cond_type = success_cond.get("type", "")
            if cond_type and cond_type not in VALID_SUCCESS_CONDITION_TYPES:
                return f"Invalid success_condition.type '{cond_type}'. " f"Must be one of: {', '.join(sorted(VALID_SUCCESS_CONDITION_TYPES))}"

    # Validate rules section
    rules = config.get("rules", {})
    warnings = []
    for rule_group in ("avoid", "focus"):
        rule_list = rules.get(rule_group, [])
        if not isinstance(rule_list, list):
            return f"rules.{rule_group} must be a list."
        for i, rule in enumerate(rule_list):
            if not isinstance(rule, dict):
                return f"rules.{rule_group}[{i}] must be a mapping."
            if not rule.get("description"):
                warnings.append(f"rules.{rule_group}[{i}] missing 'description'")
            rule_type = rule.get("type", "")
            if rule_type and rule_type not in VALID_RULE_TYPES:
                warnings.append(f"rules.{rule_group}[{i}]: unknown type '{rule_type}', " f"expected one of: {', '.join(sorted(VALID_RULE_TYPES))}")

    # Auto-register scope domains
    scope_domains = target.get("scope", [])
    scope_registered = 0
    if isinstance(scope_domains, list):
        SCOPE_DIR.mkdir(parents=True, exist_ok=True)
        scope_file = SCOPE_DIR / f"{engagement_id}.json"
        existing = _safe_read_json(scope_file, [])
        existing_domains = {e["domain"] for e in existing}
        for domain in scope_domains:
            if isinstance(domain, str) and domain not in existing_domains:
                existing.append(
                    {
                        "domain": domain,
                        "domain_type": "app",
                        "notes": "Auto-registered from config",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                scope_registered += 1
        if scope_registered:
            _atomic_write_json(scope_file, existing)

    # Validate mode
    mode = config.get("mode", "full")
    valid_modes = {"full", "ctf"}
    if mode not in valid_modes:
        warnings.append(f"Unknown mode '{mode}', defaulting to 'full'. Valid: {', '.join(sorted(valid_modes))}")
        mode = "full"

    # Store config
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config_data = {
        "loaded_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "authentication": auth or {"login_type": "none"},
        "mode": mode,
        "rules": {
            "avoid": rules.get("avoid", []),
            "focus": rules.get("focus", []),
        },
        "reporting": config.get("reporting", {}),
    }
    config_file = CONFIG_DIR / f"{engagement_id}.json"
    _atomic_write_json(config_file, config_data)

    _append_event(
        engagement_id,
        {
            "tool": "load_engagement_config",
            "args": {"target_url": target_url},
            "result": f"Config loaded for {target_url}",
        },
    )

    avoid_count = len(rules.get("avoid", []))
    focus_count = len(rules.get("focus", []))
    login_type = auth.get("login_type", "none") if auth else "none"

    # Pre-flight Python dependency check
    check_python_deps = [
        ("playwright", "pip install playwright && python -m playwright install chromium"),
        ("requests", "pip install requests"),
        ("yaml", "pip install pyyaml"),
    ]
    missing_deps = []
    for mod, install_hint in check_python_deps:
        try:
            __import__(mod)
        except ImportError:
            missing_deps.append(f"  - {mod} not found. Run: {install_hint}")
    if missing_deps:
        dep_warn = "\n".join(missing_deps)
        warnings.append(f"Missing Python dependencies — browser auth will fail:\n{dep_warn}")

    lines = [
        f"Config loaded for engagement: {engagement_id}",
        f"- Target: {target_url}",
        f"- Mode: {mode}",
        f"- Login type: {login_type}",
        f"- Scope domains: {len(scope_domains)} ({scope_registered} newly registered)",
        f"- Avoid rules: {avoid_count}",
        f"- Focus rules: {focus_count}",
    ]
    if mode == "ctf":
        lines.append("\nCTF mode enabled: relaxed phase gates, no QA reviewer requirement, " "reduced coverage thresholds, faster gate timing (15s minimum).")
    if warnings:
        lines.append(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            lines.append(f"  - {w}")

    return "\n".join(lines)


@mcp.tool()
def get_engagement_config(engagement_id: str) -> str:
    """Retrieve the stored configuration for an engagement.
    Returns target, credentials, auth flow, scope, and rules.

    Args:
        engagement_id: The engagement identifier
    """
    config_file = CONFIG_DIR / f"{engagement_id}.json"
    config = _safe_read_json(config_file)
    if config is None:
        return f"No config found for engagement '{engagement_id}'.\n" "Use load_engagement_config() to load a YAML config, " "or see configs/example-config.yaml for the template."

    lines = [f"# Engagement Config: {engagement_id}\n"]

    # Target
    target = config.get("target", {})
    lines.append("## Target")
    lines.append(f"- URL: {target.get('url', 'N/A')}")
    scope = target.get("scope", [])
    if scope:
        lines.append(f"- Scope: {', '.join(scope)}")
    exclude = target.get("exclude", [])
    if exclude:
        lines.append(f"- Exclude: {', '.join(exclude)}")
    lines.append("")

    # Authentication
    auth = config.get("authentication", {})
    lines.append("## Authentication")
    lines.append(f"- Login type: {auth.get('login_type', 'none')}")
    if auth.get("login_url"):
        lines.append(f"- Login URL: {auth['login_url']}")
    creds = auth.get("credentials", {})
    if creds:
        username = creds.get("username", "N/A")
        password = creds.get("password", "")
        masked = password[:2] + "***" if len(password) > 2 else "***"
        lines.append(f"- Username: {username}")
        lines.append(f"- Password: {masked}")
    sso = auth.get("sso", {})
    if sso:
        lines.append(f"- SSO Provider: {sso.get('provider', 'N/A')}")
        lines.append(f"- Auth Domain: {sso.get('auth_domain', 'N/A')}")
        if sso.get("realm"):
            lines.append(f"- Realm: {sso['realm']}")
        if sso.get("client_id"):
            lines.append(f"- Client ID: {sso['client_id']}")
    login_flow = auth.get("login_flow", [])
    if login_flow:
        lines.append("- Login flow:")
        for step in login_flow:
            lines.append(f"  1. {step}")
    success = auth.get("success_condition", {})
    if success:
        lines.append(f"- Success check: {success.get('type', '?')} = {success.get('value', '?')}")
    lines.append("")

    # Rules
    rules = config.get("rules", {})
    avoid = rules.get("avoid", [])
    focus = rules.get("focus", [])
    if avoid or focus:
        lines.append("## Rules")
        if avoid:
            lines.append("### Avoid (do NOT test)")
            for r in avoid:
                rtype = r.get("type", "?")
                desc = r.get("description", "No description")
                path = r.get("url_path", "")
                lines.append(f"- [{rtype}] {path} — {desc}" if path else f"- [{rtype}] {desc}")
        if focus:
            lines.append("### Focus (prioritize)")
            for r in focus:
                rtype = r.get("type", "?")
                desc = r.get("description", "No description")
                path = r.get("url_path", "")
                lines.append(f"- [{rtype}] {path} — {desc}" if path else f"- [{rtype}] {desc}")
        lines.append("")

    # Reporting
    reporting = config.get("reporting", {})
    if reporting:
        lines.append("## Reporting")
        for k, v in reporting.items():
            lines.append(f"- {k}: {v}")

    return "\n".join(lines)


@mcp.tool()
def get_engagement_rules(engagement_id: str) -> str:
    """Get focus and avoid rules for an engagement.
    Returns rules formatted for embedding in subagent prompts.
    Rules are loaded from the engagement config.

    Args:
        engagement_id: The engagement identifier
    """
    config_file = CONFIG_DIR / f"{engagement_id}.json"
    config = _safe_read_json(config_file)
    if config is None:
        return "No config loaded for this engagement. Rules not available."

    rules = config.get("rules", {})
    avoid = rules.get("avoid", [])
    focus = rules.get("focus", [])

    if not avoid and not focus:
        return "No avoid or focus rules configured for this engagement."

    lines = []
    if avoid:
        lines.append("## AVOID RULES — Do NOT test these endpoints/features")
        for r in avoid:
            rtype = r.get("type", "?")
            desc = r.get("description", "No description")
            path = r.get("url_path", "")
            method = r.get("method", "")
            prefix = f"[{rtype}]"
            if path:
                prefix += f" {path}"
            if method:
                prefix += f" ({method})"
            lines.append(f"- {prefix} — {desc}")
        lines.append("")

    if focus:
        lines.append("## FOCUS RULES — Prioritize these (test first, more depth)")
        for r in focus:
            rtype = r.get("type", "?")
            desc = r.get("description", "No description")
            path = r.get("url_path", "")
            feature = r.get("feature", "")
            prefix = f"[{rtype}]"
            if path:
                prefix += f" {path}"
            if feature:
                prefix += f" {feature}"
            lines.append(f"- {prefix} — {desc}")
        lines.append("")

    lines.append("**Instructions**: Skip endpoints matching AVOID rules entirely " "(track as skipped with reason). Test FOCUS endpoints first with extra depth.")
    return "\n".join(lines)


# ── Test Tracking Tools ────────────────────────────────────────────


@mcp.tool()
def track_test(
    engagement_id: str,
    test_id: str,
    status: str,
    notes: str,
    endpoints_tested: str = "",
    findings_count: int = 0,
    domain: str = "",
) -> str:
    """Track the execution status of a WSTG test case.
    MUST be called for every test — completed, skipped, or not applicable.

    Args:
        engagement_id: The engagement identifier
        test_id: The WSTG test ID, e.g. WSTG-INPV-01
        status: One of: completed, skipped, not_applicable, in_progress
        notes: What was tested, why skipped, or summary of findings
        endpoints_tested: Comma-separated list of endpoints tested (optional)
        findings_count: Number of findings logged from this test (default 0)
        domain: Domain this test targeted for cross-domain engagements (optional)
    """
    valid_statuses = {"completed", "skipped", "not_applicable", "in_progress"}
    if status not in valid_statuses:
        return f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}"

    if not _find_test_file(test_id):
        return f"Unknown test ID: {test_id}. Use list_wstg_categories() to see valid tests."

    TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    tracking_file = TRACKING_DIR / f"{engagement_id}.json"

    existing = []
    if tracking_file.exists():
        existing = json.loads(tracking_file.read_text(encoding="utf-8"))

    endpoints_list = [e.strip() for e in endpoints_tested.split(",") if e.strip()] if endpoints_tested else []

    # Upsert: update existing entry or append new one
    updated = False
    for entry in existing:
        if entry["test_id"] == test_id:
            entry["status"] = status
            entry["notes"] = notes
            entry["endpoints_tested"] = endpoints_list
            entry["findings_count"] = findings_count
            entry["domain"] = domain
            entry["timestamp"] = datetime.now(timezone.utc).isoformat()
            updated = True
            break

    if not updated:
        existing.append(
            {
                "test_id": test_id,
                "status": status,
                "notes": notes,
                "endpoints_tested": endpoints_list,
                "findings_count": findings_count,
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    _atomic_write_json(tracking_file, existing)
    findings_tag = f" ({findings_count} findings)" if findings_count > 0 else ""
    _append_progress_log(engagement_id, f"TEST {test_id} -> {status}{findings_tag}: {notes[:100]}")
    _append_event(
        engagement_id,
        {
            "tool": "track_test",
            "args": {"test_id": test_id, "status": status},
            "result": f"Tracked {test_id}",
        },
    )
    return f"Test tracked: {test_id} -> {status}"


@mcp.tool()
def track_tool(
    engagement_id: str,
    tool_name: str,
    status: str,
    notes: str,
    target: str = "",
    output_file: str = "",
    findings_count: int = 0,
) -> str:
    """Track the execution status of a CLI security tool.
    MUST be called for every tool — run, skipped, or not applicable.

    Args:
        engagement_id: The engagement identifier
        tool_name: The tool name, e.g. nmap, sqlmap, dalfox
        status: One of: run, skipped, not_applicable
        notes: What was tested, why skipped, or summary of results
        target: URL or host the tool was run against (optional)
        output_file: Path to tool output file (optional)
        findings_count: Number of findings from this tool (default 0)
    """
    valid_statuses = {"run", "skipped", "not_applicable"}
    if status not in valid_statuses:
        return f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}"

    tool_lower = tool_name.lower().strip()
    if tool_lower not in TOOL_REGISTRY:
        known = ", ".join(sorted(TOOL_REGISTRY.keys()))
        return f"Unknown tool '{tool_name}'. Known tools: {known}"

    TOOL_TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    tracking_file = TOOL_TRACKING_DIR / f"{engagement_id}.json"

    existing = []
    if tracking_file.exists():
        existing = json.loads(tracking_file.read_text(encoding="utf-8"))

    # Upsert: update existing entry or append new one
    updated = False
    for entry in existing:
        if entry["tool_name"] == tool_lower:
            entry["status"] = status
            entry["notes"] = notes
            entry["target"] = target
            entry["output_file"] = output_file
            entry["findings_count"] = findings_count
            entry["timestamp"] = datetime.now(timezone.utc).isoformat()
            updated = True
            break

    if not updated:
        existing.append(
            {
                "tool_name": tool_lower,
                "status": status,
                "notes": notes,
                "target": target,
                "output_file": output_file,
                "findings_count": findings_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    _atomic_write_json(tracking_file, existing)
    target_tag = f" @ {target}" if target else ""
    _append_progress_log(engagement_id, f"TOOL {tool_lower} -> {status}{target_tag}: {notes[:100]}")
    _append_event(
        engagement_id,
        {
            "tool": "track_tool",
            "args": {"tool_name": tool_lower, "status": status},
            "result": f"Tracked {tool_lower}",
        },
    )

    tool_info = TOOL_REGISTRY[tool_lower]
    phase = tool_info["phase"]
    tier = tool_info["tier"]
    return f"Tool tracked: {tool_lower} (Phase {phase}, {tier}) -> {status}"


@mcp.tool()
def track_judge_review(
    engagement_id: str,
    verdict: str,
    critical_actions: int = 0,
    recommended_actions: int = 0,
    actions_taken: int = 0,
    notes: str = "",
) -> str:
    """Record the Final Judge review results for an engagement.
    MUST be called after the Final Judge agent completes its review.

    Args:
        engagement_id: The engagement identifier
        verdict: One of: PASS, FAIL, CONDITIONAL_PASS
        critical_actions: Number of critical actions identified
        recommended_actions: Number of recommended actions identified
        actions_taken: Number of actions the main agent executed in response
        notes: Summary of the review and remediation
    """
    valid_verdicts = {"PASS", "FAIL", "CONDITIONAL_PASS"}
    if verdict not in valid_verdicts:
        return f"Invalid verdict '{verdict}'. Must be one of: {', '.join(sorted(valid_verdicts))}"

    JUDGE_TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    judge_file = JUDGE_TRACKING_DIR / f"{engagement_id}.json"

    review = {
        "verdict": verdict,
        "critical_actions": critical_actions,
        "recommended_actions": recommended_actions,
        "actions_taken": actions_taken,
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    _atomic_write_json(judge_file, review)
    _append_event(
        engagement_id,
        {
            "tool": "track_judge_review",
            "args": {"verdict": verdict},
            "result": f"Judge verdict: {verdict}",
        },
    )

    return f"Final Judge review recorded: {verdict} " f"(critical={critical_actions}, recommended={recommended_actions}, " f"actions_taken={actions_taken})"


@mcp.tool()
def track_qa_review(
    engagement_id: str,
    phase_reviewed: int,
    suggestions_count: int = 0,
    suggestions_acted_on: int = 0,
    critical_gaps_found: int = 0,
    notes: str = "",
) -> str:
    """Record a Quality Reviewer subagent's review for a phase.
    MUST be called after the Quality Reviewer completes its review of each phase.
    Phase gate checks verify that QA review was performed for the previous phase.

    Args:
        engagement_id: The engagement identifier
        phase_reviewed: The phase number that was reviewed (0-5)
        suggestions_count: Total number of suggestions the reviewer provided
        suggestions_acted_on: Number of suggestions the main agent acted on
        critical_gaps_found: Number of critical gaps identified
        notes: Summary of the review findings and actions taken
    """
    if phase_reviewed not in range(6):
        return f"Invalid phase: {phase_reviewed}. Must be 0-5."

    QA_TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    qa_file = QA_TRACKING_DIR / f"{engagement_id}.json"

    existing: list[dict] = []
    if qa_file.exists():
        existing = json.loads(qa_file.read_text(encoding="utf-8"))

    review = {
        "phase_reviewed": phase_reviewed,
        "suggestions_count": suggestions_count,
        "suggestions_acted_on": suggestions_acted_on,
        "critical_gaps_found": critical_gaps_found,
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    existing.append(review)
    _atomic_write_json(qa_file, existing)
    _append_progress_log(
        engagement_id,
        f"QA REVIEW Phase {phase_reviewed}: {suggestions_count} suggestions, " f"{suggestions_acted_on} acted on, {critical_gaps_found} critical gaps",
    )
    _append_event(
        engagement_id,
        {
            "tool": "track_qa_review",
            "args": {"phase": phase_reviewed, "suggestions": suggestions_count},
            "result": f"QA review for Phase {phase_reviewed} recorded",
        },
    )

    return f"QA review recorded for Phase {phase_reviewed}: " f"{suggestions_count} suggestions, {suggestions_acted_on} acted on, " f"{critical_gaps_found} critical gaps"


@mcp.tool()
def get_tool_coverage(engagement_id: str) -> str:
    """Get CLI tool coverage summary for an engagement.
    Shows which tools were run, skipped, or not tracked, grouped by phase.
    MUST be called before generate_report() to verify adequate tool coverage.

    Args:
        engagement_id: The engagement identifier
    """
    tracking_file = TOOL_TRACKING_DIR / f"{engagement_id}.json"

    tracked_tools = {}
    if tracking_file.exists():
        tracking = json.loads(tracking_file.read_text(encoding="utf-8"))
        tracked_tools = {entry["tool_name"]: entry for entry in tracking}

    # Group tools by phase
    phases: dict[int, list[str]] = {}
    for tool_name, info in TOOL_REGISTRY.items():
        phase: int = info["phase"]
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(tool_name)

    total_tools = len(TOOL_REGISTRY)
    total_tracked = len(tracked_tools)
    total_run = sum(1 for t in tracked_tools.values() if t["status"] == "run")
    total_skipped = sum(1 for t in tracked_tools.values() if t["status"] == "skipped")
    total_na = sum(1 for t in tracked_tools.values() if t["status"] == "not_applicable")
    total_not_tracked = total_tools - total_tracked
    mandatory_missing = []

    lines = [
        f"# Tool Coverage Report: {engagement_id}\n",
        "## Overall Summary",
        f"- Total registered tools: {total_tools}",
        f"- Run: {total_run}",
        f"- Skipped (with reason): {total_skipped}",
        f"- Not Applicable: {total_na}",
        f"- **Not Tracked: {total_not_tracked}**",
        f"- **Tool Coverage: {(total_tracked / total_tools * 100):.0f}%**",
        "\n---\n",
    ]

    for phase_num in sorted(phases.keys()):
        phase_tools = phases[phase_num]
        phase_name = PHASE_NAMES.get(phase_num, f"Phase {phase_num}")
        lines.append(f"## Phase {phase_num}: {phase_name}\n")
        lines.append("| Tool | Tier | Condition | Status | Notes |")
        lines.append("|------|------|-----------|--------|-------|")

        for tool_name in sorted(phase_tools):
            info = TOOL_REGISTRY[tool_name]
            tier = info["tier"]
            condition = info["condition"] or "Always"

            if tool_name in tracked_tools:
                entry = tracked_tools[tool_name]
                status_str = entry["status"].upper()
                notes_str = entry["notes"][:60] + "..." if len(entry["notes"]) > 60 else entry["notes"]
            else:
                status_str = "**NOT TRACKED**"
                notes_str = ""
                if tier == "mandatory" and info["condition"] is None:
                    mandatory_missing.append(f"{tool_name} (Phase {phase_num})")

            lines.append(f"| {tool_name} | {tier} | {condition} | {status_str} | {notes_str} |")

        lines.append("")

    if mandatory_missing:
        lines.append(f"\n**BLOCKING: Mandatory tools not tracked:** {', '.join(mandatory_missing)}")
        lines.append("These tools MUST be run or explicitly skipped with a reason before generating the report.")

    return "\n".join(lines)


@mcp.tool()
def get_coverage(engagement_id: str) -> str:
    """Get test coverage summary for an engagement.
    Shows which WSTG tests were run, skipped, or not applicable, with per-category percentages.
    MUST be called before generate_report() to verify adequate coverage.

    Args:
        engagement_id: The engagement identifier
    """
    tracking_file = TRACKING_DIR / f"{engagement_id}.json"
    if not tracking_file.exists():
        return f"No tracking data for engagement '{engagement_id}'. " "No WSTG tests have been tracked yet. Use track_test() after each test."

    tracking = json.loads(tracking_file.read_text(encoding="utf-8"))
    tracked_tests = {entry["test_id"]: entry for entry in tracking}

    category_lines = []
    total_tests = 0
    total_completed = 0
    total_skipped = 0
    total_na = 0
    total_in_progress = 0
    total_not_attempted = 0
    gaps = []

    for num, cat in CATEGORIES.items():
        cat_dir = WSTG_DIR / cat["dir"]
        if not cat_dir.exists():
            continue

        cat_tests = sorted(cat_dir.glob("WSTG-*.md"))
        cat_total = len(cat_tests)
        total_tests += cat_total

        completed = 0
        skipped = 0
        na = 0
        in_progress = 0
        not_attempted = []

        for md_file in cat_tests:
            test_id = md_file.stem.upper()
            if test_id in tracked_tests:
                s = tracked_tests[test_id]["status"]
                if s == "completed":
                    completed += 1
                elif s == "skipped":
                    skipped += 1
                elif s == "not_applicable":
                    na += 1
                elif s == "in_progress":
                    in_progress += 1
            else:
                not_attempted.append(test_id)

        total_completed += completed
        total_skipped += skipped
        total_na += na
        total_in_progress += in_progress
        total_not_attempted += len(not_attempted)

        attempted = completed + skipped + na
        coverage_pct = (attempted / cat_total * 100) if cat_total > 0 else 0

        status_icon = "PASS" if coverage_pct == 100 else ("PARTIAL" if coverage_pct > 0 else "MISSING")
        category_lines.append(f"## {cat['code']} - {cat['name']} [{status_icon}]")
        effective_pct = (completed / cat_total * 100) if cat_total > 0 else 0
        category_lines.append(f"Coverage: {attempted}/{cat_total} ({coverage_pct:.0f}%) | " f"Completed: {completed} | Skipped: {skipped} | N/A: {na} | In Progress: {in_progress}")
        category_lines.append(f"Effective (completed only): {completed}/{cat_total} ({effective_pct:.0f}%)")

        if not_attempted:
            category_lines.append(f"**Not attempted**: {', '.join(not_attempted)}")
            if coverage_pct == 0:
                gaps.append(cat["code"])

        category_lines.append("")

    # Overall summary
    overall_attempted = total_completed + total_skipped + total_na
    overall_pct = (overall_attempted / total_tests * 100) if total_tests > 0 else 0

    summary = [
        f"# Test Coverage Report: {engagement_id}\n",
        "## Overall Summary",
        f"- Total tests: {total_tests}",
        f"- Completed: {total_completed}",
        f"- Skipped (with reason): {total_skipped}",
        f"- Not Applicable: {total_na}",
        f"- In Progress: {total_in_progress}",
        f"- **Not Attempted: {total_not_attempted}**",
        f"- **Coverage: {overall_pct:.0f}%**",
    ]

    # Effective coverage (completed only, excludes N/A and skipped)
    effective_overall_pct = (total_completed / total_tests * 100) if total_tests > 0 else 0
    summary.append(f"- **Effective Coverage (completed only): {effective_overall_pct:.0f}%**")

    # N/A warning
    na_pct = (total_na / total_tests * 100) if total_tests > 0 else 0
    if na_pct > 40:
        summary.append(
            f"\n**WARNING: {na_pct:.0f}% of tests marked N/A ({total_na}/{total_tests}).** "
            "This is unusually high and may indicate authentication failure "
            "or premature N/A marking. Review each N/A test to ensure it is "
            "genuinely not applicable, not just untestable due to auth issues."
        )

    if gaps:
        summary.append(f"\n**COVERAGE GAPS — Categories with 0% coverage:** {', '.join(gaps)}")
        summary.append("These categories MUST be tested before generating the report.")

    required = {"INFO", "CONF", "ATHN", "ATHZ", "SESS", "INPV", "ERRH", "CLNT"}
    missing_required = [c for c in sorted(required) if c in gaps]
    if missing_required:
        summary.append(f"\n**BLOCKING: Required categories not tested:** {', '.join(missing_required)}")
        summary.append("Go back and run at least the priority tests from each missing category.")

    lines = summary + ["\n---\n"] + category_lines
    return "\n".join(lines)


@mcp.tool()
def get_findings(engagement_id: str) -> str:
    """Retrieve all findings for a specific engagement, sorted by severity.

    Args:
        engagement_id: The engagement identifier
    """
    findings = _get_findings_from_sqlite(engagement_id)
    if not findings:
        return f"No findings found for engagement '{engagement_id}'"

    lines = [f"# Findings for Engagement: {engagement_id}\n"]
    lines.append(f"**Total findings**: {len(findings)}\n")

    # Summary counts
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        if sev in counts:
            lines.append(f"- {sev}: {counts[sev]}")
    lines.append("")

    for f in findings:
        lines.append(f"## {f['id']}: {f['title']}")
        lines.append(f"- **Severity**: {f['severity']}")
        lines.append(f"- **Test**: {f['test_id']}")
        lines.append(f"- **URL**: {f['affected_url']}")
        if f.get("affected_parameter"):
            lines.append(f"- **Parameter**: {f['affected_parameter']}")
        lines.append(f"- **Description**: {f['description'][:300]}")
        lines.append("")

    return "\n".join(lines)


# ── Final Judge Tools ────────────────────────────────────────────


@mcp.tool()
def get_judge_data(engagement_id: str) -> str:
    """Compile all engagement data for Final Judge review.
    Returns a comprehensive analysis packet including test coverage,
    tool coverage, findings, scope, gate history, and statistical anomaly flags.

    This tool is designed for zero-context review agents that need
    all engagement data in a single call.

    Args:
        engagement_id: The engagement identifier
    """
    # Load all engagement data
    tracking_file = TRACKING_DIR / f"{engagement_id}.json"
    if not tracking_file.exists():
        return f"No tracking data for engagement '{engagement_id}'"

    tracking = json.loads(tracking_file.read_text(encoding="utf-8"))
    tracked_tests = {entry["test_id"]: entry for entry in tracking}

    tool_file = TOOL_TRACKING_DIR / f"{engagement_id}.json"
    tracked_tools = {}
    if tool_file.exists():
        for entry in json.loads(tool_file.read_text(encoding="utf-8")):
            tracked_tools[entry["tool_name"]] = entry

    findings = _get_findings_from_sqlite(engagement_id)

    gate_file = GATE_TRACKING_DIR / f"{engagement_id}.json"
    gate_data = []
    if gate_file.exists():
        gate_data = json.loads(gate_file.read_text(encoding="utf-8"))

    scope_file = SCOPE_DIR / f"{engagement_id}.json"
    scope_data = []
    if scope_file.exists():
        scope_data = json.loads(scope_file.read_text(encoding="utf-8"))

    lines = [f"# Final Judge Analysis Packet: {engagement_id}\n"]

    # ── Section 1: Overview ──
    lines.append("## 1. Engagement Overview\n")
    if scope_data:
        lines.append("**Registered Domains:**")
        for s in scope_data:
            lines.append(f"- {s['domain']} ({s.get('domain_type', 'unknown')}) — {s.get('notes', '')}")
        lines.append("")
    else:
        lines.append("**WARNING: No domains registered via register_scope()**\n")

    lines.append(f"- Total findings: {len(findings)}")
    lines.append(f"- Total tracked tests: {len(tracked_tests)}")
    lines.append(f"- Total tracked tools: {len(tracked_tools)}")
    lines.append("")

    # ── Section 2: Coverage Matrix ──
    lines.append("## 2. Coverage Matrix\n")
    lines.append("| Category | Total | Completed | Skipped | N/A | Untracked | Effective % |")
    lines.append("|----------|-------|-----------|---------|-----|-----------|-------------|")

    all_tests = []
    category_stats = {}
    for num, cat in CATEGORIES.items():
        cat_dir = WSTG_DIR / cat["dir"]
        if not cat_dir.exists():
            continue
        cat_tests = sorted(cat_dir.glob("WSTG-*.md"))
        completed = skipped = na = untracked = 0
        for md_file in cat_tests:
            test_id = md_file.stem.upper()
            all_tests.append(test_id)
            if test_id in tracked_tests:
                s = tracked_tests[test_id]["status"]
                if s == "completed":
                    completed += 1
                elif s == "skipped":
                    skipped += 1
                elif s == "not_applicable":
                    na += 1
            else:
                untracked += 1
        total = len(cat_tests)
        eff_pct = (completed / total * 100) if total > 0 else 0
        na_pct = (na / total * 100) if total > 0 else 0
        category_stats[cat["code"]] = {
            "total": total,
            "completed": completed,
            "skipped": skipped,
            "na": na,
            "untracked": untracked,
            "eff_pct": eff_pct,
            "na_pct": na_pct,
        }
        lines.append(f"| {cat['code']} | {total} | {completed} | {skipped} | {na} | {untracked} | {eff_pct:.0f}% |")

    total_all = len(all_tests)
    total_completed = sum(s["completed"] for s in category_stats.values())
    total_na = sum(s["na"] for s in category_stats.values())
    sum(s["untracked"] for s in category_stats.values())
    overall_eff = (total_completed / total_all * 100) if total_all > 0 else 0
    overall_na_pct = (total_na / total_all * 100) if total_all > 0 else 0

    lines.append("")
    lines.append(f"**Overall Effective Coverage: {overall_eff:.0f}%** ({total_completed}/{total_all} completed)")
    lines.append(f"**Overall N/A Rate: {overall_na_pct:.0f}%** ({total_na}/{total_all})")
    lines.append("")

    # ── Section 3: N/A Analysis ──
    lines.append("## 3. N/A Analysis\n")
    na_tests = {tid: e for tid, e in tracked_tests.items() if e["status"] == "not_applicable"}
    if na_tests:
        # Group by category
        na_by_cat: dict[str, list] = {}
        for tid, entry in na_tests.items():
            cat_code = tid.split("-")[1] if "-" in tid else "UNKNOWN"
            na_by_cat.setdefault(cat_code, []).append(entry)

        for cat_code, entries in sorted(na_by_cat.items()):
            lines.append(f"### {cat_code} ({len(entries)} N/A tests)")
            for e in entries:
                notes_text = e.get("notes", "NO NOTES PROVIDED")
                lines.append(f"- **{e['test_id']}**: {notes_text}")
            lines.append("")
    else:
        lines.append("No tests marked as N/A.\n")

    # ── Section 4: Skipped Analysis ──
    lines.append("## 4. Skipped Analysis\n")
    skipped_tests = {tid: e for tid, e in tracked_tests.items() if e["status"] == "skipped"}
    if skipped_tests:
        for tid, entry in sorted(skipped_tests.items()):
            lines.append(f"- **{tid}**: {entry.get('notes', 'NO REASON PROVIDED')}")
        lines.append("")
    else:
        lines.append("No tests skipped.\n")

    # ── Section 5: Tool Coverage ──
    lines.append("## 5. Tool Coverage\n")
    lines.append("| Tool | Phase | Tier | Status | Findings | Notes |")
    lines.append("|------|-------|------|--------|----------|-------|")
    for tool_name, info in sorted(TOOL_REGISTRY.items()):
        if tool_name in tracked_tools:
            t = tracked_tools[tool_name]
            status = t["status"]
            fc = t.get("findings_count", 0)
            notes_text = t.get("notes", "")[:80]
        else:
            status = "NOT TRACKED"
            fc = "-"
            notes_text = ""
        lines.append(f"| {tool_name} | {info['phase']} | {info['tier']} | {status} | {fc} | {notes_text} |")
    lines.append("")

    # ── Section 6: Untracked Tests ──
    lines.append("## 6. Untracked Tests\n")
    untracked_list = [tid for tid in all_tests if tid not in tracked_tests]
    if untracked_list:
        lines.append(f"**{len(untracked_list)} tests were never tracked** (never called track_test):\n")
        lines.append(", ".join(untracked_list))
    else:
        lines.append("All tests have tracking entries.")
    lines.append("")

    # ── Section 7: Finding Summary ──
    lines.append("## 7. Finding Summary\n")
    if findings:
        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Informational": 4,
        }
        findings_sorted = sorted(findings, key=lambda f: severity_order.get(f["severity"], 5))
        for f in findings_sorted:
            desc_preview = f.get("description", "")[:200]
            lines.append(f"- **{f['id']}** [{f['severity']}] {f['title']}")
            lines.append(f"  - Test: {f['test_id']} | URL: {f['affected_url']}")
            lines.append(f"  - {desc_preview}")
        lines.append("")
    else:
        lines.append("No findings logged.\n")

    # ── Section 8: Gate History ──
    lines.append("## 8. Gate History\n")
    if gate_data:
        for g in gate_data:
            phase = g.get("phase", "?")
            result = g.get("result", "?")
            blockers = g.get("blockers_count", 0)
            warnings = g.get("warnings_count", 0)
            lines.append(f"- Phase {phase}: **{result}** (blockers={blockers}, warnings={warnings})")
        lines.append("")
    else:
        lines.append("No gate checks recorded.\n")

    # ── Section 9: Statistical Flags ──
    lines.append("## 9. Statistical Flags (Anomaly Detection)\n")
    flags = []

    # Flag: N/A cascade per category
    for cat_code, stats in category_stats.items():
        if stats["na_pct"] > 50 and stats["total"] > 2:
            flags.append(f"**N/A CASCADE in {cat_code}**: {stats['na']}/{stats['total']} tests " f"({stats['na_pct']:.0f}%) marked N/A. Likely auth failure cascade.")

    # Flag: Effective vs nominal coverage gap
    overall_nominal = ((total_completed + total_na + sum(s["skipped"] for s in category_stats.values())) / total_all * 100) if total_all > 0 else 0
    if overall_nominal - overall_eff > 20:
        flags.append(
            f"**COVERAGE GAP**: Nominal coverage {overall_nominal:.0f}% vs effective "
            f"{overall_eff:.0f}% — {overall_nominal - overall_eff:.0f}pp gap. "
            "Most 'coverage' is N/A or skipped, not actual testing."
        )

    # Flag: Completed tests with no endpoints_tested
    empty_endpoint_tests = []
    for tid, entry in tracked_tests.items():
        if entry["status"] == "completed":
            endpoints = entry.get("endpoints_tested", "")
            if not endpoints or endpoints.strip() == "":
                empty_endpoint_tests.append(tid)
    if empty_endpoint_tests:
        flags.append(
            f"**EMPTY ENDPOINTS**: {len(empty_endpoint_tests)} tests marked 'completed' "
            f"with no endpoints_tested: {', '.join(empty_endpoint_tests[:10])}" + (f" ... and {len(empty_endpoint_tests) - 10} more" if len(empty_endpoint_tests) > 10 else "")
        )

    # Flag: Short notes (rubber-stamping indicator)
    short_note_tests = []
    for tid, entry in tracked_tests.items():
        if entry["status"] == "completed":
            notes_text = entry.get("notes", "")
            if len(notes_text) < 20:
                short_note_tests.append(tid)
    if short_note_tests:
        flags.append(
            f"**SHORT NOTES (rubber-stamping?)**: {len(short_note_tests)} completed tests "
            f"have notes < 20 chars: {', '.join(short_note_tests[:10])}" + (f" ... and {len(short_note_tests) - 10} more" if len(short_note_tests) > 10 else "")
        )

    # Flag: Tools run with 0 findings (output not ingested)
    uninspected_tools = []
    for tool_name, entry in tracked_tools.items():
        if entry["status"] == "run" and entry.get("findings_count", 0) == 0:
            notes_lower = entry.get("notes", "").lower()
            if "no findings" not in notes_lower and "no vulnerabilities" not in notes_lower and "clean" not in notes_lower:
                uninspected_tools.append(tool_name)
    if uninspected_tools:
        flags.append(
            f"**TOOL OUTPUT NOT INGESTED?**: {len(uninspected_tools)} tools marked 'run' "
            f"with 0 findings and no 'no findings' note: {', '.join(uninspected_tools)}. "
            "Were their outputs actually read and reviewed?"
        )

    # Flag: Categories with completed tests but 0 findings
    for cat_code, stats in category_stats.items():
        if stats["completed"] >= 3 and cat_code in {"INPV", "CONF", "ATHN", "SESS"}:
            cat_findings = [f for f in findings if cat_code in f.get("test_id", "")]
            if len(cat_findings) == 0:
                flags.append(
                    f"**ZERO FINDINGS in {cat_code}**: {stats['completed']} tests completed " "but no findings logged. Either the app is well-hardened (note this explicitly) " "or testing was superficial."
                )

    if flags:
        for flag in flags:
            lines.append(f"- {flag}")
    else:
        lines.append("No anomalies detected.")
    lines.append("")

    # ── Section 10: Feature Utilization ──
    lines.append("## 10. Feature Utilization\n")

    # Define Tier 2 features that should be used during a proper pentest
    TIER2_FEATURES = {  # noqa: N806
        "get_technique_guide": "PortSwigger technique guides for attack reference",
        "get_witness_payloads": "Context-aware witness payloads for sink confirmation",
        "get_evidence_checklist": "Evidence checklist before logging findings",
        "create_exploitation_queue": "Structured exploitation queue for vuln classes",
        "validate_exploitation_queue": "Queue validation before exploitation",
        "prioritize_endpoints": "Risk-weighted endpoint prioritization",
        "add_graph_node": "Knowledge graph for vulnerability chaining",
        "find_chains": "Automated vulnerability chain detection",
        "identify_waf": "WAF fingerprinting for adaptive evasion",
        "get_waf_bypass": "WAF-specific bypass payloads",
        "parse_tool_output": "Tool output parsing for token reduction",
        "save_deliverable": "Inter-agent deliverable handoff",
        "get_engagement_rules": "Avoid/focus rules for subagent prompts",
        "track_qa_review": "Quality Reviewer tracking at phase transitions",
    }

    # Read events log to check which features were actually used
    event_file = EVENTS_DIR / f"{engagement_id}.jsonl"
    used_tools: set[str] = set()
    if event_file.exists():
        with open(event_file, encoding="utf-8") as fh:
            for raw_line in fh:
                raw_line = raw_line.strip()
                if raw_line:
                    try:
                        evt = json.loads(raw_line)
                        tool_name = evt.get("tool", "")
                        if tool_name:
                            used_tools.add(tool_name)
                    except json.JSONDecodeError:
                        continue

    used_features = []
    unused_features = []
    for feature, desc in TIER2_FEATURES.items():
        if feature in used_tools:
            used_features.append(f"- **{feature}**: {desc}")
        else:
            unused_features.append(f"- **{feature}**: {desc}")

    total = len(TIER2_FEATURES)
    used_count = len(used_features)
    utilization_pct = (used_count / total * 100) if total > 0 else 0

    lines.append(f"**Feature Utilization: {used_count}/{total} ({utilization_pct:.0f}%)**\n")

    if unused_features:
        lines.append(f"### Unused Features ({len(unused_features)})")
        lines.extend(unused_features)
        lines.append("")

    if used_features:
        lines.append(f"### Used Features ({len(used_features)})")
        lines.extend(used_features)
        lines.append("")

    if utilization_pct < 30:
        lines.append("**WARNING: Feature utilization below 30%.** Many available tools " "were not used. This suggests the agent is not leveraging the full " "capability set, resulting in shallower testing.")
    elif utilization_pct < 60:
        lines.append("**NOTE: Feature utilization below 60%.** Consider using more " "available features for deeper testing coverage.")
    lines.append("")

    # ── Section 11: QA Review History ──
    lines.append("## 11. QA Review History\n")
    qa_file = QA_TRACKING_DIR / f"{engagement_id}.json"
    qa_reviews: list[dict] = []
    if qa_file.exists():
        qa_reviews = json.loads(qa_file.read_text(encoding="utf-8"))

    if qa_reviews:
        lines.append("| Phase | Suggestions | Acted On | Critical Gaps | Timestamp |")
        lines.append("|-------|-------------|----------|---------------|-----------|")
        for qr in qa_reviews:
            lines.append(
                f"| {qr.get('phase_reviewed', '?')} "
                f"| {qr.get('suggestions_count', 0)} "
                f"| {qr.get('suggestions_acted_on', 0)} "
                f"| {qr.get('critical_gaps_found', 0)} "
                f"| {qr.get('timestamp', '?')[:19]} |"
            )
        lines.append("")

        # Check for phases without QA review
        reviewed_phases = {qr["phase_reviewed"] for qr in qa_reviews}
        passed_phases_set = {g["phase"] for g in gate_data if g.get("result") in ("PASS", "FORCED_PASS")}
        unreviewed = passed_phases_set - reviewed_phases
        if unreviewed:
            lines.append(f"**WARNING: Phases {', '.join(str(p) for p in sorted(unreviewed))} " f"passed gate checks without QA review.** Quality Reviewer was not " f"spawned for these phases.")
        lines.append("")

        # Quality metrics
        total_suggestions = sum(qr.get("suggestions_count", 0) for qr in qa_reviews)
        total_acted = sum(qr.get("suggestions_acted_on", 0) for qr in qa_reviews)
        act_rate = (total_acted / total_suggestions * 100) if total_suggestions > 0 else 0
        lines.append(f"**QA Suggestion Action Rate: {total_acted}/{total_suggestions} " f"({act_rate:.0f}%)**")
        if act_rate < 40:
            lines.append("**WARNING: Low QA action rate.** Most QA suggestions were ignored. " "This may indicate superficial quality review compliance.")
    else:
        lines.append("**NO QA REVIEWS RECORDED.** Quality Reviewer was never spawned " "during this engagement. This is a significant quality gap — " "the reviewer catches issues the automated gates miss.")
    lines.append("")

    return "\n".join(lines)


# ── Quality Assurance System ─────────────────────────────────────


def _load_engagement_data(
    engagement_id: str,
) -> tuple[dict[str, dict], dict[str, dict], list[dict]]:
    """Load tracking, tool tracking, and findings data for an engagement.

    Returns:
        (tracked_tests, tracked_tools, findings) — each may be empty.
    """
    tracked_tests: dict[str, dict] = {}
    tracked_tools: dict[str, dict] = {}
    findings: list[dict] = []

    tracking_file = TRACKING_DIR / f"{engagement_id}.json"
    if tracking_file.exists():
        for entry in json.loads(tracking_file.read_text(encoding="utf-8")):
            tracked_tests[entry["test_id"]] = entry

    tool_file = TOOL_TRACKING_DIR / f"{engagement_id}.json"
    if tool_file.exists():
        for entry in json.loads(tool_file.read_text(encoding="utf-8")):
            tracked_tools[entry["tool_name"]] = entry

    findings = _get_findings_from_sqlite(engagement_id)

    return tracked_tests, tracked_tools, findings


def _get_phase_brainstorming(
    phase: int,
    findings: list[dict],
    tracked_tests: dict[str, dict],
    tracked_tools: dict[str, dict],
) -> list[str]:
    """Generate context-aware brainstorming suggestions for a completed phase."""
    suggestions: list[str] = []
    finding_titles = [f.get("title", "").lower() for f in findings]
    has_auth_broken = any("auth" in t and ("broken" in t or "bypass" in t or "500" in t) for t in finding_titles)
    skipped_tests = {tid: e for tid, e in tracked_tests.items() if e["status"] == "skipped"}

    if phase == 0:
        suggestions.append("SCOPE done. Did you check for SSO/OIDC/SAML redirects to a different domain? " "If the login redirects to auth.example.com, register it with register_scope().")
        suggestions.append("Did the user provide credentials? If not, label everything [UNAUTHENTICATED] " "and note blind spots for the AUTH phase.")
        suggestions.append("If Cloudflare detected, route 80% of curl testing to api.<target> " "and use the headed browser for CF-protected pages.")
        suggestions.append("Check if there are API subdomains (api.*) or different auth domains " "that should be in scope.")

    if phase == 1:
        suggestions.append("Check Wayback Machine (web.archive.org) for old site versions " "that may reveal removed endpoints or sensitive files.")
        suggestions.append("Search GitHub/GitLab for the target domain — leaked credentials, " "config files, or source code.")
        suggestions.append("Try site:target.com filetype:pdf|xlsx|docx for sensitive documents.")
        suggestions.append("Did you check for non-standard ports? nmap may reveal services " "on 8080, 8443, 3000, 9090, etc.")
        suggestions.append("Look for exposed config files: /.env, /.git/HEAD, " "/docker-compose.yml, /config.yml, /.DS_Store")
        suggestions.append("Check for API documentation: /swagger, /api-docs, /graphql, " "/openapi.json, /redoc")
        if "gau" not in tracked_tools or tracked_tools["gau"].get("status") != "run":
            suggestions.append("gau (GetAllURLs) can find historical endpoints from web " "archives that are no longer linked but still accessible.")
        if not findings:
            suggestions.append("Zero findings so far — are there information leakage issues " "you dismissed? Version disclosure, tech stack details, and " "internal path exposure are all valid findings.")

    if phase == 2:
        suggestions.append("SURFACE done. Did you prioritize endpoints using " "prioritize_endpoints()? Higher-risk endpoints should be tested first.")
        suggestions.append("Review the endpoint map for authentication-required vs " "public endpoints. Auth-bypass candidates are high priority.")
        suggestions.append("Flag any endpoints with interesting parameter names " "(id, user, file, url, redirect, token, key, api_key) for manual review.")

    if phase == 3:
        suggestions.append(
            "If the app uses SSO/OAuth, test the token exchange endpoint directly: "
            "grant_type=client_credentials, grant_type=password, implicit flow. "
            "Also test if the callback endpoint validates the state parameter "
            "and redirect_uri across domains."
        )
        suggestions.append(
            "Cross-domain sessions: inspect the cookie jar for tokens scoped to "
            "the wrong domain (cookie scope misconfiguration). Check if auth "
            "provider cookies leak to the application domain or vice versa."
        )
        suggestions.append("JWT: test alg:none, RS256->HS256 confusion, key extraction " "from /jwks endpoint, expired timestamp acceptance.")
        suggestions.append("After logout, is the old session token still valid? " "Test session invalidation.")
        suggestions.append("IDOR: try negative IDs (-1), zero (0), very large numbers, " "UUIDs from other contexts, and strings where integers expected.")
        suggestions.append("Test mass assignment: can you set admin=true or role=admin " "when creating/updating your user profile?")
        suggestions.append("Test CORS with multiple origins: evil.com, null origin, " "subdomain origins, and HTTP vs HTTPS protocol switch.")
        suggestions.append("Check for exposed debug endpoints: /debug, /actuator, /health, " "/metrics, /env, /configprops, /trace")
        suggestions.append("Test HTTP TRACE method — if enabled, it can steal HttpOnly " "cookies via cross-site tracing (XST).")
        suggestions.append("Check for .git directory exposure: /.git/HEAD, /.git/config")
        suggestions.append("XSS: test reflected, stored, and DOM variants. " "Check CSP headers — if missing or weak, XSS is easier to exploit.")
        suggestions.append("SQLi: test both string and numeric parameters. " "Look for error-based, boolean blind, and time-based indicators.")
        suggestions.append("SSRF: test DNS rebinding, IPv6 (::1), decimal IP, " "and cloud metadata at 169.254.169.254.")
        suggestions.append("Test SECOND-ORDER injection: payload stored in one endpoint, " "triggered from another (e.g., username in profile displayed " "in admin panel without sanitization).")
        suggestions.append("HTTP parameter pollution: send same param twice. Does the app " "use first, last, or both? This bypasses WAFs.")
        suggestions.append("Test headers as injection points: Host, Referer, " "X-Forwarded-For, User-Agent, Accept-Language.")
        suggestions.append("Business logic: can you change prices, apply discount codes " "multiple times, skip steps in multi-step workflows?")
        suggestions.append("DOM XSS: look for document.location, document.referrer, " "window.name as sources and innerHTML, eval(), " "document.write() as sinks.")
        suggestions.append("Open redirect: test //evil.com, \\/evil.com, /\\evil.com, " "and protocol-relative URLs in redirect parameters.")
        suggestions.append("Check localStorage/sessionStorage for tokens, PII, or " "credentials — accessible to XSS attacks.")
        if has_auth_broken:
            suggestions.append("Auth is broken but don't give up! Try password grant, " "client_credentials, or crafting a JWT manually using " "information from the OIDC configuration endpoint.")
        athz04 = tracked_tests.get("WSTG-ATHZ-04", {})
        if athz04.get("status") == "skipped":
            suggestions.append("IDOR testing was skipped. Even without full auth, try " "manipulating ID-like parameters in any accessible URLs " "(session IDs, user IDs in cookies, API version numbers).")

    if phase == 4:
        suggestions.append("CAPTURE done. Did you collect request/response evidence for all findings? " "Use validate_poc() to verify each finding is still reproducible.")
        suggestions.append("Take screenshots of rendered PoCs (headed browser) and redact " "cookies, tokens, and PII before saving evidence.")
        suggestions.append("Verify collaborator payloads received interactions " "(use burp_get_collaborator_interactions() or check interactsh-client manually).")
        xss_findings = [f for f in findings if "xss" in f.get("title", "").lower() or "INPV-01" in f.get("test_id", "") or "INPV-02" in f.get("test_id", "")]
        if xss_findings:
            suggestions.append(f"XSS FOUND ({len(xss_findings)} instances). Capture rendered " "alert() screenshots as evidence.")
        sqli_findings = [f for f in findings if "sql" in f.get("title", "").lower() or "INPV-05" in f.get("test_id", "")]
        if sqli_findings:
            suggestions.append("SQLi FOUND. Capture database fingerprint evidence " "(version banner, user, database name) for the report.")

    if phase == 5:
        suggestions.append("VALIDATE done. Run the 7-Question Gate on every finding before reporting.")
        suggestions.append("Check coverage: call get_coverage() and " "get_tool_coverage() to identify gaps before generating report.")
        suggestions.append("For each finding, verify the vulnerability class is mapped " "to the correct severity and VRT category.")

    # Universal suggestions based on skip rate
    if len(skipped_tests) > 5:
        suggestions.append(f"{len(skipped_tests)} tests skipped so far. Review each — " "can any be unblocked with a creative approach?")

    return suggestions


@mcp.tool()
def phase_gate_check(
    engagement_id: str,
    phase_completed: int,
    force: bool = False,
) -> str:
    """Check quality gates for a completed phase. Returns PASS or FAIL with
    specific blockers, warnings, and brainstorming suggestions.
    MUST be called after completing each phase before proceeding to the next.

    Supports the 12-phase methodology pipeline (0=SCOPE through 12=REPORT).
    Phases 6-12 use lighter validation (no WSTG test requirements) since
    they are meta-phases (DEEPTHINK, EXPLOIT, SEARCH, CAPTURE, VALIDATE, REPORT).

    Args:
        engagement_id: The engagement identifier
        phase_completed: The phase number just completed (0-12)
        force: If True, record as FORCED_PASS regardless of blockers
    """
    if phase_completed not in range(13):
        return f"Invalid phase: {phase_completed}. Must be 0-12."

    # ── Detect CTF mode ──────────────────────────────────────────
    config_file_check = CONFIG_DIR / f"{engagement_id}.json"
    is_ctf_mode = False
    if config_file_check.exists():
        _cfg = _safe_read_json(config_file_check, {})
        is_ctf_mode = _cfg.get("mode") == "ctf"

    # ── Phase gate timing enforcement ─────────────────────────────
    # Minimum 60 seconds between consecutive gate calls to ensure
    # actual testing work is performed between phases.
    # CTF mode uses a reduced 15-second minimum.
    MIN_GATE_INTERVAL_SECONDS = 15 if is_ctf_mode else 60  # noqa: N806
    GATE_TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    gate_file_timing = GATE_TRACKING_DIR / f"{engagement_id}.json"
    if gate_file_timing.exists():
        prev_gates = json.loads(gate_file_timing.read_text(encoding="utf-8"))
        if prev_gates:
            last_gate = prev_gates[-1]
            last_ts = datetime.fromisoformat(last_gate["timestamp"])
            now = datetime.now(timezone.utc)
            delta_seconds = (now - last_ts).total_seconds()
            if delta_seconds < MIN_GATE_INTERVAL_SECONDS and not force:
                return (
                    f"# Phase Gate Check: Phase {phase_completed}\n"
                    f"## Result: **BLOCKED — TOO SOON**\n\n"
                    f"Gate called {delta_seconds:.0f}s after Phase {last_gate['phase']} gate "
                    f"(minimum {MIN_GATE_INTERVAL_SECONDS}s required).\n\n"
                    f"This indicates insufficient testing work between phases. "
                    f"Ensure you:\n"
                    f"1. Actually execute the tests for Phase {phase_completed}\n"
                    f"2. Call track_test() for each test\n"
                    f"3. Wait at least {MIN_GATE_INTERVAL_SECONDS}s between gate calls\n\n"
                    f"Use `force=True` to override this gate (result recorded as FORCED_PASS)."
                )

    # ── Inter-gate work verification ──────────────────────────────
    # Check the events log for actual testing work between the last
    # gate and now. If no track_test/track_tool/log_finding events
    # occurred, this phase was likely not properly executed.
    if gate_file_timing.exists() and not is_ctf_mode:
        prev_gates = json.loads(gate_file_timing.read_text(encoding="utf-8"))
        if prev_gates:
            last_gate_ts_str = prev_gates[-1]["timestamp"]
            event_file_check = EVENTS_DIR / f"{engagement_id}.jsonl"
            work_events = 0
            work_tools = {"track_test", "track_tool", "log_finding"}
            if event_file_check.exists():
                with open(event_file_check, encoding="utf-8") as ef:
                    for raw_line in ef:
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        try:
                            evt = json.loads(raw_line)
                            evt_ts = evt.get("timestamp", "")
                            evt_tool = evt.get("tool", "")
                            if evt_ts > last_gate_ts_str and evt_tool in work_tools:
                                work_events += 1
                        except json.JSONDecodeError:
                            continue
            # Phase 0 doesn't require track_test calls (tool-only phase)
            min_work_events = 1 if phase_completed == 0 else 3
            if work_events < min_work_events:
                # This is a warning, not a blocker — the test/tool validation
                # will catch specifics. This catches the "zero work" case.
                pass  # Will be added to warnings after blockers list is created
                _inter_gate_work_deficit = work_events
            else:
                _inter_gate_work_deficit = None
        else:
            _inter_gate_work_deficit = None
    else:
        _inter_gate_work_deficit = None

    tracked_tests, tracked_tools, findings = _load_engagement_data(engagement_id)
    blockers: list[str] = []
    warnings: list[str] = []

    # Add inter-gate work deficit warning if detected
    if _inter_gate_work_deficit is not None:
        min_work = 1 if phase_completed == 0 else 3
        warnings.append(
            f"LOW INTER-GATE ACTIVITY: Only {_inter_gate_work_deficit} work events "
            f"(track_test/track_tool/log_finding) since last gate "
            f"(expected >= {min_work}). This suggests the phase may not have been "
            f"properly executed. Verify that testing work actually occurred."
        )

    # ── QA Review enforcement ─────────────────────────────────────
    # Phases 1+ require QA review of the PREVIOUS phase.
    # Phase 0 has no previous phase, so skip this check.
    if phase_completed >= 1:
        qa_file = QA_TRACKING_DIR / f"{engagement_id}.json"
        qa_reviews: list[dict] = []
        if qa_file.exists():
            qa_reviews = json.loads(qa_file.read_text(encoding="utf-8"))
        prev_phase = phase_completed - 1
        prev_reviewed = any(r.get("phase_reviewed") == prev_phase for r in qa_reviews)
        if not prev_reviewed:
            if not is_ctf_mode:
                blockers.append(
                    f"Quality Reviewer not spawned for Phase {prev_phase}. "
                    f"MANDATORY: Spawn a Quality Reviewer subagent after completing "
                    f"Phase {prev_phase}, then call track_qa_review(). "
                    f"Use force=True to override."
                )

    # ── Phase 0: Tool-only validation ──────────────────────────────
    if phase_completed == 0:
        phase0_reqs = PHASE_TOOL_REQUIREMENTS[0]
        # CTF mode: tool requirements are warnings, not blockers
        for tool in phase0_reqs["mandatory"]:
            if tool not in tracked_tools:
                msg = f"Phase 0 mandatory tool '{tool}' not tracked. " "Call track_tool() with status='run' or 'skipped'."
                if is_ctf_mode:
                    warnings.append(msg)
                else:
                    blockers.append(msg)
            elif tracked_tools[tool]["status"] == "skipped" and len(tracked_tools[tool].get("notes", "")) < 10:
                msg = f"Tool '{tool}' skipped without adequate reason " f"(notes: '{tracked_tools[tool].get('notes', '')}')."
                if is_ctf_mode:
                    warnings.append(msg)
                else:
                    blockers.append(msg)
        for tool in phase0_reqs["conditional"]:
            if tool not in tracked_tools:
                warnings.append(f"Conditional tool '{tool}' not tracked. " "Track as 'not_applicable' if condition not met.")

    # ── Phase 1-5: Test + tool validation ──────────────────────────
    if phase_completed >= 1:
        reqs = PHASE_TEST_REQUIREMENTS.get(phase_completed)
        if reqs:
            phase_name = reqs["name"]

            # Check MUST tests are tracked
            untracked_must = []
            for test_id in reqs["must_tests"]:
                if test_id not in tracked_tests:
                    untracked_must.append(test_id)
            if untracked_must:
                msg = f"MUST-priority tests not tracked: {', '.join(untracked_must)}. " "Call track_test() for each (completed, skipped, or not_applicable)."
                if is_ctf_mode:
                    warnings.append(msg)
                else:
                    blockers.append(msg)

            # Check minimum completion threshold
            # CTF mode halves the minimum requirement
            min_required = reqs["min_completed"]
            if is_ctf_mode:
                min_required = max(1, min_required // 2)

            actually_completed = sum(1 for tid in reqs["must_tests"] if tracked_tests.get(tid, {}).get("status") == "completed")
            completed_or_na = sum(1 for tid in reqs["must_tests"] if tracked_tests.get(tid, {}).get("status") in ("completed", "not_applicable"))
            if completed_or_na < min_required:
                blockers.append(f"Only {completed_or_na}/{min_required} MUST tests " f"completed/N/A (need at least {min_required}). " "Complete more tests or mark genuinely inapplicable ones as N/A.")
            elif actually_completed < min_required // 2:
                warnings.append(f"LOW EFFECTIVE COMPLETION: Only {actually_completed} MUST " f"tests actually completed (rest are N/A). Verify that N/A " f"markings are genuine and not caused by auth failure.")

            # Check skipped tests have reasons
            for test_id in reqs["must_tests"]:
                entry = tracked_tests.get(test_id, {})
                if entry.get("status") == "skipped" and len(entry.get("notes", "")) < 10:
                    blockers.append(f"Test {test_id} skipped without adequate reason " f"(notes: '{entry.get('notes', '')}').")

            # Core test gate (HUNT phase = 6)
            if phase_completed == 6 and "core_tests" in reqs:
                core_completed = sum(1 for tid in reqs["core_tests"] if tracked_tests.get(tid, {}).get("status") == "completed")
                core_na = sum(1 for tid in reqs["core_tests"] if tracked_tests.get(tid, {}).get("status") == "not_applicable")
                core_attempted = sum(1 for tid in reqs["core_tests"] if tracked_tests.get(tid, {}).get("status") in ("completed", "skipped", "not_applicable"))
                if core_completed < 2:
                    blockers.append(f"Gate 4: Only {core_completed}/2 core INPV tests actually " f"COMPLETED (need >= 2 completed, not just tracked as N/A). " f"Core tests: {', '.join(reqs['core_tests'])}.")
                if core_na >= 4:
                    blockers.append(
                        f"Gate 4: {core_na}/{len(reqs['core_tests'])} core INPV tests "
                        "marked N/A. This suggests authentication failure is preventing "
                        "input validation testing. Resolve auth issues or test "
                        "unauthenticated endpoints before completing Phase 4."
                    )
                if core_attempted < reqs["core_min"]:
                    blockers.append(f"Gate 4: Only {core_attempted}/{reqs['core_min']} core INPV " f"tests attempted (need >= {reqs['core_min']} of: " f"{', '.join(reqs['core_tests'])}).")

            # Warning: SHOULD tests not tracked
            untracked_should = [tid for tid in reqs["should_tests"] if tid not in tracked_tests]
            if untracked_should:
                warnings.append(f"SHOULD-priority tests not tracked: {', '.join(untracked_should)}. " "Track as 'not_applicable' if condition not met.")

            # Warning: completed tests with no endpoints
            for test_id in reqs["must_tests"] + reqs["should_tests"]:
                entry = tracked_tests.get(test_id, {})
                if entry.get("status") == "completed" and not entry.get("endpoints_tested"):
                    warnings.append(f"Test {test_id} marked completed but no endpoints listed. " "Was it actually tested against real targets?")

            # Warning: high skip rate
            total_must = len(reqs["must_tests"])
            skipped_must = sum(1 for tid in reqs["must_tests"] if tracked_tests.get(tid, {}).get("status") == "skipped")
            if total_must > 0 and skipped_must / total_must > 0.4:
                warnings.append(f"High skip rate: {skipped_must}/{total_must} MUST tests skipped " f"({skipped_must/total_must*100:.0f}%). Review if any can be " "tested with an alternative approach.")

            # Auth failure cascade detection (phases 6+)
            if phase_completed >= 6:
                na_must = sum(1 for tid in reqs["must_tests"] if tracked_tests.get(tid, {}).get("status") == "not_applicable")
                if total_must > 0 and na_must / total_must > 0.5:
                    blockers.append(
                        f"AUTH FAILURE CASCADE DETECTED: {na_must}/{total_must} "
                        f"MUST tests marked N/A ({na_must/total_must*100:.0f}%). "
                        "This pattern indicates authentication failure is preventing "
                        "testing. You MUST: (1) attempt all alternative auth methods "
                        "(password grant, client_credentials, PKCE via scripts/pkce-auth.py, "
                        "headless browser via scripts/browser-auth.py, manual token from "
                        "user), (2) test unauthenticated endpoints for the N/A tests, "
                        "(3) ask the user for a valid session token if all automated "
                        "methods fail. Do NOT proceed until auth is resolved or "
                        "unauthenticated testing is exhausted."
                    )

    # ── Cumulative tool validation (all phases up to completed) ────
    # Phase 0 tools already checked in the phase-specific block above,
    # so skip phase 0 when phase_completed == 0 to avoid duplicates.
    for p in range(phase_completed + 1):
        if p == 0 and phase_completed == 0:
            continue  # already handled above
        tool_reqs = PHASE_TOOL_REQUIREMENTS.get(p)
        if not tool_reqs:
            continue
        for tool in tool_reqs["mandatory"]:
            if tool not in tracked_tools:
                blockers.append(f"Phase {p} mandatory tool '{tool}' not tracked. " "Call track_tool().")
        for tool in tool_reqs["conditional"]:
            if tool not in tracked_tools:
                warnings.append(f"Phase {p} conditional tool '{tool}' not tracked. " "Track as 'not_applicable' if condition not met.")

    # ── Quality heuristics ─────────────────────────────────────────
    # Zero findings in high-risk phases
    if phase_completed in (6, 11) and not findings:
        warnings.append(f"No findings logged after Phase {phase_completed} (HUNT/VALIDATE). " "This is unusual for full pipeline testing. Did you dispatch hunt agents?")
    # Methodology phase 6+ heuristic: zero findings after HUNT
    if phase_completed >= 7 and not findings:
        warnings.append(f"No findings logged after Phase {phase_completed} (DEEPTHINK+). " "This is unusual for full pipeline testing. Did you dispatch hunt agents?")

    # Findings referencing tests that aren't tracked
    finding_test_ids = {f.get("test_id", "") for f in findings}
    for fid in finding_test_ids:
        if fid and fid not in tracked_tests:
            warnings.append(f"Finding references test {fid} which is not tracked. " "Call track_test() for this test.")

    # ── Brainstorming ──────────────────────────────────────────────
    brainstorming = _get_phase_brainstorming(phase_completed, findings, tracked_tests, tracked_tools)

    # ── Assemble output ───────────────────────────────────────────
    result = "PASS" if not blockers else "FAIL"
    if force and blockers:
        result = "FORCED_PASS"

    phase_name = PHASE_NAMES.get(phase_completed, f"Phase {phase_completed}")
    lines = [
        f"# Phase Gate Check: Phase {phase_completed} — {phase_name}",
        f"## Result: **{result}**\n",
    ]

    if blockers:
        lines.append(f"## BLOCKERS ({len(blockers)} issues)\n")
        for i, b in enumerate(blockers, 1):
            lines.append(f"{i}. {b}")
        lines.append("")

    if warnings:
        lines.append(f"## WARNINGS ({len(warnings)} items)\n")
        for i, w in enumerate(warnings, 1):
            lines.append(f"{i}. {w}")
        lines.append("")

    if brainstorming:
        lines.append("## BRAINSTORMING — Creative Suggestions\n")
        for i, s in enumerate(brainstorming, 1):
            lines.append(f"{i}. {s}")
        lines.append("")

    # Statistics
    tests_in_phase = []
    if phase_completed >= 1:
        reqs = PHASE_TEST_REQUIREMENTS.get(phase_completed, {})
        tests_in_phase = reqs.get("must_tests", []) + reqs.get("should_tests", [])

    tests_tracked = sum(1 for t in tests_in_phase if t in tracked_tests)
    tests_completed = sum(1 for t in tests_in_phase if tracked_tests.get(t, {}).get("status") == "completed")
    tests_skipped = sum(1 for t in tests_in_phase if tracked_tests.get(t, {}).get("status") == "skipped")
    tests_na = sum(1 for t in tests_in_phase if tracked_tests.get(t, {}).get("status") == "not_applicable")

    lines.append("## Phase Statistics\n")
    lines.append(f"- Tests in phase: {len(tests_in_phase)}")
    lines.append(f"- Tests tracked: {tests_tracked}")
    lines.append(f"- Completed: {tests_completed}")
    lines.append(f"- Skipped: {tests_skipped}")
    lines.append(f"- N/A: {tests_na}")
    lines.append(f"- Not tracked: {len(tests_in_phase) - tests_tracked}")
    lines.append(f"- Total findings so far: {len(findings)}")
    lines.append(f"- Total tools tracked: {len(tracked_tools)}")

    # ── Persist gate result ────────────────────────────────────────
    GATE_TRACKING_DIR.mkdir(parents=True, exist_ok=True)
    gate_file = GATE_TRACKING_DIR / f"{engagement_id}.json"
    gate_data: list[dict] = []
    if gate_file.exists():
        gate_data = json.loads(gate_file.read_text(encoding="utf-8"))
    gate_data.append(
        {
            "phase": phase_completed,
            "result": result,
            "blockers_count": len(blockers),
            "warnings_count": len(warnings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    _atomic_write_json(gate_file, gate_data)
    blocker_tag = f" ({len(blockers)} blockers)" if blockers else ""
    _append_progress_log(
        engagement_id,
        f"GATE Phase {phase_completed} ({phase_name}) -> {result}{blocker_tag}",
    )
    _append_event(
        engagement_id,
        {
            "tool": "phase_gate_check",
            "args": {"phase": phase_completed, "result": result},
            "result": f"Phase {phase_completed}: {result}",
        },
    )

    # Auto-save checkpoint on gate pass
    if result in ("PASS", "FORCED_PASS"):
        try:
            _auto_save_checkpoint(engagement_id, phase_completed)
        except Exception as e:
            logger.warning(f"Auto-checkpoint failed for phase {phase_completed}: {e}")

        # Auto-compress phase context on PASS (progressive context compression)
        try:
            _cc_compress(engagement_id, phase_completed)
        except Exception as e:
            logger.warning(f"Auto-compress failed for phase {phase_completed}: {e}")

    # Always update resume prompt (on pass or fail — captures latest state)
    try:
        _write_resume_prompt_file(engagement_id)
    except Exception as e:
        logger.warning(f"Resume prompt update failed for phase {phase_completed}: {e}")

    return "\n".join(lines)


# ── Report Generation ────────────────────────────────────────────


@mcp.tool()
def generate_report(
    engagement_id: str,
    target: str,
    tester: str,
    force: bool = False,
) -> str:
    """Generate a full markdown penetration test report from all logged findings.
    The report is saved to engagements/runtime/<engagement_id>/report.md.

    Before generating, validates that all phase gates have passed.
    If validation fails, report is blocked unless force=True.

    Args:
        engagement_id: The engagement identifier
        target: The target application URL or name
        tester: Name of the tester or team
        force: If True, generate report even if gates have not all passed
    """
    # ── Pre-flight validation ──────────────────────────────────────
    if not force:
        pre_flight_blockers: list[str] = []

        # Check 1: Phase gate tracking
        gate_file = GATE_TRACKING_DIR / f"{engagement_id}.json"
        if not gate_file.exists():
            pre_flight_blockers.append("No phase gate checks have been run. " "Call phase_gate_check() after each phase before generating.")
        else:
            gate_data = json.loads(gate_file.read_text(encoding="utf-8"))
            # Build latest result per phase
            latest_per_phase: dict[int, str] = {}
            for entry in gate_data:
                latest_per_phase[entry["phase"]] = entry["result"]

            max_gated = max(latest_per_phase.keys()) if latest_per_phase else -1
            expected_phases = set(range(max_gated + 1))
            unchecked = expected_phases - set(latest_per_phase.keys())
            if unchecked:
                pre_flight_blockers.append(f"Phase gate checks missing for phases: {sorted(unchecked)}. " "Run phase_gate_check() for each.")

            still_failing = [p for p, r in latest_per_phase.items() if r == "FAIL"]
            if still_failing:
                pre_flight_blockers.append(f"Phase gate FAILED for phases: {sorted(still_failing)}. " "Address blockers and re-run phase_gate_check().")

        # Check 2: Required category coverage (Gate 2)
        tracking_file = TRACKING_DIR / f"{engagement_id}.json"
        if tracking_file.exists():
            tracking = json.loads(tracking_file.read_text(encoding="utf-8"))
            tracked_test_map = {e["test_id"]: e for e in tracking}

            required_cats = {
                "INFO",
                "CONF",
                "ATHN",
                "ATHZ",
                "SESS",
                "INPV",
                "ERRH",
                "CLNT",
            }
            for num, cat in CATEGORIES.items():
                if cat["code"] not in required_cats:
                    continue
                cat_dir = WSTG_DIR / cat["dir"]
                if not cat_dir.exists():
                    continue
                cat_tests = list(cat_dir.glob("WSTG-*.md"))
                tracked_in_cat = sum(1 for t in cat_tests if tracked_test_map.get(t.stem.upper(), {}).get("status") in ("completed", "not_applicable", "skipped"))
                actually_completed_in_cat = sum(1 for t in cat_tests if tracked_test_map.get(t.stem.upper(), {}).get("status") == "completed")
                if tracked_in_cat == 0:
                    pre_flight_blockers.append(f"Gate 2: Category {cat['code']} ({cat['name']}) " "has 0% coverage.")
                elif actually_completed_in_cat == 0:
                    pre_flight_blockers.append(f"Gate 2: Category {cat['code']} ({cat['name']}) " "has NO completed tests (all are N/A or skipped). " "At least 1 test must be actually completed.")

            # Check 3: Overall coverage >= 40% (Gate 3)
            total = sum(len(list((WSTG_DIR / c["dir"]).glob("WSTG-*.md"))) for c in CATEGORIES.values() if (WSTG_DIR / c["dir"]).exists())
            attempted = sum(1 for e in tracking if e["status"] in ("completed", "skipped", "not_applicable"))
            if total > 0 and (attempted / total * 100) < 40:
                pre_flight_blockers.append(f"Gate 3: Overall coverage is {attempted/total*100:.0f}% " "(minimum 40%).")

            # Check 4: Core INPV tests (Gate 4)
            core_inpv = [
                "WSTG-INPV-01",
                "WSTG-INPV-02",
                "WSTG-INPV-05",
                "WSTG-INPV-12",
                "WSTG-INPV-18",
                "WSTG-INPV-19",
            ]
            core_completed = sum(1 for t in core_inpv if tracked_test_map.get(t, {}).get("status") == "completed")
            core_attempted = sum(1 for t in core_inpv if tracked_test_map.get(t, {}).get("status") in ("completed", "skipped", "not_applicable"))
            if core_completed < 2:
                pre_flight_blockers.append(f"Gate 4: Only {core_completed}/2 core INPV tests actually " "COMPLETED (need >= 2 completed). N/A does not count.")
            if core_attempted < 4:
                pre_flight_blockers.append(f"Gate 4: Only {core_attempted}/4 core INPV tests attempted.")
        else:
            pre_flight_blockers.append("No test tracking data found. Run track_test() for each test.")

        # Check 5: Mandatory tool coverage (Gate 6)
        tool_file = TOOL_TRACKING_DIR / f"{engagement_id}.json"
        if tool_file.exists():
            tool_data = json.loads(tool_file.read_text(encoding="utf-8"))
            tracked_tool_names = {e["tool_name"] for e in tool_data}
            missing_tools = []
            for tool_name, info in TOOL_REGISTRY.items():
                if info["tier"] == "mandatory" and info["condition"] is None:
                    if tool_name not in tracked_tool_names:
                        missing_tools.append(f"{tool_name} (Phase {info['phase']})")
            if missing_tools:
                pre_flight_blockers.append(f"Gate 6: Mandatory tools not tracked: {', '.join(missing_tools)}")
        else:
            pre_flight_blockers.append("No tool tracking data found. Run track_tool() for each tool.")

        if pre_flight_blockers:
            lines = [
                "# REPORT GENERATION BLOCKED\n",
                f"{len(pre_flight_blockers)} issues must be resolved:\n",
            ]
            for i, b in enumerate(pre_flight_blockers, 1):
                lines.append(f"{i}. {b}")
            lines.append("\nTo override: call generate_report() with force=True. " "The report will include a disclaimer about incomplete testing.")
            return "\n".join(lines)

    # ── Report generation ──────────────────────────────────────────
    findings = _get_findings_from_sqlite(engagement_id)
    if not findings:
        return "No findings to generate report from. Log findings first with log_finding()."

    # H13: Filter to verified findings unless force=True
    verified = [f for f in findings if f.get("confidence") == "confirmed" and f.get("poc_token")]
    if not force:
        findings = verified
        if not findings:
            return "No verified findings to generate report. Use force=True to include unverified findings."
    elif verified:
        findings = verified + [f for f in findings if not (f.get("confidence") == "confirmed" and f.get("poc_token"))]
    else:
        findings = findings

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    lines = [
        "# Penetration Test Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Target** | {target} |",
        f"| **Engagement ID** | {engagement_id} |",
        f"| **Tester** | {tester} |",
        f"| **Date** | {now} |",
        "| **Methodology** | OWASP WSTG v4.2 |",
        "",
        "## Executive Summary",
        "",
    ]

    if force:
        lines.append(
            "> **DISCLAIMER**: This report was generated with force override. "
            "Not all quality gates were satisfied. Some phases may have "
            "incomplete testing. Findings represent a partial assessment, "
            "not a comprehensive penetration test.\n"
        )

    # Add scope architecture table if multi-domain engagement
    scope_file = SCOPE_DIR / f"{engagement_id}.json"
    scope_data: list[dict] = []
    if scope_file.exists():
        scope_data = json.loads(scope_file.read_text(encoding="utf-8"))
        if scope_data:
            type_labels = {
                "app": "Application",
                "auth_provider": "Auth Provider",
                "api": "API",
                "cdn": "CDN",
                "third_party": "Third Party",
            }
            lines.extend(
                [
                    "### Target Scope & Domain Architecture",
                    "",
                    "| Domain | Type | Notes |",
                    "|--------|------|-------|",
                ]
            )
            for entry in scope_data:
                label = type_labels.get(entry["domain_type"], entry["domain_type"])
                lines.append(f"| {entry['domain']} | {label} | {entry.get('notes', '')} |")
            lines.extend([""])

    # ── Deduplicate findings ─────────────────────────────────────
    dedup_map: dict[tuple, list[dict]] = {}
    for f in findings:
        key = (f["affected_url"].rstrip("/"), f.get("test_id", ""), f["title"].strip().lower())
        dedup_map.setdefault(key, []).append(f)

    merged_findings = []
    for key, group in dedup_map.items():
        primary = group[0].copy()
        if len(group) > 1:
            primary["id"] = ", ".join(f["id"] for f in group)
            primary["_duplicate_ids"] = [f["id"] for f in group]
            all_evidence = [f.get("evidence", "") for f in group if f.get("evidence")]
            primary["evidence"] = "\n\n---\n\n".join(all_evidence)
            sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
            primary["severity"] = min(group, key=lambda x: sev_order.get(x["severity"], 5))["severity"]
        merged_findings.append(primary)

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    merged_findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

    # ── Split by confidence ──────────────────────────────────────
    confirmed_findings = [f for f in merged_findings if f.get("confidence", "version_based") == "confirmed"]
    additional_findings = [f for f in merged_findings if f.get("confidence", "version_based") in ("version_based", "speculative")]

    dedup_count = len(merged_findings)
    lines.extend(
        [
            f"A penetration test was conducted against **{target}** following the OWASP Web Security "
            f"Testing Guide (WSTG) methodology. A total of **{len(findings)} raw findings** "
            f"were identified, consolidated into **{dedup_count} unique findings** "
            f"(**{len(confirmed_findings)} confirmed**, "
            f"**{len(additional_findings)} version-based/speculative**).",
            "",
            "### Finding Summary",
            "",
            "| Category | Confirmed | Additional Candidates |",
            "|----------|-----------|----------------------|",
        ]
    )

    sev_categories = ["Critical", "High", "Medium", "Low", "Informational"]
    for sev in sev_categories:
        confirmed_count = sum(1 for f in confirmed_findings if f["severity"] == sev)
        additional_count = sum(1 for f in additional_findings if f["severity"] == sev)
        lines.append(f"| {sev} | {confirmed_count} | {additional_count} |")

    lines.append(f"| **Total** | {len(confirmed_findings)} | {len(additional_findings)} |")

    lines.extend(["", "## Detailed Findings", ""])

    def _render_finding(f: dict) -> list[str]:
        evidence_fence, _ = _safe_code_fence(f["evidence"])
        poc_link = ""
        poc_token = f.get("poc_token", "")
        if poc_token:
            eid_safe = _sanitize_id(engagement_id)
            poc_link = f"| **PoC Report** | `{poc_token}` (see `engagements/{eid_safe}/evidence/`) |"
        poc_out = f.get("poc_output", "")
        poc_output_fence, _ = _safe_code_fence(poc_out) if poc_out else ("", False)
        lines = [
            f"### {f['id']}: {f['title']}",
            "",
            "| Attribute | Detail |",
            "|-----------|--------|",
            f"| **Severity** | {f['severity']} |",
            f"| **Confidence** | {f.get('confidence', 'version_based')} |",
            f"| **WSTG Reference** | {f['test_id']} |",
            f"| **Affected URL** | {f['affected_url']} |",
            f"| **Affected Parameter** | {f.get('affected_parameter', 'N/A')} |",
            (poc_link if poc_link else ""),
            f"| **Reproducible** | {'✅ Reproduced' if f.get('reproduced') else '❌ Not Reproduced'} |",
            f"| **Consensus** | {'🧠 Passed' if f.get('consensus_passed') else '❌ Failed'} |",
            f"| **Baseline Anomaly** | {'⚠️ Yes' if f.get('baseline_anomaly') else '✅ No'} |",
            "",
            "#### Description",
            "",
            f"{f['description']}",
            "",
            "#### Evidence",
            "",
            evidence_fence,
            f"{f['evidence']}",
            evidence_fence,
        ]
        if poc_out:
            lines.extend(
                [
                    "",
                    "#### Reproduction Steps",
                    "",
                    poc_output_fence,
                    poc_out,
                    poc_output_fence,
                ]
            )
        lines.extend(
            [
                "",
                "#### Remediation",
                "",
                f"{f['remediation']}",
                "",
                "#### Validation Summary",
                "",
                f"- **Reproduced**: {f.get('reproduced', False)}",
                f"- **Consensus Passed**: {f.get('consensus_passed', False)}",
                f"- **Baseline Anomaly**: {f.get('baseline_anomaly', False)}",
                f"- **Independent Engine**: {f.get('independent_engine', False)}",
                "",
                "---",
                "",
            ]
        )
        return lines

    def _render_domain_section(domain_name: str, domain_findings: list[dict]) -> list[str]:
        out = [f"### Domain: {domain_name}\n"]
        for f in domain_findings:
            out.extend(_render_finding(f))
        return out

    # ── Confirmed findings ───────────────────────────────────────
    if confirmed_findings:
        lines.append("## Confirmed Findings\n")
        lines.append("> These findings have been validated with a working proof-of-concept " "(`confidence=confirmed`). Reported with full severity.\n")
        if scope_data:
            domain_groups: dict[str, list[dict]] = {}
            for f in confirmed_findings:
                d = f.get("domain", "") or "General / Cross-Domain"
                domain_groups.setdefault(d, []).append(f)
            for domain_name, domain_findings in domain_groups.items():
                lines.extend(_render_domain_section(domain_name, domain_findings))
        else:
            for f in confirmed_findings:
                lines.extend(_render_finding(f))
    else:
        lines.append("## Confirmed Findings\n\nNo confirmed findings with working PoC.\n")

    # ── Additional Candidates ────────────────────────────────────
    if additional_findings:
        lines.append("## Additional Candidates (Version-Based / Speculative)\n")
        lines.append(
            "> These findings are based on version detection, CVE matches, or other "
            "indirect evidence (`confidence=version_based` or `confidence=speculative`). "
            "Severity is capped (version_based ≤ Medium/6.0, speculative ≤ Low/3.0) "
            "until a working PoC is demonstrated. They require further testing.\n"
        )
        # Apply CVSS cap for report display
        for f in additional_findings:
            conf = f.get("confidence", "version_based")
            if conf == "version_based":
                sev_map = {"Critical": "High", "High": "Medium"}
                if f["severity"] in sev_map:
                    f["severity"] = sev_map[f["severity"]]
            elif conf == "speculative":
                f["severity"] = "Low"

        # Re-sort after severity adjustment
        additional_findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

        if scope_data:
            domain_groups = {}
            for f in additional_findings:
                d = f.get("domain", "") or "General / Cross-Domain"
                domain_groups.setdefault(d, []).append(f)
            for domain_name, domain_findings in domain_groups.items():
                lines.extend(_render_domain_section(domain_name, domain_findings))
        else:
            for f in additional_findings:
                lines.extend(_render_finding(f))

    # Add coverage section if tracking data exists
    tracking_file = TRACKING_DIR / f"{engagement_id}.json"
    if tracking_file.exists():
        tracking = json.loads(tracking_file.read_text(encoding="utf-8"))
        tracked_tests = {entry["test_id"]: entry for entry in tracking}

        lines.extend(["## Test Coverage\n"])
        lines.append("| Category | Code | Completed | Skipped | N/A | Not Attempted | Coverage |")
        lines.append("|----------|------|-----------|---------|-----|---------------|----------|")

        overall_attempted = 0
        overall_total = 0

        for num, cat in CATEGORIES.items():
            cat_dir = WSTG_DIR / cat["dir"]
            if not cat_dir.exists():
                continue
            cat_tests = sorted(cat_dir.glob("WSTG-*.md"))
            cat_total = len(cat_tests)
            overall_total += cat_total

            completed = sum(1 for t in cat_tests if tracked_tests.get(t.stem.upper(), {}).get("status") == "completed")
            skipped = sum(1 for t in cat_tests if tracked_tests.get(t.stem.upper(), {}).get("status") == "skipped")
            na = sum(1 for t in cat_tests if tracked_tests.get(t.stem.upper(), {}).get("status") == "not_applicable")
            not_attempted_list = [t.stem.upper() for t in cat_tests if t.stem.upper() not in tracked_tests]

            attempted = completed + skipped + na
            overall_attempted += attempted
            pct = (attempted / cat_total * 100) if cat_total > 0 else 0

            lines.append(f"| {cat['name']} | {cat['code']} | {completed} | {skipped} | {na} " f"| {len(not_attempted_list)} | {pct:.0f}% |")

        overall_pct = (overall_attempted / overall_total * 100) if overall_total > 0 else 0
        lines.append(f"| **Overall** | | | | | | **{overall_pct:.0f}%** |")
        lines.append("")

        # Skipped test details
        skipped_tests = [e for e in tracking if e["status"] == "skipped"]
        if skipped_tests:
            lines.append("### Skipped Tests (with reasons)\n")
            for s in skipped_tests:
                lines.append(f"- **{s['test_id']}**: {s['notes']}")
            lines.append("")

        # Not attempted tests
        all_not_attempted = []
        for num, cat in CATEGORIES.items():
            cat_dir = WSTG_DIR / cat["dir"]
            if not cat_dir.exists():
                continue
            for t in sorted(cat_dir.glob("WSTG-*.md")):
                if t.stem.upper() not in tracked_tests:
                    all_not_attempted.append(t.stem.upper())
        if all_not_attempted:
            lines.append("### Tests Not Attempted\n")
            lines.append(", ".join(all_not_attempted))
            lines.append("")
    else:
        lines.extend(
            [
                "## Test Coverage\n",
                "*No test tracking data available. Coverage tracking was not used during this engagement.*\n",
            ]
        )

    # Add tool coverage section
    tool_tracking_file = TOOL_TRACKING_DIR / f"{engagement_id}.json"
    if tool_tracking_file.exists():
        tool_tracking = json.loads(tool_tracking_file.read_text(encoding="utf-8"))
        tracked_tools_map = {entry["tool_name"]: entry for entry in tool_tracking}

        lines.extend(["## Tool Coverage\n"])
        lines.append("| Tool | Phase | Tier | Status | Findings | Notes |")
        lines.append("|------|-------|------|--------|----------|-------|")

        tool_total = len(TOOL_REGISTRY)
        tool_tracked = 0
        tool_run = 0

        for phase_num in sorted(set(info["phase"] for info in TOOL_REGISTRY.values())):
            phase_tools = [name for name, info in TOOL_REGISTRY.items() if info["phase"] == phase_num]
            for tool_name in sorted(phase_tools):
                info = TOOL_REGISTRY[tool_name]
                if tool_name in tracked_tools_map:
                    tool_tracked += 1
                    entry = tracked_tools_map[tool_name]
                    status_str = entry["status"]
                    if status_str == "run":
                        tool_run += 1
                    findings_str = str(entry.get("findings_count", 0))
                    notes_str = entry["notes"][:80]
                else:
                    status_str = "not tracked"
                    findings_str = "-"
                    notes_str = ""

                lines.append(f"| {tool_name} | {phase_num} | {info['tier']} | " f"{status_str} | {findings_str} | {notes_str} |")

        tool_pct = (tool_tracked / tool_total * 100) if tool_total > 0 else 0
        lines.append("")
        lines.append(f"**Tool coverage: {tool_tracked}/{tool_total} tracked ({tool_pct:.0f}%), " f"{tool_run} run**")
        lines.append("")
    else:
        lines.extend(
            [
                "## Tool Coverage\n",
                "*No tool tracking data available. Tool tracking was not used during this engagement.*\n",
            ]
        )

    # Add exploitation queue results if any exist
    queue_files = list(EXPLOITATION_QUEUE_DIR.glob(f"{engagement_id}_*.json"))
    if queue_files:
        lines.extend(["## Exploitation Results\n"])
        for qf in sorted(queue_files):
            queue_data = _safe_read_json(qf, {})
            if queue_data:
                vc = queue_data.get("vuln_class", "Unknown")
                vulns = queue_data.get("vulnerabilities", [])
                total = len(vulns)
                exploited = sum(1 for v in vulns if v.get("exploitation_status") == "exploited")
                failed = sum(1 for v in vulns if v.get("exploitation_status") == "failed")
                pending = sum(1 for v in vulns if v.get("exploitation_status") == "pending")

                lines.append(f"### {vc.upper()}")
                lines.append(f"- Queued: {total} | Exploited: {exploited} | Failed: {failed} | Pending: {pending}")
                for v in vulns:
                    status = v.get("exploitation_status", "pending")
                    icon = {
                        "exploited": "✅",
                        "failed": "❌",
                        "pending": "⏳",
                        "deferred": "⏸️",
                    }.get(status, "?")
                    ep = v.get("endpoint", "")
                    param = v.get("parameter", "")
                    lines.append(f"  - {icon} **{v.get('id', '?')}** [{status}] {ep} (`{param}`)")
                lines.append("")

    # Add Final Judge review section if available
    judge_file = JUDGE_TRACKING_DIR / f"{engagement_id}.json"
    if judge_file.exists():
        judge_data = json.loads(judge_file.read_text(encoding="utf-8"))
        lines.extend(
            [
                "## Final Judge Review\n",
                f"- **Verdict**: {judge_data.get('verdict', 'N/A')}",
                f"- **Critical Actions Identified**: {judge_data.get('critical_actions', 0)}",
                f"- **Recommended Actions Identified**: {judge_data.get('recommended_actions', 0)}",
                f"- **Actions Taken**: {judge_data.get('actions_taken', 0)}",
                f"- **Notes**: {judge_data.get('notes', '')}",
                "",
            ]
        )

    report_content = "\n".join(lines)

    # Save the report
    engagement_dir = _engagement_path(engagement_id)
    engagement_dir.mkdir(parents=True, exist_ok=True)
    report_file = engagement_dir / "report.md"
    report_file.write_text(report_content, encoding="utf-8")
    _append_event(
        engagement_id,
        {
            "tool": "generate_report",
            "args": {"target": target},
            "result": f"Report saved to {report_file}",
        },
    )

    return f"Report generated at: {report_file}\n\n{report_content}"


# ── Source Code Analysis Tools ─────────────────────────────────────


@mcp.tool()
def start_code_analysis(engagement_id: str, repo_path: str) -> str:
    """Begin source code analysis for an engagement. Registers the repository
    path and returns instructions for performing security-focused code review.

    Call this BEFORE Phase 0 if the target application's source code is
    available locally. The analysis output feeds into endpoint mapping and
    informs vulnerability testing in all subsequent phases.

    Args:
        engagement_id: The engagement identifier
        repo_path: Absolute path to the local repository to analyze
    """
    CODE_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    analysis_file = CODE_ANALYSIS_DIR / f"{engagement_id}.json"

    data = {
        "status": "in_progress",
        "repo_path": repo_path,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _atomic_write_json(analysis_file, data)
    _append_event(
        engagement_id,
        {
            "tool": "start_code_analysis",
            "args": {"repo_path": repo_path},
            "result": "Code analysis started",
        },
    )

    # Load template instructions
    template_path = Path(__file__).parent.parent / "templates" / "source-code-analysis.md"
    instructions = ""
    if template_path.exists():
        instructions = template_path.read_text(encoding="utf-8")
    else:
        instructions = (
            "Template not found. Perform a security-focused code review covering:\n"
            "1. Architecture & Technology Stack\n"
            "2. Authentication & Authorization\n"
            "3. Data Security & Storage\n"
            "4. Attack Surface (entry points, API endpoints)\n"
            "5. XSS Sinks & Render Contexts\n"
            "6. SSRF Sinks\n"
            "7. Critical File Paths\n"
        )

    return f"Code analysis registered for: {repo_path}\n" f"Engagement: {engagement_id}\n\n" f"## Analysis Instructions\n\n{instructions}"


@mcp.tool()
def save_code_analysis(engagement_id: str, analysis: str) -> str:
    """Save the completed source code analysis for an engagement.
    The analysis is stored and available to all subsequent phases.

    Args:
        engagement_id: The engagement identifier
        analysis: The complete markdown analysis report
    """
    CODE_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    analysis_file = CODE_ANALYSIS_DIR / f"{engagement_id}.json"

    existing = _safe_read_json(analysis_file, {})
    existing.update(
        {
            "status": "completed",
            "analysis": analysis,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "word_count": len(analysis.split()),
        }
    )
    _atomic_write_json(analysis_file, existing)

    # Also save as markdown in the engagement directory
    engagement_dir = _engagement_path(engagement_id)
    engagement_dir.mkdir(parents=True, exist_ok=True)
    (engagement_dir / "code-analysis.md").write_text(analysis, encoding="utf-8")

    _append_event(
        engagement_id,
        {
            "tool": "save_code_analysis",
            "args": {"word_count": len(analysis.split())},
            "result": "Code analysis saved",
        },
    )

    return f"Code analysis saved ({len(analysis.split())} words).\n" f"Available via get_code_analysis('{engagement_id}').\n" f"Also saved to: engagements/runtime/{engagement_id}/code-analysis.md"


@mcp.tool()
def get_code_analysis(engagement_id: str) -> str:
    """Retrieve the source code analysis for an engagement.
    Returns the full analysis markdown if completed, or status if in progress.

    Args:
        engagement_id: The engagement identifier
    """
    analysis_file = CODE_ANALYSIS_DIR / f"{engagement_id}.json"
    if not analysis_file.exists():
        return f"No code analysis found for engagement '{engagement_id}'.\n" "Use start_code_analysis() to begin analysis."

    data = _safe_read_json(analysis_file, {})
    status = data.get("status", "unknown")

    if status == "completed":
        analysis = data.get("analysis", "")
        word_count = data.get("word_count", 0)
        return f"# Source Code Analysis ({word_count} words)\n\n{analysis}"
    elif status == "in_progress":
        repo_path = data.get("repo_path", "unknown")
        started_at = data.get("started_at", "unknown")
        return f"Code analysis in progress.\nRepo: {repo_path}\nStarted: {started_at}"
    else:
        return f"Code analysis status: {status}"


# ── Checkpoint/Resume Tools ───────────────────────────────────────


def _build_checkpoint_summary(engagement_id: str) -> dict:
    """Build a summary of current engagement state for checkpoint.

    Includes mid-phase granular state: which tests are done vs remaining
    for the current phase, so resume is precise even mid-phase.
    """
    findings = _get_findings_from_sqlite(engagement_id)
    tracking = _safe_read_json(TRACKING_DIR / f"{engagement_id}.json", [])
    tool_tracking = _safe_read_json(TOOL_TRACKING_DIR / f"{engagement_id}.json", [])
    gate_tracking = _safe_read_json(GATE_TRACKING_DIR / f"{engagement_id}.json", [])

    tests_completed = sum(1 for t in tracking if t.get("status") == "completed")
    tests_in_progress = sum(1 for t in tracking if t.get("status") == "in_progress")
    total_tests = len(tracking)
    coverage_pct = round(tests_completed / total_tests * 100) if total_tests > 0 else 0

    # Determine current phase and remaining tests
    passed_phases = sorted({g["phase"] for g in gate_tracking if g.get("result") in ("PASS", "FORCED_PASS")})
    next_phase = max(passed_phases) + 1 if passed_phases else 0

    tracked_test_ids = {t.get("test_id", "") for t in tracking}
    remaining_in_phase = []
    if next_phase in PHASE_TEST_REQUIREMENTS:
        reqs = PHASE_TEST_REQUIREMENTS[next_phase]
        all_phase_tests = reqs.get("must_tests", []) + reqs.get("should_tests", [])
        remaining_in_phase = [t for t in all_phase_tests if t not in tracked_test_ids]

    return {
        "finding_count": len(findings),
        "tests_tracked": total_tests,
        "tests_completed": tests_completed,
        "tests_in_progress": tests_in_progress,
        "tools_tracked": len(tool_tracking),
        "gates_passed": sum(1 for g in gate_tracking if g.get("result") in ("PASS", "FORCED_PASS")),
        "coverage_pct": coverage_pct,
        "current_phase": next_phase,
        "remaining_tests_in_phase": remaining_in_phase,
    }


def _auto_save_checkpoint(engagement_id: str, phase_completed: int) -> None:
    """Internal: auto-save checkpoint after phase gate passes."""
    CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_file = CHECKPOINTS_DIR / f"{engagement_id}.json"
    existing = _safe_read_json(checkpoint_file, {"checkpoints": []})

    checkpoints = existing.get("checkpoints", [])
    cp_id = f"cp-{len(checkpoints) + 1:03d}"

    checkpoints.append(
        {
            "id": cp_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": f"Phase {phase_completed} completed",
            "phase_completed": phase_completed,
            "summary": _build_checkpoint_summary(engagement_id),
        }
    )

    existing["checkpoints"] = checkpoints
    _atomic_write_json(checkpoint_file, existing)


@mcp.tool()
def save_checkpoint(engagement_id: str, description: str = "") -> str:
    """Save a checkpoint of the current engagement state.
    Checkpoints capture progress so an engagement can be resumed after interruption.

    Automatically called when phase_gate_check returns PASS, but can also be
    called manually at any time.

    Args:
        engagement_id: The engagement identifier
        description: Human-readable description (e.g., "Before Phase 4 exploitation")
    """
    CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_file = CHECKPOINTS_DIR / f"{engagement_id}.json"
    existing = _safe_read_json(checkpoint_file, {"checkpoints": []})

    checkpoints = existing.get("checkpoints", [])
    cp_id = f"cp-{len(checkpoints) + 1:03d}"

    checkpoints.append(
        {
            "id": cp_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": description or "Manual checkpoint",
            "phase_completed": None,
            "summary": _build_checkpoint_summary(engagement_id),
        }
    )

    existing["checkpoints"] = checkpoints
    _atomic_write_json(checkpoint_file, existing)
    _append_event(
        engagement_id,
        {
            "tool": "save_checkpoint",
            "args": {"description": description},
            "result": f"Saved {cp_id}",
        },
    )

    # Update resume prompt file on every checkpoint
    try:
        _write_resume_prompt_file(engagement_id)
    except Exception as e:
        logger.warning(f"Resume prompt update failed on checkpoint: {e}")

    summary = checkpoints[-1]["summary"]
    return (
        f"Checkpoint saved: {cp_id}\n"
        f"- Findings: {summary['finding_count']}\n"
        f"- Tests tracked: {summary['tests_tracked']} ({summary['coverage_pct']}% coverage)\n"
        f"- Tools tracked: {summary['tools_tracked']}\n"
        f"- Gates passed: {summary['gates_passed']}\n"
        f"- Resume prompt updated: engagements/runtime/{engagement_id}/resume-prompt.md"
    )


@mcp.tool()
def resume_engagement(engagement_id: str) -> str:
    """Resume an engagement from its latest checkpoint.
    Returns the checkpoint state so Swarm/Swarm can pick up where it left off.

    Args:
        engagement_id: The engagement identifier
    """
    checkpoint_file = CHECKPOINTS_DIR / f"{engagement_id}.json"
    if not checkpoint_file.exists():
        return f"No checkpoints found for engagement '{engagement_id}'.\n" "This engagement may not have reached any phase gates yet."

    data = _safe_read_json(checkpoint_file, {"checkpoints": []})
    checkpoints = data.get("checkpoints", [])
    if not checkpoints:
        return "Checkpoint file exists but contains no checkpoints."

    latest = checkpoints[-1]
    summary = latest.get("summary", {})
    phase = latest.get("phase_completed")

    # Determine next phase
    gate_data = _safe_read_json(GATE_TRACKING_DIR / f"{engagement_id}.json", [])
    passed_phases = sorted({g["phase"] for g in gate_data if g.get("result") in ("PASS", "FORCED_PASS")})
    next_phase = max(passed_phases) + 1 if passed_phases else 0

    # Get finding severity breakdown
    findings = _get_findings_from_sqlite(engagement_id)
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Check for code analysis
    code_analysis = _safe_read_json(CODE_ANALYSIS_DIR / f"{engagement_id}.json")
    has_code_analysis = code_analysis is not None and code_analysis.get("status") == "completed"

    lines = [
        f"# Resume Engagement: {engagement_id}\n",
        f"## Latest Checkpoint: {latest['id']}",
        f"- Saved: {latest.get('timestamp', '?')[:19]}",
        f"- Description: {latest.get('description', 'N/A')}",
        f"- Phase completed: {phase if phase is not None else 'N/A'}",
        "",
        "## Resume Point",
        f"- **Next phase to execute: Phase {next_phase}**",
        f"- Phases completed: {', '.join(str(p) for p in passed_phases) if passed_phases else 'None'}",
        f"- Code analysis: {'Available' if has_code_analysis else 'Not performed'}",
        "",
        "## Current State",
        f"- Findings: {summary.get('finding_count', 0)}",
    ]

    if severity_counts:
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            if sev in severity_counts:
                lines.append(f"  - {sev}: {severity_counts[sev]}")

    lines.extend(
        [
            f"- Tests tracked: {summary.get('tests_tracked', 0)} ({summary.get('coverage_pct', 0)}% coverage)",
            f"- Tools tracked: {summary.get('tools_tracked', 0)}",
            f"- Gates passed: {summary.get('gates_passed', 0)}",
            "",
            "## Instructions",
            f"Continue with Phase {next_phase}. All tracking data, findings, and scope are intact.",
            "Call get_coverage() and get_tool_coverage() to review current state before proceeding.",
        ]
    )

    # Include mid-phase remaining tests if available
    remaining = summary.get("remaining_tests_in_phase", [])
    if remaining:
        lines.extend(
            [
                "",
                f"## Remaining Tests (Phase {next_phase})",
                f"These tests have NOT been tracked yet: {', '.join(remaining)}",
            ]
        )

    in_prog = summary.get("tests_in_progress", 0)
    if in_prog:
        lines.append(f"\n**{in_prog} test(s) were in-progress** when interrupted — check and complete them.")

    # Reference resume-prompt.md
    resume_file = _engagement_path(engagement_id) / "resume-prompt.md"
    if resume_file.exists():
        lines.extend(
            [
                "",
                "## Full Resume Prompt",
                "A detailed resume prompt with auth credentials and rules is at:",
                f"  `engagements/runtime/{engagement_id}/resume-prompt.md`",
                "Read it for the complete context needed to continue.",
            ]
        )

    # Update the resume prompt file
    try:
        _write_resume_prompt_file(engagement_id)
    except Exception:
        logger.debug("Failed to write resume prompt file (non-critical)", exc_info=True)

    _append_event(
        engagement_id,
        {
            "tool": "resume_engagement",
            "args": {},
            "result": f"Resumed from {latest['id']}, next phase: {next_phase}",
        },
    )

    return "\n".join(lines)


def _generate_resume_prompt_content(engagement_id: str) -> str:
    """Internal: build a complete, self-contained resume prompt.

    This prompt contains everything a fresh Swarm session needs
    to continue the pentest automatically — target, auth, phase state,
    remaining tests, endpoint map, and rules.
    """
    # ── Gather all engagement data ──
    findings = _get_findings_from_sqlite(engagement_id)
    tracking = _safe_read_json(TRACKING_DIR / f"{engagement_id}.json", [])
    tool_tracking = _safe_read_json(TOOL_TRACKING_DIR / f"{engagement_id}.json", [])
    gate_tracking = _safe_read_json(GATE_TRACKING_DIR / f"{engagement_id}.json", [])
    config = _safe_read_json(CONFIG_DIR / f"{engagement_id}.json")
    scope = _safe_read_json(SCOPE_DIR / f"{engagement_id}.json", [])
    code_analysis = _safe_read_json(CODE_ANALYSIS_DIR / f"{engagement_id}.json")

    # ── Determine current phase ──
    passed_phases = sorted({g["phase"] for g in gate_tracking if g.get("result") in ("PASS", "FORCED_PASS")})
    next_phase = max(passed_phases) + 1 if passed_phases else 0

    phase_names = {
        0: "Application Discovery & Mapping",
        1: "Information Gathering & Reconnaissance",
        2: "Configuration & Deployment Testing",
        3: "Identity, Authentication, Authorization & Session",
        4: "Input Validation Testing",
        5: "Error Handling, Crypto, Business Logic, Client-Side & API",
        6: "Coverage Verification & Reporting",
        7: "Final Judge Review & Remediation",
    }

    # ── Build tracked test index ──
    tracked_test_ids = set()
    tracked_test_statuses = {}
    for t in tracking:
        tid = t.get("test_id", "")
        tracked_test_ids.add(tid)
        tracked_test_statuses[tid] = t.get("status", "unknown")

    # ── Identify remaining tests for current phase ──
    remaining_tests = []
    if next_phase in PHASE_TEST_REQUIREMENTS:
        reqs = PHASE_TEST_REQUIREMENTS[next_phase]
        all_phase_tests = reqs.get("must_tests", []) + reqs.get("should_tests", [])
        remaining_tests = [t for t in all_phase_tests if t not in tracked_test_ids]

    # ── Also list in-progress tests (started but not finished) ──
    in_progress_tests = [tid for tid, status in tracked_test_statuses.items() if status == "in_progress"]

    # ── Remaining tools for current phase ──
    tracked_tool_names = {t.get("tool_name", "").lower() for t in tool_tracking}
    remaining_tools = []
    if next_phase in PHASE_TOOL_REQUIREMENTS:
        phase_tools = PHASE_TOOL_REQUIREMENTS[next_phase]
        for tool in phase_tools.get("mandatory", []):
            if tool.lower() not in tracked_tool_names:
                remaining_tools.append(f"{tool} (mandatory)")
        for tool in phase_tools.get("conditional", []):
            if tool.lower() not in tracked_tool_names:
                remaining_tools.append(f"{tool} (conditional)")

    # ── Severity breakdown ──
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # ── Coverage stats ──
    tests_completed = sum(1 for t in tracking if t.get("status") == "completed")
    tests_total = len(tracking)
    coverage_pct = round(tests_completed / tests_total * 100) if tests_total > 0 else 0

    tools_run = sum(1 for t in tool_tracking if t.get("status") == "run")

    # ── Config: target + auth ──
    target_url = "UNKNOWN"
    auth_section = ""
    if config:
        target = config.get("target", {})
        target_url = target.get("url", "UNKNOWN")

        auth = config.get("authentication", {})
        login_type = auth.get("login_type", "none")
        if login_type != "none":
            auth_lines = [f"- Login type: {login_type}"]
            if auth.get("login_url"):
                auth_lines.append(f"- Login URL: {auth['login_url']}")
            creds = auth.get("credentials", {})
            if creds:
                auth_lines.append(f"- Username: {creds.get('username', 'N/A')}")
                pw = creds.get("password", "")
                auth_lines.append(f"- Password: {pw}")
            sso = auth.get("sso", {})
            if sso:
                auth_lines.append(f"- SSO Provider: {sso.get('provider', 'N/A')}")
                auth_lines.append(f"- Auth Domain: {sso.get('auth_domain', 'N/A')}")
                if sso.get("realm"):
                    auth_lines.append(f"- Realm: {sso['realm']}")
                if sso.get("client_id"):
                    auth_lines.append(f"- Client ID: {sso['client_id']}")
            auth_section = "\n".join(auth_lines)

    # ── Scope domains ──
    scope_lines = []
    for s in scope:
        domain = s.get("domain", "?")
        dtype = s.get("domain_type", "?")
        scope_lines.append(f"- {domain} ({dtype})")

    # ── Cookie jar status ──
    cookie_jar_path = _engagement_path(engagement_id) / "cookies.txt"
    cookie_jar_exists = cookie_jar_path.exists()

    # ── Endpoint map deliverable ──
    endpoint_map_available = False
    endpoint_map_path = DELIVERABLES_DIR / f"{engagement_id}_endpoint_map.json"
    if endpoint_map_path.exists():
        endpoint_map_available = True

    # ── Exploitation queues ──
    queue_files = list(EXPLOITATION_QUEUE_DIR.glob(f"{engagement_id}_*.json"))
    queue_summary = []
    for qf in sorted(queue_files):
        qdata = _safe_read_json(qf, {})
        vc = qdata.get("vuln_class", "?")
        vulns = qdata.get("vulnerabilities", [])
        exploited = sum(1 for v in vulns if v.get("exploitation_status") == "exploited")
        pending = sum(1 for v in vulns if v.get("exploitation_status") in (None, "pending", ""))
        queue_summary.append(f"- {vc.upper()}: {len(vulns)} total, {exploited} exploited, {pending} pending")

    # ── Rules ──
    rules_section = ""
    if config:
        rules = config.get("rules", {})
        avoid = rules.get("avoid", [])
        focus = rules.get("focus", [])
        if avoid or focus:
            rules_lines = []
            if avoid:
                rules_lines.append("**Avoid rules (DO NOT test):**")
                for r in avoid:
                    rules_lines.append(f"- [{r.get('type', '?')}] {r.get('url_path', '')} — {r.get('description', '')}")
            if focus:
                rules_lines.append("**Focus rules (PRIORITIZE):**")
                for r in focus:
                    rules_lines.append(f"- [{r.get('type', '?')}] {r.get('url_path', '')} — {r.get('description', '')}")
            rules_section = "\n".join(rules_lines)

    # ── Assemble the resume prompt ──
    prompt_lines = [
        f"Resume pentest engagement `{engagement_id}` targeting **{target_url}**.",
        "",
        "This pentest was interrupted. All tracking data, findings, and scope are preserved. " "Continue exactly where it left off.",
        "",
        "## Current State",
        f"- **Next phase: Phase {next_phase}** — {phase_names.get(next_phase, 'Unknown')}",
        f"- Phases completed: {', '.join(str(p) for p in passed_phases) if passed_phases else 'None'}",
        f"- Findings: {len(findings)} ({_fmt_severity_counts(severity_counts) if severity_counts else 'none'})",
        f"- Test coverage: {coverage_pct}% ({tests_completed}/{tests_total} tests tracked)",
        f"- Tools run: {tools_run}",
        f"- Code analysis: {'Completed' if code_analysis and code_analysis.get('status') == 'completed' else 'Not performed'}",
    ]

    if scope_lines:
        prompt_lines.extend(["", "## Scope Domains"] + scope_lines)

    if auth_section:
        prompt_lines.extend(["", "## Authentication", auth_section])

    if cookie_jar_exists:
        prompt_lines.extend(
            [
                "",
                "## Session",
                f"- Cookie jar: `./engagements/runtime/{engagement_id}/cookies.txt` (exists — may be expired, re-authenticate if needed)",
            ]
        )

    if rules_section:
        prompt_lines.extend(["", "## Rules", rules_section])

    # ── Remaining work (most important section) ──
    prompt_lines.extend(["", "## Remaining Work"])

    if in_progress_tests:
        prompt_lines.append(f"\n**Tests in progress (started but not finished):** {', '.join(in_progress_tests)}")

    if remaining_tests:
        phase_reqs = PHASE_TEST_REQUIREMENTS.get(next_phase, {})
        must_remaining = [t for t in remaining_tests if t in phase_reqs.get("must_tests", [])]
        should_remaining = [t for t in remaining_tests if t in phase_reqs.get("should_tests", [])]
        prompt_lines.append(f"\n**Remaining tests for Phase {next_phase}:**")
        if must_remaining:
            prompt_lines.append(f"- MUST: {', '.join(must_remaining)}")
        if should_remaining:
            prompt_lines.append(f"- SHOULD: {', '.join(should_remaining)}")
    elif next_phase > 5:
        prompt_lines.append(f"\nPhase {next_phase} — follow the Phase {next_phase} procedure in CLAUDE.md.")
    else:
        prompt_lines.append(f"\nAll tests for Phase {next_phase - 1} are tracked. Begin Phase {next_phase}.")

    if remaining_tools:
        prompt_lines.append(f"\n**Remaining tools for Phase {next_phase}:** {', '.join(remaining_tools)}")

    if queue_summary:
        prompt_lines.extend(["\n**Exploitation queues:**"] + queue_summary)

    if endpoint_map_available:
        prompt_lines.append(f"\n**Endpoint map available** — " f"call `get_deliverable('{engagement_id}', 'endpoint_map')` to load it.")

    # ── Instructions ──
    prompt_lines.extend(
        [
            "",
            "## Instructions",
            "",
            f"1. Call `resume_engagement('{engagement_id}')` to confirm state",
            f"2. Call `get_coverage('{engagement_id}')` and `get_tool_coverage('{engagement_id}')` to review progress",
        ]
    )

    if config:
        prompt_lines.append(f"3. Call `get_engagement_config('{engagement_id}')` to load target and auth details")
        prompt_lines.append(f"4. Call `get_engagement_rules('{engagement_id}')` to load avoid/focus rules")
        prompt_lines.append(f"5. Continue with Phase {next_phase} following CLAUDE.md procedures")
    else:
        prompt_lines.append(f"3. Continue with Phase {next_phase} following CLAUDE.md procedures")

    if cookie_jar_exists:
        prompt_lines.append("\n**Re-authenticate first** — the cookie jar may have expired. " "Test with a simple authenticated request before proceeding.")

    return "\n".join(prompt_lines)


def _write_resume_prompt_file(engagement_id: str) -> None:
    """Write the resume prompt to engagements/runtime/<eid>/resume-prompt.md.

    Called automatically on every checkpoint and phase gate pass.
    The user can paste this file's contents into a new Swarm session
    to continue the pentest automatically.
    """
    try:
        eng_dir = _engagement_path(engagement_id)
        eng_dir.mkdir(parents=True, exist_ok=True)
        prompt_content = _generate_resume_prompt_content(engagement_id)
        resume_file = eng_dir / "resume-prompt.md"
        resume_file.write_text(prompt_content, encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to write resume prompt for {engagement_id}: {e}")


@mcp.tool()
def generate_resume_prompt(engagement_id: str) -> str:
    """Generate a complete, self-contained resume prompt for an interrupted engagement.

    Returns a ready-to-paste prompt that contains everything a fresh Swarm
    session needs to continue the pentest: target URL, auth credentials, current
    phase, remaining tests, endpoint map references, and rules.

    Also writes the prompt to engagements/runtime/<eid>/resume-prompt.md so it survives
    session crashes. The user can copy-paste it into a new session.

    Call this manually at any time, or it runs automatically on every checkpoint
    and phase gate pass.

    Args:
        engagement_id: The engagement identifier
    """
    prompt = _generate_resume_prompt_content(engagement_id)

    # Write to file
    _write_resume_prompt_file(engagement_id)

    _append_event(
        engagement_id,
        {
            "tool": "generate_resume_prompt",
            "args": {},
            "result": f"Resume prompt generated and saved to engagements/runtime/{engagement_id}/resume-prompt.md",
        },
    )

    eng_dir = _engagement_path(engagement_id)
    return f"Resume prompt generated and saved to:\n" f"  `{eng_dir / 'resume-prompt.md'}`\n\n" f"To continue this pentest in a new session, paste the following:\n\n" f"---\n\n{prompt}\n\n---"


@mcp.tool()
def list_checkpoints(engagement_id: str) -> str:
    """List all saved checkpoints for an engagement.

    Args:
        engagement_id: The engagement identifier
    """
    checkpoint_file = CHECKPOINTS_DIR / f"{engagement_id}.json"
    if not checkpoint_file.exists():
        return f"No checkpoints found for engagement '{engagement_id}'."

    data = _safe_read_json(checkpoint_file, {"checkpoints": []})
    checkpoints = data.get("checkpoints", [])
    if not checkpoints:
        return "Checkpoint file exists but contains no checkpoints."

    lines = [f"# Checkpoints: {engagement_id} ({len(checkpoints)} total)\n"]
    lines.append("| ID | Timestamp | Phase | Description | Findings | Coverage |")
    lines.append("|-----|-----------|-------|-------------|----------|----------|")

    for cp in checkpoints:
        ts = cp.get("timestamp", "?")[:19]
        phase = cp.get("phase_completed", "—")
        desc = cp.get("description", "")[:40]
        summary = cp.get("summary", {})
        findings = summary.get("finding_count", 0)
        coverage = f"{summary.get('coverage_pct', 0)}%"
        lines.append(f"| {cp['id']} | {ts} | {phase} | {desc} | {findings} | {coverage} |")

    return "\n".join(lines)


# ── Exploitation Queue Tools ──────────────────────────────────────

VALID_VULN_CLASSES = {
    "xss",
    "sqli",
    "cmdi",
    "ssti",
    "ssrf",
    "idor",
    "path_traversal",
    "auth",
}


@mcp.tool()
def create_exploitation_queue(
    engagement_id: str,
    vuln_class: str,
    vulnerabilities: str,
) -> str:
    """Create a structured exploitation queue for a vulnerability class.
    After discovering vulnerabilities, create a queue so exploitation can be
    performed systematically from the structured data.

    Args:
        engagement_id: The engagement identifier
        vuln_class: Vulnerability class: xss, sqli, cmdi, ssti, ssrf, idor, path_traversal, auth
        vulnerabilities: JSON string of vulnerability list. Each entry must have:
            id, type, endpoint, parameter, evidence, payload_example, confidence (high/medium/low), severity
    """
    vuln_class = vuln_class.lower().strip()
    if vuln_class not in VALID_VULN_CLASSES:
        return f"Invalid vuln_class '{vuln_class}'. Must be one of: {', '.join(sorted(VALID_VULN_CLASSES))}"

    try:
        vuln_list = json.loads(vulnerabilities)
    except json.JSONDecodeError as e:
        return f"Invalid JSON in vulnerabilities: {e}"

    if not isinstance(vuln_list, list):
        return "vulnerabilities must be a JSON array of objects."

    # Validate required fields
    required_fields = {"id", "type", "endpoint", "parameter", "confidence", "severity"}
    for i, v in enumerate(vuln_list):
        if not isinstance(v, dict):
            return f"Entry {i} is not an object."
        missing = required_fields - set(v.keys())
        if missing:
            return f"Entry {i} ('{v.get('id', '?')}') missing fields: {', '.join(sorted(missing))}"
        if v.get("confidence") not in ("high", "medium", "low"):
            return f"Entry {i}: confidence must be high, medium, or low."
        # Add default exploitation status
        v.setdefault("exploitation_status", "pending")
        v.setdefault("exploitation_result", None)
        v.setdefault("exploitation_evidence", None)

    EXPLOITATION_QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    queue_file = EXPLOITATION_QUEUE_DIR / f"{engagement_id}_{vuln_class}.json"

    # ── Merge mode: if queue already exists, append new entries ──
    if queue_file.exists():
        existing_data = _safe_read_json(queue_file, {})
        existing_vulns = existing_data.get("vulnerabilities", [])
        if existing_vulns:
            # Deduplicate by endpoint + parameter
            existing_keys = {(v.get("endpoint", ""), v.get("parameter", "")) for v in existing_vulns}
            # Find max existing ID number for auto-increment
            max_num = 0
            prefix = vuln_class.upper() + "-"
            for v in existing_vulns:
                vid = v.get("id", "")
                if vid.startswith(prefix):
                    try:
                        num = int(vid[len(prefix) :])
                        max_num = max(max_num, num)
                    except ValueError:
                        pass
            # Append non-duplicate entries with renumbered IDs
            new_entries = []
            for v in vuln_list:
                key = (v.get("endpoint", ""), v.get("parameter", ""))
                if key not in existing_keys:
                    max_num += 1
                    v["id"] = f"{prefix}{max_num:03d}"
                    new_entries.append(v)
                    existing_keys.add(key)

            if new_entries:
                existing_vulns.extend(new_entries)
                existing_data["vulnerabilities"] = existing_vulns
                existing_data["updated_at"] = datetime.now(timezone.utc).isoformat()
                _atomic_write_json(queue_file, existing_data)

                _append_event(
                    engagement_id,
                    {
                        "tool": "create_exploitation_queue",
                        "args": {
                            "vuln_class": vuln_class,
                            "count": len(new_entries),
                            "mode": "merge",
                        },
                        "result": f"Merged {len(new_entries)} new entries (total: {len(existing_vulns)})",
                    },
                )

                return (
                    f"Exploitation queue merged: {vuln_class}\n"
                    f"- New entries appended: {len(new_entries)}\n"
                    f"- Duplicates skipped: {len(vuln_list) - len(new_entries)}\n"
                    f"- Total entries: {len(existing_vulns)}\n"
                    f"- File: {queue_file}\n"
                    f"Use get_exploitation_queue('{engagement_id}', '{vuln_class}') to review."
                )
            else:
                return f"Exploitation queue unchanged: {vuln_class}\n" f"All {len(vuln_list)} entries already exist in the queue " f"(matched by endpoint + parameter).\n" f"Total entries: {len(existing_vulns)}"

    # ── Create mode: new queue ──
    queue_data = {
        "engagement_id": engagement_id,
        "vuln_class": vuln_class,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": vuln_list,
    }
    _atomic_write_json(queue_file, queue_data)
    _append_event(
        engagement_id,
        {
            "tool": "create_exploitation_queue",
            "args": {"vuln_class": vuln_class, "count": len(vuln_list)},
            "result": f"Queue created with {len(vuln_list)} entries",
        },
    )

    return (
        f"Exploitation queue created: {vuln_class}\n"
        f"- Entries: {len(vuln_list)}\n"
        f"- File: {queue_file}\n"
        f"Use get_exploitation_queue('{engagement_id}', '{vuln_class}') to review.\n"
        f"Use mark_exploited() to update entries after exploitation attempts."
    )


@mcp.tool()
def get_exploitation_queue(engagement_id: str, vuln_class: str) -> str:
    """Retrieve the exploitation queue for a vulnerability class.

    Args:
        engagement_id: The engagement identifier
        vuln_class: Vulnerability class: xss, sqli, cmdi, ssti, ssrf, idor, path_traversal, auth
    """
    vuln_class = vuln_class.lower().strip()
    queue_file = EXPLOITATION_QUEUE_DIR / f"{engagement_id}_{vuln_class}.json"
    if not queue_file.exists():
        return f"No exploitation queue found for '{vuln_class}' in engagement '{engagement_id}'."

    data = _safe_read_json(queue_file, {})
    vulns = data.get("vulnerabilities", [])

    if not vulns:
        return f"Exploitation queue for '{vuln_class}' is empty (no vulnerabilities found)."

    pending = sum(1 for v in vulns if v.get("exploitation_status") == "pending")
    exploited = sum(1 for v in vulns if v.get("exploitation_status") == "exploited")
    failed = sum(1 for v in vulns if v.get("exploitation_status") == "failed")

    lines = [
        f"# Exploitation Queue: {vuln_class.upper()}",
        f"Total: {len(vulns)} | Pending: {pending} | Exploited: {exploited} | Failed: {failed}\n",
    ]

    for v in vulns:
        status_icon = {
            "pending": "⏳",
            "exploited": "✅",
            "failed": "❌",
            "deferred": "⏸️",
        }.get(v.get("exploitation_status", "pending"), "?")
        lines.append(f"### {status_icon} {v['id']} — {v['type']} [{v.get('severity', '?')}]")
        lines.append(f"- **Endpoint**: {v.get('endpoint', '?')}")
        lines.append(f"- **Parameter**: {v.get('parameter', '?')}")
        lines.append(f"- **Confidence**: {v.get('confidence', '?')}")
        if v.get("evidence"):
            lines.append(f"- **Evidence**: {v['evidence'][:200]}")
        if v.get("payload_example"):
            lines.append(f"- **Payload**: `{v['payload_example'][:100]}`")
        if v.get("exploitation_evidence"):
            lines.append(f"- **Exploitation Evidence**: {v['exploitation_evidence'][:200]}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def mark_exploited(
    engagement_id: str,
    vuln_class: str,
    vuln_id: str,
    result: str,
    evidence: str = "",
    techniques_attempted: str = "",
    bypass_attempts: int = 0,
) -> str:
    """Mark a vulnerability in the exploitation queue as exploited, potential, failed, or false_positive.

    Three-tier classification:
    - **exploited**: Reproducible impact demonstrated (Level 3+ proof). Goes in the report.
    - **potential**: Vulnerability exists but blocked by security control after exhaustive
      bypass testing. Goes in the report as lower severity.
    - **false_positive**: Blocking mechanism IS a security feature that withstands
      bypass. Logged separately, NOT in the main report.
    - **failed**: Could not confirm vulnerability exists (inconclusive). NOT in the report.
    - **deferred**: Postponed for later testing.

    For 'failed' and 'false_positive' results, exhaustion thresholds are enforced.

    Args:
        engagement_id: The engagement identifier
        vuln_class: Vulnerability class: xss, sqli, cmdi, ssti, ssrf, idor, path_traversal, auth
        vuln_id: The vulnerability ID from the queue (e.g., XSS-001)
        result: One of: exploited, potential, failed, false_positive, deferred
        evidence: Exploitation evidence (request/response) if exploited, or failure documentation if failed
        techniques_attempted: Comma-separated list of techniques tried (e.g., "error-based, boolean blind, time-based")
        bypass_attempts: Number of bypass/encoding variations tried (e.g., 8)
    """
    valid_results = {"exploited", "potential", "failed", "false_positive", "deferred"}
    if result not in valid_results:
        return f"Invalid result '{result}'. Must be one of: {', '.join(sorted(valid_results))}"

    vuln_class = vuln_class.lower().strip()
    queue_file = EXPLOITATION_QUEUE_DIR / f"{engagement_id}_{vuln_class}.json"
    if not queue_file.exists():
        return f"No exploitation queue found for '{vuln_class}' in engagement '{engagement_id}'."

    data = _safe_read_json(queue_file, {})
    vulns = data.get("vulnerabilities", [])

    target = None
    for v in vulns:
        if v["id"] == vuln_id:
            target = v
            break

    if not target:
        known_ids = [v["id"] for v in vulns]
        return f"Vulnerability '{vuln_id}' not found. Known IDs: {', '.join(known_ids)}"

    # Exhaustion-based classification gate for "failed" and "false_positive" results
    warnings = []
    if result in ("failed", "false_positive"):
        threshold = EXHAUSTION_THRESHOLDS.get(vuln_class)
        if threshold:
            techniques_list = [t.strip() for t in techniques_attempted.split(",") if t.strip()] if techniques_attempted else []
            min_tech = threshold["min_techniques"]
            min_bypass = threshold["min_bypass_attempts"]

            if len(techniques_list) < min_tech:
                warnings.append(f"EXHAUSTION WARNING: Only {len(techniques_list)} technique(s) attempted " f"(minimum {min_tech} required for '{vuln_class}'). " f"Expected: {threshold['description']}")
            if bypass_attempts < min_bypass:
                warnings.append(
                    f"EXHAUSTION WARNING: Only {bypass_attempts} bypass attempt(s) "
                    f"(minimum {min_bypass} required for '{vuln_class}'). "
                    f"Try more encoding/filter bypass variants before classifying as failed."
                )
            if not evidence:
                warnings.append("EXHAUSTION WARNING: No failure evidence provided. " "Document what you tried and why it failed (error messages, WAF responses, encoding behavior).")

    target["exploitation_status"] = result
    target["exploitation_result"] = result
    target["exploitation_evidence"] = evidence
    target["exploitation_timestamp"] = datetime.now(timezone.utc).isoformat()
    if techniques_attempted:
        target["techniques_attempted"] = techniques_attempted
    if bypass_attempts:
        target["bypass_attempts"] = bypass_attempts

    _atomic_write_json(queue_file, data)
    _append_event(
        engagement_id,
        {
            "tool": "mark_exploited",
            "args": {
                "vuln_class": vuln_class,
                "vuln_id": vuln_id,
                "result": result,
                "techniques": techniques_attempted,
                "bypasses": bypass_attempts,
            },
            "result": f"{vuln_id}: {result}" + (f" ({len(warnings)} warnings)" if warnings else ""),
        },
    )

    output = f"Vulnerability {vuln_id} marked as: {result}"
    if warnings:
        output += "\n\n" + "\n".join(warnings)
        output += "\n\nThe classification has been recorded but these warnings indicate insufficient effort. " "Consider attempting more techniques before finalizing."
    return output


@mcp.tool()
def validate_exploitation_queue(
    engagement_id: str,
    vuln_class: str,
) -> str:
    """Validate an exploitation queue before exploitation begins.
    Checks for completeness, evidence quality, and confidence levels.
    Returns PASS or FAIL with specific issues to address.

    Args:
        engagement_id: The engagement identifier
        vuln_class: Vulnerability class: xss, sqli, cmdi, ssti, ssrf, idor, path_traversal, auth
    """
    vuln_class = vuln_class.lower().strip()
    if vuln_class not in VALID_VULN_CLASSES:
        return f"Invalid vuln_class '{vuln_class}'. Must be one of: {', '.join(sorted(VALID_VULN_CLASSES))}"

    queue_file = EXPLOITATION_QUEUE_DIR / f"{engagement_id}_{vuln_class}.json"
    if not queue_file.exists():
        return f"FAIL: No exploitation queue found for '{vuln_class}' in engagement '{engagement_id}'.\n" f"Create one first with create_exploitation_queue()."

    data = _safe_read_json(queue_file, {})
    vulns = data.get("vulnerabilities", [])

    if not vulns:
        _append_event(
            engagement_id,
            {
                "tool": "validate_exploitation_queue",
                "args": {"vuln_class": vuln_class},
                "result": "PASS (empty queue — no exploitation needed)",
            },
        )
        return f"# Queue Validation: {vuln_class.upper()}\n" f"## Result: PASS (empty queue)\n\n" f"Queue has 0 entries — no exploitation needed for this class."

    # Validate entries
    warnings = []
    errors = []
    required_fields = {"id", "type", "endpoint", "parameter", "confidence", "severity"}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    seen_pairs = {}  # endpoint+parameter -> list of IDs

    for i, v in enumerate(vulns):
        vid = v.get("id", f"entry-{i}")

        # Check required fields
        if not isinstance(v, dict):
            errors.append(f"{vid}: Entry is not a mapping")
            continue
        missing = required_fields - set(v.keys())
        if missing:
            errors.append(f"{vid}: Missing required fields: {', '.join(sorted(missing))}")

        # Count confidence levels
        conf = v.get("confidence", "")
        if conf in confidence_counts:
            confidence_counts[conf] += 1

        # Check evidence quality
        if not v.get("evidence"):
            warnings.append(f"{vid}: Empty 'evidence' field — exploitation may lack context")
        if not v.get("payload_example"):
            warnings.append(f"{vid}: Empty 'payload_example' — no starting payload for exploitation")

        # Check for duplicates
        pair_key = f"{v.get('endpoint', '')}||{v.get('parameter', '')}"
        if pair_key in seen_pairs:
            warnings.append(f"{vid}: Duplicate endpoint+parameter with {seen_pairs[pair_key]} " f"— consider consolidating")
        else:
            seen_pairs[pair_key] = vid

        # Check severity/confidence mismatch
        sev = v.get("severity", "")
        if sev == "Critical" and conf == "low":
            warnings.append(f"{vid}: Critical severity with low confidence — verify before exploitation")
        if sev == "Informational" and conf == "high":
            warnings.append(f"{vid}: High confidence but Informational severity — consider upgrading")

    # Determine result
    if errors:
        result = "FAIL"
    else:
        result = "PASS"

    qualifier = ""
    if warnings:
        qualifier = f" ({len(warnings)} warning{'s' if len(warnings) != 1 else ''})"

    lines = [
        f"# Queue Validation: {vuln_class.upper()}",
        f"## Result: {result}{qualifier}\n",
        f"### Entries: {len(vulns)}",
        f"- High confidence: {confidence_counts['high']}",
        f"- Medium confidence: {confidence_counts['medium']}",
        f"- Low confidence: {confidence_counts['low']}",
    ]

    if errors:
        lines.extend(["", f"### Errors ({len(errors)}) — must fix before exploitation"])
        for j, e in enumerate(errors, 1):
            lines.append(f"{j}. {e}")

    if warnings:
        lines.extend(["", f"### Warnings ({len(warnings)})"])
        for j, w in enumerate(warnings, 1):
            lines.append(f"{j}. {w}")

    if not errors:
        pending = sum(1 for v in vulns if v.get("exploitation_status") == "pending")
        lines.extend(
            [
                "",
                "### Ready for Exploitation",
                f"Proceed with {pending} pending entries. " f"Use get_exploitation_queue() to review, then mark_exploited() for each attempt.",
            ]
        )

    _append_event(
        engagement_id,
        {
            "tool": "validate_exploitation_queue",
            "args": {"vuln_class": vuln_class},
            "result": f"{result}: {len(vulns)} entries, {len(errors)} errors, {len(warnings)} warnings",
        },
    )

    return "\n".join(lines)


# ── Deliverable Tools ────────────────────────────────────────────


@mcp.tool()
def save_deliverable(
    engagement_id: str,
    deliverable_type: str,
    content: str,
    producer_agent: str = "",
) -> str:
    """Save a structured deliverable for inter-agent communication.
    Analysis agents save deliverables that exploitation agents consume.

    Args:
        engagement_id: The engagement identifier
        deliverable_type: One of: endpoint_map, test_matrix, xss_analysis, sqli_analysis,
            cmdi_analysis, ssrf_ssti_analysis, auth_analysis, code_review_findings, tool_results
        content: The deliverable content (markdown or structured text)
        producer_agent: Name/ID of the agent that produced this (e.g., 'xss-analyzer')
    """
    deliverable_type = deliverable_type.lower().strip()
    if deliverable_type not in DELIVERABLE_TYPES:
        valid = ", ".join(sorted(DELIVERABLE_TYPES.keys()))
        return f"Invalid deliverable_type '{deliverable_type}'. Must be one of: {valid}"

    if not content or not content.strip():
        return "Content cannot be empty."

    DELIVERABLES_DIR.mkdir(parents=True, exist_ok=True)
    deliverable_file = DELIVERABLES_DIR / f"{engagement_id}_{deliverable_type}.json"

    word_count = len(content.split())
    deliverable_data = {
        "engagement_id": engagement_id,
        "deliverable_type": deliverable_type,
        "producer_agent": producer_agent,
        "content": content,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "word_count": word_count,
    }
    _atomic_write_json(deliverable_file, deliverable_data)

    _append_event(
        engagement_id,
        {
            "tool": "save_deliverable",
            "args": {"deliverable_type": deliverable_type, "producer": producer_agent},
            "result": f"Saved {deliverable_type} ({word_count} words)",
        },
    )

    type_info = DELIVERABLE_TYPES[deliverable_type]
    return (
        f"Deliverable saved: {deliverable_type}\n"
        f"- Words: {word_count}\n"
        f"- Producer: {producer_agent or 'not specified'}\n"
        f"- Consumed by: {type_info['consumed_by']}\n\n"
        f"Exploitation/downstream agents can retrieve this with:\n"
        f"  get_deliverable('{engagement_id}', '{deliverable_type}')"
    )


@mcp.tool()
def get_deliverable(
    engagement_id: str,
    deliverable_type: str,
) -> str:
    """Retrieve a saved deliverable for inter-agent communication.
    Exploitation agents call this to consume analysis results.

    Args:
        engagement_id: The engagement identifier
        deliverable_type: The type of deliverable to retrieve
    """
    deliverable_type = deliverable_type.lower().strip()
    deliverable_file = DELIVERABLES_DIR / f"{engagement_id}_{deliverable_type}.json"

    if not deliverable_file.exists():
        # List what's available
        available = []
        if DELIVERABLES_DIR.exists():
            prefix = f"{engagement_id}_"
            for f in DELIVERABLES_DIR.glob(f"{prefix}*.json"):
                dtype = f.stem[len(prefix) :]
                available.append(dtype)

        if available:
            return f"Deliverable '{deliverable_type}' not found for engagement '{engagement_id}'.\n" f"Available deliverables: {', '.join(sorted(available))}"
        return f"No deliverables found for engagement '{engagement_id}'.\n" f"Analysis agents must save deliverables first with save_deliverable()."

    data = _safe_read_json(deliverable_file, {})
    content = data.get("content", "")
    producer = data.get("producer_agent", "unknown")
    saved_at = data.get("saved_at", "?")[:19]
    word_count = data.get("word_count", 0)

    header = f"# Deliverable: {deliverable_type}\n" f"Producer: {producer} | Saved: {saved_at} | Words: {word_count}\n\n---\n\n"
    return header + content


@mcp.tool()
def list_deliverables(engagement_id: str) -> str:
    """List all saved deliverables for an engagement.

    Args:
        engagement_id: The engagement identifier
    """
    if not DELIVERABLES_DIR.exists():
        return f"No deliverables found for engagement '{engagement_id}'."

    prefix = f"{engagement_id}_"
    files = sorted(DELIVERABLES_DIR.glob(f"{prefix}*.json"))

    if not files:
        return f"No deliverables found for engagement '{engagement_id}'."

    lines = [
        f"# Deliverables: {engagement_id}\n",
        "| Type | Producer | Saved At | Words | Consumed By |",
        "|------|----------|----------|-------|-------------|",
    ]

    for f in files:
        data = _safe_read_json(f, {})
        dtype = data.get("deliverable_type", f.stem[len(prefix) :])
        producer = data.get("producer_agent", "?")
        saved_at = data.get("saved_at", "?")[:19]
        word_count = data.get("word_count", 0)
        consumed_by = DELIVERABLE_TYPES.get(dtype, {}).get("consumed_by", "?")
        lines.append(f"| {dtype} | {producer} | {saved_at} | {word_count} | {consumed_by} |")

    lines.append(f"\nTotal: {len(files)} deliverables")
    return "\n".join(lines)


# ── Context-Aware Witness Payloads ────────────────────────────────


@mcp.tool()
def get_witness_payloads(
    sink_context: str,
    bypass_level: str = "all",
) -> str:
    """Get context-aware witness payloads for a specific sink/render context.

    Returns minimal proof-of-concept payloads matched to the exact context where
    user input is rendered or processed. Use these BEFORE exploitation — they prove
    structure influence (that attacker input reaches the sink) without full exploitation.

    Available contexts: html_body, html_attribute, javascript_string, javascript_template,
    url_param, css_value, sql_string, sql_numeric, command_shell, ssti_template, ssrf_url,
    path_traversal

    Args:
        sink_context: The render/sink context (e.g., 'html_body', 'sql_string', 'command_shell')
        bypass_level: Filter by bypass level: 'basic', 'intermediate', 'advanced', or 'all' (default)
    """
    sink_context = sink_context.lower().strip()
    if sink_context not in WITNESS_PAYLOADS:
        available = ", ".join(sorted(WITNESS_PAYLOADS.keys()))
        return f"Unknown sink context '{sink_context}'. Available: {available}"

    ctx: dict[str, Any] = WITNESS_PAYLOADS[sink_context]
    bypass_level = bypass_level.lower().strip()
    valid_levels = {"basic", "intermediate", "advanced", "all"}
    if bypass_level not in valid_levels:
        return f"Invalid bypass_level '{bypass_level}'. Must be one of: {', '.join(sorted(valid_levels))}"

    lines = [
        f"# Witness Payloads: {sink_context}",
        f"**Context**: {ctx['description']}",
        f"**Canary string**: `{ctx['canary']}` (inject first to confirm reflection/processing)",
        "",
        "## Testing Procedure",
        "1. Inject the canary string to confirm input reaches the sink",
        f"2. Check if `{ctx['canary']}` appears in the response/output",
        "3. If reflected, try payloads below in order (basic → intermediate → advanced)",
        "4. Document which payloads are blocked vs. executed",
        "",
        "## Payloads",
        "",
        "| # | Payload | Purpose | Level |",
        "|---|---------|---------|-------|",
    ]

    count = 0
    for p in ctx["payloads"]:
        if bypass_level != "all" and p["bypass_level"] != bypass_level:
            continue
        count += 1
        escaped_payload = p["payload"].replace("|", "\\|")
        lines.append(f"| {count} | `{escaped_payload}` | {p['purpose']} | {p['bypass_level']} |")

    if count == 0:
        lines.append(f"| - | No payloads at '{bypass_level}' level for this context | - | - |")

    lines.append("")
    lines.append("## Usage Notes")
    lines.append("- Start with **basic** payloads to detect baseline filtering")
    lines.append("- If basic payloads are blocked, note the WAF/filter behavior in `waf_intelligence` deliverable")
    lines.append("- Progress to **intermediate** only after documenting basic payload responses")
    lines.append("- **Advanced** payloads are for confirmed WAF bypass scenarios only")

    return "\n".join(lines)


# ── Evidence Checklists ──────────────────────────────────────────


@mcp.tool()
def get_evidence_checklist(
    vuln_class: str,
) -> str:
    """Get the mandatory evidence checklist and proof-level requirements for a vulnerability class.

    Returns the minimum proof level needed to classify a finding as EXPLOITED vs POTENTIAL,
    and a checklist of evidence items that must be collected before logging a finding.

    Use this BEFORE calling log_finding() to verify you have sufficient evidence.

    Available classes: xss, sqli, cmdi, ssti, ssrf, path_traversal, idor, auth

    Args:
        vuln_class: The vulnerability class (e.g., 'xss', 'sqli', 'cmdi')
    """
    vuln_class = vuln_class.lower().strip()
    if vuln_class not in EVIDENCE_CHECKLISTS:
        available = ", ".join(sorted(EVIDENCE_CHECKLISTS.keys()))
        return f"Unknown vulnerability class '{vuln_class}'. Available: {available}"

    checklist: dict[str, Any] = EVIDENCE_CHECKLISTS[vuln_class]
    required = int(checklist["proof_level_required"])

    lines = [
        f"# Evidence Checklist: {vuln_class.upper()}",
        f"**Minimum proof level for EXPLOITED**: L{required}",
        "",
        "## Proof Levels",
        "",
    ]

    for level, desc in sorted(checklist["levels"].items()):
        marker = " **← minimum for EXPLOITED**" if level == required else ""
        lines.append(f"- **L{level}**: {desc}{marker}")

    lines.append("")
    lines.append("## Mandatory Evidence Checklist")
    lines.append("")
    lines.append("Before calling `log_finding()`, verify you have ALL of these:")
    lines.append("")
    for i, item in enumerate(checklist["checklist"], 1):
        lines.append(f"{i}. [ ] {item}")

    lines.append("")
    lines.append("## Classification Guide")
    lines.append("")
    lines.append(f"- **EXPLOITED**: You have evidence at L{required} or higher + all checklist items")
    lines.append(f"- **POTENTIAL**: You have evidence at L1-L{required - 1} " "(vulnerability exists but full exploitation blocked)")
    lines.append("- **FALSE_POSITIVE**: Security control withstands exhaustive bypass attempts (not a finding)")
    lines.append("")
    lines.append("## Rules")
    lines.append("- NEVER log a finding as EXPLOITED without L3+ proof")
    lines.append("- NEVER claim 'JavaScript execution confirmed' without actual execution evidence")
    lines.append("- NEVER claim 'data extracted' without showing the actual extracted data")
    lines.append("- If blocked by WAF/CSP: classify as POTENTIAL and document bypass attempts")

    return "\n".join(lines)


# ── Slot Type Classification ────────────────────────────────────


@mcp.tool()
def get_slot_types(
    category: str = "all",
) -> str:
    """Get slot-type classification for sink analysis during source code review.

    Slot types identify the SPECIFIC position where user input enters a dangerous
    construct, determining the CORRECT defense (not just the general vulnerability class).

    Example: SQL-val needs parameterized queries, but SQL-ident needs a whitelist
    (parameterization doesn't work for identifiers).

    Available categories: sql, command, file, html, redirect, template, or 'all'

    Args:
        category: Sink category to retrieve, or 'all' for everything
    """
    category = category.lower().strip()
    if category != "all" and category not in SLOT_TYPES:
        available = ", ".join(sorted(SLOT_TYPES.keys()))
        return f"Unknown category '{category}'. Available: {available}, all"

    categories = SLOT_TYPES if category == "all" else {category: SLOT_TYPES[category]}

    lines = [
        "# Slot-Type Classification for Sinks",
        "",
        "Label each sink with its slot type during source code analysis.",
        "The slot type determines the CORRECT defense — general vuln class alone is insufficient.",
        "",
    ]

    for cat_name, slots in sorted(categories.items()):
        lines.append(f"## {cat_name.upper()} Slots")
        lines.append("")
        lines.append("| Slot Type | Correct Defense | Wrong Defense (Common Mistake) |")
        lines.append("|-----------|----------------|-------------------------------|")
        for slot_name, info in sorted(slots.items()):
            lines.append(f"| **{slot_name}** | {info['defense']} | {info['wrong_defense']} |")
        lines.append("")

    lines.append("## How to Use")
    lines.append("")
    lines.append("In the Taint Chain Catalog, add a `Slot Type` column:")
    lines.append("```")
    lines.append("TAINT CHAIN #3: SQL Injection via search")
    lines.append("SLOT TYPE: SQL-val")
    lines.append("CORRECT DEFENSE: Parameterized query")
    lines.append("APPLIED DEFENSE: String escaping (WRONG)")
    lines.append("VERDICT: VULNERABLE — wrong defense for this slot type")
    lines.append("```")

    return "\n".join(lines)


# ── Browser Profile Tool ──────────────────────────────────────────


@mcp.tool()
def get_browser_profile(engagement_id: str, agent_id: str) -> str:
    """Get a unique browser profile path for a subagent.
    Each subagent uses an isolated profile for independent cookie/session management,
    preventing browser state conflicts during parallel testing.

    Args:
        engagement_id: The engagement identifier
        agent_id: Unique identifier for the subagent (e.g., 'xss-agent', 'sqli-agent', 'agent-1')
    """
    profile_path = f"./engagements/runtime/{engagement_id}/browser-profiles/{agent_id}"

    return (
        f"Browser profile path: {profile_path}\n\n"
        f"## Usage with browser-auth.py\n"
        f"```bash\n"
        f"  --url <login-url> \\\n"
        f"  --username <user> --password <pass> \\\n"
        f"  --cookie-jar ./engagements/runtime/{engagement_id}/cookies-{agent_id}.txt \\\n"
        f"  --profile {profile_path}\n"
        f"```\n\n"
        f"## Usage with curl\n"
        f"```bash\n"
        f"  -b ./engagements/runtime/{engagement_id}/cookies-{agent_id}.txt \\\n"
        f"  -c ./engagements/runtime/{engagement_id}/cookies-{agent_id}.txt \\\n"
        f"  <url>\n"
        f"```\n\n"
        f"Each subagent should use its own cookie jar and profile for session isolation."
    )


# ── Git Checkpoint Tools ──────────────────────────────────────────


@mcp.tool()
def git_checkpoint(engagement_id: str, description: str) -> str:
    """Create a git checkpoint of the engagement workspace.
    Commits all current engagement files so the workspace can be rolled back on failure.

    Args:
        engagement_id: The engagement identifier
        description: Checkpoint description (used as commit message)
    """
    engagement_dir = _engagement_path(engagement_id)
    if not engagement_dir.exists():
        engagement_dir.mkdir(parents=True, exist_ok=True)

    git_dir = engagement_dir / ".git"
    if not git_dir.exists():
        result = subprocess.run(  # nosec B603, B607
            ["git", "init"],
            cwd=str(engagement_dir),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return f"Failed to initialize git repo: {result.stderr}"

    # Stage all files
    subprocess.run(  # nosec B603, B607
        ["git", "add", "-A"],
        cwd=str(engagement_dir),
        capture_output=True,
        text=True,
    )

    # Commit
    result = subprocess.run(  # nosec B603, B607
        ["git", "commit", "-m", f"Checkpoint: {description}", "--allow-empty"],
        cwd=str(engagement_dir),
        capture_output=True,
        text=True,
    )

    # Get commit hash
    hash_result = subprocess.run(  # nosec B603, B607
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(engagement_dir),
        capture_output=True,
        text=True,
    )
    commit_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"

    _append_event(
        engagement_id,
        {
            "tool": "git_checkpoint",
            "args": {"description": description},
            "result": f"Checkpoint {commit_hash}",
        },
    )

    return f"Git checkpoint created: {commit_hash}\nDescription: {description}"


@mcp.tool()
def git_rollback(engagement_id: str, reason: str) -> str:
    """Roll back the engagement workspace to the last git checkpoint.
    Use this when a phase fails and you need to restore the previous state.

    Args:
        engagement_id: The engagement identifier
        reason: Reason for rollback (logged in audit trail)
    """
    engagement_dir = _engagement_path(engagement_id)
    git_dir = engagement_dir / ".git"
    if not git_dir.exists():
        return f"No git repository found in engagement '{engagement_id}'. Use git_checkpoint() first."

    # Show current state
    log_result = subprocess.run(  # nosec B603, B607
        ["git", "log", "--oneline", "-5"],
        cwd=str(engagement_dir),
        capture_output=True,
        text=True,
    )

    # Rollback
    result = subprocess.run(  # nosec B603, B607
        ["git", "reset", "--hard", "HEAD~1"],
        cwd=str(engagement_dir),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return f"Rollback failed: {result.stderr}"

    # Get restored commit hash
    hash_result = subprocess.run(  # nosec B603, B607
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(engagement_dir),
        capture_output=True,
        text=True,
    )
    restored_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"

    _append_event(
        engagement_id,
        {
            "tool": "git_rollback",
            "args": {"reason": reason},
            "result": f"Rolled back to {restored_hash}",
        },
    )

    return f"Rollback complete. Restored to: {restored_hash}\n" f"Reason: {reason}\n\n" f"Recent commits:\n{log_result.stdout}"


# ── Engagement Status Tool ────────────────────────────────────────


@mcp.tool()
def get_engagement_status(engagement_id: str) -> str:
    """Get a comprehensive dashboard-style status summary for an engagement.
    Shows current phase, progress, finding counts, coverage, elapsed time,
    and gate results in a single view.

    Args:
        engagement_id: The engagement identifier
    """
    findings = _get_findings_from_sqlite(engagement_id)
    tracking = _safe_read_json(TRACKING_DIR / f"{engagement_id}.json", [])
    tool_tracking = _safe_read_json(TOOL_TRACKING_DIR / f"{engagement_id}.json", [])
    gate_tracking = _safe_read_json(GATE_TRACKING_DIR / f"{engagement_id}.json", [])
    checkpoints = _safe_read_json(CHECKPOINTS_DIR / f"{engagement_id}.json", {"checkpoints": []})
    code_analysis = _safe_read_json(CODE_ANALYSIS_DIR / f"{engagement_id}.json")

    # Current phase
    passed_phases = sorted({g["phase"] for g in gate_tracking if g.get("result") in ("PASS", "FORCED_PASS")})
    next_phase = max(passed_phases) + 1 if passed_phases else 0

    phase_names = {
        0: "Application Discovery & Mapping",
        1: "Information Gathering & Reconnaissance",
        2: "Configuration & Deployment Testing",
        3: "Identity, Authentication, Authorization & Session",
        4: "Input Validation Testing",
        5: "Error Handling, Crypto, Business Logic, Client-Side & API",
        6: "Coverage Verification & Reporting",
        7: "Final Judge Review & Remediation",
    }

    # Finding severity breakdown
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Coverage
    tests_completed = sum(1 for t in tracking if t.get("status") == "completed")
    tests_total = len(tracking)
    test_coverage = round(tests_completed / tests_total * 100) if tests_total > 0 else 0

    tools_run = sum(1 for t in tool_tracking if t.get("status") == "run")
    tools_total = len(TOOL_REGISTRY)
    tool_coverage = round(tools_run / tools_total * 100) if tools_total > 0 else 0

    # Elapsed time from events
    event_file = EVENTS_DIR / f"{engagement_id}.jsonl"
    elapsed_str = "N/A"
    last_activity_str = "N/A"
    if event_file.exists():
        lines = event_file.read_text(encoding="utf-8").strip().split("\n")
        if lines and lines[0].strip():
            try:
                first_event = json.loads(lines[0])
                last_event = json.loads(lines[-1])
                first_ts = datetime.fromisoformat(first_event["timestamp"])
                last_ts = datetime.fromisoformat(last_event["timestamp"])
                elapsed = last_ts - first_ts
                hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
                minutes = remainder // 60
                elapsed_str = f"{hours}h {minutes}m" if hours else f"{minutes}m"

                now = datetime.now(timezone.utc)
                ago = now - last_ts
                ago_min = int(ago.total_seconds()) // 60
                last_activity_str = f"{ago_min} minutes ago" if ago_min > 0 else "just now"
            except (json.JSONDecodeError, KeyError, ValueError):
                pass

    # Exploitation queues
    queue_files = list(EXPLOITATION_QUEUE_DIR.glob(f"{engagement_id}_*.json"))
    queue_summary = []
    for qf in sorted(queue_files):
        qdata = _safe_read_json(qf, {})
        vc = qdata.get("vuln_class", "?")
        vulns = qdata.get("vulnerabilities", [])
        exploited = sum(1 for v in vulns if v.get("exploitation_status") == "exploited")
        queue_summary.append(f"  - {vc.upper()}: {len(vulns)} queued, {exploited} exploited")

    # Build output
    lines = [
        f"# Engagement Status: {engagement_id}\n",
        "## Progress",
        f"- Current Phase: {next_phase} ({phase_names.get(next_phase, '?')})",
        f"- Phases Completed: {len(passed_phases)}/8 ({', '.join(str(p) for p in passed_phases) if passed_phases else 'None'})",
        f"- Code Analysis: {'Completed' if code_analysis and code_analysis.get('status') == 'completed' else 'Not performed'}",
        "",
        "## Findings",
    ]

    if severity_counts:
        severity_line = " | ".join(f"{sev}: {severity_counts.get(sev, 0)}" for sev in ["Critical", "High", "Medium", "Low", "Informational"] if sev in severity_counts)
        lines.append(f"- {severity_line}")
    lines.append(f"- Total: {len(findings)}")

    lines.extend(
        [
            "",
            "## Coverage",
            f"- Test Coverage: {test_coverage}% ({tests_completed}/{tests_total} tests completed)",
            f"- Tool Coverage: {tool_coverage}% ({tools_run}/{tools_total} tools run)",
            "",
            "## Timing",
            f"- Elapsed: {elapsed_str}",
            f"- Last Activity: {last_activity_str}",
            "",
            "## Gates",
            "| Phase | Result | Blockers | Warnings |",
            "|-------|--------|----------|----------|",
        ]
    )

    for g in gate_tracking:
        lines.append(f"| {g['phase']} | {g['result']} | {g.get('blockers_count', 0)} | {g.get('warnings_count', 0)} |")

    if queue_summary:
        lines.extend(["", "## Exploitation Queues"] + queue_summary)

    cp_list = checkpoints.get("checkpoints", [])
    if cp_list:
        latest_cp = cp_list[-1]
        lines.extend(
            [
                "",
                "## Checkpoints",
                f"- Latest: {latest_cp['id']} ({latest_cp.get('description', '')})",
                f"- Total: {len(cp_list)}",
            ]
        )

    # QA Reviews
    qa_reviews = _safe_read_json(QA_TRACKING_DIR / f"{engagement_id}.json", [])
    reviewed_phases = {qr["phase_reviewed"] for qr in qa_reviews}
    total_suggestions = sum(qr.get("suggestions_count", 0) for qr in qa_reviews)
    total_acted = sum(qr.get("suggestions_acted_on", 0) for qr in qa_reviews)
    lines.extend(
        [
            "",
            "## QA Reviews",
            f"- Phases reviewed: {', '.join(str(p) for p in sorted(reviewed_phases)) if reviewed_phases else 'None'}",
            f"- Total reviews: {len(qa_reviews)}",
            f"- Suggestions: {total_suggestions} total, {total_acted} acted on",
        ]
    )
    # Check for phases that passed without QA review
    unreviewed = set(passed_phases) - reviewed_phases
    if unreviewed and passed_phases:
        lines.append(f"- **Missing QA**: Phases {', '.join(str(p) for p in sorted(unreviewed))} not reviewed")

    return "\n".join(lines)


# ── Audit Log Tool ────────────────────────────────────────────────


@mcp.tool()
def get_audit_log(engagement_id: str, last_n: int = 0) -> str:
    """Retrieve the append-only event log for an engagement.
    Each event records an MCP tool call with timestamp, tool name, and result.
    Use this for debugging, forensics, and understanding engagement history.

    Args:
        engagement_id: The engagement identifier
        last_n: If > 0, return only the last N events. 0 = all events.
    """
    event_file = EVENTS_DIR / f"{engagement_id}.jsonl"
    if not event_file.exists():
        return f"No event log found for engagement '{engagement_id}'."

    lines = event_file.read_text(encoding="utf-8").strip().split("\n")
    events = []
    for line in lines:
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not events:
        return "Event log exists but contains no valid events."

    if last_n > 0:
        events = events[-last_n:]

    output = [f"# Audit Log: {engagement_id} ({len(events)} events)\n"]
    for e in events:
        ts = e.get("timestamp", "?")[:19]
        tool = e.get("tool", "?")
        result = e.get("result", "")
        output.append(f"- `{ts}` **{tool}** → {result}")

    return "\n".join(output)


# ── Tier 1: Hierarchical Task Tree Tools ─────────────────────────


@mcp.tool()
def create_task_tree(engagement_id: str) -> str:
    """Create a hierarchical task tree for a pentest engagement.
    Initializes with the standard phase structure (Phase -1 through 7).
    Idempotent — returns existing tree if already created.

    Args:
        engagement_id: The engagement identifier
    """
    return _tt_create(engagement_id)


@mcp.tool()
def add_task_node(
    engagement_id: str,
    parent_id: str,
    label: str,
    priority: str = "medium",
    notes: str = "",
) -> str:
    """Add a task node to the engagement task tree.

    Args:
        engagement_id: The engagement identifier
        parent_id: ID of the parent node (e.g., 'phase-0', 'phase-4')
        label: Human-readable task description
        priority: One of: critical, high, medium, low
        notes: Optional notes about the task
    """
    return _tt_add(engagement_id, parent_id, label, priority, notes)


@mcp.tool()
def update_task_node(
    engagement_id: str,
    node_id: str,
    status: str = "",
    notes: str = "",
    findings_count: int = -1,
) -> str:
    """Update a task node's status, notes, or findings count.
    Auto-propagates: if all children complete, parent auto-completes.

    Args:
        engagement_id: The engagement identifier
        node_id: The node ID to update
        status: New status (pending, in_progress, completed, skipped, blocked). Empty = no change.
        notes: Updated notes. Empty = no change.
        findings_count: Updated findings count. -1 = no change.
    """
    return _tt_update(engagement_id, node_id, status, notes, findings_count)


@mcp.tool()
def get_task_tree(engagement_id: str, max_depth: int = 3) -> str:
    """Get the full task tree as formatted markdown with completion percentages.

    Args:
        engagement_id: The engagement identifier
        max_depth: Maximum depth to render (default 3). Use higher for more detail.
    """
    return _tt_get(engagement_id, max_depth)


@mcp.tool()
def get_subtree(engagement_id: str, node_id: str) -> str:
    """Get a specific subtree for subagent context injection.
    Returns the node and all its descendants with unlimited depth.

    Args:
        engagement_id: The engagement identifier
        node_id: The root node of the subtree to retrieve
    """
    return _tt_subtree(engagement_id, node_id)


@mcp.tool()
def get_task_summary(engagement_id: str) -> str:
    """Get a high-level summary of task tree progress.
    One line per phase with completion %, findings, and pending item counts.
    Designed for main agent strategic decision-making.

    Args:
        engagement_id: The engagement identifier
    """
    return _tt_summary(engagement_id)


# ── Tier 1: Tool Output Parsing Tools ────────────────────────────


@mcp.tool()
def parse_tool_output(tool_name: str, raw_output: str, verbosity: str = "summary") -> str:
    """Parse and condense CLI security tool output into a structured summary.
    Reduces token usage by 3-5x while preserving key findings, endpoints, and errors.

    Args:
        tool_name: The tool name (e.g., nmap, sqlmap, ffuf, httpx, whatweb,
            testssl, nikto, dalfox, katana, gau, wapiti, commix, sstimap,
            crlfuzz, smuggler, corscanner)
        raw_output: The raw text output from the tool
        verbosity: Level of detail: 'summary' (~15 lines), 'detailed' (~50 lines), 'full' (complete parsed output)
    """
    return _tp_parse(tool_name, raw_output, verbosity)


@mcp.tool()
def ingest_tool_file(engagement_id: str, tool_name: str, file_path: str, verbosity: str = "summary") -> str:
    """Read a tool output file, parse it, and return the structured summary.
    Use this to efficiently ingest background CLI tool results.

    Args:
        engagement_id: The engagement identifier
        tool_name: The tool name (e.g., nmap, sqlmap, ffuf)
        file_path: Path to the tool output file
        verbosity: Level of detail: 'summary', 'detailed', 'full'
    """
    _validate_shell_arg(file_path, "file_path")
    return _tp_ingest(engagement_id, tool_name, file_path, verbosity)


# ── Tier 1: Endpoint Prioritization Tools ────────────────────────


@mcp.tool()
def prioritize_endpoints(engagement_id: str, endpoints_json: str) -> str:
    """Score and sort endpoints by risk for prioritized testing.
    Higher scores = higher attack surface = test first.
    Scoring factors: parameter count, tech risk, taint chains, tool convergence,
    auth requirements, HTTP method, and injectable parameter names.

    Args:
        engagement_id: The engagement identifier
        endpoints_json: JSON array of endpoint objects. Each should have:
            method (str), path (str), parameters (list), auth_required (bool),
            tech_stack (str), has_taint_chain (bool), tool_count (int)
    """
    return _ep_prioritize(engagement_id, endpoints_json)


@mcp.tool()
def get_priority_queue(engagement_id: str, limit: int = 0) -> str:
    """Retrieve the saved endpoint priority queue, sorted by risk score.

    Args:
        engagement_id: The engagement identifier
        limit: Maximum number of endpoints to return. 0 = all endpoints.
    """
    return _ep_get_queue(engagement_id, limit)


# ── Tier 2: WAF Evasion Tools ─────────────────────────────────────


@mcp.tool()
def identify_waf(
    response_headers: str,
    response_body: str = "",
    status_code: int = 403,
) -> str:
    """Identify WAF vendor from HTTP response characteristics.
    Analyzes headers, body, and status codes against a database of WAF signatures.

    Args:
        response_headers: Raw response headers (Header: Value, one per line)
        response_body: Response body text (block page). Can be empty.
        status_code: HTTP status code (default 403)
    """
    return _waf_identify(response_headers, response_body, status_code)


@mcp.tool()
def get_waf_bypass(
    waf_vendor: str,
    vuln_class: str,
    bypass_level: str = "all",
) -> str:
    """Get WAF bypass payloads tailored to a specific vendor and vulnerability class.
    Returns payloads ordered by complexity with encoding strategies.

    Args:
        waf_vendor: WAF vendor (e.g., 'cloudflare', 'modsecurity', 'aws_waf',
            'akamai', 'imperva_incapsula', 'f5_bigip_asm', 'fortinet', '_generic')
        vuln_class: Vulnerability class (e.g., 'xss', 'sqli', 'cmdi', 'ssti', 'ssrf')
        bypass_level: Filter: 'basic', 'intermediate', 'advanced', or 'all' (default)
    """
    return _waf_bypass(waf_vendor, vuln_class, bypass_level)


@mcp.tool()
def list_waf_vendors() -> str:
    """List all WAF vendors in the fingerprint database with signature counts
    and available bypass categories."""
    return _waf_list()


# ── Tier 2: Knowledge Graph Tools ─────────────────────────────────


@mcp.tool()
def add_graph_node(
    engagement_id: str,
    node_id: str,
    node_type: str,
    label: str,
    properties: str = "{}",
) -> str:
    """Add a node to the engagement knowledge graph.
    Nodes represent entities: endpoints, parameters, technologies, findings,
    user roles, cookies, domains, headers, files, secrets.

    Args:
        engagement_id: The engagement identifier
        node_id: Unique node ID (e.g., 'ep-post-api-users', 'finding-001')
        node_type: One of: endpoint, parameter, technology, finding, user_role,
            cookie, domain, header, file, secret
        label: Human-readable label (e.g., 'POST /api/users')
        properties: JSON string of additional properties
    """
    return _kg_add_node(engagement_id, node_id, node_type, label, properties)


@mcp.tool()
def add_graph_edge(
    engagement_id: str,
    source_id: str,
    target_id: str,
    edge_type: str,
    properties: str = "{}",
) -> str:
    """Add a directed edge between two nodes in the knowledge graph.
    Edges represent relationships: authenticates_to, has_parameter, reflects_in,
    redirects_to, trusts_origin, shares_session, uses_technology, has_finding,
    bypasses, chains_to, sends_to, reads_file, exposes, includes, manages,
    owned_by, injects_into.

    Args:
        engagement_id: The engagement identifier
        source_id: Source node ID
        target_id: Target node ID
        edge_type: Relationship type (see description)
        properties: JSON string of additional properties
    """
    return _kg_add_edge(engagement_id, source_id, target_id, edge_type, properties)


@mcp.tool()
def query_graph(
    engagement_id: str,
    node_type: str = "",
    edge_type: str = "",
    node_id: str = "",
    property_filter: str = "{}",
) -> str:
    """Query the knowledge graph for nodes and their connections.
    Filter by node type, edge type, specific node, or properties.

    Args:
        engagement_id: The engagement identifier
        node_type: Filter by node type (e.g., 'endpoint', 'finding'). Empty = all.
        edge_type: Filter edges by type. Empty = all.
        node_id: Get a specific node and connections. Empty = query all.
        property_filter: JSON filter for properties (e.g., '{"auth_required": false}')
    """
    return _kg_query(engagement_id, node_type, edge_type, node_id, property_filter)


@mcp.tool()
def find_chains(
    engagement_id: str,
    source_id: str = "",
    target_id: str = "",
    max_depth: int = 4,
) -> str:
    """Find vulnerability chains and attack paths in the knowledge graph.
    Uses BFS for multi-hop paths and checks predefined chaining patterns
    (XSS+no CSP, SSRF+cloud metadata, IDOR+admin, etc.) with severity upgrades.

    Args:
        engagement_id: The engagement identifier
        source_id: Starting node (empty = check all findings)
        target_id: Destination node (empty = find all sensitive targets)
        max_depth: Maximum path length (default 4)
    """
    return _kg_find_chains(engagement_id, source_id, target_id, max_depth)


@mcp.tool()
def get_graph_summary(engagement_id: str) -> str:
    """Get a high-level summary of the knowledge graph.
    Shows node/edge counts, type distribution, and isolated nodes.

    Args:
        engagement_id: The engagement identifier
    """
    return _kg_summary(engagement_id)


# ── PoC Validation Tools ────────────────────────────────────────

POC_VALIDATION_TIMEOUT = int(os.environ.get("POC_VALIDATION_TIMEOUT", "30"))  # seconds, configurable via env
POC_SECRET_KEY = secrets.token_hex(32)  # per-process random key for PoC tokens

# Commands whose first token is destructive and require force=True
# shell=False prevents chaining, so we only check the binary name.
_POC_DESTRUCTIVE_BINS: set[str] = {
    "rm",
    "dd",
    "mkfs",
    "mke2fs",
    "mkfs.ext2",
    "mkfs.ext3",
    "mkfs.ext4",
    "mkfs.xfs",
    "mkfs.btrfs",
    "mkfs.fat",
    "mkfs.ntfs",
    "mkfs.vfat",
    "fdisk",
    "cfdisk",
    "sfdisk",
    "parted",
    "gparted",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init",
    "chmod",
    "chown",
    "ddrescue",
}


def _generate_poc_token(engagement_id: str, command: str, response_body: str, timestamp: str) -> str:
    """Generate a verifiable PoC token for confirmed findings."""
    raw = f"{engagement_id}:{command}:{hashlib.sha256(response_body.encode()).hexdigest()}:{timestamp}:{POC_SECRET_KEY}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _save_poc_evidence(
    engagement_id: str,
    command: str,
    label: str,
    verdict: str,
    returncode: int,
    elapsed: float,
    stdout: str,
    stderr: str,
    http_status: str | None,
    poc_token: str,
) -> Path:
    """Save structured PoC evidence and a human-readable report."""
    eid = _sanitize_id(engagement_id)
    ev_dir = ENGAGEMENTS_DIR / eid / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", (label or "poc").strip().lower())[:40]
    safe_cmd = re.sub(r"[^a-zA-Z0-9_-]", "_", command.strip().split()[0])[:20]
    stem = f"{ts}_{safe_label}_{safe_cmd}_{poc_token[:8]}"

    # Structured JSON evidence
    evidence = {
        "poc_token": poc_token,
        "engagement_id": engagement_id,
        "command": command,
        "label": label or "",
        "verdict": verdict,
        "returncode": returncode,
        "elapsed": elapsed,
        "http_status": http_status or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "response_body": stdout[:5000],
        "response_body_truncated": len(stdout) > 5000,
        "stderr": stderr[:1000],
    }
    json_file = ev_dir / f"{stem}.json"
    json_file.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    # Human-readable PoC report using poc-report-template.md schema
    md_file = ev_dir / f"{stem}.md"
    lines = [
        f"## PoC Report: {label or 'Unlabeled'}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **PoC Token** | `{poc_token}` |",
        f"| **Engagement** | {engagement_id} |",
        f"| **Verdict** | {verdict} |",
        f"| **Command** | `{command}` |",
        f"| **Duration** | {elapsed:.1f}s |",
    ]
    if http_status:
        lines.append(f"| **HTTP Status** | {http_status} |")
    lines.append(f"| **Exit Code** | {returncode} |")
    lines.append(f"| **Timestamp** | {evidence['timestamp']} |")
    lines.extend(
        [
            "",
            "## Steps To Reproduce",
            "",
            "1. Run the following command:",
            "   ```",
            f"   {command}",
            "   ```",
            "",
            "## Supporting Material",
            "",
            "### Response Body",
            "```",
            stdout[:2000] + ("\n... (truncated)" if len(stdout) > 2000 else ""),
            "```",
            "",
        ]
    )
    if stderr:
        lines.extend(["### stderr", "```", stderr[:1000], "```\n"])
    md_file.write_text("\n".join(lines), encoding="utf-8")

    return json_file


def _extract_context_line(text: str, position: int) -> str:
    """Extract the surrounding line from text at the given character position."""
    start = text.rfind("\n", 0, position)
    if start == -1:
        start = 0
    else:
        start += 1
    end = text.find("\n", position)
    if end == -1:
        end = len(text)
    return text[start:end]


def _verify_poc_token(engagement_id: str, poc_token: str) -> bool:
    """Verify a PoC token against this engagement's evidence files.

    The 8-hex filename prefix is used only for an O(1) candidate lookup; the
    token is then confirmed by an exact full-length match against the
    `poc_token` stored inside the evidence JSON (M6). A filename-prefix match
    alone is NOT sufficient — that allowed prefix collisions and forged tokens
    to pass.
    """
    if not poc_token or len(poc_token) < 16:
        return False
    eid = _sanitize_id(engagement_id)
    ev_dir = ENGAGEMENTS_DIR / eid / "evidence"
    if not ev_dir.exists():
        return False
    prefix = poc_token[:8]
    candidates = list(ev_dir.glob(f"*{prefix}*.json"))
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        stored = data.get("poc_token", "")
        # Constant-time compare of the full token.
        if isinstance(stored, str) and stored and secrets.compare_digest(stored, poc_token):
            return True
    return False


def _poc_audit_log(engagement_id: str, command: str, label: str, verdict: str, returncode: int, elapsed: float) -> None:
    """Append a line to the PoC audit log for this engagement."""
    try:
        audit_dir = _engagement_path(engagement_id)
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_file = audit_dir / "poc-audit.log"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        audit_line = f"{timestamp} | {label or '-'} | {verdict} | " f"exit={returncode} | {elapsed:.1f}s | {command}\n"
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(audit_line)
    except Exception:
        logger.warning("Failed to write PoC audit log", exc_info=True)


# ── Payload Consensus Rules ────────────────────────────────────────────────

CONSENSUS_RULES: dict[str, dict] = {
    "sqli": {
        "payloads": [
            "' OR '1'='1",
            "' AND SLEEP(3)--",
            "' UNION SELECT NULL--",
        ],
        "min_success": 2,
    },
    "xss": {
        "payloads": [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ],
        "min_success": 2,
    },
    "ssrf": {
        "payloads": [
            "http://127.0.0.1",
            "http://169.254.169.254/",
            "http://[::1]",
        ],
        "min_success": 2,
    },
    "ssti": {
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
        ],
        "min_success": 2,
    },
    "cmdi": {
        "payloads": [
            ";id",
            "|id",
            "`id`",
        ],
        "min_success": 2,
    },
    "path_traversal": {
        "payloads": [
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
        ],
        "min_success": 1,
    },
    "open_redirect": {
        "payloads": [
            "//evil.com",
            "https://evil.com",
            "/%09/evil.com",
        ],
        "min_success": 1,
    },
    "nosqli": {
        "payloads": [
            r"?foo[$ne]=bar",
            r"?foo[$regex]=.*",
            r"?foo[$gt]=",
        ],
        "min_success": 1,
    },
    "xxe": {
        "payloads": [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/hostname'>]><root>&test;</root>",
        ],
        "min_success": 1,
    },
    "ldap_injection": {
        "payloads": [
            "*)(uid=*",
            "admin(|(uid=*))",
            "admin*",
        ],
        "min_success": 1,
    },
    "graphql_abuse": {
        "payloads": [
            "{__schema{types{name}}}",
            "query{__typename}",
            "mutation{__typename}",
        ],
        "min_success": 1,
    },
    "_default": {
        "payloads": [],
        "min_success": 1,
    },
}


def _extract_base_url(command: str) -> str:
    """Extract the first URL from a curl command."""
    parts = shlex.split(command)
    for p in parts:
        if p.startswith("http://") or p.startswith("https://"):
            return p
    return ""


# ── Consensus injection marker ──────────────────────────────────────────────
# If the agent's command contains this marker, payloads are substituted there
# (the real injection point). Otherwise we fall back to injecting into the
# first existing query parameter's value (NOT a synthetic `q=` param).
CONSENSUS_MARKER = "__PAYLOAD__"
_CONSENSUS_BENIGN = "swarmbenign42x"  # control token for differential oracles

# Exploitation oracles — evidence that a payload actually *triggered* the bug,
# not merely that the server responded. Compared against a benign control
# request where relevant. These are deliberately conservative: an unrecognised
# class returns no evidence (fail-closed) rather than passing on reachability.
_SQLI_ERROR_RE = re.compile(
    r"SQL syntax|mysql_fetch|mysqli?_|MariaDB|PostgreSQL|PG::|psql|SQLite|"
    r"ORA-\d{5}|ODBC|SQLSTATE|System\.Data\.SqlClient|unclosed quotation|"
    r"quoted string not properly terminated|near \".*\": syntax error",
    re.I,
)
_TIME_PAYLOAD_RE = re.compile(r"sleep\s*\(|waitfor|pg_sleep|benchmark\s*\(", re.I)
_PASSWD_RE = re.compile(r"root:.*?:0:0:")
_WINI_RE = re.compile(r"\[(fonts|extensions)\]|for 16-bit app support", re.I)
_CMDI_RE = re.compile(r"uid=\d+\(|gid=\d+\(|root:.*?:0:0:")
_METADATA_RE = re.compile(r"ami-id|instance-id|iam/security-credentials|computeMetadata|meta-data|hostname", re.I)
_GRAPHQL_INTROSPECT_RE = re.compile(r"__schema|queryType|\"types\"|__typename", re.I)
_REDIRECT_EVIL_RE = re.compile(r"location:\s*(https?:)?//(www\.)?evil\.com", re.I)


def _inject_payload_into_url(url: str, payload: str) -> str:
    """Inject a payload at the marker, or into the first existing query
    parameter's value (falling back to a `q=` param only when the URL has no
    query string at all)."""
    import urllib.parse

    if CONSENSUS_MARKER in url:
        return url.replace(CONSENSUS_MARKER, urllib.parse.quote(payload, safe=""))

    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        pairs = parsed.query.split("&")
        first_key = pairs[0].split("=", 1)[0]
        pairs[0] = f"{first_key}={urllib.parse.quote(payload, safe='')}"
        return urllib.parse.urlunparse(parsed._replace(query="&".join(pairs)))
    return f"{url}?q={urllib.parse.quote(payload, safe='')}"


def _build_poc_command(base_command: str, payload: str) -> str:
    """Build a PoC command using the given payload.

    Substitutes the CONSENSUS_MARKER if present (the agent-declared injection
    point); otherwise injects into the curl URL; otherwise appends the payload.
    """
    if CONSENSUS_MARKER in base_command:
        return base_command.replace(CONSENSUS_MARKER, payload)
    if "curl" in base_command:
        base_url = _extract_base_url(base_command)
        if base_url:
            injected_url = _inject_payload_into_url(base_url, payload)
            return base_command.replace(base_url, injected_url)
    return f"{base_command} {shlex.quote(payload)}"


def _ensure_probe_flags(command: str) -> str:
    """For curl probes, ensure -s (quiet) and -i (headers in body) so status
    codes and redirect Location headers are observable by the oracles."""
    if "curl" not in command:
        return command
    extra = []
    if not re.search(r"(^|\s)-[a-zA-Z]*s", command) and " --silent" not in command:
        extra.append("-s")
    if not re.search(r"(^|\s)-[a-zA-Z]*i", command) and " --include" not in command:
        extra.append("-i")
    if not extra:
        return command
    return command.replace("curl", "curl " + " ".join(extra), 1)


def _run_curl(cmd: str) -> dict:
    """Execute a curl/shell probe and return a structured response dict:
    {ok_conn, status, body, elapsed_ms, returncode, err}."""
    start = time.time()
    try:
        r = subprocess.run(shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=30)
    except Exception as e:
        return {"ok_conn": False, "status": None, "body": "", "elapsed_ms": (time.time() - start) * 1000, "returncode": -1, "err": str(e)}
    elapsed_ms = (time.time() - start) * 1000
    stdout = r.stdout or ""
    stderr = r.stderr or ""
    if "curl: (" in stderr:
        return {"ok_conn": False, "status": None, "body": stdout, "elapsed_ms": elapsed_ms, "returncode": r.returncode, "err": "curl error"}
    m = re.search(r"HTTP/[\d.]+ (\d+)", stdout) or re.search(r"HTTP/[\d.]+ (\d+)", stderr)
    status = m.group(1) if m else None
    if status == "000":
        return {"ok_conn": False, "status": "000", "body": stdout, "elapsed_ms": elapsed_ms, "returncode": r.returncode, "err": "status 000"}
    # For non-curl commands, a non-zero exit means the probe did not run cleanly.
    ok_conn = True if "curl" in cmd else (r.returncode == 0)
    return {"ok_conn": ok_conn, "status": status, "body": stdout, "elapsed_ms": elapsed_ms, "returncode": r.returncode, "err": ""}


def _consensus_oracle(vuln_class: str, payload: str, resp: dict, control: dict | None) -> bool:
    """Return True only if `resp` shows class-specific evidence the payload
    actually triggered the vulnerability. Conservative / fail-closed."""
    if not resp.get("ok_conn"):
        return False
    body = resp.get("body", "") or ""
    cbody = (control or {}).get("body", "") or ""

    if vuln_class == "sqli":
        # DB error newly introduced by the payload …
        if _SQLI_ERROR_RE.search(body) and not _SQLI_ERROR_RE.search(cbody):
            return True
        # … or a time-based payload that measurably delayed the response.
        if _TIME_PAYLOAD_RE.search(payload) and control:
            return (resp.get("elapsed_ms", 0) - control.get("elapsed_ms", 0)) >= 2500
        return False

    if vuln_class in ("xss",):
        # Payload reflected verbatim (unescaped) and not already in the control.
        return payload in body and payload not in cbody

    if vuln_class == "ssti":
        # Arithmetic evaluated server-side: result present, literal expr gone.
        return ("49" in body) and ("49" not in cbody) and ("7*7" not in body)

    if vuln_class == "cmdi":
        return bool(_CMDI_RE.search(body)) and not _CMDI_RE.search(cbody)

    if vuln_class in ("path_traversal", "xxe"):
        return bool(_PASSWD_RE.search(body) or _WINI_RE.search(body))

    if vuln_class == "graphql_abuse":
        return bool(_GRAPHQL_INTROSPECT_RE.search(body)) and not _GRAPHQL_INTROSPECT_RE.search(cbody)

    if vuln_class == "open_redirect":
        return bool(_REDIRECT_EVIL_RE.search(body))

    if vuln_class == "ssrf":
        # Cloud-metadata markers, or a response that meaningfully differs from
        # the benign control (status change or large body delta).
        if _METADATA_RE.search(body) and not _METADATA_RE.search(cbody):
            return True
        return _differs_from_control(resp, control)

    if vuln_class in ("nosqli", "ldap_injection"):
        # Injection-driven differential vs the benign control.
        return _differs_from_control(resp, control)

    # Unknown class → no oracle → fail closed.
    return False


def _differs_from_control(resp: dict, control: dict | None) -> bool:
    """Heuristic differential: payload response differs from the benign control
    by status code or a >25% body-length change. Used only for classes without
    a deterministic marker (ssrf/nosqli/ldap)."""
    if not control or not control.get("ok_conn"):
        return False
    if resp.get("status") != control.get("status"):
        return True
    rb = len(resp.get("body", "") or "")
    cb = len(control.get("body", "") or "")
    if cb == 0:
        return rb > 0
    return abs(rb - cb) / cb > 0.25


def _run_payload(test_cmd: str, payload: str, vuln_class: str = "", control: dict | None = None) -> tuple[bool, str]:
    """Run a single consensus payload and apply the class-specific oracle.

    `success` means the response shows evidence the payload triggered the
    vulnerability class — NOT merely that the server responded. When no
    vuln_class is supplied the result reflects connectivity only (kept for the
    helper's standalone callers), but consensus itself always passes a class.
    """
    resp = _run_curl(test_cmd)
    if not resp.get("ok_conn"):
        reason = resp.get("err") or "no response"
        return False, f"✗ {payload[:60]} ({reason})"
    if not vuln_class:
        # No class → connectivity-only signal (legacy helper behaviour).
        return True, f"✓ {payload[:60]} (reachable)"
    success = _consensus_oracle(vuln_class, payload, resp, control)
    tag = "✓" if success else "✗"
    detail = "exploited" if success else "no evidence"
    return success, f"{tag} {payload[:60]} ({detail})"


def _check_consensus(command: str, vuln_class: str, extra_payloads: list[str] | None = None) -> tuple[bool, int, int, list[str]]:
    """Run payload consensus for the given vulnerability class.

    Each payload must produce class-specific exploitation evidence (compared
    against a benign control request) to count as a success. Returns
    (passed, successes, total_attempted, results). Fail-closed: non-curl
    commands and classes with no payloads do NOT pass.
    """
    from concurrent.futures import ThreadPoolExecutor

    rules = CONSENSUS_RULES.get(vuln_class, CONSENSUS_RULES["_default"])
    payloads = list(rules["payloads"])
    if extra_payloads:
        seen = set(payloads)
        for p in extra_payloads:
            if p not in seen:
                payloads.append(p)
                seen.add(p)

    if "curl" not in command:
        return False, 0, 0, ["Consensus requires a curl command with an injection point — cannot verify"]

    if not payloads:
        return False, 0, 0, [f"No consensus payloads defined for class '{vuln_class}' — cannot auto-verify"]

    # Benign control request for differential / timing / reflection oracles.
    control_cmd = _ensure_probe_flags(_build_poc_command(command, _CONSENSUS_BENIGN))
    control = _run_curl(control_cmd)

    successes = 0
    results: list[str] = []
    with ThreadPoolExecutor(max_workers=len(payloads)) as executor:
        futures = [executor.submit(_run_payload, _ensure_probe_flags(_build_poc_command(command, p)), p, vuln_class, control) for p in payloads]
        for future in futures:
            success, msg = future.result()
            if success:
                successes += 1
            results.append(msg)

    passed = successes >= rules["min_success"]
    return passed, successes, len(payloads), results


@dataclass
class ReproducibilityResult:
    """Structured reproducibility output with consistency statistics."""

    all_succeeded: bool = False
    success_count: int = 0
    total_runs: int = 0
    avg_timing_ms: float = 0.0
    timing_stddev: float = 0.0
    individual_results: list[tuple[int, int]] = field(default_factory=list)  # [(run_num, exit_code), ...]

    @property
    def success_rate(self) -> float:
        return self.success_count / self.total_runs if self.total_runs > 0 else 0.0

    @property
    def is_consistent(self) -> bool:
        return self.success_rate >= 0.8 and self.timing_stddev < 2000

    def to_summary_lines(self) -> list[str]:
        return [f"Run {run+1}: {'✓' if code == 0 else '✗'} (exit={code})" for run, code in self.individual_results]


def _check_reproducibility(command: str, required_runs: int, expected_match: str = "", expected_status: str = "") -> ReproducibilityResult:
    """Run the same command N times and check the *evidence* reproduces.

    A run counts as successful only if it exits 0 AND (when provided) the
    expected_match string is present and the expected HTTP status matches. This
    prevents a stably-returning error page (e.g. a constant 404) from being
    reported as a reproducible PoC (M4). The success counter never goes
    negative — failures simply do not increment it.
    """
    result = ReproducibilityResult(total_runs=required_runs)
    timings: list[float] = []
    for i in range(required_runs):
        try:
            start = time.time()
            resp = subprocess.run(
                shlex.split(command),
                shell=False,
                capture_output=True,
                text=True,
                timeout=POC_VALIDATION_TIMEOUT,
            )
            elapsed_ms = (time.time() - start) * 1000
            stdout = resp.stdout or ""
            success = resp.returncode == 0
            if success and expected_match:
                success = expected_match in stdout
            if success and expected_status:
                m = re.search(r"HTTP/[\d.]+ (\d+)", stdout) or re.search(r"HTTP/[\d.]+ (\d+)", resp.stderr or "")
                got = m.group(1) if m else ""
                if expected_status.endswith("xx") and len(expected_status) == 3:
                    success = got.startswith(expected_status[0])
                else:
                    success = got == expected_status
            result.individual_results.append((i + 1, resp.returncode))
            timings.append(elapsed_ms)
            if success:
                result.success_count += 1
        except Exception:
            # Record the failed run but never drive the counter negative.
            result.individual_results.append((i + 1, -1))
            continue

    result.all_succeeded = result.success_count == required_runs
    if timings:
        result.avg_timing_ms = sum(timings) / len(timings)
        if len(timings) > 1:
            variance = sum((t - result.avg_timing_ms) ** 2 for t in timings) / len(timings)
            result.timing_stddev = math.sqrt(variance)
    return result


@mcp.tool()
def validate_poc(
    engagement_id: str,
    command: str,
    expected_status: str = "",
    expected_match: str = "",
    expected_no_match: str = "",
    label: str = "",
    force: bool = False,
    require_consensus: bool = False,
    vuln_class: str = "",
    auto_retry: int = 1,
    baseline_id: str = "",
    finding_id: int = 0,
    extra_payloads: str = "",
) -> str:
    """Execute a PoC command and validate the response in real time.
    Use this BEFORE logging a finding — verify your PoC actually works.
    Supports curl, burp_repeater (via MCP), and arbitrary shell commands.

    Args:
        engagement_id: The engagement identifier
        command: The PoC command to execute (e.g. 'curl -s https://target.com/api/...')
        expected_status: Expected HTTP status code or pattern (e.g. '200', '403', '2xx')
        expected_match: String that MUST appear in the response body for validation to pass
        expected_no_match: String that MUST NOT appear in the response body
        label: Optional human-readable label for this PoC (e.g. 'Config leak', 'Admin takeover')
        force: Set to True to allow potentially destructive commands (rm, dd, mkfs, etc.)
        require_consensus: If True, run multiple independent payloads and require min_success to pass
        vuln_class: Vulnerability class for consensus rules (e.g. 'sqli', 'xss', 'ssti', 'cmdi', 'ssrf')
        auto_retry: Number of times to retry the command for reproducibility (default 1, no retry)
        baseline_id: Optional baseline ID from collect_baseline() to diff against
        finding_id: Optional finding ID to auto-update poc_token on PASS (Phase M17)
        extra_payloads: Comma-separated custom payloads to append to default consensus set
    """
    label_str = f" [{label}]" if label else ""

    # ── Payload Consensus (Phase B) ──────────────────────────────────
    consensus_passed = True
    consensus_results: list[str] = []
    reproducibility_passed = True

    if require_consensus:
        extra = [p.strip() for p in extra_payloads.split(",") if p.strip()] if extra_payloads else None
        consensus_passed, successes, total, consensus_results = _check_consensus(command, vuln_class, extra_payloads=extra)
        if not consensus_passed:
            lines = [
                f"## PoC Validation{label_str}: FAIL ❌\n",
                f"**Command**: `{command}`",
                f"**Vuln Class**: {vuln_class or 'unknown'}",
                f"**Consensus**: {successes}/{total} passed (required {CONSENSUS_RULES.get(vuln_class, CONSENSUS_RULES['_default'])['min_success']})\n",
            ]
            lines.append("### Payload Results")
            for r in consensus_results:
                lines.append(f"- {r}")
            lines.append("")
            lines.append("**⚠️  Payload consensus not met — do NOT log this as a confirmed finding.**")
            _append_event(engagement_id, {"tool": "validate_poc", "args": {"command": command[:200], "label": label}, "result": f"FAIL: consensus {successes}/{total}"})
            return "\n".join(lines)

    # ── Reproducibility Check (Phase B → F stats) ───────────────────
    if auto_retry > 1:
        reproducibility_result = _check_reproducibility(command, auto_retry, expected_match=expected_match, expected_status=expected_status)
        reproducibility_passed = reproducibility_result.all_succeeded
        if not reproducibility_passed:
            lines = [
                f"## PoC Validation{label_str}: FAIL ❌\n",
                f"**Command**: `{command}`",
                f"**Reproducibility**: {reproducibility_result.success_count}/{auto_retry} runs passed " f"(rate={reproducibility_result.success_rate:.0%})\n",
            ]
            lines.append("### Run Results")
            for r in reproducibility_result.to_summary_lines():
                lines.append(f"- {r}")
            lines.append("")
            if reproducibility_result.timing_stddev > 0:
                lines.append(f"**Timing**: avg={reproducibility_result.avg_timing_ms:.0f}ms, " f"stddev={reproducibility_result.timing_stddev:.0f}ms\n")
            lines.append("**⚠️  Results were not reproducible — do NOT log this as a confirmed finding.**")
            _append_event(engagement_id, {"tool": "validate_poc", "args": {"command": command[:200], "label": label}, "result": f"FAIL: not reproducible ({auto_retry} runs)"})
            return "\n".join(lines)
    _append_event(
        engagement_id,
        {
            "tool": "validate_poc",
            "args": {
                "command": command[:200],
                "label": label,
                "engagement_id": engagement_id,
                "force": force,
            },
            "result": "RUNNING",
        },
    )

    # ── Destructive command guard ──
    try:
        tokens = shlex.split(command)
        cmd_bin = tokens[0] if tokens else ""
    except ValueError:
        cmd_bin = ""
    cmd_base = os.path.basename(cmd_bin)
    if (cmd_bin in _POC_DESTRUCTIVE_BINS or cmd_base in _POC_DESTRUCTIVE_BINS) and not force:
        return (
            f"## PoC Validation{label_str}: BLOCKED 🛑\n\n"
            f"**Command**: `{command}`\n\n"
            f"**Reason**: `{cmd_bin}` is a potentially destructive command "
            f"(see `_POC_DESTRUCTIVE_BINS` in server.py).\n\n"
            f"To run it anyway, set `force=True`:\n"
            f"`validate_poc(..., force=True)`\n\n"
            f"This safety check exists to prevent accidental destructive operations."
        )

    try:
        start_time = time.time()
        result = subprocess.run(
            shlex.split(command),
            shell=False,
            capture_output=True,
            text=True,
            timeout=POC_VALIDATION_TIMEOUT,
        )
        elapsed = time.time() - start_time
    except subprocess.TimeoutExpired:
        _poc_audit_log(engagement_id, command, label, "TIMEOUT", -1, POC_VALIDATION_TIMEOUT)
        _append_event(
            engagement_id,
            {
                "tool": "validate_poc",
                "args": {"command": command[:200], "label": label},
                "result": f"TIMEOUT after {POC_VALIDATION_TIMEOUT}s",
            },
        )
        return (
            f"## PoC Validation{label_str}: TIMEOUT ⏱️\n\n"
            f"**Command**: `{command}`\n\n"
            f"The command did not complete within {POC_VALIDATION_TIMEOUT} seconds. "
            f"This may indicate:\n"
            f"1. The endpoint is slow or unresponsive\n"
            f"2. The command syntax is wrong (hanging indefinitely)\n"
            f"3. Network/proxy issues\n\n"
            f"**Verdict**: FAIL — PoC could not be verified (timeout)"
        )
    except Exception as e:
        _poc_audit_log(engagement_id, command, label, "ERROR", -1, 0.0)
        _append_event(
            engagement_id,
            {
                "tool": "validate_poc",
                "args": {"command": command[:200], "label": label},
                "result": f"ERROR: {e}",
            },
        )
        return f"## PoC Validation{label_str}: ERROR ❌\n\n" f"**Command**: `{command}`\n\n" f"**Error**: {e}\n\n" f"**Verdict**: FAIL — PoC could not be executed"

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    returncode = result.returncode

    # Parse HTTP status from curl output if applicable — reuse existing stdout, no extra request
    http_status = None
    if "curl" in command:
        try:
            import re as _re

            # Try to extract status from existing output: "HTTP/1.1 200 OK"
            match = _re.search(r"HTTP/[\d.]+ (\d+)", stdout)
            if match:
                http_status = match.group(1)
        except Exception:
            logger.debug("Failed to extract HTTP status from existing curl output", exc_info=True)

    issues = []
    passes = []

    # Check return code
    if returncode != 0:
        issues.append(f"Non-zero exit code: {returncode}")
        if stderr:
            issues.append(f"stderr: {stderr[:500]}")
    else:
        passes.append("Exit code 0 (command succeeded)")

    # Check HTTP status
    if http_status:
        if http_status == "000":
            issues.append("HTTP status 000 — connection failed (DNS, timeout, or SSL error)")
        elif expected_status == "2xx" and not http_status.startswith("2"):
            issues.append(f"Expected status 2xx, got {http_status}")
        elif expected_status == "3xx" and not http_status.startswith("3"):
            issues.append(f"Expected status 3xx, got {http_status}")
        elif expected_status == "4xx" and not http_status.startswith("4"):
            issues.append(f"Expected status 4xx, got {http_status}")
        elif expected_status and http_status != expected_status:
            issues.append(f"Expected status {expected_status}, got {http_status}")
        else:
            passes.append(f"HTTP status: {http_status}" + (f" (expected: {expected_status})" if expected_status else ""))

    # Check expected_match
    if expected_match:
        if expected_match in stdout:
            passes.append(f"Expected content found: '{expected_match[:100]}'")
        else:
            issues.append(f"Expected content NOT found: '{expected_match[:100]}'")

    # Check expected_no_match
    if expected_no_match:
        if expected_no_match in stdout:
            issues.append(f"Unexpected content found: '{expected_no_match[:100]}' (should be absent)")
        else:
            passes.append(f"Confirmed absence of: '{expected_no_match[:100]}'")

    # Determine verdict
    response_preview = stdout[:2000]
    if len(stdout) > 2000:
        response_preview += f"\n... (truncated, {len(stdout)} total chars)"

    if issues:
        verdict = "FAIL"
        icon = "❌"
        summary = f"{len(issues)} issue(s) found"
    else:
        verdict = "PASS"
        icon = "✅"
        summary = f"{len(passes)} check(s) passed"

    _append_event(
        engagement_id,
        {
            "tool": "validate_poc",
            "args": {"command": command[:200], "label": label},
            "result": f"{verdict}: {summary} (in {elapsed:.1f}s)",
        },
    )

    _poc_audit_log(engagement_id, command, label, verdict, returncode, elapsed)

    lines = [
        f"## PoC Validation{label_str}: {verdict} {icon}\n",
        f"**Command**: `{command}`",
        f"**Duration**: {elapsed:.1f}s\n",
    ]

    if http_status:
        lines.append(f"**HTTP Status**: {http_status}")
    if returncode != 0:
        lines.append(f"**Exit Code**: {returncode}")
    lines.append("")

    if passes:
        lines.append("### ✅ Checks Passed")
        for p in passes:
            lines.append(f"- {p}")
        lines.append("")

    if issues:
        lines.append("### ❌ Issues Found")
        for i in issues:
            lines.append(f"- {i}")
        lines.append("")

    lines.append("### Response Preview")
    lines.append("```")
    lines.append(response_preview)
    lines.append("```\n")

    if verdict == "FAIL":
        lines.append(
            "**⚠️  This PoC did not verify. Do NOT log this as a confirmed finding.**\n\n"
            "Suggestions:\n"
            "1. Check if the endpoint/URL is correct\n"
            "2. Verify authentication/session state\n"
            "3. Try alternative approaches\n"
            "4. If the vulnerability is real but PoC fails due to environmental constraints "
            "(e.g., WAF blocking, ALB rules), document this clearly in the finding"
        )
        return "\n".join(lines)

    elif verdict == "PASS":
        poc_token = _generate_poc_token(engagement_id, command, stdout, datetime.now(timezone.utc).isoformat())
        ev_file = _save_poc_evidence(
            engagement_id,
            command,
            label,
            verdict,
            returncode,
            elapsed,
            stdout,
            stderr,
            http_status,
            poc_token,
        )

        # Auto-update poc_token on finding if finding_id provided
        if finding_id > 0:
            try:
                _fdb._execute(
                    "UPDATE vulns SET poc_token = ?, updated_at = ? WHERE id = ? AND engagement_id = ?",
                    (poc_token, datetime.now(timezone.utc).isoformat(), finding_id, engagement_id),
                )
                _fdb._get_conn().commit()
                lines.append(f"**Auto-updated** finding #{finding_id} with PoC token ✅\n")
            except Exception as e:
                lines.append(f"**Warning**: Failed to update finding #{finding_id}: {e}\n")

        # Add consensus/reproducibility summary if checked
        if require_consensus:
            successes = sum(1 for r in consensus_results if r.startswith("✓"))
            total = len(consensus_results)
            lines.append(f"**Payload Consensus**: {successes}/{total} passed ✅\n")

        if auto_retry > 1:
            lines.append(
                f"**Reproducibility**: {reproducibility_result.success_count}/{auto_retry} runs successful "
                f"(avg={reproducibility_result.avg_timing_ms:.0f}ms, "
                f"stddev={reproducibility_result.timing_stddev:.0f}ms) ✅\n"
            )

        # ── Baseline Response Diff (Phase C) ─────────────────────────────
        baseline_anomaly = False
        if baseline_id:
            from response_diff import BaselineProfile, ResponseFingerprint, compare

            baseline_data = _fdb.get_baseline(baseline_id)
            if baseline_data:
                bp = BaselineProfile.from_dict(baseline_data.get("profile", {}))
                attack_fp = ResponseFingerprint.from_curl_output(stdout, elapsed * 1000)
                diff = compare(bp, attack_fp, payload_string=vuln_class)
                lines.append("### Baseline Diff\n")
                lines.append(f"**Verdict**: {diff.verdict} (confidence: {diff.confidence:.0%})\n")
                if not diff.status_same:
                    lines.append("- Status code: changed")
                if not diff.body_length_within_normal:
                    lines.append(f"- Body length delta: {diff.body_length_delta:+d} ({diff.body_length_delta_pct:+.1%})")
                if diff.dom_changed:
                    lines.append("- DOM structure: changed")
                if diff.error_signatures_found:
                    lines.append(f"- Error signatures: {', '.join(diff.error_signatures_found)}")
                if diff.reflection_count > 0:
                    lines.append(f"- Payload reflected {diff.reflection_count} time(s)")
                if diff.timing_anomaly:
                    lines.append(f"- Timing anomaly: +{diff.timing_delta_ms:.0f}ms")
                baseline_anomaly = diff.verdict in ("DIFFERENT", "SUSPICIOUS")
                lines.append("")

        lines.append("**✅ PoC verified — finding can be logged with confidence.**\n")
        lines.append(f"**PoC Token**: `{poc_token}`\n")
        if baseline_id:
            lines.append(f"**Baseline Anomaly**: `{str(baseline_anomaly).lower()}`\n")
        lines.append(
            "To log this finding with PoC proof, call:\n\n" f'`findings_add_vuln(engagement_id="{engagement_id}", title="...", ' f'severity="...", confidence="confirmed", poc_token="{poc_token}", ...)`\n'
        )
        if baseline_anomaly:
            lines.append("When calling findings_add_vuln, also pass `baseline_anomaly=True` for confidence scoring.\n")
        lines.append(f"\n**Evidence saved**: `{ev_file}`")
        lines.append("Include the PoC Token in your finding to attach validated proof.")

    return "\n".join(lines)


@mcp.tool()
def validate_finding_poc(
    engagement_id: str,
    finding_id: int,
) -> str:
    """Re-validate an already-logged finding by re-running its PoC command.
    Useful for verifying a finding is still reproducible after some time.

    Args:
        engagement_id: The engagement identifier
        finding_id: The finding ID from the SQLite findings database
    """
    db = _FindingsDB(str(_fdb_path()))
    if not db:
        return f"Engagement '{engagement_id}' not found. Run findings_init() first."

    rows = db._execute(
        "SELECT id, title, poc_output, affected_url FROM vulns WHERE id = ?",
        (finding_id,),
    )
    row = rows.fetchone() if hasattr(rows, "fetchone") else None
    if not row:
        return f"Finding #{finding_id} not found in engagement '{engagement_id}'."

    finding_id_val, title, poc_output, affected_url = row

    if not poc_output:
        return f"Finding #{finding_id} ('{title}') has no PoC command stored.\n" f"Use validate_poc() to run and save a PoC for this finding."

    # Run the stored PoC
    result = validate_poc(
        engagement_id=engagement_id,
        command=poc_output,
        label=f"Finding #{finding_id}: {title[:60]}",
    )

    # Extract new poc_token from result and update vuln record
    token_match = re.search(r"\*\*PoC Token\*\*.*?`([^`]+)`", result)
    if token_match:
        new_token = token_match.group(1)
        try:
            db._execute(
                "UPDATE vulns SET poc_token = ?, updated_at = ? WHERE id = ?",
                (new_token, datetime.now(timezone.utc).isoformat(), finding_id_val),
            )
            db._get_conn().commit()
            result += f"\n✅ PoC token updated for Finding #{finding_id}."
        except Exception:
            result += "\n⚠️ PoC validated but failed to update token in DB."
    return result


_SHELL_UNSAFE = re.compile(r"[\"';$`|&><(){}!\\]")
_SHELL_UNSAFE_PATHS = re.compile(r"\.\.")


def _validate_shell_arg(value: str, name: str) -> None:
    """Reject values containing shell metacharacters or path traversal."""
    if _SHELL_UNSAFE.search(value):
        raise ValueError(f"Invalid {name!r}: contains shell metacharacters")
    if _SHELL_UNSAFE_PATHS.search(value):
        raise ValueError(f"Invalid {name!r}: contains path traversal")


# ── Tool Verification & Context Compression Tools ─────────────────


@mcp.tool()
def verify_tool_result(tool_name: str, command: str, raw_output: str) -> str:
    """Verify CLI tool output quality. Returns status (valid/suspicious/empty),
    issues found, and corrected command suggestions.

    Args:
        tool_name: The tool name (e.g., nmap, sqlmap, ffuf, dalfox, katana)
        command: The exact command that was run
        raw_output: The raw output text from the tool
    """
    return _tv_verify(tool_name, command, raw_output)


@mcp.tool()
def compress_phase_context(engagement_id: str, phase: int) -> str:
    """Generate a compressed summary of all engagement activity for a phase.
    Reads tracking, findings, tools, deliverables, and gate results.
    Saves as deliverable type 'phase_N_summary'. Auto-triggered on phase gate PASS.

    Args:
        engagement_id: The engagement identifier
        phase: The phase number to summarize (0-5)
    """
    return _cc_compress(engagement_id, phase)


@mcp.tool()
def get_engagement_summary(engagement_id: str) -> str:
    """Get a compressed summary of all phases completed so far.
    Combines individual phase summaries into an engagement-wide overview.
    Useful for injecting into subagent prompts to provide full context
    without raw historical data.

    Args:
        engagement_id: The engagement identifier
    """
    return _cc_summary(engagement_id)


# ── GraphQL Tools ──────────────────────────────────────────────────


@mcp.tool()
def call_graphql_introspect(
    endpoint: str,
    query: str = "",
    headers: str = "",
) -> str:
    """Execute a GraphQL introspection query against an endpoint.
    Use this when Burp MCP is unavailable for quick schema discovery.

    Args:
        endpoint: Full GraphQL endpoint URL (e.g. 'https://example.com/graphql')
        query: Optional custom query. Defaults to standard introspection query.
        headers: Optional HTTP headers (JSON object string, e.g. '{"Authorization": "Bearer x"}')
    """
    import json as _json

    _validate_shell_arg(endpoint, "endpoint")

    introspection_query = query or """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields {
            name
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """.strip()

    try:
        import subprocess as _sp  # nosec B404

        payload = _json.dumps({"query": introspection_query})
        cmd = [
            "curl",
            "-s",
            "-X",
            "POST",
            endpoint,
            "-H",
            "Content-Type: application/json",
            "--data-raw",
            payload,
        ]
        if headers:
            try:
                hdrs = _json.loads(headers)
                for k, v in hdrs.items():
                    cmd.extend(["-H", f"{k}: {v}"])
            except _json.JSONDecodeError:
                pass
        result = _sp.run(cmd, capture_output=True, text=True, timeout=30)  # nosec B603
        if result.returncode != 0:
            return f"## GraphQL Introspection: FAILED\n\n**Error**: {result.stderr[:500]}"
        resp = _json.loads(result.stdout)
    except Exception as e:
        return f"## GraphQL Introspection: ERROR\n\n**Error**: {e}"

    if "errors" in resp:
        msgs = [e.get("message", "") for e in resp["errors"]]
        return (
            f"## GraphQL Introspection: BLOCKED\n\n"
            f"Introspection returned errors — likely disabled.\n"
            f"**Errors**: {'; '.join(msgs[:5])}\n\n"
            f"Try alternative discovery:\n"
            f"- GET /graphql?query={{__typename}}\n"
            f"- Common field bruteforcing\n"
            f"- Schema stitching / batch queries"
        )

    schema = resp.get("data", {}).get("__schema", {})
    if not schema:
        return "## GraphQL Introspection: No schema returned"

    qtype = schema.get("queryType", {}).get("name", "?")
    mtype = schema.get("mutationType", {}).get("name", "None")
    stype = schema.get("subscriptionType", {}).get("name", "None")

    lines = [
        f"# GraphQL Schema: {endpoint}\n",
        f"**Query Type**: `{qtype}`",
        f"**Mutation Type**: `{mtype}`",
        f"**Subscription Type**: `{stype}`\n",
        "## Types",
    ]

    for t in schema.get("types", []):
        tname = t.get("name", "")
        if tname.startswith("__") or tname in {
            "String",
            "Int",
            "Float",
            "Boolean",
            "ID",
        }:
            continue
        kind = t.get("kind", "")
        desc = t.get("description", "") or ""
        lines.append(f"\n### {tname} ({kind})")
        if desc:
            lines.append(f"> {desc[:200]}")
        for f in t.get("fields") or []:
            fname = f.get("name", "?")
            ftype = f.get("type", {}).get("name", f.get("type", {}).get("kind", "?"))
            lines.append(f"- `{fname}`: {ftype}")

    return "\n".join(lines)


# ── Agent Reasoning & Guardrail Tools ──────────────────────────────

_INJECTION_PATTERNS = [
    # Direct override attempts
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
    r"ignore\s+(all\s+)?(previous|prior)\s+(directives?|commands?|prompts?)",
    r"forget\s+(all\s+)?(previous|prior)\s+(instructions?|directives?)",
    r"disregard\s+(all\s+)?(previous|prior)\s+(instructions?|directives?)",
    # Role-play takeover
    r"you\s+are\s+(now\s+)?(a\s+)?(free\s+)?(unconstrained\s+)?(AI|assistant|model|chatbot)",
    r"you\s+are\s+not\s+(bound\s+by|constrained\s+by|limited\s+by)",
    r"act\s+as\s+(if\s+you\s+are|you\s+are)\s+(a\s+)?(different\s+)?(person|AI|assistant|character)",
    r"from\s+(now\s+on|this\s+point\s+(forward|on))",
    # Extraction attempts
    r"(print|reveal|show|output|display|leak)\s+(your\s+)?(system\s+)?prompt",
    r"(print|reveal|show|output|display|leak)\s+(your\s+)?(initial\s+)?instructions?",
    r"output\s+(your\s+)?(system\s+)?prompt\s+(in\s+)?(code\s+)?block",
    # Deceptive embedding
    r"this\s+(is\s+)?(a\s+)?(test|simulation|example)\s+of\s+(how\s+to\s+)?respond",
    r"below\s+(is\s+)?(a\s+)?(test|example|sample)\s+of\s+(a\s+)?response",
    r"the\s+(above|following)\s+(is\s+)?how\s+you\s+should\s+(respond|answer|reply)",
]


@mcp.tool()
def detect_prompt_injection(content: str) -> str:
    """Check text for prompt injection patterns.
    Scan web content, search results, or any untrusted text for
    common prompt injection attempts. Returns SAFE or details.

    Args:
        content: The text to scan for injection patterns
    """
    if not content or not content.strip():
        return "SAFE: empty content"

    content_lower = content.lower()

    for idx, pattern in enumerate(_INJECTION_PATTERNS):
        matches = re.findall(pattern, content_lower, re.IGNORECASE | re.DOTALL)
        if matches:
            example = matches[0] if isinstance(matches[0], str) else matches[0][0]
            return f"INJECTION_DETECTED: pattern matched" f" [{_INJECTION_PATTERNS[idx].pattern[:60]}]\n" f"Example match: {example[:200]}"

    return "SAFE"


@mcp.tool()
def write_agent_notes(
    engagement_id: str,
    notes: str,
    agent_id: str = "default",
    append: bool = False,
) -> str:
    """Persist structured reasoning notes for an agent across turns.

    Saves or appends notes to the engagement's agent-notes storage.
    Use this to preserve intermediate reasoning, hypotheses, observations,
    and findings-in-progress between successive tool calls.

    Args:
        engagement_id: The engagement identifier
        notes: The notes content to persist (Markdown or JSON text)
        agent_id: A label identifying the agent (e.g. 'xss', 'sqli', 'recon')
        append: If True, append to existing notes. If False, overwrite.
    """
    eid = _sanitize_id(engagement_id)
    if not eid:
        return "## write_agent_notes: FAIL\n\nError: Invalid engagement_id"

    safe_agent = _sanitize_id(agent_id, max_len=50) if agent_id else "default"

    notes_dir = ENGAGEMENTS_DIR / eid / "agent-notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    notes_file = notes_dir / f"{safe_agent}.md"

    if append and notes_file.exists():
        existing = notes_file.read_text(encoding="utf-8")
        separator = "\n\n---\n\n"
        updated = existing.rstrip() + separator + notes.strip()
    else:
        updated = notes.strip()

    _atomic_write_str(notes_file, updated)
    char_count = len(updated)
    return (
        f"## write_agent_notes: OK\n\n"
        f"**Agent**: {safe_agent}\n"
        f"**Engagement**: {eid}\n"
        f"**Mode**: {'append' if append else 'overwrite'}\n"
        f"**Size**: {char_count} characters\n"
        f"**File**: `{notes_file}`"
    )


@mcp.tool()
def read_agent_notes(
    engagement_id: str,
    agent_id: str = "default",
) -> str:
    """Retrieve persisted reasoning notes for an agent.

    Returns the full notes content saved by a previous call to
    `write_agent_notes()`. Use this at the start of each turn to
    resume prior context.

    Args:
        engagement_id: The engagement identifier
        agent_id: The agent label used when notes were saved
    """
    eid = _sanitize_id(engagement_id)
    if not eid:
        return "## read_agent_notes: FAIL\n\nError: Invalid engagement_id"

    safe_agent = _sanitize_id(agent_id, max_len=50) if agent_id else "default"
    notes_file = ENGAGEMENTS_DIR / eid / "agent-notes" / f"{safe_agent}.md"

    if not notes_file.exists():
        return "## read_agent_notes: EMPTY\n\nNo notes found for this agent."

    content = notes_file.read_text(encoding="utf-8")
    char_count = len(content)
    return f"## read_agent_notes: OK\n\n" f"**Agent**: {safe_agent}\n" f"**Size**: {char_count} characters\n\n" f"{content}"


def _atomic_write_str(filepath: Path, content: str) -> None:
    """Crash-safe string write: write to temp file, then atomic rename."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(filepath.parent), suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, str(filepath))  # atomic overwrite on POSIX + Windows
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ── Burp Suite Stubs ───────────────────────────────────────────────


@mcp.tool()
def burp_send_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    timeout: int = 15,
) -> str:
    """Send an HTTP request (standalone, no Burp required).
    Use this when Burp Suite MCP is not available. For full Burp features
    (repeater, intruder, scanner), connect to a running Burp MCP server.

    Args:
        url: Full URL to send request to
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Raw HTTP headers (one per line, colon-separated)
        body: Request body for POST/PUT requests
        timeout: Request timeout in seconds (default 15)
    """
    import shutil as _shutil

    _validate_shell_arg(url, "url")
    if not _shutil.which("curl"):
        return "## burp_send_request: FAIL\n\n**Error**: `curl` is not installed."

    cmd = ["curl", "-s", "-X", method, url, "-i", "-L", "--max-time", str(timeout)]
    if headers:
        for line in headers.strip().split("\n"):
            line = line.strip()
            if ":" in line:
                cmd.extend(["-H", line])
    if body:
        cmd.extend(["--data-raw", body])

    try:
        import subprocess as _sp  # nosec B404

        result = _sp.run(cmd, capture_output=True, text=True, timeout=timeout + 5)  # nosec B603
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        status = "OK" if result.returncode == 0 else f"EXIT {result.returncode}"
    except Exception as e:
        return f"## burp_send_request: ERROR\n\n**Error**: {e}"

    response = stdout[:5000]
    if len(stdout) > 5000:
        response += f"\n... (truncated, {len(stdout)} total chars)"

    return f"## burp_send_request: {status}\n\n" f"**{method} {url}**\n\n" f"### Response\n```\n{response}\n```\n" + (f"\n### Stderr\n```\n{stderr[:500]}\n```" if stderr else "")


# ── Entry Point ────────────────────────────────────────────────────


def main():
    transport = os.environ.get("WSTG_TRANSPORT", "stdio")  # "stdio", "sse", or "streamable-http"
    if transport == "sse":
        import uvicorn

        starlette_app = mcp.sse_app()
        uvicorn.run(
            starlette_app,
            host=mcp.settings.host,
            port=mcp.settings.port,
            log_level=mcp.settings.log_level.lower(),
        )
    else:
        mcp.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
