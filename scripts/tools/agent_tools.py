#!/usr/bin/env python3
"""
Agent tool: validate agent .md files and generate index.json.

Usage:
  python scripts/tools/agent_tools.py              # validate only (default)
  python scripts/tools/agent_tools.py --validate    # validate only
  python scripts/tools/agent_tools.py --index       # generate index.json only
  python scripts/tools/agent_tools.py --all         # validate + generate index
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AGENTS_DIR = REPO_ROOT / ".swarm" / "agents"
COMMANDS_DIR = REPO_ROOT / ".swarm" / "commands"
SERVER_PY = REPO_ROOT / "server" / "server.py"
INDEX_JSON = REPO_ROOT / "index.json"

VALID_MODES = {"subagent", "all"}
VALID_PERMISSIONS = {"allow", "deny"}
REQUIRED_FRONTMATTER = {"description"}

REMOVED_TOOLS = {
    "get_technique_guide",
    "search_techniques",
    "list_portswigger_categories",
}

EXTERNAL_TOOLS = {
    "browser_act", "browser_analyze", "browser_auto_auth",
    "browser_login", "browser_screenshot", "browser_crawl", "browser_extract_storage",
    # Burp MCP bridge tools
    "burp_get_proxy_http_history", "burp_get_active_editor_contents",
    "burp_generate_collaborator_payload", "burp_get_scanner_issues",
    "burp_create_repeater_tab", "burp_base64_decode", "burp_base64_encode",
    "burp_get_collaborator_interactions",
    "burp_send_http1_request", "burp_send_to_intruder",
    "burp_send_http2_request", "burp_set_active_editor_contents",
    "burp_url_encode", "burp_url_decode",
    "burp_generate_random_string", "burp_set_proxy_intercept_state",
    # OpenCode built-in tools
    "websearch", "webfetch", "task",
}

TOOL_REF_RE = re.compile(r"`(\w+)\(\)`")


def extract_mcp_tools(server_py_path):
    """Extract all MCP tool function names from server.py by finding @mcp.tool() + def name(."""
    tools = set()
    if not server_py_path.exists():
        print(f"  [WARN] server.py not found at {server_py_path}", file=sys.stderr)
        return tools
    content = server_py_path.read_text()
    lines = content.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "@mcp.tool()" or stripped == "@_original_mcp_tool()":
            # look ahead for def <name>(
            for j in range(i + 1, min(i + 5, len(lines))):
                m = re.match(r"^def (\w+)\(", lines[j].strip())
                if m:
                    tools.add(m.group(1))
                    break
    return tools


def parse_frontmatter(file_path):
    """Parse YAML frontmatter from a .md file. Returns (frontmatter_dict, body_lines)."""
    try:
        content = file_path.read_text()
    except Exception as e:
        return None, [], str(e)

    lines = content.split("\n")
    if not lines or lines[0].strip() != "---":
        return None, lines, "Missing opening ---"

    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break

    if end_idx is None:
        return None, lines, "Missing closing ---"

    fm_lines = lines[1:end_idx]
    body_lines = lines[end_idx + 1:]

    fm = {}
    current_key = None
    current_indent = 0
    nested = {}

    for line in fm_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        m = re.match(r"^(\w+):\s*(.*)", stripped)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            if indent == 0:
                current_key = key
                if val == "" or val.startswith("#"):
                    fm[key] = {}
                    nested[key] = {}
                elif val.startswith("[") and val.endswith("]") and "," in val:
                    fm[key] = [v.strip().strip('"').strip("'") for v in val.strip("[]").split(",") if v.strip()]
                else:
                    fm[key] = val.strip('"').strip("'")
                nested[key] = {}
            else:
                sub_m = re.match(r"^(\w+):\s*(.*)", stripped)
                if sub_m and current_key and indent <= 4:
                    sub_key = sub_m.group(1)
                    sub_val = sub_m.group(2).strip()
                    if sub_val:
                        if isinstance(fm.get(current_key), dict):
                            fm[current_key][sub_key] = sub_val.strip('"').strip("'")
                    else:
                        if not isinstance(fm.get(current_key), dict):
                            fm[current_key] = {}
                        fm[current_key][sub_key] = None

    for line in fm_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^(\w+):\s*(.*)", stripped)
        if not m:
            continue
        m2 = re.match(r"^  (\w+):\s*(\w+)", stripped)
        if m2 and current_key:
            sub_key = m2.group(1)
            sub_val = m2.group(2)
            if isinstance(fm.get(current_key), dict):
                fm[current_key][sub_key] = sub_val.strip('"').strip("'")

    return fm, body_lines, None


def validate_agent(file_path, valid_tools):
    """Validate a single agent .md file. Returns list of issue strings."""
    issues = []
    fm, body_lines, error = parse_frontmatter(file_path)
    name = file_path.stem

    if error:
        issues.append(f"  Frontmatter error: {error}")
        return issues

    if not fm:
        issues.append("  No frontmatter found")
        return issues

    if not fm.get("description"):
        issues.append("  Missing or empty 'description'")
    elif isinstance(fm["description"], list):
        issues.append("  'description' is a list, not a string — check frontmatter syntax")
    elif not isinstance(fm["description"], str):
        issues.append(f"  'description' must be a string, got {type(fm['description']).__name__}")
    elif len(fm["description"].strip()) < 10:
        issues.append(f"  'description' too short ({len(fm['description'].strip())} chars, min 10)")

    mode = fm.get("mode")
    if mode and mode not in VALID_MODES:
        issues.append(f"  Invalid mode '{mode}' (must be one of {VALID_MODES})")
    elif not mode:
        issues.append("  Missing 'mode'")

    perms = fm.get("permission", {})
    if isinstance(perms, dict):
        for p in ("read", "bash", "edit", "grep", "glob"):
            val = perms.get(p)
            if val and val not in VALID_PERMISSIONS:
                issues.append(f"  permission.{p} = '{val}' (must be allow/deny)")

    body = "\n".join(body_lines)
    for m in TOOL_REF_RE.finditer(body):
        tool = m.group(1)
        if tool in REMOVED_TOOLS:
            issues.append(f"  Line {_find_line(body_lines, m.group(0))}: REMOVED tool '{tool}()' — replace with search_wstg()")
        elif tool in EXTERNAL_TOOLS:
            continue
        elif tool not in valid_tools:
            if not _is_false_positive(tool):
                issues.append(f"  Line {_find_line(body_lines, m.group(0))}: Unknown tool '{tool}()' — not found in server.py")

    return issues


def validate_command(file_path):
    """Validate a single command .md file. Returns list of issue strings."""
    issues = []
    fm, body_lines, error = parse_frontmatter(file_path)
    name = file_path.stem

    if error:
        issues.append(f"  Frontmatter error: {error}")
        return issues

    if not fm:
        issues.append("  No frontmatter found")
        return issues

    if not fm.get("name"):
        issues.append("  Missing 'name'")
    elif fm["name"] != name:
        issues.append(f"  frontmatter name '{fm['name']}' != filename '{name}'")

    if not fm.get("description"):
        issues.append("  Missing or empty 'description'")
    elif isinstance(fm["description"], list):
        issues.append("  'description' is a list, not a string — check frontmatter syntax")
    elif not isinstance(fm["description"], str):
        issues.append(f"  'description' must be a string, got {type(fm['description']).__name__}")
    elif len(fm["description"].strip()) < 10:
        issues.append(f"  'description' too short ({len(fm['description'].strip())} chars, min 10)")

    return issues


def _find_line(lines, substr):
    """Find the 1-indexed line number containing substr in lines."""
    for i, line in enumerate(lines):
        if substr in line:
            return i + 2  # +1 for 1-indexed, +1 for frontmatter offset
    return "?"


def _is_false_positive(tool_name):
    """Check if a tool name is a known false positive (not an MCP tool ref)."""
    false_positives = {
        "read", "write", "open", "close", "start", "stop", "run", "exec",
        "send", "get", "set", "add", "remove", "list", "find", "search",
        "create", "delete", "update", "check", "test", "log", "print",
        "load", "save", "init", "reset", "clear", "parse", "format",
        "encode", "decode", "hash", "encrypt", "decrypt", "sign", "verify",
        "connect", "disconnect", "bind", "listen", "accept", "reject",
        "sleep", "wait", "retry", "timeout", "try", "catch", "raise",
        "assert", "expect", "describe", "it", "before", "after", "each",
        "len", "str", "int", "float", "bool", "dict", "list", "set", "tuple",
        "range", "zip", "map", "filter", "sorted", "reversed", "enumerate",
        "min", "max", "sum", "any", "all", "abs", "round", "type", "dir",
        "vars", "hasattr", "getattr", "setattr", "isinstance", "issubclass",
        "shell_exec", "exec", "system", "popen",
        # code expressions in markdown examples
        "fromJson", "contains", "hashFiles",
        "node", "file_exists", "require", "endsWith", "startswith",
        "fetch", "eval", "t", "Image", "simplexml_load_string",
        "attempt", "transfer", "phpinfo", "program", "claimRedemption",
        "vote", "poke", "harvest",
    }
    return tool_name in false_positives


def validate_all(agents_dir, commands_dir, valid_tools):
    """Validate all agent and command files. Returns (total_issues, files_with_issues)."""
    total_issues = 0
    files_with_issues = 0

    agent_files = sorted(agents_dir.glob("*.md")) if agents_dir.exists() else []
    command_files = sorted(commands_dir.glob("*.md")) if commands_dir.exists() else []

    print(f"\n{'='*60}")
    print(f"Validating {len(agent_files)} agent files + {len(command_files)} command files")
    print(f"MCP tools in server.py: {len(valid_tools)}")
    print(f"{'='*60}\n")

    for f in agent_files:
        issues = validate_agent(f, valid_tools)
        label = "✓" if not issues else "✗"
        print(f"  {label} agents/{f.stem}")
        for issue in issues:
            print(f"     {issue}")
            total_issues += 1
        if issues:
            files_with_issues += 1

    print()
    for f in command_files:
        issues = validate_command(f)
        label = "✓" if not issues else "✗"
        print(f"  {label} commands/{f.stem}")
        for issue in issues:
            print(f"     {issue}")
            total_issues += 1
        if issues:
            files_with_issues += 1

    print(f"\n{'='*60}")
    print(f"Result: {total_issues} issues across {files_with_issues} files")
    if total_issues == 0:
        print("Status: ALL CLEAN")
    else:
        print("Status: ISSUES FOUND")
    print(f"{'='*60}\n")

    return total_issues


def generate_index(agents_dir, commands_dir, valid_tools):
    """Generate index.json from agent and command files."""
    agents = []
    commands = []

    if agents_dir.exists():
        for f in sorted(agents_dir.glob("*.md")):
            fm, _, _ = parse_frontmatter(f)
            if fm:
                agents.append({
                    "name": f.stem,
                    "description": fm.get("description", ""),
                    "mode": fm.get("mode", ""),
                    "path": str(f.relative_to(REPO_ROOT)),
                })

    if commands_dir.exists():
        for f in sorted(commands_dir.glob("*.md")):
            fm, _, _ = parse_frontmatter(f)
            if fm:
                commands.append({
                    "name": fm.get("name", f.stem),
                    "description": fm.get("description", ""),
                    "path": str(f.relative_to(REPO_ROOT)),
                })

    index = {
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_agents": len(agents),
        "total_commands": len(commands),
        "mcp_tools": len(valid_tools),
        "agents": agents,
        "commands": commands,
        "mcp_tool_names": sorted(valid_tools),
    }

    INDEX_JSON.write_text(json.dumps(index, indent=2) + "\n")
    print(f"  Generated {INDEX_JSON} ({len(agents)} agents, {len(commands)} commands, {len(valid_tools)} MCP tools)")


def main():
    parser = argparse.ArgumentParser(description="Validate agent files and generate index.json")
    parser.add_argument("--validate", "-v", action="store_true", help="Validate all agent/command files")
    parser.add_argument("--index", "-i", action="store_true", help="Generate index.json")
    parser.add_argument("--all", "-a", action="store_true", help="Run both validate and index")
    args = parser.parse_args()

    if not any(vars(args).values()):
        args.validate = True

    valid_tools = extract_mcp_tools(SERVER_PY)

    issues = 0
    if args.validate or args.all:
        issues = validate_all(AGENTS_DIR, COMMANDS_DIR, valid_tools)

    if args.index or args.all:
        generate_index(AGENTS_DIR, COMMANDS_DIR, valid_tools)

    sys.exit(1 if issues > 0 else 0)


if __name__ == "__main__":
    main()
