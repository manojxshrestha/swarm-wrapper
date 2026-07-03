# Tab Mode — Agent Switching

In OpenCode, pressing **Tab** cycles through **primary agents**. Only agents with `mode: all` or `mode: primary` appear in the Tab switcher.

## The Problem

18 pipeline agents now have `mode: all`, which makes them visible in Tab. The 57 `@hunt-*` agents remain `mode: subagent` (Tab-hidden, accessible via `@`).

## The Fix

Changed `mode: subagent` → `mode: all` in 12 existing agent files, and created 2 missing ones (`auth.md`, `osint.md`) with `mode: all`.

If no `mode` is specified, OpenCode defaults to `all`.

## Agents Changed

| Agent | File | Change |
|-------|------|--------|
| scope | `.swarm/agents/scope.md` | `subagent` → `all` |
| auth | `.swarm/agents/auth.md` | **Created** with `mode: all` |
| osint | `.swarm/agents/osint.md` | **Created** with `mode: all` |
| recon | `.swarm/agents/recon.md` | `subagent` → `all` |
| surface | `.swarm/agents/surface.md` | `subagent` → `all` |
| hunt | `.swarm/agents/hunt.md` | `subagent` → `all` |
| deepthink | `.swarm/agents/deepthink.md` | `subagent` → `all` |
| exploit | `.swarm/agents/exploit.md` | `subagent` → `all` |
| search | `.swarm/agents/search.md` | `subagent` → `all` |
| capture | `.swarm/agents/capture.md` | `subagent` → `all` |
| validate | `.swarm/agents/validate.md` | `subagent` → `all` |
| report | `.swarm/agents/report.md` | `subagent` → `all` |
| autopilot | `.swarm/agents/autopilot.md` | `subagent` → `all` |
| consult | `.swarm/agents/consult.md` | `subagent` → `all` |

## How Tab Works

- **Tab** cycles through agents with `mode: all` or `mode: primary`
- **@name** invokes any agent (including `mode: subagent`)
- `mode: all` = shows in **both** Tab and @-mention
- `mode: subagent` = @-mention only (hidden from Tab)
- `mode: primary` = Tab only

Specialized hunt agents (xss-hunter, sqli-hunter, etc.) remain `mode: subagent` — they're invoked automatically by pipeline agents or with `@name`, not cycled in Tab.
