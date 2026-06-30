#!/usr/bin/env bash
# =============================================================================
# pipeline.sh — Swarm 12-Phase Security Testing Pipeline (Script-Driven)
#
# Runs each phase in strict order. The AI never decides "what's next" —
# this script does. The AI is called ONLY for analysis within each phase.
#
# Usage:
#   bash scripts/pipeline.sh <domain> [phase-start] [phase-end] [--resume] [--timeout N]
#   SKIP_LIST=tool1,tool2 bash scripts/pipeline.sh ...
#   PIPELINE_TIMEOUT=1200 bash scripts/pipeline.sh ...
#
# Examples:
#   bash scripts/pipeline.sh target.com                 # Run all 12 phases
#   bash scripts/pipeline.sh target.com 1-4             # Run phases 1 through 4
#   bash scripts/pipeline.sh target.com 3               # Run phase 3 only
#   bash scripts/pipeline.sh target.com 6 10            # Run phases 6 through 10
#   bash scripts/pipeline.sh target.com --resume        # Skip already-completed phases
#   bash scripts/pipeline.sh target.com --timeout 1200  # 20min per phase
#   SKIP_LIST=gospider,katana bash scripts/pipeline.sh target.com 4  # Skip slow tools
# =============================================================================

set -euo pipefail

# ── Resolve paths ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
source "$TOOLS_DIR/_env.sh"

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${CYAN}  Phase $1: $2${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

# ── Argument parsing ────────────────────────────────────────────────────────
# FIX #5: Re-ordered arg parsing — collect all args before consuming $1 for TARGET
RESUME=false
POSITIONAL=()
for arg; do
  case "$arg" in
    --resume) RESUME=true ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

: "${RECON_BASE:?RECON_BASE not set}"
TARGET="${POSITIONAL[0]:?Usage: $0 <domain> [phase-start] [phase-end]}"
if [ "$RESUME" = true ] && [ -f "${RECON_BASE}/${TARGET}/.pipeline_checkpoint" ]; then
  PHASE_START="resume"
else
  PHASE_START="${POSITIONAL[1]:-0}"
fi
PHASE_END="${POSITIONAL[2]:-${POSITIONAL[1]:-12}}"

# Handle hyphenated range (e.g. "4-8")
if [[ "$PHASE_START" != "resume" ]] && [[ "$PHASE_START" == *-* ]]; then
  PHASE_END="${PHASE_START#*-}"
  PHASE_START="${PHASE_START%-*}"
fi

# Determine actual start phase
if [ "$PHASE_START" = "resume" ]; then
  CACHED_PHASES=$(grep -o 'phase_[0-9][0-9]*' "${RECON_BASE}/${TARGET}/.pipeline_checkpoint" 2>/dev/null | sed 's/phase_//' | sort -n | tail -1)
  if [ -n "$CACHED_PHASES" ]; then
    PHASE_START=$((CACHED_PHASES + 1))
    info "Resuming from Phase $PHASE_START (last completed: Phase $CACHED_PHASES)"
  else
    PHASE_START=0
    info "No checkpoint found — starting from Phase 0"
  fi
fi

# Normalize: start cannot exceed end
[ "$PHASE_START" -gt "$PHASE_END" ] && PHASE_END="$PHASE_START"

OUT_DIR="${RECON_BASE}/${TARGET}"
mkdir -p "$OUT_DIR"

# Checkpoint file for resume support
CHECKPOINT_FILE="$OUT_DIR/.pipeline_checkpoint"
CHECKPOINT_TMP="${CHECKPOINT_FILE}.tmp.$$"

# Atomic checkpoint write — clean up temp file on interrupt
mark_checkpoint() {
    local num="$1"
    grep -qx "phase_$num" "$CHECKPOINT_FILE" 2>/dev/null && return
    {
        cat "$CHECKPOINT_FILE" 2>/dev/null
        echo "phase_$num"
    } > "$CHECKPOINT_TMP" && mv "$CHECKPOINT_TMP" "$CHECKPOINT_FILE"
}
trap 'rm -f "$CHECKPOINT_TMP"; echo ""; warn "Pipeline interrupted — checkpoint may be incomplete"; exit 1' INT TERM

# Suppress phase ordering gate when running a single phase standalone
if [ "$PHASE_START" = "$PHASE_END" ]; then
  export SINGLE_PHASE_MODE=1
fi

# ── Phase definitions ───────────────────────────────────────────────────────
source "$TOOLS_DIR/_phase_defs.sh"

# ── Phase runner (deprecated — logic inlined below) ─────────────────────────

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           Swarm Pipeline — $TARGET${NC}"
echo -e "${CYAN}║           Phases $PHASE_START → $PHASE_END${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Validate environment
if [ -f "$TOOLS_DIR/validate-env.sh" ]; then
  bash "$TOOLS_DIR/validate-env.sh"
fi

# Run requested phases
for entry in "${PHASES[@]}"; do
  num="${entry%%:*}"
  rest="${entry#*:}"
  name="${rest%%:*}"
  desc="${rest#*:}"

  if [ "$num" -ge "$PHASE_START" ] && [ "$num" -le "$PHASE_END" ]; then
    # Condition checks
    if [ "$num" -eq 7 ] && [ "$PHASE_START" -ne 7 ]; then
      # Phase 7 (deepthink): skip only if hunt produced real candidate output.
      # P-M1: previously counted files in hunt/ (which holds dispatch_list.json,
      # coverage_matrix.csv and *.log — dispatch artifacts, NOT findings), with
      # a find `-o` precedence bug that ignored *.txt. Count non-empty files in
      # the actual hunt output dirs (params/, secrets/) instead.
      findings_count=0
      for _hd in "$OUT_DIR/params" "$OUT_DIR/secrets"; do
        if [ -d "$_hd" ]; then
          _n=$(find "$_hd" -type f -size +0c 2>/dev/null | wc -l)
          findings_count=$((findings_count + _n))
        fi
      done
      if [ "$findings_count" -gt 0 ]; then
        info "Phase 7 (deepthink): skipped — hunt produced findings"
        mark_checkpoint "7"
        # P-L4: record the gate marker for the skipped phase so the ordering
        # check on the next phase does not spuriously fail/warn.
        mkdir -p "$OUT_DIR/.gates" && date -Iseconds > "$OUT_DIR/.gates/phase7_done"
        continue
      fi
    fi
    if [ "$num" -eq 9 ] && [ "$PHASE_START" -ne 9 ]; then
      # Phase 9 (search): skip if exploit already completed
      if grep -qx "phase_8" "$CHECKPOINT_FILE" 2>/dev/null; then
        info "Phase 9 (search): skipped — exploit already completed"
        mark_checkpoint "9"
        # P-L4: record the gate marker for the skipped phase.
        mkdir -p "$OUT_DIR/.gates" && date -Iseconds > "$OUT_DIR/.gates/phase9_done"
        continue
      fi
    fi
    # ── Run phase ────────────────────────────────────────────────
    # NOTE: this loop runs at top level (not inside a function), so `local`
    # is invalid here and aborts the script under `set -e`. Use a plain var.
    _script="$TOOLS_DIR/phase-${name}.sh"
    if [ "$RESUME" = true ] && [ -f "$CHECKPOINT_FILE" ]; then
      if grep -qx "phase_$num" "$CHECKPOINT_FILE" 2>/dev/null; then
        info "Skipping Phase $num ($name) — already completed (--resume)"
        continue
      fi
    fi
    step "$num" "$name — $desc"
    if [ ! -f "$_script" ]; then
      err "Script not found: $_script"
      warn "Run the phase manually: docs/pipeline.md#$name"
      continue
    fi
    if [ ! -x "$_script" ]; then
      chmod +x "$_script"
    fi
    if bash "$_script" "$TARGET" "$OUT_DIR"; then
      ok "Phase $num ($name) completed"
      mark_checkpoint "$num"
      if [ -n "${ENGAGEMENT_ID:-}" ]; then
        bash "$SCRIPT_DIR/findings.sh" log "$ENGAGEMENT_ID" "pipeline" \
          "phase_${num}_${name}" "completed" 2>/dev/null || true
      fi
    else
      rc=$?   # P-L3: capture immediately rather than relying on a later $?
      warn "Phase $num ($name) exited with code $rc"
    fi
    if [ -f "$TOOLS_DIR/phase_gate.sh" ]; then
      # P-H1: honour the gate's exit code so an enforced gate (Phase 6 coverage,
      # or ordering when STRICT_GATES=1) actually stops the pipeline.
      if ! bash "$TOOLS_DIR/phase_gate.sh" "$num" "$TARGET"; then
        err "Phase $num gate failed — stopping pipeline"
        exit 1
      fi
    fi
  fi
done

info "Pipeline complete (phases $PHASE_START-$PHASE_END)"
ok "Output in: $OUT_DIR"
echo ""
echo "  Steps:"
echo "    1. Run: bash scripts/tools/todo-export.sh $TARGET"
echo "    2. Feed output into todowrite to mark phases as ✅"
echo "    3. Call AI agent: @surface (surface), @hunt (hunt)"
