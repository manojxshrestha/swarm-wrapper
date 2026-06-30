#!/usr/bin/env bash
# =============================================================================
# dir_bruteforce.sh — AI-driven directory bruteforcing
#
# Usage:
#   dir_bruteforce.sh --plan <file>                    Execute scan plan
#   dir_bruteforce.sh --url <url> [options]            Single host scan
#
# Options (with --url):
#   --intent <name>       default|api|wordpress|java|oauth|iis|full|custom
#   --profile <name>      light|standard|deep (default: light)
#   --ext-profile <name>  php|java|dotnet|generic (deep only)
#   --wordlist <name>     Advanced: force specific wordlist (repeatable)
#   --rate <ms>           Request delay (default 0)
#   --dry-run             Print plan without executing
#   --force               Re-scan existing results
#   --engagement <id>     Engagement ID for WSTG tracking
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_env.sh"

BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WL_DIR="$BASE_DIR/wordlists/dirbust"
EVIDENCE_BASE=""  # set per-host during execution

# ── Intent → wordlist mapping ─────────────────────────────────────────────
declare -A INTENT_WL
INTENT_WL["default"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,sensitivejs.txt"
INTENT_WL["api"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,api-endpoints.txt,graphql-paths.txt,swagger-paths.txt,swaggerAPI.txt,swagger-wordlist.txt"
INTENT_WL["wordpress"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,wp-fuzz.txt"
INTENT_WL["java"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,Apache-Tomcat.txt"
INTENT_WL["oauth"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,oauth.txt"
INTENT_WL["iis"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,cgi-bin.txt"
INTENT_WL["full"]="common.txt,admin-panels.txt,admin-PATHS.txt,Sensitive-Dirs-Files.txt,backup.txt,api-endpoints.txt,graphql-paths.txt,swagger-paths.txt,swaggerAPI.txt,swagger-wordlist.txt,oauth.txt,wp-fuzz.txt,Apache-Tomcat.txt,cgi-bin.txt,business-logic-paths.txt,signup-PATHS.txt,endpoints.txt,kibana.txt,sensitivejs.txt,apac.txt,xml.txt,big.txt,pl.txt"

# ── Extension profiles ────────────────────────────────────────────────────
declare -A EXT_PROFILES
EXT_PROFILES["php"]=".php,.php3,.php4,.phtml,.bak,.old,.zip,.tar.gz"
EXT_PROFILES["java"]=".jsp,.jspx,.do,.action,.class,.bak,.old"
EXT_PROFILES["dotnet"]=".aspx,.ashx,.asmx,.config,.bak,.old"
EXT_PROFILES["generic"]=".bak,.old,.zip,.tar.gz,.txt,.sql,.json"

# ── Profile request budgets ───────────────────────────────────────────────
declare -A PROFILE_BUDGET
PROFILE_BUDGET["light"]=5000
PROFILE_BUDGET["standard"]=50000
PROFILE_BUDGET["deep"]=150000

# ── High-value path patterns (substring match) ──────────────────────────
CRITICAL_PATTERNS="\.git/|\.env|heapdump|backup\.zip|backup\.tar|dump\.sql|database\.sql|web\.config|app\.config|settings\.py|\.svn/|\.hg/config|phpinfo\.php|id_rsa|\.aws/credentials|\.npmrc|\.dockercfg|\.env\.production"
INTERESTING_PATTERNS="/admin|/graphql|/graphiql|/swagger|/api-docs|/actuator|/manager/html|/jmx-console|/server-status|/server-info|/oauth/|/login|/wp-admin|/wp-login|/api/|/console|\.well-known"

# ── Help ──────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage:
  $0 --plan <file>                    Execute scan plan (JSON)
  $0 --url <url> [options]            Single host scan

Options (with --url):
  --intent <name>       default|api|wordpress|java|oauth|iis|full|custom
  --profile <name>      light|standard|deep (default: light)
  --ext-profile <name>  php|java|dotnet|generic (deep only)
  --wordlist <name>     Force specific wordlist file (repeatable, custom intent)
  --rate <ms>           Request delay in ms (default 0)
  --dry-run             Print plan without executing
  --force               Re-scan existing results
  --engagement <id>     Engagement ID for tracking
EOF
  exit 0
}

# ── Logging ───────────────────────────────────────────────────────────────


# ── Resolve wordlist files for a given intent ──────────────────────────
resolve_wordlists() {
  local intent="$1"
  shift
  local custom_wls=("$@")
  local files=()

  if [ "$intent" = "custom" ]; then
    for wl in "${custom_wls[@]}"; do
      files+=("$WL_DIR/$wl")
    done
  else
    local wl_list="${INTENT_WL[$intent]:-${INTENT_WL[default]}}"
    IFS=',' read -ra names <<< "$wl_list"
    for name in "${names[@]}"; do
      files+=("$WL_DIR/$name")
    done
  fi

  # Filter to existing files
  local existing=()
  for f in "${files[@]}"; do
    if [ -f "$f" ]; then
      existing+=("$f")
    else
      log_warn "Wordlist not found: $f — skipping"
    fi
  done

  if [ ${#existing[@]} -eq 0 ]; then
    log_warn "No wordlists resolved for intent '$intent' — falling back to default"
    resolve_wordlists "default"
    return
  fi

  printf '%s\n' "${existing[@]}"
}

# ── Estimate total lines in wordlist files ────────────────────────────
estimate_requests() {
  local files=("$@")
  local total=0
  for f in "${files[@]}"; do
    if [ -f "$f" ]; then
      local count
      count=$(grep -cve '^\s*\(#\|$\)' "$f" 2>/dev/null || echo "0")
      total=$((total + count))
    fi
  done
  echo "$total"
}

# ── Check WAF via probe request ──────────────────────────────────────
check_waf() {
  local url="$1"
  local headers
  headers=$(curl -sI -o /dev/null -w "%{http_code}\n" "$url" 2>/dev/null || true)
  local code
  code=$(echo "$headers" | tail -1)
  # Simple WAF heuristics: 403/503 on root, or known header patterns
  # We'd need full headers for proper detection, but keep it light
  if [ "$code" = "403" ] || [ "$code" = "503" ]; then
    echo "suspected:waf_block_${code}"
    return 0
  fi
  echo ""
}

# ── Fingerprint an ffuf result entry ─────────────────────────────────
fingerprint_entry() {
  local json="$1"
  # Use (status, words, lines, length) as composite fingerprint
  python3 -c "
import json, sys
try:
    with open('$json') as f:
        data = json.load(f)
    results = data.get('results', [])
    for r in results:
        fp = {
            'url': r.get('url', ''),
            'status': r.get('status', 0),
            'words': r.get('words', 0),
            'lines': r.get('lines', 0),
            'length': r.get('length', 0),
            'path': r.get('input', {}).get('FUZZ', ''),
        }
        print(json.dumps(fp))
except Exception as e:
    print(json.dumps({'error': str(e)}), file=sys.stderr)
"
}

# ── Check if path matches critical or interesting patterns ────────────
classify_path() {
  local path="$1"
  local status="$2"
  local critical=0
  local interesting=0

  if echo "$path" | grep -qE "$CRITICAL_PATTERNS"; then
    critical=1
  fi
  if echo "$path" | grep -qE "$INTERESTING_PATTERNS"; then
    interesting=1
  fi

  echo "$critical|$interesting"
}

# ── Scan a single host ─────────────────────────────────────────────────
scan_host() {
  local host="$1"
  local intent="$2"
  local profile="$3"
  local ext_profile="$4"
  local rate_ms="$5"
  local dry_run="$6"
  local run_id="$7"
  local host_domain
  host_domain=$(echo "$host" | sed -E 's|https?://||' | sed 's|/.*$||')

  # Determine output directory
  local out_dir="${RECON_BASE}/${host_domain}/directories"
  local evi_dir="$out_dir/evidence/${host_domain}"
  rm -rf "$evi_dir"
  mkdir -p "$evi_dir"/{200,201,204,301,302,303,307,308,401,403,405,500,502,503}

  local meta_file="$evi_dir/scan_meta.json"
  local results_file="$evi_dir/results.json"
  local robots_file="$evi_dir/robots.txt"

  # Resolve wordlists (use CUSTOM_WORDLISTS if non-empty)
  if [ ${#CUSTOM_WORDLISTS[@]} -gt 0 ]; then
    mapfile -t wl_files < <(resolve_wordlists "custom" "${CUSTOM_WORDLISTS[@]}")
  else
    mapfile -t wl_files < <(resolve_wordlists "$intent")
  fi
  local wl_names=()
  for f in "${wl_files[@]}"; do
    wl_names+=("$(basename "$f")")
  done

  local est_requests
  est_requests=$(estimate_requests "${wl_files[@]}")
  local max_req="${PROFILE_BUDGET[$profile]:-5000}"

  if [ "$est_requests" -gt "$max_req" ]; then
    log_warn "Estimated requests ($est_requests) exceeds $profile budget ($max_req) — capped"
    est_requests=$max_req
  fi

  log_info "Host: $host | Intent: $intent | Profile: $profile | Est: ~${est_requests} reqs"

  if [ "$dry_run" = "true" ]; then
    echo "  Wordlists: ${wl_names[*]}"
    echo "  Ext profile: ${ext_profile:-none}"
    echo "  Output: $out_dir"
    return 0
  fi

  local start_ts
  start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local waf_result
  waf_result=$(check_waf "$host")

  # ── Check robots.txt ─────────────────────────────────────────────
  log_info "  Checking robots.txt + sitemap.xml..."
  for doc_path in robots.txt sitemap.xml sitemap-index.xml sitemap_index.xml sitemapindex.xml; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$host/$doc_path" 2>/dev/null || echo "000")
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
      local content
      content=$(curl -s "$host/$doc_path" 2>/dev/null || true)
      echo "--- $doc_path ($code) ---" >> "$robots_file"
      echo "$content" >> "$robots_file"
      echo "" >> "$robots_file"
      log_ok "    $host/$doc_path → $code"
    fi
  done

  # ── Run ffuf with each wordlist ──────────────────────────────────
  local all_results=()
  local rate_flag=""
  local total_429=0
  local total_requests=0
  local stopped_reason="completed"

  if [ -n "$rate_ms" ] && [ "$rate_ms" -gt 0 ]; then
    local req_per_sec=$((1000 / rate_ms))
    [ "$req_per_sec" -lt 1 ] && req_per_sec=1
    rate_flag="-rate $req_per_sec"
  fi

  for wl_file in "${wl_files[@]}"; do
    local wl_name
    wl_name=$(basename "$wl_file")
    local wl_count
    wl_count=$(grep -cve '^\s*\(#\|$\)' "$wl_file" 2>/dev/null || echo "0")
    local ffuf_out="$evi_dir/ffuf_${wl_name%.txt}.json"

    # Check budget
    if [ "$total_requests" -ge "$max_req" ]; then
      log_warn "  Max requests ($max_req) reached — stopping wordlist loop"
      stopped_reason="budget_exhausted"
      break
    fi

    local remaining=$((max_req - total_requests))
    local use_count=$wl_count
    [ "$use_count" -gt "$remaining" ] && use_count=$remaining

    log_info "  ffuf: $wl_name (${use_count} entries)..."

    # Clean wordlist — strip comments/blanks, truncate to budget
    local clean_wl
    clean_wl=$(mktemp /tmp/dirbust_XXXXXX.txt)
    grep -vE '^\s*(#|$)' "$wl_file" | head -"$use_count" > "$clean_wl"

    timeout 120 ffuf -u "$host/FUZZ" -w "$clean_wl" \
      -ac -o "$ffuf_out" -of json -s -timeout 10 "$rate_flag" || true

    rm -f "$clean_wl"

    # Parse results
    if [ -s "$ffuf_out" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        local entry_status
        entry_status=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',0))" 2>/dev/null || echo "0")
        if [ "$entry_status" = "429" ]; then
          total_429=$((total_429 + 1))
        fi
        all_results+=("$line")
      done < <(fingerprint_entry "$ffuf_out")

      local result_count
      result_count=$(python3 -c "import json; d=json.load(open('$ffuf_out')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
      total_requests=$((total_requests + use_count))
      log_ok "    → $result_count hits (${total_429} rate-limited)"
    fi

    # Check stop conditions
    if [ "$total_requests" -gt 0 ] && [ "$total_429" -gt 0 ]; then
      local pct_429=$((total_429 * 100 / total_requests))
      if [ "$pct_429" -gt 30 ]; then
        log_warn "  >30% of responses are 429 — rate limited, stopping"
        stopped_reason="rate_limited"
        break
      fi
    fi

    if [ "$total_requests" -ge "$max_req" ]; then
      stopped_reason="budget_exhausted"
      break
    fi
  done

  # ── Extension scan (only if ext_profile set and deep profile) ─────
  local ext_results=()
  if [ -n "$ext_profile" ] && [ "$profile" = "deep" ]; then
    local exts="${EXT_PROFILES[$ext_profile]:-}"
    if [ -n "$exts" ]; then
      local ext_wl="$WL_DIR/raft-medium-files.txt"
      if [ -f "$ext_wl" ]; then
        local ext_out="$evi_dir/ffuf_extensions.json"
        log_info "  Extension scan: $ext_profile ($exts)..."
        local clean_ext
        clean_ext=$(mktemp /tmp/dirbust_ext_XXXXXX.txt)
        grep -vE '^\s*(#|$)' "$ext_wl" > "$clean_ext"
        timeout 120 ffuf -u "$host/FUZZ" -w "$clean_ext" -e "$exts" \
          -ac -o "$ext_out" -of json -s -timeout 10 "$rate_flag" || true
        rm -f "$clean_ext"
        if [ -s "$ext_out" ]; then
          while IFS= read -r line; do
            [ -z "$line" ] && continue
            ext_results+=("$line")
          done < <(fingerprint_entry "$ext_out")
          local ext_count
          ext_count=$(python3 -c "import json; d=json.load(open('$ext_out')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
          log_ok "    → $ext_count extension hits"
        fi
      fi
    fi
  fi

  local end_ts
  end_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # ── Write scan_meta.json ──────────────────────────────────────────
  local wl_json="["
  local first=true
  for n in "${wl_names[@]}"; do
    $first || wl_json+=","
    wl_json+="\"$n\""
    first=false
  done
  wl_json+="]"

  cat > "$meta_file" <<METAEOF
{
  "schema_version": "1.0",
  "run_id": "$run_id",
  "host": "$host",
  "started": "$start_ts",
  "finished": "$end_ts",
  "intent": "$intent",
  "profile": "$profile",
  "ext_profile": ${ext_profile:-null},
  "wordlists": $wl_json,
  "request_count": $total_requests,
  "max_requests": $max_req,
  "stopped_reason": "$stopped_reason",
  "rate_limited": $( [ "$stopped_reason" = "rate_limited" ] && echo true || echo false ),
  "waf_suspected": $( [ -n "$waf_result" ] && echo true || echo false )
}
METAEOF
  log_ok "  scan_meta.json written ($total_requests requests, reason: $stopped_reason)"

  # ── Write results.json + per-status files ─────────────────────────
  {
    echo '['
    local first_entry=true
    for entry in "${all_results[@]}" "${ext_results[@]}"; do
      $first_entry || echo ','
      echo "$entry"
      first_entry=false
    done
    echo ']'
  } > "$results_file"

  # Also write per-status files
  for entry in "${all_results[@]}" "${ext_results[@]}"; do
    local status url path
    status=$(echo "$entry" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',0))" 2>/dev/null || echo "0")
    path=$(echo "$entry" | python3 -c "import json,sys; print(json.load(sys.stdin).get('path',''))" 2>/dev/null || echo "")
    local status_dir="$evi_dir/$status"
    [ -d "$status_dir" ] && echo "$entry" >> "$status_dir/entries.json"
  done

  log_ok "  Results: $results_file"

  # Signal active param discovery if new paths found
  local trigger_file="${RECON_BASE}/${host_domain}/.run_active_param"
  touch "$trigger_file"
  log_info "Trigger created: $trigger_file (active param discovery will run if enabled)"
}

# ── Generate aggregate reports ──────────────────────────────────────────
generate_reports() {
  local domain="$1"
  local out_dir="${RECON_BASE}/${domain}/directories"
  local evi_base="$out_dir/evidence"

  local critical_file="$out_dir/critical_exposure.txt"
  local interesting_file="$out_dir/interesting_surface.txt"
  local summary_file="$out_dir/results_summary.md"

  : > "$critical_file"
  : > "$interesting_file"

  log_info "Generating reports..."

  # Aggregate all evidence entries
  local all_entries_json="$out_dir/_all_entries.json"
  : > "$all_entries_json"
  {
    echo '['
    local first=true
    while IFS= read -r -d '' entry_file; do
      if [ -s "$entry_file" ]; then
        $first || echo ','
        cat "$entry_file"
        first=false
      fi
    done < <(find "$evi_base" -name 'entries.json' -type f -print0 2>/dev/null)
    echo ']'
  } > "$all_entries_json"

  # Classify and write critical/interesting
  python3 <<PYEOF 2>/dev/null || true
import json
try:
    with open("$all_entries_json") as f:
        entries = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    entries = []

critical = []
interesting = []
all_lines = []

for e in entries:
    path = e.get("path", "")
    status = e.get("status", 0)
    url = e.get("url", "")
    words = e.get("words", 0)
    lines = e.get("lines", 0)
    length = e.get("length", 0)

    line = f"{url} [{status}] words:{words} lines:{lines} bytes:{length}"
    all_lines.append(line)

    import re
    critical_pat = r'\.git/|\.env|heapdump|backup\.zip|backup\.tar|dump\.sql|database\.sql|web\.config|app\.config|settings\.py|\.svn/|\.hg/config|phpinfo\.php|id_rsa|\.aws/credentials|\.npmrc|\.dockercfg|\.env\.production'
    interesting_pat = r'/admin|/graphql|/graphiql|/swagger|/api-docs|/actuator|/manager/html|/jmx-console|/server-status|/server-info|/oauth/|/login|/wp-admin|/wp-login|/api/|/console|\.well-known'

    if re.search(critical_pat, path, re.IGNORECASE):
        critical.append(line)
    elif re.search(interesting_pat, path, re.IGNORECASE):
        interesting.append(line)

with open("$critical_file", "w") as f:
    f.write("# Critical Exposure\n# Format: url [status] words lines bytes\n")
    for line in critical:
        f.write(line + "\n")

with open("$interesting_file", "w") as f:
    f.write("# Interesting Surface\n# Format: url [status] words lines bytes\n")
    for line in interesting:
        f.write(line + "\n")

# Write summary
with open("$summary_file", "w") as f:
    f.write(f"# Directory Bruteforce Results: {domain}\n\n")
    f.write(f"## Summary\n")
    f.write(f"- Total entries: {len(entries)}\n")
    f.write(f"- Critical exposures: {len(critical)}\n")
    f.write(f"- Interesting surface: {len(interesting)}\n")

    if critical:
        f.write(f"\n## Critical Exposures\n")
        for line in critical:
            f.write(f"- {line}\n")

    if interesting:
        f.write(f"\n## Interesting Surface\n")
        for line in interesting[:20]:
            f.write(f"- {line}\n")
        if len(interesting) > 20:
            f.write(f"- ... and {len(interesting) - 20} more\n")

    if not critical and not interesting:
        f.write(f"\n## All Findings\n")
        for line in all_lines[:30]:
            f.write(f"- {line}\n")
        if len(all_lines) > 30:
            f.write(f"- ... and {len(all_lines) - 30} more\n")

    f.write(f"\n## Evidence\n")
    f.write(f"- Raw: evidence/<host>/results.json\n")
    f.write(f"- Per-status: evidence/<host>/<status_code>/entries.json\n")
PYEOF

  log_ok "Reports written: $out_dir/"
  log_ok "  critical_exposure.txt ($(grep -cve '^\s*\(#\|$\)' "$critical_file" 2>/dev/null || echo 0) entries)"
  log_ok "  interesting_surface.txt ($(grep -cve '^\s*\(#\|$\)' "$interesting_file" 2>/dev/null || echo 0) entries)"
  log_ok "  results_summary.md"

  rm -f "$all_entries_json"
}

# =========================================================================
# MAIN
# =========================================================================

[ $# -eq 0 ] && usage

MODE=""
URL=""
PLAN_FILE=""
INTENT="default"
PROFILE="light"
EXT_PROFILE=""
RATE_MS=""
DRY_RUN="false"
FORCE="false"
ENGAGEMENT=""
CUSTOM_WORDLISTS=()
RUN_ID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --plan)       shift; PLAN_FILE="$1"; MODE="plan" ;;
    --url)        shift; URL="$1"; MODE="url" ;;
    --intent)     shift; INTENT="$1" ;;
    --profile)    shift; PROFILE="$1" ;;
    --ext-profile) shift; EXT_PROFILE="$1" ;;
    --wordlist)   shift; CUSTOM_WORDLISTS+=("$1") ;;
    --rate)       shift; RATE_MS="$1" ;;
    --dry-run)    DRY_RUN="true" ;;
    --force)      FORCE="true" ;;
    --engagement) shift; ENGAGEMENT="$1" ;;
    --help|-h)    usage ;;
    *) log_err "Unknown option: $1"; usage ;;
  esac
  shift
done

if [ -z "$MODE" ]; then
  log_err "Missing --plan or --url"; usage
fi

# Check ffuf
if ! command -v ffuf &>/dev/null; then
  log_err "ffuf not found — install: go install github.com/ffuf/ffuf/v2@latest"
  exit 1
fi

: "${RECON_BASE:?RECON_BASE not set}"
[ ! -d "$WL_DIR" ] && log_err "Wordlist dir not found: $WL_DIR" && exit 1

# Generate run ID
RUN_ID=$(date -u +"%Y%m%d-%H%M%S")-$(openssl rand -hex 3 2>/dev/null || echo "000000")

# ── --plan mode ─────────────────────────────────────────────────────
if [ "$MODE" = "plan" ]; then
  if [ ! -f "$PLAN_FILE" ]; then
    log_err "Plan file not found: $PLAN_FILE"; exit 1
  fi

  log_info "Reading scan plan: $PLAN_FILE"

  # Parse plan and scan each entry
  python3 -c "
import json
with open('$PLAN_FILE') as f:
    data = json.load(f)
plans = data.get('plans', [])
if not plans:
    print('NO_PLANS')
else:
    for p in plans:
        host = p.get('host', '')
        intent = p.get('intent', 'default')
        profile = p.get('profile', 'light')
        ext_prof = p.get('ext_profile') or ''
        conf = p.get('confidence', 1.0)
        if conf < 0.5:
            print(f'SKIP_LOW_CONF|{host}|{intent}|{conf}')
        else:
            ext = ext_prof or ''
            print(f'SCAN|{host}|{intent}|{profile}|{ext}')
" | while IFS='|' read -r cmd rest; do
    case "$cmd" in
      NO_PLANS)
        log_warn "No plans in scan_plan.json — nothing to scan"
        ;;
      SKIP_LOW_CONF)
        log_info "  Skip: $rest"
        ;;
      SCAN)
        IFS='|' read -r host intent profile ext_prof <<< "$rest"
        scan_host "$host" "$intent" "$profile" "$ext_prof" "$RATE_MS" "$DRY_RUN" "$RUN_ID"
        ;;
    esac
  done

  # Generate aggregate reports — extract domain from plan
  domain_from_plan=$(python3 -c "
import json
with open('$PLAN_FILE') as f:
    data = json.load(f)
plans = data.get('plans', [])
for p in plans:
    h = p.get('host', '')
    if h:
        import re
        m = re.search(r'https?://([^/]+)', h)
        if m:
            print(m.group(1))
            break
" 2>/dev/null || echo "")

  if [ -n "$domain_from_plan" ]; then
    generate_reports "$domain_from_plan"
  fi
fi

# ── --url mode ──────────────────────────────────────────────────────
if [ "$MODE" = "url" ]; then
  if [ -z "$URL" ]; then
    log_err "--url requires a URL"; usage
  fi

  # URL-format cleanup
  case "$URL" in
    http://*|https://*) ;;
    *) URL="https://$URL" ;;
  esac

  if [ "$DRY_RUN" = "true" ]; then
    host_domain=$(echo "$URL" | sed -E 's|https?://||' | sed 's|/.*$||')
    out_dir="${RECON_BASE}/${host_domain}/directories"
    if [ ${#CUSTOM_WORDLISTS[@]} -gt 0 ]; then
      mapfile -t wl_files < <(resolve_wordlists "custom" "${CUSTOM_WORDLISTS[@]}")
    else
      mapfile -t wl_files < <(resolve_wordlists "$INTENT")
    fi
    est=$(estimate_requests "${wl_files[@]}")
    budget="${PROFILE_BUDGET[$PROFILE]:-5000}"
    [ "$est" -gt "$budget" ] && est=$budget

    echo ""
    echo "=== Dry Run ==="
    echo "Host:     $URL"
    echo "Intent:   $INTENT"
    echo "Profile:  $PROFILE"
    echo "Ext:      ${EXT_PROFILE:-none}"
    echo "Budget:   $budget requests"
    echo "Estimated: ~$est requests"
    echo "Wordlists:"
    for f in "${wl_files[@]}"; do
      echo "  - $(basename "$f") ($(wc -l < "$f" | tr -d ' ') lines)"
    done
    echo "Output:   $out_dir"
    echo ""
    exit 0
  fi

  scan_host "$URL" "$INTENT" "$PROFILE" "$EXT_PROFILE" "$RATE_MS" "$DRY_RUN" "$RUN_ID"

  host_domain=$(echo "$URL" | sed -E 's|https?://||' | sed 's|/.*$||')
  generate_reports "$host_domain"
fi

log_ok "dir_bruteforce complete"
