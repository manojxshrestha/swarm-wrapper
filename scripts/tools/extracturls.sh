#!/bin/bash

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"
source "$(dirname "$0")/_env.sh"

usage() {
  echo "Usage: $0 -f <gospider_output_folder> -d <target_domain>"
  exit 1
}

while getopts ":f:d:" opt; do
  case $opt in
    f) FOLDER="$OPTARG" ;;
    d) DOMAIN="$OPTARG" ;;
    *) usage ;;
  esac
done

# Validate inputs
if [ -z "$FOLDER" ] || [ -z "$DOMAIN" ]; then
  usage
fi

ALL_URLS_FILE="${FOLDER}/allsubsurls.txt"
ALIVE_URLS_FILE="${FOLDER}/alivesubsurls.txt"
SUBDOMAINS_RAW="${FOLDER}/subdomains.txt"
ALIVE_SUBDOMAINS="${FOLDER}/alivesubdomains.txt"

EXCLUDE_EXT="(woff|woff2|ttf|eot|otf|png|svg|jpg|jpeg|gif|ico|bmp|webp|map)(\?.*)?$"

log_info "Extracting scoped URLs from $FOLDER for domain: $DOMAIN"

find "$FOLDER" -type f -exec cat {} + | \
grep -Eo 'https?://[^ ]+' | \
grep -i "$DOMAIN" | \
grep -viE "$EXCLUDE_EXT" | \
sed -e 's/[[:space:]]*$//' -e 's:/*$::' | \
sort -u > "$ALL_URLS_FILE"

log_ok "Saved filtered URLs to: $ALL_URLS_FILE"

# Check tools (soft fallback — probe sections skip if missing)
SKIP_DNSX=false; SKIP_HTTPX=false
command -v dnsx >/dev/null 2>&1 || { log_warn "dnsx not found — skipping subdomain probing"; SKIP_DNSX=true; }
command -v httpx >/dev/null 2>&1 || { log_warn "httpx not found — skipping URL probing"; SKIP_HTTPX=true; }

log_info "Extracting subdomains from URLs..."
cut -d '/' -f3 "$ALL_URLS_FILE" | sort -u > "${FOLDER}/temp_domains.txt"

if [ "$SKIP_DNSX" = false ] && [ "$SKIP_HTTPX" = false ]; then
  log_info "Probing for live subdomains..."
  httpx -l "${FOLDER}/temp_domains.txt" \
    -ports 80,443,8080,8443,8000,8888 \
    -status-code -mc 200,204,301,302,307,401,403,500 \
    -title -tech-detect -web-server \
    -threads 200 -silent -o "$SUBDOMAINS_RAW" 2>/dev/null

  cut -d ' ' -f1 "$SUBDOMAINS_RAW" > "$ALIVE_SUBDOMAINS" 2>/dev/null || true
  rm -f "$SUBDOMAINS_RAW"
  log_ok "Live subdomains saved to: $ALIVE_SUBDOMAINS"
fi

if [ "$SKIP_HTTPX" = false ]; then
  log_info "Probing for alive full URLs..."
  cat "$ALL_URLS_FILE" | httpx \
    -status-code -mc 200,204,301,302,307,401,403,500 \
    -title -tech-detect -web-server \
    -threads 200 -silent 2>/dev/null | \
  cut -d ' ' -f1 | sort -u > "$ALIVE_URLS_FILE"
  sed -i 's/\r$//' "$ALIVE_URLS_FILE" 2>/dev/null || true
  log_ok "Alive scoped URLs saved to: $ALIVE_URLS_FILE"
fi

# Cleanup
rm -f "${FOLDER}/temp_domains.txt"
