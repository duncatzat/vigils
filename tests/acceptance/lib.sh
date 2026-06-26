#!/usr/bin/env bash
# Shared helpers for the Vigils release-acceptance suite. Source, don't execute.
set -u

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- result tracking ------------------------------------------------------
PASS_N=0; FAIL_N=0; FAILED=()
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS_N=$((PASS_N+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL_N=$((FAIL_N+1)); FAILED+=("$*"); }
info() { printf '  ---- %s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }
# assert "label" <expected> <actual>
asrt() { if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 (want=$2 got=$3)"; fi; }
suite_summary() {
  printf '\n========== SUMMARY: %d passed, %d failed ==========\n' "$PASS_N" "$FAIL_N"
  if [ "$FAIL_N" -gt 0 ]; then printf '  FAILED:\n'; for f in "${FAILED[@]}"; do printf '   - %s\n' "$f"; done; return 1; fi
  return 0
}

# --- config ---------------------------------------------------------------
load_config() {
  if [ -f "$SUITE_DIR/config.env" ]; then . "$SUITE_DIR/config.env"; else
    echo "FATAL: $SUITE_DIR/config.env not found (copy config.env.example)"; exit 2; fi
  : "${REPO:?REPO unset}"
  : "${RUN_ML_MODEL:=1}"
}

asset_url() { echo "https://github.com/$REPO/releases/download/$VERSION/$1"; }

# ssh/scp with per-platform opts. $1=plat (linux|macos|windows)
plat_ssh_target() { local v; v="$(echo "$1" | tr a-z A-Z)_SSH"; echo "${!v:-}"; }
plat_ssh_opts()   { local v; v="$(echo "$1" | tr a-z A-Z)_SSH_OPTS"; echo "${!v:-}"; }
psh()  { local p=$1; shift; local t; t="$(plat_ssh_target "$p")"; [ -z "$t" ] && return 9
         ssh -o BatchMode=yes -o ConnectTimeout=12 $(plat_ssh_opts "$p") "$t" "$@"; }
pscp() { local p=$1 src=$2 dst=$3; local t; t="$(plat_ssh_target "$p")"; [ -z "$t" ] && return 9
         scp -q -o BatchMode=yes $(plat_ssh_opts "$p") "$src" "$t:$dst"; }
