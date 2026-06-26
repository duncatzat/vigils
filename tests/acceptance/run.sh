#!/usr/bin/env bash
# Vigils release-acceptance orchestrator: downloads published artifacts and tests them
# as a real user across platforms, to catch packaging/distribution defects that local
# builds and CI cannot see. Usage:  ./run.sh <version>      (e.g. ./run.sh v0.4.0)
#
# FAIL-CLOSED gate: any phase that detects a defect propagates its exit code and makes
# the whole run exit non-zero. (Earlier `|| true` + trailing `rm` swallowed sub-script
# failures → the gate always "passed" → packaging defects didn't block release.)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/lib.sh"
VERSION="${1:?usage: run.sh <version, e.g. v0.4.0>}"; export VERSION
load_config; export REPO RUN_ML_MODEL

echo "######## Vigils acceptance — $REPO @ $VERSION ########"
FAILED=0
fail(){ echo ">>> \033[31mFAIL\033[0m: $*"; FAILED=$((FAILED+1)); }

echo; echo ">>> Phase 1: local artifact audit (no test machine required)"
bash "$HERE/local-audit.sh" || fail "local-audit (packaging/checksum/sig/arch/dylib/OTA)"

# Optional functional sweep against the published CLI on the local-audit host (if downloaded).
if [ -n "${VIGIL_FN_HUB:-}" ]; then
  echo; echo ">>> Phase 1b: functional sweep (local HUB=$VIGIL_FN_HUB)"
  HUB="$VIGIL_FN_HUB" bash "$HERE/functional-sweep.sh" || fail "functional-sweep (local)"
fi

run_unix(){
  local p=$1 t; t="$(plat_ssh_target "$p")"
  [ -z "$t" ] && { echo ">>> [$p] skipped (no SSH configured in config.env)"; return; }
  echo; echo ">>> Phase 2: [$p] runtime e2e on $t"
  pscp "$p" "$HERE/ml-e2e.sh" /tmp/vigil-ml-e2e.sh
  pscp "$p" "$HERE/daemon-regression.sh" /tmp/vigil-dreg.sh
  pscp "$p" "$HERE/functional-sweep.sh" /tmp/vigil-fn-sweep.sh
  pscp "$p" "$HERE/mcp_probe.py" /tmp/mcp_probe.py
  # 退出码必须传播(不被尾部 rm 吞):任一子脚本失败 → 本平台失败。每步 `|| rc=1`,
  # 单独 rm,最后 `exit $rc`。functional-sweep 复用 ml-e2e 落地的二进制(VIGIL_FN_HUB)。
  psh "$p" "rc=0; \
            VERSION=$VERSION REPO=$REPO RUN_ML_MODEL=$RUN_ML_MODEL VIGIL_FN_SWEEP=/tmp/vigil-fn-sweep.sh \
              bash /tmp/vigil-ml-e2e.sh || rc=1; \
            VERSION=$VERSION REPO=$REPO bash /tmp/vigil-dreg.sh || rc=1; \
            rm -f /tmp/vigil-ml-e2e.sh /tmp/vigil-dreg.sh /tmp/vigil-fn-sweep.sh /tmp/mcp_probe.py; \
            exit \$rc" || fail "[$p] runtime e2e"
}
run_unix linux
run_unix macos

WT="$(plat_ssh_target windows)"
if [ -n "$WT" ]; then
  echo; echo ">>> Phase 2: [windows] runtime e2e on $WT"
  scp -q -o BatchMode=yes $(plat_ssh_opts windows) "$HERE/win-acceptance.ps1" "$WT:C:/Users/Administrator/win-acceptance.ps1"
  ssh -o BatchMode=yes $(plat_ssh_opts windows) "$WT" \
    "powershell -NoProfile -ExecutionPolicy Bypass -File C:/Users/Administrator/win-acceptance.ps1 -Version $VERSION -Repo $REPO -RunMlModel $RUN_ML_MODEL" \
    || fail "[windows] runtime e2e"
else echo ">>> [windows] skipped (no SSH configured)"; fi

echo
if [ "$FAILED" = 0 ]; then
  printf '######## acceptance \033[32mPASSED\033[0m ########\n'
else
  printf '######## acceptance \033[31mFAILED\033[0m: %d phase(s) ########\n' "$FAILED"
fi
exit "$FAILED"
