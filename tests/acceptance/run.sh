#!/usr/bin/env bash
# Vigils release-acceptance orchestrator: downloads published artifacts and tests them
# as a real user across platforms, to catch packaging/distribution defects that local
# builds and CI cannot see. Usage:  ./run.sh <version>      (e.g. ./run.sh v0.4.0)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/lib.sh"
VERSION="${1:?usage: run.sh <version, e.g. v0.4.0>}"; export VERSION
load_config; export REPO RUN_ML_MODEL

echo "######## Vigils acceptance — $REPO @ $VERSION ########"

echo; echo ">>> Phase 1: local artifact audit (no test machine required)"
bash "$HERE/local-audit.sh" || true

run_unix(){
  local p=$1 t; t="$(plat_ssh_target "$p")"
  [ -z "$t" ] && { echo ">>> [$p] skipped (no SSH configured in config.env)"; return; }
  echo; echo ">>> Phase 2: [$p] runtime e2e on $t"
  pscp "$p" "$HERE/ml-e2e.sh" /tmp/vigil-ml-e2e.sh
  pscp "$p" "$HERE/daemon-regression.sh" /tmp/vigil-dreg.sh
  psh "$p" "VERSION=$VERSION REPO=$REPO RUN_ML_MODEL=$RUN_ML_MODEL bash /tmp/vigil-ml-e2e.sh; \
            VERSION=$VERSION REPO=$REPO bash /tmp/vigil-dreg.sh; rm -f /tmp/vigil-ml-e2e.sh /tmp/vigil-dreg.sh"
}
run_unix linux
run_unix macos

WT="$(plat_ssh_target windows)"
if [ -n "$WT" ]; then
  echo; echo ">>> Phase 2: [windows] runtime e2e on $WT"
  scp -q -o BatchMode=yes $(plat_ssh_opts windows) "$HERE/win-acceptance.ps1" "$WT:C:/Users/Administrator/win-acceptance.ps1"
  ssh -o BatchMode=yes $(plat_ssh_opts windows) "$WT" \
    "powershell -NoProfile -ExecutionPolicy Bypass -File C:/Users/Administrator/win-acceptance.ps1 -Version $VERSION -Repo $REPO -RunMlModel $RUN_ML_MODEL"
else echo ">>> [windows] skipped (no SSH configured)"; fi

echo; echo "######## acceptance run complete ########"
