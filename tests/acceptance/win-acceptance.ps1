param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$Repo, [int]$RunMlModel = 1)
# Windows runtime e2e for a published CLI ML variant. Env-SAFE: snapshots/restores
# daemon.json and removes only artifacts this run created (NTFS is case-insensitive:
# Vigil == vigil — never blind-delete the shared dir).
$ErrorActionPreference='Continue'; $ProgressPreference='SilentlyContinue'
$script:P=0; $script:F=0
function ok($m){ Write-Host "  PASS $m"; $script:P++ }
function no($m){ Write-Host "  FAIL $m"; $script:F++ }

$vigilDir="$env:LOCALAPPDATA\Vigil"; $dj="$vigilDir\daemon.json"
$djBak    = if (Test-Path $dj) { Get-Content $dj -Raw } else { $null }
$preVigil = Test-Path $vigilDir
$preModel = Test-Path "$vigilDir\models\privacy-filter-0.5.1"
Get-Process vigil-hub -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$env:VIGIL_LANG="en"   # pin assertions to English output regardless of system locale
$sbx="$env:TEMP\vigil-acc-win"; Remove-Item -Recurse -Force $sbx -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $sbx | Out-Null; Set-Location $sbx

try {
  Write-Host "### windows runtime e2e: $Version ###"
  curl.exe -fsSL -o ml.zip "https://github.com/$Repo/releases/download/$Version/vigils-cli-ml-windows-x64.zip"
  Expand-Archive -Force ml.zip ml
  $hub="$sbx\ml\vigil-hub.exe"
  $verExp = "vigil-hub " + ($Version -replace '^v','')
  if ((& $hub --version) -eq $verExp) { ok "version == $verExp" } else { no "version: $(& $hub --version)" }
  if (Test-Path "$sbx\ml\onnxruntime.dll") { ok "ORT dll bundled exe-adjacent" } else { no "onnxruntime.dll missing" }
  Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class L{[DllImport("kernel32",SetLastError=true,CharSet=CharSet.Unicode)]public static extern IntPtr LoadLibrary(string p);
 public static bool T(string p){return LoadLibrary(p)!=IntPtr.Zero;}}
"@
  if ([L]::T("$sbx\ml\onnxruntime.dll")) { ok "onnxruntime.dll loads (PE + VC++ runtime deps)" } else { no "onnxruntime.dll LoadLibrary failed err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }

  if ($RunMlModel -eq 1) {
    & $hub model install --privacy 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { ok "model install --privacy (turnkey download)" } else { no "model install FAILED" }
  }
  $d = Start-Process $hub -ArgumentList 'daemon','start' -PassThru -WindowStyle Hidden -RedirectStandardOutput "$sbx\d.out" -RedirectStandardError "$sbx\d.err"
  $up=$false; for($i=0;$i -lt 40;$i++){ Start-Sleep 1; if ((& $hub daemon status 2>&1|Out-String) -match 'running \(pid'){$up=$true;break}; if($d.HasExited){break} }
  if ($up) { ok "daemon reachable via R1 (named-pipe)" } else { no "daemon unreachable"; Get-Content "$sbx\d.out","$sbx\d.err" -ErrorAction SilentlyContinue }
  & $hub daemon stop 2>&1 | Out-Null
  if (-not $d.HasExited){ Stop-Process -Id $d.Id -Force -ErrorAction SilentlyContinue }
}
finally {
  if ($null -ne $djBak){ Set-Content -Path $dj -Value $djBak -NoNewline } elseif (Test-Path $dj){ Remove-Item $dj -Force }
  if (-not $preVigil) { Remove-Item -Recurse -Force $vigilDir -ErrorAction SilentlyContinue }
  elseif (-not $preModel) { Remove-Item -Recurse -Force "$vigilDir\models\privacy-filter-0.5.1" -ErrorAction SilentlyContinue }
  Remove-Item -Recurse -Force $sbx -ErrorAction SilentlyContinue
}
Write-Host ""; Write-Host "### result: $script:P passed, $script:F failed (windows) ###"
if ($script:F -gt 0){ exit 1 }
