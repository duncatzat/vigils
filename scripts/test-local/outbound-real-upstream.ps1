# 出站闸门真上游冒烟(本地 / 远端编译机均可):前台起闸门 → 用无效 key 打真 Anthropic 端点 →
# 期望上游 401 被原样中继,且 healthz 显示请求体被改写(样本里有 ghp_ token)。不需要真凭据。
$ErrorActionPreference = "Continue"
$exe = Join-Path (Get-Location) "target\debug\vigil-hub.exe"
$listen = "127.0.0.1:8446"
$err = Join-Path (Get-Location) "outbound-serve.err"
$p = Start-Process -FilePath $exe -ArgumentList @("outbound", "serve", "--listen", $listen) -PassThru -NoNewWindow -RedirectStandardError $err
Start-Sleep -Seconds 2
try {
    $req = Join-Path (Get-Location) "outbound-req.json"
    Set-Content -Path $req -Value '{"model":"claude-sonnet-4-5","max_tokens":8,"messages":[{"role":"user","content":"token ghp_1234567890abcdef1234567890abcdef12345678"}]}' -NoNewline -Encoding ascii
    $body = Join-Path (Get-Location) "outbound-body.txt"
    $code = & curl.exe -s -o $body -w "%{http_code}" -X POST "http://$listen/anthropic/v1/messages" -H "x-api-key: sk-ant-invalid" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" --data-binary "@$req"
    Write-Output "STATUS=$code"
    Write-Output ("BODY=" + (Get-Content $body -Raw))
    $health = & curl.exe -s "http://$listen/vigil/healthz"
    Write-Output "HEALTH=$health"
    $blocked = & curl.exe -s -o $body -w "%{http_code}" -X POST "http://$listen/anthropic/v1/messages" -H "content-type: text/plain" --data-binary "raw"
    Write-Output "NONJSON_STATUS=$blocked"
    Remove-Item $req, $body -ErrorAction SilentlyContinue
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Write-Output "--- serve stderr ---"
    Get-Content $err -ErrorAction SilentlyContinue
    Remove-Item $err -ErrorAction SilentlyContinue
}
