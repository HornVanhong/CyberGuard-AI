# CyberGuard AI - Start Scanner Backend and Cloudflare Tunnel

$Host.UI.RawUI.WindowTitle = "CyberGuard AI - Scanner and Tunnel"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CyberGuard AI - Scanner Service and Cloudflare Tunnel" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Locate cloudflared.exe
$cloudflaredPath = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
if (-not (Test-Path $cloudflaredPath)) {
    $found = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($found) {
        $cloudflaredPath = $found.Source
    } else {
        Write-Error "cloudflared.exe not found at $cloudflaredPath"
        exit 1
    }
}
Write-Host " [OK] Found cloudflared: $cloudflaredPath" -ForegroundColor Green

# 2. Check Python virtual environment
$pythonPath = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}

# 3. Start Python Scanner API in background
Write-Host "`n[1/2] Starting Python Scanner API on http://localhost:8000..." -ForegroundColor Yellow

$procInfo = New-Object System.Diagnostics.ProcessStartInfo
$procInfo.FileName = $pythonPath
$procInfo.Arguments = "-m app.api"
$procInfo.WorkingDirectory = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$procInfo.UseShellExecute = $false
$procInfo.EnvironmentVariables["CLAMAV_HOST"] = "127.0.0.1"
$procInfo.EnvironmentVariables["CLAMAV_PORT"] = "3310"

$scannerProc = [System.Diagnostics.Process]::Start($procInfo)
Start-Sleep -Seconds 2

if ($scannerProc.HasExited) {
    Write-Error "Failed to start scanner API process. Exit code: $($scannerProc.ExitCode)"
    exit 1
}
Write-Host " [OK] Scanner API running (PID: $($scannerProc.Id))" -ForegroundColor Green

# 4. Start Cloudflare Tunnel
Write-Host "`n[2/2] Launching Cloudflare Tunnel (http://localhost:8000)..." -ForegroundColor Yellow
Write-Host " Look for your TryCloudflare URL below (e.g. https://xxx.trycloudflare.com)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    & $cloudflaredPath tunnel --url http://localhost:8000
}
finally {
    Write-Host "`nStopping Scanner API..." -ForegroundColor Yellow
    if ($scannerProc -and -not $scannerProc.HasExited) {
        $scannerProc.Kill()
    }
}
