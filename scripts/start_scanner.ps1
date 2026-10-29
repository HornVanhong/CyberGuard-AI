<#
.SYNOPSIS
    CyberGuard AI - Start Scanner Backend & Cloudflare Tunnel
.DESCRIPTION
    Launches the multi-engine Python scanner API on http://localhost:8000 and connects
    it to a Cloudflare Quick Tunnel so the Cloudflare Worker can reach all 12 engines.
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CyberGuard AI — Scanner Service & Cloudflare Tunnel" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Locate cloudflared
$cloudflaredPath = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
if (-not (Test-Path $cloudflaredPath)) {
    $cloudflaredCmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($cloudflaredCmd) {
        $cloudflaredPath = $cloudflaredCmd.Source
    } else {
        Write-Error "cloudflared.exe not found. Please install via: winget install --id Cloudflare.cloudflared -e"
        exit 1
    }
}
Write-Host " [OK] Found cloudflared: $cloudflaredPath" -ForegroundColor Green

# 2. Start Scanner API Service in Background
Write-Host "`n[1/2] Starting Python Scanner API on http://localhost:8000..." -ForegroundColor Yellow
$scannerProc = Start-Process -FilePath ".venv\Scripts\python.exe" -ArgumentList "-m", "app.api" -PassThru -NoNewWindow
Start-Sleep -Seconds 2

if ($scannerProc.HasExited) {
    Write-Error "Failed to start scanner API process."
    exit 1
}
Write-Host " [OK] Scanner API running (PID: $($scannerProc.Id))" -ForegroundColor Green

# 3. Start Cloudflare Tunnel
Write-Host "`n[2/2] Launching Cloudflare Tunnel (http://localhost:8000)..." -ForegroundColor Yellow
Write-Host " Look for your TryCloudflare URL below (e.g. https://xxx.trycloudflare.com)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    & $cloudflaredPath tunnel --url http://localhost:8000
}
finally {
    Write-Host "`nStopping Scanner API (PID: $($scannerProc.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $scannerProc.Id -Force -ErrorAction SilentlyContinue
}
