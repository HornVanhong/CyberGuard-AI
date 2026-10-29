<#
.SYNOPSIS
    CyberGuard AI - Telegram Bot API Webhook Setup & Verification Script
.DESCRIPTION
    Safely inspects, registers, or deletes the Telegram Bot API Webhook for CyberGuard AI
    pointing to the Cloudflare Worker. Never echoes or prints sensitive tokens.
.EXAMPLE
    .\scripts\setup_webhook.ps1
#>

[CmdletBinding()]
param(
    [string]$WorkerUrl = "https://telegram-scan-bot.vanhonghorn37.workers.dev/"
)

# Set UTF-8 encoding for console output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Mask-Secret([string]$Secret) {
    if ([string]::IsNullOrWhiteSpace($Secret) -or $Secret.Length -lt 8) {
        return "[REDACTED]"
    }
    return $Secret.Substring(0, 4) + "..." + $Secret.Substring($Secret.Length - 4)
}

function Get-SecureInput([string]$PromptText, [string]$EnvVarName) {
    # Check if available in environment
    $existing = [System.Environment]::GetEnvironmentVariable($EnvVarName)
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        Write-Host " [OK] Using $EnvVarName from environment ($(Mask-Secret $existing))" -ForegroundColor Cyan
        return $existing
    }

    Write-Host "$PromptText" -ForegroundColor Yellow -NoNewline
    $secure = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        return $plain.Trim()
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CyberGuard AI - Cloudflare Worker Webhook Manager" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Worker Target: $WorkerUrl" -ForegroundColor Gray
Write-Host ""

# 1. Obtain Bot Token securely
$botToken = Get-SecureInput -PromptText "Enter Telegram Bot Token: " -EnvVarName "TELEGRAM_BOT_TOKEN"
if ([string]::IsNullOrWhiteSpace($botToken)) {
    Write-Error "Bot token cannot be empty."
    exit 1
}

# 2. Check Worker Health Endpoint
Write-Host "`n[1/3] Testing Worker Health Endpoint ($WorkerUrl)..." -ForegroundColor Yellow
try {
    $healthRes = Invoke-RestMethod -Uri $WorkerUrl -Method GET -TimeoutSec 10
    if ($healthRes.status -eq "online") {
        Write-Host " [OK] Worker is ONLINE!" -ForegroundColor Green
        Write-Host "      Service: $($healthRes.service)" -ForegroundColor Gray
        Write-Host "      Gemini AI: $($healthRes.gemini_ai)" -ForegroundColor Gray
        Write-Host "      Scanner Service: $($healthRes.scanner_service)" -ForegroundColor Gray
    } else {
        Write-Host " [WARN] Worker responded, but status was: $($healthRes.status)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host " [WARN] Could not reach worker health endpoint: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "        Ensure the Worker has been deployed to Cloudflare." -ForegroundColor Gray
}

# 3. Action Menu
Write-Host "`n[2/3] Select Webhook Operation:" -ForegroundColor Yellow
Write-Host " 1. Inspect current Webhook info (getWebhookInfo)"
Write-Host " 2. Register / Update Webhook (setWebhook)"
Write-Host " 3. Delete Webhook (deleteWebhook)"
Write-Host " 4. Exit"
$choice = Read-Host "Choose [1-4]"

$telegramBase = "https://api.telegram.org/bot$botToken"

switch ($choice) {
    "1" {
        Write-Host "`nInspecting Webhook configuration via Telegram Bot API..." -ForegroundColor Yellow
        try {
            $infoRes = Invoke-RestMethod -Uri "$telegramBase/getWebhookInfo" -Method GET -TimeoutSec 15
            if ($infoRes.ok) {
                Write-Host "`n[Telegram Webhook Status]" -ForegroundColor Green
                Write-Host " URL:                     $($infoRes.result.url)"
                Write-Host " Custom Certificate:     $($infoRes.result.has_custom_certificate)"
                Write-Host " Pending Update Count:   $($infoRes.result.pending_update_count)"
                Write-Host " Max Connections:        $($infoRes.result.max_connections)"
                Write-Host " Allowed Updates:        $($infoRes.result.allowed_updates -join ', ')"
                if ($infoRes.result.last_error_date) {
                    Write-Host " Last Error Date:        $([DateTimeOffset]::FromUnixTimeSeconds($infoRes.result.last_error_date).LocalDateTime)" -ForegroundColor Red
                    Write-Host " Last Error Message:     $($infoRes.result.last_error_message)" -ForegroundColor Red
                }
                if ($infoRes.result.last_synchronization_error_date) {
                    Write-Host " Last Sync Error Date:   $([DateTimeOffset]::FromUnixTimeSeconds($infoRes.result.last_synchronization_error_date).LocalDateTime)" -ForegroundColor Red
                }
            } else {
                Write-Host "Failed to get webhook info: $($infoRes.description)" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Error contacting Telegram API: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    "2" {
        $secretToken = Get-SecureInput -PromptText "`nEnter Telegram Webhook Secret Token (TELEGRAM_WEBHOOK_SECRET): " -EnvVarName "TELEGRAM_WEBHOOK_SECRET"
        if ([string]::IsNullOrWhiteSpace($secretToken)) {
            Write-Error "Secret token cannot be empty."
            exit 1
        }

        $dropPending = Read-Host "Drop pending updates? (Y/n) [Recommended: Y]"
        $dropBool = if ($dropPending -eq "n" -or $dropPending -eq "N") { $false } else { $true }

        Write-Host "`nRegistering Webhook with Telegram API..." -ForegroundColor Yellow
        $payload = @{
            url = $WorkerUrl
            secret_token = $secretToken
            max_connections = 40
            allowed_updates = @("message", "callback_query")
            drop_pending_updates = $dropBool
        } | ConvertTo-Json

        try {
            $setRes = Invoke-RestMethod -Uri "$telegramBase/setWebhook" -Method POST -ContentType "application/json" -Body $payload -TimeoutSec 15
            if ($setRes.ok) {
                Write-Host "`n [SUCCESS] Webhook registered successfully!" -ForegroundColor Green
                Write-Host " Description: $($setRes.description)" -ForegroundColor Gray
                Write-Host " Secret token set: [CONFIGURED]" -ForegroundColor Gray
            } else {
                Write-Host "`n [FAILED] Telegram rejected setWebhook: $($setRes.description)" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "`n [ERROR] Request failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    "3" {
        $dropPending = Read-Host "`nDrop pending updates when deleting? (y/N)"
        $dropBool = if ($dropPending -eq "y" -or $dropPending -eq "Y") { $true } else { $false }

        Write-Host "Removing webhook from Telegram..." -ForegroundColor Yellow
        $payload = @{
            drop_pending_updates = $dropBool
        } | ConvertTo-Json

        try {
            $delRes = Invoke-RestMethod -Uri "$telegramBase/deleteWebhook" -Method POST -ContentType "application/json" -Body $payload -TimeoutSec 15
            if ($delRes.ok) {
                Write-Host "`n [SUCCESS] Webhook removed: $($delRes.description)" -ForegroundColor Green
            } else {
                Write-Host "`n [FAILED] $($delRes.description)" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "`n [ERROR] Request failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    default {
        Write-Host "Exiting." -ForegroundColor Gray
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
