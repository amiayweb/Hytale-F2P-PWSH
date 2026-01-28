# HYTALE F2P - INSTANT LAUNCHER (Bootstrap)
# Run via:
# irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex

$ProgressPreference = 'SilentlyContinue'

# ==============================
# FORCE MODERN TLS (CRITICAL)
# ==============================
try {
    # Enable TLS 1.2 + TLS 1.3 (if supported)
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor `
        ([Enum]::GetValues([Net.SecurityProtocolType]) -contains 'Tls13' ? [Net.SecurityProtocolType]::Tls13 : 0)
}
catch {
    # Fallback: TLS 1.2 only
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ==============================
# CONFIG
# ==============================
$API_HOST  = "https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src"
$TARGET_BAT = "game launcher.bat"
$URL       = "$API_HOST/$($TARGET_BAT -replace ' ', '%20')"
$DEST      = Join-Path $env:TEMP $TARGET_BAT

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       HYTALE F2P - INSTANT LAUNCH" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Fetching latest Hytale Launcher..." -ForegroundColor Gray
Write-Host "      URL: $URL" -ForegroundColor DarkGray

try {
    # ------------------------------
    # DOWNLOAD
    # ------------------------------
    Invoke-WebRequest `
        -Uri $URL `
        -OutFile $DEST `
        -UseBasicParsing `
        -TimeoutSec 30 `
        -ErrorAction Stop

    if (-not (Test-Path $DEST)) {
        throw "Downloaded file missing after request."
    }

    Write-Host "[OK] Launcher downloaded successfully." -ForegroundColor Green
    Write-Host "     Location: $DEST" -ForegroundColor DarkGray

    # ------------------------------
    # EXECUTE
    # ------------------------------
    Write-Host "`n[2/2] Starting Hytale..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1

    # Run batch file in new cmd window (safer)
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$DEST`"" -WorkingDirectory $env:TEMP
}
catch {
    Write-Host "`n[ERROR] Failed to download or start launcher" -ForegroundColor Red
    Write-Host "        Reason: $($_.Exception.Message)" -ForegroundColor Gray

    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host " - Ensure GitHub is reachable" -ForegroundColor Yellow
    Write-Host " - Ensure TLS 1.2 is enabled on your system" -ForegroundColor Yellow
    Write-Host " - Try running PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host " - Corporate / ISP firewalls may block raw.githubusercontent.com" -ForegroundColor Yellow

    pause
}
