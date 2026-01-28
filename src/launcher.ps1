# HYTALE F2P - INSTANT LAUNCHER (Bootstrap)
# Run via:
# irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex

$ProgressPreference = 'SilentlyContinue'

# ======================================
# FORCE MODERN TLS (REQUIRED FOR GITHUB)
# ======================================
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor `
        ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13' ? [Net.SecurityProtocolType]::Tls13 : 0)
}
catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ======================================
# CONFIG
# ======================================
$LAUNCHER_URL = "https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/game%20launcher.bat"
$DEST = Join-Path $env:TEMP "game launcher.bat"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       HYTALE F2P - INSTANT LAUNCH" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Fetching latest Hytale Launcher..." -ForegroundColor Gray
Write-Host "      $LAUNCHER_URL" -ForegroundColor DarkGray

try {
    # ----------------------------------
    # DOWNLOAD
    # ----------------------------------
    Invoke-WebRequest `
        -Uri $LAUNCHER_URL `
        -OutFile $DEST `
        -UseBasicParsing `
        -TimeoutSec 30 `
        -ErrorAction Stop

    if (-not (Test-Path $DEST)) {
        throw "Launcher download failed (file missing)."
    }

    Write-Host "[OK] Launcher downloaded successfully." -ForegroundColor Green
    Write-Host "     Location: $DEST" -ForegroundColor DarkGray

    # ----------------------------------
    # EXECUTE
    # ----------------------------------
    Write-Host "`n[2/2] Launching Hytale..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1

    Start-Process `
        -FilePath "cmd.exe" `
        -ArgumentList "/c `"$DEST`"" `
        -WorkingDirectory $env:TEMP
}
catch {
    Write-Host "`n[ERROR] Failed to download or start launcher" -ForegroundColor Red
    Write-Host "        Reason: $($_.Exception.Message)" -ForegroundColor Gray

    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host " - Ensure TLS 1.2 is enabled" -ForegroundColor Yellow
    Write-Host " - raw.githubusercontent.com is reachable" -ForegroundColor Yellow
    Write-Host " - Firewall / ISP is not blocking GitHub" -ForegroundColor Yellow
    Write-Host " - Try running PowerShell as Administrator" -ForegroundColor Yellow

    pause
}
