# HYTALE F2P - INSTANT LAUNCHER (Bootstrap)
# Run via:
# irm https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/launcher.ps1 | iex

$ProgressPreference = 'SilentlyContinue'

# ---------------- TLS FIX (PowerShell 5.1 compatible) ----------------
try {
    $tls = [Net.SecurityProtocolType]::Tls12

    # Add TLS 1.3 only if the enum exists (PS 7+ / newer .NET)
    if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
        $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
    }

    [Net.ServicePointManager]::SecurityProtocol = $tls
}
catch {
    # Fail silently – TLS 1.2 is usually enough for GitHub
}

# ---------------- CONFIG ----------------
$URL  = "https://raw.githubusercontent.com/T03ty/Hytale-F2P-PWSH/refs/heads/main/src/game%20launcher.bat"
$DEST = Join-Path $env:TEMP "game launcher.bat"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       HYTALE F2P - INSTANT LAUNCH" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Fetching latest Hytale Launcher..." -ForegroundColor Gray

try {
    Invoke-WebRequest -Uri $URL -OutFile $DEST -UseBasicParsing

    Write-Host "[OK] Launcher downloaded successfully." -ForegroundColor Green
    Write-Host "[2/2] Starting Hytale..." -ForegroundColor Cyan

    Start-Sleep -Seconds 1

    & $DEST
}
catch {
    Write-Host "[ERROR] Failed to download launcher." -ForegroundColor Red
    Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host "`nTip: Check your internet connection or GitHub availability." -ForegroundColor Yellow
    pause
}
