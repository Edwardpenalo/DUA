param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$frontend = Join-Path $root "frontend"
$backend = Join-Path $root "backend"
$embedDist = Join-Path $backend "internal\webui\dist"
$exePath = Join-Path $backend "DUA.exe"
$issPath = Join-Path $root "installer\DUA_Setup.iss"

Write-Host "[1/5] Build frontend..."
Set-Location $frontend
npm run build

Write-Host "[2/5] Sync frontend dist to backend embedded assets..."
Set-Location $backend
if (Test-Path $embedDist) { Remove-Item $embedDist -Recurse -Force }
New-Item -ItemType Directory -Path $embedDist | Out-Null
Copy-Item (Join-Path $frontend "dist\*") $embedDist -Recurse -Force

Write-Host "[3/5] Build single EXE..."
go build -ldflags "-s -w" -o $exePath ./cmd/api

Write-Host "[4/5] Cleanup old executables..."
$old = @("app.exe", "api.exe", "dua-api.exe")
foreach ($f in $old) {
    $p = Join-Path $backend $f
    if (Test-Path $p) { Remove-Item $p -Force }
}

Write-Host "[5/5] Build installer (.iss) if Inno Setup is available..."
$innoCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
)

$iscc = $null
foreach ($c in $innoCandidates) {
    if (Test-Path $c) { $iscc = $c; break }
}

if (-not $iscc) {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { $iscc = $cmd.Source }
}

if ($iscc) {
    Push-Location (Join-Path $root "installer")
    & $iscc $issPath
    Pop-Location
    Write-Host "Installer generated at: installer\output\DUA-Setup.exe"
} else {
    Write-Warning "Inno Setup (ISCC.exe) not found. EXE built successfully at backend\DUA.exe"
    Write-Host "Install Inno Setup and rerun this script to generate DUA-Setup.exe"
}

Write-Host "Done."
