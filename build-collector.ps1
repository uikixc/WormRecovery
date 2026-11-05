param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$runtimeData = @(& $Python (Join-Path $PSScriptRoot 'packaging_support.py'))
if ($LASTEXITCODE -ne 0) { throw 'Cannot locate Python runtime certificate resources.' }
& $Python -m PyInstaller --noconfirm --clean --onefile --noupx --console --name WormRecovery-Collector @runtimeData collector_entry.py
if ($LASTEXITCODE -ne 0) { throw 'Collector build failed.' }
Write-Host "Collector created: $PSScriptRoot/dist/WormRecovery-Collector.exe"
