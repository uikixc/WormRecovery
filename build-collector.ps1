param([string]$Python = "python", [string]$OutputDirectory = "")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'release\WormRecovery-Collector-1.8.2' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath (Join-Path $OutputDirectory 'WormRecovery-Collector.exe')) { throw 'A collector already exists at the output path. Choose a new build directory.' }
$runtimeData = @(& $Python (Join-Path $PSScriptRoot 'packaging_support.py'))
if ($LASTEXITCODE -ne 0) { throw 'Cannot locate Python runtime certificate resources.' }
& $Python -m PyInstaller --noconfirm --clean --onefile --noupx --console --name WormRecovery-Collector --distpath $OutputDirectory @runtimeData collector_entry.py
if ($LASTEXITCODE -ne 0) { throw 'Collector build failed.' }
Write-Host "Collector created: $OutputDirectory/WormRecovery-Collector.exe"
