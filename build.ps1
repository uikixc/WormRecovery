param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
function Invoke-Python {
    param([string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python command failed with exit code $LASTEXITCODE" }
}
$privateDist = Join-Path $PSScriptRoot 'build/embedded'
New-Item -ItemType Directory -Path $privateDist -Force | Out-Null
$collect = @('--collect-all', 'oletools', '--collect-all', 'pcodedmp', '--collect-all', 'yara_x', '--collect-all', 'autoit_ripper', '--collect-all', 'XLMMacroDeobfuscator', '--collect-all', 'defusedxml')
$runtimeData = @(& $Python (Join-Path $PSScriptRoot 'packaging_support.py'))
if ($LASTEXITCODE -ne 0) { throw 'Cannot locate Python runtime certificate resources.' }
$base = @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--noupx') + $runtimeData
Invoke-Python -Arguments ($base + @('--console', '--name', 'WormRecovery-Analysis', '--distpath', $privateDist) + $collect + @('analysis_entry.py'))
Invoke-Python -Arguments ($base + @('--console', '--uac-admin', '--name', 'WormRecovery-CLI', '--distpath', $privateDist) + $collect + @('--hidden-import', 'olefile', '--hidden-import', 'psutil', '--hidden-import', 'winreg', 'cli_entry.py'))
$analysis = Join-Path $privateDist 'WormRecovery-Analysis.exe'
$cli = Join-Path $privateDist 'WormRecovery-CLI.exe'
$engineAssets = Join-Path $PSScriptRoot 'build/engine-assets/engines'
if (-not (Test-Path -LiteralPath (Join-Path $engineAssets 'manifest.json'))) { throw 'Prepare verified offline engine assets before building.' }
Invoke-Python -Arguments ($base + @('--windowed', '--uac-admin', '--name', 'WormRecovery', '--add-binary', ($analysis + ':engines'), '--add-binary', ($cli + ':engines'), '--add-data', ($engineAssets + ':engines')) + $collect + @('--hidden-import', 'olefile', '--hidden-import', 'psutil', '--hidden-import', 'winreg', 'worm_recovery.py'))
Write-Host "Build completed: $PSScriptRoot/dist/WormRecovery.exe (single-file distribution)"
