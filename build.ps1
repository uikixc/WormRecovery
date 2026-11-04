param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
function Invoke-Python {
    param([string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python command failed with exit code $LASTEXITCODE" }
}
Invoke-Python -Arguments @("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed", "--uac-admin", "--noupx", "--name", "WormRecovery", "--collect-all", "oletools", "--hidden-import", "olefile", "--hidden-import", "psutil", "--hidden-import", "winreg", "worm_recovery.py")
Invoke-Python -Arguments @("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console", "--uac-admin", "--noupx", "--name", "WormRecovery-CLI", "--collect-all", "oletools", "--hidden-import", "olefile", "--hidden-import", "psutil", "--hidden-import", "winreg", "cli_entry.py")
Write-Host "Build completed: $PSScriptRoot/dist"
