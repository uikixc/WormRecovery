param(
    [string]$InstallDirectory = "$env:ProgramData\WormRecoveryCollector",
    [string]$Executable = (Join-Path $PSScriptRoot '../WormRecovery-Collector.exe')
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员身份在采集服务器上运行此脚本。'
}
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw '未找到采集服务程序。' }
$root = [IO.Path]::GetFullPath($InstallDirectory)
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '无法设置采集目录访问权限。' }
$target = Join-Path $root 'WormRecovery-Collector.exe'
$taskName = 'WormRecoveryDiagnosticsCollector'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw '采集任务已存在。请先停止现有任务，再按部署说明升级，避免覆盖正在运行的程序。'
}
Copy-Item -LiteralPath $Executable -Destination $target -Force
$data = Join-Path $root 'collector-data'
$config = Join-Path $data 'collector-server.json'
if (-not (Test-Path -LiteralPath $config)) {
    & $target init --directory $data
    if ($LASTEXITCODE -ne 0) { throw '初始化采集服务失败。' }
}
$action = New-ScheduledTaskAction -Execute $target -Argument ('serve --config "' + $config + '"') -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
if (-not (Get-NetFirewallRule -Name 'WormRecoveryCollector10888' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'WormRecoveryCollector10888' -DisplayName 'WormRecovery Diagnostics HTTPS 10888' -Direction Inbound -Protocol TCP -LocalPort 10888 -Action Allow -Program $target | Out-Null
}
Start-ScheduledTask -TaskName $taskName
Write-Host "采集任务已注册并启动。设备配置：$data\devices.enroll"
Write-Host '请妥善保管服务端密钥及管理授权；仅向使用者提供 devices.enroll。'
