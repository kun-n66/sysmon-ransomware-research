# Run as administrator INSIDE the Windows 10 analysis VM.
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidatePattern('^COM[1-9][0-9]*$')][string]$Port = 'COM1',
    [ValidateRange(1,4000000)][int]$Baud = 115200,
    [ValidateRange(1,1024)][int]$QueueMiB = 64,
    [ValidateRange(1,1000000)][int]$QueueEvents = 8192
)
$ErrorActionPreference = 'Stop'
$release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
if ($release -lt 528040) { throw 'Install .NET Framework 4.8 or later in the guest first.' }
$sourceExe = Join-Path $PSScriptRoot 'SysmonSerialCollector.exe'
if (-not (Test-Path -LiteralPath $sourceExe)) { & (Join-Path $PSScriptRoot 'build.ps1') }
$installDir = Join-Path $env:ProgramFiles 'SysmonSerialCollector'
$logDir = Join-Path $env:ProgramData 'SysmonSerialCollector'
$taskName = 'SysmonSerialCollector'
$old = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($old) { Stop-ScheduledTask -TaskName $taskName; Start-Sleep -Seconds 2 }
New-Item -ItemType Directory -Force -Path $installDir,$logDir | Out-Null
Copy-Item -LiteralPath $sourceExe -Destination $installDir -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SysmonSerialCollector.exe.config') -Destination $installDir -Force
$exe = Join-Path $installDir 'SysmonSerialCollector.exe'
$log = Join-Path $logDir 'agent.log'
$arguments = '--port {0} --baud {1} --queue-mib {2} --queue-events {3} --log "{4}"' -f $Port,$Baud,$QueueMiB,$QueueEvents,$log
$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed and started $taskName. Log: $log"
Write-Host 'Verify collection, then shut down the VM and create/update the clean snapshot.'
