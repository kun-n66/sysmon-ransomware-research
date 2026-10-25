#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName 'SysmonSerialCollector' -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName 'SysmonSerialCollector'
    Unregister-ScheduledTask -TaskName 'SysmonSerialCollector' -Confirm:$false
}
Write-Host 'Startup task removed. Program files and diagnostic logs retained.'
