# Start host reception for a generated benign workload. Guest launch is manual.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('documents','archive','backup','reports','cleanup','mixed')][string]$Scenario,
    [string]$InterpreterHash,
    [string]$PythonExe = 'py.exe',
    [string]$OutputRoot = 'D:\SysmonBenignLogs\scripted-v1',
    [string]$PipeName = '\\.\pipe\sysmon-log',
    [switch]$Preview
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($InterpreterHash)) {
    $InterpreterHash = Read-Host 'SHA256 of the Windows PowerShell exe used to launch the workload INSIDE the guest'
}
if ([string]::IsNullOrWhiteSpace($InterpreterHash)) { throw 'Guest interpreter SHA256 is required.' }
$options = @{
    SoftwareName=('Scripted_' + $Scenario)
    SoftwareHash=$InterpreterHash
    PythonExe=$PythonExe
    OutputRoot=$OutputRoot
    PipeName=$PipeName
    WaitSeconds=300
    DrainTimeout=120
}
& (Join-Path $PSScriptRoot 'run_benign_realtime.ps1') @options -Preview:$Preview
