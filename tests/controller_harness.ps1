# Calls the real controller with a mock executable, a dummy VMX, and synthetic telemetry.
[CmdletBinding()]
param([string]$HarnessExe,[string]$PythonExe,[string]$TestDirectory,[string]$PipeName,[string]$ControllerRoot)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ($ControllerRoot) { $root = $ControllerRoot }
$dummyVmx = Join-Path $TestDirectory 'dummy.vmx'
$list = Join-Path $TestDirectory 'samples.json'
$hash = 'a' * 64
[IO.File]::WriteAllText($dummyVmx,'test fixture - not a virtual machine')
[IO.File]::WriteAllText($list,('["' + $hash + '"]'))
$password = ConvertTo-SecureString 'test-only' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('test-user',$password)
& (Join-Path $root 'host\run_mal_realtime.ps1') -Vmrun $HarnessExe -Vmx $dummyVmx -SnapshotName 'mock' `
    -MalwareFamily 'test' -JsonPath $list -OutputRoot (Join-Path $TestDirectory 'logs') `
    -PythonExe $PythonExe -PipeName $PipeName -GuestCredential $credential `
    -WaitSeconds 1 -BaselineSeconds 0 -ExecuteTimeout 10 -BootTimeout 10 -CollectorTimeout 10 -StartTimeout 12 -DrainTimeout 10 -ReceiverExitTimeout 2
exit $LASTEXITCODE
