[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $env:TEMP ('sysmon-tests-' + [Guid]::NewGuid().ToString('N'))),
    [string]$PythonExe = 'py.exe'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Force -Path $BuildDirectory | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$harness = Join-Path $BuildDirectory 'GuestHarness.exe'
& $compiler /nologo /target:exe /main:GuestHarness /warn:4 /warnaserror+ "/out:$harness" /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll (Join-Path $root 'guest\Collector.cs') (Join-Path $PSScriptRoot 'GuestHarness.cs')
if ($LASTEXITCODE -ne 0) { throw 'Guest harness compilation failed.' }
. (Join-Path $root 'host\process_helpers.ps1')
$expectedArguments = @('', 'plain', 'with spaces', 'C:\trailing\', 'a"b', 'a\"b', '测试')
$argumentResult = Invoke-TimedProcess -Executable $harness -ArgumentValues (@('echo') + $expectedArguments) -TimeoutSeconds 5 -Utf8
$parsedArguments = $argumentResult.Output | ConvertFrom-Json
$actualArguments = @($parsedArguments)
if ($argumentResult.ExitCode -ne 0 -or $actualArguments.Count -ne $expectedArguments.Count) { throw 'Native argument count test failed.' }
for ($i = 0; $i -lt $expectedArguments.Count; $i++) {
    if ($actualArguments[$i] -cne $expectedArguments[$i]) { throw "Native argument round-trip failed at index $i." }
}
$timedOut = $false
try { Invoke-TimedProcess -Executable $harness -ArgumentValues @('sleep') -TimeoutSeconds 1 | Out-Null }
catch { if ($_.Exception.Message -like '*exceeded*') { $timedOut = $true } else { throw } }
if (-not $timedOut) { throw 'Native process timeout test failed.' }
Write-Host 'PowerShell native argument and timeout tests passed.'
$env:GUEST_HARNESS = $harness
try {
    $pythonArguments = @()
    if ([IO.Path]::GetFileName($PythonExe) -ieq 'py.exe') { $pythonArguments += '-3' }
    $pythonArguments += @('-m','unittest','discover','-s',$PSScriptRoot,'-p','test_*.py','-v')
    & $PythonExe @pythonArguments
    if ($LASTEXITCODE -ne 0) { throw 'Python/native pipe tests failed.' }
} finally { Remove-Item Env:GUEST_HARNESS -ErrorAction SilentlyContinue }
# Parse scripts without executing installation, vmrun, or samples.
foreach ($script in Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1') {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "PowerShell parse errors in $($script.Name): $parseErrors" }
}
Write-Host 'All tests passed. These tests do not exercise a VMware virtual serial port or live Sysmon.'
