[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework compiler not found.' }
$out = Join-Path $PSScriptRoot 'SysmonSerialCollector.exe'
& $compiler /nologo /target:exe /platform:anycpu /optimize+ /warn:4 /warnaserror+ "/out:$out" /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll (Join-Path $PSScriptRoot 'Collector.cs')
if ($LASTEXITCODE -ne 0) { throw "Compilation failed: $LASTEXITCODE" }
Get-FileHash -LiteralPath $out -Algorithm SHA256
