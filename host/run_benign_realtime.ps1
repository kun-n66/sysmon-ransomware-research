# Host-only manual benign capture. Does not launch software or control the VM.
[CmdletBinding()]
param(
    [string]$SoftwareName,
    [string]$SoftwareHash,
    [string]$OutputRoot = 'D:\SysmonBenignLogs\thesis-v1_1-batch01',
    [string]$PythonExe = 'py.exe',
    [string]$PipeName = '\\.\pipe\sysmon-log',
    [ValidateRange(1,86400)][int]$WaitSeconds = 300,
    [ValidateRange(1,86400)][int]$DrainTimeout = 120,
    [switch]$Preview
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($SoftwareName)) {
    $SoftwareName = Read-Host 'Software name (for example: SumatraPDF or LibreOffice)'
}
if ([string]::IsNullOrWhiteSpace($SoftwareName)) { throw 'Software name is required; there is no default application.' }
$SoftwareName = $SoftwareName.Trim()
if ($SoftwareName.Length -gt 128 -or $SoftwareName -match '[\x00-\x1F\x7F]') {
    throw 'Software name must contain 1-128 characters without control characters.'
}
if ([string]::IsNullOrWhiteSpace($SoftwareHash)) {
    $SoftwareHash = Read-Host 'Paste the 64-character SHA256 of the actual executable in the guest'
}
if ([string]::IsNullOrWhiteSpace($SoftwareHash)) { throw 'SHA256 is required.' }
$SoftwareHash = $SoftwareHash.Trim().ToLowerInvariant()
if ($SoftwareHash -notmatch '^[0-9a-f]{64}$') { throw 'SHA256 must contain exactly 64 hexadecimal characters.' }
$receiverScript = Join-Path $PSScriptRoot 'receiver.py'
if (-not (Test-Path -LiteralPath $receiverScript -PathType Leaf)) { throw "Missing receiver: $receiverScript" }
# No software name in filesystem paths: metadata is the authoritative name.
$runId = 'benign_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '_' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$runDir = Join-Path (Join-Path $OutputRoot $SoftwareHash) $runId
$receiveArgs = @('-u', $receiverScript, 'receive',
    '--sample', $SoftwareHash, '--software-name', $SoftwareName,
    '--output', $OutputRoot, '--run-id', $runId, '--pipe', $PipeName,
    '--start-mode', 'immediate', '--duration', [string]$WaitSeconds,
    '--drain-timeout', [string]$DrainTimeout)
Write-Host "Software: $SoftwareName"
Write-Host "SHA256:   $SoftwareHash"
Write-Host "Output:   $runDir"
if ($Preview) {
    [PSCustomObject]@{ SoftwareName=$SoftwareName; Family=('Benign_' + $SoftwareName);
        SoftwareHash=$SoftwareHash; RunId=$runId; OutputDirectory=$runDir; ReceiverArguments=$receiveArgs }
    return
}
$PythonExe = (Get-Command $PythonExe -CommandType Application -ErrorAction Stop).Source
$launchArgs = @()
if ([IO.Path]::GetFileName($PythonExe) -ieq 'py.exe') { $launchArgs += '-3' }
$launchArgs += $receiveArgs
& $PythonExe @launchArgs
if ($LASTEXITCODE -ne 0) { throw "Receiver failed with exit code $LASTEXITCODE. Review metadata/status in $runDir" }
