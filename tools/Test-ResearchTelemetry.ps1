# Run manually inside the clean Windows guest, after loading the research config.
# Does not install Sysmon, clear logs, change networking, or run malware.
[CmdletBinding()]
param([string]$OutputRoot = "$env:TEMP\SysmonResearchSmoke")
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$marker = 'smoke_' + [Guid]::NewGuid().ToString('N')
$workDir = Join-Path $OutputRoot $marker
$null = New-Item -ItemType Directory -Path $workDir -Force
$dataFile = Join-Path $workDir 'document.txt'
$otherFile = Join-Path $workDir 'document.uncommon-extension'
$childFile = Join-Path $workDir 'child.txt'
$started = Get-Date
$childId = $null
[IO.File]::WriteAllText($dataFile, 'benign create')
[IO.File]::WriteAllText($dataFile, 'benign overwrite')
[IO.File]::WriteAllText($otherFile, 'benign uncommon extension')
# Delete only the two files created above; no recursive deletion.
Remove-Item -LiteralPath $dataFile, $otherFile
$argsText = '/d /c echo ' + $marker + ' > "' + $childFile + '"'
$child = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList $argsText -WindowStyle Hidden -PassThru
$childId = $child.Id
$null = $child.Handle
if (-not $child.WaitForExit(10000)) { throw 'Benign child did not exit in 10 seconds.' }
if ($child.ExitCode -ne 0) { throw 'Benign child returned a nonzero exit code.' }
$rows = @()
$checks = [ordered]@{}
for ($attempt = 0; $attempt -lt 6; $attempt++) {
    Start-Sleep -Seconds 2
    $rows = @()
    $readErrors = @()
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $started
        Id = @(1,5,11,26)
    } -ErrorAction SilentlyContinue -ErrorVariable readErrors)
    foreach ($err in $readErrors) {
        if ($err.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $err }
    }
    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $fields = @{}
        foreach ($item in $xml.Event.EventData.Data) { $fields[$item.GetAttribute('Name')] = $item.InnerText }
        $pidMatches = $fields.ContainsKey('ProcessId') -and $fields['ProcessId'] -eq [string]$childId
        if ($event.ToXml().Contains($marker) -or ($event.Id -eq 5 -and $pidMatches)) {
            $rows += [pscustomobject]@{ EventId = $event.Id; RecordId = $event.RecordId; Data = $fields }
        }
    }
    $starts = @($rows | Where-Object { $_.EventId -eq 1 -and $_.Data['ProcessId'] -eq [string]$childId -and $_.Data['CommandLine'] -like ('*' + $marker + '*') })
    $guids = @($starts | ForEach-Object { $_.Data['ProcessGuid'] })
    $checks = [ordered]@{
        ProcessCreate1 = ($starts.Count -gt 0)
        ProcessTerminate5 = (@($rows | Where-Object { $_.EventId -eq 5 -and $_.Data['ProcessGuid'] -in $guids }).Count -gt 0)
        TextFileCreate11 = (@($rows | Where-Object { $_.EventId -eq 11 -and $_.Data['TargetFilename'] -eq $dataFile }).Count -gt 0)
        TextFileDelete26 = (@($rows | Where-Object { $_.EventId -eq 26 -and $_.Data['TargetFilename'] -eq $dataFile }).Count -gt 0)
        UncommonExtensionCreate11 = (@($rows | Where-Object { $_.EventId -eq 11 -and $_.Data['TargetFilename'] -eq $otherFile }).Count -gt 0)
        UncommonExtensionDelete26 = (@($rows | Where-Object { $_.EventId -eq 26 -and $_.Data['TargetFilename'] -eq $otherFile }).Count -gt 0)
    }
    if (@($checks.Values | Where-Object { -not $_ }).Count -eq 0) { break }
}
$passed = @($checks.Values | Where-Object { -not $_ }).Count -eq 0
$report = [ordered]@{
    marker = $marker; started_utc = $started.ToUniversalTime().ToString('o')
    finished_utc = (Get-Date).ToUniversalTime().ToString('o'); all_required_checks_passed = $passed
    checks = $checks; observed_events = $rows
    limitation = 'Checks local Sysmon only. Verify the same marker in host XML separately; this is not a load test.'
}
$reportPath = Join-Path $workDir 'smoke-report.json'
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
[pscustomobject]$checks | Format-List
Write-Host ('Marker: ' + $marker)
Write-Host ('Report: ' + $reportPath)
if (-not $passed) { throw 'One or more required local events were not observed. Inspect the report and active Sysmon configuration.' }
