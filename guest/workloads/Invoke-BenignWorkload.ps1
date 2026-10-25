# Windows PowerShell 5.1+. Generated files only; no network or system changes.
[CmdletBinding()]
param(
    [ValidateSet('documents','archive','backup','reports','cleanup','mixed')]
    [string]$Scenario = 'mixed',
    [string]$Root = 'C:\BenignWorkloads',
    [ValidateRange(1,600)][int]$DurationSeconds = 240,
    [ValidateRange(1,80)][int]$MaxCycles = 40,
    [ValidateRange(1,20)][int]$FilesPerCycle = 8,
    [ValidateRange(1,64)][int]$FileKiB = 8,
    [ValidateRange(0,30000)][int]$MinPauseMs = 3000,
    [ValidateRange(0,30000)][int]$MaxPauseMs = 9000,
    [ValidateRange(0,2147483646)][int]$Seed = 101
)
$ErrorActionPreference = 'Stop'
if ($MaxPauseMs -lt $MinPauseMs) { throw 'MaxPauseMs must be >= MinPauseMs.' }
if (-not [IO.Path]::IsPathRooted($Root) -or $Root.StartsWith('\\')) {
    throw 'Root must be an absolute local filesystem path.'
}
$basePath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
if ($basePath -eq [IO.Path]::GetPathRoot($basePath).TrimEnd('\')) { throw 'Root cannot be a drive root.' }
function Assert-NoReparse([string]$Path) {
    $cursor = $Path
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Reparse point is not allowed: $cursor"
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
Assert-NoReparse $basePath
[void][IO.Directory]::CreateDirectory($basePath)
$runId = 'workload_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '_' + [Guid]::NewGuid().ToString('N')
$script:runPath = Join-Path $basePath $runId
if (Test-Path -LiteralPath $script:runPath) { throw 'Run directory already exists.' }
[void][IO.Directory]::CreateDirectory($script:runPath)
$script:prefix = $script:runPath.TrimEnd('\') + '\'
$script:operations = @{}
$script:operationCount = 0
$script:utf8 = New-Object Text.UTF8Encoding($false)
$rng = New-Object Random($Seed)
$actionLog = Join-Path $script:runPath 'actions.jsonl'
$manifestPath = Join-Path $script:runPath 'workload.json'
$clock = [Diagnostics.Stopwatch]::StartNew()
function File-SHA256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $hash.Dispose() }
}
$ownExe = (Get-Process -Id $PID).Path
$manifest = [ordered]@{
    schema_version=1; workload_version='1.0.0'; data_origin='scripted_benign';
    scenario=$Scenario; seed=$Seed; workload_run_id=$runId;
    started_utc=[DateTime]::UtcNow.ToString('o'); status='running';
    script_sha256=(File-SHA256 $PSCommandPath);
    interpreter_path=$ownExe;
    interpreter_sha256=(File-SHA256 $ownExe);
    parameters=@{duration_seconds=$DurationSeconds;max_cycles=$MaxCycles;files_per_cycle=$FilesPerCycle;
        file_kib=$FileKiB;min_pause_ms=$MinPauseMs;max_pause_ms=$MaxPauseMs};
    completed_cycles=0; operations=@{}; limitations='Generated workload, not real application execution or Sysmon event verification.'
}
function Save-Manifest {
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 6), $script:utf8)
}
function Checked-Path([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($script:prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path outside this generated run: $full"
    }
    Assert-NoReparse $full
    return $full
}
function Directory([string]$Path) {
    $full = Checked-Path $Path
    [void][IO.Directory]::CreateDirectory($full)
    return $full
}
function Record([string]$Kind, [string]$Path) {
    $full = Checked-Path $Path
    if (-not $script:operations.ContainsKey($Kind)) { $script:operations[$Kind] = 0 }
    $script:operations[$Kind]++
    $script:operationCount++
    $row = @{utc=[DateTime]::UtcNow.ToString('o');operation=$Kind;path=$full.Substring($script:prefix.Length)}
    [IO.File]::AppendAllText($actionLog, (($row | ConvertTo-Json -Compress) + [Environment]::NewLine), $script:utf8)
}
function Write-Text([string]$Path, [string]$Content) {
    $full = Checked-Path $Path
    [IO.File]::WriteAllText($full, $Content, $script:utf8)
    Record 'write' $full
}
function Copy-Generated([string]$Source, [string]$Target) {
    $a = Checked-Path $Source; $b = Checked-Path $Target
    [IO.File]::Copy($a, $b, $true)
    Record 'copy' $b
}
function Delete-Generated([string]$Path) {
    $full = Checked-Path $Path
    # Delete only individual files in the fresh generated run; never recursive.
    if (-not [IO.File]::Exists($full)) { throw "Expected generated file is missing: $full" }
    [IO.File]::Delete($full)
    Record 'delete' $full
}
function Move-Generated([string]$Source, [string]$Target) {
    $a = Checked-Path $Source; $b = Checked-Path $Target
    [IO.File]::Move($a, $b)
    Record 'rename' $b
}
function New-Documents([string]$Folder, [int]$Cycle) {
    $result = @()
    for ($i=0; $i -lt $FilesPerCycle; $i++) {
        $path = Join-Path $Folder ('document_{0:D3}.txt' -f $i)
        $line = 'Local document {0}; revision {1}; item {2}; value {3}. ' -f $Seed,$Cycle,$i,$rng.Next(100000)
        $content = ($line * ([int][Math]::Ceiling(($FileKiB*1024)/$line.Length))).Substring(0,$FileKiB*1024)
        Write-Text $path $content
        $result += $path
    }
    return $result
}
Save-Manifest
Write-Host "Workload: $Scenario; seed=$Seed; output=$script:runPath"
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $choices = @('documents','archive','backup','reports','cleanup')
    for ($cycle=0; $cycle -lt $MaxCycles -and $clock.Elapsed.TotalSeconds -lt $DurationSeconds; $cycle++) {
        $kind = if ($Scenario -eq 'mixed') { $choices[$rng.Next($choices.Count)] } else { $Scenario }
        $folder = Directory (Join-Path $script:runPath ('cycle_{0:D3}_{1}' -f $cycle,$kind))
        $source = Directory (Join-Path $folder 'source')
        $paths = @(New-Documents $source $cycle)
        switch ($kind) {
            'documents' {
                foreach ($path in $paths) {
                    $content = [IO.File]::ReadAllText((Checked-Path $path))
                    Record 'read' $path
                    $temp = $path + '.tmp'
                    Write-Text $temp ($content + "`r`nEdited and saved locally.")
                    Copy-Generated $temp $path
                    Delete-Generated $temp
                }
                Move-Generated $paths[0] (Join-Path $source 'renamed_document.txt')
            }
            'archive' {
                $zip = Checked-Path (Join-Path $folder 'documents.zip')
                [IO.Compression.ZipFile]::CreateFromDirectory($source,$zip)
                Record 'zip_create' $zip
                $expanded = Checked-Path (Join-Path $folder 'expanded')
                [IO.Compression.ZipFile]::ExtractToDirectory($zip,$expanded)
                foreach ($path in $paths) {
                    $target = Checked-Path (Join-Path $expanded ([IO.Path]::GetFileName($path)))
                    if ((File-SHA256 $path) -ne (File-SHA256 $target)) {
                        throw 'Archive round-trip hash mismatch.'
                    }
                    Record 'zip_extract_verified' $target
                }
                Delete-Generated $zip
            }
            'backup' {
                $destination = Directory (Join-Path $folder 'backup')
                foreach ($path in $paths) {
                    $target = Join-Path $destination ([IO.Path]::GetFileName($path))
                    Copy-Generated $path $target
                    if ((File-SHA256 $path) -ne (File-SHA256 $target)) {
                        throw 'Backup hash mismatch.'
                    }
                    Record 'backup_verified' $target
                }
                Write-Text $paths[0] 'Updated local source document.'
                Copy-Generated $paths[0] (Join-Path $destination ([IO.Path]::GetFileName($paths[0])))
            }
            'reports' {
                $rows = for ($i=0; $i -lt $FilesPerCycle*4; $i++) {
                    [PSCustomObject]@{Item=$i;Quantity=$rng.Next(1,100);Category=('group'+($i%3))}
                }
                $csv = Join-Path $folder 'data.csv'
                Write-Text $csv (($rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n")
                $loaded = @(Import-Csv -LiteralPath (Checked-Path $csv))
                Record 'csv_read' $csv
                Write-Text (Join-Path $folder 'report.json') ($loaded | ConvertTo-Json)
                Write-Text (Join-Path $folder 'report.html') (($loaded | ConvertTo-Html -Title 'Local report') -join "`r`n")
                Copy-Generated $csv (Join-Path $folder 'export.csv')
                Delete-Generated (Join-Path $folder 'export.csv')
            }
            'cleanup' {
                foreach ($path in $paths) {
                    $temp = $path + '.tmp'
                    Move-Generated $path $temp
                    Delete-Generated $temp
                }
            }
        }
        $manifest.completed_cycles++
        $remainingMs = [Math]::Max(0, [int](($DurationSeconds-$clock.Elapsed.TotalSeconds)*1000))
        if ($cycle+1 -lt $MaxCycles -and $remainingMs -gt 0) {
            $pause = [Math]::Min($remainingMs,$rng.Next($MinPauseMs,$MaxPauseMs+1))
            if ($pause -gt 0) { Start-Sleep -Milliseconds $pause }
        }
    }
    $manifest.status = 'complete'
    $manifest['stop_reason'] = if ($manifest.completed_cycles -ge $MaxCycles) { 'max_cycles' } else { 'duration_limit' }
} catch {
    $manifest.status = 'failed'
    $manifest['error'] = $_.Exception.Message
    throw
} finally {
    $clock.Stop()
    $manifest['finished_utc'] = [DateTime]::UtcNow.ToString('o')
    $manifest['elapsed_seconds'] = [Math]::Round($clock.Elapsed.TotalSeconds,3)
    $manifest.operations = $script:operations
    $manifest['operation_count'] = $script:operationCount
    Save-Manifest
}
Write-Host "Finished: $($manifest.completed_cycles) cycles; $script:operationCount operations. Keep workload.json and actions.jsonl."
