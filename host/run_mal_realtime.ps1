# Integration copy based on the supplied run_mal.ps1. Never executes a sample on the host.
[CmdletBinding()]
param(
    [string]$Vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    [string]$Vmx = 'D:\VMware\Windows10\Windows10.vmx',
    [string]$SnapshotName = 'Lockbit_run',
    [string]$MalwareFamily = 'Lockbit',
    [string]$GuestSampleRoot = 'C:\samples',
    [string]$GuestUser = 'User',
    [PSCredential]$GuestCredential,
    [string]$JsonPath = "$env:USERPROFILE\Desktop\malware_list.json",
    [string]$OutputRoot = "$env:USERPROFILE\Desktop\sysmon_xml_logs",
    [string]$PythonExe = 'py.exe',
    [string]$PipeName = '\\.\pipe\sysmon-log',
    [ValidateRange(1,86400)][int]$WaitSeconds = 300,
    [ValidateRange(0,60)][int]$BaselineSeconds = 10,
    [ValidateRange(10,600)][int]$ExecuteTimeout = 60,
    [ValidateRange(10,600)][int]$BootTimeout = 120,
    [ValidateRange(10,600)][int]$CollectorTimeout = 60,
    [ValidateRange(10,600)][int]$StartTimeout = 120,
    [ValidateRange(10,3600)][int]$DrainTimeout = 120,
    [ValidateRange(1,60)][int]$ReceiverExitTimeout = 10
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'process_helpers.ps1')
$receiverScript = Join-Path $PSScriptRoot 'receiver.py'
if ($StartTimeout -le ($BaselineSeconds + $ExecuteTimeout)) {
    throw 'StartTimeout must be greater than BaselineSeconds + ExecuteTimeout.'
}
foreach ($path in @($Vmrun,$Vmx,$JsonPath,$receiverScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing file: $path" }
}
if ($MalwareFamily -match '[\\/:*?"<>|\x00-\x1F]' -or $MalwareFamily -in @('.','..','')) {
    throw 'MalwareFamily must be a single directory name.'
}
$PythonExe = (Get-Command $PythonExe -CommandType Application -ErrorAction Stop).Source
$pythonPrefix = @()
if ([IO.Path]::GetFileName($PythonExe) -ieq 'py.exe') { $pythonPrefix = @('-3') }
$version = Invoke-TimedProcess -Executable $PythonExe -ArgumentValues ($pythonPrefix + @('-c','import sys,json; print(json.dumps(sys.executable)); sys.exit(0 if sys.version_info >= (3,9) else 1)')) -TimeoutSeconds 10
if ($version.ExitCode -ne 0) { throw 'Python 3.9+ is required.' }
# Run the interpreter itself, not a launcher whose child could survive timeout termination.
$PythonExe = $version.Output.Trim() | ConvertFrom-Json
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw 'Cannot resolve Python interpreter path.' }
$pythonPrefix = @()
$parsedSamples = Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
# Windows PowerShell 5.1 emits a JSON array as one pipeline object; unwrap after assignment.
$sampleItems = @($parsedSamples)
$hashes = @()
foreach ($item in $sampleItems) {
    if ($item -isnot [string] -or $item -notmatch '^[a-fA-F0-9]{64}(\.exe)?$') {
        throw 'JSON must be an array of SHA256 strings, optionally ending in .exe.'
    }
    $hashes += ($item -replace '(?i)\.exe$','').ToLowerInvariant()
}
if ($hashes.Count -eq 0) { throw 'Sample list is empty.' }
$hashes = @($hashes | Select-Object -Unique)
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
if (-not $GuestCredential) { $GuestCredential = Get-Credential -UserName $GuestUser -Message 'VMware guest credentials (not written to output files)' }
if (-not $GuestCredential) { throw 'Guest credential is required.' }
$guestLogin = $GuestCredential.UserName
$guestSecret = $GuestCredential.GetNetworkCredential().Password

function Invoke-VmrunChecked {
    param([string[]]$VmArguments, [int]$Timeout = 60)
    $result = Invoke-TimedProcess -Executable $Vmrun -ArgumentValues $VmArguments -TimeoutSeconds $Timeout
    if ($result.ExitCode -ne 0) {
        $message = ($result.Output + ' ' + $result.ErrorOutput).Trim()
        if ($guestSecret) { $message = $message.Replace($guestSecret,'[redacted]') }
        throw "vmrun failed ($($result.ExitCode)): $message"
    }
}

function Wait-GuestReady {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $attempt = 0
    $lastFailure = 'No guest probe completed.'
    $reportedFailure = $null
    while ($clock.Elapsed.TotalSeconds -lt $BootTimeout) {
        $left = [Math]::Max(1,[int]($BootTimeout - $clock.Elapsed.TotalSeconds))
        $attempt++
        try {
            # No cmd/start shell; the probe is a harmless Windows program.
            Invoke-VmrunChecked -VmArguments @('-T','ws','-gu',$guestLogin,'-gp',$guestSecret,
                'runProgramInGuest',$Vmx,'C:\Windows\System32\whoami.exe') -Timeout ([Math]::Min(10,$left))
            return
        } catch {
            # Authentication, Tools errors and per-call timeouts must not be hidden behind
            # a generic boot timeout. Invoke-VmrunChecked already redacts the guest password.
            $lastFailure = $_.Exception.Message
            if ($guestSecret) { $lastFailure = $lastFailure.Replace($guestSecret,'[redacted]') }
            if ($lastFailure -ne $reportedFailure) {
                Write-Warning ("Guest readiness probe {0}: {1}" -f $attempt,$lastFailure)
                $reportedFailure = $lastFailure
            }
            if ($clock.Elapsed.TotalSeconds -ge $BootTimeout) { break }
            Start-Sleep -Seconds 2
        }
    }
    throw ("VMware guest readiness timeout after {0} seconds ({1} probes). Last error: {2}" -f $BootTimeout,$attempt,$lastFailure)
}

function Test-CompletedSample {
    param([string]$Hash)
    $sampleDir = Join-Path $OutputRoot $Hash
    if (-not (Test-Path -LiteralPath $sampleDir -PathType Container)) { return $false }
    foreach ($runDir in Get-ChildItem -LiteralPath $sampleDir -Directory) {
        $metaPath = Join-Path $runDir.FullName 'metadata.json'
        $xmlPath = Join-Path $runDir.FullName 'events.xml'
        if (-not (Test-Path -LiteralPath $metaPath) -or -not (Test-Path -LiteralPath $xmlPath)) { continue }
        try {
            $meta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($meta.status -eq 'complete' -and $meta.sample_sha256 -eq $Hash -and $meta.requested_duration_seconds -eq $WaitSeconds -and
                $meta.start_mode -eq 'process' -and $meta.family -eq $MalwareFamily -and
                (Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $meta.log_sha256) {
                return $true
            }
        } catch { Write-Warning "Cannot validate previous run: $($runDir.FullName)" }
    }
    return $false
}

$completedCount = 0
$failedCount = 0
$skippedCount = 0
try {
    foreach ($hash in $hashes) {
        if (Test-CompletedSample $hash) {
            Write-Host "[SKIP] $hash has a complete, checksum-verified run."
            $skippedCount++
            continue
        }
        $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '_' + [Guid]::NewGuid().ToString('N').Substring(0,12)
        $runDir = Join-Path (Join-Path $OutputRoot $hash) $runId
        $statusPath = Join-Path $runDir 'status.json'
        $receiver = $null
        $resultCommitted = $false
        $receiverStopped = $false
        $vmTouched = $false
        try {
            Write-Host "[RUN] $hash / $runId"
            $vmTouched = $true
            Invoke-VmrunChecked -VmArguments @('-T','ws','revertToSnapshot',$Vmx,$SnapshotName) -Timeout $BootTimeout
            Invoke-VmrunChecked -VmArguments @('-T','ws','start',$Vmx,'nogui') -Timeout $BootTimeout
            Wait-GuestReady
            $receiveArgs = $pythonPrefix + @('-u',$receiverScript,'receive','--sample',$hash,'--family',$MalwareFamily,
                '--output',$OutputRoot,'--run-id',$runId,'--pipe',$PipeName,'--duration',"$WaitSeconds",
                '--connect-timeout',"$CollectorTimeout",'--ready-timeout',"$CollectorTimeout",
                '--start-timeout',"$StartTimeout",'--drain-timeout',"$DrainTimeout")
            $receiver = New-HiddenProcess -Executable $PythonExe -ArgumentValues $receiveArgs -Utf8
            $readyClock = [Diagnostics.Stopwatch]::StartNew()
            $armed = $false
            while ($readyClock.Elapsed.TotalSeconds -lt (2 * $CollectorTimeout + 5)) {
                if ($receiver.Process.HasExited) { throw 'Receiver exited before collector READY.' }
                if (Test-Path -LiteralPath $statusPath) {
                    $status = Read-ProgressSnapshot -Path $statusPath
                    if ($status.run_id -eq $runId -and $status.state -eq 'armed') { $armed = $true; break }
                    if ($status.state -eq 'incomplete') { throw 'Receiver reported an incomplete session.' }
                }
                Start-Sleep -Milliseconds 200
            }
            if (-not $armed) { throw 'Collector readiness timeout.' }
            Write-Host '[READY] Sysmon subscription active; recording baseline.'
            if ($BaselineSeconds -gt 0) { Start-Sleep -Seconds $BaselineSeconds }
            if ($receiver.Process.HasExited) { throw 'Receiver exited before sample launch.' }
            $currentStatus = $null
            for ($readAttempt = 0; $readAttempt -lt 10; $readAttempt++) {
                $currentStatus = Read-ProgressSnapshot -Path $statusPath
                if ($currentStatus) { break }
                Start-Sleep -Milliseconds 200
            }
            if (-not $currentStatus -or $currentStatus.run_id -ne $runId -or $currentStatus.state -ne 'armed' -or
                ([DateTime]::UtcNow - [DateTime]::Parse($currentStatus.updated_utc).ToUniversalTime()).TotalSeconds -gt 5) {
                throw 'Collector is no longer armed; sample will not be launched.'
            }
            $samplePath = $GuestSampleRoot.TrimEnd('\') + '\' + $MalwareFamily + '\' + $hash + '.exe'
            # -noWait returns without waiting for sample termination. The receiver independently
            # confirms Event ID 1 / Image == HASH.exe before starting its observation timer.
            Invoke-VmrunChecked -VmArguments @('-T','ws','-gu',$guestLogin,'-gp',$guestSecret,
                'runProgramInGuest',$Vmx,'-noWait',$samplePath) -Timeout $ExecuteTimeout
            Write-Host "[COLLECT] Waiting for process evidence, $WaitSeconds seconds, then queue drain."
            $deadline = [Diagnostics.Stopwatch]::StartNew()
            $maximum = $StartTimeout + $WaitSeconds + $DrainTimeout + 15
            $lastProgress = -10.0
            $lastState = ''
            while ($true) {
                $live = $null
                if (Test-Path -LiteralPath $statusPath) {
                    $live = Read-ProgressSnapshot -Path $statusPath
                    if ($live -and ($live.run_id -ne $runId -or $live.sample_sha256 -ne $hash)) { throw 'Receiver status identity mismatch.' }
                }
                # status.json is best-effort. A final metadata commit remains
                # discoverable even when the terminal progress update failed.
                $committed = Read-ProgressSnapshot -Path (Join-Path $runDir 'metadata.json')
                if ($committed -and $committed.status -in @('complete','incomplete')) {
                    if ($committed.run_id -ne $runId -or $committed.sample_sha256 -ne $hash) { throw 'Receiver metadata identity mismatch.' }
                    $resultCommitted = $true
                    break
                }
                $receiver.Process.Refresh()
                if ($receiver.Process.WaitForExit(0)) { break }
                if ($live -and ($live.state -ne $lastState -or $deadline.Elapsed.TotalSeconds - $lastProgress -ge 10)) {
                    $remaining = if ($null -ne $live.window_remaining_seconds) { $live.window_remaining_seconds } else { '-' }
                    Write-Host ("[PROGRESS] state={0}; events={1}; window remaining={2}s; status updated={3}" -f $live.state,$live.events,$remaining,$live.updated_utc)
                    $lastState = $live.state
                    $lastProgress = $deadline.Elapsed.TotalSeconds
                }
                if ($deadline.Elapsed.TotalSeconds -gt $maximum) { throw 'Receiver exceeded experiment deadline.' }
                Start-Sleep -Milliseconds 250
            }
            $meta = Get-Content -LiteralPath (Join-Path $runDir 'metadata.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($meta.run_id -ne $runId -or $meta.sample_sha256 -ne $hash) { throw 'Receiver metadata identity mismatch.' }
            # A committed result is independent of interpreter shutdown. Validate it before
            # applying the short exit grace period; never accept a bare status flag as success.
            if ($meta.status -eq 'complete') {
                $xmlPath = Join-Path $runDir 'events.xml'
                if (-not (Test-Path -LiteralPath $xmlPath -PathType Leaf)) { throw 'Completed XML is missing.' }
                if ((Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $meta.log_sha256) {
                    throw 'Completed XML checksum mismatch.'
                }
            }
            Write-Host ("[SAVED] status={0}; events={1}. Waiting up to {2}s for receiver exit." -f $meta.status,$meta.event_count,$ReceiverExitTimeout)
            $forcedStop = Stop-HiddenProcessBounded -Running $receiver -GraceSeconds $ReceiverExitTimeout
            $receiverStopped = $true
            $controllerResult = [ordered]@{
                run_id = $runId
                result_committed = $resultCommitted
                receiver_forced_termination = $forcedStop
                receiver_exit_code = $receiver.Process.ExitCode
                observed_utc = [DateTime]::UtcNow.ToString('o')
            } | ConvertTo-Json
            [IO.File]::WriteAllText((Join-Path $runDir 'controller_result.json'),$controllerResult)
            if ($resultCommitted -and $meta.status -eq 'complete' -and ($forcedStop -or $receiver.Process.ExitCode -ne 0)) {
                Write-Warning 'XML and metadata are complete and verified, but receiver shutdown was abnormal.'
            } elseif ($receiver.Process.ExitCode -ne 0) { throw "Receiver failed; inspect $runDir" }
            if ($meta.status -ne 'complete') { throw 'Experiment did not complete.' }
            $completedCount++
            Write-Host "[OK] $($meta.event_count) events: $runDir\events.xml"
        } catch {
            $failedCount++
            Write-Warning $_.Exception.Message
        } finally {
            $cleanupFailure = $null
            if ($receiver) {
                try {
                if (-not $receiverStopped -and -not $receiver.Process.WaitForExit(0)) {
                    if (Test-Path -LiteralPath $runDir) {
                        [IO.File]::WriteAllText((Join-Path $runDir 'abort.request'),'controller abort')
                    }
                    Write-Host "[STOP] Waiting up to $DrainTimeout seconds for receiver drain."
                    $stopClock = [Diagnostics.Stopwatch]::StartNew()
                    while (-not $receiver.Process.WaitForExit(1000) -and $stopClock.Elapsed.TotalSeconds -lt $DrainTimeout) {
                        if (Test-Path -LiteralPath $statusPath) {
                            $closing = Read-ProgressSnapshot -Path $statusPath
                            if ($closing.run_id -eq $runId -and $closing.state -in @('complete','incomplete')) { break }
                        }
                    }
                    Stop-HiddenProcessBounded -Running $receiver -GraceSeconds $ReceiverExitTimeout | Out-Null
                }
                if (Test-Path -LiteralPath $runDir) {
                    $capture = Get-HiddenProcessOutput -Running $receiver
                    [IO.File]::WriteAllText((Join-Path $runDir 'receiver.stdout.log'),$capture.Output)
                    [IO.File]::WriteAllText((Join-Path $runDir 'receiver.stderr.log'),$capture.ErrorOutput)
                }
                } catch { $cleanupFailure = $_.Exception.Message }
                finally { $receiver.Process.Dispose() }
            }
            if ($vmTouched) {
                # A reset failure is fatal: do not proceed to another sample in an unknown VM state.
                Write-Host '[RESET] Restoring the clean snapshot.'
                Invoke-VmrunChecked -VmArguments @('-T','ws','revertToSnapshot',$Vmx,$SnapshotName) -Timeout $BootTimeout
            }
            if ($cleanupFailure) { throw "Receiver cleanup failed: $cleanupFailure" }
        }
    }
} finally { $guestSecret = $null }
Write-Host "Completed=$completedCount; failed=$failedCount; skipped=$skippedCount; output=$OutputRoot"
if ($failedCount -gt 0) { exit 2 }
