# Windows PowerShell 5.1 / PowerShell 7 native process helpers.
function Read-ProgressSnapshot {
    param([string]$Path)
    # Share deletion so the receiver can replace status.json during this read.
    $stream = $null
    $reader = $null
    try {
        $sharing = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $sharing)
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
        $text = $reader.ReadToEnd()
    } catch [IO.IOException] { return $null }
      catch [UnauthorizedAccessException] { return $null }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
    try { return ($text | ConvertFrom-Json -ErrorAction Stop) }
    catch { return $null }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    # CommandLineToArgvW-compatible quoting, including quotes and trailing backslashes.
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
        } else {
            [void]$builder.Append(('\' * $slashes))
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    [void]$builder.Append(('\' * (2 * $slashes)))
    [void]$builder.Append('"')
    return $builder.ToString()
}

function New-HiddenProcess {
    param([string]$Executable, [string[]]$ArgumentValues, [switch]$Utf8)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = (($ArgumentValues | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    if ($Utf8) {
        $info.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $info.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Failed to start external process.' }
    return [PSCustomObject]@{
        Process = $process
        Output = $process.StandardOutput.ReadToEndAsync()
        ErrorOutput = $process.StandardError.ReadToEndAsync()
    }
}

function Invoke-TimedProcess {
    param([string]$Executable, [string[]]$ArgumentValues, [int]$TimeoutSeconds = 60, [switch]$Utf8)
    $running = New-HiddenProcess -Executable $Executable -ArgumentValues $ArgumentValues -Utf8:$Utf8
    try {
        if (-not $running.Process.WaitForExit($TimeoutSeconds * 1000)) {
            $running.Process.Kill()
            $running.Process.WaitForExit()
            throw "External process exceeded $TimeoutSeconds seconds."
        }
        return [PSCustomObject]@{
            ExitCode = $running.Process.ExitCode
            Output = $running.Output.GetAwaiter().GetResult()
            ErrorOutput = $running.ErrorOutput.GetAwaiter().GetResult()
        }
    } finally { $running.Process.Dispose() }
}

function Get-HiddenProcessOutput {
    param($Running, [int]$TimeoutSeconds = 2)
    $captured = @{}
    foreach ($name in @('Output','ErrorOutput')) {
        try {
            if ($Running.$name.Wait($TimeoutSeconds * 1000)) {
                $captured[$name] = $Running.$name.GetAwaiter().GetResult()
            } else {
                $captured[$name] = '[capture incomplete: stream EOF was not received within the deadline]'
            }
        } catch { $captured[$name] = '[capture error: ' + $_.Exception.Message + ']' }
    }
    return [PSCustomObject]$captured
}

function Stop-HiddenProcessBounded {
    param($Running, [int]$GraceSeconds = 10, [int]$KillTimeoutSeconds = 5)
    $Running.Process.Refresh()
    if ($Running.Process.WaitForExit($GraceSeconds * 1000)) { return $false }
    Write-Warning 'Receiver did not exit within the grace period; terminating this receiver process.'
    try { $Running.Process.Kill() }
    catch {
        if (-not $Running.Process.WaitForExit(0)) { throw }
    }
    if (-not $Running.Process.WaitForExit($KillTimeoutSeconds * 1000)) {
        throw 'Receiver termination could not be confirmed within the deadline.'
    }
    return $true
}
