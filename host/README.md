# 正常软件日志采集：PowerShell 操作说明

适用入口：`host/run_benign_realtime.ps1`，接收器1.2.0及以上。脚本在**物理机**运行，通过VMware管道接收虚拟机Sysmon日志；软件操作在**虚拟机**内手动进行。

## 1. 采集前准备

恢复选定的健康快照，打开虚拟机并登录，确认Sysmon及SysmonSerialCollector任务已经运行。管道名称与VMware设置保持一致；同一时刻只运行一个接收器。此脚本不会恢复快照、启动虚拟机或启动软件。

先不要进行正式操作，最好在开始采集后才启动本轮目标程序。

## 2. 在虚拟机计算实际程序的SHA256

在**虚拟机PowerShell**执行：

```powershell
$exePath = Read-Host '输入本轮实际运行的exe完整路径，不要额外加引号'
(Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
```

输入目标程序实际exe路径，将输出的64位哈希复制到物理机。普通使用场景填写主程序哈希；不要用安装包、其他机器的程序版本或任意占位值代替。

## 3. 在物理机开始采集：推荐命令

在**物理机PowerShell终端A**复制执行：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
.\host\run_benign_realtime.ps1 -PythonExe $python -OutputRoot 'D:\SysmonBenignLogs\thesis-v1_1-batch01'
```

脚本会依次询问：

1. 软件名称：输入本轮真实名称，例如 `SumatraPDF`、`LibreOffice`、`DB Browser for SQLite`。
2. SHA256：粘贴上一步输出的64位哈希，再按Enter。

**名称没有默认值，不要在名称前添加 `Benign_`。只复制代码块内的命令，不要复制 Markdown 围栏、`PS>` 或 `>>`。Read-Host 引号里的文字是提示；真正的值要在提示出现后输入，不能只把提示文字改成哈希。**

输入完成后脚本显示软件名、SHA256和输出目录，随即连接管道并开始接收流程；终端A会等待本轮结束。默认观察300秒，排空最多120秒，建立连接及等待READY的耗时另计。没有持续打印进度不表示卡住，按下一节查看状态。

### 可选：完整参数写法与预览

如果希望一次明确填写全部设置，在同一物理机终端使用：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
$softwareName = (Read-Host '本轮软件名称').Trim()
$softwareHash = (Read-Host '粘贴虚拟机实际exe的64位SHA256').Trim().ToLowerInvariant()
$options = @{
    SoftwareName = $softwareName
    SoftwareHash = $softwareHash
    PythonExe    = $python
    OutputRoot   = 'D:\SysmonBenignLogs\thesis-v1_1-batch01'
    PipeName     = '\\.\pipe\sysmon-log'
    WaitSeconds  = 300
    DrainTimeout = 120
}
.\host\run_benign_realtime.ps1 @options -Preview
```

Preview只查看参数，**尚未采集**。确认后在同一终端执行：

```powershell
.\host\run_benign_realtime.ps1 @options
```

推荐命令和完整参数写法二选一，不要同时启动两份接收器。开始新一轮前重新输入名称和哈希，避免复用上一软件的$options。

| 参数 | 含义/默认值 |
|---|---|
| SoftwareName | 本轮软件名称；未传时交互询问 |
| SoftwareHash | 本轮实际exe的SHA256；未传时交互询问 |
| PythonExe | Python解释器路径；默认py.exe，示例显式解析实际解释器 |
| OutputRoot | 默认D:\SysmonBenignLogs\thesis-v1_1-batch01 |
| PipeName | 默认\\.\pipe\sysmon-log |
| WaitSeconds | 默认300秒观察窗口 |
| DrainTimeout | 默认120秒排空等待上限 |
| Preview | 只显示参数，不连接管道、不创建采集目录 |

## 4. 物理机查看状态，虚拟机执行操作

新开**物理机PowerShell终端B**，把终端A的 `Output:` 后面的完整目录复制过来：

```powershell
Set-Location D:\SysmonRealtime
. .\host\process_helpers.ps1
$runDir = (Read-Host '粘贴终端A显示的本轮完整输出目录，不要额外加引号').Trim()
$statusPath = Join-Path $runDir 'status.json'
while ($true) {
    $s = Read-ProgressSnapshot -Path $statusPath
    if ($s) {
        $s | Select-Object state, events, window_remaining_seconds, updated_utc | Format-Table
    }
    $m = Read-ProgressSnapshot -Path (Join-Path $runDir 'metadata.json')
    if ($m -and $m.status -in @('complete', 'incomplete')) {
        $m | Select-Object software_name, family, status, event_count, problems | Format-List
        break
    }
    Start-Sleep -Seconds 2
}
```

看到 `state=recording` 后，在虚拟机启动目标软件，执行预定操作。immediate在READY后开始计时，不等待首次点击；尽快开始，软件退出早于300秒时仍继续观察剩余时间。先操作完再启动接收器不能补回本轮操作。

在终端B按Ctrl+C只会停止这段查看循环；在终端A中断采集可能使本轮不完整。正常情况下等待终端A自动结束。

## 5. 卸载软件等操作如何填写

已知实际卸载程序时，软件名称可写为 `LibreOffice_Uninstall` 等明确场景名，哈希填写**实际卸载程序**的SHA256。被卸载软件的主程序与卸载程序可能不是同一文件。先开始采集，看到recording后再执行卸载；使用和普通软件相同的时长、Sysmon配置与健康快照流程。

多个操作可能共用同一卸载程序，哈希不一定能区分具体卸载场景；请在scenario.md记录被卸载的软件、版本和步骤，后续审核分组。关联进程视图不保证覆盖系统服务代理执行的所有行为。

当前没有无需真实程序哈希的system_activity模式。**只写System并统一填全零/随机哈希，不是已支持的系统活动采集方法。** 无单一目标程序的综合系统活动，需先扩展身份记录及预处理分组逻辑，再纳入正式数据集。

## 6. 保存结果与后续预处理

默认目录结构：

```text
D:\SysmonBenignLogs\thesis-v1_1-batch01\实际SHA256\benign_UTC时间_随机ID\
    events.xml
    events.xml.sha256
    metadata.json
    status.json
    sample.sha256
```

例如名称输入SumatraPDF，metadata会记录 `software_name=SumatraPDF`、`family=Benign_SumatraPDF`、`software_name_source=operator_declared`。名称是人工声明，不是接收器从SHA256自动识别出来的。

在终端B保留$runDir的情况下，采集结束后执行：

```powershell
Get-Content -LiteralPath (Join-Path $runDir 'metadata.json') -Raw -Encoding UTF8 |
    ConvertFrom-Json |
    Select-Object software_name, family, sample_sha256, status, transport_complete, event_count, problems |
    Format-List
```

在该目录另存scenario.md，记录操作场景、程序版本与实际步骤。complete只表示采集完成，后续仍由预处理检查哈希、计数和完整性。下一轮恢复健康快照，重新输入本轮名称与哈希。

当前预处理2.0.1已经读取software_name；无需因使用新入口再修改代码。历史日志不自动改名，可以在review_template.csv中填写software_name和group_id，再重建派生数据。完整流程见项目preprocess/README.md。

## 7. 旧命令与直接调用接收器

日常使用上面的PowerShell脚本即可，不再复制固定的 `--family Benign_NotepadPlusPlus` 或 `benign_notepadpp` 前缀。旧Benign_*命令缺少software-name或名称互相冲突时，接收器会提前拒绝。

若需要直接调用Python，在物理机执行以下完整命令，替代第3节入口，不要与它并行运行：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
$softwareName = (Read-Host '本轮软件名称').Trim()
$softwareHash = (Read-Host '虚拟机实际exe的64位SHA256').Trim().ToLowerInvariant()
$receiveArgs = @(
    '.\host\receiver.py', 'receive',
    '--sample', $softwareHash, '--software-name', $softwareName,
    '--output', 'D:\SysmonBenignLogs\thesis-v1_1-batch01',
    '--pipe', '\\.\pipe\sysmon-log',
    '--start-mode', 'immediate', '--duration', '300', '--drain-timeout', '120'
)
& $python @receiveArgs
```

直接Python方式不使用PowerShell脚本的benign_运行名前缀，软件名仍正确写入metadata。两种入口均不会自动启动虚拟机里的应用。

## 8. 可选：脚本生成的正常活动

新增入口host/run_scripted_benign.ps1，用于文档、压缩、备份等受控工作负载。部署及研究分组限制见[工作负载说明](../guest/workloads/README.md)。这类数据单独保存到scripted-v1，作为真实软件数据的补充。
