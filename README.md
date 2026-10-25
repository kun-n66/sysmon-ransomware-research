# Sysmon Ransomware Research

Windows 离线虚拟机 Sysmon 行为采集、数据预处理与 CNN–LSTM / CNN-only / LSTM-only 分类研究代码。

## 公开源码版

本仓库只发布研究代码、配置、测试和使用文档。原始日志、预处理数据、模型权重、个人科研归档和恶意软件样本未包含在本次发布中。基线目录中的参考划分和配置用于复现原实验设置；对应数据尚未随源码发布，不能直接重现原实验分数。

文档中的 D 盘和 Google Drive 路径是原实验环境示例，运行前请修改配置。历史测试报告保留原日期及环境说明，不代表当前发布环境重新通过了所有测试。实验结论的边界见 training/README.md 与 training_baselines/README.md。

### 使用入口

1. Windows 物理机与隔离的 VMware Windows 虚拟机：按下方操作手册准备环境；在 Windows PowerShell 运行 `./guest/build.ps1`，从源码生成采集器后再执行安装步骤。本源码版不附带预编译采集器。
2. 数据预处理：参阅 [预处理文档](preprocess/README.md)，使用 `preprocess/inputs.all.example.json` 配置自己的输入目录。
3. CNN–LSTM：参阅 [主模型说明](training/README.md)，Notebook 已内嵌所需项目模块。
4. CNN-only / LSTM-only：参阅 [基线说明](training_baselines/README.md)。复用本仓库参考划分需要原实验的匹配数据；对新数据应预先冻结并明确记录独立划分。
5. 本地测试：Windows PowerShell 执行 `./tests/run-tests.ps1 -PythonExe python`；预处理测试执行 `python -m unittest discover -s preprocess/tests -v`。这些测试使用合成事件和本地测试管道，不运行恶意软件或恢复虚拟机。

### 许可证

项目原创代码与文档遵循 MIT；Sysmon 上游配置及派生规则分别保留其原许可证，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。本项目不代表 Microsoft、VMware 或上游规则作者提供支持或背书。

---

## 原集成操作手册

# SysmonRealtime：离线虚拟机日志采集与研究工具

整合版本：**2026.09.29-benign-name**。用于 Windows 11 物理机、Windows 10 VMware 虚拟机、Sysmon、300 秒行为观察，以及后续正常/勒索运行分类研究。

**日常使用入口只有两个：正常软件使用 `host/run_benign_realtime.ps1`（内部为 immediate 模式）；勒索软件使用 `host/run_mal_realtime.ps1` 自动恢复快照并采集。** Sysmon 安装和 C# 计划任务安装只在准备环境时进行。此包没有更改你现有的虚拟机或 `D:\SysmonRealtime`。

**已冻结的规则说明：阅读 [Swift 离线版更新说明](docs/UPDATE-SWIFT-V2.md)。** 当前规则以 SwiftOnSecurity 为基础：ID 1/5/11/26 全范围，ID 2 保留上游筛选，ID 3/22 关闭，ID 7/9/10 沿用上游关闭状态。其他规则保留上游语义。2026-09-29更新物理机正常采集入口、receiver及预处理的软件名称读取；虚拟机XML、快照和C#采集器保持不变。详细用法见 [预处理v2说明](preprocess/README.md)。

## 1. 本项目包含什么

```text
SysmonRealtime/
  README.md                         本文：统一操作手册
  VERSIONS.json                     组件版本及配置指纹
  SHA256SUMS.txt                    项目文件校验清单
  sysmon/
    sysmonconfig-export.xml        实际加载的唯一研究配置
    build_config.py                可选，离线重建/验证规则
    upstream/                      固定上游 XML、来源、许可证
  guest/
    SysmonSerialCollector.exe      运行 guest/build.ps1 后生成的 C# 采集器
    SysmonSerialCollector.exe.config
    Collector.cs                   源码
    install.ps1                    安装开机计划任务
    uninstall.ps1                  移除采集任务，保留诊断文件
    build.ps1                      从源码编译采集器
  host/
    receiver.py                    单轮接收与中断文件恢复
    run_benign_realtime.ps1         正常手动采集：每轮明确输入软件名称与SHA256
    storage.py                     XML、metadata、哈希
    winpipe.py                     Win32 本地命名管道客户端
    process_helpers.ps1            外部进程超时/参数处理
    run_mal_realtime.ps1            勒索样本批量控制脚本
  preprocess/
    preprocess.py                  v2.0，双类别输入、行为时序和质量审计
    dataset.py                     校验并读取结构化训练输入
    README.md                      详细数据格式、质量与时间语义
    tests/
  tools/
    Test-ResearchTelemetry.ps1      虚拟机无害自检
    check_log_volume.py             物理机文件大小/metadata 检查
  examples/malware_list.example.json  JSON 格式示例，必须换成真实哈希
  tests/                           合成事件、本地管道和 mock vmrun 测试
  docs/                            更新说明、规则回放和历史验证
```

组件版本分别管理：C# 采集器 1.0、Python 接收端 1.2.0、预处理 2.0.1、规则 `thesis-swift-offline-v2.0.0`。新配置 SHA256 为 `2411d23e6d8f7902848ff14aa1061d9dc0caa5ed4f7052ebaba0eb00be2f1db1`，与旧 v1.0 配置不同。

不包含 Sysmon 官方二进制、VMware、样本文件和原始研究日志。训练 Notebook 位于 training/ 与 training_baselines/。`sysmon/build_config.py` 只为复现规则服务，安装不需要运行它。所有示例均为 PowerShell；复制代码块内部内容，不要复制提示符 `PS>`、`>>` 或 Markdown 围栏。

## 2. 目录和数据流约定

本手册假定物理机项目位于 `D:\SysmonRealtime`。已有同名项目时先自行备份，再放入整合版，避免目录套成 `D:\SysmonRealtime\SysmonRealtime`。整合包包含预处理 v2.0；接收端继续包含已有进度写入容错修复；此次规则切换无需重新安装已有的 C# 采集器。

| 位置 | 示例路径 | 内容 |
|---|---|---|
| 物理机 | `D:\SysmonRealtime` | 项目和 Python 主机脚本 |
| 物理机 | `D:\SysmonLogs\thesis-swift-v2-batch01` | 新规则勒索运行输出 |
| 物理机 | `D:\SysmonBenignLogs\thesis-swift-v2-batch01` | 新规则正常运行输出 |
| 物理机 | `D:\SysmonPrepared` | 结构化数据；必须在原日志目录之外 |
| 虚拟机 | `C:\SysmonRealtime` | 复制进来的 guest、sysmon、tools 文件夹 |
| 虚拟机 | `C:\Sysmon` | 你实际使用的 Sysmon64.exe |
| 虚拟机 | `C:\samples\Lockbit\<SHA256>.exe` | 已解压的勒索样本，随干净快照保存 |
| 虚拟机 | `C:\Program Files\Notepad++\notepad++.exe` | 正常软件示例，不重命名 |

```text
虚拟机 Sysmon → Operational 事件通道 → C# 采集器 → COM1
→ VMware 本地命名管道 → 物理机 Python → XML + metadata + SHA256
→ preprocess.py → 结构化事件/特征/序列 → 后续训练 Notebook
```

传输不需要虚拟机网卡联网、共享目录或映射物理机日志盘。Python 是管道客户端，VMware 是管道服务端。采集器不执行远程命令，样本启动由既有 vmrun 流程负责。

## 3. 一次性准备 VMware 和运行环境

虚拟机需要 .NET Framework 4.8、可正常使用的 Sysmon 和 VMware Tools。物理机需要 VMware Workstation/vmrun、Python 3.9+，Python 部分仅用标准库，不需 pip 安装。

先关闭虚拟机，再在 VMware Settings → Add → Serial Port 中设置：

1. 使用命名管道，名称为 `\\.\pipe\sysmon-log`。
2. This end is the server；The other end is an application。
3. 勾选 Connect at power on。
4. 开机后确认虚拟机端口为 COM1；若不同，安装采集器时传实际端口。

一个管道同一时刻只能由一个接收程序使用；自动采集前关闭手动接收端。多台虚拟机应分别使用不同管道名。

物理机检查 Python，并取得后续通用的实际解释器路径：

```powershell
Set-Location D:\SysmonRealtime
py -3 --version
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
& $python --version
```

没有 `py` 时直接指定你实际的 Python 路径，例如 `$python = 'C:\Python312\python.exe'`。变量只在当前 PowerShell 窗口有效，新开窗口需要重新设置。

## 4. 虚拟机：安装或更新 Sysmon 配置

管理员 PowerShell；根据实际位置修改 Sysmon EXE 路径。你已经安装了 Sysmon，当前使用更新命令即可：

```powershell
& 'C:\Sysmon\Sysmon64.exe' -c 'C:\SysmonRealtime\sysmon\sysmonconfig-export.xml'
```

仅首次安装时使用：

```powershell
& 'C:\Sysmon\Sysmon64.exe' -accepteula -i 'C:\SysmonRealtime\sysmon\sysmonconfig-export.xml'
```

查看已加载配置：

```powershell
& 'C:\Sysmon\Sysmon64.exe' -c
```

这与 SwiftOnSecurity 的 XML 加载方式相同。程序若叫 `sysmon.exe`，替换文件名即可。无需先卸载，也无需仅为配置生效而重启。

规则使用 schema 4.90。出现不兼容时保留错误，使用 `Sysmon64.exe -s` 检查实际二进制支持的 schema；不能只修改 XML 的版本数字。使用已经在你的 Windows 10 中正常工作的 Sysmon 核对，不把更新到最新二进制作为必要步骤。

配置全范围记录 ID 1/5/11/26；关闭 ID 3/22，ID 2/6/8/12–15/17–21 使用 Swift 原有规则，ID 7/9/10 保持关闭。ID 23/24/25/27/28/29 明确关闭，不归档、不阻止操作。它不会记录每次文件读写，也不会直接判断加密成功或家族归属；关闭网络日志不等于断网。

## 5. 虚拟机：安装 C# 后台采集任务

把整个 `guest` 目录复制到 `C:\SysmonRealtime\guest`，管理员 PowerShell：

```powershell
Set-Location C:\SysmonRealtime\guest
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Port COM1
```

Bypass 仅作用于这次 PowerShell 进程。安装后的程序位于 `C:\Program Files\SysmonSerialCollector`，任务名为 `SysmonSerialCollector`，以 SYSTEM 在开机时运行，安装后立即启动；它是计划任务，不是 Windows Service。

```powershell
Get-ScheduledTask -TaskName SysmonSerialCollector
Get-Content C:\ProgramData\SysmonSerialCollector\agent.log -Tail 20
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1
```

看到 `waiting for host START` 是正常待机；主机发 START 才创建本轮未来事件订阅。任务一直 Running 也正常。COM1 不能同时被计划任务和前台采集器占用。

源码版不包含 EXE；安装前的编译命令是 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1`，EXE 与 `.exe.config` 一起部署。

## 6. 建立统一、健康的快照

先完成规则和采集器安装、串口连接，并用第 7 节无害自检确认数据可达。准备正常软件、共同文档语料和所需样本后，结束接收会话，确保系统健康。

推荐关闭虚拟机后保存新快照，例如 **`SysmonResearch_Swift_v2`**，每次开机重新打开串口。不要把正在采集的会话保存为基准内存快照。你的原有健康快照可以保留，不能把感染后的系统只清空日志就当作健康快照。

清日志是可选操作，不是实验分轮机制。每轮只订阅新的事件，并分配新的 run_id。若仍希望清空 Sysmon 历史，可在健康虚拟机管理员终端执行：

```powershell
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

之后仍可能出现系统事件，这是正常背景活动。保存新快照后，所有 vmrun 命令使用新 SnapshotName；恢复旧快照会恢复旧规则和旧文件。

样本必须在快照内，目录拼接规则为 `GuestSampleRoot\MalwareFamily\SHA256.exe`。只在快照之后复制文件，恢复时文件会消失。下载、上传、解压和样本家族鉴定不由本项目自动处理。

## 7. 第一次先做无害端到端自检

启动健康虚拟机，物理机运行：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
$testHash = '0' * 64
& $python .\host\receiver.py receive --sample $testHash --family SmokeTest --output D:\SysmonTestLogs --start-mode immediate --duration 60
```

接收器首先打印本轮目录。按第 8 节的状态查看方法确认 recording，然后在虚拟机运行：

```powershell
Set-Location C:\SysmonRealtime
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-ResearchTelemetry.ps1
```

脚本创建并删除自己的测试文件、启动正常短命进程。六项核心检查应为 True；选择性注册表事件不作为通过条件，输出 `smoke_...` 标记。最终还需在物理机 events.xml 中找到同一标记；本地自检通过不等于传输已经验证。零哈希只是联通测试标识，这轮不进入训练。

## 8. 正常软件：immediate 模式手动操作完整示例

### 8.1 虚拟机先恢复健康环境

开始新轮之前关闭上一接收程序，再恢复包含新规则与正常软件的快照。可以在 VMware GUI 操作；也可以在物理机执行以下命令，用 GUI 打开，便于手动操作：

```powershell
$vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$vmx = 'D:\VMware\Windows10\Windows10.vmx'
& $vmrun -T ws revertToSnapshot $vmx 'SysmonResearch_Swift_v2'
if ($LASTEXITCODE -ne 0) { throw '恢复快照失败' }
& $vmrun -T ws start $vmx gui
if ($LASTEXITCODE -ne 0) { throw '启动虚拟机失败' }
```

等虚拟机登录、采集任务就绪。此时先不要开始正式文档操作。正常采集的 receiver 本身不会恢复快照或启动软件。

### 8.2 正常采集命令入口（2026-09-29更新）

正常采集的逐步操作已整理到 **[host/README.md](host/README.md)**，包括虚拟机计算SHA256、物理机交互采集、完整参数/Preview、第二终端查看进度、卸载操作填写及结果核对。

在物理机PowerShell运行下面的推荐命令：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
.\host\run_benign_realtime.ps1 -PythonExe $python -OutputRoot 'D:\SysmonBenignLogs\thesis-v1_1-batch01'
```

按提示输入本轮软件名称和虚拟机实际exe的SHA256；看到recording后在虚拟机操作。默认300秒，排空上限120秒。不要把Read-Host的提示文字当作已提交的输入，也不要继续使用固定Notepad++的旧命令。

卸载场景使用明确名称及真实卸载程序的SHA256。当前不支持通过System名称和统一占位哈希代替系统活动模式。详细限制见host/README.md第5节。

结束后核对第10节的结果，记录场景，再恢复健康快照开始下一轮。

## 9. 勒索软件：vmrun 自动采集完整示例

### 9.1 核对快照内的样本和 JSON

虚拟机内应存在：

```text
C:\samples\Lockbit\实际64位SHA256.exe
```

物理机 JSON 是当前家族的哈希数组，`examples/malware_list.example.json` 只展示格式。把其中全零占位符换成真实标识，保存为 `$env:USERPROFILE\Desktop\malware_list.json`。允许裸 SHA256 或带 `.exe` 后缀，不能传 `{hash:..., family:...}` 对象列表；同一列表中重复哈希会去重。

脚本每次只处理 `MalwareFamily` 指定的一个家族。换家族时，同时换 family 参数和对应 JSON；不要把多家族混成一个列表却只传 Lockbit。自动化假定文件名和家族目录已经正确，内容哈希需在已有样本管理/审查中核对。

### 9.2 物理机执行

先关闭手动 receiver，保持同一个管道只有一个接收端。物理机 PowerShell：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
$cred = Get-Credential -UserName 'User' -Message 'Windows 10 虚拟机的用户名和密码'
$options = @{
    Vmrun           = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    Vmx             = 'D:\VMware\Windows10\Windows10.vmx'
    SnapshotName    = 'SysmonResearch_Swift_v2'
    MalwareFamily   = 'Lockbit'
    GuestSampleRoot = 'C:\samples'
    JsonPath        = "$env:USERPROFILE\Desktop\malware_list.json"
    OutputRoot      = 'D:\SysmonLogs\thesis-swift-v2-batch01'
    PythonExe       = $python
    GuestCredential = $cred
    PipeName        = '\\.\pipe\sysmon-log'
    WaitSeconds     = 300
    BaselineSeconds = 10
    StartTimeout    = 120
    DrainTimeout    = 120
}
.\host\run_mal_realtime.ps1 @options
```

工作顺序为：恢复快照 → `start ... nogui` 启动 → 客体凭据/Tools 探测 → 建立接收订阅 → READY → 10 秒基线 → vmrun 启动虚拟机内程序 → 观察到文件名匹配的 Event ID 1 → 300 秒观察 → 排空保存 → 恢复健康快照 → 下一样本。

**本包保持脚本原有 nogui 行为。** 没弹出 VMware 窗口不代表虚拟机没运行；需要观察时，可在 VMware GUI 打开同一虚拟机查看，不要并行再启动第二轮控制脚本。

300 秒不包括启动系统、等待 Tools、订阅、基线、等待样本启动和排空。默认 `StartTimeout` 必须大于 `BaselineSeconds + ExecuteTimeout`（默认 10 + 60 秒），改参数时需保留这个关系。

脚本不在物理机启动样本。凭据不写入实验输出，但 VMware 客体操作本身通过 vmrun 认证。样本是否真正开始加密，需要独立行为证据，不能由 vmrun 返回 0 推断。

### 9.3 重跑、跳过和更换配置

同一输出根目录中，已有同哈希、同家族、同观察时长、process 模式且 status=complete、XML 哈希相符的运行会被跳过。异常记录保留，新尝试使用新 run_id。

**当前跳过逻辑不比较 Sysmon 配置哈希或快照名称。** 因此更换配置、文档语料或实验环境后应使用新的批次目录（例如 `thesis-swift-v2-batch02`），不能仍用旧输出根目录来期望全部重采。不需要为重采删除历史数据。

### 9.4 可选：手动启动单个样本，只用接收器

若需要手动诊断，先恢复健康虚拟机，在物理机启动 process 接收模式：

```powershell
$sampleHash = (Read-Host '填写当前家族样本的64位SHA256').Trim()
& $python .\host\receiver.py receive --sample $sampleHash --family Lockbit --output D:\SysmonLogs\manual-diagnostic --start-mode process --duration 300
```

按第 8 节方法读取本轮 status.json；看到 armed 后，才在隔离虚拟机中按照原有流程启动对应 SHA256.exe。出现匹配 Event ID 1 后开始计时。该命令不会自动执行样本，也不会在结束后自动恢复快照，需要手动收尾；诊断轮单独保存。一般批量采集使用 9.2 节即可。

### 9.5 时间参数对照

| 自动脚本参数 | 默认 | 单轮接收器对应项/含义 |
|---|---:|---|
| WaitSeconds | 300 | `--duration`，观察时间 |
| BaselineSeconds | 10 | 自动启动前的基线，手动模式没有自动等待这一阶段 |
| BootTimeout | 120 | 虚拟机启动与客体探测相关等待 |
| CollectorTimeout | 60 | 分别传给 `--connect-timeout`、`--ready-timeout` |
| ExecuteTimeout | 60 | 单次 vmrun 启动调用超时，不是程序运行时长 |
| StartTimeout | 120 | `--start-timeout`，等待匹配的进程创建事件 |
| DrainTimeout | 120 | `--drain-timeout`，停止订阅后排空等待 |
| ReceiverExitTimeout | 10 | 结果提交后接收进程退出宽限 |

单轮接收器另有 `--silence-timeout`（默认 30 秒，无任何传输字节）；自动控制脚本没有暴露同名参数。以上是分阶段超时，不能把它们全部理解为固定的额外耗时，也不宜无依据地扩大。

## 10. 输出文件、完成状态与中止

每轮保存为 `输出根目录\样本或软件SHA256\run_id\`：

| 文件 | 含义 |
|---|---|
| `events.xml` | 完成写入的 XML 容器，内部保留各 Sysmon 原始事件 XML；异常轮也可能有这个文件 |
| `events.xml.sha256` | XML 文件内容的哈希，不是样本哈希 |
| `metadata.json` | 身份、时间、采集状态、停止原因、统计及异常 |
| `status.json` | 接收状态和进度；是状态快照，不是完整进度历史 |
| `events.xml.part` | 中断时尚未正式闭合的文件，不能直接当作完整 XML |
| `controller_result.json` | 自动控制脚本在部分收尾路径记录的接收端退出情况；不是全流程审计 |
| `receiver.stdout.log` / `receiver.stderr.log` | 自动流程的接收端输出；手动接收时不自动生成这两个文件 |

状态为 `connecting → waiting_ready → armed/recording → draining → finalizing → complete/incomplete`。process 模式有 armed 等待启动；immediate 不依赖样本启动来开始计时。

**complete 说明被采集器观察到的传输通过检查，不说明源头所有事件都被采到，不说明发生了加密，也不表示正常类别标签。** `Completed/failed/skipped` 是控制流程的汇总，failed 有时发生在尚未建立输出目录之前，也可能发生在文件已保存的后续步骤；不能用 metadata 一个字段推断所有失败原因。

新版 metadata 的 `status_updates.write_failures` 记录辅助进度写入失败次数。这些告警不等于事件丢失，不单独将运行判为 incomplete；最终 XML/metadata 写入失败和队列丢弃仍按失败处理。进度可能暂时过期，最终结果以 metadata、XML 和计数核验为准。

查看一轮：

```powershell
$runDir = Read-Host '粘贴要检查的完整运行目录'
$m = Get-Content (Join-Path $runDir 'metadata.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$m | Select-Object status, event_count, transport_complete, stop_reason, problems | Format-List
$m.guest_final_stats | Format-List
$m.status_updates | Format-List
Get-FileHash (Join-Path $runDir 'events.xml') -Algorithm SHA256
```

检查大小和队列（物理机；`$python` 按第 3 节设置）：

```powershell
& $python .\tools\check_log_volume.py D:\SysmonLogs\thesis-swift-v2-batch01 D:\SysmonBenignLogs\thesis-swift-v2-batch01
```

重点核对 dropped、watcher_errors、序号、observed/sent/received、最终 END 和最终队列。缺少 final stats 不能拿最后心跳当成功结束。默认队列为 8192 个事件 / 64 MiB 估算 XML 字符串负载，宽范围事件是否能在 120 秒排空必须试采；日志大小无固定上限。

要提前停止手动接收，可在另一个物理机终端向本轮目录发送中止请求：

```powershell
$runDir = Read-Host '粘贴要中止的完整运行目录'
Set-Content -LiteralPath (Join-Path $runDir 'abort.request') -Value 'manual stop'
```

这会中止整轮并标记异常，不是“成功完成较短实验”。直接 Ctrl+C 也会被视为中断，且不保证完整排空。手动 receiver 退出不会自动重置虚拟机；自动 vmrun 脚本则会尝试在 finally 中排空和恢复，若整个终端被强制关闭，这些收尾不一定完成。

修复中断的 `.part` 文件（先确保该轮接收程序已经停止）：

```powershell
& $python .\host\receiver.py recover $runDir
```

恢复只保留可恢复完整记录、闭合 XML 并重算哈希，仍标记 incomplete，不会补回丢失事件。不要手工把 status 改成 complete。

## 11. 配置与批次记录

本版没有自动把配置指纹写入每一轮 metadata。项目 VERSIONS.json 和静态 XML 哈希只证明项目中的文件，不能单独证明虚拟机实际加载了它。

在虚拟机完成配置更新、核对活动配置后，记录 Sysmon 版本、实际 EXE 哈希、配置文件哈希、快照名称、文档语料版本和采集模式，保存成批次记录。可以在物理机的项目外创建：

```powershell
New-Item -ItemType Directory -Path D:\SysmonExperimentProfiles\thesis-swift-v2-batch01 -Force | Out-Null
Copy-Item .\VERSIONS.json D:\SysmonExperimentProfiles\thesis-swift-v2-batch01\package-versions.json
Copy-Item .\sysmon\sysmonconfig-export.xml D:\SysmonExperimentProfiles\thesis-swift-v2-batch01\sysmonconfig-export.xml
```

再加入从虚拟机取得的实际配置与版本记录，以及 `batch-notes.md`。每轮目录通过批次路径关联这些记录。旧数据没有证据时配置标为未知，不反填当前版本。

## 12. 预处理：两类日志统一构建

使用 [preprocess/README.md](preprocess/README.md) 的v2流程。预处理脚本只读原日志，正常和恶意批次在清单中显式标注，输出到新目录。源码版提供 inputs.all.example.json；将其复制为本地 inputs.all.json，并按自己的数据修改路径与标签。

```powershell
& $python .\preprocess\preprocess.py --input-manifest .\preprocess\inputs.all.json --output 'D:\SysmonProcessed\pilot-v2' --sequence-length 64
& $python .\preprocess\dataset.py 'D:\SysmonProcessed\pilot-v2'
```

统一保留原始事件审计、28个行为字段、系统/关联两种连续事件视图。数值加载器输出 `[64,148]` 和padding mask。旧v1.1特征及旧Notebook的逐行reshape不能直接混用。

全部同规则运行通过审核后，再使用 make_splits.py 按运行组/样本划分；不要按事件随机划分。同正常软件不同版本建议通过review_template.csv统一group_id。具体命令、OOV、字段清单和论文依据均见预处理子目录说明。

## 13. 后续训练读哪些文件

| 输出 | 用途 |
|---|---|
| `runs.jsonl.gz`、`manifest.csv` | 每轮身份、标签、质量和分组 |
| `events.jsonl.gz` | 结构化事件、时间、来源和关联 |
| `features.jsonl.gz` | 当前固定特征，模型输入只取嵌套 features 对象 |
| `sequences.jsonl.gz` | 有序事件 ID 列表、system/related 视图、有效长度和补齐要求 |
| `feature_schema.json` | 特征字段契约 |
| `summary.json`、`build.json`、`SHA256SUMS.txt` | 构建与完整性审计 |

使用当前特征和时间定义训练，可以读取这些产物，不需要每个 epoch 重新解析 XML。更改字段、时间策略或清洗方法时，从原 XML 重新生成新版本，因此原日志需要长期保留。

默认使用 System/TimeCreated，process 窗口锚定已验证的启动事件，immediate 窗口锚定 guest_ready_utc；原始 Sysmon UtcTime 和主机收到时间保留用于审计。`--time-source sysmon` 可用于独立敏感性分析，但要对比较的数据采用一致策略。

system 与 related 是有重叠的两种视图，应分别训练/比较，不能当作独立样本直接混合。训练前按样本 SHA256 分组；正常软件还要按软件/场景分组。不要把同一轮片段拆到训练和测试两侧。采集与预处理工具不做模型训练、编码器拟合或 SMOTE。数据划分见 make_splits.py，训练见 training/ 与 training_baselines/。

## 14. 常见问题

| 现象 | 检查方向 |
|---|---|
| guest readiness timeout | VMware Tools、客体账号密码和实际 whoami 探测；不先归因样本文件 |
| 等不到 READY | 管道名称/服务端设置、COM1、任务是否运行、是否有另一个接收器占用 |
| armed 一直不 recording | process 模式未看到指定 SHA256.exe 的 Event ID 1；检查样本是否真的在当前快照中及配置是否生效 |
| immediate 显示 recording，但事件很少 | 软件是否实际操作、事件是否能被 Sysmon 观察；不等于传输坏了 |
| 等待超过 300 秒 | 查看 state 区分启动等待、排空与保存；不要仅根据墙钟判断卡死 |
| status=complete 但控制台 failed | 同时读 controller_result、stderr、控制台和恢复快照错误；它们不是同一层状态 |
| 换了规则仍被 skipped | 当前跳过逻辑不比较配置指纹；换新输出批次目录 |
| 正常日志预处理失败 | 确认用包内 v2.0、显式 benign、完整时长、guest_ready_utc/END 和最终统计 |
| XML 很大或 dropped 增长 | 看文件/注册表等事件分布和队列负载；不能通过仅过滤某一类别或强制截断来解决 |
| 操作了删除但没有预期事件 | 区分真实删除和移入回收站，确认实际加载的配置，并用自检验证 |

## 15. 可选诊断、测试和卸载

物理机或正常测试环境可以运行以下合成测试，它们使用 mock vmrun 和合成事件，不操作真实虚拟机或样本：

```powershell
.\tests\run-tests.ps1 -PythonExe $python
& $python -m unittest discover -s .\preprocess\tests -p 'test_*.py' -v
& $python .\sysmon\build_config.py --validate
```

编译测试需要 Windows 自带 .NET Framework 编译器。测试通过不代表虚拟串口吞吐或实际 Sysmon 驱动覆盖已验证。当前整合验证见 `INTEGRATION_CHECKS.md`，历史报告在 docs 中。

虚拟机前台调试采集器时，先停止任务，避免争用 COM1：

```powershell
Stop-ScheduledTask -TaskName SysmonSerialCollector
& 'C:\Program Files\SysmonSerialCollector\SysmonSerialCollector.exe' --port COM1 --baud 115200
# 前台退出后，再执行：
Start-ScheduledTask -TaskName SysmonSerialCollector
```

移除 C# 开机任务（保留程序与诊断日志）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SysmonRealtime\guest\uninstall.ps1
```

卸载 Sysmon 本身是另一件事，只在确实要移除时使用：

```powershell
& 'C:\Sysmon\Sysmon64.exe' -u
```

上述卸载都不是日常每轮采集步骤。规则来源和许可见 `sysmon/upstream`；官方命令参考 [Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。
