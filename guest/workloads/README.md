# 离线正常工作负载 v1.0：补充真实软件的行为覆盖

本组件自动执行受控的正常文件工作流，通过现有VMware管道采集Sysmon。适用Windows PowerShell 5.1、Windows 10离线虚拟机，无需安装Python或第三方包，不要求管理员权限。它不是新的系统活动无哈希模式：目标进程是**实际执行脚本的powershell.exe**，使用该exe的真实SHA256关联启动事件。

## 1. 用于什么研究

脚本生成的正常活动适合补充批量文件操作、备份、压缩、临时文件清理，提供可能与勒索行为相似的正常对照。保留已有真实软件数据；不同场景、种子和重复次数不等于独立的软件产品数量。不能将本组件生成的日志称为LibreOffice、7-Zip等真实应用的日志，也不能把其性能当作真实应用泛化结果。

建议先单独采集一轮，检查实际Sysmon分布，再作为辅助训练数据；主要误报评估仍使用保留的真实软件运行。所有场景保持原冻结Sysmon规则，沿用300秒观察窗口、断网环境和健康快照流程。环境和分组差异可能导致过高估计，实验设计需控制这些偏差：[TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury)。

## 2. 已实现的场景

| Scenario | 工作流 | 主要可观察行为 |
|---|---|---|
| documents | 生成文本、读取、临时文件保存、覆盖原文件、清理临时文件、重命名 | 文档编辑/另存流程的文件操作部分 |
| archive | 生成文档、ZIP压缩、解压、SHA256校验、删除临时ZIP | 压缩与恢复 |
| backup | 复制文件、校验哈希、修改一个源文件、更新备份 | 小型备份/同步 |
| reports | 生成CSV、重新读取、导出JSON/HTML、复制及删除导出副本 | 数据转换/报表处理 |
| cleanup | 生成本轮测试文件、改为临时文件名、逐个删除 | 应用缓存清理 |
| mixed | 按随机种子从上述五种场景中选择，每个循环执行一种 | 混合活动；不是第六种独立软件 |

输入均为脚本生成的文本、CSV等有效测试文件，不读取已有用户文档。每轮创建唯一目录，所有文件操作限制在该目录内；拒绝重解析点，删除仅针对本轮生成的单个文件，没有递归删除。文件数量/大小、循环次数有上限，不修改服务、驱动、Sysmon配置或网络设置。

**生成语料与真实软件/恶意软件所用语料可能不同，这仍可能构成实验差异。** 在论文中记录这一点；不要仅用“真实恶意语料 vs 脚本生成语料”的结果证明可泛化。此版本没有任意输入目录或批量处理真实用户文件的参数。

## 3. 不追求凑齐所有事件ID

当前冻结配置下，主要观察ID1、5、11、26，即进程生命周期与文件创建/删除。ID11不是逐次写入审计，重命名/读取也不保证对应独立Sysmon事件；actions.jsonl的操作数量不能当成Sysmon记录数量。[Microsoft Sysmon说明](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

- ID2：本组件不主动修改创建时间，不保证产生或命中现有筛选。
- ID12/13/14及17/18：是否出现取决于实际进程行为、后台活动和Swift筛选。本组件没有为了命中规则而写敏感注册表位置或使用可疑管道名。
- 已关闭的网络/DLL等事件不会因为脚本产生相关活动就被捕获，不为正常类单独更换规则。
- 注入、WMI持久化、Sysmon错误/配置变更不作为日常工作负载目标。事件覆盖自检和正常行为训练数据应分别标记。

没有某些事件ID并不意味着样本无效。最终需要关注两类数据可比性及正常行为多样性，而不是事件ID全集。

## 4. 文件放置

这是新增组件，搭配接收器1.2.0、正常采集入口和预处理2.0.1使用。

物理机放置：

```text
D:\SysmonRealtime\host\run_scripted_benign.ps1       新增
D:\SysmonRealtime\host\run_benign_realtime.ps1       已有
D:\SysmonRealtime\host\receiver.py                  已有1.2.0
```

将guest/workloads文件夹复制到虚拟机：

```text
C:\SysmonRealtime\guest\workloads\Invoke-BenignWorkload.ps1
```

准备好健康快照。后续每轮恢复该快照，保证输入环境可比。不要在正在运行恶意样本的实例上同时采集正常数据。

## 5. 一次半自动采集：只需手动开始一次，随后自动执行

### 第一步：虚拟机取得执行器的真实SHA256

在虚拟机64位Windows PowerShell中执行：

```powershell
$engine = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant()
```

复制这个哈希到物理机。**不要传.ps1文件的哈希、物理机powershell.exe的哈希或任意固定值。** 32位/64位执行器可能不同；计算与启动使用同一个$engine路径。

### 第二步：物理机启动采集

在物理机终端A：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
.\host\run_scripted_benign.ps1 -Scenario documents -PythonExe $python
```

按提示粘贴虚拟机执行器SHA256。默认结果保存在单独目录 `D:\SysmonBenignLogs\scripted-v1`，不会混入现有真实软件批次。metadata名称为 `Scripted_documents`，family为 `Benign_Scripted_documents`。

在物理机终端B，按host/README.md第4节的方法读取status.json。看到recording后才进行下一步。软件名称不会使脚本自动连接或控制虚拟机。

### 第三步：虚拟机运行工作负载

在虚拟机PowerShell中执行以下完整命令，**它会创建一个新的powershell.exe进程**，保证启动事件位于采集窗口内：

```powershell
$engine = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$workloadArgs = @(
    '-NoProfile', '-File',
    'C:\SysmonRealtime\guest\workloads\Invoke-BenignWorkload.ps1',
    '-Scenario', 'documents',
    '-Root', 'C:\BenignWorkloads',
    '-DurationSeconds', '240',
    '-MaxCycles', '40',
    '-FilesPerCycle', '8',
    '-FileKiB', '8',
    '-MinPauseMs', '3000',
    '-MaxPauseMs', '9000',
    '-Seed', '101'
)
& $engine @workloadArgs
```

如果实验虚拟机的执行策略阻止运行这份已检查过的本地脚本，可仅对这个子进程在$workloadArgs的-NoProfile后添加 `'-ExecutionPolicy', 'Bypass'`，无需永久更改系统执行策略。

工作负载开始后不需要持续点击操作。它在达到时间限制或最大循环数后停止；时间限制在循环边界检查，最后一个循环可能稍微超过240秒。默认保留约60秒给手动启动及尾部观察。即使工作负载先结束，也让物理机完成300秒观察及排空。主机与虚拟机的Scenario必须相同；改变Seed不改变类别或软件身份。

### 第四步：保存实验说明，再恢复快照

虚拟机输出目录为 `C:\BenignWorkloads\workload_时间_随机ID`，其中：

- workload.json：`data_origin=scripted_benign`、场景、种子、参数、脚本SHA256、解释器SHA256、状态、操作计数。
- actions.jsonl：实际完成的文件操作、UTC时间及本轮相对路径。
- cycle_*：生成的测试文件、备份和报表。

在恢复快照前，通过已有的受控文件复制方式，将 **workload.json和actions.jsonl** 另存到物理机对应采集运行目录，例如 `workload-evidence` 子目录。不要把workload.json重命名为metadata.json，也不需要复制生成的全部文档。

核对接收器metadata的采集状态，并核对workload.json的status、实际场景和解释器哈希。采集complete不等于工作负载complete；本版预处理不会自动读取这两个辅助报告，需先人工审核。来源标记在工作负载报告及Scripted_名称中，接收器metadata没有新增data_origin字段。

## 6. 少量试采建议

先做5种单一场景各1轮，验证事件内容。确认正常后，可按下面的设置增加行为变化：

| 变化 | 例子 | 目的 |
|---|---|---|
| FilesPerCycle | 3、8、15 | 改变批量操作数量 |
| FileKiB | 1、8、32 | 改变文件大小 |
| MinPauseMs/MaxPauseMs | 3000/9000、1000/4000 | 区分缓慢与较密集的正常操作 |
| Seed | 101、202、303 | 改变内容及暂停/混合场景选择 |

不要求凑到1000条日志。相同参数与Seed可复现生成内容及随机选择，但调度、执行时间和Sysmon事件条数不保证逐条一致。六个Scenario属于同一工具生成的数据，不要写成“新增六种正常软件”。

## 7. 与现有预处理和训练分组的衔接

现有预处理2.0.1即可读取这些immediate日志，继续生成system和related视图、28字段/148维时序输入，无需修改Sysmon或模型输入结构。默认仍建议system作为主视图：相同powershell.exe哈希可能匹配窗口内多个PowerShell启动，related不一定只包含这一份脚本。

单独处理补充数据的命令：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
& $python .\preprocess\preprocess.py --input 'D:\SysmonBenignLogs\scripted-v1' --label benign --output 'D:\SysmonProcessed\scripted-v1-audit'
& $python .\preprocess\dataset.py 'D:\SysmonProcessed\scripted-v1-audit'
```

只包含正常类时，dataset会提示不能单独进行二分类训练，这是预期行为。

同一PowerShell二进制哈希相同，因此默认同组；这是合理的相关性保护，不能为了增加“独立样本”而伪造哈希。同工具不同执行器版本也建议通过审核CSV合并为 `software:scripted-workload-toolkit-v1`。同组不同轮次和种子必须一起划分，不能跨训练和测试。

正式评估建议对比“只用真实软件训练”与“真实软件+脚本补充训练”，使用相同的真实软件测试集，观察误报率/召回率是否改善。当前make_splits不会自动把scripted组固定为train；合并后需要显式审核划分CSV，把整个工具组放到训练集，并保证真实软件测试组仍保持独立。不要把分别预处理的JSONL随意拼接，正式合并仍用输入清单统一构建。

不要把脚本命令行中的Scenario/Seed、完整路径或Scripted标签作为特征。当前行为编码已排除这些原文字段，但PowerShell角色、临时文件布局和生成语料仍可能形成捷径；不能声称已完全消除偏差。

## 8. 已验证和未验证的范围

已在Windows PowerShell5.1中实跑全部六个场景的小规模工作流，核对压缩/备份哈希、操作报告与目录外哨兵文件不变；验证相同种子的生成文本一致、错误Root/暂停参数拒绝；物理机采集入口完成Preview验证。

尚未在你的虚拟机上实际采集这组脚本的Sysmon日志，所以没有宣称每轮会产生固定数量或全部目标事件ID。需要先采集一轮，核对进程SHA256、ID1/5/11/26及采集质量，再决定补充数量。
