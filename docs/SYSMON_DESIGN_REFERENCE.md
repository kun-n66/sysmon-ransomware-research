> 历史记录：本文描述旧 Modular 配置。当前规则与部署步骤以 [Swift v2 更新说明](UPDATE-SWIFT-V2.md) 为准。

> 历史 v1.0 文档。当前规则已更新为 v1.1.1，部署与范围请以 [2026-09-14 更新说明](UPDATE-20260914.md) 为准。本文旧哈希、全量注册表设计及体积估算不代表当前配置。

> 本文件是整理前的设计/验证记录，保留原日期和原包路径。当前项目操作以根目录 README.md 为准；本次测试见 INTEGRATION_CHECKS.md。

# Sysmon 勒索软件行为研究配置 v1.0.0

配置标识：`thesis-sysmon-v1.0.0`。制作日期：2026-09-11。

本配置用于你的 Windows 10 隔离虚拟机、300 秒实验窗口、串口实时传输、正常/勒索运行分类和后续 CNN-LSTM 时序研究。它定义采集范围，不输出恶意判定，也不承诺提高分类准确率。当前交付是通过静态检查的试采候选版本，尚未在你的虚拟机 Sysmon 驱动上加载或完成吞吐测试。

## 1. 交付文件

| 文件 | 用途 |
|---|---|
| `sysmonconfig-thesis-v1.xml` | 应用到虚拟机 Sysmon 的完整配置；无需与其他 XML 手工拼接 |
| `Test-ResearchTelemetry.ps1` | 在虚拟机执行的无害自检，检查本地核心事件是否可见 |
| `build_config.py` | Python 3.9+ 标准库离线重建和静态验证程序；正常部署不需要 Python |
| `changes.json` | 各事件的新模式与上游规则数量 |
| `default-plus-to-thesis.patch` | 上游到本配置的完整文本差异，包含重排/格式变化 |
| `upstream/` | 固定版本的原始 default+、原始许可证和来源/哈希记录 |
| `VALIDATION.md` | 本次实际验证范围和待完成的虚拟机验证 |
| `SHA256SUMS.txt` | 包内文件完整性清单 |

上游为 Olaf Hartong 的 Sysmon Modular `sysmonconfig-with-filedelete.xml`，固定到该文件的提交 `a9ff298f6d228c181be71b213c73d111c6096f41`。保留原始许可证；本包新增代码亦按 MIT 许可提供，见 `LICENSE`。上游文件最后修改时间为 2023-09-20，并不等于仓库其他模块最后更新时间。实验固定到实际 XML 字节，不能用“下载了最新 master”代替版本记录。

## 2. 文献依据与本研究设计的边界

1. **Ispahany 等，IEEE Access 2025，DOI 10.1109/ACCESS.2025.3569635。** 论文 III-B、III-C 与 IV-A 描述了 Sysmon 事件流、正常与勒索运行、快照恢复和五分钟实验。本研究继承行为遥测与实验窗口的思路。文中提到“default events”，不能据此推断作者使用了 Sysmon Modular default+，更不能推断所有事件默认启用。该论文的联网 Windows 11 环境与当前完全断网 Windows 10 环境不同，结果不应直接等价比较。[正式论文页面](https://ieeexplore.ieee.org/document/11002852/)；[作者机构保存的正式论文](https://researchoutput.csu.edu.au/files/604926062/604439333_Published_article.pdf)。
2. **Akhtar 与 Feng，Symmetry 2022，DOI 10.3390/sym14112308。** 可作为 CNN-LSTM 架构方面的参考。其第 5.1 节说明数据来自 Kaggle；它没有给出可供本项目复用的 Sysmon XML。因此，本配置不能宣称复现了该论文的 Sysmon 采集规则。[论文原文](https://www.mdpi.com/2073-8994/14/11/2308)。
3. **Sysmon Modular** 提供可审查的规则起点；**微软 Sysmon 文档**提供事件和过滤语义。下面的宽范围核心采集、归档关闭及高负载事件取舍，是针对当前研究的设计选择，不是文献已经验证的最佳参数。

本次核对了用户提供的两篇 PDF 的相关采集/方法章节。没有将文献中的实验结果视作本配置的测试结果，也没有重新训练模型。

## 3. 具体采集策略

“全量”仅指该事件类别没有配置级的路径、软件、用户或后缀过滤；不代表 Sysmon 可以看到全部操作系统行为，也不保证事件零丢失。

| Event ID | 类别 | 本配置 | 为什么 |
|---|---|---|---|
| 1、5 | 进程创建、结束 | 全量 | 保留主进程、子进程和退出；支持启动验证、ProcessGuid 关联和时序上下文 |
| 2 | 文件创建时间修改 | 全量 | 保留时间属性变化；不是普通写文件事件 |
| 3 | 网络连接 | 全量 | 两类实验采用同一策略；离线时允许没有这类事件，不改变网络设置 |
| 6 | 驱动加载 | 保留 default+ 筛选 | 保留当前折中，存在签名相关盲点；不宣称完整驱动审计 |
| 7 | 模块加载 | 保留 default+ 筛选 | 全开容易大量增加事件；作为辅助上下文，核心模型应做排除它的消融 |
| 8、9 | 远程线程、原始设备读取 | 全量 | 保留较少见的上下文；不等于覆盖所有注入，也不等于普通文件读取 |
| 10 | 进程访问 | 保留 default+ 筛选 | 控制事件量；仍受人工规则选择影响，单独评估其贡献 |
| 11 | 文件创建/覆盖 | 全量 | 普通文档、临时文件、勒索说明和任意后缀均使用相同采集规则 |
| 12–14 | 注册表变化 | 全量 | 同时保留正常配置修改和运行相关注册表变化；不按“可疑键”预筛 |
| 15 | 文件流创建及哈希 | 全量 | 补充 NTFS 文件流上下文；其哈希语义与普通文件内容哈希不同 |
| 17–18 | 命名管道活动 | 全量 | 补充进程间通信上下文 |
| 19–21 | WMI 事件订阅活动 | 全量 | 保留 Sysmon 支持的 WMI 订阅事件；并非记录所有 WMI 查询 |
| 22 | DNS 查询 | 全量 | 保留成功、失败及缓存查询中 Sysmon 可观测的事件；无需网络报文内容 |
| 23 | 删除并归档文件 | 关闭 | 本研究使用 XML；避免额外保存被删除文件造成磁盘与时序负担 |
| 24 | 剪贴板变化 | 关闭 | 本研究不以剪贴板内容为特征，也不采集其归档内容 |
| 25 | 进程映像篡改 | 全量 | 保留 Sysmon 检测到的篡改上下文，不能单独作为勒索行为标签 |
| 26 | 删除，仅日志 | 全量 | 获取删除行为，不归档内容，不限扩展名 |
| 27、28 | 阻止可执行文件创建、阻止文件粉碎 | 关闭 | 避免使用这些 Sysmon 功能干预被研究程序 |
| 29 | 检测可执行文件创建 | 全量 | 补充新 PE 文件创建上下文，无阻止操作 |

Event ID 4（服务状态）、16（配置变更）、255（Sysmon 错误）不通过上述事件过滤配置控制。现有采集器订阅通道全部新事件，可继续保留它们用于质量审计；它们不是恶意行为的直接证据。

### 为什么这版不是只监控某个文档目录

你目前正常操作和勒索运行的实际活动路径并不完全一致。只指定一个目录，可能遗漏软件临时文件、用户目录、程序创建的子目录与后缀变化。短时隔离实验先放开核心文件事件，再在预处理中按实验语料、进程树与系统窗口构建视图，可以减少不可逆的采集遗漏。

这比上一条建议的“至少覆盖实验文档目录”更宽，是本次针对数据集可复用性的具体取舍；代价是日志量更大，需要试采验证。两类实验仍应使用相同文档语料、目录布局与快照环境，减少模型学习环境差异的机会。

### 为什么保留 6、7、10 的选择性规则

其中 7、10 的全量记录可能显著增加负载。本版保留这三个类别的上游 RuleGroup、条件、排除关系和规则名称，其他类别原有的包含/排除块则整体替换，避免残留排除规则覆盖新增包含规则。

因此，本配置的准确描述是“核心事件宽范围采集，辅助事件选择性采集”。不应写成“全部事件无过滤”。训练时建议报告一个去除 6/7/10 的消融结果，判断性能是否依赖已有人工检测规则。若日后改变这些规则，必须发布新配置版本并同步应用到正常与恶意采集。

## 4. 全局设置

- `HashAlgorithms=SHA256`：保留与你的样本标识一致的算法，取消 `*` 对其他算法的计算。它影响 Sysmon 支持哈希的事件，不会给每个事件或每个删除文件自动附加 SHA256。现有接收端保存的 XML 文件 SHA256 是另一层完整性校验。
- `CheckRevocation=False`：沿用 default+，不在完全断网环境尝试证书吊销查询。签名字段仍不代表软件可信。
- `DnsLookup=False`：沿用 default+，关闭网络事件的反向 DNS 补全；**不关闭 Event ID 22**，也不改变其他软件的联网行为。断网下 DNS 事件缺失不证明样本没有尝试联网。
- 移除 `ArchiveDirectory`，关闭 23/24，且没有 `CopyOnDelete*` 额外归档设置。不会删除历史归档。
- 空 `onmatch="exclude"` 表示该类别不设排除；空 `onmatch="include"` 表示不包含任何事件。27/28 采用后者。

## 5. 在虚拟机中应用

只在干净分析虚拟机中操作，不要在物理机上应用此研究配置。配置制作过程没有修改任何现有 Sysmon 安装、快照、采集器或接收端。

本版沿用上游 schema `4.90`，包含 Event ID 29。schema 版本与二进制版本不是同一编号。使用当前已在 Windows 10 中工作的 Sysmon 检查其支持情况，不要为了通过校验而只改 XML 的版本数字，也不要自动更换二进制。

将本文件夹复制到虚拟机，例如 `C:\SysmonResearchConfig`。以管理员 PowerShell 执行，首先把 `$sysmon` 改为虚拟机上实际使用的 Sysmon EXE 路径：

```powershell
$sysmon = 'C:\Tools\Sysmon\Sysmon64.exe'  # 改为实际路径
$bundle = 'C:\SysmonResearchConfig'
$config = Join-Path $bundle 'sysmonconfig-thesis-v1.xml'
$audit = Join-Path $bundle ('audit_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $audit | Out-Null
if (-not (Test-Path -LiteralPath $sysmon)) { throw '请先填写正确的 Sysmon 路径' }

# 只读：记录当前状态和本机支持的 schema。
& $sysmon -c 2>&1 | Out-File (Join-Path $audit 'before-config.txt') -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw '无法读取当前 Sysmon 配置' }
& $sysmon -s 2>&1 | Out-File (Join-Path $audit 'supported-schema.txt') -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw '无法读取 Sysmon schema' }
Get-FileHash -LiteralPath $config -Algorithm SHA256

# 检查支持的 schema 后应用。配置成功无需仅为生效而重启。
& $sysmon -c $config
if ($LASTEXITCODE -ne 0) { throw '配置加载失败；停止试采，保留报错和 schema 输出' }
& $sysmon -c 2>&1 | Out-File (Join-Path $audit 'after-config.txt') -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw '无法核对加载后的配置' }

[ordered]@{
    config_id = 'thesis-sysmon-v1.0.0'
    sysmon_config_sha256 = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()
    sysmon_file_version = (Get-Item -LiteralPath $sysmon).VersionInfo.FileVersion
    sysmon_exe_sha256 = (Get-FileHash -LiteralPath $sysmon -Algorithm SHA256).Hash.ToLowerInvariant()
    os_version = [Environment]::OSVersion.Version.ToString()
    schema_version = '4.90'
    network_profile = 'offline'
    recorded_utc = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json | Set-Content (Join-Path $audit 'collection-profile.json') -Encoding UTF8
```

`before-config.txt` 是审计输出，**不能当作可直接恢复的 XML**。应用前保留你原来实际加载的 SwiftOnSecurity XML 和旧干净快照；回退使用原 XML 的 `sysmon -c` 或旧快照。加载失败后先读活动配置确认状态，不假设失败过程已经自动回退。

将该 audit 目录和 XML 保存到物理机，后续每轮输出附带对应的 `collection-profile.json`，或维护 `run_id → config_id/config_sha256` 映射。**现有 metadata 不一定已经自动记录这些新字段**，本次没有改动接收端；不要把本配置的版本补填到旧实验上。

## 6. 先做无害自检，再做少量试采

### 本地可见性

在虚拟机管理员 PowerShell：

```powershell
Set-Location C:\SysmonResearchConfig
.\Test-ResearchTelemetry.ps1
```

脚本在独立随机子目录中创建、覆盖并真实删除两个测试文件，创建并删除独立的 HKCU 测试键/值，启动一个打印标记的短命 `cmd.exe`。不使用回收站、不清空日志、不改变网络、不调用恶意程序，也不递归删除目录。保留测试目录、子进程文本和报告用于检查。

八个检查项应全部为 True，覆盖 Event ID 1、5、11、12、13、26。它不会要求“覆盖两次必须两条 11”，也不会把未触发的稀有事件认定为故障。运行需要约 2–12 秒的日志等待；异常子进程有 10 秒等待上限。

### 端到端可见性

使用你已经验证的 `immediate` 接收流程开始一轮**单独的自检采集**，然后在虚拟机执行上述脚本。把脚本输出的 `smoke_...` 标记与本地报告内的 ProcessGuid、目标路径在物理机 XML 中核对。自检记录不是正式正常软件训练样本，应在清单中标记为 `smoke_test` 并排除训练。

### 负载与实验放行

随后选择少量正常操作（例如文本编辑、批量复制、压缩/解压）和已有流程中的少量勒索试采。保持两类配置相同，检查：

- Sysmon 是否生成 255 等错误、采集器是否报告 watcher 错误。
- metadata 的 observed/sent/received 数量、dropped 计数、序号连续性和最终 END/队列状态；传输完整不证明 Sysmon 源头没有遗漏。
- 每秒事件量、XML 大小、虚拟机 CPU/内存和实验结束时队列能否在既有 120 秒内排空。
- 根进程证据、实验窗口、异常退出和行为证据是否分别记录；`complete` 不等于发生了加密。

不要仅通过无限延长 drain 超时掩盖持续积压。若宽范围注册表或文件事件明显超过当前串口吞吐，需要根据实测统一调整配置/传输方案并重新编号；不得只对正常软件删事件以降低负载。

通过试采后，从健康系统固定该配置和共同文档语料，创建**新名称**的干净快照，保留旧快照。更新主机调用的 SnapshotName，使后续恢复不会退回旧规则。自检活动无需混入正式窗口；可以按原流程清日志后保存健康快照，但清日志不保证快照后系统不再生成背景事件。

## 7. 与 XML、预处理和训练衔接

采集器仍订阅同一 Sysmon 通道，接收端仍保存 XML；无需为了增加这些 Event ID 改写传输协议。已有 `preprocess.py` v1.1 的通用 XML 解析可以保留这些事件，但其当前特征列并不等于使用了所有新字段。增加字段到模型仍需要明确更新 feature schema 并重新生成全体数据，不应只重建单一类别。

- 保留每轮完整 XML、哈希、metadata、配置指纹和原始时间字段。
- 继续输出整个系统窗口和主进程树/关联上下文两种视图，不能把整个勒索运行窗口中的每条系统事件都当作已验证的恶意行为。
- `RuleName` 及其中 MITRE 技术名称不作为模型输入；配置版本、质量状态、家族名称、样本 SHA256、run_id 和原始绝对路径等标识也不直接作为训练特征。
- 按样本 SHA256/运行组划分数据；正常软件还需要按软件/场景分组。不要把同一次运行的片段随机散入训练集和测试集。
- 推荐核心事件模型与去除 6/7/10 后的模型对照，之后再评估辅助事件收益。噪音处理、特征选择和缩放仅在训练集拟合。
- 旧 SwiftOnSecurity 日志保留为旧批次；主实验优先使用配置一致的数据。不同配置批次可以做单独对照，不能无标记混合。

Sysmon 不提供每次文件读取、每次写入、通用重命名或加密成功的完整证据。单纯统计 11/26 不能证明文件已被加密。如果论文需要“确实加密”的标签，还需独立的文档语料前后状态核验或人工证据。本包没有实现这部分。

## 8. 可复现验证

```powershell
python .\build_config.py --validate
# 可选：从固定上游离线重新生成 XML、差异文件及变更清单
python .\build_config.py
```

构建程序校验上游哈希；断言每个宽范围事件只有一个空 exclude 块、每个关闭事件只有一个空 include 块；校验 6/7/10 的整组条件与上游一致。它不是 Sysmon 驱动的 schema 校验器；最终兼容性必须通过实际二进制加载和自检确认。

参考：[Sysmon 事件与命令文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)、[微软配置语义说明](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)、[Sysmon Modular 项目](https://github.com/olafhartong/sysmon-modular)。

论文可采用如下表述：

> 本研究在固定版本的 Sysmon Modular 配置上，对进程、文件、注册表等核心事件取消基于软件及路径的预筛选，使用仅日志的文件删除事件，并关闭归档与阻止类功能；对部分辅助事件保留选择性规则。正常与勒索运行使用相同配置及配置指纹，以减少采集策略差异形成的分类偏差。该配置的有效性通过可见性检查、传输质量审计与后续分类实验验证。

在尚未完成虚拟机测试之前，将最后一句写为“计划通过……验证”，不能把计划写成完成的实验。
