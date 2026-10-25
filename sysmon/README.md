# Swift 离线研究配置 v2.0.0

当前配置：**thesis-swift-offline-v2.0.0**。唯一部署文件为本目录的 sysmonconfig-export.xml。

SHA256：2411d23e6d8f7902848ff14aa1061d9dc0caa5ed4f7052ebaba0eb00be2f1db1

研究边界：断网 Windows 虚拟机中的主机行为分类，不研究网络流量、联网后行为或网络依赖。规则命中不是恶意标签，日志完整也不能证明样本已加密文件。

## 安装与更新

将 sysmonconfig-export.xml 复制到虚拟机 C:\SysmonRealtime\sysmon\。以下命令在**虚拟机管理员 PowerShell**执行，EXE 路径按实际位置调整。

首次安装：

~~~powershell
& 'C:\Sysmon\Sysmon64.exe' -accepteula -i 'C:\SysmonRealtime\sysmon\sysmonconfig-export.xml'
if ($LASTEXITCODE -ne 0) { throw 'Sysmon 安装失败，请保留完整错误信息。' }
~~~

已有 Sysmon，直接更新：

~~~powershell
& 'C:\Sysmon\Sysmon64.exe' -c 'C:\SysmonRealtime\sysmon\sysmonconfig-export.xml'
if ($LASTEXITCODE -ne 0) { throw 'Sysmon 配置更新失败，请保留完整错误信息。' }
(Get-FileHash -LiteralPath 'C:\SysmonRealtime\sysmon\sysmonconfig-export.xml' -Algorithm SHA256).Hash.ToLowerInvariant()
& 'C:\Sysmon\Sysmon64.exe' -c
~~~

文件哈希验证复制是否正确；必须同时检查更新退出码和实际加载配置，不能用文件存在来证明规则生效。若 EXE 名为 sysmon.exe，替换命令中的文件名即可。无需 Python、生成器、额外 SIEM 或重新安装 C# 采集器。

卸载（仅在确实要移除 Sysmon 时）：

~~~powershell
& 'C:\Sysmon\Sysmon64.exe' -u
~~~

XML 使用 schema 4.90，面向本项目已使用的 Sysmon 15.21 环境。这里未在用户虚拟机内实际加载。遇到版本问题先保存错误并查看 Sysmon64.exe -s；不要只改 schema 数字。更新本身不要求重启，准备可复现的健康快照是后续独立步骤。

## 事件策略

| ID | 配置 | 理由及范围 |
|---|---|---|
| 1 | 全范围 | 保留正常与样本进程创建、父进程信息，撤掉 Swift 进程排除 |
| 2 | Swift 原筛选 | 文件创建时间修改线索；不是普通文件修改，原 include/exclude 均保留 |
| 3 | 关闭 | 网络连接不在研究范围 |
| 4、16、255 | Sysmon 自身状态、配置变更与错误信息 | 用于质量审计，不作为恶意标签，不强行删除 |
| 5 | 全范围 | 包括 C:\samples 和 Program Files 中程序的退出 |
| 6 | Swift 原筛选 | 保留其驱动加载选择性规则 |
| 7 | 关闭，沿用 Swift | 不全面记录模块加载 |
| 8 | Swift 原筛选 | 保留远程线程创建规则及其排除 |
| 9、10 | 关闭，沿用 Swift | 不再保留旧 Modular 的原始设备读取、进程访问扩展 |
| 11 | 全范围 | 记录 Sysmon 可见的文件创建/覆盖，不限制扩展名或样本目录 |
| 12–14 | Swift 原筛选 | 不再使用旧自定义注册表扩展及 vmtoolsd 特例 |
| 15 | Swift 原筛选 | 保留原命名流规则、直接事件块与分组语义 |
| 17–18 | Swift 原筛选 | 命名管道也是本机 IPC，不因离线而整体关闭；不再全部放开 |
| 19–21 | Swift 原规则 | WMI 事件订阅记录 |
| 22 | 关闭 | DNS 不在此次研究范围 |
| 23 | 明确关闭 | 不归档被删除文件内容 |
| 24、25 | 明确关闭 | 上游对应示例未启用，本研究不额外打开 |
| 26 | 全范围新增 | 记录删除，不归档删除文件内容 |
| 27、28 | 明确关闭 | 不主动阻止样本操作 |
| 29 | 明确关闭 | 撤掉此前的额外可执行文件检测记录 |

“全范围”仅表示该事件类别无配置过滤，不表示 Sysmon 能记录所有系统调用、每次读写或全部重命名，也不保证无丢失。ID 11/26 不是加密内容证据。ID 2 原筛选可能漏掉 C:\samples 下样本修改普通文档创建时间；此限制有意保留，不宣称完整时间戳监测。

全局 HashAlgorithms 只保留 SHA256；CheckRevocation=False、DnsLookup=False 用于关闭相应联网补充查询。关闭网络日志和补充查询都不是网络隔离措施，隔离依然由 VMware 环境保证。

## 与旧版的区别

不再以 Sysmon Modular default+ 作为生成来源。除了上表明确覆盖的事件和全局选项，所有 Swift 活动规则的字段、条件、分组关系与顺序均保留。原文件有直接位于 EventFiltering 下的 FileCreateStreamHash 块，生成器也完整保留。

旧 Modular 材料位于 legacy-modular/ 和 upstream/ 中原有文件，均是历史材料；当前生成器只读取 upstream/swift/。不加载旧规则，不叠加前几轮白名单。

关闭无关后台应用、完成更新和旧版本清理，通常比继续扩大排除名单更合理。正常文件批量创建/删除仍会被记录，应作为正常对照的一部分。不得只对正常类过滤某种操作。

## 验证与开始新批次

1. 更新 XML，检查命令成功、文件 SHA256 和实际配置。
2. 使用本项目 tools/Test-ResearchTelemetry.ps1 执行无害核心自检：ID 1、5、11、26，共六项检查。它不再要求选择性注册表事件出现。
3. 在物理机接收 XML 中确认相同 smoke 标记；本地成功不代表管道已验证。
4. 测试 300 秒空闲、正常操作和少量既有样本采集，核对 metadata、丢弃数、进程启动证据、XML/哈希和数据量。仅 status=complete 不证明发生了加密。
5. 在健康系统中保存新基准快照，如 SysmonResearch_Swift_v2。正式采集前关闭用于检查日志的管理窗口。
6. 新批次使用 D:\SysmonLogs\thesis-swift-v2-batch01 和 D:\SysmonBenignLogs\thesis-swift-v2-batch01；批量脚本的 SnapshotName 指向新快照。其余采集命令见主 README。

不必删除历史日志。两类正式数据必须使用同一个配置哈希、快照基线和文件语料。旧日志经过清洗不能补回当时未采集的事件，因此不可直接冒充新配置数据。现有接收端不会自动记录实际 Sysmon 配置指纹，需按主 README 保存批次配置与 VERSIONS.json，勿只依赖单轮 metadata。

## 可复现来源与检查

上游：[SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)，固定提交 1836897f12fbd6a0a473665ef6abc34a6b497e31，文件提交日期 2021-10-17 UTC；2026-09-14 获取。该日期不代表项目所有文件的最新更新时间。

保留的原 XML 含原作者说明及 CC BY 4.0 授权；归属和改动说明见 upstream/swift/ATTRIBUTION.md、source.json、changes.json 和 swift-to-thesis.patch。派生配置同样使用 CC BY 4.0，不代表上游作者认可本研究。

~~~powershell
python .\sysmon\build_config.py
python .\sysmon\build_config.py --validate
python -m unittest discover -s tests -p test_config.py -v
~~~

这些是离线复现/静态验证命令，安装时无需执行。静态验证不能代替虚拟机的驱动加载、实际事件和吞吐量验证。

事件含义参考：[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。

