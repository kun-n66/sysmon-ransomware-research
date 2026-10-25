# Sysmon 行为时序预处理 v2.0.1

v2.0.1新增：读取新接收器metadata中的software_name，审核CSV可覆盖纠正。28字段/148维模型特征契约不变。正常采集入口见项目主README第8节。旧日志不会自动改名或改写metadata。

适用：冻结的 `thesis-swift-offline-v2.0.0` 配置、Windows 10 离线虚拟机、管道采集的 XML 和 metadata。基于原 v1.1 更新，采集端、接收程序、Sysmon XML 均不改变。Python 3.9+，所有预处理和编码工具只依赖标准库；已在 Windows/Python 3.12 实测，未在 Colab 实机测试。

**默认推荐：系统窗口 → 身份信息隔离 → 行为特征 → 连续事件片段 → 按运行/样本分组划分。** 不根据进程是系统程序、出现频率高或看起来正常就删除事件。正常软件的批量写文件、删除、打印和缓存行为，是区分勒索行为所需的对照。

## 1. 先理解这次变更

| 项目 | v1.1 | v2.0 |
|---|---|---|
| 多个类别/根目录 | 一次一个输入目录 | 支持 JSON 输入清单，每个根目录显式给定类别 |
| 稳定事件身份 | 相对输入目录生成；单轮输入可能碰撞 | `sample_sha256/run_id` + Record 序号；换输入根目录身份不变；重复运行身份拒绝构建 |
| 特征 | 36 个通用字段，含路径长度、深度和不适用的网络字段 | 28 个行为字段；去掉具体程序身份、路径长度/深度及网络字段 |
| 编码 | 留给训练 Notebook | 固定词表独热编码，148 维；MISSING/UNK/OTHER 与 padding 区分 |
| 时间 | 保留事件序列索引 | 新增相邻事件/同一进程时间间隔、过去 5 秒文件操作密度 |
| 重复事件 | 不处理 | 仅完全相同 Event XML 的后续副本不进入模型；原始审计仍保留 |
| 质量 | metadata、XML、计数、时间窗 | 增加 controller_result 检查、process 模式 END 时间覆盖检查、ID255 隔离 |
| 划分 | 人工后续处理 | 提供按组划分工具和防同样本跨集合的验证器 |

这是特征契约升级：**不能把旧 v1.1 特征与新 v2.0 混在同一次训练中，也不能直接加载旧模型权重当作已适配模型。** 原 XML 无需重新采集，使用同一版本统一重跑预处理。历史说明保存在 `README-v1.1.md`，只用于追溯。

## 2. 预处理具体做什么

### 2.1 质量审计与标签

- 读取 `metadata.json`、`events.xml`、`events.xml.sha256`；核对 XML 身份、SHA256、记录数量、连续传输 Sequence、最终 observed/sent/dropped/error/queue、停止原因。
- process 模式在 XML 内核对启动序号、ProcessGuid 和 SHA256.exe 文件名；Sysmon 启动事件有 SHA256 时，再核对内容哈希。
- immediate 模式必须显式标记 benign。窗口以 guest_ready_utc 为起点；用登记的 SHA256 搜索软件启动事件，不要求正常软件重命名。
- 有 `controller_result.json` 时核对 run_id、提交状态、强制终止状态和退出码。缺少此文件不自动视为失败，因为正常手动采集本来就可能没有控制脚本。
- END guest_utc 已记录时必须覆盖窗口；旧 process metadata 未记录该时间仅告警，不伪造完整证据。ID255 表示 Sysmon 内部错误，整轮保留审计但不出训练序列。
- 不完整、哈希不一致、截断 XML、失败运行仍进入清单和审计输出；默认不出训练序列。截断文档只保留完整解析的 Record 前缀。
- `complete` 仅描述采集传输；`label` 由输入清单/审核 CSV 明确指定；`behavior_review` 单独记录人工证据。没有人工确认时 `unknown` 保持不变。允许这种运行作为**弱标签候选**，并不宣称已确认加密。

旧 metadata 没有实际 Sysmon 配置哈希。v2 会写 `config_verification=not_available_in_legacy_metadata`。事件 ID 分布符合预期也不能证明当时使用了某一完整 XML；请在实验记录中保留固定配置文件和 SHA256。

### 2.2 时间和事件筛选

默认时间轴为 `System/TimeCreated`，按该时间、传输 Sequence 排序，窗口 `[start, start+300秒)`；使用 metadata 中实际 requested_duration，不硬编码所有运行都是300秒。process 从核实的启动事件计时，immediate 从 guest_ready 计时。它们的起点语义不同，报告中保留说明。

原 Sysmon `UtcTime`、SystemTime、ReceivedUtc 全部保留审计。两种事件时间差超过默认 5 秒会告警，不把旧时间强行修成当前时间；存在大幅时间跳变的批次必须先审核。`--time-source sysmon` 只用于经确认的对照实验，不能在同一实验中按类别选择不同时间轴。

进入行为特征的事件 ID：`1,2,5,6,8,11,12,13,14,15,17,18,19,20,21,26`。ID4/16/255 用于诊断审计；其余 ID 在当前冻结配置下不进入模型，并提示配置范围异常。**这是预处理选择，不会更改 Sysmon 的采集规则。**

基线和排空尾部保留在 events 中；不计入300秒训练窗口。仅完全相同 Windows Event 子树的重复副本标为 exact_xml_duplicate，不进入模型。不同 RecordID、时间或目标文件仍是不同事件，即使编码后向量相同也不去重。相同名字的 readme.txt 在不同路径出现，必须保留其频率。

### 2.3 删除身份字段，提取行为字段

模型不读取：family、软件名、SHA256、ProcessGuid/PID、用户名、Computer、SID、RuleName、RecordID、绝对日期、run_id、采集状态、具体程序/文件名称、完整命令行、路径长度与深度、软件版本与厂商、Source/Target 原始 GUID。

这些字段不是从证据中销毁：它们仍在 events/runs 审计层。GUID 仅临时用于关联进程和计算同进程时间间隔；完整文件路径仅临时用于统计近期不同文件数。

28 个字段：

| 类别 | 字段/含义 |
|---|---|
| 事件及角色（3） | event_id；actor_role；parent_role。只识别少量通用系统工具角色，如 shell、shadow_admin；普通应用和样本都是 other |
| 文件上下文（2） | file_class：文档、文本、媒体、数据库、临时文件等；file_location：临时目录、文档目录、系统目录等粗类别 |
| 注册表及权限（5） | registry_area、registry_hive、operation、integrity、registry_value_kind；不传具体值或产品名 |
| 命令行与执行标志（12） | command_missing、is_executable；10 个通用语义标志：编码参数、URL、卷影删除、备份删除、禁用恢复、停止服务、注册表编辑、计划任务、文件删除、递归参数 |
| 关联与时序（6） | same_actor_as_previous、delta_previous、delta_actor；过去5秒含当前事件的创建次数、删除次数、不同文件数 |

时间间隔先截断到300秒、计数到10000，再 log1p；不读取未来事件，不以整个运行的最终总量归一化。相关视图使用同一系统时间线已计算的背景统计，便于对照。

文件扩展名映射到预定义语义类别；未知后缀统一 other，不为 LockBit/Conti 等后缀设置专门标志。不识别特定勒索信文件名。代价是可能丢失细粒度语义，因此需要后续消融验证；不能预先保证优于原论文。

不会用微软签名或系统程序名作为“无害证明”。命令行标志表示观察到的文本意图，并不证明命令执行成功。

### 2.4 OOV、缺失值、padding

- 当前主方案不再给成千上万条路径学习类别编号或目标均值。新用户名、哈希、文件名通常根本不进入词表。
- 未收录后缀、普通程序、其他注册表路径 → **other 语义类**。
- 固定词表编码器仍保留 `<UNK>` 通道，遇到不在 schema 的类别走 UNK，不报错。
- 源字段不存在/空/`-` → null；类别编码为 `<MISSING>`；数值和布尔使用0加缺失指示列。
- 末段不足64条仍保留。补齐行为是全零行，另给显式 mask；模型必须正确使用 mask，尤其 Conv1D 不会天然自动尊重它。
- 无需在全部数据上拟合词表、StandardScaler 或目标编码器。若后续加可学习文本嵌入、PCC/MI、Scaler，必须只用训练组拟合。

### 2.5 两种视图与弱标签

`system` 是主实验：窗口内所有可用事件，包括后台活动。`related` 是辅助对照：用已知样本/软件 SHA256 确认启动进程，再通过 ProcessGuid/ParentProcessGuid 构建进程树，加 GUID 关联上下文。**related 使用已知目标身份，不能当作未知攻击检测的无先验能力。** 已经在窗口前启动的软件、经服务代理的行为可能无法关联；这不表示行为不存在。

默认每64条连续事件一段，无重叠、不跨运行；不足64条补齐时保留 mask。可用 `--sequence-length 32` 或128做训练集内选参，不能用测试集挑长度。片段内部不打乱；训练时可打乱片段顺序。

所有片段继承 `run_weak_label`。恶意运行里的某段可能完全是系统背景活动；`background_only_by_guid`、related_event_count 只是审核字段，不能作为模型特征，也不按此字段单方面删除恶意背景段。提供每段 `run_weight=1/该运行片段数`，避免高产日志的运行主导损失；这是按运行加权，并没有自动平衡类别。

建议主报告同时给出运行级聚合指标。片段级指标明确写“弱标签片段分类”，不能改称逐事件恶意判定。若用 max/mean/投票聚合片段预测，阈值与聚合方式在验证集确定。没有实现模型训练或声称早期阻断能力。

## 3. 快速运行：先验证用户提供的两轮日志

将此包的 `preprocess` 文件夹复制到 `D:\SysmonRealtime\preprocess`，保留现有 host/guest/sysmon 文件。以下命令在物理机 PowerShell 执行，不需要启动虚拟机。

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
& $python .\preprocess\preprocess.py --input-manifest .\preprocess\inputs.pilot.json --output 'D:\SysmonProcessed\pilot-v2' --sequence-length 64
if ($LASTEXITCODE -ne 0) { throw '预处理失败；查看报错，不要使用未完成输出。' }
& $python .\preprocess\dataset.py 'D:\SysmonProcessed\pilot-v2'
```

inputs.pilot.json 已包含本次两个确切路径和显式二分类标签。输出目录必须不存在，重跑请换名字。两轮只能验证处理流程，不能独立划分 train/validation/test。

处理全部同规则日志前，检查并复制 `inputs.all.example.json` 为 `inputs.all.json`，确认目录中只有你打算纳入的批次： 

```json
[
  {"path": "D:\\SysmonBenignLogs\\thesis-v1_1-batch01", "label": "benign"},
  {"path": "D:\\SysmonLogs\\newrules", "label": "ransomware"}
]
```

```powershell
& $python .\preprocess\preprocess.py --input-manifest .\preprocess\inputs.all.json --output 'D:\SysmonProcessed\all-v2' --sequence-length 64
& $python .\preprocess\dataset.py 'D:\SysmonProcessed\all-v2'
```

一个根目录只含同一标签；混合目录应细分清单路径或使用审核 CSV 显式覆盖标签。输入清单不允许重叠目录或重复运行。旧单目录命令仍可用：

```powershell
& $python .\preprocess\preprocess.py --input 'D:\SysmonLogs\newrules' --label ransomware --output 'D:\SysmonProcessed\ransomware-v2'
```

不要把两个单独输出目录的 JSONL 简单拼接当作最终数据集；使用多输入清单统一构建并生成校验清单。

## 4. 审核、分组、划分

先看 manifest.csv 的 quality_issues、warnings、observed_primary_images、model_event_count、label。人工结果写入**复制出来的** review_template.csv：

- run_key 是稳定的 `SHA256/run_id`；标签取 benign/ransomware/other_malware/unknown。
- behavior_review：unknown、behavior_observed、encryption_confirmed、no_observed_activity；非unknown需要 review_note。不要仅凭 ID11 写 encryption_confirmed。
- group_id 默认 `sha256:样本哈希`。同一样本重复运行必须同组；正常软件不同版本建议手工统一成 `software:sumatrapdf` 等，使同软件不跨集合。没有审核时不会从错误的 family 字段猜软件。
- 本次标成 Notepad++ 的正常轮实际哈希匹配 SumatraPDF，建议记录 `software_name=SumatraPDF`、`group_id=software:sumatrapdf`，review_note 写实际操作。原 metadata 不覆盖，论文清单使用审核后的软件身份。

```powershell
Copy-Item 'D:\SysmonProcessed\all-v2\review_template.csv' 'D:\SysmonProcessed\reviews-v2.csv'
# 编辑 reviews-v2.csv 后，在新目录重建；不可直接修改带校验和的输出。
& $python .\preprocess\preprocess.py --input-manifest .\preprocess\inputs.all.json --annotations 'D:\SysmonProcessed\reviews-v2.csv' --output 'D:\SysmonProcessed\all-v2-reviewed'
& $python .\preprocess\make_splits.py 'D:\SysmonProcessed\all-v2-reviewed' --output 'D:\SysmonProcessed\splits-v2.csv' --seed 20260928
```

make_splits 按类别分层、按group随机划分约70/15/15，每类至少3个独立组，否则拒绝划分。小组数时每类至少保留1个验证和1个测试组，实际比例会变化；这只是技术下限，不表示3组就能可靠评估。seed和实际组数打印到终端，CSV是实际划分依据。验证器同时禁止同 SHA256 或同 group 跨集合。

11种正常软件的泛化证据仍有限。重复运行有助于覆盖操作，但不能当作新软件；尤其不要随机按事件分层，让相同软件操作/同一恶意运行的相邻片段泄漏到测试。家族留出、时间留出属于后续单独实验，当前工具的随机分组结果不冒充这些实验。

## 5. 输出与训练读取

| 文件 | 用途 |
|---|---|
| runs.jsonl.gz / manifest.csv | 运行标签、质量、证据和审核；不作为X |
| events.jsonl.gz | 全部已解析事件、原字段、时间、关系、排除原因；审计原文，不直接作为X |
| features.jsonl.gz | 每条事件的28个结构化行为字段；是否使用由序列索引决定 |
| sequences.jsonl.gz | 两个视图、顺序、UID、标签、分组、有效长度和运行权重 |
| feature_schema.json / numeric_schema.json | 行为字段定义和固定148维数值列顺序 |
| review_template.csv | 人工审核入口；复制到输出之外编辑 |
| summary.json / REPORT.md / build.json | 统计、参数、脚本和来源清单指纹 |
| SHA256SUMS.txt | 输出文件完整性校验 |

JSONL.gz 保留类型、空值、可变 EventData，并压缩大小，Python标准库可读。CSV用于清单，不能替代原始结构。暂不强制安装PyArrow或把复杂原文摊成极宽CSV。每轮XML最多512MiB，解析按轮持有事件；dataset便利加载器会在内存建立索引，大数据集应后续分区/流式读取。

训练时无需重新解析 XML；使用 dataset.py 读取上述输出即可，XML继续保留用于复核和未来提取新特征。以下只演示加载，**不是训练代码**：

```python
import sys
sys.path.insert(0, r'D:\SysmonRealtime\preprocess')
from dataset import iter_numeric_examples

for batch_item in iter_numeric_examples(
    r'D:\SysmonProcessed\all-v2-reviewed',
    view='system',
    splits=r'D:\SysmonProcessed\splits-v2.csv',
    split='train',
):
    x = batch_item['x']         # [64, 148]；实际转换为 numpy.float32 / tensor
    mask = batch_item['mask']   # [64]；True表示真实事件
    y = batch_item['y']         # benign=0, ransomware=1；运行级弱标签
    weight = batch_item['weight']
    context = batch_item['context']  # 仅评估聚合/追溯，不喂给模型
```

旧Notebook的 `reshape(-1, K_TOP, 1)` 把单条事件的不同字段当成序列位置。本版真正的维度是 `[batch, 连续事件数, 148个数值维度]`。CNN沿事件轴提取局部模式，LSTM沿事件时间轴建模；不能直接接回旧reshape。不要对时序片段使用普通SMOTE生成不真实的混合事件序列。可在训练集使用类别权重、按运行采样，并记录评估分布。

## 6. 研究依据与建议实验

详见 `RESEARCH_AND_PILOT.md`：区分从论文借鉴的设计和本项目新增选择，不声称逐项复现原论文。建议先比较 EventID-only 与完整28字段，再做去时间密度的消融；system主实验、related辅助对照。评价包括召回率、F2、PR-AUC、误报率与运行级指标，先固定测试集，再做训练/验证集选参。当前代码不做增量学习，也不需要为了预处理购买更多GPU。

运行回归测试：

```powershell
& $python -m unittest discover -s .\preprocess\tests -v
```
