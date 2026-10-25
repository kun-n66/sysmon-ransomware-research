# Sysmon 深度学习前预处理 v1.1

v1.1 新增正常手动实验的 `immediate` 支持：显式标注 benign，按虚拟机 `guest_ready_utc` 开始观察窗口，核对虚拟机 END 时间覆盖窗口。无需重命名软件或修改旧 metadata。原 process 模式及 36 个特征保持兼容。

本程序读取采集系统生成的 `metadata.json`、`events.xml`、`events.xml.sha256`，完成质量审计、事件结构化、无监督参数拟合的特征提取和事件序列索引生成。只读取日志，不启动虚拟机，不打开或执行样本，不改写原始文件。

需要 Python 3.9 或更高版本，仅使用标准库。在 Windows 10/11 和 Colab 的 Python 环境中使用相同命令。实际测试环境为 Windows、Python 3.12；没有在 Colab 上运行测试。

## 1. metadata 已经证明什么，还缺什么

| 信息 | 当前情况 | 本程序的处理 |
|---|---|---|
| 采集状态 | `status`、`transport_complete`、`problems`、最终计数等已保存 | 重新核对 XML 哈希、数量、连续传输序号、最终计数与停止原因 |
| 样本启动 | process 保存启动事件序号、ProcessGuid、时间；immediate 无此必选标记 | process 必须在 XML 中核实；immediate 的软件启动可通过 SHA256 匹配作为可选证据 |
| 样本哈希 | metadata 原本从文件名获取，并非计算样本文件内容 | 若启动事件含 Sysmon SHA256，再核对它与样本标识是否一致；缺失不伪造验证 |
| 文件/注册表等行为 | XML 中可以有相关事件 | 输出进程树关联及事件计数，便于进一步检查 |
| 成功加密、修改了哪些诱饵文档 | 当前 metadata 没有这类独立证据 | 默认 `behavior_review=unknown`；不根据 FileCreate 自动认定加密成功 |
| 正常/恶意标签 | `complete` 不能表示正常软件或已确认恶意行为 | 标签由 `--label` 或审核 CSV 明确提供，与采集状态分开 |

Sysmon 的 ProcessGuid 适合跨事件关联，避免只用可能被复用的 PID；FileCreate 描述创建或覆盖文件，本身不是加密确认。[Microsoft Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

完整和异常采集均可解析。XML 被截断时，仅保留解析器已经完整读到的 Record 前缀，整次运行进入隔离状态；无法可靠解析的文件仍在清单中记录错误。程序不修复原文件，也不会给 `.part` 冒充完整性。

**metadata 可以支持采集质量和启动证据；行为确认仍需人工审查或诱饵文件前后变化等额外证据。**

## 2. 推荐输出格式

当前采用 **JSONL.gz + CSV + JSON**，不将所有内容挤进一张 CSV。

- JSONL 每行一个对象，保留空值、布尔、原始 EventData 名称和可变字段；gzip 减小大小；Python 标准库和 Pandas 均可读取。
- CSV 用来人工检查实验清单、填写标签和行为审核记录。
- JSON 保存特征定义、处理参数、统计报告和来源映射规则。
- 原始 XML 继续作为证据源，不被这些文件替代。

Parquet 适合后续较大规模列式训练数据，但需要额外引擎。本版没有强制安装 PyArrow，也没有输出未经测试的 Parquet。数据量增长后，可以在固定 schema 后从本格式生成 Parquet；这一步不改变标签、事件身份和分组规则。[Apache Arrow Parquet 文档](https://arrow.apache.org/docs/python/parquet.html)

输出目录：

```text
processed-v1/
  manifest.csv            每次运行一行，质量、启动证据、行为状态、事件计数
  review_template.csv     可复制后人工填写的审核表
  runs.jsonl.gz           清单的完整版本，包含原始 metadata 和更多审计字段
  events.jsonl.gz         所有已解析事件，含原始字段、两种时间、关系和来源位置
  features.jsonl.gz       event_uid + 36 个明确允许进入模型的特征
  sequences.jsonl.gz      两种视图的事件序列索引，只引用 event_uid
  feature_schema.json    特征类型、源字段、解释分组、禁止使用的审计字段
  summary.json           统计和是否同时包含两类样本
  build.json             版本、代码 SHA256、参数、输入位置和生成时间
  REPORT.md              可阅读的汇总报告
  SHA256SUMS.txt          本次输出各文件的 SHA256
```

构建中断时会留下 `BUILDING.json`。只使用没有此文件、且通过 `dataset.py` 校验的输出。

CSV 对可能被电子表格解释为公式的字符串添加前导单引号；JSONL 保留精确文本，作为权威结构化版本。gzip 文件的字节哈希可能随构建时间变化，逻辑转换与事件 UID 在输入位置及内容不变时稳定。

## 3. 运行当前两个家族

将本目录 `preprocess` 放在采集项目下，与 `host`、`guest` 同级。无需在虚拟机安装这个目录。在物理机 PowerShell 中执行：

```powershell
Set-Location D:\SysmonRealtime

$options = @(
    '--input', 'D:\SysmonLogs',
    '--output', 'D:\SysmonPrepared\avos-blackbasta-v1',
    '--family', 'AvosLocker',
    '--family', 'BlackBasta',
    '--label', 'ransomware',
    '--sequence-length', '32'
)
python .\preprocess\preprocess.py @options
python .\preprocess\dataset.py 'D:\SysmonPrepared\avos-blackbasta-v1'
```

这里 `ransomware` 表示你给这批实验提供的运行标签，不表示每一条后台事件均为恶意。

本次 Codex 项目内已包含 `preprocess`，上面的命令适用于你将更新版项目放到 `D:\SysmonRealtime` 后。程序拒绝覆盖现有输出目录；再次运行请改为 `v2` 等新目录。输出目录不能位于输入日志目录内，也不能是其祖先。

不指定 `--family` 会处理输入目录下全部 metadata；不指定 `--label` 默认是 `unknown`，不会根据家族目录或采集状态推断标签。

其他参数：

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--time-source` | `system` | 按 `System/TimeCreated` 构建写入时间窗口；可选择 `sysmon` 使用 `EventData/UtcTime` |
| `--timestamp-tolerance` | `5` | 两种时间相差超过多少秒时记录审计警告；不是检测阈值 |
| `--sequence-length` | `32` | 每个非重叠序列最多包含多少事件；不是 32 秒 |
| `--max-xml-mib` | `512` | 单次运行 XML 大小上限，超过则隔离；可显式调大 |
| `--annotations` | 无 | 根据 `run_key` 加载人工审核表，覆盖该运行的标签与行为审核结果 |

解析器按文件流读取 XML，但事件处理会把单次运行的事件放入内存。不是恒定内存的无限流处理器。只处理采集系统生成的 UTF-8 XML；拒绝 DTD/ENTITY 和含 NUL 的其他编码。

## 4. 预处理规则

### 4.1 质量检查与候选数据

以下条件全部满足才有 `quality_pass=true`：

1. metadata、目录和 XML 的实验身份一致。
2. XML SHA256 同时匹配 metadata 和旁边的哈希文件。
3. XML 能完整解析，Sysmon 事件结构有效，事件数量匹配。
4. 传输 Sequence 从 1 连续递增；这里不要求 Windows EventRecordID 连续。
5. metadata 声明完整、无问题，最终 observed/sent 等计数与日志一致，无丢弃和订阅错误。
6. 停止原因为 `duration_elapsed`，持续时间有效，选用时间可解析且窗口非空。process 模式要求样本启动可核实；immediate 模式要求显式 benign 标签、虚拟机 READY 起点和覆盖窗口的虚拟机 END 时间。
7. 若存在启动事件 SHA256，不能与样本标识冲突。

同时具备 `benign` 或 `ransomware` 标签、且未被人工标记为 `no_observed_activity`，才有 `training_candidate=true` 并生成序列。

**candidate 表示可用于运行级弱标签研究的技术候选，不等同于“已确认执行加密”。** 未审核行为的完整运行可以是 candidate，其 `behavior_review` 仍明确为 `unknown`。如果论文实验限定“确认加密”，应进一步只选人工标记 `encryption_confirmed` 的运行，并同时报告筛选规则及排除数量。

异常运行的事件和特征仍保留；训练必须从 `sequences` 选择数据，不可将 `features` 全表直接赋标签训练。

### 4.2 时间与窗口

每条事件保留：

- `system_time_raw`：Windows `System/TimeCreated/@SystemTime` 原字符串。
- `sysmon_time_raw`：Sysmon `EventData/UtcTime` 原字符串。
- `received_utc`：物理机接收时间，仅用于审计。
- `system_utc`、`sysmon_utc`：规范化 UTC，计算精度为微秒；原始字符串保留更细精度。
- `system_minus_sysmon_seconds`、`timestamp_disagreement`：时间差及警告。

默认选择 `System/TimeCreated`：起点取已核实启动事件的这个时间，终点是起点加 metadata 中请求时长，窗口为 `[start, end)`。保留 `baseline`、`window`、`tail`、`unknown` 分区，训练序列只使用 `window`。

上述进程起点适用于 process 模式。正常手动实验的 immediate 模式以 `metadata.guest_ready_utc` 为起点，终点为其加请求时长；仍用相同的事件时间策略归窗。窗口定义保存在 `window_anchor_source` 和 `window_definition` 中，仅用于审计，不进入模型。接收器实际计时始于主机收到 READY，存在传输延迟，因此这一定义是虚拟机 READY 锚定的观察窗口，不是用户第一次操作的精确时刻。

这是**按事件写入时间定义的观测窗口**，并不声称事件对应的行为刚好在写入时发生。当前日志中部分 DNS 事件的 UtcTime 较早，可能涉及延迟上报或快照时间影响；本程序不自动归因、不删除它们，也不偷偷重写其时间。选择 `--time-source sysmon` 会按行为时间字段重新归窗，是可以保留的敏感性分析版本；缺少该字段的事件会导致该运行不能通过严格质量检查。

两种时钟绝不混合计算。物理机接收时刻不用于替代虚拟机事件时刻；没有尾部事件也不自动认定窗口不完整。300 秒完成依赖接收器的停止状态与最终计数，而不是最后一个事件必须恰好位于第 300 秒。

### 4.3 两种视图

- `system`：窗口内的全部已订阅系统事件，是主检测视图。
- `related`：样本根 ProcessGuid、Event ID 1 的 ParentProcessGuid 所构成的后代树，以及 SourceProcessGUID/TargetProcessGUID 一跳直接关联事件。

不使用 PID 推断后代；访问了某个进程不意味着那个进程成为样本后代。没有捕获父子关系就不会凭空补全；注入、服务和跨进程行为可能不完全被该视图覆盖。

`related` 依赖已知样本启动证据，适合辅助分析，不能当成部署时无需任何先验即可获得的视图。两种视图有重叠事件，应分别实验，不能当成独立数据简单合并。

### 4.4 特征与防止标签捷径

本版固定提取 36 个特征，不读取训练标签来计算特征：

- Event ID，作为类别而非连续数值。
- Image、ParentImage、TargetFilename、ImageLoaded：缺失指示、规范化路径深度与长度、路径位置类别、扩展名类别。
- CommandLine、ParentCommandLine：缺失指示、规范化长度、编码参数标记、URL 标记。
- IntegrityLevel、Protocol、Signed、SignatureStatus、Initiated：限定类别，未知值归为 `other`。
- 注册表根键类别、是否有 DNS 查询名称。

路径先用不依赖标签的规则规范化：实验目录中的家族层级、用户目录名、32–64 位十六进制字符串、GUID、SID。未列出的扩展名统一为 `other`，降低专有加密扩展名成为答案的风险。

路径统计修正了旧 Notebook 中把单反斜杠错误识别为双反斜杠的问题。原始字段中的 `-`、空文本和字段不存在仍可以通过 EventData 审计区分；模型视图用 null 和显式缺失特征表示，不将未知值捏造成有效的 0。

**只有 `features.jsonl.gz` 每行内的 `features` 对象可以作为模型特征。** event_uid、SHA256、家族、标签、原始路径、命令全文、绝对时间、主机名、ProcessGuid/PID、关系、采集状态、行为审核结果都不能直接输入模型。原始路径保存在审计数据中，不能把审计表全列拼接进模型。

这套规则降低明显身份信息的影响，不保证消除了所有环境捷径；路径长度、位置和缺失模式仍可能反映环境，因此正常实验的采集流程也必须一致。

不执行全局去重、不按 Windows 目录或微软签名删除事件，不删所有后台事件，不进行 PCC/MI 筛选、Target Encoding、标准化、SMOTE 或模型训练。这些涉及数据分布或标签的拟合，应在划分训练集之后进行。

### 4.5 事件追溯与解释

`features.event_uid → events.event_uid → source_xml + source_xml_sha256 + record_index`。

`record_index` 是源 XML 中第几个 Record，从 1 开始，不是文本行号。另存传输 Sequence 和 Windows EventRecordID。原始 EventData 的列表也保留，遇到重复字段名不会把覆盖后的字典当作无问题输入。

`feature_schema.json` 将路径派生特征映射回 Image 等源字段。后续解释实验可以按同一源字段分组替换，并重新计算其派生特征。映射不等于目标编码可逆，也不是对因果恶意性的证明。

### 4.6 序列与数据划分

每种视图先按所选 UTC、Sequence 排序，再在**单次运行内部**切成默认长度 32 的非重叠事件序列。末尾不足 32 的序列保留，记录 `valid_length` 和 `padding_required`，不复制最后事件补齐。

此时输出的是索引，还不是数值张量。训练阶段完成类别编码、缺失值处理和标准化之后，再构建 `[batch, events, features]`，为补齐的位置构建有效长度或 mask。CNN、池化、LSTM、attention 都必须正确处理补齐位置，不能假设一个 Masking 层会自动穿过所有层。

同一个 SHA256 的所有运行共享 `group_id=sha256:<hash>`。先按这个组划分，再把划分传给所有序列；不能先随机打散事件或序列。固定模型选择规则后才能使用测试集。

本版不自动生成训练/验证/测试划分，`split=unassigned`。候选标签不同时含 benign 和 ransomware 时，`dataset.require_binary_labels()` 会报错；两类均存在也不保证独立样本量足够评估。

正常软件若采用相同 SHA256.exe 启动证据和完整窗口协议，本程序接受 `--label benign`。v1.1 同时支持 `--start-mode immediate` 录制的正常活动。采集后执行：

```powershell
python .\preprocess\preprocess.py --input 'D:\SysmonBenignLogs' --output 'D:\SysmonPrepared\benign-v1_1' --label benign
```

标签必须显式为 benign；不根据 family 名字猜测。缺失虚拟机 READY/END 时间、提前停止、丢包等仍隔离，绝不使用物理机时间填补虚拟机时间。正常软件未在窗口内重新启动也允许生成 system 视图，此时程序身份仅是提供的标识，不声称从 XML 核实了它。

如果窗口内 Event ID 1 中的 SHA256 匹配所提供的软件标识，会记录 `xml_hash_verified`、实际主程序路径及启动次数；相同软件的多次启动均可成为 related 视图根节点，无需 SHA256.exe 文件名。related 视图仍是辅助分析，主实验统一使用 system 视图。文件创建/删除事件缺失会产生警告，而不会自动否定正常实验或补造事件。

正常、恶意可以先分别运行同一个程序生成同构输出；训练读取器后续按数据目录联合加载，并在所有数据上统一规划分组划分。不要把同名 JSONL 文件直接覆盖合并，也不要向正常源目录混入未单独标注的恶意运行。

## 5. 人工行为审核

将 `review_template.csv` 复制到输出目录之外，例如 `D:\SysmonPrepared\review.csv`。不要直接编辑已计算 SHA256 的生成文件。

字段含义：

- `run_key`：保持不变，精确对应输入目录中的相对实验路径。
- `label`：`unknown`、`benign`、`ransomware`、`other_malware`。
- `behavior_review`：`unknown`、`behavior_observed`、`encryption_confirmed`、`no_observed_activity`。
- `review_note`：非 unknown 审核必须填写证据位置和判断依据，例如具体事件、诱饵文件检查记录。程序不自动验证人工说明的真实性。

`no_observed_activity` 只是当前观察条件下未发现活动，不证明样本永久无效。`behavior_observed` 表示有活动证据，不自动指恶意活动；`encryption_confirmed` 应基于独立核验，不能只因为有 Event ID 11。

重新运行时增加：

```powershell
python .\preprocess\preprocess.py --input 'D:\SysmonLogs' --output 'D:\SysmonPrepared\avos-blackbasta-v2' --family AvosLocker --family BlackBasta --label ransomware --annotations 'D:\SysmonPrepared\review.csv'
```

## 6. 在 Notebook 中读取

标准库即可检查和读取：

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path('/content/sysmon-realtime/preprocess')))
from dataset import verify_checksums, read_rows, iter_examples, require_binary_labels

directory = Path('/content/avos-blackbasta-v1')
verify_checksums(directory)
example = next(iter_examples(directory, view='system'))
event_feature_rows = example['features']   # 未编码，包含 null
audit_context = example['context']        # 含标签与 group_id，不作为输入特征
print(len(event_feature_rows), audit_context['valid_length'])

# 现在这一行会报缺少正常样本；补齐正常实验后才进入二分类训练。
require_binary_labels(directory)
```

如果只想查看表格，可用 Colab 通常已有的 Pandas：

```python
import pandas as pd
manifest = pd.read_csv(directory / 'manifest.csv', encoding='utf-8-sig')
events = pd.read_json(directory / 'events.jsonl.gz', lines=True, compression='gzip')
features = pd.read_json(directory / 'features.jsonl.gz', lines=True, compression='gzip')
feature_table = pd.json_normalize(features['features'])
feature_table.index = features['event_uid']
```

`dataset.py` 的方便读取器会在内存中建立事件和特征索引，适合当前规模；大数据版本应使用按运行分区的 Parquet/流式加载。

## 7. 测试

```powershell
python -m unittest discover -s .\preprocess\tests -v
python .\preprocess\dataset.py 'D:\SysmonPrepared\avos-blackbasta-v1'
```

覆盖哈希不一致、样本启动 GUID 与内容哈希、截断 XML、DTD、传输序号缺口、提前停止、进程树及一跳上下文、半开窗口、时间差、缺失值、路径规范化、标签不推断和端到端来源追溯。

本程序不导入 RADAR CSV，也不会手动修复 RADAR。那类字段错位需要独立、有记录的数据修复步骤，不能用当前 XML 解析流程混合处理。
