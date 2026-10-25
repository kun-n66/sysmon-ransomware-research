# 预处理研究依据与两轮日志审计

日期：2026-09-28。本文基于用户提供的两篇完整论文的已提取文本、PermutationImportance_v3_3.ipynb 的已提取代码、现有 v1.1 预处理源代码以及本次两个真实 XML。未重新运行旧论文的模型，未训练新模型，不报告分类准确率。

## 1. 参考研究如何落实到代码

| 来源 | 阅读所得与采用部分 | 不直接照搬的部分 |
|---|---|---|
| Ispahany et al. (2025), §III-D | Sysmon 多字段行为表示；FastText 使用字符 n-gram，处理稀有词与词内部结构；论文说明93个属性覆盖29类事件 | 当前冻结规则并没有29种事件，更不能强行补成93个同名有效特征。本实现采用结构化行为字段作为主方案，未实现增量学习和FastText复现 |
| Akhtar et al. (2022), §5–6 | CNN-LSTM 混合结构、特征提取/选择和恶意/正常分类动机 | 文中描述不足以给出与当前XML一一对应的可执行预处理契约；不据此声称其编码方法或其性能已经复现 |
| DeepLog (2017), §2–3 | 保留事件类型、参数信息和事件间时间；用有顺序的多事件窗口建模 | DeepLog以正常数据学习异常检测，本项目是带弱标签的二分类，不把其目标函数当作本实现 |
| LogBERT (2021) | 日志序列上下文是可学习对象，为保留时间序列提供另一个研究参照 | 未采用BERT或自监督训练；有限时间/GPU下不增加这种训练任务 |
| Drain | 解决非结构化文本日志的模板提取 | Sysmon已经有EventID和命名EventData，无需把XML转成自由文本再用Drain猜模板 |
| TESSERACT (2019) | 恶意软件评估中数据分布、时间和实验偏差会造成过高估计 | 该研究场景为Android；这里只借鉴控制评估偏差的原则，不推断其数值适用于Windows Sysmon |

对应原文：[Ispahany DOI](https://doi.org/10.1109/ACCESS.2025.3569635)、[Akhtar DOI](https://doi.org/10.3390/sym14112308)、[DeepLog 作者托管原文](https://nlp.cs.utah.edu/assets/pdfs/du2017deeplog.pdf)、[LogBERT 原文](https://arxiv.org/abs/2103.04475)、[Drain 官方实现](https://github.com/logpai/logparser/blob/main/logparser/Drain/README.md)、[TESSERACT USENIX](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury)。

**固定28字段、64事件片段、5秒因果统计、两层审计与行为表示，是本项目根据当前数据与资源提出的实现选择，不是上述论文已经替我们证明的最优参数。** 64和5秒需要后续验证集/消融实验支持。去除身份信息可以减少直接泄漏，但不能保证已经消除了应用类型、环境或人为操作差异。

## 2. 与旧 Notebook 的关系及 OOV

核对 `PermutationImportance_v3_3.ipynb` 的提取代码：v3.3 已不使用 FastText；低基数字符串使用整数类别编码，高基数使用平滑目标均值编码，另加路径结构特征。旧流程对未见低基数类别使用兜底编码，高基数未知值回退训练集标签均值。

这种“未知路径退回总体恶意率”的方式不能保留新路径的行为含义。目标编码还需要注意训练行自身的标签污染，通常应采用交叉拟合；本数据有运行相关性，还要确保折分按运行/样本分组，而非普通逐行折分。[scikit-learn TargetEncoder 文档](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.TargetEncoder.html)

本版直接去除高基数身份字符串，保留粗语义类别和事件关系/密度，使用固定独热表示，不访问标签计算输入特征。未知文件名不会增加词表；未知后缀归other；真正未收录的类别保留UNK。FastText仍可作为未来可选对照，但应先脱敏、仅以训练语料学习，不能把包含家族名、SHA256和样本路径的原文直接用于预训练。[fastText 官方说明](https://fasttext.cc/docs/en/unsupervised-tutorial.html)

另一个必要修正是时间轴：旧代码 `reshape(-1, K_TOP, 1)` 对应一条事件的K个字段。本版 `x[64,148]` 是64条按时间排列的事件，每条148个固定编码维度。SHAP/LIME的方法可以后续继续使用，但解释对象必须跟着新输入定义更新，不能把旧32字段的重要性直接继承为新模型的结论。

## 3. 本次日志核对结果

### 3.1 来源

正常：
```text
D:\SysmonBenignLogs\thesis-v1_1-batch01\1eee71cccd2ea6e94d5bcea54ee2f759844da3e1a0ee2f6045035b1d17b94381\benign_notepadpp_20260916T050442Z_76a38e96
```
恶意：
```text
D:\SysmonLogs\newrules\7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a\20260920T115934Z_9c255459e24c
```

| 检查 | 正常运行 | BlackBasta运行 |
|---|---:|---:|
| XML字节数 | 654,299 | 3,359,377 |
| 原始记录数 | 526 | 2,755 |
| 300秒窗口记录数 | 526 | 2,636 |
| 窗口外记录 | 0 | 119（启动前基线） |
| 当前策略进入模型的事件 | 526 | 2,636 |
| 进程树/关联窗口事件 | 80 | 2,382 |
| 关联树进程数 | 5 | 7 |
| 完全重复Event记录 | 0 | 0 |
| SystemTime与UtcTime最大差值 | 0.098736秒 | 0.354528秒 |
| 系统视图64事件片段 | 9，末段14条 | 42，末段12条 |
| 关联视图片段 | 2 | 38 |
| 传输质量检查 | 通过 | 通过 |

两轮均满足 observed=sent=XML数，dropped/watcher_errors/queued_events=0，XML SHA256同时匹配metadata与sidecar。正常 END 时间覆盖完整窗口；恶意 controller_result 表示正常提交、退出码0、未强制终止。未检测到ID255。

XML SHA256：

- 正常：`0c967d5adbcd15478d786868ca84654d223db539fd1af4c57edd190b74aab7c1`
- 恶意：`1d7402d27f356c4acafd8e510d785cdf0ccfb2d89f191810cc82019aa6bc03b0`

窗口内事件分布：

| ID | 正常 | 恶意 |
|---|---:|---:|
| 1 | 33 | 29 |
| 5 | 32 | 46 |
| 11 | 302 | 2,031 |
| 12 | 1 | 0 |
| 13 | 7 | 9 |
| 26 | 151 | 521 |

这些数量描述采集到的记录，不等价于所有磁盘读写次数。Sysmon ID11涉及文件创建或覆盖，ID26是删除检测；它们本身不验证文件内容是否已加密。[Microsoft Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### 3.2 正常日志的软件标签需要纠正

目录及metadata family为 `Benign_NotepadPlusPlus`，但登记SHA256在ID1中匹配的是：

```text
C:\Users\<username>\AppData\Local\SumatraPDF\SumatraPDF.exe
```

窗口有3次匹配SHA256的启动。包括打开 `123.pdf`、打印相关进程，以及由SumatraPDF启动Edge访问项目网站的命令行；命令行含URL不等于网络已经连接成功。系统窗口还有Edge文件缓存、spool/打印、Explorer等操作。

因此，该轮可保留为正常活动候选，不能在论文统计中继续算成“已核实的Notepad++专用实验”。通过审核CSV填写software_name和group_id纠正派生数据，不修改原始metadata。主视图继续保留这些活动；不把混合活动错误归因于单个软件根进程。

### 3.3 恶意日志有行为证据，但不是加密成功的独立证明

样本启动的文件名与Sysmon内容SHA256匹配。关联进程包含cmd/vssadmin，日志中出现3条包含 `delete shadows` 的命令行（不同进程事件）。这支持存在卷影副本删除尝试，不能仅由命令行证明命令成功。

关联ID11为1,929条，其中 basename `readme.txt` 为1,926条；关联ID26为440条，其中小写 `readme.txt` 为437条，另有1条大小写不同的 `ReadMe.txt`。文件创建涉及1,706个不同完整目标路径。它们不是传输重复事件，不能按相同文件名去重。它们体现勒索信创建/删除的行为模式，但不能单独证明大量用户文档完成加密。

所有9个正常系统片段中，4段没有已知目标GUID关联事件。这说明系统片段不能简单等同于该软件自己的行为。当前恶意42段都有已知GUID关联事件，但不能据此把未来所有恶意窗口片段都标成“每事件恶意”。

## 4. 接下来的实际流程

1. 使用本版统一处理全部已冻结规则的批次，先检查质量清单、软件身份、时钟告警和采集异常；不要为了增加样本数把失败运行默认混进训练。
2. 通过review_template记录软件名、操作场景与人工行为证据；把同一样本重复运行、同一正常软件不同版本合理合并为分组。
3. 固定按组划分的训练/验证/测试，保留实际CSV。先做少量pilot训练，确认特征、mask和弱标签边界处理无误，再扩大规模。
4. 最小可行对照：EventID序列基线；完整28字段；去除时间/密度字段；system与related视图对照。所有模型使用同一分组，related结果注明已知目标身份前提。
5. 用类别召回率、F2、PR-AUC、误报率及运行级结果衡量；报告按独立运行/样本的数量，不用片段数量冒充独立样本量。训练集可按运行/类别加权，不在验证和测试集做人为合成平衡。
6. HIDS离线主机行为识别为研究范围。缺少网络事件并不阻止这项实验，但不能据此推广为在线C2检测、所有未知家族识别或加密发生前检测。

当前两轮只完成了**审计、结构化和读取链路验证**；28字段是否优于其他方案、11种正常软件能否充分覆盖误报场景，仍需后续独立测试支持。
