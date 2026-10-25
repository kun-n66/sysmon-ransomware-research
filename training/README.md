# Sysmon CNN-LSTM Colab v1.0

本项目把 Preprocess **v2.0.1** 的系统事件序列输入 CNN-LSTM，完成 `benign=0 / ransomware=1` 二分类。主要实验使用 `system` 视图，预测单位包括事件片段与整次采集。它是针对离线 Windows 10 主机行为的实验代码，不是完整复现 iCNN-LSTM+，也没有实现增量学习。

## 1. 最简单的 Colab 使用方法

1. 将 `Sysmon_CNN_LSTM_Colab.ipynb` 上传到 Colab。Notebook 内嵌了本项目 Python 模块和原版 v2.0.1 读取器，不需要额外上传代码文件。
2. 将**完整的前处理结果文件夹**上传 Google Drive，例如 `MyDrive/SysmonResearch/avos-blackbasta-benign-v1/`。Windows 上对应的是 `D:\SysmonProcessed\avos-blackbasta-benign-v1`。不要把 D 盘路径直接写入 Colab。
3. Colab 中选择 GPU 运行时。代码也能使用 CPU，只是较慢。使用 Colab 已有的 TensorFlow、NumPy、scikit-learn、Matplotlib；不要在现有 GPU 环境中盲目升级 TensorFlow。缺少依赖时安装后重启运行时再从头运行。
4. 按顺序执行 Notebook。默认参数已经对应上述 Drive 路径；若目录不同，只修改配置单元中的 `DATA_DIR`。
5. 首次运行自动创建固定的 `splits_family_seed20261001.csv`，以后比较模型必须复用它。正式训练默认最多 40 epoch，早停耐心 7 epoch，batch size 32。
6. 先看训练/验证结果，再执行独立的测试评估单元。结果保存到 Drive 的 `SysmonResearch/experiments/cnn_lstm_时间戳/`，也可以在最后下载 ZIP。

需要上传的前处理文件（保留原文件名，不要手工编辑）：

```text
avos-blackbasta-benign-v1/
  build.json
  events.jsonl.gz
  features.jsonl.gz
  feature_schema.json
  numeric_schema.json
  runs.jsonl.gz
  sequences.jsonl.gz
  manifest.csv
  review_template.csv
  summary.json
  REPORT.md
  SHA256SUMS.txt
```

不需要上传原始 XML，更不需要上传样本 EXE。读取器为了验证时序和片段完整性仍然读取前处理的 `events.jsonl.gz`，但不会将原始路径、命令行等审计字段送入网络。

也可上传打包好的数据 ZIP 到 Drive，将配置中的 `DATA_ZIP` 指向它；代码先解压到 Colab 临时磁盘再读取，减少 Drive 小文件访问。ZIP 必须只含上述文件或单层同名文件夹；内置解压函数检查目标路径与文件大小。读取器会核验全部 SHA256。内存读取器适合当前数据量；扩大到全部家族后如内存不足，需要分区/流式加载，不能通过删除完整性校验解决。

## 2. 当前数据与划分边界

制作代码时核对的这份数据有 70 次采集：32 benign、15 AvosLocker、23 BlackBasta。其中 **53 次满足当前训练候选条件**（32 benign、15 AvosLocker、6 BlackBasta），另外 17 次不进入训练序列。默认 system 视图有 **1,326 个 `[64,148]` 片段**。候选通过不等于已经人工确认加密行为；标签仍是采集运行级弱标签。

训练/验证/测试按 `group_id` 分组：正常类作为一层，恶意类按家族分层，约 70/15/15；同一 SHA256 不能跨集合。片段在训练时打乱，片段内事件顺序保留。默认种子不按性能挑选。输出同时记录各集合家族分布，每个恶意家族至少需要 3 个独立组，默认让各家族在三个集合中都有代表；这不是留一家族测试。已有划分会校验并复用，不自动重排；极少样本家族需另行预先设计划分，不能强拆同组数据。

**正常软件的 SHA256 分组不等于软件产品分组。** 同一软件不同版本、安装器、卸载器可能有不同 SHA256；旧数据里也有错误的 Notepad++ 名称。正式论文实验前，应使用前处理 `review_template.csv` 和现有 annotation 流程纠正 `software_name`，让同一产品/工作负载的运行共享 `group_id`，重新生成不可变数据，再生成一份新的固定划分。不要直接修改有校验和的数据。只有完成这种复核后才把 `SOFTWARE_GROUPS_REVIEWED=True`；这个参数只记录声明，不会自动纠正分组。

未经复核也能运行，但只能称为 **SHA256/group 留出初步实验**，不能据此宣称对未见过正常软件的泛化能力。当前测试运行数很小，不适合把接近 100% 的分数解释为稳定结论。重复观察测试集后继续改模型，会把测试集变成开发集；正式结果需要冻结方案后的独立留出集。

## 3. 特征、时间轴与 OOV

输入为 `[batch, 64 个按时间排序的事件, 148 个数值特征]`，另有 `[batch,64]` 布尔掩码。28 个结构化字段经前处理固定类别编码后成为 148 维；代码动态读取 schema，不硬编码特征宽度。

- 主输入只来自 `features`，不包含家族名、软件名、SHA256、PID、GUID、绝对时间、原始路径、RuleName 或标签。
- 类别已固定为语义类别，未知值走 `<UNK>`，缺失值走 `<MISSING>`；数值及布尔项带缺失标记。PAD 是掩码为假的全零行，与缺失事件不同。
- 直接继承 v2.0.1 的固定 log1p 数值变换。不额外做全数据词表、标签编码、PCC/MI 筛选、StandardScaler 或 SMOTE。后续如引入拟合型变换，只能在训练集拟合。
- 64 是**事件数量**而非秒数；时间间隔及近期文件活动作为特征输入。一个片段的 LSTM 不会自动跨到下一个片段，也不能声称记住整段 300 秒轨迹。
- 普通类别映射与脱敏降低身份捷径，但不能消除系统环境、工作流程、样本覆盖差异造成的全部偏差。

## 4. 网络与学习目标

```text
features + valid mask
    → 清零 PAD
    → 并行 causal Conv1D(32, kernel=3) / Conv1D(32, kernel=5)
    → 拼接为 64 通道 → 再次清零 PAD
    → LSTM(64)，显式传入 valid mask
    → Dropout(0.3) → Dense(32, ReLU) → Dense(1, sigmoid)
```

两个卷积核提供不同局部上下文尺度；单层 LSTM 控制当前小样本下的模型复杂度。没有时间池化，避免额外的掩码重采样。因果卷积只看当前位置及之前的事件，但模型仍然是片段分类实验，不等于已验证在线检测延迟。

Adam 学习率 0.001、clipnorm=1.0、二元交叉熵。训练权重使每次运行在同一类别中总贡献相同，同时平衡两类的总权重；不能把长日志拆出很多片段当成很多独立软件。验证损失只做运行平衡，最佳 checkpoint 按验证损失保存。训练和验证 loss 的加权方式不同，不应直接比较其绝对差值判断过拟合。

每个片段继承所在运行的标签；勒索软件运行里的背景系统事件不都具有恶意性。整次运行的概率采用**固定的片段概率算术平均**，末尾短片段也占一份，明确记录该选择。它可能稀释稀疏恶意行为；如比较其他聚合方式，必须在验证集上决定，不能看测试集后更换。

## 5. 阈值、指标及输出

最佳模型仅在验证集运行级概率上选择最大 F2 的阈值；并列时优先较低 FPR，再取较高阈值。F2 强调漏报，但可能增加误报，必须同时报告 Precision、Recall、FPR、FNR。

主要指标是**运行级**结果，片段级结果为辅助。输出包括 ROC-AUC、Average Precision（AP，区别于梯形积分 PR-AUC）、F1/F2、混淆矩阵与各类别计数。家族表仅是二分类检出的分组统计，不是家族分类模型。没有把片段当独立样本计算置信区间。

```text
best.keras                       最佳验证损失模型
config.json                      版本、种子、硬件、形状、参数、数据校验指纹
splits.csv / split_summary.json   固定划分及运行/家族数量
feature_columns.json             特征顺序
dataset_*.json / dataset_SHA256SUMS.txt   原数据 schema / 构建记录
history.csv / history.json        训练历史
threshold.json                   验证集选择的阈值与聚合规则
validation_run_predictions.csv
test_run_predictions.csv          主要预测结果
test_sequence_predictions.csv    辅助片段结果
test_metrics.json / evaluation.png
```

加载模型前要 `import training` 注册自定义掩码层。Notebook 给出了重载验证单元。对于未来尚无标签的生产日志，需要另外实现推理数据入口；现有 v2.0.1 读取器面向已经标注的研究数据。不要为了推理而伪造真实标签。

## 6. 与参考研究的关系

- Ispahany 等（2025），[iCNN-LSTM+](https://doi.org/10.1109/ACCESS.2025.3569635)：借鉴 Sysmon 行为表征和 CNN/LSTM 组合；本实现不采用其增量更新流程，也不宣称复现其网络、FastText 特征或原始数据分布。
- Akhtar 等（2022），[Detection of Malware by Deep Learning as CNN-LSTM Machine Learning Techniques in Real Time](https://doi.org/10.3390/sym14112308)：作为 CNN-LSTM 组合的研究依据；当前实现的事件序列定义、离线主机采集条件和评估单位单独说明。
- 旧 `PermutationImportance_v3_3.ipynb` 使用特征轴 reshape 与更大的多分支 BiLSTM/Attention。本实现改为真正的事件时间轴，不能直接把旧分数与本结果视为同一实验条件下的提升。
- TensorFlow 官方 [masking 文档](https://www.tensorflow.org/guide/keras/understanding_masking_and_padding) 支持向 LSTM 显式传入掩码；代码同时在卷积前后处理 PAD。
- [TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury) 讨论恶意软件分类评估偏差。本实现防止样本/分组跨集合，但随机留出不是跨时间部署评估。

建议论文下一步先冻结人工复核后的数据划分，再对比 CNN-only、LSTM-only、CNN-LSTM，以及运行级统计特征基线。只有消融结果支持，才把时序网络的收益写成结论。本版本优先交付可核验的 CNN-LSTM 主流程。

## 7. 本地验证

见 `TEST_REPORT.md`。独立环境可使用 `requirements-tested.txt`；这是本地验证版本，Colab 可以先使用预装兼容版本，实际版本自动保存。固定种子不保证跨硬件/软件版本逐位一致。

```powershell
python .\smoke_test.py 'D:\SysmonProcessed\avos-blackbasta-benign-v1' '.\smoke-output-new'
```

短程 smoke test 使用测试集检查评估代码，并不产生可用于论文的有效性能结论；正式实验应重新按冻结方案训练，不能依据 smoke test 的测试分数调参。
