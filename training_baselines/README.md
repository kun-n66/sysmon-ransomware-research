# Sysmon CNN-only / LSTM-only：Colab 固定划分训练

本组件为已有 CNN–LSTM 实验增加两个独立架构对照。每次只训练一个模型，各自输出模型、指标和预测文件；**不生成跨模型比较、排名或自动择优功能**。

## 1. 直接使用

1. 将 `Sysmon_CNN_LSTM_Baselines_Colab.ipynb` 上传到 Colab，选择 GPU 运行时。
2. 将**原 CNN–LSTM 主实验使用的完整前处理文件夹**放到 Google Drive，例如：

   ```text
   MyDrive/SysmonResearch/all-families-benign-seq32-v1/
   ```

   本地对应的已核实目录是 `D:\SysmonPrepared\all-families-benign-seq32-v1`。不要把 `D:\...` 路径填入 Colab，也不要重新生成一份不同的数据代替它。
3. 在配置单元设置以下内容，然后顺序运行：

   ```python
   PROJECT = Path('/content/drive/MyDrive/SysmonResearch')
   DATA_DIR = PROJECT / 'all-families-benign-seq32-v1'
   DATA_ZIP = None
   MODEL_TYPE = 'cnn_only'
   REFERENCE_EXPERIMENT = None
   ```

4. 训练单元只使用训练与验证集。之后执行独立测试单元，保存该模型的最终测试结果。
5. 最后一个单元核验模型重载并下载结果 ZIP。Drive 中也有完整结果。
6. 将 `MODEL_TYPE` 改为 `'lstm_only'`，从**配置单元开始向后重新运行**，产生另一个独立结果目录。也可复制一份 Notebook 分别运行。无需重新制作数据或划分。

若上传的是完整前处理 ZIP，可以设置：

```python
DATA_ZIP = PROJECT / 'all-families-benign-seq32-v1.zip'
```

程序会将它解压到 Colab 临时磁盘，再执行相同校验。ZIP 可以包含数据文件本身，或一个包裹这些文件的目录。辅助源码及参考划分已内嵌于 Notebook，**仅上传 Notebook 即可获得代码和参考划分**。仍需自行提供前处理数据，无需原始 XML 或样本 EXE。

## 2. 如何保证使用原来的数据划分

Notebook 内嵌了已核实主实验 `cnn_lstm_20261009T153018Z_561fd196` 的三个原始文件：

```text
reference_cnn_lstm_main/
  config.json
  splits.csv
  dataset_SHA256SUMS.txt
```

默认 `REFERENCE_EXPERIMENT=None` 使用这份参考，不需要再寻找 `splits_family_seed20261001.csv`。这里的 `splits.csv` 是原实验最终保存的划分，内容不重新生成。参考文件只用于读取实验设置和分组，程序不读取参考实验的测试分数或预测。

对应的已核实规模为：

| 项目 | 训练 | 验证 | 测试 |
|---|---:|---:|---:|
| 采集运行数 | 355 | 73 | 84 |
| 正常运行数 | 39 | 7 | 18 |
| 恶意运行数 | 316 | 66 | 66 |
| system 片段数 | 21,240 | 4,364 | 5,726 |

输入为 `[32,148]`，共 512 次候选运行。参考数据校验清单的 SHA256 为：

```text
5466ce4e9fed55ea2fe17dd1c7b2341be4fa9b8f5bb540ffb09a8dab49e0455e
```

代码同时检查：

- 前处理版本为 2.0.1，数据文件校验和有效。
- 数据校验清单指纹与参考实验相同，视图和输入形状相同。
- 原始划分准确覆盖全部候选运行，run_key/group_id 相符。
- 同一 group_id 和 SHA256 不跨训练、验证和测试集。
- 时间序列、候选状态及右侧补齐符合原读取器约束。

**缺失或不匹配时会报错，不会悄悄创建新划分。** 数据文件夹可以移动或改目录名，但里面的构建产物应保持原样。

如果要使用另一份原始 CNN–LSTM v1.0.0 实验，可设置其结果目录或 ZIP，例如：

```python
REFERENCE_EXPERIMENT = PROJECT / 'experiments' / 'cnn_lstm_20261009T153018Z_561fd196'
# 或
REFERENCE_EXPERIMENT = PROJECT / 'cnn_lstm_20261009T153018Z_561fd196.zip'
```

该目录/ZIP 必须包含前述三个参考文件，且 `DATA_DIR` 指向对应的完整前处理构建。更改前处理或软件分组后，应为所有模型重新建立共同实验，不能直接沿用旧模型分数进行严格同条件比较。

## 3. 两个模型的定义

### CNN-only

```text
事件向量 + valid mask
  → 清零 PAD
  → 并行 causal Conv1D(32,kernel=3) / Conv1D(32,kernel=5)
  → 通道拼接为 64 维 → 再次清零 PAD
  → GlobalAveragePooling1D，显式传入 mask
  → Dropout(0.3) → Dense(32,ReLU) → Dense(1,sigmoid)
```

保留原混合模型的卷积分支，去掉 LSTM，以对有效时间步的平均池化形成片段表示。PAD 不进入平均值的分子或分母。卷积仍可捕获局部顺序模式，不能将 CNN-only 称为“完全不使用时序信息”的模型。

### LSTM-only

```text
事件向量 + valid mask
  → 清零 PAD
  → LSTM(64)，显式传入 mask
  → Dropout(0.3) → Dense(32,ReLU) → Dense(1,sigmoid)
```

去掉卷积，将原始 148 维事件向量直接输入 LSTM。LSTM 的状态只在片段内部传递，不跨片段延续。

在 148 维输入下，CNN-only 为 **40,065** 个参数，LSTM-only 为 **56,641** 个参数，原 CNN–LSTM 为 73,089 个参数。这是按模块移除构建的架构对照；CNN-only 需要额外的池化读出层，且三者容量不同，因此不是严格等参数量实验。参数量自动保存，不需要手动填写。

掩码行为依据 Keras 官方接口：[GlobalAveragePooling1D](https://keras.io/api/layers/pooling_layers/global_average_pooling1d/)、[LSTM](https://keras.io/api/layers/recurrent_layers/lstm/)。

## 4. 与原 CNN–LSTM 保持一致的部分

| 项目 | 处理方式 |
|---|---|
| 数据、视图、输入长度与维度 | 核验并继承参考实验 |
| 训练/验证/测试划分 | 原始 splits.csv 字节直接复用 |
| 随机种子、最大 epoch、batch size | 从参考 config.json 读取，当前为 20261001 / 40 / 32 |
| 编码与 OOV | 原 v2.0.1 读取器，不额外拟合词表或归一化 |
| 训练权重 | 运行内片段数的倒数 × 类别运行数的倒数，归一化均值为 1 |
| 验证权重 | 只做运行平衡，归一化均值为 1 |
| 优化器与损失 | Adam，learning_rate=0.001，clipnorm=1；二元交叉熵 |
| checkpoint / 早停 | 最小 val_loss；patience=7 |
| 运行级聚合 | 片段概率算术平均，短末段也占一份 |
| 阈值选择 | 各自验证集运行级 F2 最大；并列时较低 FPR，再取较高阈值 |
| 测试输出 | 同一运行级与片段级指标定义 |

**相同的是阈值选择规则，不是阈值数值。** 新模型的输出分布不同，因此不强制使用原 CNN–LSTM 的 0.716264 阈值。也不要求三个模型最终早停在同一 epoch；它们使用相同的最大预算和模型选择规则。

Colab 运行环境随时间变化，代码记录实际依赖版本、GPU 信息及与参考环境的差异。没有自动升级 TensorFlow，以免破坏预装 GPU 兼容性。跨硬件/依赖版本不保证逐位复现。使用同一 Colab 环境完成两个新实验更便于说明条件。

## 5. 每个模型单独保存什么

```text
experiments/cnn_only_时间戳_随机后缀/   # 或 lstm_only_...
  best.keras
  config.json
  model_architecture.json
  model_summary.txt
  training_summary.json
  reference_config.json
  splits.csv
  split_summary.json
  feature_columns.json
  dataset_SHA256SUMS.txt
  dataset_feature_schema.json
  dataset_numeric_schema.json
  dataset_build.json
  history.csv
  history.json
  threshold.json
  validation_run_predictions.csv
  test_run_predictions.csv
  test_sequence_predictions.csv
  test_metrics.json
  evaluation.png
  source/                         本次使用的 Python 源码
```

`config.json` 包含架构、输入形状、参数数、数据指纹、划分 SHA256、原实验配置指纹和训练设置。`training_summary.json` 保存实际 epoch、最佳 epoch、最佳验证损失、fit 耗时及模型重载核验结果。耗时受硬件与运行负载影响，不应直接视为严格效率基准。

手动整理时，主要读取各结果包的 `test_metrics.json → primary_run_level`。保留 `secondary_chunk_level` 作为辅助，并同时报告混淆矩阵、FPR/FNR、样本数和参数量。`evaluation.png` 仅展示当前模型的学习曲线、混淆矩阵及 ROC/PR 曲线，不汇总其他模型。

## 6. 研究解释

此组件复用原主实验划分，因此也继承其正常类数量、产品级分组未复核及运行级弱标签等边界。完成对照不能自动消除这些限制。测试数据已经用于之前的结果分析，应将这次工作报告为固定留出集上的补充架构实验，不将其称为新独立测试集。

不做过采样、不增加合成事件、不变更标签、不按测试成绩重新选划分。若比较后需要调整架构，应通过训练/验证流程完成选择，并为新的泛化结论保留独立评估数据。

## 7. 验证与源码

`baselines.py` 提供两个架构、严格参考划分读取与训练入口；`training_core.py` 是原 v1.0.0 的完整源代码快照，数据加载、权重、聚合、阈值与指标函数直接复用，原 CNN–LSTM 项目不被修改。`preprocess_v201/` 保留原读取器。

Notebook 内嵌代码与这些文件一致。验证范围和实际环境见 `TEST_REPORT.md`。本地短程验证用于发现工程问题，不能将其指标写入论文；正式实验请在 Colab 按完整预算运行。
