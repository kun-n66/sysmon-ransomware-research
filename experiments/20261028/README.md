# Expanded benign-data experiment — 2026-10-28

This snapshot records the expanded dataset and the three saved model experiments, checked on **2026-11-01**. The collection, preprocessing, feature, and training implementations have not changed. The update adds dataset provenance, a new fixed split, recorded predictions and metrics, and dated notebook variants.

## Dataset changes

| Item | Previous batch | Expanded batch |
|---|---:|---:|
| Collected runs | 603 | 658 |
| Training-candidate runs | 512 | 563 |
| Benign candidates | 64 | 115 |
| Ransomware candidates | 448 | 448 |
| Parsed events | 1,274,473 | 1,440,830 |
| Model-window events | 1,231,297 | 1,397,422 |
| System-view chunks | 31,330 | 35,877 |
| Related-view chunks | 19,433 | 23,193 |

All 55 additional collected runs are benign; 51 qualify as training candidates. The expanded batch retains every previously present run. Of 658 collected runs, 95 are excluded from training. Exclusion reasons can overlap; see [summary.json](dataset_metadata/summary.json).

The dataset uses preprocessing v2.0.1, `system` time semantics, 32 events per chunk, and 148 numeric input columns derived from 28 behavioral fields. System and related views overlap and are not independent datasets. The 563 candidate runs correspond to 520 distinct candidate sample identifiers, not 563 independent software products.

## Fixed split

| Partition | Benign runs | Ransomware runs | Total runs | System chunks |
|---|---:|---:|---:|---:|
| Train | 87 | 316 | 403 | 25,757 |
| Validation | 14 | 66 | 80 | 5,319 |
| Test | 14 | 66 | 80 | 4,801 |

The exact assignments are in [reference_cnn_lstm/splits.csv](reference_cnn_lstm/splits.csv). No `group_id` or sample SHA-256 crosses partitions, and all three model experiments use identical split bytes and dataset checksums.

**This is a new split, not an extension of the old held-out test set.** Among previously present candidate runs, 222 changed partitions, and only 16 old test runs remain in the new test set. A score difference between batches cannot be attributed solely to adding benign data. The dataset and earlier test results had already been inspected; this update is not a new independent prospective validation.

Software-product/workflow grouping has not been declared reviewed: the saved configurations retain `software_groups_reviewed = false`. Hash-based isolation alone does not establish generalization to unseen benign products or unseen ransomware families.

## Recorded model results

Primary metrics use one prediction per test run. Each run probability is the arithmetic mean of its chunk probabilities. Thresholds were selected using validation runs only, maximizing F2, with ties resolved by lower FPR and then higher threshold.

| Model | Parameters | Threshold | TN / FP / FN / TP | Accuracy | Recall | F2 |
|---|---:|---:|---|---:|---:|---:|
| CNN–LSTM | 73,089 | 0.696418 | 14 / 0 / 0 / 66 | 1.0000 | 1.0000 | 1.0000 |
| CNN-only | 40,065 | 0.727777 | 14 / 0 / 1 / 65 | 0.9875 | 0.9848 | 0.9878 |
| LSTM-only | 56,641 | 0.713916 | 14 / 0 / 0 / 66 | 1.0000 | 1.0000 | 1.0000 |

The exact saved threshold values are in each model's `threshold.json`; the table rounds them for readability. Each model directory includes its config, split summary, training history, test metrics, run/chunk predictions, and validation-run predictions. Model weights are not included.

The test set contains only 14 benign runs. Zero observed false positives does not establish a zero population false-positive rate. The identical final run labels for CNN–LSTM and LSTM-only do not establish equivalent scores or architectures. The architectures also have different parameter counts. Treat these results as a single-seed pilot comparison under this dataset and split.

## Files and availability

- `dataset_metadata/`: dataset summary, feature/numeric schemas, portable input-manifest example, and a public build-metadata copy.
- `reference_cnn_lstm/`: the original main-experiment config, exact split, and source-dataset checksum manifest needed by baseline verification.
- `models/`: selected recorded artifacts for CNN–LSTM, CNN-only, and LSTM-only.
- [verification.json](verification.json): machine-readable checks and recomputed confusion-derived metrics.
- [provenance.json](provenance.json): source experiment identifiers, publication edits, and audit scope.

**Raw logs, prepared JSONL data, trained weights, and manuscript drafts remain outside this repository.** The checksum manifests identify the original unpublished dataset; they are not checksums for `build.public.json`, whose local paths were replaced with placeholders. Baseline result configs also replace their original Drive reference path with a relative path. Numerical prediction files are copied unchanged.

## Dated notebooks

- [CNN–LSTM, expanded dataset](../../training/Sysmon_CNN_LSTM_Colab_20261028.ipynb)
- [CNN-only / LSTM-only, expanded reference](../../training_baselines/Sysmon_CNN_LSTM_Baselines_Colab_20261028.ipynb)

Upload the matching complete prepared dataset to Google Drive under `MyDrive/SysmonResearch/all-families-benign-seq32-20261028-094152/`, or adapt the notebook's data path. A local folder name such as `all-families-benign-seq32-v2` is an alias, not evidence of dataset identity; verify the checksums.

For the dated CNN–LSTM notebook, first copy `reference_cnn_lstm/splits.csv` to `MyDrive/SysmonResearch/splits_20261028.csv`. The underlying training helper can create a split if its configured file is absent; that would not be proof of reproducing this snapshot. Use the published file and verify its hash before running. The dated baseline notebook embeds all three reference files and rejects a mismatched dataset. It trains one architecture per execution, without automatically comparing or selecting models.

The original notebooks and their October 9 reference remain unchanged for historical reproducibility. Do not use the old baseline notebook's embedded reference with the expanded dataset.

## Verification performed

The checks on 2026-11-01 verified:

1. All 11 files listed by the prepared dataset's checksum manifest.
2. Current source-directory coverage for 658 runs and the recorded source metadata/XML hashes where present.
3. Candidate counts, event counts, sequence structure, run/group/label consistency, and split isolation.
   The unchanged dataset loader also validated all 35,877 system-view and 23,193 related-view sequences.
4. Identical dataset manifests, schemas, and split bytes across the three experiments.
5. Test and validation prediction coverage, chunk-to-run aggregation, recorded labels, confusion matrices, accuracy, balanced accuracy, precision, recall, F1, F2, FPR, and FNR.
6. Each validation-only threshold selection using the saved objective and tie-breaking rules.

These are artifact and dataset checks. They do not retrain or reload the saved models, establish that encryption occurred, or validate software-product grouping. ROC-AUC and average precision remain the saved experiment values; they were not independently recomputed in this update.

## Identifiers

```text
Dataset: all-families-benign-seq32-20261028-094152
Dataset checksum-manifest SHA-256:
82e04daedb6c7ca650ad26a9169d739e19090fdaa25801508a23605331e25d83

Split SHA-256:
7516b569aae2c455ad5e7d464440c41809ee4cfcb0628f4bbe66f0b15fa6ca45
```
