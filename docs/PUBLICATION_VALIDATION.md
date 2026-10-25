# Source publication validation — 2026-10-25

This source distribution was prepared from the archived integrated research project. Collection, preprocessing, feature extraction and model implementation code were not changed for publication.

Publication edits: cleared Notebook outputs and execution counts, replaced one personal username path in documentation with a placeholder, omitted the precompiled collector and local experiment input configurations, added source-publication instructions and third-party license clarification, regenerated checksums.

## Checks performed

- Preprocessing: `python -m unittest discover -s preprocess/tests -v` — 43 tests passed.
- Windows native/controller suite: `./tests/run-tests.ps1 -PythonExe python` — final full run: 44 tests passed, PowerShell script parsing passed, C# harness compilation and native argument/timeout checks passed.
- The first full native/controller run had one failure in `test_controller_finds_commit_when_recording_and_final_status_locked`: the receiver exited before collector READY. A second full run passed without source changes. The underlying cause has not been established; the rerun does not demonstrate that this intermittent failure is fixed.
- Pattern-based credential and personal-path scan of the publication source files returned no findings. This is a bounded automated check, not a guarantee that all sensitive content has been detected.

Tests use synthetic events and a mock vmrun executable. No live malware, VMware snapshot, live Sysmon installation, model training or GPU evaluation was executed for publication. Historical test reports elsewhere in this repository describe earlier environments and runs.

## Availability

This release contains source code and documentation. Raw logs, prepared datasets and trained weights are not distributed with it. The original study's reference split and configuration are retained under `training_baselines/reference_cnn_lstm_main`; full numerical reproduction requires the corresponding dataset, which is not currently included.
