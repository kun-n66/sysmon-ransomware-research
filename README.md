# Sysmon Ransomware Research

**English** | [简体中文](README.zh-CN.md)

A research toolkit for collecting Sysmon events from an offline Windows virtual machine, building auditable behavioral datasets, and training CNN–LSTM, CNN-only, and LSTM-only classifiers.

The collection workflow streams events to the physical host through a VMware virtual serial port and a local named pipe. It supports controlled benign-software sessions and snapshot-based ransomware experiments, with a default observation window of 300 seconds.

## Features

- **Event collection:** a C# guest collector, a Python host receiver, and PowerShell controllers for benign and ransomware sessions.
- **Research configuration:** a pinned Sysmon configuration derived from SwiftOnSecurity, with documented changes and attribution.
- **Dataset preparation:** integrity checks, run-quality auditing, behavioral features, ordered sequences, and grouped data splitting.
- **Classification:** CNN–LSTM training and separate CNN-only / LSTM-only baselines, with self-contained Colab notebooks.
- **Verification:** synthetic-event tests, Windows named-pipe integration tests, a mock VMware controller, and validation reports.

This repository publishes source code, configurations, tests, and documentation. **Raw logs, prepared datasets, trained weights, and malware samples are not included.** The baseline component retains the original experiment's reference configuration and split; reproducing its numerical results requires the matching dataset.

## Workflow

```text
Windows guest
  Sysmon Operational channel → C# collector → COM1
    → VMware virtual serial port / local named pipe

Windows host
  Python receiver → events.xml + metadata.json + SHA-256
    → preprocessing and quality review
    → behavioral features and ordered event sequences
    → grouped train / validation / test split
    → CNN–LSTM, CNN-only, or LSTM-only
```

The transport does not require guest network connectivity, shared folders, or a mapped host log directory. The guest collector handles telemetry; the host controller uses `vmrun` for VM lifecycle and sample-launch operations.

## Repository layout

```text
.
├── host/                  # Receiver, storage, named-pipe client, and controllers
├── guest/                 # C# collector, build/install scripts, benign workloads
├── sysmon/                # Research configuration, patches, pinned upstream files
├── preprocess/            # Features, dataset construction, quality checks, tests
├── training/              # CNN–LSTM implementation and Colab notebook
├── training_baselines/    # CNN-only / LSTM-only code and reference split
├── tests/                 # Synthetic events and native/controller tests
├── tools/                 # Telemetry and log-volume checks
├── examples/              # Sample-list format example
├── docs/                  # Configuration notes and validation history
├── README.zh-CN.md        # Chinese overview and detailed operating manual
├── THIRD_PARTY_NOTICES.md
└── VERSIONS.json
```

## Requirements

| Component | Environment |
|---|---|
| Collection host | Windows; the original setup uses Windows 11, VMware Workstation with `vmrun`, PowerShell, and Python 3.9+ |
| Collection guest | Windows; the original setup uses Windows 10, .NET Framework 4.8, Sysmon, and VMware Tools |
| Collector build | Windows .NET Framework C# compiler, invoked by `guest/build.ps1` |
| Training | Compatible TensorFlow/Keras, NumPy, scikit-learn, and Matplotlib packages; Colab notebooks are provided |

The host collection code uses the Python standard library. Training has separate dependencies; see the [recorded training requirements](training/requirements-tested.txt) and model guides. That requirements file describes a historical CPU smoke-test environment. In Colab, follow the notebook's guidance before changing installed packages.

## Getting started

All commands below use PowerShell. Paths such as `D:\SysmonRealtime` and `C:\SysmonRealtime` are examples; adapt them to your environment. The [Chinese operating manual](README.zh-CN.md) contains detailed installation, collection, recovery, and troubleshooting instructions. Component guides currently retain their original Chinese text.

### 1. Prepare the guest and transport

1. Place the project on the host, for example at `D:\SysmonRealtime`.
2. With the VM powered off, add a VMware serial port using `\\.\pipe\sysmon-log`. Select **This end is the server**, **The other end is an application**, and **Connect at power on**.
3. Copy `guest/`, `sysmon/`, and `tools/` to `C:\SysmonRealtime` in the guest. Confirm its port is COM1, or pass the actual port when installing the collector.
4. Load the research configuration and build/install the collector.

For an existing Sysmon installation, run in an elevated guest PowerShell session:

```powershell
& 'C:\Sysmon\Sysmon64.exe' -c 'C:\SysmonRealtime\sysmon\sysmonconfig-export.xml'
Set-Location C:\SysmonRealtime\guest
.\build.ps1
.\install.ps1 -Port COM1
```

The source distribution does not include a precompiled collector. Build it before installation and keep the generated EXE together with its `.exe.config` file. The installer creates a startup scheduled task named `SysmonSerialCollector`.

The configuration uses Sysmon schema 4.90. Check compatibility with your installed Sysmon version rather than changing the schema number to bypass a load error. See the [configuration guide](sysmon/README.md) and [Swift configuration update](docs/UPDATE-SWIFT-V2.md).

### 2. Verify collection with synthetic activity

On the host:

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
$testHash = '0' * 64
& $python .\host\receiver.py receive --sample $testHash --family SmokeTest --output D:\SysmonTestLogs --start-mode immediate --duration 60
```

After the receiver reaches `recording`, run in the guest:

```powershell
Set-Location C:\SysmonRealtime
.\tools\Test-ResearchTelemetry.ps1
```

Confirm that the generated activity marker appears in the host's saved `events.xml`. A guest-side check alone does not verify transmission. The zero hash identifies this transport check; exclude this run from training.

### 3. Collect research sessions

| Session | Entry point | Behavior |
|---|---|---|
| Benign software | `host/run_benign_realtime.ps1` | Prompts for the software name and executable SHA-256; uses `immediate` mode while you perform the activity in the guest |
| Ransomware | `host/run_mal_realtime.ps1` | Restores a clean snapshot, waits for the collector, launches a guest sample through `vmrun`, collects events, and restores the snapshot |

For benign collection on the host:

```powershell
.\host\run_benign_realtime.ps1 -PythonExe $python -OutputRoot 'D:\SysmonBenignLogs\batch01'
```

The default observation duration is 300 seconds. In ransomware `process` mode, the window starts after a matching process-creation event is observed. Boot, readiness checks, baseline recording, and draining add time outside that window.

Before using the ransomware controller, configure the VM path, clean snapshot, guest credentials, family name, and sample list. Samples must already exist inside the snapshot at `GuestSampleRoot\MalwareFamily\SHA256.exe`. See the [complete controller example](README.zh-CN.md#92-物理机执行), [benign collection guide](host/README.md), and [sample-list example](examples/malware_list.example.json).

Use a new batch directory after changing configurations, snapshots, or workloads. The current skip logic does not compare the configuration hash or snapshot name.

### 4. Build and review a dataset

Copy the manifest example and edit its directories and labels before preprocessing:

```powershell
Copy-Item .\preprocess\inputs.all.example.json .\preprocess\inputs.all.json
# Edit inputs.all.json before running the following commands.
& $python .\preprocess\preprocess.py --input-manifest .\preprocess\inputs.all.json --output 'D:\SysmonPrepared\batch01' --sequence-length 64
& $python .\preprocess\dataset.py 'D:\SysmonPrepared\batch01'
```

Preprocessing reads the original logs and writes a separate dataset directory. Outputs include run manifests, structured events, features, sequences, schemas, quality reports, and checksums. The `system` and `related` views overlap and should be evaluated separately.

Review quality, labels, and software groups before freezing a split. Keep all chunks from a run in one partition. For benign software, grouping only by executable hash can allow related versions, installers, and uninstallers to cross partitions; review product/workflow groups explicitly.

See the [preprocessing guide](preprocess/README.md) for time semantics, annotations, sequence construction, and `make_splits.py`. Sequence length is configurable: the reference baseline experiment uses 32 events per chunk, while the example above uses 64.

### 5. Train a model

| Model | Notebook | Guide |
|---|---|---|
| CNN–LSTM | [Sysmon_CNN_LSTM_Colab.ipynb](training/Sysmon_CNN_LSTM_Colab.ipynb) | [Main model](training/README.md) |
| CNN-only / LSTM-only | [Sysmon_CNN_LSTM_Baselines_Colab.ipynb](training_baselines/Sysmon_CNN_LSTM_Baselines_Colab.ipynb) | [Baselines](training_baselines/README.md) |

The notebooks embed the required project modules. Upload a notebook to Colab, provide the complete prepared dataset in Google Drive, set the paths, and run the cells in order. Train one baseline at a time with `MODEL_TYPE = 'cnn_only'` or `MODEL_TYPE = 'lstm_only'`.

The baseline notebook embeds the original CNN–LSTM experiment's reference split and verifies the dataset against it. For a new study, define and freeze a suitable split before comparing architectures; the embedded reference requires the original matching data.

Training uses run/class weighting. Run-level predictions aggregate chunk probabilities by their arithmetic mean. Threshold selection uses validation-set run predictions and the F2 criterion; the test set is evaluated separately. The model guides describe the weighting, tie-breaking, and checkpoint rules.

## Data quality and interpretation

- A `complete` status means the observed transport passed its checks. It does not prove that every source event was captured or encryption occurred.
- Labels apply to runs. Chunks from a ransomware run can contain benign background events.
- A chunk contains a configured event count, not a fixed duration. Chunk classification does not establish online detection latency.
- Hash/group holdout results do not establish generalization to unseen software products or ransomware families. The reference experiment records `software_groups_reviewed = false`.
- Repository checksums identify artifacts; they do not establish which configuration was loaded during a historical run. Record the actual configuration, Sysmon version, snapshot, and workload for each batch.

Preserve original logs and create new dataset versions when changing features or time policies. Choose transformations, thresholds, and model settings using training/validation data rather than repeatedly adapting them to test results.

## Testing and validation

On Windows, from the repository root:

```powershell
.\tests\run-tests.ps1 -PythonExe $python
& $python -m unittest discover -s .\preprocess\tests -p 'test_*.py' -v
& $python .\sysmon\build_config.py --validate
```

These checks use synthetic events, local named pipes, and a mock `vmrun`. They do not run malware or operate a real VM. The native suite builds a C# harness with the Windows .NET Framework compiler.

For the initial source publication on 2026-10-25, 43 preprocessing tests passed and the final full native/controller run passed 44 tests. The first native run failed before collector readiness; a full rerun passed without source changes, and its cause remains unresolved. See [publication validation](docs/PUBLICATION_VALIDATION.md) for the scope and limitations. Historical reports describe their own environments, not a new end-to-end deployment check.

## Versions and provenance

The integrated collection package is `2026.09.29-benign-name`: collector 1.0, receiver 1.2.0, preprocessing 2.0.1, and configuration `thesis-swift-offline-v2.0.0`. See [VERSIONS.json](VERSIONS.json), the [configuration notes](sysmon/README.md), and [SHA256SUMS.txt](SHA256SUMS.txt).

## License

Original project code and documentation use the [MIT license](LICENSE). Retained upstream configurations and derived rules keep their applicable licenses, including CC BY 4.0 for the SwiftOnSecurity configuration and its derivative. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the notices under `sysmon/upstream/`.

Sysmon, VMware, and training dependencies are obtained separately under their own licenses. No endorsement by Microsoft, VMware, or upstream configuration authors is implied.
