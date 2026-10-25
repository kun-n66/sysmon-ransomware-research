"""CNN-only / LSTM-only experiments with a mandatory, existing reference split."""
from collections import Counter
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import tempfile
import time
import zipfile

import numpy as np
import tensorflow as tf
import training_core as core

VERSION = '1.0.0'
ARCHITECTURES = ('cnn_only', 'lstm_only')
load_data = core.load_data
predict = core.predict
evaluate_test = core.evaluate_test
save_json = core.save_json


def digest(content):
    return hashlib.sha256(content).hexdigest()


def load_reference(path):
    """Read protocol files only; never read reference test scores or predictions."""
    path = Path(path)
    names = ('config.json', 'splits.csv', 'dataset_SHA256SUMS.txt')
    if not path.exists():
        raise FileNotFoundError(f'Reference experiment not found: {path}. Supply the original results ZIP or folder; a new split will NOT be created.')
    if path.is_dir():
        content = {n: (path / n).read_bytes() for n in names}
    else:
        with zipfile.ZipFile(path) as archive:
            configs = [i for i in archive.infolist() if PurePosixPath(i.filename).name == 'config.json' and not i.is_dir()]
            if len(configs) != 1:
                raise ValueError('Reference ZIP must contain exactly one experiment config.json')
            parent = PurePosixPath(configs[0].filename).parent
            content = {}
            for name in names:
                member = str(parent / name)
                matches = [i for i in archive.infolist() if i.filename == member]
                if len(matches) != 1 or matches[0].file_size > 16 * 1024**2:
                    raise ValueError(f'Missing, duplicate or oversized reference file: {name}')
                content[name] = archive.read(matches[0])
    config = json.loads(content['config.json'].decode('utf-8-sig'))
    if config.get('version') != '1.0.0':
        raise ValueError('Reference must use the original training v1.0.0 protocol')
    if config.get('architecture') not in (None, 'cnn_lstm'):
        raise ValueError('Use the CNN-LSTM reference experiment, not another baseline run')
    if config.get('labels') != {'benign': 0, 'ransomware': 1} or config.get('label_scope') != 'run_weak_label':
        raise ValueError('Reference label contract differs')
    if config.get('aggregation') != 'mean chunk probability; fixed before evaluation':
        raise ValueError('Reference aggregation differs from this implementation')
    if config.get('selection') != 'minimum run-balanced validation binary crossentropy':
        raise ValueError('Reference checkpoint selection differs')
    if config.get('weights') != 'train: inverse chunks per run times inverse class run count; normalized mean 1':
        raise ValueError('Reference training weights differ')
    for name in ('seed', 'epochs', 'batch_size'):
        if type(config.get(name)) is not int or config[name] < (0 if name == 'seed' else 1):
            raise ValueError(f'Invalid reference {name}')
    if config.get('view') not in ('system', 'related'):
        raise ValueError('Invalid reference view')
    if digest(content['dataset_SHA256SUMS.txt']) != config.get('dataset_checksums_sha256'):
        raise ValueError('Reference data manifest disagrees with its config')
    # Freeze the exact bytes read; repeated reads or edited input cannot silently change a run.
    return dict(path=str(path), config=config, content=content,
                config_sha256=digest(content['config.json']),
                splits_sha256=digest(content['splits.csv']))


def verify_reference_dataset(directory, reference):
    actual = digest((Path(directory) / 'SHA256SUMS.txt').read_bytes())
    if actual != reference['config']['dataset_checksums_sha256']:
        raise ValueError('Dataset fingerprint differs from the reference CNN-LSTM experiment. Use its exact immutable preprocessing output; do not edit checksums.')


def prepare_reference_splits(data, reference):
    verify_reference_dataset(data['directory'], reference)
    config = reference['config']
    if data['view'] != config['view'] or list(data['x'].shape[1:]) != config['input_shape']:
        raise ValueError('View or input shape differs from the reference experiment')
    with tempfile.TemporaryDirectory(prefix='sysmon_fixed_split_') as temporary:
        path = Path(temporary) / 'splits.csv'
        path.write_bytes(reference['content']['splits.csv'])
        assignment = core.read_splits(data['directory'], path)
    indices, summary = {}, {}
    for split in ('train', 'validation', 'test'):
        idx = np.asarray([i for i, c in enumerate(data['contexts']) if assignment[c['run_key']] == split], dtype=np.int64)
        if not len(idx) or set(data['y'][idx]) != {0, 1}:
            raise ValueError(f'{split} must contain both labels in the selected view')
        indices[split] = idx
        keys = {data['contexts'][i]['run_key'] for i in idx}
        summary[split] = dict(sequences=len(idx), runs=len(keys),
                             labels=dict(Counter(data['runs'][k]['label'] for k in keys)),
                             families=dict(Counter(data['runs'][k]['family'] for k in keys)),
                             groups=len({data['runs'][k]['group_id'] for k in keys}))
    return indices, summary


def build_model(length, width, architecture, seed=20261001):
    if architecture not in ARCHITECTURES:
        raise ValueError(f'architecture must be one of {ARCHITECTURES}')
    tf.keras.utils.set_random_seed(seed)
    features = tf.keras.Input((length, width), dtype='float32', name='features')
    valid = tf.keras.Input((length,), dtype='bool', name='valid')
    clean = core.ApplyMask(name='mask_input')([features, valid])
    if architecture == 'cnn_only':
        branches = [tf.keras.layers.Conv1D(32, k, padding='causal', activation='relu',
                                         name=f'conv_{k}')(clean) for k in (3, 5)]
        hidden = tf.keras.layers.Concatenate(name='multiscale')(branches)
        hidden = core.ApplyMask(name='mask_convolution')([hidden, valid])
        # Exclude padded steps from BOTH the numerator and denominator.
        hidden = tf.keras.layers.GlobalAveragePooling1D(name='masked_temporal_mean')(hidden, mask=valid)
    else:
        hidden = tf.keras.layers.LSTM(64, name='event_lstm')(clean, mask=valid)
    hidden = tf.keras.layers.Dropout(.3, name='dropout')(hidden)
    hidden = tf.keras.layers.Dense(32, activation='relu', name='dense')(hidden)
    output = tf.keras.layers.Dense(1, activation='sigmoid', name='ransomware_probability')(hidden)
    model = tf.keras.Model({'features': features, 'valid': valid}, output, name='Sysmon_' + architecture)
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=.001, clipnorm=1.), loss='binary_crossentropy')
    return model


def train(data, indices, output, architecture, reference):
    """Same saved split/settings as reference; fit train, select on validation only."""
    if architecture not in ARCHITECTURES:
        raise ValueError('Unknown architecture')
    expected, summary = prepare_reference_splits(data, reference)
    if set(indices) != set(expected) or any(not np.array_equal(indices[k], expected[k]) for k in expected):
        raise ValueError('Training indices differ from the frozen reference split')
    output = Path(output)
    if output.exists():
        raise FileExistsError('Use a new experiment directory; existing results are never overwritten')
    protocol = reference['config']
    seed, epochs, batch_size = (protocol[k] for k in ('seed', 'epochs', 'batch_size'))
    tf.keras.backend.clear_session()
    tf.keras.utils.set_random_seed(seed)
    tf.config.experimental.enable_op_determinism()
    model = build_model(*data['x'].shape[1:], architecture, seed)
    packages = {p: importlib.metadata.version(p) for p in ('tensorflow', 'keras', 'numpy', 'scikit-learn')}
    config = dict(version=VERSION, architecture=architecture,
                  protocol_source='CNN-LSTM training v1.0.0', python=platform.python_version(), packages=packages,
                  seed=seed, epochs=epochs, batch_size=batch_size, view=data['view'],
                  input_shape=list(data['x'].shape[1:]), parameters=model.count_params(),
                  software_groups_reviewed=protocol['software_groups_reviewed'],
                  interpretation=protocol['interpretation'], dataset_checksums_sha256=protocol['dataset_checksums_sha256'],
                  labels=protocol['labels'], label_scope=protocol['label_scope'],
                  aggregation=protocol['aggregation'], weights=protocol['weights'], selection=protocol['selection'],
                  validation_weights='inverse chunks per run; normalized mean 1; no class balancing',
                  optimizer={'name': 'Adam', 'learning_rate': .001, 'clipnorm': 1.},
                  early_stopping={'monitor': 'val_loss', 'patience': 7},
                  reference_experiment=reference['path'], reference_config_sha256=reference['config_sha256'],
                  splits_sha256=reference['splits_sha256'],
                  training_source_sha256=digest(Path(__file__).read_bytes()),
                  core_source_sha256=digest(Path(core.__file__).read_bytes()),
                  devices=[str(d) for d in tf.config.list_physical_devices()],
                  device_details=[{'device': str(d), 'details': tf.config.experimental.get_device_details(d)}
                                  for d in tf.config.list_physical_devices('GPU')],
                  reference_packages=protocol.get('packages', {}),
                  package_version_differences={p: {'reference': protocol.get('packages', {}).get(p), 'current': v}
                      for p, v in packages.items() if protocol.get('packages', {}).get(p) != v})
    output.mkdir(parents=True)
    save_json(output / 'config.json', config)
    (output / 'splits.csv').write_bytes(reference['content']['splits.csv'])
    (output / 'reference_config.json').write_bytes(reference['content']['config.json'])
    save_json(output / 'split_summary.json', summary)
    save_json(output / 'feature_columns.json', data['columns'])
    for name in ('SHA256SUMS.txt', 'feature_schema.json', 'numeric_schema.json', 'build.json'):
        shutil.copy2(data['directory'] / name, output / ('dataset_' + name))
    # Keep executable provenance with the result, as well as the model configuration.
    code_dir = output / 'source'
    code_dir.mkdir()
    shutil.copy2(__file__, code_dir / 'baselines.py')
    shutil.copy2(core.__file__, code_dir / 'training_core.py')
    for file in (Path(__file__).parent / 'preprocess_v201').glob('*.py'):
        destination = code_dir / 'preprocess_v201' / file.name
        destination.parent.mkdir(exist_ok=True)
        shutil.copy2(file, destination)
    model.summary()
    with (output / 'model_summary.txt').open('w', encoding='utf-8') as stream:
        model.summary(print_fn=lambda line: stream.write(line + '\n'))
    (output / 'model_architecture.json').write_text(model.to_json(), encoding='utf-8')
    train_idx, val_idx = indices['train'], indices['validation']
    callbacks = [tf.keras.callbacks.ModelCheckpoint(str(output / 'best.keras'), monitor='val_loss', save_best_only=True),
                 tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=7, restore_best_weights=True),
                 tf.keras.callbacks.CSVLogger(str(output / 'history.csv'))]
    start = time.perf_counter()
    history = model.fit(core.batches(data, train_idx, core.training_weights(data, train_idx), batch_size, True, seed),
                        validation_data=core.batches(data, val_idx, core.validation_weights(data, val_idx), batch_size),
                        epochs=epochs, callbacks=callbacks, verbose=2, shuffle=False)
    elapsed = time.perf_counter() - start
    restored = tf.keras.models.load_model(output / 'best.keras')
    sample_idx = val_idx[:8]
    np.testing.assert_allclose(predict(model, data, sample_idx), predict(restored, data, sample_idx), atol=1e-6, rtol=1e-6)
    rows = core.aggregate_runs(data, val_idx, predict(restored, data, val_idx))
    decision = core.select_threshold(rows)
    save_json(output / 'threshold.json', decision)
    core.write_csv(output / 'validation_run_predictions.csv', rows)
    save_json(output / 'history.json', history.history)
    save_json(output / 'training_summary.json', dict(epochs_completed=len(history.history['loss']),
              best_epoch=int(np.argmin(history.history['val_loss']))+1,
              best_validation_loss=float(min(history.history['val_loss'])),
              fit_seconds=elapsed, checkpoint_reload_verified=True))
    return restored, decision


def plot_results(output):
    """A single experiment's diagnostics, not a cross-model comparison."""
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay
    output = Path(output)
    config = json.loads((output / 'config.json').read_text(encoding='utf-8'))
    history = json.loads((output / 'history.json').read_text(encoding='utf-8'))
    with (output / 'test_run_predictions.csv').open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.DictReader(stream))
    y, p, pred = ([int(r['y']) for r in rows], [float(r['probability']) for r in rows], [int(r['prediction']) for r in rows])
    fig, axes = plt.subplots(2, 2, figsize=(10, 8), layout='constrained')
    axes[0, 0].plot(range(1, len(history['loss'])+1), history['loss'], label='Train (class/run weighted)')
    axes[0, 0].plot(range(1, len(history['val_loss'])+1), history['val_loss'], label='Validation (run weighted)')
    axes[0, 0].set(xlabel='Epoch', ylabel='Binary crossentropy'); axes[0, 0].legend()
    ConfusionMatrixDisplay.from_predictions(y, pred, labels=[0, 1], display_labels=['Benign', 'Ransomware'], ax=axes[0, 1], colorbar=False)
    PrecisionRecallDisplay.from_predictions(y, p, ax=axes[1, 0])
    RocCurveDisplay.from_predictions(y, p, ax=axes[1, 1])
    fig.suptitle(f"{config['architecture']}: run-level holdout evaluation (n={len(rows)})")
    fig.savefig(output / 'evaluation.png', dpi=180)
    return fig


def unpack_dataset(path, target=None):
    """Extract a preprocessing ZIP to a new local directory, with size/path checks."""
    target = Path(target) if target is not None else Path(tempfile.mkdtemp(prefix='sysmon_data_'))
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise ValueError('Dataset staging directory must be empty')
    with zipfile.ZipFile(path) as archive:
        if sum(i.file_size for i in archive.infolist()) > 8 * 1024**3:
            raise ValueError('Dataset ZIP exceeds the 8 GiB uncompressed limit')
        seen = set()
        for info in archive.infolist():
            dest = (target / info.filename).resolve()
            if not dest.is_relative_to(target.resolve()) or '\\' in info.filename or dest in seen:
                raise ValueError('Unsafe or duplicate ZIP path')
            seen.add(dest)
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, dest.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
    candidates = list(target.rglob('build.json'))
    if len(candidates) != 1:
        raise ValueError('ZIP must contain exactly one complete preprocessing dataset')
    return candidates[0].parent
