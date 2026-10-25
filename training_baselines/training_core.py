"""CNN-LSTM for immutable Preprocess 2.0.1 outputs; run-level weak labels."""
from collections import Counter, defaultdict
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import random
import shutil
import sys

import numpy as np
import tensorflow as tf
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                             confusion_matrix, fbeta_score, precision_score, recall_score,
                             roc_auc_score)

sys.path.insert(0, str(Path(__file__).parent / 'preprocess_v201'))
from dataset import iter_numeric_examples, read_rows, read_splits, verify_checksums
from behavior_features import numeric_columns

VERSION = '1.0.0'


def save_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')


def write_csv(path, rows):
    if not rows:
        raise ValueError('No rows to export')
    with Path(path).open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def load_data(directory, view='system'):
    directory = Path(directory)
    verify_checksums(directory)
    build = json.loads((directory / 'build.json').read_text(encoding='utf-8'))
    if build.get('version') != '2.0.1':
        raise ValueError('This training contract requires Preprocess 2.0.1; review compatibility before using another version')
    schema = json.loads((directory / 'feature_schema.json').read_text(encoding='utf-8'))
    columns = numeric_columns(schema['features'])
    xs, masks, labels, contexts = [], [], [], []
    for e in iter_numeric_examples(directory, view=view):
        xs.append(np.asarray(e['x'], dtype=np.float32))
        masks.append(np.asarray(e['mask'], dtype=bool))
        labels.append(e['y'])
        contexts.append(e['context'])
    if not xs:
        raise ValueError('No candidate sequences in selected view')
    x, mask, y = np.stack(xs), np.stack(masks), np.asarray(labels, dtype=np.int32)
    if x.shape[2] != len(columns) or not np.isfinite(x).all():
        raise ValueError('Feature width mismatch or non-finite values')
    if not mask.any(axis=1).all() or np.any(mask[:, 1:] & ~mask[:, :-1]):
        raise ValueError('Masks must be nonempty and strictly right-padded')
    if np.any(x[~mask] != 0):
        raise ValueError('Padding must be zero')
    if len({c['sequence_id'] for c in contexts}) != len(contexts):
        raise ValueError('Duplicate sequence IDs')
    runs = {r['run_key']: r for r in read_rows(directory, 'runs') if r['training_candidate']}
    return dict(x=x, mask=mask, y=y, contexts=contexts, runs=runs, columns=columns,
                directory=directory, view=view)


def prepare_splits(data, path, seed):
    path = Path(path)
    if not path.exists():
        # Prespecified strata prevent a small ransomware family disappearing from
        # validation/test. Never split a group, and never search seeds by accuracy.
        if path.resolve().parent == data['directory'].resolve():
            raise ValueError('Keep split files outside the immutable dataset directory')
        grouped, strata = defaultdict(list), defaultdict(list)
        for run in data['runs'].values():
            grouped[run['group_id']].append(run)
        for group, runs in grouped.items():
            labels = {r['label'] for r in runs}
            if len(labels) != 1 or not labels <= {'benign', 'ransomware'}:
                raise ValueError('Group contains conflicting/nonbinary labels')
            label = next(iter(labels))
            families = {r['family'] for r in runs}
            if label == 'ransomware' and (len(families) != 1 or not next(iter(families))):
                raise ValueError('Ransomware group needs a consistent family for stratification')
            stratum = 'benign' if label == 'benign' else 'ransomware:' + next(iter(families))
            strata[stratum].append(group)
        rng, assignment = random.Random(seed), {}
        for stratum in sorted(strata):
            ids = sorted(strata[stratum])
            if len(ids) < 3:
                raise ValueError(f'{stratum}: need >=3 groups for family-stratified holdout; use a separately justified supplied split for rare families')
            rng.shuffle(ids)
            n = max(1, int(len(ids) * .15))
            for i, group in enumerate(ids):
                assignment[group] = 'test' if i < n else 'validation' if i < 2*n else 'train'
        rows = [dict(run_key=r['run_key'], group_id=r['group_id'], split=assignment[r['group_id']])
                for r in sorted(data['runs'].values(), key=lambda r: r['run_key'])]
        # Validate before publishing, especially if the same SHA has inconsistent group IDs.
        path.parent.mkdir(parents=True, exist_ok=True)
        draft = path.with_name(path.name + '.pending')
        write_csv(draft, rows)
        read_splits(data['directory'], draft)
        draft.replace(path)
    assignment = read_splits(data['directory'], path)
    indices, summary = {}, {}
    for split in ('train', 'validation', 'test'):
        idx = np.array([i for i, c in enumerate(data['contexts']) if assignment[c['run_key']] == split])
        if not len(idx) or set(data['y'][idx]) != {0, 1}:
            raise ValueError(f'{split} needs sequences from BOTH classes; do not repeatedly search seeds for better results')
        indices[split] = idx
        keys = {data['contexts'][i]['run_key'] for i in idx}
        summary[split] = dict(sequences=len(idx), runs=len(keys),
                             labels=dict(Counter(data['runs'][k]['label'] for k in keys)),
                             families=dict(Counter(data['runs'][k]['family'] for k in keys)),
                             groups=len({data['runs'][k]['group_id'] for k in keys}))
    return indices, summary


def training_weights(data, indices):
    """Equal total loss per run, then equal class mass; labels from TRAIN only."""
    counts = Counter(data['contexts'][i]['run_key'] for i in indices)
    classes = Counter(data['runs'][key]['label'] for key in counts)
    weight = np.array([1.0 / counts[data['contexts'][i]['run_key']] /
                       classes[data['runs'][data['contexts'][i]['run_key']]['label']]
                      for i in indices], dtype=np.float32)
    return weight / weight.mean()


def validation_weights(data, indices):
    counts = Counter(data['contexts'][i]['run_key'] for i in indices)
    weight = np.array([1.0 / counts[data['contexts'][i]['run_key']] for i in indices], dtype=np.float32)
    return weight / weight.mean()


@tf.keras.utils.register_keras_serializable(package='Sysmon')
class ApplyMask(tf.keras.layers.Layer):
    def call(self, inputs):
        values, valid = inputs
        return tf.where(valid[..., None], values, tf.zeros_like(values))


def build_model(length, width, seed=20261001):
    tf.keras.utils.set_random_seed(seed)
    features = tf.keras.Input((length, width), name='features', dtype='float32')
    valid = tf.keras.Input((length,), name='valid', dtype='bool')
    clean = ApplyMask(name='mask_input')([features, valid])
    branches = [tf.keras.layers.Conv1D(32, k, padding='causal', activation='relu',
                                     name=f'conv_{k}')(clean) for k in (3, 5)]
    hidden = tf.keras.layers.Concatenate(name='multiscale')(branches)
    hidden = ApplyMask(name='mask_convolution')([hidden, valid])
    hidden = tf.keras.layers.LSTM(64, name='event_lstm')(hidden, mask=valid)
    hidden = tf.keras.layers.Dropout(0.3)(hidden)
    hidden = tf.keras.layers.Dense(32, activation='relu')(hidden)
    output = tf.keras.layers.Dense(1, activation='sigmoid', name='ransomware_probability')(hidden)
    model = tf.keras.Model({'features': features, 'valid': valid}, output, name='Sysmon_CNN_LSTM')
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3, clipnorm=1.0),
                  loss='binary_crossentropy')
    return model


def batches(data, indices, weights, batch_size, shuffle=False, seed=20261001):
    ds = tf.data.Dataset.from_tensor_slices((
        {'features': data['x'][indices], 'valid': data['mask'][indices]},
        data['y'][indices].astype(np.float32)[:, None], weights))
    if shuffle:
        ds = ds.shuffle(len(indices), seed=seed, reshuffle_each_iteration=True)
    options = tf.data.Options()
    options.threading.private_threadpool_size = 2
    return ds.batch(batch_size).with_options(options).prefetch(1)


def predict(model, data, indices, batch_size=64):
    # Direct calls avoid an extra prediction dataset/thread pool.
    result = []
    for start in range(0, len(indices), batch_size):
        chunk = indices[start:start + batch_size]
        result.append(model({'features': data['x'][chunk], 'valid': data['mask'][chunk]},
                            training=False).numpy().ravel())
    return np.concatenate(result)


def aggregate_runs(data, indices, probabilities):
    """Fixed arithmetic mean of chunk probabilities; each run is one evaluation unit."""
    grouped = defaultdict(list)
    for i, p in zip(indices, probabilities):
        grouped[data['contexts'][i]['run_key']].append(float(p))
    rows = []
    for key, values in sorted(grouped.items()):
        run = data['runs'][key]
        rows.append(dict(run_key=key, group_id=run['group_id'], family=run['family'],
                         y=0 if run['label'] == 'benign' else 1,
                         probability=float(np.mean(values)), chunks=len(values)))
    return rows


def metrics(y, p, threshold):
    y, p = np.asarray(y), np.asarray(p)
    predicted = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    both = len(set(y)) == 2
    return dict(n=len(y), threshold=float(threshold), accuracy=float(accuracy_score(y, predicted)),
                balanced_accuracy=float(balanced_accuracy_score(y, predicted)) if both else None,
                precision=float(precision_score(y, predicted, zero_division=0)),
                recall=float(recall_score(y, predicted, zero_division=0)),
                f1=float(fbeta_score(y, predicted, beta=1, zero_division=0)),
                f2=float(fbeta_score(y, predicted, beta=2, zero_division=0)),
                roc_auc=float(roc_auc_score(y, p)) if both else None,
                average_precision=float(average_precision_score(y, p)) if both else None,
                fpr=float(fp / (fp + tn)) if fp + tn else None,
                fnr=float(fn / (fn + tp)) if fn + tp else None,
                tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))


def select_threshold(validation_rows):
    y = np.array([r['y'] for r in validation_rows])
    p = np.array([r['probability'] for r in validation_rows])
    if set(y) != {0, 1}:
        raise ValueError('Validation threshold selection needs both classes')
    candidates = sorted(set([0.0, 0.5, 1.0, *p.tolist()]))
    scores = [metrics(y, p, threshold) for threshold in candidates]
    best = max(scores, key=lambda m: (m['f2'], -m['fpr'], m['threshold']))
    return dict(threshold=best['threshold'], source='validation runs ONLY',
                objective='max F2; ties: lower FPR, then higher threshold',
                aggregation='arithmetic mean of chunk probabilities', validation_metrics=best)


def train(data, indices, output, epochs=40, batch_size=32, seed=20261001,
          software_groups_reviewed=False):
    output = Path(output)
    if output.exists():
        raise ValueError('Use a new experiment output directory to preserve results')
    output.mkdir(parents=True)
    tf.keras.utils.set_random_seed(seed)
    tf.config.experimental.enable_op_determinism()
    model = build_model(data['x'].shape[1], data['x'].shape[2], seed)
    packages = {p: importlib.metadata.version(p) for p in ['tensorflow', 'keras', 'numpy', 'scikit-learn']}
    config = dict(version=VERSION, python=platform.python_version(), packages=packages,
                  seed=seed, epochs=epochs, batch_size=batch_size, view=data['view'],
                  input_shape=list(data['x'].shape[1:]), parameters=model.count_params(),
                  software_groups_reviewed=software_groups_reviewed,
                  interpretation='pilot hash/group holdout' if not software_groups_reviewed else 'reviewed group holdout',
                  dataset_checksums_sha256=hashlib.sha256((data['directory'] / 'SHA256SUMS.txt').read_bytes()).hexdigest(),
                  devices=[str(d) for d in tf.config.list_physical_devices()],
                  labels={'benign': 0, 'ransomware': 1}, label_scope='run_weak_label',
                  aggregation='mean chunk probability; fixed before evaluation',
                  weights='train: inverse chunks per run times inverse class run count; normalized mean 1',
                  selection='minimum run-balanced validation binary crossentropy')
    save_json(output / 'config.json', config)
    save_json(output / 'feature_columns.json', data['columns'])
    for name in ['SHA256SUMS.txt', 'feature_schema.json', 'numeric_schema.json', 'build.json']:
        shutil.copy2(data['directory'] / name, output / ('dataset_' + name))
    model.summary(print_fn=lambda line: print(line))
    train_idx, val_idx = indices['train'], indices['validation']
    callbacks = [tf.keras.callbacks.ModelCheckpoint(str(output / 'best.keras'), monitor='val_loss', save_best_only=True),
                 tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=7, restore_best_weights=True),
                 tf.keras.callbacks.CSVLogger(str(output / 'history.csv'))]
    history = model.fit(batches(data, train_idx, training_weights(data, train_idx), batch_size, True, seed),
                        validation_data=batches(data, val_idx, validation_weights(data, val_idx), batch_size),
                        epochs=epochs, callbacks=callbacks, verbose=2, shuffle=False)
    model = tf.keras.models.load_model(output / 'best.keras')
    val_predictions = predict(model, data, val_idx)
    rows = aggregate_runs(data, val_idx, val_predictions)
    decision = select_threshold(rows)
    save_json(output / 'threshold.json', decision)
    write_csv(output / 'validation_run_predictions.csv', rows)
    save_json(output / 'history.json', history.history)
    return model, decision


def evaluate_test(model, data, indices, output, decision):
    """Call after architecture/checkpoint/aggregation/threshold have been frozen."""
    output = Path(output)
    if (output / 'test_metrics.json').exists():
        raise ValueError('Test evaluation already saved; preserve it and do not tune against test results')
    idx = indices['test']
    p = predict(model, data, idx)
    rows = aggregate_runs(data, idx, p)
    threshold = float(decision['threshold'])
    for row in rows:
        row['prediction'] = int(row['probability'] >= threshold)
    report = dict(primary_run_level=metrics([r['y'] for r in rows], [r['probability'] for r in rows], threshold),
                  secondary_chunk_level=metrics(data['y'][idx], p, threshold),
                  notes='Chunks are dependent weak-label samples; primary metric unit is a run, not an event.')
    # Family recall is descriptive only: this is still a binary classifier.
    report['ransomware_family_recall'] = {}
    for family in sorted({r['family'] for r in rows if r['y'] == 1}):
        selected = [r for r in rows if r['y'] == 1 and r['family'] == family]
        report['ransomware_family_recall'][family] = dict(n=len(selected), detected=sum(r['prediction'] for r in selected))
    save_json(output / 'test_metrics.json', report)
    write_csv(output / 'test_run_predictions.csv', rows)
    write_csv(output / 'test_sequence_predictions.csv', [dict(sequence_id=data['contexts'][i]['sequence_id'],
               run_key=data['contexts'][i]['run_key'], y=int(data['y'][i]), probability=float(prob),
               prediction=int(prob >= threshold)) for i, prob in zip(idx, p)])
    return report


def plot_results(output):
    import matplotlib.pyplot as plt
    from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay
    output = Path(output)
    h = json.loads((output / 'history.json').read_text(encoding='utf-8'))
    rows = list(csv.DictReader((output / 'test_run_predictions.csv').open(encoding='utf-8-sig')))
    y = [int(r['y']) for r in rows]
    p = [float(r['probability']) for r in rows]
    predicted = [int(r['prediction']) for r in rows]
    fig, axes = plt.subplots(2, 2, figsize=(10, 8))
    axes[0, 0].plot(range(1, len(h['loss'])+1), h['loss'], label='Train (class/run weighted)')
    axes[0, 0].plot(range(1, len(h['val_loss'])+1), h['val_loss'], label='Validation (run weighted)')
    axes[0, 0].set(xlabel='Epoch', ylabel='Binary crossentropy'); axes[0, 0].legend()
    from sklearn.metrics import ConfusionMatrixDisplay
    ConfusionMatrixDisplay.from_predictions(y, predicted, labels=[0, 1], display_labels=['Benign', 'Ransomware'], ax=axes[0, 1], colorbar=False)
    PrecisionRecallDisplay.from_predictions(y, p, ax=axes[1, 0])
    RocCurveDisplay.from_predictions(y, p, ax=axes[1, 1])
    fig.suptitle('Run-level holdout evaluation (small pilot)')
    fig.tight_layout(); fig.savefig(output / 'evaluation.png', dpi=180)
    return fig
