"""Short CPU integration check, NOT a paper performance experiment."""
import argparse
import json
from pathlib import Path
import shutil
import matplotlib
matplotlib.use('Agg')
import numpy as np
import tensorflow as tf
import training as t


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dataset', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    data = t.load_data(args.dataset)
    splits_path = args.output / 'splits.csv'
    indices, summary = t.prepare_splits(data, splits_path, 20261001)
    # Explicit independent checks of both group and executable hash disjointness.
    for identity in ('group_id', 'sample_sha256'):
        sets = []
        for name in ('train', 'validation', 'test'):
            sets.append({data['runs'][data['contexts'][i]['run_key']][identity] for i in indices[name]})
        assert not (sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2])
    weights = t.training_weights(data, indices['train'])
    y = data['y'][indices['train']]
    np.testing.assert_allclose(weights[y == 0].sum(), weights[y == 1].sum(), rtol=1e-6)
    # Deliberately leaking split must be rejected.
    t.read_splits(args.dataset, splits_path)
    duplicate = args.output / 'invalid_splits.csv'
    import csv
    rows = list(csv.DictReader(splits_path.open(encoding='utf-8-sig')))
    t.write_csv(duplicate, rows + [rows[0]])
    try:
        t.read_splits(args.dataset, duplicate)
        raise AssertionError('Invalid split accepted')
    except ValueError:
        pass
    model, decision = t.train(data, indices, args.output / 'one_epoch', epochs=1)
    model_dir = args.output / 'one_epoch'
    shutil.copy2(splits_path, model_dir / 'splits.csv')
    padded = np.flatnonzero(~data['mask'].all(axis=1))[:8]
    assert len(padded)
    x, mask = data['x'][padded].copy(), data['mask'][padded]
    original = model({'features': x, 'valid': mask}, training=False).numpy()
    x[~mask] = 12345.0
    noisy = model({'features': x, 'valid': mask}, training=False).numpy()
    np.testing.assert_allclose(original, noisy, atol=1e-6, rtol=1e-6)
    # Same valid sequence with a longer right-padded input must give the same answer.
    extended = t.build_model(x.shape[1] + 8, x.shape[2])
    extended.set_weights(model.get_weights())
    long_result = extended({'features': np.pad(x, ((0, 0), (0, 8), (0, 0))),
                            'valid': np.pad(mask, ((0, 0), (0, 8)))}, training=False).numpy()
    np.testing.assert_allclose(original, long_result, atol=1e-6, rtol=1e-6)
    restored = tf.keras.models.load_model(model_dir / 'best.keras')
    np.testing.assert_allclose(original, t.predict(restored, data, padded)[:, None], atol=1e-6, rtol=1e-6)
    report = t.evaluate_test(restored, data, indices, model_dir, decision)
    fig = t.plot_results(model_dir)
    import matplotlib.pyplot as plt
    plt.close(fig)
    # Unit test for run aggregation and validation-only threshold selection.
    synthetic = [{'y': 0, 'probability': .1}, {'y': 0, 'probability': .2},
                 {'y': 1, 'probability': .8}, {'y': 1, 'probability': .9}]
    assert t.select_threshold(synthetic)['threshold'] == .8
    assert report['primary_run_level']['n'] == summary['test']['runs']
    t.save_json(args.output / 'smoke_report.json', dict(passed=True, shape=list(data['x'].shape),
        splits=summary, checks=['source checksums and sequence integrity', 'group/hash disjointness',
        'invalid split rejection', 'equal training class weight', 'one full training epoch',
        'padding value invariance', 'padding length invariance', 'checkpoint reload equality',
        'validation threshold selection', 'run-level test aggregation', 'PNG plot export'],
        interpretation='Engineering smoke test only; do not cite its performance as a paper result'))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print('SMOKE TEST PASSED')


if __name__ == '__main__':
    main()
