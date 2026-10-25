"""Create reproducible class-stratified GROUP splits; never split event rows.

This random holdout is an initial experiment, not a temporal/generalization claim.
Use review_template.csv group_id to group benign versions of the same software.
"""
import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import random

from dataset import read_rows, verify_checksums, read_splits


def make_splits(directory, output, seed=20260928):
    verify_checksums(directory)
    output = Path(output)
    if output.exists() or output.resolve().parent == Path(directory).resolve():
        raise ValueError('use a new CSV outside the immutable dataset directory')
    runs = [r for r in read_rows(directory, 'runs') if r['training_candidate']]
    groups = defaultdict(list)
    sample_groups = defaultdict(set)
    for r in runs:
        groups[r['group_id']].append(r)
        sample_groups[r['sample_sha256']].add(r['group_id'])
    if any(len(g) > 1 for g in sample_groups.values()):
        raise ValueError('same sample has inconsistent group IDs; correct annotations first')
    by_label = defaultdict(list)
    for group, items in groups.items():
        labels = {r['label'] for r in items}
        if len(labels) != 1:
            raise ValueError('conflicting labels within group: ' + group)
        by_label[next(iter(labels))].append(group)
    if set(by_label) != {'benign', 'ransomware'} or min(map(len, by_label.values()), default=0) < 3:
        raise ValueError('need at least 3 independent groups PER CLASS; two-run pilot cannot be split')
    assignment = {}
    rng = random.Random(seed)
    for label in sorted(by_label):
        ids = sorted(by_label[label])
        rng.shuffle(ids)
        n = len(ids)
        test_n = max(1, int(n * 0.15))
        val_n = max(1, int(n * 0.15))
        for i, group in enumerate(ids):
            assignment[group] = 'test' if i < test_n else 'validation' if i < test_n + val_n else 'train'
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['run_key', 'group_id', 'split'])
        writer.writeheader()
        for r in sorted(runs, key=lambda r: r['run_key']):
            writer.writerow({'run_key': r['run_key'], 'group_id': r['group_id'], 'split': assignment[r['group_id']]})
    read_splits(directory, output)
    return {'seed': seed, 'group_counts': dict(Counter(assignment.values())),
            'groups_per_class': {k: len(v) for k, v in by_label.items()},
            'method': 'class-stratified group shuffle, approx 70/15/15; minimum 1 validation/test group per class'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--seed', type=int, default=20260928)
    a = p.parse_args()
    try:
        print(json.dumps(make_splits(a.directory, a.output, a.seed)))
    except (ValueError, OSError) as error:
        p.exit(2, 'ERROR: ' + str(error) + '\n')
