"""Load and validate preprocessing outputs without fitting anything.

Usage: python dataset.py DATASET_DIRECTORY
Use iter_examples() from a training notebook; model inputs are under features only.
"""
import argparse
import csv
import gzip
import json
from pathlib import Path

from preprocess import sha256
from behavior_features import encode, numeric_columns


def read_rows(directory, name):
    with gzip.open(Path(directory) / (name + ".jsonl.gz"), "rt", encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def verify_checksums(directory):
    directory = Path(directory)
    if (directory / "BUILDING.json").exists():
        raise ValueError("dataset build was interrupted")
    for line in (directory / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines():
        digest, name = line.split("  ", 1)
        path = (directory / name).resolve()
        if path.parent != directory.resolve() or sha256(path) != digest:
            raise ValueError("dataset checksum mismatch: " + name)


def require_binary_labels(directory):
    labels = {r["label"] for r in read_rows(directory, "runs") if r["training_candidate"]}
    if not {"benign", "ransomware"}.issubset(labels):
        raise ValueError("binary training requires both benign and ransomware candidate runs")


def iter_examples(directory, view="system"):
    """Yield unencoded, unpadded [events, fields] examples plus explicit audit context.

    This convenience loader holds feature/event indexes in memory. For a larger
    release, convert to Parquet and partition by run; the format contract is unchanged.
    Call verify_checksums once before use. Apply group splits before any fitting.
    """
    if view not in ("system", "related"):
        raise ValueError("view must be system or related")
    directory = Path(directory)
    schema = json.loads((directory / "feature_schema.json").read_text(encoding="utf-8"))["features"]
    runs = {r["run_key"]: r for r in read_rows(directory, "runs")}
    feature_index = {}
    for item in read_rows(directory, "features"):
        if item["event_uid"] in feature_index or set(item["features"]) != set(schema):
            raise ValueError("duplicate event features or unexpected model feature columns")
        feature_index[item["event_uid"]] = item["features"]
    events = {r["event_uid"]: r for r in read_rows(directory, "events")}
    seen = set()
    for seq in read_rows(directory, "sequences"):
        if seq["view"] != view:
            continue
        run = runs[seq["run_key"]]
        ids = seq["event_uids"]
        if not run["training_candidate"] or seq["group_id"] != run["group_id"] or seq["label"] != run["label"]:
            raise ValueError("sequence run/label/quality mismatch")
        if not ids or len(ids) != seq["valid_length"] or seq["valid_length"] + seq["padding_required"] != seq["target_length"]:
            raise ValueError("invalid sequence lengths")
        order = []
        for uid in ids:
            e = events[uid]
            if uid in seen or e["run_key"] != seq["run_key"] or e["phase"] != "window" or not e.get("model_eligible", False):
                raise ValueError("overlap, cross-run sequence, or out-of-window event")
            if view == "related" and e["relation"] == "unrelated":
                raise ValueError("unrelated event in related view")
            seen.add(uid)
            order.append((e["selected_utc"], e["sequence"]))
        if order != sorted(order):
            raise ValueError("sequence is not ordered by selected timestamp")
        yield {"features": [feature_index[uid] for uid in ids], "context": seq}


def read_splits(directory, path):
    """Reject missing runs and leakage across either software/sample or group ID."""
    runs = {r['run_key']: r for r in read_rows(directory, 'runs') if r['training_candidate']}
    result, groups, samples = {}, {}, {}
    with Path(path).open(encoding='utf-8-sig', newline='') as stream:
        for row in csv.DictReader(stream):
            key, split = row['run_key'], row['split']
            if key not in runs or key in result or split not in ('train', 'validation', 'test'):
                raise ValueError('invalid/duplicate split row: ' + key)
            run = runs[key]
            if row['group_id'] != run['group_id']:
                raise ValueError('split group mismatch: ' + key)
            for index, identity in ((groups, run['group_id']), (samples, run['sample_sha256'])):
                if identity in index and index[identity] != split:
                    raise ValueError('sample/group leaks across splits: ' + identity)
                index[identity] = split
            result[key] = split
    if set(result) != set(runs):
        raise ValueError('split file must cover exactly all candidate runs')
    return result


def iter_numeric_examples(directory, view='system', splits=None, split=None):
    """Yield real [time, feature] arrays as Python lists, plus padding mask.

    Convert x to numpy.float32 in the notebook. Only x and mask are inputs;
    context is audit information, y is a weak run label, weight balances runs.
    This is NOT the old per-row reshape(feature_count, 1).
    """
    verify_checksums(directory)
    if (splits is None) != (split is None):
        raise ValueError('supply both splits and split, or neither for inspection')
    if split is not None and split not in ('train', 'validation', 'test'):
        raise ValueError('invalid requested split')
    assignment = read_splits(directory, splits) if splits is not None else None
    specs = json.loads((Path(directory) / 'feature_schema.json').read_text(encoding='utf-8'))['features']
    width = len(numeric_columns(specs))
    for example in iter_examples(directory, view):
        seq = example['context']
        if assignment is not None and assignment[seq['run_key']] != split:
            continue
        x = [encode(values, specs) for values in example['features']]
        valid, padding = len(x), seq['padding_required']
        x.extend([[0.0] * width for _ in range(padding)])
        yield {'x': x, 'mask': [True] * valid + [False] * padding,
               'y': {'benign': 0, 'ransomware': 1}[seq['label']],
               'weight': seq['run_weight'], 'context': seq}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    verify_checksums(args.directory)
    counts = {view: sum(1 for _ in iter_examples(args.directory, view)) for view in ("system", "related")}
    print(json.dumps({"checksums": "verified", "validated_sequences": counts}))
    try:
        require_binary_labels(args.directory)
    except ValueError as error:
        print("NOT READY FOR BINARY TRAINING: " + str(error))


if __name__ == "__main__":
    main()
