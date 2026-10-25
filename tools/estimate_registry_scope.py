"""HISTORICAL ONLY (not Swift v2): Estimate v1.1 registry retention on existing XML; never modify source logs.

This is policy replay, not a driver/throughput test or a cleaned training dataset.
All non-registry records are retained in this estimate because their rules did
not change from v1.0. Only already captured events can be evaluated.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sysmon' / 'legacy-modular'))
from registry_policy import keep_registry, SELF_IMAGES
VERSION = 'thesis-sysmon-v1.1.1'

NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def inspect(path):
    before_hash = digest(path)
    before, after = Counter(), Counter()
    self_before = self_after = 0
    images = {value.casefold() for value in SELF_IMAGES}
    for _, record in ET.iterparse(path, events=('end',)):
        if record.tag != 'Record':
            continue
        event = record.find(NS + 'Event')
        if event is None:
            raise ValueError('Record has no Windows event: ' + str(path))
        event_id = event.findtext(NS + 'System/' + NS + 'EventID')
        fields = {node.get('Name'): node.text or '' for node in event.findall(NS + 'EventData/' + NS + 'Data')}
        registry = event_id in ('12', '13', '14')
        own = registry and fields.get('Image', '').casefold() in images
        before[event_id] += 1
        self_before += int(own)
        if not registry or keep_registry(fields):
            after[event_id] += 1
            self_after += int(own)
        record.clear()
    if not before:
        raise ValueError('No collector Records found: ' + str(path))
    if before_hash != digest(path):
        raise ValueError('Input changed during replay: ' + str(path))
    return dict(path=str(path), xml_sha256=before_hash, original_events=sum(before.values()),
                retained_events=sum(after.values()), removed_registry_events=sum(before.values())-sum(after.values()),
                estimated_event_reduction_percent=round(100*(1-sum(after.values())/sum(before.values())), 2),
                before_counts=dict(before), retained_counts=dict(after),
                sysmon_own_registry_before=self_before, sysmon_own_registry_retained=self_after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', nargs='+', type=Path)
    args = parser.parse_args()
    files = set()
    for root in args.roots:
        if root.is_file():
            files.add(root.resolve())
        elif root.is_dir():
            files.update(p.resolve() for p in root.rglob('events.xml'))
        else:
            parser.error('Input does not exist: ' + str(root))
    if not files:
        parser.error('No events.xml files found')
    print(json.dumps(dict(config_version=VERSION, scope='existing-event policy replay only; not measured future loss/size',
                          runs=[inspect(path) for path in sorted(files)]), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    main()
