"""Read-only size/metadata summary; not an XML integrity or behavioral validator.

Python 3.9+, standard library. Prints JSON to stdout; never modifies input logs.
"""
import argparse
import json
from pathlib import Path
import statistics
import sys


def inspect(path, review_mib):
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    final = data.get('guest_final_stats')
    last = data.get('last_guest_stats')
    stats = final if isinstance(final, dict) else last if isinstance(last, dict) else {}
    kind = 'final' if isinstance(final, dict) else 'last_heartbeat' if isinstance(last, dict) else 'missing'
    # Do not follow metadata-provided paths: only read known log filenames.
    logfile = path.parent / 'events.xml'
    if not logfile.is_file():
        logfile = path.parent / 'events.xml.part'
    size = logfile.stat().st_size if logfile.is_file() else None
    count = data.get('event_count')
    count_valid = isinstance(count, int) and not isinstance(count, bool) and count > 0
    mib = size / 1048576 if size is not None else None
    concerns = []
    if data.get('status') != 'complete': concerns.append('status_not_complete')
    if data.get('transport_complete') is not True: concerns.append('transport_not_confirmed')
    if kind != 'final': concerns.append('final_stats_missing')
    for key in ('dropped', 'watcher_errors', 'queued_events', 'queued_xml_bytes'):
        if key not in stats: concerns.append(key + '_unknown')
        elif stats[key] != 0: concerns.append(key + '_nonzero')
    if data.get('sequence_gaps') != 0: concerns.append('sequence_gaps_nonzero_or_unknown')
    if data.get('problems'): concerns.append('metadata_reports_problems')
    if logfile.name.endswith('.part'): concerns.append('only_partial_or_missing_xml')
    if size is None: concerns.append('xml_missing')
    if not count_valid: concerns.append('event_count_zero_or_unknown')
    if count_valid and kind == 'final' and not (stats.get('observed') == stats.get('sent') == count):
        concerns.append('observed_sent_received_mismatch')
    if mib is not None and mib > review_mib: concerns.append('size_review_threshold_exceeded')
    return {
        'metadata_path': str(path), 'run_id': data.get('run_id'),
        'status': data.get('status'), 'transport_complete': data.get('transport_complete'),
        'event_count_from_metadata': count, 'xml_mib': round(mib, 4) if mib is not None else None,
        'approx_bytes_per_event': round(size / count, 1) if size is not None and count_valid else None,
        'stats_source': kind, 'observed': stats.get('observed'), 'sent': stats.get('sent'),
        'dropped': stats.get('dropped'), 'watcher_errors': stats.get('watcher_errors'),
        'queued_events': stats.get('queued_events'), 'queued_xml_bytes': stats.get('queued_xml_bytes'),
        'peak_queued_xml_bytes': stats.get('peak_queued_xml_bytes'),
        'config_sha256_from_metadata': data.get('sysmon_config_sha256'),
        'status_updates': data.get('status_updates'),
        'operational_warnings': (['progress_file_write_failed; inspect status_updates']
                                 if (data.get('status_updates') or {}).get('write_failures', 0) else []),
        'concerns': concerns,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', nargs='+', type=Path, help='Run directory, data root, or metadata.json')
    parser.add_argument('--review-mib', type=float, default=20,
                        help='Planning threshold only; default 20 MiB. Never truncates logs.')
    args = parser.parse_args()
    if not 0 < args.review_mib < float('inf'): parser.error('--review-mib must be positive and finite')
    files = set()
    errors = []
    for root in args.roots:
        if root.is_file() and root.name == 'metadata.json': files.add(root.resolve())
        elif root.is_dir(): files.update(p.resolve() for p in root.rglob('metadata.json'))
        else: errors.append({'path': str(root), 'error': 'not a directory or metadata.json'})
    rows = []
    for path in sorted(files):
        try: rows.append(inspect(path, args.review_mib))
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            errors.append({'path': str(path), 'error': str(exc)})
    sizes = [r['xml_mib'] for r in rows if r['xml_mib'] is not None]
    report = {
        'scope': 'Read-only metadata and file-size audit; XML content, hashes, source completeness, and behavior NOT verified.',
        'review_threshold_mib': args.review_mib,
        'threshold_meaning': 'User-adjustable planning trigger, not a scientific cutoff or quality label.',
        'run_count': len(rows), 'runs_with_concerns': sum(bool(r['concerns']) for r in rows),
        'total_xml_mib': round(sum(sizes), 4),
        'median_xml_mib': round(statistics.median(sizes), 4) if sizes else None,
        'max_xml_mib': max(sizes) if sizes else None,
        'runs': rows, 'read_errors': errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    # Concerns are reported, not reclassified into dataset labels. Errors mean audit incomplete.
    return 2 if errors or not rows else 0


if __name__ == '__main__':
    sys.exit(main())
