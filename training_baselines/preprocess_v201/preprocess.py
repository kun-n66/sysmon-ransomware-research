#!/usr/bin/env python3
"""Read-only Sysmon experiment preprocessing. Python 3.9+, standard library only.

No sample execution, model fitting, label inference from status, or source repair.
See README.md for the evidence boundaries and output contract.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
import csv
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import sys
import xml.etree.ElementTree as ET

VERSION = "2.0.1"
from behavior_features import features, schema as feature_schema, annotate, MODEL_IDS, DIAGNOSTIC_IDS, numeric_columns
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
LABELS = {"unknown", "benign", "ransomware", "other_malware"}
REVIEWS = {"unknown", "behavior_observed", "encryption_confirmed", "no_observed_activity"}
PATH_FIELDS = ("Image", "ParentImage", "TargetFilename", "ImageLoaded")
GUID_FIELDS = ("ProcessGuid", "SourceProcessGUID", "TargetProcessGUID")
HASH_RE = re.compile(r"(?i)(?<![a-z0-9])[a-f0-9]{32,64}(?![a-z0-9])")
GUID_RE = re.compile(r"(?i)\{?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?")
EXTENSIONS = {"exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "js", "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "7z", "rar", "jpg", "png", "log", "tmp", "lnk", "ini", "xml", "json"}


def dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        # Retain the original 100ns string in audit output; calculations use microseconds.
        value = re.sub(r"(\.\d{6})\d+", r"\1", value.strip()).replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def iso(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z") if value else None


def integer(value):
    try:
        return int(value) if value is not None and not isinstance(value, bool) else None
    except (ValueError, TypeError):
        return None


def guid(value):
    value = (value or "").strip().lower().strip("{}")
    return value if GUID_RE.fullmatch(value) and value != "00000000-0000-0000-0000-000000000000" else None


def missing(value):
    return value is None or value.strip() in ("", "-")


def event_sha256(event):
    return [h.lower() for h in re.findall(
        r"(?i)(?:^|[,;])\s*SHA256=([0-9a-f]{64})(?=$|[,;])",
        event["event_data"].get("Hashes", ""))]


def normalized(value):
    if missing(value):
        return None
    value = value.lower().replace("/", "\\")
    # Rules never inspect the family or class label. Apply to benign experiments too.
    value = re.sub(r"(?i)([a-z]:\\)samples\\[^\\\s\"]+", r"\1<experiment>", value)
    value = re.sub(r"(?i)(\\users\\)[^\\\s\"]+", r"\1<user>", value)
    value = re.sub(r"(?i)s-1-(?:\d+-)+\d+", "<sid>", value)
    value = GUID_RE.sub("<guid>", value)
    return HASH_RE.sub("<hash>", value)


def path_features(value):
    value = normalized(value)
    if value is None:
        return dict(missing=True, depth=None, length=None, location=None, extension=None)
    parts = [p for p in value.split("\\") if p]
    extension = parts[-1].rsplit(".", 1)[-1] if parts and "." in parts[-1] else "none"
    if extension not in EXTENSIONS and extension != "none":
        extension = "other"
    location = "other"
    for token, name in (("\\temp\\", "temp"), ("\\windows\\system32\\", "system32"),
                        ("\\windows\\", "windows"), ("\\program files", "program_files"),
                        ("\\users\\", "user_profile")):
        if token in value:
            location = name
            break
    if value.startswith("\\\\"):
        location = "unc"
    return dict(missing=False, depth=max(0, len(parts) - 1), length=len(value), location=location, extension=extension)


def check_xml_declarations(path):
    # Scan the entire input before parsing; do not expand internal entities.
    tail = b""
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            chunk = tail + block
            if b"\x00" in chunk or re.search(br"<!\s*(?:DOCTYPE|ENTITY)", chunk, re.I):
                raise ValueError("unsupported XML encoding or DTD/entity declaration")
            tail = chunk[-128:]


def parse_xml(path, run_key):
    check_xml_declarations(path)
    events, issues, stack = [], [], []
    root_attributes = None
    try:
        for action, node in ET.iterparse(path, events=("start", "end")):
            if action == "start":
                if not stack:
                    if node.tag != "SysmonExperiment":
                        raise ValueError("expected collector SysmonExperiment XML")
                    root_attributes = dict(node.attrib)
                stack.append(node)
                continue
            if node.tag == "Record":
                number = len(events) + 1
                event = node.find(NS + "Event")
                if event is None or len(node.findall(NS + "Event")) != 1:
                    raise ValueError("Record must contain exactly one Windows Event")
                system = event.find(NS + "System")
                if system is None:
                    raise ValueError("Event/System missing")
                provider = system.find(NS + "Provider")
                stamp = system.find(NS + "TimeCreated")
                entries = [{"name": d.get("Name"), "value": d.text or ""} for d in event.findall(NS + "EventData/" + NS + "Data")]
                data = {d["name"]: d["value"] for d in entries if d["name"] is not None}
                event_id = integer(system.findtext(NS + "EventID"))
                flags = []
                if len(data) != len(entries):
                    flags.append("duplicate_or_unnamed_data_field")
                if provider is None or provider.get("Name") != "Microsoft-Windows-Sysmon":
                    flags.append("unexpected_provider")
                if event_id is None:
                    flags.append("invalid_event_id")
                system_raw = stamp.get("SystemTime") if stamp is not None else None
                uid = hashlib.sha256((run_key + ":" + str(number)).encode()).hexdigest()
                events.append({"event_uid": uid, "record_index": number,
                    "sequence": integer(node.get("Sequence")), "received_utc": node.get("ReceivedUtc"),
                    "event_id": event_id, "event_record_id": system.findtext(NS + "EventRecordID"),
                    "event_xml_sha256": hashlib.sha256(ET.tostring(event, encoding="utf-8")).hexdigest(),
                    "system_time_raw": system_raw, "sysmon_time_raw": data.get("UtcTime"),
                    "system_utc": iso(timestamp(system_raw)), "sysmon_utc": iso(timestamp(data.get("UtcTime"))),
                    "computer": system.findtext(NS + "Computer"), "channel": system.findtext(NS + "Channel"),
                    "event_data": data, "event_data_entries": entries, "event_issues": flags})
                if len(stack) > 1:
                    stack[-2].remove(node)
                node.clear()
            stack.pop()
    except ET.ParseError as error:
        # Whole Record prefixes may be audited, but a malformed document never qualifies.
        issues.append("xml_parse_error: " + str(error))
    return events, root_attributes or {}, issues


def read_annotations(path):
    if path is None:
        return {}
    annotations = {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            key = row.get("run_key", "").strip()
            if not key or key in annotations:
                raise ValueError("annotations require unique nonempty run_key")
            if row.get("label", "unknown") not in LABELS or row.get("behavior_review", "unknown") not in REVIEWS:
                raise ValueError("invalid annotation label/behavior_review for " + key)
            if row.get("behavior_review", "unknown") != "unknown" and not row.get("review_note", "").strip():
                raise ValueError("behavior review requires a review_note: " + key)
            annotations[key] = row
    return annotations


def analyze(metadata_path, source, args, annotation):
    relative = metadata_path.parent.relative_to(source).as_posix()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    sample = str(metadata.get("sample_sha256", "")).lower()
    run_id = str(metadata.get("run_id", ""))
    run_key = sample + "/" + run_id
    label = annotation.get("label", args.label)
    review = annotation.get("behavior_review", "unknown")
    problems, warnings = [], []
    row = {"run_key": run_key, "run_id": run_id, "sample_sha256": sample,
        "group_id": annotation.get("group_id") or "sha256:" + sample, "family": metadata.get("family", "unknown"),
        "label": label, "label_scope": "run_weak_label", "behavior_review": review,
        "software_name": annotation.get("software_name") or metadata.get("software_name", ""),
        "review_note": annotation.get("review_note", ""), "source_directory": relative,
        "metadata_sha256": sha256(metadata_path), "metadata": metadata,
        "collection_status": metadata.get("status"), "transport_complete": metadata.get("transport_complete") is True}
    if not re.fullmatch(r"[a-f0-9]{64}", sample):
        problems.append("invalid_sample_sha256")
    if not run_id or metadata_path.parent.name != run_id or metadata_path.parent.parent.name.lower() != sample:
        problems.append("directory_identity_mismatch")
    path = metadata_path.parent / "events.xml"
    if not path.exists():
        path = metadata_path.parent / "events.xml.part"
        problems.append("final_xml_missing")
    events, attrs, parse_issues = [], {}, []
    digest = None
    if path.exists():
        before = path.stat()
        if before.st_size > args.max_xml_mib * 1024 * 1024:
            problems.append("xml_exceeds_size_limit")
        else:
            digest = sha256(path)
            try:
                events, attrs, parse_issues = parse_xml(path, run_key)
            except (ValueError, OSError) as error:
                problems.append("xml_rejected: " + str(error))
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                problems.append("source_changed_during_read")
    else:
        problems.append("xml_missing")
    problems.extend(parse_issues)
    row.update(xml_file=path.name, xml_sha256=digest, parsed_event_count=len(events))
    if digest is None or digest != metadata.get("log_sha256"):
        problems.append("metadata_xml_hash_missing_or_mismatch")
    sidecar = metadata_path.parent / "events.xml.sha256"
    sidecar_hash = sidecar.read_text(encoding="utf-8-sig").split() if sidecar.exists() else []
    if not digest or not sidecar_hash or sidecar_hash[0].lower() != digest:
        problems.append("sidecar_xml_hash_missing_or_mismatch")
    if attrs.get("RunId") != run_id or attrs.get("SampleSHA256", "").lower() != sample:
        problems.append("xml_identity_mismatch")
    if len(events) != metadata.get("event_count"):
        problems.append("metadata_event_count_mismatch")
    if [e["sequence"] for e in events] != list(range(1, len(events) + 1)):
        problems.append("noncontiguous_transport_sequence")
    if any(e["event_issues"] for e in events):
        problems.append("event_schema_issue")
    if not row["transport_complete"] or metadata.get("status") != "complete":
        problems.append("collection_incomplete")
    if metadata.get("problems"):
        problems.append("collector_reported_problems")
    if metadata.get("sequence_gaps", 0) != 0:
        problems.append("collector_reported_sequence_gap")
    final = metadata.get("guest_final_stats") or {}
    if not isinstance(final, dict) or any(type(final.get(k)) is not int for k in ("observed", "sent", "dropped", "watcher_errors", "queued_events")):
        problems.append("final_counters_missing")
    elif final["observed"] != len(events) or final["sent"] != len(events) or any(final[k] != 0 for k in ("dropped", "watcher_errors", "queued_events")):
        problems.append("final_counter_mismatch_or_loss")
    if metadata.get("stop_reason") != "duration_elapsed":
        problems.append("duration_not_completed")
    mode = metadata.get("start_mode", "process")
    immediate = mode == "immediate"
    if mode not in ("process", "immediate"):
        problems.append("unsupported_start_mode")
    if immediate and label != "benign":
        problems.append("immediate_requires_explicit_benign_label")
    root = None
    seq = metadata.get("sample_process_event_sequence")
    expected_guid = guid(metadata.get("sample_process_guid"))
    for e in events:
        name = e["event_data"].get("Image", "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if e["sequence"] == seq and e["event_id"] == 1 and expected_guid and guid(e["event_data"].get("ProcessGuid")) == expected_guid and name == sample + ".exe":
            root = e
            break
    row["sample_start_evidence"] = "xml_verified" if root else "not_verified"
    row["sample_content_hash_evidence"] = "not_available"
    if root:
        matches = re.findall(r"(?i)(?:^|[,;])\s*SHA256=([0-9a-f]{64})(?=$|[,;])", root["event_data"].get("Hashes", ""))
        if matches:
            row["sample_content_hash_evidence"] = "sysmon_hash_matches" if all(h.lower() == sample for h in matches) else "sysmon_hash_mismatch"
            if row["sample_content_hash_evidence"] == "sysmon_hash_mismatch":
                problems.append("sample_hash_mismatch")
    elif not immediate:
        problems.append("sample_start_not_verified")
    duration = metadata.get("requested_duration_seconds")
    valid_duration = isinstance(duration, (int, float)) and not isinstance(duration, bool) and math.isfinite(duration) and 0 < duration <= 86400
    if not valid_duration:
        problems.append("invalid_requested_duration")
    start = timestamp(metadata.get("guest_ready_utc")) if immediate else timestamp(root[args.time_source + "_utc"]) if root else None
    end = start + timedelta(seconds=duration) if start and valid_duration else None
    if start is None:
        problems.append("event_window_start_unavailable")
    row.update(start_mode=mode, window_start_utc=iso(start), window_end_utc=iso(end), time_source=args.time_source,
        window_anchor_source="metadata.guest_ready_utc" if immediate else "verified_process_event",
        window_definition="guest_ready_observation" if immediate else "process_start_observation")
    # Use GUID edges only; PID reuse and Source/Target interactions do not define ancestry.
    tree = {expected_guid} if root else set()
    primary_events = [root] if root else []
    if immediate:
        # A readiness-anchored observation window does not require launching a
        # renamed executable. Hash-matched process starts are optional context.
        row["sample_start_evidence"] = "not_observed_optional"
        row["sample_content_hash_evidence"] = "not_available"
        tree, primary_events = set(), []
        for e in events:
            t = timestamp(e[args.time_source + "_utc"])
            hashes = event_sha256(e)
            process = guid(e["event_data"].get("ProcessGuid"))
            if e["event_id"] == 1 and process and hashes and all(h == sample for h in hashes) and t and start and end and start <= t < end:
                primary_events.append(e)
                tree.add(process)
        if primary_events:
            row["sample_start_evidence"] = "xml_hash_verified"
            row["sample_content_hash_evidence"] = "sysmon_hash_matches"
        else:
            warnings.append("primary_software_start_not_observed")
        # Host receipt timestamps are never substituted for guest timestamps.
        guest_end = timestamp(final.get("guest_utc")) if isinstance(final, dict) else None
        if guest_end is None:
            problems.append("guest_end_time_unavailable")
        elif end and guest_end < end:
            problems.append("guest_end_before_window_end")
        warnings.append("immediate_window_uses_guest_ready_not_first_manual_action")
    if not immediate:
        guest_end = timestamp(final.get("guest_utc")) if isinstance(final, dict) else None
        if guest_end is None:
            warnings.append("guest_end_time_unavailable_legacy")
        elif end and guest_end < end:
            problems.append("guest_end_before_window_end")
    controller_path = metadata_path.parent / "controller_result.json"
    if controller_path.exists():
        controller = json.loads(controller_path.read_text(encoding="utf-8-sig"))
        row["controller_result"] = controller
        row["controller_result_sha256"] = sha256(controller_path)
        if (controller.get("run_id") != run_id or controller.get("result_committed") is not True
                or controller.get("receiver_forced_termination") is not False
                or controller.get("receiver_exit_code") != 0):
            problems.append("controller_not_successful")
    row["config_verification"] = "not_available_in_legacy_metadata"
    warnings.append("sysmon_config_fingerprint_not_recorded")
    row["observed_primary_images"] = sorted({e["event_data"].get("Image", "") for e in primary_events})
    row["primary_start_count"] = len(primary_events)
    changed = True
    while changed:
        changed = False
        for e in events:
            data = e["event_data"]
            child = guid(data.get("ProcessGuid"))
            if e["event_id"] == 1 and guid(data.get("ParentProcessGuid")) in tree and child and child not in tree:
                tree.add(child)
                changed = True
    offsets, invalid_times, window_events, related_events = [], 0, [], []
    for e in events:
        data = e["event_data"]
        event_time = timestamp(e[args.time_source + "_utc"])
        a, b = timestamp(e["system_utc"]), timestamp(e["sysmon_utc"])
        offset = (a - b).total_seconds() if a and b else None
        e["system_minus_sysmon_seconds"] = offset
        e["timestamp_disagreement"] = abs(offset) > args.timestamp_tolerance if offset is not None else False
        if e["timestamp_disagreement"]:
            offsets.append(offset)
        if event_time is None:
            invalid_times += 1
        e["selected_utc"] = iso(event_time)
        e["relative_seconds"] = (event_time - start).total_seconds() if event_time and start else None
        e["phase"] = "unknown" if not event_time or not start or not end else "baseline" if event_time < start else "window" if event_time < end else "tail"
        direct = guid(data.get("ProcessGuid")) in tree
        context = any(guid(data.get(k)) in tree for k in GUID_FIELDS[1:])
        e["relation"] = "process_tree" if direct else "guid_context" if context else "unrelated"
        e["normalized_paths"] = {k: normalized(data.get(k)) for k in PATH_FIELDS}
        if e["phase"] == "window":
            window_events.append(e)
            if e["relation"] != "unrelated":
                related_events.append(e)
    if invalid_times:
        problems.append("selected_timestamp_missing")
    if offsets:
        warnings.append("system_sysmon_timestamp_disagreement")
    if not window_events:
        problems.append("empty_window")
    if review == "no_observed_activity":
        warnings.append("review_reports_no_activity")
    if label == "unknown":
        warnings.append("label_unknown")
    if not any(e["event_id"] in (11, 23, 26) for e in window_events):
        warnings.append("no_file_create_delete_events_in_window")
    row.update(window_event_count=len(window_events), related_event_count=len(related_events),
        tree_process_count=len(tree), timestamp_disagreement_count=len(offsets),
        max_abs_timestamp_difference_seconds=max((abs(e["system_minus_sysmon_seconds"]) for e in events if e["system_minus_sysmon_seconds"] is not None), default=0),
        event_id_counts=dict(sorted(Counter(str(e["event_id"]) for e in window_events).items())),
        related_event_id_counts=dict(sorted(Counter(str(e["event_id"]) for e in related_events).items())),
        related_file_create_count=sum(e["event_id"] == 11 for e in related_events),
        related_file_delete_count=sum(e["event_id"] in (23, 26) for e in related_events),
        quality_issues=sorted(set(problems)), warnings=warnings,
        quality_pass=not problems, training_candidate=not problems and label in ("benign", "ransomware") and review != "no_observed_activity")
    row["behavior_evidence"] = "manual:" + review if review != "unknown" else "event_counts_only_not_encryption_proof"
    annotate(events)
    row["model_event_count"] = sum(e["model_eligible"] for e in events)
    row["exact_duplicate_count"] = sum(e["duplicate_of"] is not None for e in events)
    row["exclusion_counts"] = dict(Counter(reason for e in events for reason in e["model_exclusion_reasons"]))
    row["model_related_event_count"] = sum(e["model_eligible"] and e["relation"] != "unrelated" for e in events)
    if any(e["event_id"] == 255 for e in events):
        row["quality_issues"].append("sysmon_error_event_255")
    if not row["model_event_count"]:
        row["quality_issues"].append("empty_model_window")
    if any(e["event_id"] not in MODEL_IDS + DIAGNOSTIC_IDS for e in events):
        row["warnings"].append("events_outside_frozen_profile")
    # Audit timestamp disagreement, but do not rewrite event times to hide it.
    if row["timestamp_disagreement_count"]:
        row["warnings"].append("review_clock_before_training")
    row["quality_pass"] = not row["quality_issues"]
    row["training_candidate"] = row["training_candidate"] and row["quality_pass"]
    return row, events


def csv_write(path, rows, columns):
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            values = {k: dump(row[k]) if isinstance(row.get(k), (dict, list)) else row.get(k) for k in columns}
            # CSV is for human review; JSONL holds exact strings and remains authoritative.
            for key, value in values.items():
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
                    values[key] = "'" + value
            writer.writerow(values)


def create_sequences(row, events, length):
    if not row["training_candidate"]:
        return
    for view in ("system", "related"):
        selected = [e for e in events if e.get("model_eligible", False) and (view == "system" or e["relation"] != "unrelated")]
        selected.sort(key=lambda e: (e["selected_utc"], e["sequence"]))
        for start in range(0, len(selected), length):
            chunk = selected[start:start + length]
            yield {"sequence_id": hashlib.sha256((row["run_key"] + ":" + view + ":" + str(start)).encode()).hexdigest(),
                "run_key": row["run_key"], "group_id": row["group_id"], "view": view,
                "label": row["label"], "label_scope": "run_weak_label", "family": row["family"],
                "event_uids": [e["event_uid"] for e in chunk], "valid_length": len(chunk),
                "target_length": length, "padding_required": length - len(chunk),
                "start_utc": chunk[0]["selected_utc"], "end_utc": chunk[-1]["selected_utc"],
                "related_event_count": sum(e["relation"] != "unrelated" for e in chunk),
                "background_only_by_guid": all(e["relation"] == "unrelated" for e in chunk),
                "chunk_index": start // length,
                "run_weight": 1.0 / math.ceil(len(selected) / length),
                "split": "unassigned"}


def execute(args):
    output = args.output.resolve()
    manifest = getattr(args, "input_manifest", None)
    if manifest:
        inputs = json.loads(manifest.read_text(encoding="utf-8-sig"))
        if not isinstance(inputs, list) or not inputs:
            raise ValueError("input manifest must be a nonempty JSON list")
        specs = []
        for item in inputs:
            if item.get("label") not in LABELS or not isinstance(item.get("path"), str):
                raise ValueError("each input needs path and explicit valid label")
            source = Path(item["path"])
            if not source.is_absolute():
                source = manifest.resolve().parent / source
            specs.append((source.resolve(), item["label"]))
    else:
        specs = [(args.input.resolve(), args.label)]
    annotations = read_annotations(args.annotations)
    paths, seen_paths = [], set()
    for source, label in specs:
        if not source.is_dir():
            raise ValueError("input directory does not exist: " + str(source))
        if output == source or source in output.parents or output in source.parents:
            raise ValueError("output must be separate from the input tree")
        for path in sorted(source.rglob("metadata.json")):
            if path.resolve() in seen_paths:
                raise ValueError("overlapping inputs: " + str(path))
            seen_paths.add(path.resolve())
            paths.append((path, source, label))
    if output.exists():
        raise ValueError("output already exists; choose a new versioned directory")
    if not paths:
        raise ValueError("no metadata.json found")
    output.mkdir(parents=True)
    write_json(output / "BUILDING.json", {"version": VERSION, "state": "building"})
    rows, all_keys, counts = [], set(), Counter()
    with ExitStack() as stack:
        writers = {name: stack.enter_context(gzip.open(output / (name + ".jsonl.gz"), "wt", encoding="utf-8", newline="\n")) for name in ("runs", "events", "features", "sequences")}
        for path, source, source_label in paths:
            key = "unreadable:" + hashlib.sha256(str(path).encode()).hexdigest()
            try:
                meta = json.loads(path.read_text(encoding="utf-8-sig"))
                if args.family and str(meta.get("family", "")).lower() not in {f.lower() for f in args.family}:
                    continue
                key = str(meta.get("sample_sha256", "")).lower() + "/" + str(meta.get("run_id", ""))
                if key in all_keys:
                    raise RuntimeError("duplicate run identity: " + key)
                all_keys.add(key)
                settings = argparse.Namespace(**vars(args))
                settings.label = source_label
                row, events = analyze(path, source, settings, annotations.get(key, {}))
                row["source_root"] = str(source)
            except (ValueError, TypeError, AttributeError, OSError, OverflowError) as error:
                row = {"run_key": key, "source_directory": key, "label": "unknown", "family": "unknown",
                       "quality_pass": False, "training_candidate": False,
                       "quality_issues": ["run_read_error: " + str(error)], "warnings": [], "parsed_event_count": 0}
                events = []
            rows.append(row)
            writers["runs"].write(dump(row) + "\n")
            counts["runs"] += 1
            counts["events"] += len(events)
            counts["model_events"] += row.get("model_event_count", 0)
            counts["quality_pass_runs"] += bool(row["quality_pass"])
            counts["training_candidate_runs"] += bool(row["training_candidate"])
            for e in events:
                e.update(run_key=key, source_xml=(path.parent.relative_to(source) / row["xml_file"]).as_posix(), source_xml_sha256=row["xml_sha256"])
                writers["events"].write(dump(e) + "\n")
                writers["features"].write(dump({"event_uid": e["event_uid"], "features": features(e)}) + "\n")
            for seq in create_sequences(row, events, args.sequence_length):
                writers["sequences"].write(dump(seq) + "\n")
                counts[seq["view"] + "_sequences"] += 1
            print("[PREPROCESS] {} events={} candidate={}".format(row.get("run_id", key), len(events), row["training_candidate"]), flush=True)
    if not rows:
        raise ValueError("no runs matched --family")
    columns = ["run_key", "run_id", "sample_sha256", "group_id", "family", "software_name", "label", "start_mode", "window_anchor_source", "collection_status", "transport_complete",
               "sample_start_evidence", "sample_content_hash_evidence", "behavior_review", "behavior_evidence", "quality_pass",
               "training_candidate", "parsed_event_count", "window_event_count", "related_event_count", "tree_process_count",
               "model_event_count", "model_related_event_count", "exact_duplicate_count", "exclusion_counts", "config_verification", "related_file_create_count", "related_file_delete_count", "observed_primary_images", "primary_start_count", "timestamp_disagreement_count", "quality_issues", "warnings"]
    csv_write(output / "manifest.csv", rows, columns)
    csv_write(output / "review_template.csv", [{"run_key": r["run_key"], "label": r["label"],
              "behavior_review": r.get("behavior_review", "unknown"), "review_note": r.get("review_note", ""), "group_id": r.get("group_id", ""), "software_name": r.get("software_name", "")} for r in rows],
              ["run_key", "label", "behavior_review", "review_note", "group_id", "software_name"])
    schema = feature_schema()
    write_json(output / "feature_schema.json", {"version": VERSION, "features": schema,
        "input_rule": "Only the nested features object is a model input. Join labels/splits by run via events and runs.",
        "excluded": ["family", "label", "sample_sha256", "run_key", "group_id", "process_guid", "process_id", "computer", "raw_paths", "raw_command_lines", "absolute_timestamps", "quality_flags", "relation", "event_uid"],
        "missing": "null for absent/empty/dash; fixed encoder separates MISSING and UNK; model PAD uses mask"})
    write_json(output / "numeric_schema.json", {"version": VERSION, "columns": numeric_columns(schema),
        "encoding": "fixed one-hot; MISSING and UNK; numeric zero + missing indicator; no fitting"})
    eligible = [r for r in rows if r["training_candidate"]]
    label_counts = Counter(r["label"] for r in eligible)
    summary = {"version": VERSION, **counts, "feature_count": len(schema),
        "family_runs": dict(Counter(r["family"] for r in rows)),
        "collection_status_counts": dict(Counter(str(r.get("collection_status")) for r in rows)),
        "candidate_label_counts": dict(label_counts), "has_both_binary_classes": all(label_counts[k] > 0 for k in ("benign", "ransomware")),
        "independent_candidate_samples": len({r["group_id"] for r in eligible}),
        "quality_issue_counts": dict(Counter(i for r in rows for i in r["quality_issues"])),
        "warning_counts": dict(Counter(w for r in rows for w in r["warnings"])),
        "unused_annotation_keys": sorted(set(annotations) - {r["run_key"] for r in rows}),
        "splits_created": False,
        "limitations": ["complete describes observed transport, not all source activity", "file events do not prove encryption", "labels apply to runs, not individual events", "related view requires known sample root", "no model fitting or train/test split performed", "timestamp default is event write time, not a claim of exact behavior time"]}
    write_json(output / "summary.json", summary)
    write_json(output / "build.json", {"state": "complete", "version": VERSION, "python": platform.python_version(),
        "created_utc": iso(datetime.now(timezone.utc)), "source_roots": [str(source) for source, _ in specs], "script_sha256": sha256(Path(__file__)),
        "feature_code_sha256": sha256(Path(__file__).with_name("behavior_features.py")),
        "input_manifest_sha256": sha256(manifest) if manifest else None,
        "parameters": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "annotations_sha256": sha256(args.annotations) if args.annotations else None})
    report = ["# Sysmon 预处理报告", "", "此报告描述预处理质量，不证明样本完成加密。", "",
              "```json", json.dumps(summary, ensure_ascii=False, indent=2), "```", "",
              "模型只能读取 feature_schema.json 列出的特征。先按 group_id 划分数据，再拟合编码器、缺失值处理和标准化。",
              "缺少正常软件时不能进行二分类训练；异常运行保留用于审计，默认不生成训练序列。",
              "sequences 的标签属于运行窗口；related 视图用于已知样本分析。所有 split 暂为 unassigned。"]
    (output / "REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    (output / "BUILDING.json").unlink()
    files = sorted(p for p in output.iterdir() if p.is_file())
    (output / "SHA256SUMS.txt").write_text("".join(sha256(p) + "  " + p.name + "\n" for p in files), encoding="ascii")
    print(dump(summary))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--input", type=Path, help="one SysmonLogs root or run directory")
    inputs.add_argument("--input-manifest", type=Path, help="JSON list of path/label objects; supports multiple roots")
    parser.add_argument("--output", required=True, type=Path, help="new directory outside input")
    parser.add_argument("--family", action="append", help="optional family selection, repeatable")
    parser.add_argument("--label", choices=sorted(LABELS), default="unknown", help="explicit run label for selected inputs; never inferred from family/status")
    parser.add_argument("--annotations", type=Path, help="edited review_template.csv; exact run_key overrides --label")
    parser.add_argument("--time-source", choices=("system", "sysmon"), default="system")
    parser.add_argument("--timestamp-tolerance", type=float, default=5.0, help="seconds; audit warning only")
    parser.add_argument("--sequence-length", type=int, default=64, help="nonoverlapping event chunks; short last chunk retained")
    parser.add_argument("--max-xml-mib", type=int, default=512, help="per-run input size guard; events are held one run at a time")
    args = parser.parse_args()
    if args.sequence_length < 1 or args.max_xml_mib < 1 or not math.isfinite(args.timestamp_tolerance) or args.timestamp_tolerance < 0:
        parser.error("sequence length/size must be positive; timestamp tolerance must be finite and nonnegative")
    try:
        execute(args)
    except (ValueError, OSError, RuntimeError) as error:
        parser.exit(2, "ERROR: " + str(error) + "\n")


if __name__ == "__main__":
    main()
