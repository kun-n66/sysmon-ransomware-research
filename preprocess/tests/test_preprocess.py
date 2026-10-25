import argparse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import preprocess as p
import dataset

SAMPLE = "a" * 64
ROOT_GUID = "{11111111-1111-1111-1111-111111111111}"
CHILD_GUID = "{22222222-2222-2222-2222-222222222222}"
OTHER_GUID = "{33333333-3333-3333-3333-333333333333}"
T0 = datetime(2026, 9, 10, tzinfo=timezone.utc)


def event(event_id=1, seconds=0, **fields):
    fields.setdefault("UtcTime", p.iso(T0 + timedelta(seconds=seconds)))
    return event_id, seconds, fields


class PreprocessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "logs"
        self.directory = self.source / SAMPLE / "test_run"
        self.directory.mkdir(parents=True)
        self.args = argparse.Namespace(input=self.source, output=self.base / "processed", family=[],
            label="ransomware", annotations=None, time_source="system", timestamp_tolerance=5.0,
            sequence_length=2, max_xml_mib=512)

    def tearDown(self):
        self.temp.cleanup()

    def write_run(self, events=None, **overrides):
        if events is None:
            events = [event(ProcessGuid=ROOT_GUID, Image="C:\\samples\\AvosLocker\\" + SAMPLE + ".exe", Hashes="SHA256=" + SAMPLE)]
        root = ET.Element("SysmonExperiment", RunId=self.directory.name, SampleSHA256=SAMPLE)
        collection = ET.SubElement(root, "Events")
        for i, (eid, seconds, fields) in enumerate(events, 1):
            record = ET.SubElement(collection, "Record", Sequence=str(i), ReceivedUtc=p.iso(T0))
            node = ET.SubElement(record, p.NS + "Event")
            system = ET.SubElement(node, p.NS + "System")
            ET.SubElement(system, p.NS + "Provider", Name="Microsoft-Windows-Sysmon")
            ET.SubElement(system, p.NS + "EventID").text = str(eid)
            ET.SubElement(system, p.NS + "EventRecordID").text = str(100 + i)
            ET.SubElement(system, p.NS + "TimeCreated", SystemTime=p.iso(T0 + timedelta(seconds=seconds)))
            data = ET.SubElement(node, p.NS + "EventData")
            for key, value in fields.items():
                ET.SubElement(data, p.NS + "Data", Name=key).text = value
        path = self.directory / "events.xml"
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
        meta = dict(run_id=self.directory.name, sample_sha256=SAMPLE, family="AvosLocker", status="complete",
            transport_complete=True, problems=[], event_count=len(events), sequence_gaps=0,
            sample_process_event_sequence=1, sample_process_guid=ROOT_GUID, requested_duration_seconds=300,
            stop_reason="duration_elapsed", log_sha256=p.sha256(path),
            guest_final_stats=dict(observed=len(events), sent=len(events), dropped=0, watcher_errors=0, queued_events=0))
        meta.update(overrides)
        p.write_json(self.directory / "metadata.json", meta)
        (self.directory / "events.xml.sha256").write_text(p.sha256(path) + "  events.xml\n", encoding="ascii")
        return self.directory / "metadata.json"

    def analyze(self, annotation=None):
        return p.analyze(self.directory / "metadata.json", self.source, self.args, annotation or {})

    def test_complete_is_not_behavior_proof(self):
        self.write_run()
        row, events = self.analyze()
        self.assertTrue(row["training_candidate"])
        self.assertEqual(row["sample_content_hash_evidence"], "sysmon_hash_matches")
        self.assertEqual(row["behavior_review"], "unknown")
        self.assertNotIn("label", p.features(events[0]))

    def write_immediate(self, events=None, **overrides):
        self.args.label = "benign"
        if events is None:
            events = [event(seconds=2, ProcessGuid=ROOT_GUID, Image="C:\\Program Files\\Notepad++\\notepad++.exe", Hashes="SHA256=" + SAMPLE)]
        options = dict(start_mode="immediate", sample_process_event_sequence=None, sample_process_guid=None,
            guest_ready_utc=p.iso(T0), guest_final_stats=dict(observed=len(events), sent=len(events), dropped=0,
                watcher_errors=0, queued_events=0, guest_utc=p.iso(T0 + timedelta(seconds=301))))
        options.update(overrides)
        return self.write_run(events, **options)

    def test_immediate_benign_accepts_real_filename(self):
        self.write_immediate()
        row, events = self.analyze()
        self.assertTrue(row["training_candidate"])
        self.assertEqual(row["window_start_utc"], p.iso(T0))
        self.assertEqual(row["sample_start_evidence"], "xml_hash_verified")
        self.assertEqual(row["related_event_count"], 1)
        self.assertEqual(set(p.features(events[0])), set(p.feature_schema()))

    def test_immediate_does_not_require_process_launch(self):
        self.write_immediate([event(13, 2, ProcessGuid=OTHER_GUID)])
        row, events = self.analyze()
        self.assertTrue(row["training_candidate"])
        self.assertEqual(row["sample_start_evidence"], "not_observed_optional")
        self.assertEqual(row["related_event_count"], 0)
        self.assertEqual({s["view"] for s in p.create_sequences(row, events, 32)}, {"system"})

    def test_immediate_no_fallback_to_host_clock(self):
        self.write_immediate(guest_ready_utc=None, host_ready_utc=p.iso(T0))
        row, _ = self.analyze()
        self.assertFalse(row["training_candidate"])
        self.assertIsNone(row["window_start_utc"])

    def test_immediate_requires_explicit_benign_label(self):
        self.write_immediate()
        self.args.label = "unknown"
        row, _ = self.analyze()
        self.assertIn("immediate_requires_explicit_benign_label", row["quality_issues"])

    def test_immediate_checks_guest_window_coverage(self):
        self.write_immediate(guest_final_stats=dict(observed=1, sent=1, dropped=0, watcher_errors=0,
            queued_events=0, guest_utc=p.iso(T0 + timedelta(seconds=10))))
        row, _ = self.analyze()
        self.assertIn("guest_end_before_window_end", row["quality_issues"])
        self.assertFalse(row["training_candidate"])

    def test_immediate_multiple_hash_matched_starts(self):
        self.write_immediate([event(seconds=1, ProcessGuid=ROOT_GUID, Hashes="SHA256=" + SAMPLE),
                              event(seconds=2, ProcessGuid=CHILD_GUID, Hashes="SHA256=" + SAMPLE),
                              event(11, 3, ProcessGuid=CHILD_GUID)])
        row, _ = self.analyze()
        self.assertEqual(row["primary_start_count"], 2)
        self.assertEqual(row["related_event_count"], 3)

    def test_incomplete_immediate_is_still_quarantined(self):
        self.write_immediate(status="incomplete", transport_complete=False)
        row, events = self.analyze()
        self.assertFalse(row["training_candidate"])
        self.assertEqual(list(p.create_sequences(row, events, 32)), [])

    def test_incomplete_preserved_but_no_training_sequences(self):
        self.write_run(status="incomplete", transport_complete=False)
        row, events = self.analyze()
        self.assertEqual(len(events), 1)
        self.assertFalse(row["training_candidate"])
        self.assertEqual(list(p.create_sequences(row, events, 32)), [])

    def test_hash_tamper_rejected(self):
        self.write_run()
        with (self.directory / "events.xml").open("ab") as f:
            f.write(b"\n")
        row, _ = self.analyze()
        self.assertIn("metadata_xml_hash_missing_or_mismatch", row["quality_issues"])
        self.assertFalse(row["quality_pass"])

    def test_start_guid_is_cross_checked(self):
        self.write_run(sample_process_guid=OTHER_GUID)
        row, _ = self.analyze()
        self.assertEqual(row["sample_start_evidence"], "not_verified")
        self.assertFalse(row["training_candidate"])

    def test_start_content_hash_mismatch(self):
        self.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE + ".exe", Hashes="SHA256=" + "b" * 64)])
        row, _ = self.analyze()
        self.assertIn("sample_hash_mismatch", row["quality_issues"])

    def test_missing_content_hash_does_not_invent_verification(self):
        self.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE + ".exe")])
        row, _ = self.analyze()
        self.assertEqual(row["sample_content_hash_evidence"], "not_available")

    def test_half_open_window_and_tree_context(self):
        self.write_run([
            event(seconds=-1, ProcessGuid=OTHER_GUID),
            event(ProcessGuid=ROOT_GUID, Image=SAMPLE + ".exe"),
            event(seconds=1, ProcessGuid=CHILD_GUID, ParentProcessGuid=ROOT_GUID),
            event(10, 2, SourceProcessGUID=CHILD_GUID, TargetProcessGUID=OTHER_GUID),
            event(11, 3, ProcessGuid=OTHER_GUID, ProcessId="999"),
            event(11, 299.999, ProcessGuid=CHILD_GUID),
            event(11, 300, ProcessGuid=ROOT_GUID),
        ], sample_process_event_sequence=2)
        row, events = self.analyze()
        self.assertEqual([e["phase"] for e in events], ["baseline"] + ["window"] * 5 + ["tail"])
        self.assertEqual(events[3]["relation"], "guid_context")
        self.assertEqual(events[4]["relation"], "unrelated")
        self.assertEqual(row["tree_process_count"], 2)
        seqs = list(p.create_sequences(row, events, 2))
        system = [s for s in seqs if s["view"] == "system"]
        self.assertEqual([s["valid_length"] for s in system], [2, 2])
        self.assertEqual(system[-1]["padding_required"], 0)
        self.assertIn("outside_frozen_profile", events[3]["model_exclusion_reasons"])

    def test_timestamp_disagreement_retains_both(self):
        self.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE + ".exe", UtcTime="2026-09-01T00:00:00Z")])
        row, events = self.analyze()
        self.assertEqual(row["timestamp_disagreement_count"], 1)
        self.assertEqual(events[0]["selected_utc"], events[0]["system_utc"])
        self.assertNotEqual(events[0]["sysmon_utc"], events[0]["system_utc"])

    def test_truncated_xml_keeps_complete_record_prefix_only(self):
        self.write_run()
        path = self.directory / "events.xml"
        path.write_bytes(path.read_bytes().replace(b"</Events></SysmonExperiment>", b""))
        row, events = self.analyze()
        self.assertEqual(len(events), 1)
        self.assertFalse(row["quality_pass"])
        self.assertTrue(any("xml_parse_error" in i for i in row["quality_issues"]))

    def test_dtd_rejected_without_expansion(self):
        self.write_run()
        path = self.directory / "events.xml"
        path.write_text('<!DOCTYPE x [<!ENTITY x "bad">]><SysmonExperiment/>', encoding="utf-8")
        row, events = self.analyze()
        self.assertFalse(row["quality_pass"])
        self.assertEqual(events, [])

    def test_transport_sequence_gap_rejected(self):
        self.write_run()
        path = self.directory / "events.xml"
        path.write_bytes(path.read_bytes().replace(b'Sequence="1"', b'Sequence="2"'))
        row, _ = self.analyze()
        self.assertIn("noncontiguous_transport_sequence", row["quality_issues"])

    def test_counter_loss_and_early_stop_rejected(self):
        self.write_run(stop_reason="controller_abort", guest_final_stats=dict(observed=2, sent=1, dropped=1, queued_events=0, watcher_errors=0))
        row, _ = self.analyze()
        self.assertIn("duration_not_completed", row["quality_issues"])
        self.assertIn("final_counter_mismatch_or_loss", row["quality_issues"])

    def test_unknown_label_never_inferred_from_family(self):
        self.write_run()
        self.args.label = "unknown"
        row, _ = self.analyze()
        self.assertTrue(row["quality_pass"])
        self.assertFalse(row["training_candidate"])

    def test_review_overrides_label_and_excludes_no_activity(self):
        self.write_run()
        row, _ = self.analyze({"label": "benign", "behavior_review": "no_observed_activity", "review_note": "manual review"})
        self.assertEqual(row["label"], "benign")
        self.assertFalse(row["training_candidate"])

    def test_path_features_do_not_repeat_backslash_bug(self):
        values = p.path_features("C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(values["location"], "system32")
        self.assertEqual(values["depth"], 3)
        self.assertEqual(values["extension"], "exe")
        self.assertIsNone(p.path_features("-")["depth"])

    def test_path_normalization_does_not_use_labels(self):
        self.assertEqual(p.path_features("C:\\samples\\AvosLocker\\" + "a" * 64 + ".exe"),
                         p.path_features("C:\\samples\\BlackBasta\\" + "b" * 64 + ".exe"))

    def test_100ns_time_is_accepted_and_invalid_rejected(self):
        self.assertEqual(p.timestamp("2026-09-10T00:00:00.1234567Z").microsecond, 123456)
        self.assertIsNone(p.timestamp("bad"))

    def test_annotation_requires_evidence_note(self):
        path = self.base / "review.csv"
        path.write_text("run_key,label,behavior_review,review_note\na,ransomware,encryption_confirmed,\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            p.read_annotations(path)

    def test_missing_final_xml_part_stays_quarantined(self):
        self.write_run()
        (self.directory / "events.xml").rename(self.directory / "events.xml.part")
        row, events = self.analyze()
        self.assertEqual(len(events), 1)
        self.assertIn("final_xml_missing", row["quality_issues"])
        self.assertFalse(row["training_candidate"])

    def test_duplicate_named_fields_preserved_and_quarantined(self):
        self.write_run()
        path = self.directory / "events.xml"
        tree = ET.parse(path)
        data = tree.getroot().find("Events/Record/" + p.NS + "Event/" + p.NS + "EventData")
        ET.SubElement(data, p.NS + "Data", Name="Image").text = "second.exe"
        tree.write(path, encoding="utf-8", xml_declaration=True)
        row, events = self.analyze()
        self.assertEqual(sum(d["name"] == "Image" for d in events[0]["event_data_entries"]), 2)
        self.assertIn("event_schema_issue", row["quality_issues"])

    def test_event_order_not_field_order_and_same_sample_group(self):
        self.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE + ".exe"),
                        event(11, 20, ProcessGuid=ROOT_GUID), event(11, 10, ProcessGuid=ROOT_GUID)])
        row, events = self.analyze()
        sequences = [s for s in p.create_sequences(row, events, 32) if s["view"] == "system"]
        self.assertEqual(sequences[0]["event_uids"], [events[i]["event_uid"] for i in (0, 2, 1)])
        old_directory = self.directory
        self.directory = self.source / SAMPLE / "second_run"
        self.directory.mkdir()
        self.write_run()
        second, _ = self.analyze()
        self.assertTrue(second["training_candidate"])
        self.assertEqual(row["group_id"], second["group_id"])
        self.directory = old_directory

    def test_end_to_end_source_unchanged_loader_and_no_overwrite(self):
        self.write_run()
        before = {f.name: p.sha256(f) for f in self.directory.iterdir()}
        with redirect_stdout(io.StringIO()):
            summary = p.execute(self.args)
        self.assertFalse(summary["has_both_binary_classes"])
        self.assertEqual(before, {f.name: p.sha256(f) for f in self.directory.iterdir()})
        dataset.verify_checksums(self.args.output)
        example = next(dataset.iter_examples(self.args.output))
        self.assertEqual(set(example["features"][0]), set(p.feature_schema()))
        self.assertEqual(example["context"]["group_id"], "sha256:" + SAMPLE)
        with self.assertRaises(ValueError):
            dataset.require_binary_labels(self.args.output)
        with self.assertRaises(ValueError):
            p.execute(self.args)


if __name__ == "__main__":
    unittest.main()
