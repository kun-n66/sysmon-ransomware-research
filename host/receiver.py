#!/usr/bin/env python3
"""Receive Sysmon from a VMware serial named pipe; never opens/runs a sample."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
import uuid

from storage import XmlStore, atomic_json, parse_event, recover, sample_hash, utc_now
from winpipe import WindowsPipe

MAX_FRAME = 8 * 1024 * 1024
RECEIVER_VERSION = "1.2.0"


class Frames:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        while True:
            end = self.buffer.find(b"\n")
            if end < 0:
                if len(self.buffer) > MAX_FRAME:
                    raise ValueError("Protocol frame exceeds 8 MiB.")
                return
            if end > MAX_FRAME:
                raise ValueError("Protocol frame exceeds 8 MiB.")
            line = bytes(self.buffer[:end])
            del self.buffer[:end + 1]
            if not line.strip():
                continue
            message = json.loads(line.decode("utf-8"))
            if not isinstance(message, dict) or message.get("v") != 1:
                raise ValueError("Invalid protocol message/version.")
            yield message


def positive_float(value):
    value = float(value)
    if not 0 < value < 86401:
        raise argparse.ArgumentTypeError("Must be positive and no greater than 86400 seconds.")
    return value


def end_utc(value, duration):
    if not value:
        return None
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:  # Sysmon UtcTime uses 'YYYY-MM-DD HH:MM:SS.mmm'.
        stamp = stamp.replace(tzinfo=timezone.utc)
    return (stamp + timedelta(seconds=duration)).isoformat().replace("+00:00", "Z")


def receive(args, transport_factory=WindowsPipe):
    sample = sample_hash(args.sample)
    software = getattr(args, "software_name", None)
    family = args.family
    if software is not None:
        software = software.strip()
        if not software or len(software) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in software):
            raise ValueError("Software name must contain 1-128 characters without control characters.")
        if args.start_mode != "immediate":
            raise ValueError("--software-name is for benign immediate capture only.")
        expected_family = "Benign_" + software
        if family not in ("unknown", expected_family):
            raise ValueError("--family conflicts with --software-name; omit --family for benign capture.")
        family = expected_family
    elif args.start_mode == "immediate" and family.lower().startswith("benign_"):
        raise ValueError("Benign capture requires --software-name. Use host/run_benign_realtime.ps1; SHA256 cannot infer a software name.")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:12]
    identity = {"software_name": software, "software_name_source": "operator_declared"} if software else {}
    store = XmlStore(args.output, sample, run_id, {
        **identity,
        "family": family, "pipe": args.pipe, "requested_duration_seconds": args.duration,
        "start_mode": args.start_mode, "sysmon_filter": "none; guest Sysmon configuration governs events",
        "collection_scope": "all subscribed events including prelaunch and drain tail",
        "completeness_scope": "collector-observed transport only; not proof of all source events",
        "receiver_version": RECEIVER_VERSION,
    })
    print(str(store.directory), flush=True)
    status_path = store.directory / "status.json"
    abort_path = store.directory / "abort.request"
    state = "connecting"
    problems = []
    details = {"problems": problems, "sequence_gaps": 0, "ignored_other_run_frames": 0}
    status_updates = {"write_failures": 0, "last_error": None,
                      "last_failure_utc": None, "last_success_utc": None}
    details["status_updates"] = status_updates
    transport = None
    last_seq = 0
    ready_at = started_at = stop_at = None
    last_activity = time.monotonic()
    last_status = 0
    last_status_warning = None
    finished = False
    got_end = False
    frames = Frames()

    def status(force=False):
        nonlocal last_status, last_status_warning
        now = time.monotonic()
        if force or now - last_status >= 0.5:
            # Advance even on failure: retry on the next scheduled update, never
            # spin/sleep on this optional file while the guest queue is filling.
            last_status = now
            payload = {"run_id": run_id, "sample_sha256": sample, "state": state,
                                     "events": store.count, "last_sequence": last_seq,
                                     "updated_utc": utc_now(), "problems": problems,
                                     "window_elapsed_seconds": round(now - started_at, 2) if started_at is not None else None,
                                     "window_remaining_seconds": round(max(0, args.duration - (now - started_at)), 2) if started_at is not None else None,
                                     "drain_elapsed_seconds": round(now - stop_at, 2) if stop_at is not None else None,
                                     "last_guest_stats": details.get("last_guest_stats"),
                                     "status_updates": dict(status_updates)}
            try:
                atomic_json(status_path, payload, replace_attempts=1)
                status_updates["last_success_utc"] = payload["updated_utc"]
            except OSError as error:
                status_updates["write_failures"] += 1
                status_updates["last_error"] = type(error).__name__ + ": " + str(error)
                status_updates["last_failure_utc"] = utc_now()
                if last_status_warning is None or now - last_status_warning >= 60:
                    print("[WARNING] Progress status update failed; XML reception continues: " + str(error),
                          file=sys.stderr, flush=True)
                    last_status_warning = now

    def command(kind):
        message = {"v": 1, "type": kind, "run_id": run_id}
        if kind == "start":
            message["sample_sha256"] = sample
        transport.write((json.dumps(message, separators=(",", ":")) + "\n").encode("ascii"))

    def stop(reason):
        nonlocal state, stop_at
        if stop_at is not None:
            return
        details["stop_reason"] = reason
        details["host_stop_requested_utc"] = utc_now()
        command("stop")
        stop_at = time.monotonic()
        state = "draining"
        status(True)

    try:
        status(True)
        transport = transport_factory(args.pipe, args.connect_timeout)
        command("start")
        state = "waiting_ready"
        connect_at = time.monotonic()
        last_activity = connect_at
        status(True)
        while not finished:
            data = transport.read(65536, 0.1)
            # Count bytes as transport activity; a large fragmented XML frame is not silence.
            if data:
                last_activity = time.monotonic()
            for message in frames.feed(data):
                kind = message.get("type")
                if kind == "hello":
                    continue
                if message.get("run_id") != run_id:
                    details["ignored_other_run_frames"] += 1
                    continue
                now = time.monotonic()
                if kind == "ready":
                    if ready_at is not None or message.get("sample_sha256") != sample:
                        raise ValueError("Unexpected READY or sample hash mismatch.")
                    ready_at = now
                    details["guest_ready_utc"] = message.get("guest_utc")
                    details["host_ready_utc"] = utc_now()
                    state = "armed"
                    if args.start_mode == "immediate":
                        started_at = now
                        details["host_window_started_utc"] = utc_now()
                        state = "recording"
                    status(True)
                elif kind == "event":
                    if ready_at is None:
                        raise ValueError("Received EVENT before READY.")
                    seq = message.get("seq")
                    if type(seq) is not int or seq <= last_seq:
                        raise ValueError("Invalid, duplicate, or decreasing event sequence.")
                    if seq != last_seq + 1:
                        details["sequence_gaps"] += seq - last_seq - 1
                    xml = message.get("xml")
                    event = parse_event(xml)
                    received = utc_now()
                    store.append(seq, xml, received)
                    last_seq = seq
                    image_name = event["image"].replace("\\", "/").rsplit("/", 1)[-1].lower()
                    if started_at is None and stop_at is None and args.start_mode == "process" and event["event_id"] == "1" and image_name == sample + ".exe":
                        started_at = now
                        details.update(host_window_started_utc=received, sample_process_guid=event["process_guid"],
                                       sample_process_event_sequence=seq, window_start_event_utc=event["event_utc"],
                                       window_end_event_utc=end_utc(event["event_utc"], args.duration))
                        state = "recording"
                        status(True)
                elif kind == "heartbeat":
                    details["last_guest_stats"] = {key: value for key, value in message.items() if key not in ("v", "type", "run_id")}
                elif kind == "error":
                    raise RuntimeError("Guest collector: " + str(message.get("message", "unknown error")))
                elif kind == "end":
                    if stop_at is None:
                        raise ValueError("Unexpected END before host STOP.")
                    details["guest_final_stats"] = {key: value for key, value in message.items() if key not in ("v", "type", "run_id")}
                    for key in ("observed", "sent", "dropped", "watcher_errors", "queued_events"):
                        if type(message.get(key)) is not int or message[key] < 0:
                            raise ValueError("Invalid END counter: " + key)
                    if message["sent"] != store.count or message["observed"] != message["sent"] + message["dropped"]:
                        problems.append("guest_host_count_mismatch")
                    if message["dropped"]:
                        problems.append("guest_queue_overflow")
                    if message["watcher_errors"]:
                        problems.append("guest_event_subscription_errors")
                    if message["queued_events"]:
                        problems.append("guest_queue_not_drained")
                    if details["sequence_gaps"]:
                        problems.append("transport_sequence_gap")
                    if started_at is None:
                        problems.append("window_never_started")
                    got_end = True
                    finished = True
                    break
                else:
                    raise ValueError("Unknown message type: " + str(kind))
            now = time.monotonic()
            if not finished:
                if abort_path.exists() and stop_at is None:
                    problems.append("aborted_by_controller")
                    if ready_at is None:
                        raise RuntimeError("Controller aborted before READY.")
                    stop("controller_abort")
                if ready_at is None and now - connect_at >= args.ready_timeout:
                    raise TimeoutError("Collector READY timeout; check guest task, COM port and Sysmon permissions.")
                if ready_at is not None and started_at is None and stop_at is None and now - ready_at >= args.start_timeout:
                    problems.append("sample_process_start_timeout")
                    stop("start_timeout")
                if started_at is not None and stop_at is None and now - started_at >= args.duration:
                    stop("duration_elapsed")
                if stop_at is not None and now - stop_at >= args.drain_timeout:
                    raise TimeoutError("Drain timeout; guest queue may exceed serial throughput.")
                if now - last_activity >= args.silence_timeout:
                    raise TimeoutError("Collector transport is silent.")
                store.flush()
                status()
    except KeyboardInterrupt:
        problems.append("receiver_interrupted")
    except Exception as error:
        problems.append(type(error).__name__ + ": " + str(error))
        print(str(error), file=sys.stderr, flush=True)
    finally:
        if transport is not None:
            if not got_end and stop_at is None:
                try:
                    command("stop")
                except Exception:
                    pass
            try:
                transport.close()
            except Exception as error:
                problems.append("transport_close_error: " + str(error))
        if not got_end:
            problems.append("missing_end_frame")
        state = "complete" if got_end and not problems else "incomplete"
        details["transport_complete"] = got_end and not problems
        final_state = state
        state = "finalizing"
        status(True)
        details["receiver_pid"] = os.getpid()
        store.finish(final_state, details)
        state = final_state
        failures_before = status_updates["write_failures"]
        status(True)
        if status_updates["write_failures"] != failures_before:
            # Record even a failure of the final progress publication. This is
            # critical metadata, so errors here must still propagate to the caller.
            atomic_json(store.directory / "metadata.json", store.metadata)
    print("{}: {} events -> {}".format(state, store.count, store.directory / "events.xml"), flush=True)
    return 0 if state == "complete" else 2


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    run = commands.add_parser("receive", help="Receive one experiment; connect to VMware's pipe server.")
    run.add_argument("--sample", required=True, help="SHA256, SHA256.exe, or sample path; used as an identifier only.")
    run.add_argument("--family", default="unknown", help="Metadata label, never used as an output path.")
    run.add_argument("--software-name", help="Explicit benign application name; immediate mode; generates Benign_<name> metadata family.")
    run.add_argument("--output", required=True)
    run.add_argument("--run-id")
    run.add_argument("--pipe", default=r"\\.\pipe\sysmon-log")
    run.add_argument("--duration", type=positive_float, default=300)
    run.add_argument("--start-mode", choices=("process", "immediate"), default="process")
    run.add_argument("--connect-timeout", type=positive_float, default=60)
    run.add_argument("--ready-timeout", type=positive_float, default=60)
    run.add_argument("--start-timeout", type=positive_float, default=120)
    run.add_argument("--drain-timeout", type=positive_float, default=120)
    run.add_argument("--silence-timeout", type=positive_float, default=30)
    repair = commands.add_parser("recover", help="Repair an interrupted XML .part; always mark incomplete.")
    repair.add_argument("run_directory")
    return result


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    if sys.version_info < (3, 9):
        raise SystemExit("Python 3.9+ required; Python 3.11/3.12 recommended.")
    args = parser().parse_args()
    if args.command == "recover":
        print(recover(args.run_directory))
        return 0
    return receive(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
