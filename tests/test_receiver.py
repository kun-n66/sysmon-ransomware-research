import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))
from receiver import Frames, end_utc, parser, receive
from storage import NS, XmlStore, atomic_json, file_sha256, parse_event, recover, sample_hash
from winpipe import PipeDisconnected

HASH = "a" * 64


def xml(event_id=1, hash_value=HASH):
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>{}</EventID>'
            '<TimeCreated SystemTime="2026-09-07T00:00:00.1234567Z"/>'
            '<EventRecordID>9</EventRecordID></System><EventData>'
            '<Data Name="Image">C:\\samples\\测试\\{}.exe</Data>'
            '<Data Name="CommandLine">a &amp; b &lt; c "quotes"</Data>'
            '<Data Name="ProcessGuid">{{test}}</Data></EventData></Event>').format(event_id, hash_value)


def frame(kind, **fields):
    return dict(v=1, type=kind, run_id="test", **fields)


class FakePipe:
    def __init__(self, messages, end_changes=None, disconnect=False):
        self.messages = list(messages)
        self.end_changes = end_changes or {}
        self.disconnect = disconnect
        self.writes = []

    def write(self, data, timeout=5):
        message = json.loads(data)
        self.writes.append(message)
        if message["type"] == "stop" and not self.disconnect:
            result = frame("end", observed=1, sent=1, dropped=0, watcher_errors=0, queued_events=0)
            result.update(self.end_changes)
            self.messages.append(result)

    def read(self, size, timeout):
        if self.messages:
            return (json.dumps(self.messages.pop(0), ensure_ascii=False) + "\n").encode("utf-8")
        if self.disconnect:
            raise PipeDisconnected("synthetic disconnect")
        time.sleep(0.005)
        return b""

    def close(self):
        pass


class ReceiverTests(unittest.TestCase):
    def test_benign_software_name_saved_and_family_derived(self):
        for name in ("SumatraPDF", "DB Browser for SQLite", "LibreOffice", "计算器"):
            code, meta, _ = self.execute(self.normal(), "--start-mode", "immediate", "--software-name", name)
            self.assertEqual(code, 0)
            self.assertEqual(meta["software_name"], name)
            self.assertEqual(meta["family"], "Benign_" + name)
            self.assertEqual(meta["software_name_source"], "operator_declared")
            self.assertEqual(meta["sample_sha256"], HASH)

    def test_stale_family_conflict_rejected_before_pipe_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            factory = mock.Mock()
            args = self.args(folder, "--start-mode", "immediate", "--software-name", "SumatraPDF",
                             "--family", "Benign_NotepadPlusPlus")
            with self.assertRaisesRegex(ValueError, "conflicts"):
                receive(args, factory)
            factory.assert_not_called()
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_old_benign_command_requires_explicit_software_name(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "requires --software-name"):
                receive(self.args(folder, "--start-mode", "immediate", "--family", "Benign_NotepadPlusPlus"))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_software_name_invalid_or_process_mode_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in ("   ", "bad\nname", "x" * 129):
                with self.assertRaises(ValueError):
                    receive(self.args(folder, "--start-mode", "immediate", "--software-name", name))
            with self.assertRaisesRegex(ValueError, "immediate"):
                receive(self.args(folder, "--software-name", "SumatraPDF"))

    def test_malware_family_keeps_existing_behavior(self):
        code, meta, _ = self.execute(self.normal(), "--family", "Conti")
        self.assertEqual(code, 0)
        self.assertEqual(meta["family"], "Conti")
        self.assertNotIn("software_name", meta)

    def args(self, directory, *extra):
        return parser().parse_args(["receive", "--sample", HASH, "--run-id", "test", "--output", directory,
                                    "--duration", "0.02", "--start-timeout", "0.03",
                                    "--silence-timeout", "0.2", "--drain-timeout", "0.2"] + list(extra))

    def execute(self, pipe, *extra):
        with tempfile.TemporaryDirectory() as folder:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = receive(self.args(folder, *extra), lambda *_: pipe)
            directory = Path(folder) / HASH / "test"
            meta = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
            document = ET.parse(directory / "events.xml")
            self.assertEqual(meta["log_sha256"], file_sha256(directory / "events.xml"))
            return code, meta, document

    def normal(self, **options):
        return FakePipe([frame("ready", sample_sha256=HASH), frame("event", seq=1, xml=xml())], **options)

    def test_progress_replace_denied_through_finalization_is_nonfatal(self):
        real_replace = os.replace
        def replace(source, target):
            if Path(target).name == "status.json":
                error = PermissionError("synthetic status sharing violation")
                error.winerror = 5
                raise error
            return real_replace(source, target)
        with mock.patch("storage.os.replace", side_effect=replace):
            for mode in ("process", "immediate"):
                code, meta, document = self.execute(self.normal(), "--start-mode", mode)
                self.assertEqual(code, 0, meta)
                self.assertEqual(meta["status"], "complete")
                self.assertEqual(meta["problems"], [])
                self.assertGreaterEqual(meta["status_updates"]["write_failures"], 5)
                self.assertIn("sharing violation", meta["status_updates"]["last_error"])
                self.assertEqual(len(document.findall("Events/Record")), 1)

    def test_progress_tmp_open_failure_is_nonfatal(self):
        real_open = Path.open
        def open_path(path, *args, **kwargs):
            if path.name == "status.json.tmp":
                raise PermissionError("synthetic locked temporary file")
            return real_open(path, *args, **kwargs)
        with mock.patch.object(Path, "open", open_path):
            code, meta, _ = self.execute(self.normal())
        self.assertEqual(code, 0, meta)
        self.assertGreater(meta["status_updates"]["write_failures"], 0)

    def test_transient_progress_failure_recovers(self):
        real_replace = os.replace
        remaining = [2]
        def replace(source, target):
            if Path(target).name == "status.json" and remaining[0]:
                remaining[0] -= 1
                raise PermissionError("synthetic transient lock")
            return real_replace(source, target)
        with mock.patch("storage.os.replace", side_effect=replace):
            code, meta, _ = self.execute(self.normal())
        self.assertEqual(code, 0, meta)
        self.assertEqual(meta["status_updates"]["write_failures"], 2)
        self.assertIsNotNone(meta["status_updates"]["last_success_utc"])

    def test_progress_warning_does_not_hide_transport_failure(self):
        real_atomic = atomic_json
        def publish(path, data, **kwargs):
            if Path(path).name == "status.json":
                raise PermissionError("synthetic progress lock")
            return real_atomic(path, data, **kwargs)
        with mock.patch("receiver.atomic_json", side_effect=publish):
            code, meta, _ = self.execute(self.normal(end_changes={"observed": 2, "dropped": 1}))
        self.assertEqual(code, 2)
        self.assertIn("guest_queue_overflow", meta["problems"])

    def test_critical_metadata_write_still_fails(self):
        real_replace = os.replace
        def replace(source, target):
            if Path(target).name == "metadata.json":
                data = json.loads(Path(source).read_text(encoding="utf-8"))
                if data.get("status") == "complete":
                    raise PermissionError("synthetic final metadata failure")
            return real_replace(source, target)
        with mock.patch("storage.os.replace", side_effect=replace):
            with self.assertRaisesRegex(PermissionError, "final metadata"):
                self.execute(self.normal())

    def test_atomic_json_retries_only_bounded_windows_conflicts(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "metadata.json"
            error = PermissionError("synthetic WinError 32")
            error.winerror = 32
            real_replace = os.replace
            attempts = [0]
            def replace(source, target):
                attempts[0] += 1
                if attempts[0] < 3:
                    raise error
                return real_replace(source, target)
            with mock.patch("storage.os.replace", side_effect=replace), mock.patch("storage.time.sleep") as sleep:
                atomic_json(path, {"saved": True})
                self.assertEqual(sleep.call_count, 2)
            self.assertTrue(json.loads(path.read_text())["saved"])
            with mock.patch("storage.os.replace", side_effect=error) as replace, mock.patch("storage.time.sleep"):
                with self.assertRaises(PermissionError):
                    atomic_json(path, {"saved": False})
                self.assertEqual(replace.call_count, 4)
            self.assertTrue(json.loads(path.read_text())["saved"])
            with mock.patch("storage.os.replace", side_effect=OSError("disk error")) as replace:
                with self.assertRaises(OSError):
                    atomic_json(path, {})
                self.assertEqual(replace.call_count, 1)

    @unittest.skipUnless(os.name == "nt", "Windows file sharing semantics")
    def test_real_windows_status_lock_does_not_interrupt_receive(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        pipe = self.normal()
        handle = None
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / HASH / "test"
            def connect(*_):
                nonlocal handle
                # Initial connecting status exists. Permit reading/writing but
                # deliberately NOT deletion, reproducing another reader's lock.
                handle = kernel.CreateFileW(str(directory / "status.json"), 0x80000000,
                                            3, None, 3, 0, None)
                if handle == wintypes.HANDLE(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
                return pipe
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = receive(self.args(folder), connect)
            finally:
                if handle is not None and handle != wintypes.HANDLE(-1).value:
                    kernel.CloseHandle(handle)
            meta = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0, meta)
            self.assertEqual(meta["status"], "complete")
            self.assertGreater(meta["status_updates"]["write_failures"], 0)
            self.assertEqual(file_sha256(directory / "events.xml"), meta["log_sha256"])

    def test_hash_names(self):
        self.assertEqual(sample_hash("C:\\samples\\" + HASH.upper() + ".EXE"), HASH)
        for value in ("../events.xml", "f" * 63, "g" * 64, HASH + ".exe.exe"):
            with self.assertRaises(ValueError):
                sample_hash(value)

    def test_xml_unicode_and_escaping(self):
        data = parse_event(xml())
        self.assertEqual(data["event_id"], "1")
        self.assertIn("测试", data["image"])

    def test_xml_dtd_and_foreign_provider_rejected(self):
        for value in ('<!DOCTYPE Event [<!ENTITY x "boom">]>' + xml(), xml().replace("Microsoft-Windows-Sysmon", "other"), "<Event/>"):
            with self.assertRaises((ValueError, ET.ParseError)):
                parse_event(value)

    def test_fragmented_unicode_frames(self):
        data = (json.dumps(frame("event", xml=xml()), ensure_ascii=False) + "\n").encode("utf-8")
        decoder = Frames()
        results = []
        for byte in data:
            results.extend(decoder.feed(bytes([byte])))
        self.assertEqual(results[0]["xml"], xml())

    def test_bad_json_and_version(self):
        for value in (b"no-json\n", b'[]\n', b'{"v":2}\n'):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                list(Frames().feed(value))

    def test_oversized_frame(self):
        with self.assertRaises(ValueError):
            list(Frames().feed(b"x" * (8 * 1024 * 1024 + 1)))

    def test_complete_and_raw_event_retained(self):
        code, meta, document = self.execute(self.normal())
        self.assertEqual(code, 0)
        self.assertEqual(meta["status"], "complete")
        self.assertEqual(meta["sample_sha256"], HASH)
        self.assertEqual(meta["sample_process_event_sequence"], 1)
        self.assertEqual(meta["sample_sha256_source"], "filename_not_content_verified")
        self.assertEqual(len(document.findall("Events/Record/" + NS + "Event")), 1)

    def test_initial_stale_run_ignored(self):
        pipe = self.normal()
        pipe.messages.insert(0, dict(v=1, type="event", run_id="old", seq=999, xml=xml()))
        code, meta, _ = self.execute(pipe)
        self.assertEqual(code, 0)
        self.assertEqual(meta["ignored_other_run_frames"], 1)

    def test_wrong_ready_hash(self):
        code, meta, _ = self.execute(FakePipe([frame("ready", sample_sha256="b" * 64)]))
        self.assertEqual(code, 2)
        self.assertIn("hash mismatch", " ".join(meta["problems"]))

    def test_no_matching_process_is_incomplete(self):
        pipe = FakePipe([frame("ready", sample_sha256=HASH), frame("event", seq=1, xml=xml(hash_value="b" * 64))])
        code, meta, _ = self.execute(pipe)
        self.assertEqual(code, 2)
        self.assertIn("sample_process_start_timeout", meta["problems"])

    def test_immediate_mode_does_not_need_matching_image(self):
        pipe = FakePipe([frame("ready", sample_sha256=HASH), frame("event", seq=1, xml=xml(11))])
        code, meta, _ = self.execute(pipe, "--start-mode", "immediate")
        self.assertEqual(code, 0)
        self.assertNotIn("sample_process_guid", meta)

    def test_disconnect_finalizes_partial_xml(self):
        code, meta, _ = self.execute(self.normal(disconnect=True))
        self.assertEqual(code, 2)
        self.assertEqual(meta["event_count"], 1)
        self.assertIn("missing_end_frame", meta["problems"])

    def test_queue_overflow_and_sequence_gap(self):
        pipe = self.normal(end_changes=dict(observed=2, sent=1, dropped=1))
        pipe.messages[-1]["seq"] = 2
        code, meta, _ = self.execute(pipe)
        self.assertEqual(code, 2)
        self.assertIn("guest_queue_overflow", meta["problems"])
        self.assertEqual(meta["sequence_gaps"], 1)

    def test_duplicate_sequence_fails(self):
        pipe = self.normal()
        pipe.messages.append(frame("event", seq=1, xml=xml()))
        code, meta, _ = self.execute(pipe)
        self.assertEqual(code, 2)
        self.assertEqual(meta["event_count"], 1)

    def test_counter_mismatch(self):
        code, meta, _ = self.execute(self.normal(end_changes=dict(sent=2, observed=2)))
        self.assertEqual(code, 2)
        self.assertIn("guest_host_count_mismatch", meta["problems"])

    def test_watcher_errors(self):
        code, meta, _ = self.execute(self.normal(end_changes=dict(watcher_errors=1)))
        self.assertEqual(code, 2)
        self.assertIn("guest_event_subscription_errors", meta["problems"])

    def test_window_timestamp(self):
        self.assertEqual(end_utc("2026-09-07 00:00:00.123", 300), "2026-09-07T00:05:00.123000Z")

    def test_run_directory_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            store = XmlStore(folder, HASH, "test", {})
            store.finish("incomplete", {})
            with self.assertRaises(FileExistsError):
                XmlStore(folder, HASH, "test", {})
            with self.assertRaises(ValueError):
                XmlStore(folder, HASH, "../escape", {})

    def test_recovery_retains_whole_records_and_original(self):
        with tempfile.TemporaryDirectory() as folder:
            store = XmlStore(folder, HASH, "test", {})
            store.append(1, xml(), "2026-09-07T00:00:00Z")
            store.flush(force=True)
            store.stream.write(b'<Record Sequence="2">partial')
            store.stream.close()
            result = recover(store.directory)
            self.assertEqual(len(ET.parse(result).findall("Events/Record")), 1)
            self.assertTrue((store.directory / "events.interrupted.part").exists())
            meta = json.loads((store.directory / "metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["status"], "incomplete")
            self.assertEqual(meta["log_sha256"], file_sha256(result))


@unittest.skipUnless(os.name == "nt" and os.environ.get("GUEST_HARNESS"), "Set GUEST_HARNESS to compiled tests/GuestHarness.exe")
class NativePipeTests(unittest.TestCase):
    def test_guest_queue_overflow(self):
        result = subprocess.run([os.environ["GUEST_HARNESS"], "queue"], capture_output=True, timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        messages = list(Frames().feed(result.stdout))
        self.assertEqual(messages[-1]["dropped"], 1)

    def pipe_run(self, disconnect=False):
        name = "sysmon-test-" + uuid.uuid4().hex
        command = [os.environ["GUEST_HARNESS"], name]
        if disconnect:
            command.append("disconnect")
        server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            with tempfile.TemporaryDirectory() as folder:
                args = parser().parse_args(["receive", "--sample", HASH, "--run-id", "test", "--output", folder,
                                           "--pipe", "\\\\.\\pipe\\" + name, "--duration", "0.3",
                                           "--connect-timeout", "3", "--ready-timeout", "3", "--drain-timeout", "3"])
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = receive(args)
                metadata = json.loads((Path(folder) / HASH / "test" / "metadata.json").read_text(encoding="utf-8"))
                document = ET.parse(Path(folder) / HASH / "test" / "events.xml")
            _, errors = server.communicate(timeout=10)
            self.assertEqual(server.returncode, 0, errors)
            return code, metadata, document
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()

    def test_real_windows_pipe_csharp_to_python(self):
        code, meta, document = self.pipe_run()
        self.assertEqual(code, 0, meta)
        self.assertEqual(meta["event_count"], 3)
        self.assertEqual(meta["sample_process_event_sequence"], 2)
        command = document.find("Events/Record/" + NS + "Event/" + NS + "EventData/" + NS + "Data[@Name='CommandLine']")
        self.assertEqual(command.text, '测试 & <escaped> "quoted"')

    def test_real_pipe_disconnect(self):
        code, meta, _ = self.pipe_run(True)
        self.assertEqual(code, 2)
        self.assertEqual(meta["status"], "incomplete")

    def test_controller_and_resume_with_mock_vmrun(self):
        with tempfile.TemporaryDirectory(prefix="sysmon workflow ") as folder:
            name = "sysmon-controller-" + uuid.uuid4().hex
            trigger = str(Path(folder) / "launch.signal")
            operations = Path(folder) / "operations.txt"
            env = dict(os.environ, SYSMON_TEST_TRIGGER=trigger, SYSMON_TEST_OPERATIONS=str(operations))
            # A PowerShell 7 parent may export its module path; let Windows PowerShell 5.1
            # construct its own default module path instead of importing 7.x modules.
            for key in list(env):
                if key.upper() == "PSMODULEPATH":
                    del env[key]
            server = subprocess.Popen([os.environ["GUEST_HARNESS"], name, "gated", trigger],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            powershell = str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
            command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(ROOT / "tests/controller_harness.ps1"), "-HarnessExe", os.environ["GUEST_HARNESS"],
                       "-PythonExe", sys.executable, "-TestDirectory", folder, "-PipeName", "\\\\.\\pipe\\" + name]
            try:
                result = subprocess.run(command, env=env, capture_output=True, timeout=30,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                server.communicate(timeout=5)
                self.assertEqual(server.returncode, 0)
                runs = list((Path(folder) / "logs" / HASH).iterdir())
                self.assertEqual(len(runs), 1)
                meta = json.loads((runs[0] / "metadata.json").read_text(encoding="utf-8"))
                self.assertEqual(meta["status"], "complete")
                self.assertEqual(meta["sample_process_event_sequence"], 2)
                self.assertEqual(operations.read_text().splitlines(), ["revertToSnapshot", "start",
                                 "runProgramInGuest", "runProgramInGuest", "revertToSnapshot"])
                before = operations.read_bytes()
                second = subprocess.run(command, env=env, capture_output=True, timeout=15,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(second.returncode, 0, (second.stdout, second.stderr))
                self.assertIn(b"[SKIP]", second.stdout)
                self.assertEqual(operations.read_bytes(), before)
            finally:
                if server.poll() is None:
                    server.kill()
                    server.communicate()

    def test_guest_probe_failure_is_reported_and_password_redacted(self):
        with tempfile.TemporaryDirectory(prefix="sysmon probe failure ") as folder:
            operations = Path(folder) / "operations.txt"
            env = dict(os.environ, SYSMON_TEST_TRIGGER=str(Path(folder) / "launch.signal"),
                       SYSMON_TEST_OPERATIONS=str(operations), SYSMON_TEST_PROBE_FAILURE="1")
            for key in list(env):
                if key.upper() == "PSMODULEPATH":
                    del env[key]
            powershell = str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
            command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(ROOT / "tests/controller_harness.ps1"), "-HarnessExe", os.environ["GUEST_HARNESS"],
                       "-PythonExe", sys.executable, "-TestDirectory", folder,
                       "-PipeName", r"\\.\pipe\unused-probe-test"]
            result = subprocess.run(command, env=env, capture_output=True, timeout=25,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
            output = result.stdout + result.stderr
            self.assertIn(b"Synthetic guest authentication failure", output)
            self.assertIn(b"Last error:", output)
            self.assertIn(b"[redacted]", output)
            self.assertNotIn(b"test-only", output)
            self.assertEqual(operations.read_text().splitlines()[-1], "revertToSnapshot")

    def test_committed_run_does_not_wait_for_lingering_receiver(self):
        self.controller_linger()

    def test_controller_finds_commit_when_recording_and_final_status_locked(self):
        self.controller_linger(lock_status=True)

    def controller_linger(self, lock_status=False):
        with tempfile.TemporaryDirectory(prefix="sysmon receiver linger ") as folder:
            name = "sysmon-linger-" + uuid.uuid4().hex
            trigger = str(Path(folder) / "launch.signal")
            operations = Path(folder) / "operations.txt"
            env = dict(os.environ, SYSMON_TEST_TRIGGER=trigger, SYSMON_TEST_OPERATIONS=str(operations))
            for key in list(env):
                if key.upper() == "PSMODULEPATH":
                    del env[key]
            project = Path(folder) / "fixture"
            shutil.copytree(ROOT / "host", project / "host", ignore=shutil.ignore_patterns("__pycache__"))
            # Run the real receiver, then keep its process alive for 30 seconds after commit.
            # This reproduces the supervisor defect without running VMware or samples.
            wrapper = "import sys,time\nsys.path.insert(0, " + repr(str(ROOT / "host")) + ")\nfrom receiver import main\ncode=main()\ntime.sleep(30)\nsys.exit(code)\n"
            if lock_status:
                patch = ("import os,json\nfrom pathlib import Path\nreal_replace=os.replace\n"
                         "def replace(source,target):\n"
                         "    if Path(target).name=='status.json' and json.loads(Path(source).read_text())['state'] in ('recording','draining','finalizing','complete'):\n"
                         "        raise PermissionError('synthetic post-launch status lock')\n"
                         "    return real_replace(source,target)\nos.replace=replace\n")
                wrapper = wrapper.replace("code=main()", patch + "code=main()")
            (project / "host/receiver.py").write_text(wrapper, encoding="utf-8")
            server = subprocess.Popen([os.environ["GUEST_HARNESS"], name, "gated", trigger],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            powershell = str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
            command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(ROOT / "tests/controller_harness.ps1"), "-HarnessExe", os.environ["GUEST_HARNESS"],
                       "-PythonExe", sys.executable, "-TestDirectory", folder, "-ControllerRoot", str(project),
                       "-PipeName", "\\\\.\\pipe\\" + name]
            try:
                start = time.monotonic()
                result = subprocess.run(command, env=env, capture_output=True, timeout=20,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertLess(time.monotonic() - start, 20)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertIn(b"[SAVED]", result.stdout)
                self.assertIn(b"[RESET]", result.stdout)
                server.communicate(timeout=5)
                self.assertEqual(server.returncode, 0)
                run = next((Path(folder) / "logs" / HASH).iterdir())
                meta = json.loads((run / "metadata.json").read_text(encoding="utf-8"))
                self.assertEqual(meta["status"], "complete")
                if lock_status:
                    self.assertGreater(meta["status_updates"]["write_failures"], 0)
                self.assertEqual(meta["log_sha256"], file_sha256(run / "events.xml"))
                control = json.loads((run / "controller_result.json").read_text(encoding="utf-8"))
                self.assertTrue(control["result_committed"])
                self.assertTrue(control["receiver_forced_termination"])
                self.assertEqual(operations.read_text().splitlines()[-1], "revertToSnapshot")
            finally:
                if server.poll() is None:
                    server.kill()
                    server.communicate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
