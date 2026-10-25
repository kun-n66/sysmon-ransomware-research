"""Append original Sysmon XML; finalize an XML document and its independent digest."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_XML_BYTES = 4 * 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sample_hash(value):
    # Accept a bare hash, HASH.exe, or its path. No file is opened or executed.
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", name):
        raise ValueError("Sample name must be exactly 64 hexadecimal SHA-256 characters, optionally .exe.")
    return name.lower()


def atomic_json(path, data, replace_attempts=4):
    """Publish JSON atomically; bound retries to Windows access/sharing conflicts.

    Critical metadata callers propagate every terminal failure. Progress callers
    use one attempt so a locked progress file cannot stall the receive loop.
    """
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    for attempt in range(replace_attempts):
        try:
            os.replace(temporary, path)
            return
        except OSError as error:
            if getattr(error, "winerror", None) not in (5, 32, 33) or attempt + 1 == replace_attempts:
                raise
            time.sleep(0.025 * (2 ** attempt))


def parse_event(xml):
    if not isinstance(xml, str) or len(xml.encode("utf-8")) > MAX_XML_BYTES:
        raise ValueError("Invalid/oversized XML event.")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)|<\?xml", xml, re.IGNORECASE):
        raise ValueError("XML declarations and DTD/entity declarations are not allowed in event fragments.")
    root = ET.fromstring(xml)
    if root.tag != NS + "Event":
        raise ValueError("Expected Windows Event XML namespace/root.")
    system = root.find(NS + "System")
    if system is None:
        raise ValueError("Missing Event/System.")
    provider = system.find(NS + "Provider")
    if provider is None or provider.get("Name") != "Microsoft-Windows-Sysmon":
        raise ValueError("Unexpected event provider.")
    data_node = root.find(NS + "EventData")
    data = {} if data_node is None else {node.get("Name"): node.text or "" for node in data_node.findall(NS + "Data")}
    stamp = system.find(NS + "TimeCreated")
    return {
        "event_id": system.findtext(NS + "EventID"),
        "record_id": system.findtext(NS + "EventRecordID"),
        "event_utc": data.get("UtcTime") or (stamp.get("SystemTime") if stamp is not None else None),
        "image": data.get("Image", ""),
        "process_guid": data.get("ProcessGuid"),
    }


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class XmlStore:
    def __init__(self, output, hash_value, run_id, metadata):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise ValueError("run_id must contain 1..80 ASCII letters/digits/underscores/hyphens.")
        self.directory = Path(output).resolve() / sample_hash(hash_value) / run_id
        self.directory.mkdir(parents=True, exist_ok=False)  # Never overwrite an earlier experiment.
        self.metadata = dict(metadata)
        self.metadata.update(schema_version=1, run_id=run_id, sample_sha256=hash_value,
                             sample_sha256_source="filename_not_content_verified", created_utc=utc_now(),
                             status="connecting", event_count=0)
        atomic_json(self.directory / "metadata.json", self.metadata)
        (self.directory / "sample.sha256").write_text(hash_value + "  " + hash_value + ".exe\n", encoding="ascii")
        self.part = self.directory / "events.xml.part"
        self.stream = self.part.open("xb", buffering=256 * 1024)
        header = '<?xml version="1.0" encoding="utf-8"?>\n<SysmonExperiment SchemaVersion="1" RunId={} SampleSHA256={}>\n<Events>\n'.format(quoteattr(run_id), quoteattr(hash_value))
        self.stream.write(header.encode("utf-8"))
        self.count = 0
        self.last_flush = time.monotonic()
        self.last_sync = self.last_flush
        self.closed = False
        self.flush(force=True)

    def append(self, seq, xml, received_utc):
        # parse_event must already have validated this raw fragment. Do not reserialize it.
        record = '<Record Sequence="{}" ReceivedUtc={}>\n{}\n</Record>\n'.format(seq, quoteattr(received_utc), xml)
        self.stream.write(record.encode("utf-8"))
        self.count += 1
        self.flush()

    def flush(self, force=False):
        current = time.monotonic()
        if force or current - self.last_flush >= 0.25:
            self.stream.flush()
            self.last_flush = current
        if force or current - self.last_sync >= 1:
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.last_sync = current

    def finish(self, status, details):
        if self.closed:
            return
        self.stream.write(b"</Events>\n</SysmonExperiment>\n")
        self.flush(force=True)
        self.stream.close()
        self.closed = True
        final = self.directory / "events.xml"
        os.replace(self.part, final)
        digest = file_sha256(final)
        (self.directory / "events.xml.sha256").write_text(digest + "  events.xml\n", encoding="ascii")
        self.metadata.update(details)
        self.metadata.update(status=status, event_count=self.count, finished_utc=utc_now(),
                             log_sha256=digest, log_file="events.xml")
        # Metadata status is the final commit marker, written only after XML and digest exist.
        atomic_json(self.directory / "metadata.json", self.metadata)


def recover(directory):
    """Recover complete Record fragments after a killed receiver; always mark incomplete."""
    directory = Path(directory).resolve()
    metadata_path = directory / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("status") == "complete":
        raise ValueError("Refusing to alter a completed run.")
    part = directory / "events.xml.part"
    final = directory / "events.xml"
    if final.exists():
        if part.exists():
            raise ValueError("Both XML and .part exist; inspect manually.")
        count = sum(1 for _, item in ET.iterparse(final, events=("end",)) if item.tag == "Record")
    else:
        # Streaming copy through the last complete Record; avoid loading a large run into RAM.
        recovery = directory / "events.recovering"
        if recovery.exists():
            raise ValueError("events.recovering already exists; inspect the previous recovery attempt.")
        last_good = 0
        with part.open("rb") as source, recovery.open("xb") as target:
            for line in source:
                target.write(line)
                if line == b"<Events>\n" or line == b"</Record>\n":
                    last_good = target.tell()
            if not last_good:
                raise ValueError("No valid XML header found.")
            target.truncate(last_good)
            target.seek(last_good)
            target.write(b"</Events>\n</SysmonExperiment>\n")
            target.flush()
            os.fsync(target.fileno())
        count = 0
        for _, item in ET.iterparse(recovery, events=("end",)):
            if item.tag == "Record":
                count += 1
                item.clear()
        os.replace(recovery, final)
        # Retain original .part as crash evidence without changing its bytes.
        os.replace(part, directory / "events.interrupted.part")
    digest = file_sha256(final)
    (directory / "events.xml.sha256").write_text(digest + "  events.xml\n", encoding="ascii")
    metadata.update(status="incomplete", event_count=count, log_file="events.xml", log_sha256=digest,
                    recovered_utc=utc_now(), recovery_reason="receiver_interrupted")
    atomic_json(metadata_path, metadata)
    return final
