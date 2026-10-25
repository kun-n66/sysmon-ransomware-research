"""Versioned, label-independent registry scope used by the XML builder and replay.

Replay estimates retention of ALREADY captured events; it cannot simulate the
Sysmon driver, new events, queue throughput, or recover previously lost events.
"""

# Apply these locations to all programs, including benign and Windows programs.
TARGET_RULES = [
    ("contains", "\\CurrentVersion\\Run"),
    ("contains", "\\CurrentVersion\\Policies"),
    ("contains", "\\CurrentVersion\\Winlogon"),
    ("contains", "\\CurrentVersion\\Image File Execution Options"),
    ("contains", "\\CurrentVersion\\SilentProcessExit"),
    ("contains", "\\Windows NT\\CurrentVersion\\Windows"),
    ("contains", "\\CurrentVersion\\Schedule\\TaskCache"),
    ("contains", "\\CurrentVersion\\Explorer\\Shell Folders"),
    ("contains", "\\CurrentVersion\\Explorer\\User Shell Folders"),
    ("contains", "\\CurrentVersion\\Explorer\\FileExts"),
    ("contains", "\\CurrentControlSet\\Services"),
    ("contains", "\\CurrentControlSet\\Control\\SafeBoot"),
    ("contains", "\\CurrentControlSet\\Control\\Lsa"),
    ("contains", "\\CurrentControlSet\\Control\\Session Manager"),
    ("contains", "\\CurrentControlSet\\Control\\Terminal Server"),
    ("contains", "\\Software\\Policies"),
    ("contains", "\\Microsoft\\Windows Defender"),
    ("contains", "\\Microsoft\\Security Center"),
    ("contains", "\\Microsoft\\SystemCertificates"),
    ("contains", "\\Microsoft\\EnterpriseCertificates"),
    ("contains", "\\CurrentVersion\\WinTrust"),
    ("contains", "\\Software\\Classes"),
    ("begin with", "HKCR\\"),
    ("contains", "_Classes\\"),  # HKU\SID_Classes is a per-user classes hive.
    ("contains", "\\Software\\RegisteredApplications"),
    ("contains", "\\Group Policy\\Scripts"),
    ("contains", "\\Windows\\System\\Scripts"),
]

# Preserve low-volume rename operations even outside the selected locations.
RENAME_TYPES = ("RenameKey", "RenameValue")

# Do not exclude a name such as '*sysmon*', all SYSTEM activity, or all events
# from these images. Only the observed self-generated CreateKey cache churn.
SELF_IMAGES = ("C:\\Windows\\Sysmon64.exe", "C:\\Windows\\Sysmon.exe")
SELF_CREATE_SCOPES = (
    "\\SystemCertificates\\Disallowed",
    "\\EnterpriseCertificates\\Disallowed",
    "\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing",
)

# Exact observed VMware Tools background key creation. Do not exclude writes to
# this key's values, its child keys, other event types, or other processes.
VMTOOLS_IMAGE = r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
VMTOOLS_CREATE_TARGET = r"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"


def matches(condition, value, pattern):
    value, pattern = value.casefold(), pattern.casefold()
    if condition == "contains":
        return pattern in value
    if condition == "begin with":
        return value.startswith(pattern)
    raise ValueError("Unsupported registry policy condition: " + condition)


def keep_registry(fields):
    target = fields.get("TargetObject", "")
    event_type = fields.get("EventType", "").casefold()
    image = fields.get("Image", "").casefold()
    if (event_type == "createkey" and image == VMTOOLS_IMAGE.casefold()
            and target.casefold() == VMTOOLS_CREATE_TARGET.casefold()):
        return False
    if (event_type == "createkey" and image in {x.casefold() for x in SELF_IMAGES}
            and any(x.casefold() in target.casefold() for x in SELF_CREATE_SCOPES)):
        return False
    return (event_type in {x.casefold() for x in RENAME_TYPES}
            or any(matches(condition, target, pattern) for condition, pattern in TARGET_RULES))
