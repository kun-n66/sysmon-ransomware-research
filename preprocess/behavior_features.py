"""Label-independent, fixed-vocabulary behavior features for offline Sysmon v2.

Identity strings are used transiently for correlation, never as model columns.
No learned vocabulary, target encoding, scaling, or family-specific indicators.
"""
from collections import Counter, deque
from datetime import datetime
import math
import re

MODEL_IDS = (1, 2, 5, 6, 8, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 26)
DIAGNOSTIC_IDS = (4, 16, 255)
ROLES = ('shell', 'script_host', 'shadow_admin', 'backup_admin', 'boot_admin',
         'registry_admin', 'service_admin', 'task_admin', 'loader', 'other')
ROLE_NAMES = {
    'cmd.exe': 'shell', 'powershell.exe': 'shell', 'pwsh.exe': 'shell',
    'wscript.exe': 'script_host', 'cscript.exe': 'script_host', 'mshta.exe': 'script_host',
    'vssadmin.exe': 'shadow_admin', 'wbadmin.exe': 'backup_admin', 'bcdedit.exe': 'boot_admin',
    'reg.exe': 'registry_admin', 'sc.exe': 'service_admin', 'schtasks.exe': 'task_admin',
    'rundll32.exe': 'loader', 'regsvr32.exe': 'loader',
}
FILE_CLASSES = {
    'executable': {'exe', 'dll', 'sys', 'com', 'scr', 'msi'},
    'script': {'ps1', 'bat', 'cmd', 'vbs', 'js', 'wsf', 'hta', 'py'},
    'document': {'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'odt', 'ods', 'rtf'},
    'text': {'txt', 'csv', 'md'}, 'archive': {'zip', '7z', 'rar', 'gz', 'tar'},
    'media': {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'mp3', 'wav', 'mp4', 'avi'},
    'database': {'db', 'sqlite', 'sqlite3', 'kdbx'},
    'config': {'ini', 'xml', 'json', 'yaml', 'yml', 'cfg'},
    'temporary': {'tmp', 'temp', 'bak'}, 'log': {'log', 'etl'}, 'shortcut': {'lnk', 'url'},
}
COMMAND_RULES = {
    'encoded_switch': r'(?:^|\s)-(?:enc|encodedcommand)\b',
    'url': r'https?://',
    'shadow_delete': r'\bdelete\s+shadows\b|\bshadowcopy\b.*\bdelete\b',
    'backup_delete': r'\bdelete\s+(?:catalog|systemstatebackup|backup)\b',
    'recovery_disable': r'\brecoveryenabled\s+(?:no|off)\b|\bignoreallfailures\b',
    'service_stop': r'\b(?:sc(?:\.exe)?|net(?:\.exe)?)\s+(?:stop|delete)\b',
    'registry_edit': r'\breg(?:\.exe)?\s+(?:add|delete|import)\b',
    'scheduled_task': r'\bschtasks(?:\.exe)?\b',
    'file_delete': r'(?:^|\s)(?:del|erase|rmdir|remove-item)(?:\s|$)',
    'recursive_switch': r'(?:^|\s)(?:/s|-recurse)(?:\s|$)',
}


def text(value):
    return None if value is None or str(value).strip() in ('', '-') else str(value).lower().replace('/', '\\')


def role(value):
    v = text(value)
    return None if v is None else ROLE_NAMES.get(v.rsplit('\\', 1)[-1], 'other')


def file_class(value):
    v = text(value)
    if v is None:
        return None
    name = v.rsplit('\\', 1)[-1]
    if '.' not in name:
        return 'none'
    ext = name.rsplit('.', 1)[-1]
    return next((k for k, values in FILE_CLASSES.items() if ext in values), 'other')


def location(value):
    v = text(value)
    if v is None:
        return None
    if v.startswith('\\\\'):
        return 'unc'
    for token, category in (
        ('\\temp\\', 'temp'), ('\\cache\\', 'cache'), ('\\inetcache\\', 'cache'),
        ('\\documents\\', 'documents'), ('\\desktop\\', 'documents'),
        ('\\downloads\\', 'downloads'), ('\\appdata\\', 'appdata'),
        ('\\windows\\', 'windows'), ('\\program files', 'program_files'),
        ('\\programdata\\', 'programdata'), ('\\users\\', 'user_other')):
        if token in v:
            return category
    return 'other'


def registry_area(value):
    v = text(value)
    if v is None:
        return None
    for pattern, category in (
        (r'\\currentversion\\run(?:once)?(?:\\|$)', 'autorun'),
        (r'\\services\\', 'services'), (r'\\(?:policies|policy)\\', 'policy'),
        (r'\\(?:appcompatflags|inventoryapplicationfile)\\', 'inventory'),
        (r'\\(?:classes|fileexts)\\', 'file_association')):
        if re.search(pattern, v):
            return category
    return 'other'


def schema():
    cats = {
        'event_id': [str(x) for x in MODEL_IDS],
        'actor_role': ROLES, 'parent_role': ROLES,
        'file_class': tuple(FILE_CLASSES) + ('none', 'other'),
        'file_location': ('temp', 'cache', 'documents', 'downloads', 'appdata', 'windows',
                          'program_files', 'programdata', 'user_other', 'unc', 'other'),
        'registry_area': ('autorun', 'services', 'policy', 'inventory', 'file_association', 'other'),
        'registry_hive': ('hklm', 'hkcu', 'hku', 'hkcr', 'hkcc', 'other'),
        'operation': ('createkey', 'deletekey', 'deletevalue', 'setvalue', 'renamekey',
                      'renamevalue', 'createpipe', 'connectpipe', 'other'),
        'integrity': ('low', 'medium', 'high', 'system', 'appcontainer', 'untrusted', 'other'),
        'registry_value_kind': ('dword', 'qword', 'binary', 'other'),
    }
    result = {k: {'type': 'categorical', 'values': list(v)} for k, v in cats.items()}
    for k in ('command_missing', 'is_executable', 'same_actor_as_previous', *('cmd_' + k for k in COMMAND_RULES)):
        result[k] = {'type': 'boolean'}
    for k in ('delta_previous', 'delta_actor', 'recent_creates', 'recent_deletes', 'recent_unique_files'):
        result[k] = {'type': 'numeric', 'transform': 'log1p; elapsed clipped to 300s, counts to 10000'}
    return result


def features(event):
    data = event['event_data']
    command = data.get('CommandLine')
    command = None if text(command) is None else command.lower()
    reg = text(data.get('TargetObject'))
    details = text(data.get('Details'))
    hive = reg.split('\\', 1)[0] if reg else None
    op = text(data.get('EventType'))
    integrity = text(data.get('IntegrityLevel'))
    result = {
        'event_id': str(event['event_id']) if event['event_id'] is not None else None,
        'actor_role': role(data.get('Image', data.get('SourceImage'))),
        'parent_role': role(data.get('ParentImage')),
        'file_class': file_class(data.get('TargetFilename', data.get('ImageLoaded'))),
        'file_location': location(data.get('TargetFilename', data.get('ImageLoaded'))),
        'registry_area': registry_area(reg), 'registry_hive': hive,
        'operation': op, 'integrity': integrity,
        'registry_value_kind': None if details is None else next((k for k in ('dword', 'qword', 'binary') if details.startswith(k)), 'other'),
        'command_missing': command is None,
        'is_executable': {'true': True, 'false': False}.get(text(data.get('IsExecutable'))),
    }
    result.update({'cmd_' + k: None if command is None else bool(re.search(pattern, command)) for k, pattern in COMMAND_RULES.items()})
    for key in ('same_actor_as_previous', 'delta_previous', 'delta_actor', 'recent_creates', 'recent_deletes', 'recent_unique_files'):
        result[key] = event.get('behavior_context', {}).get(key)
    for key, spec in schema().items():
        if spec['type'] == 'categorical' and result[key] is not None and result[key] not in spec['values']:
            result[key] = 'other'
    return result


def annotate(events):
    """Keep raw rows; mark exact duplicates/diagnostics; calculate causal context.

    Event XML hashes exclude collector receipt timestamps. Different record IDs,
    times, or target files remain separate events even if feature vectors match.
    """
    seen = {}
    for e in events:
        digest = e.get('event_xml_sha256')
        duplicate = seen.get(digest) if digest else None
        if digest and duplicate is None:
            seen[digest] = e['event_uid']
        e['duplicate_of'] = duplicate
        reasons = []
        if e['phase'] != 'window':
            reasons.append('outside_window')
        if duplicate:
            reasons.append('exact_xml_duplicate')
        if e['event_id'] in DIAGNOSTIC_IDS:
            reasons.append('diagnostic_event')
        elif e['event_id'] not in MODEL_IDS:
            reasons.append('outside_frozen_profile')
        e['model_exclusion_reasons'] = reasons
        e['model_eligible'] = not reasons
    ordered = sorted((e for e in events if e['model_eligible']), key=lambda e: (e['selected_utc'], e['sequence']))
    previous_time = previous_actor = None
    actor_times = {}
    recent = deque()
    files = Counter()
    counts = Counter()
    for e in ordered:
        t = datetime.fromisoformat(e['selected_utc'].replace('Z', '+00:00'))
        d = e['event_data']
        actor = text(d.get('ProcessGuid', d.get('SourceProcessGUID')))
        target = text(d.get('TargetFilename'))
        while recent and (t - recent[0][0]).total_seconds() > 5:
            _, kind, name = recent.popleft()
            counts[kind] -= 1
            if name:
                files[name] -= 1
                if not files[name]:
                    del files[name]
        if e['event_id'] in (11, 26):
            recent.append((t, e['event_id'], target))
            counts[e['event_id']] += 1
            if target:
                files[target] += 1
        def elapsed(old):
            return None if old is None else math.log1p(min(300, max(0, (t-old).total_seconds())))
        e['behavior_context'] = {
            'delta_previous': elapsed(previous_time), 'delta_actor': elapsed(actor_times.get(actor)) if actor else None,
            'same_actor_as_previous': actor == previous_actor if actor and previous_actor else None,
            'recent_creates': math.log1p(min(counts[11], 10000)),
            'recent_deletes': math.log1p(min(counts[26], 10000)),
            'recent_unique_files': math.log1p(min(len(files), 10000)),
        }
        previous_time, previous_actor = t, actor
        if actor:
            actor_times[actor] = t


def numeric_columns(specs=None):
    columns = []
    for key, spec in (specs or schema()).items():
        if spec['type'] == 'categorical':
            columns.extend(key + '=' + value for value in ('<MISSING>', '<UNK>', *spec['values']))
        else:
            columns.extend((key, key + '_missing'))
    return columns


def encode(values, specs=None):
    """Fixed one-hot categories, explicit MISSING/UNK; no fitting or label access."""
    result = []
    for key, spec in (specs or schema()).items():
        value = values[key]
        if spec['type'] == 'categorical':
            options = ['<MISSING>', '<UNK>'] + spec['values']
            token = '<MISSING>' if value is None else value if value in spec['values'] else '<UNK>'
            result.extend(float(token == item) for item in options)
        else:
            result.extend((0.0 if value is None else float(value), float(value is None)))
    return result
