"""Rebuild Swift-based offline rules from pinned XML; Python 3.9+."""
from pathlib import Path
import copy, difflib, hashlib, json
import xml.etree.ElementTree as ET
BASE = Path(__file__).resolve().parent
SOURCE = BASE / 'upstream/swift/sysmonconfig-export.xml'
TARGET = BASE / 'sysmonconfig-export.xml'
VERSION = 'thesis-swift-offline-v2.0.0'
ALL = {'ProcessCreate', 'ProcessTerminate', 'FileCreate', 'FileDeleteDetected'}
DISABLED = {'NetworkConnect', 'DnsQuery', 'FileDelete', 'ClipboardChange',
            'ProcessTampering', 'FileBlockExecutable', 'FileBlockShredding', 'FileExecutableDetected'}
ORDER = ['ProcessCreate', 'NetworkConnect', 'ProcessTerminate', 'FileCreate',
         'DnsQuery', 'FileDelete', 'ClipboardChange', 'ProcessTampering',
         'FileDeleteDetected', 'FileBlockExecutable', 'FileBlockShredding', 'FileExecutableDetected']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def shape(node):
    return [node.tag, dict(node.attrib), (node.text or '').strip(), [shape(c) for c in node]]

def tags(unit):
    return {n.tag for n in unit} if unit.tag == 'RuleGroup' else {unit.tag}

def original():
    info = json.loads((SOURCE.parent / 'source.json').read_text(encoding='utf-8'))
    if digest(SOURCE) != info['xml_sha256']:
        raise ValueError('Pinned upstream SHA256 mismatch')
    return ET.parse(SOURCE).getroot(), info

def build():
    upstream, info = original()
    root = ET.Element('Sysmon', {'schemaversion': '4.90'})
    root.append(ET.Comment(
        f' {VERSION}. Derived from SwiftOnSecurity/sysmon-config; commit {info["commit"]}. '
        'Original license CC BY 4.0. Source and attribution: upstream/swift/. Changes: README.md. '
        'Offline host-behavior research; identical rules for both classes. '
        'No network telemetry, archival or blocking. Not a ransomware classifier. '))
    for tag, value in [('HashAlgorithms', 'SHA256'), ('CheckRevocation', 'False'), ('DnsLookup', 'False')]:
        ET.SubElement(root, tag).text = value
    filtering = ET.SubElement(root, 'EventFiltering')
    # Upstream has both RuleGroups and a direct FileCreateStreamHash block.
    for unit in upstream.find('EventFiltering'):
        if tags(unit) & (ALL | DISABLED):
            if tags(unit) - (ALL | DISABLED):
                raise ValueError('Mixed overridden/retained group needs review')
        else:
            filtering.append(copy.deepcopy(unit))
    for tag in ORDER:
        group = ET.SubElement(filtering, 'RuleGroup', {'groupRelation': 'or'})
        ET.SubElement(group, tag, {'onmatch': 'exclude' if tag in ALL else 'include'})
    ET.indent(root, space='  ')
    TARGET.write_bytes(ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n')
    changes = dict(config_version=VERSION, source=info,
        global_changes={'schemaversion': '4.50 -> 4.90', 'HashAlgorithms': 'md5,sha256,IMPHASH -> SHA256',
                        'CheckRevocation': 'enabled -> False', 'DnsLookup': 'False'},
        all_events=sorted(ALL), disabled_overrides=sorted(DISABLED),
        retained_upstream_disabled=['ImageLoad', 'RawAccessRead', 'ProcessAccess'],
        retained_upstream='All other active predicates, attributes, group relations and direct blocks unchanged')
    (BASE / 'changes.json').write_text(json.dumps(changes, indent=2) + '\n', encoding='utf-8')
    diff = difflib.unified_diff(SOURCE.read_text(encoding='utf-8-sig').splitlines(True),
            TARGET.read_text(encoding='utf-8').splitlines(True),
            fromfile='upstream/swift/sysmonconfig-export.xml', tofile=TARGET.name)
    (BASE / 'swift-to-thesis.patch').write_text(''.join(diff), encoding='utf-8')
    validate()

def validate():
    upstream, _ = original()
    root = ET.parse(TARGET).getroot()
    assert root.get('schemaversion') == '4.90'
    assert root.findtext('HashAlgorithms') == 'SHA256'
    assert root.findtext('CheckRevocation') == root.findtext('DnsLookup') == 'False'
    assert {n.tag for n in root} == {'HashAlgorithms', 'CheckRevocation', 'DnsLookup', 'EventFiltering'}
    overridden = ALL | DISABLED
    assert [shape(g) for g in upstream.find('EventFiltering') if not tags(g) & overridden] == [
        shape(g) for g in root.find('EventFiltering') if not tags(g) & overridden], 'Retained rules changed'
    for tag in overridden:
        nodes = root.findall('.//' + tag)
        assert len(nodes) == 1 and len(nodes[0]) == 0, tag
        assert nodes[0].attrib == {'onmatch': 'exclude' if tag in ALL else 'include'}, tag
    for tag in ('ImageLoad', 'RawAccessRead', 'ProcessAccess'):
        nodes = root.findall('.//' + tag)
        assert len(nodes) == 1 and len(nodes[0]) == 0 and nodes[0].get('onmatch') == 'include', tag
    print('PASS: XML; pinned Swift source; retained predicates/groups; full 1/5/11/26;')
    print('      selective 2; disabled 7/9/10; no network/archival/blocking; SHA256.')
    print('Config SHA256:', digest(TARGET))
    print('NOT verified here: guest Sysmon load, actual events, queue throughput.')

if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['--validate']:
        validate()
    elif not sys.argv[1:]:
        build()
    else:
        raise SystemExit('Usage: python build_config.py [--validate]')

