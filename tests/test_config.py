import sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sysmon"))
import build_config as config

class ConfigTests(unittest.TestCase):
    def test_policy_and_pinned_source(self):
        config.validate()

    def reject(self, tag, child=None):
        root = ET.parse(config.TARGET).getroot()
        node = root.find('.//' + tag)
        if child:
            ET.SubElement(node, child, {'condition': 'contains'}).text = 'C:\\samples\\'
        else:
            node.set('onmatch', 'exclude')
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'changed.xml'
            ET.ElementTree(root).write(p, encoding='utf-8')
            with patch.object(config, 'TARGET', p), self.assertRaises(AssertionError):
                config.validate()

    def test_reject_core_exclusion(self):
        self.reject('FileCreate', 'Image')

    def test_reject_network_collection(self):
        self.reject('NetworkConnect')

    def test_reject_changed_registry_scope(self):
        self.reject('RegistryEvent', 'TargetObject')

    def test_reject_module_collection(self):
        self.reject('ImageLoad')

    def test_direct_stream_block_preserved(self):
        before, _ = config.original()
        after = ET.parse(config.TARGET).getroot()
        self.assertEqual(config.shape(before.find('EventFiltering/FileCreateStreamHash')),
                         config.shape(after.find('EventFiltering/FileCreateStreamHash')))

