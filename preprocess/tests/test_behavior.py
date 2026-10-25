import copy
from contextlib import redirect_stdout
import io
import gzip
import json
import math
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import behavior_features as b
import dataset
import preprocess as p
import test_preprocess as fixtures
from test_preprocess import SAMPLE, ROOT_GUID, event


class BehaviorTests(unittest.TestCase):
    def test_declared_software_name_preserved_and_review_can_correct_it(self):
        f = self.fixture
        f.write_immediate(software_name='SumatraPDF')
        row, _ = f.analyze()
        self.assertEqual(row['software_name'], 'SumatraPDF')
        row, _ = f.analyze({'software_name': 'Reviewed name'})
        self.assertEqual(row['software_name'], 'Reviewed name')

    def setUp(self):
        self.fixture = fixtures.PreprocessTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def test_identity_and_install_location_do_not_identify_actor(self):
        a = {'event_id': 1, 'event_data': {'Image': 'C:\\samples\\FamilyA\\' + 'a'*64 + '.exe',
              'CommandLine': '"C:\\samples\\FamilyA\\' + 'a'*64 + '.exe"', 'User': 'Alice'}}
        c = copy.deepcopy(a)
        c['event_data'].update(Image='C:\\Program Files\\Editor\\editor.exe',
            CommandLine='"C:\\Program Files\\Editor\\editor.exe"', User='Bob', RuleName='T9999')
        c.update(label='benign', family='Anything', computer='different-host')
        self.assertEqual(b.features(a), b.features(c))

    def test_unknown_extension_does_not_encode_family(self):
        def feature(path):
            return b.features({'event_id': 11, 'event_data': {'TargetFilename': path}})
        self.assertEqual(feature('C:\\Users\\Alice\\Documents\\a.lockbit'),
                         feature('C:\\Users\\Bob\\Documents\\b.conti'))

    def test_shadow_command_semantics(self):
        f = b.features({'event_id': 1, 'event_data': {'Image': 'C:\\Windows\\SysNative\\vssadmin.exe',
             'CommandLine': 'vssadmin.exe delete shadows /all /quiet'}})
        self.assertEqual(f['actor_role'], 'shadow_admin')
        self.assertTrue(f['cmd_shadow_delete'])
        self.assertFalse(f['cmd_backup_delete'])

    def test_exact_duplicate_only_and_causal_counts(self):
        f = self.fixture
        f.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE+'.exe'),
            event(11, 1, ProcessGuid=ROOT_GUID, TargetFilename='C:\\a.txt'),
            event(11, 2, ProcessGuid=ROOT_GUID, TargetFilename='C:\\b.txt')])
        _, es = f.analyze()
        duplicate = copy.deepcopy(es[1])
        duplicate.update(event_uid='duplicate', sequence=99)
        es.append(duplicate)
        b.annotate(es)
        self.assertEqual(duplicate['duplicate_of'], es[1]['event_uid'])
        self.assertFalse(duplicate['model_eligible'])
        self.assertTrue(es[2]['model_eligible'])
        self.assertAlmostEqual(b.features(es[1])['recent_creates'], math.log1p(1))
        self.assertAlmostEqual(b.features(es[2])['recent_unique_files'], math.log1p(2))

    def test_diagnostic_error_quarantines_run(self):
        f = self.fixture
        f.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE+'.exe'), event(255, 2)])
        r, es = f.analyze()
        self.assertFalse(r['training_candidate'])
        self.assertIn('sysmon_error_event_255', r['quality_issues'])
        self.assertIn('diagnostic_event', es[1]['model_exclusion_reasons'])

    def test_uid_independent_of_input_root(self):
        f = self.fixture
        f.write_run()
        r, es = f.analyze()
        r2, es2 = p.analyze(f.directory/'metadata.json', f.directory, f.args, {})
        self.assertEqual(r['run_key'], r2['run_key'])
        self.assertEqual(es[0]['event_uid'], es2[0]['event_uid'])

    def test_unknown_missing_and_pad_distinct(self):
        specs = {'event_id': {'type': 'categorical', 'values': ['1']}}
        missing = b.encode({'event_id': None}, specs)
        unknown = b.encode({'event_id': '999'}, specs)
        known = b.encode({'event_id': '1'}, specs)
        self.assertEqual(missing, [1., 0., 0.])
        self.assertEqual(unknown, [0., 1., 0.])
        self.assertEqual(known, [0., 0., 1.])
        self.assertNotEqual(missing, [0., 0., 0.])

    def test_numeric_real_time_axis_padding_and_weights(self):
        f = self.fixture
        f.write_run([event(ProcessGuid=ROOT_GUID, Image=SAMPLE+'.exe'),
                     event(11, 1), event(26, 2)])
        with redirect_stdout(io.StringIO()):
            p.execute(f.args)
        rows = list(dataset.iter_numeric_examples(f.args.output))
        self.assertEqual(len(rows), 2)
        self.assertEqual([r['mask'] for r in rows], [[True, True], [True, False]])
        self.assertEqual(len(rows[0]['x'][0]), len(b.numeric_columns()))
        self.assertEqual(sum(r['weight'] for r in rows), 1.)
        self.assertTrue(all(v == 0 for v in rows[1]['x'][1]))

    def test_controller_failure_blocks_training(self):
        f = self.fixture
        f.write_run()
        p.write_json(f.directory/'controller_result.json', {'run_id': 'test_run',
            'result_committed': True, 'receiver_exit_code': 1, 'receiver_forced_termination': False})
        r, es = f.analyze()
        self.assertFalse(r['training_candidate'])
        self.assertEqual(len(es), 1)

    def test_process_window_cannot_end_early(self):
        f = self.fixture
        f.write_run(guest_final_stats={'observed': 1, 'sent': 1, 'dropped': 0,
            'watcher_errors': 0, 'queued_events': 0, 'guest_utc': '2026-09-10T00:00:01Z'})
        r, _ = f.analyze()
        self.assertIn('guest_end_before_window_end', r['quality_issues'])

    def test_duplicate_input_root_rejected(self):
        f = self.fixture
        f.write_run()
        manifest = f.base/'input.json'
        p.write_json(manifest, [{'path': str(f.source), 'label': 'ransomware'},
                               {'path': str(f.directory), 'label': 'ransomware'}])
        f.args.input_manifest = manifest
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            p.execute(f.args)

    def test_single_class_split_refused(self):
        from make_splits import make_splits
        f = self.fixture
        f.write_run()
        with redirect_stdout(io.StringIO()):
            p.execute(f.args)
        with self.assertRaisesRegex(ValueError, '3 independent'):
            make_splits(f.args.output, f.base/'splits.csv')

    def test_group_split_success_reproducibility_and_leakage_rejection(self):
        from make_splits import make_splits
        f = self.fixture
        directory = f.base/'mock_dataset'
        directory.mkdir()
        rows = []
        for label in ('benign', 'ransomware'):
            for i in range(3):
                for repeat in range(2):
                    rows.append({'run_key': f'{label}/{i}/{repeat}', 'group_id': f'{label}:{i}',
                        'sample_sha256': f'{label}_sha{i}', 'label': label, 'training_candidate': True})
        with gzip.open(directory/'runs.jsonl.gz', 'wt', encoding='utf-8') as stream:
            for row in rows:
                stream.write(json.dumps(row)+'\n')
        (directory/'SHA256SUMS.txt').write_text(p.sha256(directory/'runs.jsonl.gz')+'  runs.jsonl.gz\n')
        a, c = f.base/'a.csv', f.base/'c.csv'
        make_splits(directory, a, 1)
        make_splits(directory, c, 1)
        self.assertEqual(a.read_bytes(), c.read_bytes())
        assignments = dataset.read_splits(directory, a)
        for row in rows[::2]:
            key = row['run_key']
            self.assertEqual(assignments[key], assignments[key[:-1]+'1'])
        contents = a.read_text(encoding='utf-8-sig').splitlines()
        parts = contents[2].split(',')
        parts[-1] = 'test' if parts[-1] != 'test' else 'train'
        contents[2] = ','.join(parts)
        a.write_text('\n'.join(contents)+'\n', encoding='utf-8-sig')
        with self.assertRaisesRegex(ValueError, 'leaks across'):
            dataset.read_splits(directory, a)


if __name__ == '__main__':
    unittest.main()
