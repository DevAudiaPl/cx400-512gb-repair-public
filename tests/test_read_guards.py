"""Offline read-only runner checks against actual supplied fio/SMART JSON.
No main, fio, SMART, vendor tool or block device is invoked.
"""
from pathlib import Path
import copy
import os
import importlib.util
import json
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[1]
BASE=REPO/'scripts'
RUNNER_DIR=BASE/'final-test-v2'
DATA=REPO/'evidence'/'final-write-003327'
spec=importlib.util.spec_from_file_location('cx400_verify_v3',RUNNER_DIR/os.environ.get('CX400_READ_RUNNER','cx400-verify-v3.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
core=m.load_core(RUNNER_DIR)
state=json.loads((DATA/'test-state-copy.json').read_text())
before=json.loads((DATA/'smart-before.json').read_text())
after=json.loads((DATA/'smart-after.json').read_text())

class Checks(unittest.TestCase):
    def test_original_core_accepted(self):
        self.assertEqual(core.SERIAL,m.SERIAL)
        self.assertEqual(core.CAPACITY,512110190592)

    def test_changed_core_rejected_before_import(self):
        with tempfile.TemporaryDirectory(prefix='cx400-readonly-') as temp:
            p=Path(temp);(p/'cx400-test.py').write_text('raise AssertionError("must never import")\n')
            with self.assertRaisesRegex(RuntimeError,'Brak oryginalnego'):m.load_core(p)

    def with_proof(self,root):
        folder=root/m.WRITE_FOLDER;folder.mkdir()
        path=folder/'cx400-full.json';path.write_bytes((DATA/'cx400-full.json').read_bytes())
        return path

    def test_actual_completed_write_proof(self):
        with tempfile.TemporaryDirectory(prefix='cx400-readonly-') as temp:
            root=Path(temp);self.with_proof(root)
            m.check_write_proof(root,state,core)

    def test_state_must_match_actual_write(self):
        with tempfile.TemporaryDirectory(prefix='cx400-readonly-') as temp:
            root=Path(temp);self.with_proof(root)
            for change in ({'status':'WRITE_IN_PROGRESS'},{'write_fio_sha256':'0'*64},
                           {'write_result_folder':'other'},{'pattern':'0'*32}):
                with self.subTest(change=change):
                    with self.assertRaises(RuntimeError):m.check_write_proof(root,dict(state,**change),core)

    def test_original_write_file_required(self):
        with tempfile.TemporaryDirectory(prefix='cx400-readonly-') as temp:
            with self.assertRaises(RuntimeError):m.check_write_proof(Path(temp),state,core)

    def test_changed_proof_rejected(self):
        with tempfile.TemporaryDirectory(prefix='cx400-readonly-') as temp:
            root=Path(temp);path=self.with_proof(root);path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaises(RuntimeError):m.check_write_proof(root,state,core)

    def test_verify_requires_power_cycle(self):
        with self.assertRaises(RuntimeError):core.verify_state(state,after,state['write_boot_id'])
        with self.assertRaises(RuntimeError):core.verify_state(state,after,'different-boot')

    def test_new_boot_and_power_cycle_accepted(self):
        new=copy.deepcopy(after);new['power_cycle_count']=3
        core.verify_state(state,new,'different-boot')

    def test_exact_boot_limit_and_measured_speed(self):
        m.check_environment('ro quiet pci=nomsi libata.force=4:1.5Gbps',after)
        with self.assertRaises(RuntimeError):m.check_environment('pci=nomsi libata.force=4:1.5Gbps',before)

    def test_wrong_or_mistyped_limits_rejected(self):
        for line in ('pci=nomsi libata=4:1.5Gbps','pci=nomsi libata.force=4:1.5 Gbps',
                     'pci=nomsi libata.force=4:3.0Gbps','libata.force=4:1.5Gbps',
                     'pci=nomsi libata.force=4:1.5Gbps libata.force=4:3.0Gbps'):
            with self.subTest(line=line):
                with self.assertRaises(RuntimeError):m.check_environment(line,after)

    def test_readonly_recipe_has_full_coverage(self):
        recipe=core.job_text('/dev/sdb',512110190592,'verify',state['pattern'])
        self.assertIn('rw=read\n',recipe);self.assertNotIn('rw=write',recipe)
        self.assertIn('do_verify=1\n',recipe);self.assertIn('end_fsync=0\n',recipe)
        self.assertIn('size=512109838336\n',recipe);self.assertIn('size=352256\n',recipe)
        self.assertIn('verify_pattern=0x'+state['pattern']+'\n',recipe)
        argv=m.fio_command(Path('/host/private/cx400-full.fio'))
        self.assertEqual(argv[:2],['fio','--readonly'])
        self.assertEqual(argv[-1],str(Path('/host/private/cx400-full.fio')))

    def test_smart_transport_errors_are_visible(self):
        a=m.smart_counters(before);b=m.smart_counters(after)
        self.assertEqual((a['CRC'],b['CRC']),(4,8))
        self.assertEqual((a['SATA_PHY'],b['SATA_PHY']),(4,8))
        self.assertEqual(a['Bad_Blk_Ct_Lat/Erl_raw'],b['Bad_Blk_Ct_Lat/Erl_raw'])
        self.assertEqual(b['Reported_Uncorrectable'],0)

    def test_progress_uses_read_counter_and_512_byte_units(self):
        self.assertEqual(m.read_stat_bytes('1 2 12345 4 5 6 999999 8 9 10 11'),12345*512)

    def test_bad_counter_rejected(self):
        with self.assertRaises(RuntimeError):m.read_stat_bytes('1 2 3')

    def test_existing_target_and_wrong_disk_guards(self):
        tree=json.loads((DATA/'lsblk.json').read_text())
        self.assertEqual(core.select_device(tree)[0]['serial'],m.SERIAL)
        bad=copy.deepcopy(tree)
        bad['blockdevices']=[d for d in bad['blockdevices'] if d.get('serial')!=m.SERIAL]
        with self.assertRaises(RuntimeError):core.select_device(bad)

if __name__=='__main__':unittest.main(verbosity=2)
