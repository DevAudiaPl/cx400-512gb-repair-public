"""Offline regression against the user's real fio-3.39 output.

No fio process, SMART command, firmware command or block device is opened.
The smoke-flow test uses an explicit Python stub and a temporary regular file.
"""
from pathlib import Path
import copy
import importlib.util
import json
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
FIXTURES=ROOT/'regression-fixtures'
spec=importlib.util.spec_from_file_location('cx400_test_v2',ROOT/'cx400-test.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SIZE=7692288
def fixture(name):return (FIXTURES/name).read_text(encoding='utf-8')
WRITE=fixture('sanity-write.json')
READ=fixture('sanity-verify.json')
BAD=fixture('sanity-wrong-pattern-EXPECTED.json')
STDERR=fixture('sanity-wrong-pattern-EXPECTED-stderr.txt')

class Regression(unittest.TestCase):
    def test_reproduces_original_failure(self):
        with self.assertRaises(json.JSONDecodeError):json.loads(BAD)

    def test_real_write(self):
        obj,prefix=m.parse_fio(WRITE)
        self.assertEqual(prefix,'')
        self.assertEqual(m.check_fio(obj,SIZE,'write'),SIZE)

    def test_real_read(self):
        obj,prefix=m.parse_fio(READ)
        self.assertEqual(prefix,'')
        self.assertEqual(m.check_fio(obj,SIZE,'verify'),SIZE)

    def test_real_expected_mismatch(self):
        obj,prefix=m.parse_fio(BAD)
        self.assertEqual(len(prefix.splitlines()),2)
        self.assertTrue(all(line.startswith('fio: pid=') for line in prefix.splitlines()))
        self.assertEqual([j['error'] for j in obj['jobs']],[84,84])
        m.check_expected_failure(obj,2,STDERR,SIZE)

    def test_real_mismatch_cannot_pass_full_disk_check(self):
        obj,_=m.parse_fio(BAD)
        with self.assertRaises(RuntimeError):m.check_fio(obj,SIZE,'verify')

    def test_malformed_output_rejected(self):
        for raw in ('','fio: err=84\n',WRITE[:-20],WRITE+READ,'unknown failure\n'+WRITE,
                    'fio: error\n{broken JSON','{}','[]','{"fio version":"fio-3.39","jobs":[]}',
                    WRITE+'\nunknown suffix'):
            with self.subTest(raw=raw[:50]):
                with self.assertRaises(RuntimeError):m.parse_fio(raw)

    def test_blank_lines_and_bom(self):
        obj,_=m.parse_fio('\ufeff\n'+READ+'\n  ')
        self.assertEqual(m.check_fio(obj,SIZE,'verify'),SIZE)

    def test_wrong_error_is_not_an_expected_mismatch(self):
        original,_=m.parse_fio(BAD)
        for field,value in (('error',5),('error',22),('jobname','unknown')):
            obj=copy.deepcopy(original);obj['jobs'][0][field]=value
            with self.subTest(field=field,value=value):
                with self.assertRaises(RuntimeError):m.check_expected_failure(obj,2,STDERR,SIZE)

    def test_success_or_unrelated_stderr_not_accepted_as_negative(self):
        obj,_=m.parse_fio(BAD)
        for rc,stderr in ((0,STDERR),(-9,STDERR),(2,''),(2,'fio: Input/output error')):
            with self.subTest(rc=rc,stderr=stderr[:30]):
                with self.assertRaises(RuntimeError):m.check_expected_failure(obj,rc,stderr,SIZE)

    def test_negative_read_must_not_write_or_trim(self):
        original,_=m.parse_fio(BAD)
        for direction in ('write','trim'):
            obj=copy.deepcopy(original);obj['jobs'][0][direction]['io_bytes']=4096
            with self.subTest(direction=direction):
                with self.assertRaises(RuntimeError):m.check_expected_failure(obj,2,STDERR,SIZE)

    def test_full_run_must_not_trim(self):
        obj,_=m.parse_fio(WRITE);obj['jobs'][0]['trim']['io_bytes']=4096
        with self.assertRaises(RuntimeError):m.check_fio(obj,SIZE,'write')

    def test_smoke_completes_with_stubbed_fio_and_real_report_fixtures(self):
        calls=[];events=[]
        original=m.run_fio
        patterns={}
        def stub(folder,device,size,mode,pattern,tag,emit):
            # This stub never starts a process. It checks the wrapper's flow.
            self.assertEqual(device,folder/'fio-sanity-regular-file.bin')
            self.assertTrue(device.is_file());self.assertEqual(size,SIZE)
            patterns[tag]=pattern;calls.append(tag)
            if tag=='sanity-corruption-EXPECTED':
                with device.open('rb') as f:
                    f.seek(100);self.assertEqual(f.read(1),b'\x01')
            output=folder/(tag+'.json')
            output.write_text(WRITE if mode=='write' else READ if tag=='sanity-verify' else BAD,encoding='utf-8')
            (folder/(tag+'-stderr.txt')).write_text('' if tag in ('sanity-write','sanity-verify') else STDERR,encoding='utf-8')
            return (0 if tag in ('sanity-write','sanity-verify') else 2),output
        m.run_fio=stub
        try:
            with tempfile.TemporaryDirectory(prefix='cx400-offline-') as temp:
                folder=Path(temp);m.smoke(folder,lambda **item:events.append(item))
                self.assertFalse((folder/'fio-sanity-regular-file.bin').exists())
                self.assertEqual(len(list(folder.glob('*-parsed.json'))),4)
        finally:m.run_fio=original
        self.assertEqual(calls,['sanity-write','sanity-verify','sanity-wrong-pattern-EXPECTED','sanity-corruption-EXPECTED'])
        self.assertEqual(patterns['sanity-write'],patterns['sanity-verify'])
        self.assertEqual(patterns['sanity-write'],patterns['sanity-corruption-EXPECTED'])
        self.assertNotEqual(patterns['sanity-write'],patterns['sanity-wrong-pattern-EXPECTED'])
        self.assertEqual(events[-1]['stage'],'fio_sanity_pass')
        self.assertEqual([x['test'] for x in events if x['stage']=='fio_expected_mismatch_detected'],['wrong_pattern','bit_flip'])

if __name__=='__main__':unittest.main(verbosity=2)
