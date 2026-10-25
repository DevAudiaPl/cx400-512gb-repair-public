#!/usr/bin/env python3
"""Check this public release using files and mocks only. No physical-device I/O."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))

def check_evidence():
    write_root = ROOT / 'evidence/final-write-003327'
    read_root = ROOT / 'evidence/final-verify-065039'
    capacity = 512110190592
    hashes = ['c549af45679d750193ea3ba4fe5d142ba3945cd7306b457b726ace528bbff33e',
              '034550576a4070b029992319998f6dd16eac56bf7f9fb95409d4b2c6ea6cb5b6']
    data = []
    expected = [('cx400-bulk', 0, 512109838336), ('cx400-tail', 512109838336, 352256)]
    for folder, direction, checksum in zip((write_root, read_root), ('write', 'read'), hashes):
        require(digest(folder / 'cx400-full.json') == checksum, 'Original fio proof changed')
        obj = read_json(folder / 'cx400-full.json')
        require(len(obj['jobs']) == 2, 'Missing fio jobs')
        for job, (name, offset, size) in zip(obj['jobs'], expected):
            require(job['jobname'] == name and job['error'] == 0, 'Fio job error')
            require(int(job['job options']['offset']) == offset and int(job['job options']['size']) == size,
                    'Incomplete/overlapping coverage')
            require(job[direction]['io_bytes'] == size, 'Incomplete I/O')
            require(job[direction]['short_ios'] == 0 and job[direction]['drop_ios'] == 0, 'Short/dropped I/O')
            require(job['read' if direction == 'write' else 'write']['io_bytes'] == 0, 'Wrong I/O direction')
            require(job['trim']['io_bytes'] == 0, 'Unexpected TRIM')
        require((folder / 'cx400-full-stderr.txt').stat().st_size == 0, 'Fio stderr')
        data.append(obj)
    require(data[0]['global options']['verify_pattern'] == data[1]['global options']['verify_pattern'], 'Changed pattern')
    require(data[1]['global options']['do_verify'] == '1', 'Read without verification')
    state = read_json(write_root / 'test-state-copy.json')
    require(state == read_json(read_root / 'test-state-copy.json'), 'Historical state changed')
    require(state['write_fio_sha256'] == hashes[0], 'State does not match actual write')
    final = read_json(read_root / 'report.json')[-1]
    require(final['unique_pattern_matched'] and final['bytes'] == capacity, 'Missing data-match result')
    require(final['write_power_cycles'] == 2 and final['read_power_cycles'] == 3, 'Missing cold-cycle proof')
    require(final['kernel_warnings'] == [] and final['smart_counter_changes'] == {}, 'New read errors')
    require(final['write_kernel_warnings'] == state['kernel_warnings'], 'Earlier warnings lost')
    require((read_root / 'kernel-during.txt').stat().st_size == 0, 'New kernel output')
    summary = read_json(ROOT / 'evidence/recovery-summary.json')
    require(summary['command_completions'] == 481 and summary['rejected_commands'] == 0, 'Recovery command summary')
    require(summary['final_event']['result'] == 'PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED', 'Recovery not completed')
    return dict(written_bytes=capacity, cold_verified_bytes=capacity, power_cycles=[2, 3],
                new_read_kernel_errors=0, original_fio_hashes_preserved=True)

def publication_files():
    excluded = {'.git', 'work', '__pycache__', '.pytest_cache'}
    return [p for p in ROOT.rglob('*') if p.is_file() and not (set(p.relative_to(ROOT).parts) & excluded)
            and p.name != 'validation-local.json']

def check_publication():
    # High-confidence publication boundaries; do not print matched private values.
    private = re.compile(r'(?i)(?:/' + r'home/(?!operator(?:/|\b))[^/\s"\\]+|[A-Z]:\\+Users\\+|'
                         r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|'
                         r'gh[pousr]_[A-Za-z0-9]{30,})')
    mac = re.compile(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])')
    files = publication_files()
    for path in files:
        relative = path.relative_to(ROOT)
        require(relative.parts[0] not in ('archive', 'packages'), 'Private archive included')
        require(path.suffix.lower() not in ('.bin', '.exe', '.dll', '.zip', '.rar', '.7z'),
                'Vendor/packed binary included: ' + str(relative))
        text = path.read_text(encoding='utf-8')
        require(not private.search(text) and not mac.search(text), 'Privacy marker in ' + str(relative))
    require(sum(p.stat().st_size for p in files) < 5_000_000, 'Unexpected public payload size')
    return len(files)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-tests', action='store_true')
    parser.add_argument('--recovery-assets', type=Path)
    args = parser.parse_args()
    entries = read_json(ROOT / 'manifests/artifacts.json')
    for entry in entries:
        path = ROOT / entry['path']
        require(path.resolve().is_relative_to(ROOT.resolve()), 'Manifest path escapes repository')
        require(path.is_file() and path.stat().st_size == entry['bytes'], 'Missing/size mismatch: ' + entry['path'])
        require(digest(path) == entry['sha256'], 'SHA mismatch: ' + entry['path'])
    links = 0
    docs = [ROOT / n for n in ('README.md', 'AGENTS.md', 'THIRD_PARTY.md')]
    docs += list((ROOT / 'docs').glob('*.md'))
    for doc in docs:
        for raw in re.findall(r'(?<!!)\[[^\]]*\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if raw.startswith(('https:', 'http:', '#', 'mailto:')):
                continue
            require((doc.parent / unquote(raw.split('#')[0])).exists(), 'Broken link: ' + raw)
            links += 1
    evidence = check_evidence()
    public_count = check_publication()
    runs = []
    if args.offline_tests:
        cases = [('final-test58', ROOT / 'scripts/final-test-v2/offline_test.py', {}),
                 ('fio-regression12', ROOT / 'scripts/final-test-v2/regression_test.py', {}),
                 ('read-v3-guards15', ROOT / 'tests/test_read_guards.py', {'CX400_READ_RUNNER':'cx400-verify-v3.py'}),
                 ('read-v4-guards15', ROOT / 'tests/test_read_guards.py', {'CX400_READ_RUNNER':'cx400-verify-v4.py'})]
        if args.recovery_assets:
            folder = args.recovery_assets.resolve()
            # The original Assets loader checks the pinned manifest and every required byte.
            cases.append(('recovery236', folder / 'offline_test.py', {}))
        for name, script, extra in cases:
            result = subprocess.run([sys.executable, '-B', str(script)], cwd=script.parent,
                                    env=dict(os.environ, **extra, PYTHONDONTWRITEBYTECODE='1'),
                                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
            runs.append(dict(name=name, returncode=result.returncode, output=result.stdout + result.stderr))
            print(name, ':', 'PASS' if result.returncode == 0 else 'FAIL', flush=True)
            require(result.returncode == 0, result.stdout + result.stderr)
    result = dict(validated_on=datetime.date(2026, 10, 25).isoformat(), scope='public-release',
                  artifacts_checked=len(entries), public_files_checked=public_count, document_links_checked=links,
                  evidence=evidence, offline_tests=runs,
                  recovery_assets='checked by recovery236' if args.recovery_assets and args.offline_tests else 'not run; local vendor assets required',
                  hardware_commands_executed=False)
    (ROOT / 'manifests/validation-local.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k != 'offline_tests'}, indent=2))

if __name__ == '__main__':
    main()
