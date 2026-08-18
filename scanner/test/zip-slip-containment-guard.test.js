// FIX-DISCRIMINATION: a patched _extract_member + containment check is the
// canonical CVE-2007-4559 mitigation, not just filter="data".
//
// From GHSA-f42x-p2mx-hm8r (brightio/penelope). The upstream fix wraps
// extraction so every member's destination is checked before it is written:
//
//     def safe_tar_extractall(tar, dest):
//         dest_real = os.path.realpath(dest)
//         orig_extract_member = tar._extract_member
//         def guarded(tarinfo, targetpath, *args, **kwargs):
//             if not _is_within_directory(dest_real, targetpath):
//                 return                      # refuse, don't write
//             orig_extract_member(tarinfo, targetpath, *args, **kwargs)
//         tar._extract_member = guarded
//         tar.extractall(dest)                <-- the rule fired HERE
//
// zip-slip.js recognised only `filter="data"` / `tarfile.data_filter`, so the
// finding moved from the vulnerable call to the inside of the guard function
// and survived its own fix. filter= requires Python 3.12; the interception
// form is what codebases supporting older Pythons actually ship, which is why
// it needs to be recognised rather than treated as an exotic case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanZipSlip } from '../src/sast/zip-slip.js';

const zs = (src) => scanZipSlip('penelope.py', src).filter(f => f.parser === 'ZIP-SLIP');

const GUARDED = [
  'import tarfile',
  'import os',
  '',
  'def _is_within_directory(directory, target):',
  '    target = os.path.realpath(target)',
  '    return os.path.commonpath([directory]) == os.path.commonpath([directory, target])',
  '',
  'def safe_tar_extractall(tar, dest):',
  '    dest_real = os.path.realpath(dest)',
  '    orig_extract_member = tar._extract_member',
  '',
  '    def guarded(tarinfo, targetpath, *args, **kwargs):',
  '        if not _is_within_directory(dest_real, targetpath):',
  '            return',
  '        orig_extract_member(tarinfo, targetpath, *args, **kwargs)',
  '',
  '    tar._extract_member = guarded',
  '    tar.extractall(dest)',
].join('\n');

const UNGUARDED = [
  'import tarfile',
  '',
  'def download(tar, local_download_folder):',
  '    tar.extractall(local_download_folder)',
].join('\n');

test('REAL CODE: the vulnerable bare extractall is still reported', () => {
  assert.equal(zs(UNGUARDED).length, 1);
});

test('REAL CODE: the interception guard silences it (fix-discrimination)', () => {
  assert.deepEqual(zs(GUARDED), [],
    'every member passes a containment check before being written');
});

test('REFUSES: patching _extract_member WITHOUT a containment check is not a guard', () => {
  // The pre/ revision did exactly this — it patched _extract_member only to
  // add a write bit (args[0].mode |= 0o200), with no path validation at all.
  // Recognising the patch alone would silence the vulnerable revision.
  const modeOnly = [
    'import tarfile',
    '',
    'def download(tar, dest):',
    '    def add_w(func):',
    '        def inner(*args, **kwargs):',
    '            args[0].mode |= 0o200',
    '            func(*args, **kwargs)',
    '        return inner',
    '    tar._extract_member = add_w(tar._extract_member)',
    '    tar.extractall(dest)',
  ].join('\n');
  assert.equal(zs(modeOnly).length, 1, 'no containment check — still vulnerable');
});

test('filter="data" is still recognised', () => {
  assert.deepEqual(zs('import tarfile\ntar.extractall(dest, filter="data")\n'), []);
});
