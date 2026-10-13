import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  readTarEntries, isSafeEntryName, isWhiteoutName, whiteoutTarget,
  decompressIfGzip, TarSafetyError, DEFAULT_LIMITS,
} from '../../src/artifact/safe-tar.js';
import { buildTar, gzipTar } from '../helpers/build-tar-fixture.js';

function entries(tar, limits) {
  return [...readTarEntries(tar, limits)];
}

test('ST/1a: round-trips a simple file entry with exact content', () => {
  const tar = buildTar([{ name: 'hello.txt', content: 'hello world' }]);
  const [e] = entries(tar);
  assert.equal(e.name, 'hello.txt');
  assert.equal(e.size, 11);
  assert.equal(e.data.toString('utf8'), 'hello world');
  assert.equal(e.unsafe, false);
});

test('ST/1b: round-trips a nested path and an empty file', () => {
  const tar = buildTar([{ name: 'a/b/c.txt', content: 'x' }, { name: 'empty.txt', content: '' }]);
  const [e1, e2] = entries(tar);
  assert.equal(e1.name, 'a/b/c.txt');
  assert.equal(e2.name, 'empty.txt');
  assert.equal(e2.size, 0);
  assert.equal(e2.data.length, 0);
});

test('ST/2a: a `..`-segment path is flagged unsafe, never silently normalized or accepted', () => {
  const tar = buildTar([{ name: '../../etc/passwd', content: 'evil' }]);
  const [e] = entries(tar);
  assert.equal(e.unsafe, true);
  assert.equal(e.data, null);
});

test('ST/2b: an absolute path is flagged unsafe', () => {
  assert.equal(isSafeEntryName('/etc/passwd'), false);
  assert.equal(isSafeEntryName('relative/ok.txt'), true);
});

test('ST/2c: a NUL byte or an empty name is flagged unsafe', () => {
  assert.equal(isSafeEntryName('a\0b'), false);
  assert.equal(isSafeEntryName(''), false);
});

test('ST/3a: whiteout entries are identified and resolve to the deleted path', () => {
  const tar = buildTar([{ name: 'secret.txt', whiteout: true }]);
  const [e] = entries(tar);
  assert.equal(e.name, '.wh.secret.txt');
  assert.equal(isWhiteoutName(e.name), true);
  assert.deepEqual(whiteoutTarget(e.name), { opaque: false, path: 'secret.txt' });
});

test('ST/3b: the opaque-directory whiteout marker is distinguished from a single-file deletion', () => {
  assert.deepEqual(whiteoutTarget('some/dir/.wh..wh..opq'), { opaque: true, dir: 'some/dir' });
});

test('ST/4a: a per-entry size over the limit throws TarSafetyError without yielding a partial result', () => {
  const tar = buildTar([{ name: 'big.bin', content: Buffer.alloc(1000) }]);
  assert.throws(() => entries(tar, { ...DEFAULT_LIMITS, maxEntrySize: 10 }), TarSafetyError);
});

test('ST/4b: exceeding the entry-count limit throws', () => {
  const many = Array.from({ length: 50 }, (_, i) => ({ name: `f${i}.txt`, content: 'x' }));
  const tar = buildTar(many);
  assert.throws(() => entries(tar, { ...DEFAULT_LIMITS, maxEntries: 10 }), TarSafetyError);
});

test('ST/4c: exceeding the total-archive-size limit throws', () => {
  const tar = buildTar([{ name: 'a.bin', content: Buffer.alloc(600) }, { name: 'b.bin', content: Buffer.alloc(600) }]);
  assert.throws(() => entries(tar, { ...DEFAULT_LIMITS, maxEntrySize: 10_000, maxTotalSize: 1000 }), TarSafetyError);
});

test('ST/5a: a non-gzip buffer passes through decompressIfGzip unchanged', () => {
  const tar = buildTar([{ name: 'a.txt', content: 'plain' }]);
  const out = decompressIfGzip(tar);
  assert.equal(out, tar);
});

test('ST/5b: a gzip member decompresses to the original tar', () => {
  const gz = gzipTar([{ name: 'a.txt', content: 'zzz' }]);
  const out = decompressIfGzip(gz);
  const [e] = entries(out);
  assert.equal(e.data.toString(), 'zzz');
});

test('ST/5c: a decompression bomb is rejected by the output-size cap, never fully materialized', () => {
  const gz = gzipTar([{ name: 'big.bin', content: Buffer.alloc(200_000, 0) }]);
  assert.throws(() => decompressIfGzip(gz, { ...DEFAULT_LIMITS, maxGunzipOutput: 1000 }), (err) => {
    return err instanceof TarSafetyError && err.code === 'gunzip_too_large';
  });
});

test('ST/5d: a malformed gzip stream is rejected cleanly, not thrown as a raw zlib error', () => {
  const bad = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
  assert.throws(() => decompressIfGzip(bad), TarSafetyError);
});

test('ST/6: GNU longname entries resolve the following entry\'s real name', () => {
  // Build by hand: an 'L' typeflag entry carrying a long name, followed by a
  // regular entry whose header name is a stub — exercising the longname path
  // the writer helper doesn't need for any current fixture.
  const BLOCK = 512;
  function h(name, size, typeflag) {
    const buf = Buffer.alloc(BLOCK);
    Buffer.from(name).copy(buf, 0);
    Buffer.from(size.toString(8).padStart(11, '0') + '\0').copy(buf, 124);
    buf[156] = typeflag.charCodeAt(0);
    Buffer.from('ustar\0').copy(buf, 257);
    return buf;
  }
  const longName = 'this/is/a/very/long/path/name/that/exceeds/the/100/byte/ustar/name/field/limit/deliberately/file.txt';
  const longNameData = Buffer.alloc(Math.ceil(longName.length / BLOCK) * BLOCK);
  Buffer.from(longName).copy(longNameData);
  const content = Buffer.from('payload');
  const contentPadded = Buffer.alloc(BLOCK);
  content.copy(contentPadded);
  const tar = Buffer.concat([
    h('././@LongLink', longName.length, 'L'), longNameData,
    h('stub.txt', content.length, '0'), contentPadded,
    Buffer.alloc(BLOCK * 2),
  ]);
  const [e] = entries(tar);
  assert.equal(e.name, longName);
  assert.equal(e.data.toString(), 'payload');
});

test('ST/7: never throws on an empty buffer, yields nothing', () => {
  assert.deepEqual(entries(Buffer.alloc(0)), []);
});
