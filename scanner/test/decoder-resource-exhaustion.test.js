// Decoder resource exhaustion: src/sast/decompression-bomb.js (CWE-400), src/sast/decoded-length.js (CWE-770/129/125/190)
// and src/sast/receive-loop-exception.js (CWE-248). Each rule fires on the vulnerable fixture and is silent on the clean one,
// which adds exactly the bound (or the try) the rule asks for.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanDecompressionBomb } from '../src/sast/decompression-bomb.js';
import { scanDecodedLength } from '../src/sast/decoded-length.js';
import { scanReceiveLoopException } from '../src/sast/receive-loop-exception.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (rule, kind, name) => fs.readFileSync(path.join(here, 'fixtures', rule, kind, name), 'utf8');
const run = (fn, rule, kind, name) => fn(`src/${name}`, read(rule, kind, name));
const sig = (fs_) => fs_.map((f) => `${f.line}:${f.cwe}`).sort();

describe('decompression-bomb', () => {
  for (const [name, want] of [
    ['archive.php', ['4:CWE-400']],
    ['unpack.js', ['10:CWE-400', '4:CWE-400']],
    ['thumbs.go', ['10:CWE-400']],
    ['inflate.rb', ['5:CWE-400']],
  ]) {
    test(`${name}: vulnerable fires, clean is silent`, () => {
      assert.deepEqual(sig(run(scanDecompressionBomb, 'decompression-bomb', 'vulnerable', name)), want);
      assert.deepEqual(run(scanDecompressionBomb, 'decompression-bomb', 'clean', name), []);
    });
  }

  test('a forwarding data handler and a literal argument are not sinks', () => {
    const fwd = "const zlib = require('zlib');\nconst z = zlib.createInflate();\nz.on('data', (c) => out.push(c));\n";
    assert.deepEqual(scanDecompressionBomb('a.js', fwd), []);
    assert.deepEqual(scanDecompressionBomb('a.php', "<?php\n$x = gzdecode('abc');\n"), []);
  });

  test('a DecompressionStream drained whole fires', () => {
    const code = "async function f(res) {\n  return new Response(res.body.pipeThrough(new DecompressionStream('gzip'))).text();\n}\n";
    assert.equal(scanDecompressionBomb('a.ts', code).length, 1);
  });

  test('test files and other languages are skipped', () => {
    assert.deepEqual(scanDecompressionBomb('test/archive.php', read('decompression-bomb', 'vulnerable', 'archive.php')), []);
    assert.deepEqual(scanDecompressionBomb('a.py', 'import zlib\nzlib.decompress(x)\n'), []);
  });
});

describe('decoded-length', () => {
  test('Go: decoded length sizes make; 32-bit length sum used as a slice bound', () => {
    assert.deepEqual(sig(run(scanDecodedLength, 'decoded-length', 'vulnerable', 'frame.go')), ['10:CWE-770', '21:CWE-129']);
    assert.deepEqual(run(scanDecodedLength, 'decoded-length', 'clean', 'frame.go'), []);
  });

  test('C#: decoded count drives a loop over the same buffer', () => {
    assert.deepEqual(sig(run(scanDecodedLength, 'decoded-length', 'vulnerable', 'Record.cs')), ['10:CWE-125']);
    assert.deepEqual(run(scanDecodedLength, 'decoded-length', 'clean', 'Record.cs'), []);
  });

  test('Java: 1 << n in an int with a guard admitting 31; range check adding two ints', () => {
    assert.deepEqual(sig(run(scanDecodedLength, 'decoded-length', 'vulnerable', 'Work.java')), ['13:CWE-129', '6:CWE-190']);
    assert.deepEqual(run(scanDecodedLength, 'decoded-length', 'clean', 'Work.java'), []);
  });

  test('a shift whose guard caps the exponent at 30 is silent', () => {
    const code = 'class A {\n  int f(int n) {\n    if (n > 30) throw new IllegalArgumentException();\n    int r = 1 << n;\n    return r;\n  }\n}\n';
    assert.deepEqual(scanDecodedLength('A.java', code), []);
  });

  test('a random-number call is not a decoded length', () => {
    const code = 'package p\n\nfunc f() []byte {\n\tn, err := rand.Uint32()\n\t_ = err\n\treturn make([]byte, n)\n}\n';
    assert.deepEqual(scanDecodedLength('p.go', code), []);
  });
});

describe('receive-loop-exception', () => {
  test('handler call in a receive loop with the only catch outside the loop', () => {
    assert.deepEqual(sig(run(scanReceiveLoopException, 'receive-loop-exception', 'vulnerable', 'Relay.cs')), ['23:CWE-248']);
    assert.deepEqual(run(scanReceiveLoopException, 'receive-loop-exception', 'clean', 'Relay.cs'), []);
  });

  test('fire-and-forget dispatch and loops without a receive are silent', () => {
    const code = 'class A {\n  async Task Run() {\n    while (_on)\n    {\n      var c = await _l.AcceptTcpClientAsync();\n      _ = HandleClientAsync(c);\n    }\n  }\n}\n';
    assert.deepEqual(scanReceiveLoopException('A.cs', code), []);
  });
});
