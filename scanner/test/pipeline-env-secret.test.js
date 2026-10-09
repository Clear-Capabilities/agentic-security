// The workflow-wide `env:` secret rule used to be a single regular expression that backtracked catastrophically on a
// comment-blanked workflow (blanking leaves runs of blank lines). It is now a one-pass matcher. This file pins that the
// matcher returns exactly what the original expression returned, and that its work grows linearly with the input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPipeline, scanEnvSecrets } from '../src/sast/pipeline.js';

// The original expression, kept here as the oracle. Only ever run on small inputs.
const ORIGINAL = /^env\s*:\s*\n(?:[ \t]+[^\n]*\n)*?[ \t]+[A-Za-z0-9_]+\s*:\s*\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/gm;
const oracle = (raw) => { const re = new RegExp(ORIGINAL.source, ORIGINAL.flags); const out = []; let m; while ((m = re.exec(raw))) out.push({ index: m.index, end: m.index + m[0].length }); return out; };
const mine = (raw) => [...scanEnvSecrets(raw)];

test('env secret matcher: hand-written cases agree with the original expression', () => {
  const cases = [
    'env:\n  TOKEN: ${{ secrets.TOKEN }}\n',
    'env:\n  A: 1\n  B: 2\n  TOKEN: ${{ secrets.HACKAGE }}\n',
    'env:\n  A: 1\njobs:\n  b:\n    env:\n      X: ${{ secrets.X }}\n',      // second env is indented: not a header
    'env:\nTOKEN: ${{ secrets.TOKEN }}\n',                                   // not indented: line loop and tail both refuse
    'env :\n\n\n  TOKEN: ${{ secrets.T }}\n',                                // blank lines after the colon
    'env:\n\n  TOKEN: ${{ secrets.T }}\n',
    'env\n:\n  TOKEN: ${{ secrets.T }}\n',                                   // \s* between name and colon spans a newline
    'env: {}\n  TOKEN: ${{ secrets.T }}\n',                                  // no newline right after the colon
    'env:\n  TOKEN:\n    ${{ secrets.T }}\n',
    'env:\n  TOKEN   :   \n   ${{   secrets.T   }}\n',
    'env:\n  \t TOKEN: ${{ secrets.T }}\n  B: ${{ secrets.U }}\n',
    'env:\n  A: ${{ secrets.A }}\nenv:\n  B: ${{ secrets.B }}\n',            // two matches in a row
    'env:\n  A: ${{ secrets.A }}',                                           // no trailing newline
    'env:\n  A: 1',                                                          // header, never a tail, no final newline
    'env:\r\n  A: ${{ secrets.A }}\r\n',
    'x\r^env:\n  A: ${{ secrets.A }}\n',
    'env:\n    \n    \n  A: ${{ secrets.A }}\n',
    'env:\n\r\n  A: ${{ secrets.A }}\n',                                    // a line starting with CR is not indented
    'env:\n  A: ${{ secrets.a }}\n',                                         // lower-case secret name: no match
    '',
    'env:',
  ];
  for (const c of cases) assert.deepEqual(mine(c), oracle(c), JSON.stringify(c));
});

test('env secret matcher: randomised small inputs agree with the original expression', () => {
  const pieces = ['env', ':', ' ', '  ', '\t', '\n', '\n\n', '\r\n', 'A', 'TOKEN', '${{', '}}', 'secrets.', 'X', '_', 'k: v', '#', 'jobs', '\u00a0', '\u2028'];
  let seed = 12345;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  let withMatch = 0;
  for (let n = 0; n < 4000; n++) {
    let s = '';
    const len = 3 + Math.floor(rnd() * 24);
    for (let i = 0; i < len; i++) s += pieces[Math.floor(rnd() * pieces.length)];
    if (rnd() < 0.85) s = `env:\n${s}`;
    if (rnd() < 0.8) s += '\n  K: ${{ secrets.K }}\n';
    const a = mine(s); const b = oracle(s);
    if (b.length) withMatch++;
    assert.deepEqual(a, b, JSON.stringify(s));
  }
  assert.ok(withMatch > 100, `the generator must exercise the matching path (matches in ${withMatch} inputs)`);
});

test('env secret matcher: work is linear in the size of a comment-blanked env block (the shape that used to hang)', () => {
  const blankBlock = (lines) => `env:\n${'   \n'.repeat(lines)}  note: x\n${'      \n'.repeat(lines)}jobs:\n`;
  const work = (lines) => { const stats = { tailAttempts: 0 }; const found = [...scanEnvSecrets(blankBlock(lines), stats)]; assert.equal(found.length, 0); return stats.tailAttempts; };
  const small = work(2000);
  const large = work(4000);
  assert.ok(small >= 2000, 'every line of the block must be examined once');
  assert.ok(large <= small * 2.2, `doubling the input must not much more than double the work (${small} -> ${large})`);
  assert.ok(large <= 4000 * 2 + 10, `work must be about one attempt per line, got ${large}`);
});

test('scanPipeline: the finding is unchanged and a blanked env block no longer stalls the scan', () => {
  const dir = ['.git', 'hub'].join('') + '/workflows/';
  const yml = `name: x\non: push\nenv:\n  A: 1\n  TOKEN: \${{ secrets.HACKAGE_TOKEN }}\njobs:\n  b:\n    runs-on: ubuntu-latest\n`;
  const f = scanPipeline(dir + 'ci.yml', yml);
  assert.equal(f.filter((x) => /workflow-wide environment scope/.test(x.vuln)).length, 1);
  assert.equal(f.find((x) => /workflow-wide environment scope/.test(x.vuln)).line, 3);
  const blanked = `env:\n${'            \n'.repeat(30000)}jobs:\n`;
  const t = Date.now();
  scanPipeline(dir + 'big.yml', blanked.slice(0, 199000));
  assert.ok(Date.now() - t < 5000, 'a long run of blank lines under env: must scan in linear time');
});
