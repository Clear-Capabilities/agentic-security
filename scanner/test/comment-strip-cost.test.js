// PRD F2.5 — "reclaim the comment-stripping cost". MEASURED: already reclaimed.
//
// The item was written when the comment-blindness fix cost 5.7% end-to-end
// (down from 19.7% after two optimizations), and proposed a lexer-level
// integration to remove the separate pass entirely.
//
// Measured on scanner/src/posture (175 files, 1.4 MB) the pass is now **0.26%**
// of scan wall-clock — roughly 32 ms of 12 s — after the memo (`_blankCached`)
// and the bulk-slice rewrite. Against the faster ttff baseline it is still
// under 1%.
//
// So the proposed work would reclaim a quarter of one percent, by rewriting
// comment handling into the lexer — the exact code path whose defects caused
// the comment-leak bugs this project already paid for once (a detector reading
// commented-out code, a string spanning a newline disabling stripping, `//`
// treated as a comment inside Python floor division). That is a poor trade, and
// declining it with a number is a better outcome than doing it.
//
// This test exists so the DECISION is re-derivable. If the share ever climbs
// back toward the figure that motivated the item, the trade changes and the
// gate says so instead of leaving a stale PRD line to be actioned on faith.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { blankComments } from '../src/sast/_comment-strip.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TARGET = path.join(HERE, '..', 'src', 'posture');

function jsFiles(dir) {
  const out = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { if (!/node_modules|\.git/.test(p)) walk(p); }
      else if (/\.(js|mjs)$/.test(e.name)) out.push(p);
    }
  }(dir));
  return out;
}

test('comment stripping sustains a high throughput on real source', () => {
  // Throughput rather than a share-of-scan assertion: a wall-clock ratio
  // against a full scan is noisy on a shared machine and would make this gate
  // a coin flip. Throughput over a fixed corpus is stable and is what actually
  // changed when the memo landed.
  const srcs = jsFiles(TARGET).map((f) => fs.readFileSync(f, 'utf8'));
  assert.ok(srcs.length > 50, 'the corpus must be large enough to time meaningfully');
  const bytes = srcs.reduce((a, c) => a + c.length, 0);

  const t0 = process.hrtime.bigint();
  for (const c of srcs) blankComments(c);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const mbPerSec = (bytes / 1e6) / (ms / 1000);

  // Measured ~100 MB/s. The floor is set well below that so ordinary machine
  // variation does not fail the build — this catches an ORDER-OF-MAGNITUDE
  // regression (a reintroduced quadratic, a lost memo), not a slow afternoon.
  assert.ok(mbPerSec > 20,
    `comment stripping fell to ${mbPerSec.toFixed(1)} MB/s (${ms.toFixed(0)}ms for ${(bytes / 1e6).toFixed(1)}MB) — `
    + 'F2.5 was closed on the basis that this pass is negligible; at this rate that is no longer true');
});

test('the pass is idempotent — a second strip changes nothing', () => {
  // The property that makes the memo safe. If stripping twice differed, the
  // cached view and a fresh one could disagree and detectors would see
  // different source depending on cache state.
  const sample = [
    'const a = 1; // trailing',
    '/* block */ const b = 2;',
    'const s = "// not a comment";',
    'const t = `/* nor this */`;',
    'const re = /\\/\\/[^\\n]*/;',
  ].join('\n');
  const once = blankComments(sample);
  assert.equal(blankComments(once), once, 'blankComments must be idempotent for the memo to be sound');
});

test('line numbers survive stripping — the whole point of blanking over deleting', () => {
  // Findings carry a line. If stripping shifted lines, every finding on a file
  // with a block comment would point at the wrong place, which is worse than
  // not stripping at all.
  const src = 'const a = 1;\n/* two\n   line\n   comment */\nconst b = 2;\n';
  assert.equal(blankComments(src).split('\n').length, src.split('\n').length,
    'stripping must preserve line count');
});
