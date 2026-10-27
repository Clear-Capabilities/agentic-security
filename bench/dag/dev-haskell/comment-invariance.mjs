// Comment invariance on a REAL project: scans the project three ways (as written, comments blanked, comments replaced by lies) in temp copies
// and reports any finding that appears, disappears or changes. A non-empty report is an engine bug.
// usage: node bench/dag/dev-haskell/comment-invariance.mjs <project id in .cache>
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';
import { stripComments, lieAboutComments } from '../../../scanner/test/helpers/haskell-comments.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const id = process.argv[2];
const src = path.join(HERE, '.cache', id);
await disableStateWrites();
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;
const { runScan } = await import('../../../scanner/src/runScan.js');

function copyWith(map) {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), `cmt-${id}-`));
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.git' || e.name === 'dist-newstyle') continue;
      const p = path.join(d, e.name); const r = path.join(rel, e.name);
      if (e.isDirectory()) { fs.mkdirSync(path.join(dest, r), { recursive: true }); walk(p, r); }
      else {
        const text = fs.readFileSync(p, 'utf8');
        fs.writeFileSync(path.join(dest, r), /\.hs$/.test(e.name) ? map(text) : text);
      }
    }
  };
  walk(src, '');
  return dest;
}
async function findingsOf(map) {
  const dir = copyWith(map);
  try {
    const { scan } = await runScan(dir);
    return new Set(scan.findings.filter((f) => /\.hs$/.test(f.file || '')).map((f) => [f.file, f.line, f.parser, f.rule || '', f.cwe || '', f.vuln || '', f.severity, f.trustBoundary ? f.trustBoundary.verdict : '', f.reachability ? `${f.reachability.status}/${f.reachability.holeReason || ''}` : '', f.originalSeverity || ''].join('|')));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const base = await findingsOf((t) => t);
let bad = 0;
for (const [name, map] of [['blanked', stripComments], ['says safe', (t) => lieAboutComments(t, 'safe, sanitized')], ['says vulnerable', (t) => lieAboutComments(t, 'vulnerable')]]) {
  const got = await findingsOf(map);
  const gone = [...base].filter((x) => !got.has(x)); const added = [...got].filter((x) => !base.has(x));
  console.log(`${id} [${name}]: ${base.size} findings as written; ${gone.length} disappeared, ${added.length} appeared`);
  for (const x of gone.slice(0, 5)) console.log(`   - ${x}`);
  for (const x of added.slice(0, 5)) console.log(`   + ${x}`);
  bad += gone.length + added.length;
}
console.log(bad === 0 ? `${id}: INVARIANT` : `${id}: VARIES (${bad})`);
process.exit(bad === 0 ? 0 : 1);
