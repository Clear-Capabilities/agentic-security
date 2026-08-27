// Helper for the C1 regression tests: run `runFullScan` from inside a given
// directory with either NO scanRoot at all, or a scanRoot that does not exist —
// the two ways `resolveProjectRoot` falls back to walking up from the PROCESS
// CWD — and let the caller check whether that directory got littered with a
// provenance lifecycle store.
//
// A child process because the only way to exercise either bug is to control
// `process.cwd()`, and `process.chdir()` inside the test runner would leak into
// every other test in the same file.
//
// argv[2] = directory to chdir into and scan from.
// argv[3] = optional scanRoot to pass. Omitted -> no scanRoot at all. A path
//           that does not exist -> the truthy-but-unresolvable case.
import * as path from 'node:path';

const dir = process.argv[2];
const scanRoot = process.argv[3];
process.chdir(dir);

const { runFullScan } = await import(new URL('../../src/engine.js', import.meta.url).href);

await runFullScan({
  fileContents: { 'server.js': 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n' },
  // `scanRoot` deliberately absent unless argv[3] was given: absent is the shape
  // an in-process harness or an embedder uses, and the shape that corrupted this
  // repo's own checkout.
  ...(scanRoot === undefined ? {} : { scanRoot }),
}, () => {});

process.stdout.write(JSON.stringify({ ok: true, cwd: process.cwd(), dir: path.resolve(dir), scanRoot: scanRoot ?? null }));
