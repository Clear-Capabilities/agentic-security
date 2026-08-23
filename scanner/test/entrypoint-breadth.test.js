// PRD F2.3 — entry-point breadth: SDK / network-response sources.
//
// Only two network-response sources existed, both C++ (`recv`, `recvfrom`), so
// a response body from an external service was TRUSTED input everywhere else.
// It is not. The upstream may be compromised, attacker-influenced (the far end
// of an SSRF), or simply a third party whose output this code renders, executes
// or shells out with. It is the same trust boundary as an inbound request —
// the direction is reversed, not the trust.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CATALOG } from '../src/dataflow/catalog.js';

const networkSources = () => CATALOG.filter((e) => e.kind === 'source' && e.provenance === 'network');

test('network responses are modelled beyond C++ sockets', () => {
  const langs = new Set(networkSources().map((e) => e.language));
  assert.ok(langs.has('js'), 'fetch/axios responses were unmodelled');
  assert.ok(langs.has('py'), 'requests/urllib responses were unmodelled');
  assert.ok(langs.has('cpp'), 'existing socket coverage must be retained');
});

test('the network provenance stays DISTINCT from http-body', () => {
  // A team that genuinely trusts its own internal API needs to filter on this.
  // Folding network responses into http-body removes the one fact that makes
  // these findings triageable, and would silently reclassify every existing
  // finding's origin.
  for (const e of networkSources()) {
    assert.equal(e.provenance, 'network');
    assert.notEqual(e.provenance, 'http-body');
  }
});

test('every network source carries a renderable label', () => {
  for (const e of networkSources()) {
    assert.ok(typeof e.label === 'string' && e.label.length > 3, `${e.id} needs a label a report can show`);
  }
});

test('source ids are unique across the whole catalog', () => {
  // A duplicate id silently shadows one of the two entries, and the shadowed
  // source stops matching with nothing failing.
  const ids = CATALOG.filter((e) => e.kind === 'source').map((e) => e.id);
  const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
  assert.deepEqual([...new Set(dupes)], [], 'duplicate source ids');
});

test('a fetch response reaching a shell sink is taint-tracked', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');

  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'netsrc-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{"name":"n","version":"1.0.0"}');
    fs.writeFileSync(path.join(d, 'sync.js'), [
      "const { exec } = require('child_process');",
      'async function sync(url) {',
      '  const response = await fetch(url);',
      '  const body = await response.text();',   // network source
      '  exec(`process ${body}`, () => {});',     // ...into a shell sink
      '}',
      'module.exports = sync;',
    ].join('\n'));
    const { runScan } = await import('../src/runScan.js');
    const { scan } = await runScan(d);
    const cmdi = (scan.findings || []).filter((f) => String(f.cwe) === 'CWE-78');
    assert.ok(cmdi.length > 0, 'an upstream response reaching exec() must be reported');
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
});
