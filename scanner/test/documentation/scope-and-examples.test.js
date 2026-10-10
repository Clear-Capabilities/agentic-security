// DOC-001.AC01 and DOC-001.AC02: the scope page lists coverage, prerequisites, adapters, invariant limits and enforced-backend
// capabilities with links to evidence that exists; the examples are runnable locally on synthetic fixtures, and what the page quotes
// is what the commands print. The execution-backed examples exit 3 on a host that cannot run the confinement boundary: that is a
// declared skip (never a pass) and is named as such.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { read, REPO, SCANNER, script, cli, run, blockWith, textBlocks, missingFrom, norm } from './helpers.js';
import { oracleManifest } from '../../src/posture/oracles/registry.js';
import { ORACLE_CLASSES } from '../../src/posture/oracles/oracle.js';
import { INVARIANT_CLASSES } from '../../src/posture/invariants/schema.js';
import { ADAPTER_NAMES } from '../../src/lineage/deployment/ingest.js';
import { platformStatements } from '../../src/capabilities/probes.js';

const SCOPE = read('docs/guides/assurance-scope-and-contracts.md');
const EXAMPLES = read('docs/guides/assurance-examples.md');

/** The rows of the coverage table that name no evidence link (a link to a file or directory in the repository). */
function rowsWithoutEvidence(md) {
  const lines = md.split('\n');
  const i = lines.findIndex((l) => l.startsWith('| Area |'));
  const rows = [];
  for (let j = i + 2; j < lines.length && lines[j].startsWith('|'); j++) rows.push(lines[j]);
  return rows.filter((r) => !/\]\([^)]*(?:scanner|docs|bench|\.\.)[^)]*\)|\]\([a-z-]+\.md\)/.test(r.split('|').slice(-2)[0] ?? '')).map((r) => r.split('|')[1].trim());
}

describe('[DOC-001.AC01] the scope page lists coverage, prerequisites, adapters, invariant limits and enforced-backend capabilities with evidence', () => {
  test('[DOC-001.AC01] it names every oracle class that is registered, and the count matches the manifest', () => {
    const man = oracleManifest();
    assert.equal(man.oracles.length, 8);
    assert.match(SCOPE, /Eight adapters/);
    assert.deepEqual(man.oracles.map((o) => o.class).sort(), [...ORACLE_CLASSES].sort());
    const flat = SCOPE.toLowerCase().replace(/[-\s]+/g, ' ');
    for (const c of ORACLE_CLASSES) assert.ok(flat.includes(c.replace(/-/g, ' ')), `the page does not name the ${c} oracle class`);
  });

  test('[DOC-001.AC01] it lists every oracle prerequisite the manifest declares, and says an unmet one is unsupported, not a pass', () => {
    const ids = new Set(oracleManifest().oracles.flatMap((o) => o.prerequisites.map((p) => p.id)));
    for (const id of ids) assert.ok(SCOPE.includes(`\`${id}\``), `prerequisite ${id} is not documented`);
    assert.match(SCOPE, /`unsupported`/);
    assert.match(SCOPE, /never a pass/);
  });

  test('[DOC-001.AC01] it lists every deployment adapter with the status the evaluation gives it', () => {
    const guide = read('docs/guides/deployment-aware-support.md');
    for (const name of ADAPTER_NAMES) {
      const status = /\| `[a-z-]+` \| validated \|/.test(guide) && new RegExp(`\\| \`${name}\` \\| validated \\|`).test(guide) ? 'validated' : 'not validated';
      const row = new RegExp(`\\| \`${name}\` \\| ([^|]+) \\|`).exec(SCOPE);
      assert.ok(row, `${name} is not in the adapter table`);
      assert.equal(/not validated/.test(row[1]), status === 'not validated', `${name}: the page and the deployment guide disagree`);
    }
  });

  test('[DOC-001.AC01] it names every invariant class and states the invariant limits', () => {
    for (const c of INVARIANT_CLASSES) assert.ok(SCOPE.toLowerCase().includes(c.replace(/-/g, ' ')), `invariant class ${c} is missing`);
    assert.match(SCOPE, /advisory until a named human approves/);
    assert.match(SCOPE, /hard ceiling that rejects rather than clamps/);
    assert.match(SCOPE, /durable state outside an in-memory store/);
  });

  test('[DOC-001.AC01] its enforced-backend statement equals the probe module: Linux unverified, macOS host-proved, Windows none', () => {
    const ps = platformStatements();
    assert.equal(ps.linux.status, 'unverified');
    assert.equal(ps.darwin.status, 'host-proved-not-advertised');
    assert.equal(ps.win32.status, 'unsupported');
    assert.match(SCOPE, /Linux is advertised but `unverified`/);
    assert.match(SCOPE, /macOS is `host-proved-not-advertised`/);
    assert.match(SCOPE, /Windows has no backend/);
    assert.ok(!/Linux[^.\n]*\b(?:is|are) (?:fully )?(?:supported|verified|enforced)\b/.test(SCOPE.replace(/unverified/g, '')), 'the page must not claim Linux support');
  });

  test('[DOC-001.AC01] every row of the coverage table links to evidence, and that evidence exists in the repository', () => {
    assert.deepEqual(rowsWithoutEvidence(SCOPE), []);
    const links = [...SCOPE.matchAll(/\]\((\.\.\/\.\.\/[^)#]+|\.\.\/[^)#]+|[a-z0-9-]+\.md)(?:#[^)]*)?\)/g)].map((m) => m[1]);
    assert.ok(links.length >= 20, `expected many evidence links, found ${links.length}`);
    for (const l of links) assert.ok(fs.existsSync(path.resolve(REPO, 'docs/guides', l)), `${l} does not exist`);
  });

  test('[DOC-001.AC01] a coverage row stripped of its evidence is caught (the check can fail)', () => {
    const stripped = SCOPE.replace(/\[oracle fixtures\]\([^)]*\), \[conformance guide\]\([^)]*\)/, 'none');
    assert.notEqual(stripped, SCOPE);
    assert.deepEqual(rowsWithoutEvidence(stripped), ['Runtime oracles']);
  });

  test('[DOC-001.AC01] it links the two generated pages and the contract sources, and makes the not-claimed statements', () => {
    for (const p of ['assurance-capability-matrix.md', 'mcp-tool-contract.md']) assert.ok(SCOPE.includes(`../reference/${p}`));
    assert.match(SCOPE, /off by default/);
    assert.match(SCOPE, /No real-code accuracy gate has been met/);
    for (const schema of ['verification-record', 'capability-manifest', 'release-assurance-manifest', 'boundary-drift', 'invariant-scenario-export']) assert.ok(SCOPE.includes(`agentic-security/${schema}`));
  });
});

describe('[DOC-001.AC02] the runnable examples use synthetic local fixtures and print what the page quotes', () => {
  const here = (rel) => path.join(SCANNER, rel);
  const skipIfNotRun = (t, r, what) => {
    if (r.status === 3) { t.skip(`SKIPPED, NOT PASSED: ${what} needs the confinement boundary, which this host cannot run (exit 3: nothing was verified)`); return true; }
    return false;
  };

  test('[DOC-001.AC02] every example is a local script that opens no socket and reads no terminal, and says its fixtures are synthetic', () => {
    for (const s of ['patch-replay-example', 'tenant-invariant-example', 'graph-drift-example', 'blocked-capability-example', 'migration-example', 'verification-replay-example']) {
      const src = fs.readFileSync(path.join(REPO, 'scripts', `${s}.mjs`), 'utf8');
      assert.ok(!/node:(?:http|https|net|dgram|readline|tls)\b|\bfetch\(|process\.stdin/.test(src), `${s} must be local and non-interactive`);
    }
    for (const s of ['patch-replay-example', 'tenant-invariant-example', 'graph-drift-example', 'blocked-capability-example', 'migration-example']) {
      assert.match(fs.readFileSync(path.join(REPO, 'scripts', `${s}.mjs`), 'utf8'), /synthetic|SYNTHETIC/i, `${s} does not say its fixtures are synthetic`);
    }
    const pkg = JSON.parse(fs.readFileSync(here('package.json'), 'utf8')).scripts;
    for (const n of ['verification:patch-example', 'example:tenant-invariant', 'example:graph-drift', 'example:blocked-capability', 'example:migration']) assert.ok(pkg[n], `npm run ${n} is not defined`);
  });

  test('[DOC-001.AC02] original/patch replay: the single replay and the verified fix print the quoted lines and exit 0', async (t) => {
    const replay = script('scripts/verification-replay-example.mjs');
    if (skipIfNotRun(t, replay, 'replay')) return;
    assert.equal(replay.status, 0, replay.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'manifest rpl:'), replay.text), []);
    const patch = script('scripts/patch-replay-example.mjs');
    if (skipIfNotRun(t, patch, 'the patch replay')) return;
    assert.equal(patch.status, 0, patch.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'original-positive: passed (oracle outcome confirmed, expected confirmed)'), patch.text), []);
    assert.match(patch.stdout, /result: verified-fix \(declared scenario and cases only\)/);
  });

  test('[DOC-001.AC02] original/patch replay, other direction: a cosmetic edit is not a verified fix, and later steps do not run', async (t) => {
    const r = script('scripts/patch-replay-example.mjs', ['--still-vulnerable']);
    if (skipIfNotRun(t, r, 'the patch replay')) return;
    assert.equal(r.status, 0, r.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'patch sha256:de944a544df0'), r.text), []);
    assert.match(r.stdout, /patched-still-exploitable/);
    assert.match(r.stdout, /functional-regression: not-run/);
    assert.match(r.stdout, /NOT verified-fix/);
  });

  test('[DOC-001.AC02] tenant invariant: the defective app violates the approved contract, the sound one does not', async (t) => {
    const r = script('scripts/tenant-invariant-example.mjs');
    if (skipIfNotRun(t, r, 'the tenant invariant')) return;
    assert.equal(r.status, 0, r.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'invoices-cross-tenant-update [tenant-isolation]'), r.text), []);
    assert.match(r.stdout, /tickets-tenant-scoped \[tenant-isolation\]: 1 bounded scenario\(s\) run, 1 settled, 0 approved violation\(s\)/);
  });

  test('[DOC-001.AC02] the invariants export is refused with the feature off and runs with it on', () => {
    const contract = 'test/fixtures/invariant-benchmark/cases/invoices-cross-tenant-update/contract.json';
    const fixture = 'test/fixtures/invariant-benchmark/cases/invoices-cross-tenant-update';
    const off = cli(['invariants', 'export', '--invariant', contract, '--fixture', fixture], { env: { AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS: '' } });
    assert.equal(off.status, 1, off.text);
    assert.deepEqual(missingFrom(['agentic-security invariants export: disabled: invariant-scenarios is not available: default: off'], off.text), []);
    const on = cli(['invariants', 'export', '--invariant', contract, '--fixture', fixture], { env: { AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS: '1' } });
    assert.equal(on.status, 0, on.text);
    const doc = JSON.parse(on.stdout);
    assert.equal(doc.schema, 'agentic-security/invariant-scenario-export');
    assert.equal(doc.fixture.included, false, 'the fixture source is not exported');
  });

  test('[DOC-001.AC02] graph drift: the boundaries command is off by default (exit 3) and the drift between two revisions is reported', () => {
    const dir = 'test/fixtures/deployment-ablation/cases/k8s-ingress-vs-internal/exploitable';
    const off = cli(['boundaries', '--from', dir], { env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '' } });
    assert.equal(off.status, 3, off.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'agentic-security boundaries: not run (disabled)'), off.text), []);
    const on = cli(['boundaries', '--from', dir], { env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1' } });
    assert.equal(on.status, 0, on.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'Deployment boundaries (environment prod)'), on.text), []);
    const drift = script('scripts/graph-drift-example.mjs');
    assert.equal(drift.status, 0, drift.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'before: 6 node(s)'), drift.text), []);
    const reverse = script('scripts/graph-drift-example.mjs', ['--reverse']);
    assert.equal(reverse.status, 0, reverse.text);
    assert.match(reverse.stdout, /exposure-reduced: service 'shop\/api' is no longer reachable/);
    assert.match(reverse.stdout, /\[material\] changed-privilege/);
  });

  test('[DOC-001.AC02] blocked capability: all three refusals happen and nothing is executed', () => {
    const r = script('scripts/blocked-capability-example.mjs');
    assert.equal(r.status, 0, r.text);
    // line 3 names the host platform and the exact refusal code, which differ off macOS (where it is expected to be `blocked`, unverified)
    const ignore = (l) => process.platform !== 'darwin' && /platform-unsupported|on darwin/.test(l);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, '1. read of ~/.ssh/id_ed25519'), r.text, { ignore }), []);
    assert.match(r.stdout, /executed false/);
    assert.match(r.stdout, /all three were refused; nothing was executed/);
  });

  test('[DOC-001.AC02] migration: no legacy shape reaches a decided outcome, and a missing id is refused', () => {
    const r = script('scripts/migration-example.mjs');
    assert.equal(r.status, 0, r.text);
    assert.deepEqual(missingFrom(blockWith(EXAMPLES, 'a boolean `true`'), r.text), []);
    assert.doesNotMatch(r.stdout, /outcome: (?:confirmed|refuted)/);
  });

  test('[DOC-001.AC02] the npm scripts the page names run the same scripts (one is run end to end through npm)', () => {
    const r = run('npm', ['run', '--silent', 'example:migration']);
    assert.equal(r.status, 0, r.text);
    for (const [n, s] of [['verification:patch-example', 'patch-replay-example'], ['example:tenant-invariant', 'tenant-invariant-example'], ['example:graph-drift', 'graph-drift-example'], ['example:blocked-capability', 'blocked-capability-example'], ['example:migration', 'migration-example']]) {
      assert.match(JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8')).scripts[n], new RegExp(`${s}\\.mjs`));
    }
  });

  test('[DOC-001.AC02] the comparison can fail: a quoted line that was never printed is reported, and masked tokens compare equal', () => {
    const real = 'result: verified-fix (declared scenario and cases only)\nrecord vrec:66a3e16d5a82fa52 in 12 ms\n';
    assert.deepEqual(missingFrom(['result: verified-fix (declared scenario and cases only)'], real), []);
    assert.deepEqual(missingFrom(['result: verified-fix everywhere'], real), ['result: verified-fix everywhere']);
    assert.equal(norm('record vrec:aaaaaaaaaaaaaaaa in 99 ms'), norm('record vrec:66a3e16d5a82fa52 in 12 ms'));
    assert.ok(textBlocks(EXAMPLES).length >= 10, 'the page quotes the outputs it shows');
  });

  test('[DOC-001.AC02] the page marks Linux unverified and shows no Linux output', () => {
    assert.match(EXAMPLES, /\*\*Linux is unverified:\*\*/);
    assert.match(EXAMPLES, /exit 3/);
    assert.ok(!/\blinux\b/i.test(textBlocks(EXAMPLES).flat().join('\n')), 'no output block may be attributed to Linux');
  });
});
