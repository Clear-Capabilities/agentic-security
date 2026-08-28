// M3 §3.4: providers must make ZERO network calls when unconfigured. Spy on
// global.fetch, matching llm-validator-default-on.test.js's existing
// precedent (scanner/test/llm-validator-default-on.test.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolveProviderConfig } from '../../src/posture/provenance/providers/config.js';
import * as github from '../../src/posture/provenance/providers/github.js';
import * as gitlab from '../../src/posture/provenance/providers/gitlab.js';
import { annotateGitProvenance } from '../../src/posture/provenance/coordinator.js';
import { runFullScan } from '../../src/engine.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

function withEnv(vars, fn) {
  const prior = {};
  for (const k of Object.keys(vars)) prior[k] = process.env[k];
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return Promise.resolve(fn()).finally(() => {
    for (const [k, v] of Object.entries(prior)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });
}

test('resolveProviderConfig: returns null with no env var and no config file present', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  try {
    assert.equal(resolveProviderConfig(tmp, 'github'), null);
    assert.equal(resolveProviderConfig(tmp, 'gitlab'), null);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('resolveProviderConfig: env var wins, no file needed', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: 'ghp_test123' }, () => {
      const cfg = resolveProviderConfig(tmp, 'github');
      assert.equal(cfg.token, 'ghp_test123');
    });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('github.fetchPRMetadata / fetchCodeowners: unconfigured means zero network calls', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: undefined }, async () => {
      const cfg = resolveProviderConfig(tmp, 'github');
      const pr = await github.fetchPRMetadata(tmp, 'abc123', 'https://github.com/owner/repo.git', cfg);
      const owners = await github.fetchCodeowners(tmp, 'https://github.com/owner/repo.git', cfg);
      assert.equal(pr, null);
      assert.equal(owners, null);
      assert.equal(fetchCalled, false, 'no fetch should be attempted without configuration');
    });
  } finally {
    global.fetch = priorFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('gitlab.fetchPRMetadata / fetchCodeowners: unconfigured means zero network calls', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-provider-'));
  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
  try {
    await withEnv({ AGENTIC_SECURITY_GITLAB_TOKEN: undefined }, async () => {
      const cfg = resolveProviderConfig(tmp, 'gitlab');
      const pr = await gitlab.fetchPRMetadata(tmp, 'abc123', 'https://gitlab.com/owner/repo.git', cfg);
      const owners = await gitlab.fetchCodeowners(tmp, 'https://gitlab.com/owner/repo.git', cfg);
      assert.equal(pr, null);
      assert.equal(owners, null);
      assert.equal(fetchCalled, false, 'no fetch should be attempted without configuration');
    });
  } finally {
    global.fetch = priorFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('github.fetchPRMetadata: configured, makes exactly one fetch call and parses a real-shaped response', async () => {
  const priorFetch = global.fetch;
  let callCount = 0;
  global.fetch = async (url) => {
    callCount++;
    assert.match(url, /\/commits\/abc123\/pulls$/);
    return {
      ok: true,
      json: async () => ([{ number: 42, requested_reviewers: [{ login: 'alice' }], merged_at: '2026-01-01T00:00:00Z' }]),
    };
  };
  try {
    const pr = await github.fetchPRMetadata('/tmp', 'abc123', 'https://github.com/owner/repo.git', { token: 'x', baseUrl: null });
    assert.equal(pr.prNumber, 42);
    assert.deepEqual(pr.reviewers, ['alice']);
    assert.equal(callCount, 1);
  } finally { global.fetch = priorFetch; }
});

// ── FR-PROV-022: provider enrichment wired into the live pipeline ──
//
// Everything above this line drives the provider functions directly, in
// isolation. These tests instead go through `annotateGitProvenance` —
// coordinator.js's actual integration point — because the hermeticity
// property that matters ("zero network calls when unconfigured") is a
// property of the COORDINATOR (it must never call `getRemoteUrl`, let alone
// a provider fetch, when no provider is configured), not of the provider
// functions in isolation, which were already proven hermetic above.

// A hand-rolled `{file, line, ruleId, stableId}` finding (the shape earlier
// coordinator tests use for the uncommitted/budget-exhausted short-circuits)
// is not enough to reach status:'complete' here: origin-resolver.js's walk
// confirms an origin by semantically REPLAYING the real detector suite
// against each candidate commit's blob content (`predicate-replay.js`) and
// checking the replayed finding's *real, detector-computed* stableId against
// the target — an invented stableId can never reproduce. So these tests use
// a genuinely detected finding (a real `eval(x)` code-injection hit,
// produced by `runFullScan` itself) the same way
// provenance-coordinator.test.js's repo-lineage test does.
async function realCompleteFinding(fx, relPath, content) {
  const scan = await runFullScan({ fileContents: { [relPath]: content }, scanRoot: fx.root, provenance: false }, () => {});
  const finding = (scan.findings || []).find((f) => f.file === relPath && f.family === 'code-injection');
  if (!finding) throw new Error(`expected a code-injection finding for ${relPath}; got ${JSON.stringify((scan.findings || []).map((f) => ({ file: f.file, family: f.family })))}`);
  return finding;
}

test('annotateGitProvenance: zero network calls when no provider is configured (end-to-end)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', 'eval(x);\n');
  fx.commit('introduce eval', { date: '2026-01-01T00:00:00Z' });
  const finding = await realCompleteFinding(fx, 'a.js', 'eval(x);\n');

  const priorFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => { fetchCalled = true; return { ok: false, json: async () => ({}) }; };

  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: undefined, AGENTIC_SECURITY_GITLAB_TOKEN: undefined }, async () => {
      await annotateGitProvenance([finding], {
        scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard',
      });
    });
  } finally {
    global.fetch = priorFetch;
  }

  assert.equal(finding.findingProvenance.status, 'complete');
  assert.equal(fetchCalled, false, 'no provider configured -- fetch must never be attempted, even though the finding resolves to complete');
  assert.equal(finding.findingProvenance.providerEnrichment, null);
});

test('annotateGitProvenance: a configured provider enriches a complete-status finding with real-shaped PR metadata', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', 'eval(x);\n');
  const sha = fx.commit('introduce eval', { date: '2026-01-01T00:00:00Z' });
  execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/owner/repo.git'], { cwd: fx.root });
  const finding = await realCompleteFinding(fx, 'a.js', 'eval(x);\n');

  const priorFetch = global.fetch;
  global.fetch = async (url) => {
    if (/\/pulls$/.test(url)) {
      return {
        ok: true,
        json: async () => ([{ number: 7, requested_reviewers: [{ login: 'alice' }], merged_at: '2026-01-02T00:00:00Z' }]),
      };
    }
    if (/\/contents\//.test(url)) {
      return { ok: true, json: async () => ({ content: Buffer.from('alice\nbob\n').toString('base64') }) };
    }
    return { ok: false, json: async () => ({}) };
  };

  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: 'ghp_test123', AGENTIC_SECURITY_GITLAB_TOKEN: undefined }, async () => {
      await annotateGitProvenance([finding], {
        scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard',
      });
    });
  } finally {
    global.fetch = priorFetch;
  }

  assert.equal(finding.findingProvenance.status, 'complete');
  assert.equal(finding.findingProvenance.findingOrigin.commit, sha);
  assert.ok(finding.findingProvenance.providerEnrichment, 'expected providerEnrichment to be populated');
  assert.deepEqual(finding.findingProvenance.providerEnrichment, {
    provider: 'github',
    prNumber: 7,
    reviewers: ['alice'],
    approvals: null,
    mergedAt: '2026-01-02T00:00:00Z',
    codeowners: ['alice', 'bob'],
  });
});

test('annotateGitProvenance: the per-scan enrichment cap is honored and disclosed', async (t) => {
  // Must match coordinator.js's MAX_PROVIDER_ENRICHMENTS_PER_SCAN. Kept as a
  // local literal (not imported) so this test proves the OBSERVABLE cap
  // behavior rather than merely echoing the constant back at itself.
  const CAP = 20;
  const TOTAL = CAP + 2;

  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  // TOTAL distinct files, each a genuine eval() code-injection hit, all
  // introduced in one commit — distinct files/stableIds means each gets its
  // own cache key and its own independent resolveAndCache call, so none of
  // them can satisfy another's cache/memo entry and skip the enrichment
  // attempt for free.
  const relPaths = Array.from({ length: TOTAL }, (_, i) => `f${i}.js`);
  const fileContents = {};
  for (let i = 0; i < TOTAL; i++) fileContents[relPaths[i]] = `eval(x${i});\n`;
  for (const [rel, content] of Object.entries(fileContents)) fx.writeFile(rel, content);
  fx.commit('introduce eval calls', { date: '2026-01-01T00:00:00Z' });
  execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/owner/repo.git'], { cwd: fx.root });

  const scan = await runFullScan({ fileContents, scanRoot: fx.root, provenance: false }, () => {});
  const findings = (scan.findings || []).filter((f) => f.family === 'code-injection');
  assert.equal(findings.length, TOTAL, `expected ${TOTAL} real code-injection findings; got ${findings.length}`);

  const priorFetch = global.fetch;
  global.fetch = async (url) => {
    if (/\/pulls$/.test(url)) {
      return { ok: true, json: async () => ([{ number: 1, requested_reviewers: [], merged_at: null }]) };
    }
    if (/\/contents\//.test(url)) {
      return { ok: true, json: async () => ({ content: Buffer.from('').toString('base64') }) };
    }
    return { ok: false, json: async () => ({}) };
  };

  try {
    await withEnv({ AGENTIC_SECURITY_GITHUB_TOKEN: 'ghp_test123', AGENTIC_SECURITY_GITLAB_TOKEN: undefined }, async () => {
      await annotateGitProvenance(findings, {
        scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard',
      });
    });
  } finally {
    global.fetch = priorFetch;
  }

  for (const f of findings) {
    assert.equal(f.findingProvenance.status, 'complete', `expected finding for ${f.file} to resolve complete`);
  }

  const enriched = findings.filter((f) => f.findingProvenance.providerEnrichment !== null);
  const capped = findings.filter((f) => f.findingProvenance.limitations.some((l) => /provider enrichment cap/.test(l)));

  assert.equal(enriched.length, CAP, `expected exactly ${CAP} findings enriched under the cap; got ${enriched.length}`);
  assert.equal(capped.length, TOTAL - CAP, `expected the remaining ${TOTAL - CAP} findings to carry the cap-reached limitation`);
});
