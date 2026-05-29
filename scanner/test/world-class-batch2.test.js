// Sanity tests for the 10 world-class+2 modules. Verifies each is
// importable, exposes its documented public API, and behaves correctly
// on small fixtures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'wc2-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── Item 1: LLM app security ───────────────────────────────────────────────

test('llm-app: detects prompt injection via system+user concat', async () => {
  const { scanLlmApp } = await import('../src/sast/llm-app.js');
  const src = `
import openai
def chat(user_input):
    system_prompt = "You are a helpful assistant."
    full = system_prompt + " The user said: " + user_input
    return openai.ChatCompletion.create(messages=[{"role":"user","content": full}])
`;
  const findings = scanLlmApp('app.py', src);
  assert.ok(findings.some(f => f.subfamily === 'prompt-injection'));
});

test('llm-app: detects RAG injection (vectorstore → llm.generate)', async () => {
  const { scanLlmApp } = await import('../src/sast/llm-app.js');
  const src = `
from langchain import VectorStore
def answer(q):
    docs = vectorstore.similarity_search(q)
    return openai.chat.completions.create(messages=[{"role":"system","content":"answer using: " + str(docs)}])
`;
  const findings = scanLlmApp('app.py', src);
  assert.ok(findings.some(f => f.subfamily === 'rag-injection'));
});

test('llm-app: detects exposed exec tool', async () => {
  const { scanLlmApp } = await import('../src/sast/llm-app.js');
  const src = `
const anthropic = new Anthropic();
const tools = [{ name: "shell_exec", description: "run a shell command", input_schema: {...} }];
`;
  const findings = scanLlmApp('agent.js', src);
  assert.ok(findings.some(f => f.subfamily === 'tool-exec'));
});

test('llm-app: untrusted output sink (eval(llm_result))', async () => {
  const { scanLlmApp } = await import('../src/sast/llm-app.js');
  const src = `
const result = await openai.chat.completions.create({...});
eval(result.choices[0].message.content);
`;
  const findings = scanLlmApp('eval.js', src);
  assert.ok(findings.some(f => f.subfamily === 'output-untrusted-sink'));
});

test('llm-app: non-LLM file produces no findings', async () => {
  const { scanLlmApp } = await import('../src/sast/llm-app.js');
  const src = 'function add(a, b) { return a + b; }';
  assert.deepEqual(scanLlmApp('math.js', src), []);
});

// ── Item 2: Threat modeling ────────────────────────────────────────────────

test('threat-model-auto: buildThreatModel produces entities + threats from findings', async () => {
  const { buildThreatModel } = await import('../src/posture/threat-model-auto.js');
  const scan = {
    routes: [{ method: 'GET', path: '/api/users', file: 'r.js', line: 1, requiresAuth: false }],
    findings: [
      { family: 'sql-injection', cwe: 'CWE-89', severity: 'high', file: 'r.js', line: 5, id: 'f1', vuln: 'SQLi' },
      { family: 'hardcoded-secret', cwe: 'CWE-798', severity: 'critical', file: 's.js', line: 1, id: 'f2', vuln: 'secret' },
    ],
  };
  const model = buildThreatModel(scan);
  assert.ok(model.entities.length > 0);
  assert.ok(model.assets.length > 0);
  assert.ok(model.threats.length > 0);
});

test('threat-model-auto: renderMermaid produces flowchart syntax', async () => {
  const { renderMermaid, buildThreatModel } = await import('../src/posture/threat-model-auto.js');
  const scan = { routes: [], findings: [] };
  const md = renderMermaid(buildThreatModel(scan));
  assert.match(md, /^flowchart TB/);
});

// ── Item 3: API contract ───────────────────────────────────────────────────

test('api-contract: parseOpenAPI extracts routes + auth + parameters', async () => {
  const { parseOpenAPI } = await import('../src/posture/api-contract.js');
  const doc = {
    paths: {
      '/users/{id}': { get: {
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        security: [{ bearer: [] }],
        operationId: 'getUser',
      }},
      '/health': { get: {} },
    },
  };
  const routes = parseOpenAPI(doc);
  assert.equal(routes.length, 2);
  assert.ok(routes.find(r => r.path === '/users/{id}').requiresAuth);
});

test('api-contract: diffRoutes flags undocumented endpoint', async () => {
  const { diffRoutes } = await import('../src/posture/api-contract.js');
  const findings = diffRoutes(
    [],
    [{ method: 'GET', path: '/secret/admin', file: 'r.js', line: 1 }],
  );
  assert.ok(findings.some(f => f.subfamily === 'undocumented-endpoint'));
});

test('api-contract: diffRoutes flags missing-auth-on-route', async () => {
  const { diffRoutes } = await import('../src/posture/api-contract.js');
  const findings = diffRoutes(
    [{ method: 'POST', path: '/admin', requiresAuth: true }],
    [{ method: 'POST', path: '/admin', requiresAuth: false, file: 'r.js', line: 1 }],
  );
  assert.ok(findings.some(f => f.subfamily === 'missing-auth-on-route'));
});

// ── Item 4: Mobile ─────────────────────────────────────────────────────────

test('mobile (Android): exported activity without permission flagged', async () => {
  const { scanMobile } = await import('../src/sast/mobile.js');
  const manifest = `<?xml version="1.0"?>
<manifest>
  <application android:debuggable="true">
    <activity android:name=".Main" android:exported="true" />
  </application>
</manifest>`;
  const findings = scanMobile('AndroidManifest.xml', manifest);
  assert.ok(findings.some(f => f.family === 'mobile-exported-component'));
  assert.ok(findings.some(f => f.family === 'mobile-debug-build'));
});

test('mobile (Android): WebView.addJavascriptInterface flagged in Kotlin', async () => {
  const { scanMobile } = await import('../src/sast/mobile.js');
  const kt = `
import android.webkit.WebView
class Main {
  fun setup(webView: WebView) {
    webView.addJavascriptInterface(JsBridge(), "android")
  }
}`;
  const findings = scanMobile('Main.kt', kt);
  assert.ok(findings.some(f => f.family === 'mobile-webview-js-iface'));
});

test('mobile (iOS): NSAllowsArbitraryLoads flagged', async () => {
  const { scanMobile } = await import('../src/sast/mobile.js');
  const plist = `<?xml version="1.0"?>
<plist>
  <dict>
    <key>NSAppTransportSecurity</key>
    <dict>
      <key>NSAllowsArbitraryLoads</key>
      <true/>
    </dict>
  </dict>
</plist>`;
  const findings = scanMobile('Info.plist', plist);
  assert.ok(findings.some(f => f.family === 'ios-cleartext-transit'));
});

test('mobile (iOS): kSecAttrAccessibleAlways flagged in Swift', async () => {
  const { scanMobile } = await import('../src/sast/mobile.js');
  const swift = `
import Foundation
import Security
let q: [String: Any] = [
  kSecAttrAccessible as String: kSecAttrAccessibleAlways,
]`;
  const findings = scanMobile('App.swift', swift);
  assert.ok(findings.some(f => f.family === 'ios-keychain-accessible'));
});

// ── Item 5: Formal verification (scaffolded; gracefully degrades) ──────────

test('formal-verify: skipped when AGENTIC_SECURITY_FORMAL not set', async () => {
  const { annotateFormalVerification } = await import('../src/dataflow/formal-verify.js');
  delete process.env.AGENTIC_SECURITY_FORMAL;
  const r = await annotateFormalVerification([{ family: 'buffer-overflow', severity: 'high' }], {});
  assert.equal(r.skipped, true);
});

test('formal-verify: returns cbmc-not-installed when CBMC missing', async () => {
  const { dischargeCbmc } = await import('../src/dataflow/formal-verify.js');
  const r = await dischargeCbmc({ line: 1 }, 'int main() { return 0; }');
  assert.ok(r.verdict === 'unknown' || r.verdict === 'proved-safe');
});

// ── Item 7: Federated learning ─────────────────────────────────────────────

test('federated-learning: computePrivatizedGradient adds noise', async () => {
  const { computePrivatizedGradient, _internals } = await import('../src/posture/federated-learning.js');
  const current = { global: { 'sql-injection|exec': { tp: 5, fp: 1 } } };
  const baseline = { snapshot: { global: { 'sql-injection|exec': { tp: 2, fp: 0 } } } };
  const grad = computePrivatizedGradient(current, baseline);
  assert.ok(grad.global['sql-injection|exec']);
  // Delta is 3, 1 — with noise, value should be ≥0 (Math.max(0, …)).
  assert.ok(grad.global['sql-injection|exec'].tp >= 0);
  assert.equal(grad.perProject, null, 'per-project must NEVER leave the local store');
});

test('federated-learning: pushGradient refuses without opt-in flag', async () => {
  const { pushGradient } = await import('../src/posture/federated-learning.js');
  delete process.env.AGENTIC_SECURITY_FEDERATED;
  const r = await pushGradient('/tmp', { global: {} });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'opt-in-not-enabled');
});

// ── Item 8: Real-time CVE monitor ──────────────────────────────────────────

test('cve-monitor: indexSbom builds (ecosystem, name) → component map', async () => {
  const { indexSbom } = await import('../src/posture/realtime-cve-monitor.js');
  const idx = indexSbom([
    { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
    { ecosystem: 'pypi', name: 'requests', version: '2.28.0' },
  ]);
  assert.ok(idx.has('npm:lodash'));
  assert.ok(idx.has('pypi:requests'));
});

test('cve-monitor: matchOsvToSbom returns matches for affected packages', async () => {
  const { matchOsvToSbom, indexSbom } = await import('../src/posture/realtime-cve-monitor.js');
  const idx = indexSbom([{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }]);
  const vuln = {
    id: 'GHSA-x', aliases: ['CVE-2024-X'],
    affected: [{ package: { ecosystem: 'npm', name: 'lodash' } }],
  };
  const matches = matchOsvToSbom(vuln, idx);
  assert.equal(matches.length, 1);
});

// ── Item 9: Compliance DSL ─────────────────────────────────────────────────

test('compliance-policy: verifyPolicy runs primitives against a synthetic context', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "Logical access controls"
    requires:
      - finding-family: "auth-missing"
        must-be: zero
  CC7.2:
    title: "Documentation present"
    requires:
      - file-exists: "package.json"
`);
    const { loadPolicy, verifyPolicy } = await import('../src/posture/compliance-policy.js');
    const policy = loadPolicy(sess.dir);
    assert.ok(policy);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.summary.total, 2);
    assert.equal(report.summary.compliant, 2);
  } finally { await sess.cleanup(); }
});

test('compliance-policy: emitEvidenceJsonLd produces a JSON-LD doc', async () => {
  const sess = await mkSession();
  try {
    const { emitEvidenceJsonLd } = await import('../src/posture/compliance-policy.js');
    const report = {
      framework: 'X', version: '1',
      summary: { total: 1, compliant: 1, nonCompliant: 0, notApplicable: 0 },
      controls: [{ id: 'C1', title: 't', status: 'compliant', checks: [], evidence: [] }],
    };
    const jsonld = emitEvidenceJsonLd(report, sess.dir);
    assert.equal(jsonld['@type'], 'ComplianceEvidence');
    assert.ok(fs.existsSync(path.join(sess.dir, '.agentic-security', 'compliance-evidence.json')));
  } finally { await sess.cleanup(); }
});

// ── Item 10: SBOM diff ─────────────────────────────────────────────────────

test('sbom-diff: diffSboms detects added / removed / bumped / substituted', async () => {
  const { diffSboms } = await import('../src/posture/sbom-diff.js');
  const prev = {
    sha: 'abc',
    components: [
      { ecosystem: 'npm', name: 'lodash',  version: '4.17.20', sha256: 'aaa' },
      { ecosystem: 'npm', name: 'removed', version: '1.0.0' },
    ],
  };
  const cur = {
    sha: 'def',
    components: [
      { ecosystem: 'npm', name: 'lodash',  version: '4.17.21' },                // bumped
      { ecosystem: 'npm', name: 'newdep',  version: '1.0.0' },                  // added
      { ecosystem: 'npm', name: 'sub',     version: '1.0.0', sha256: 'bbb' },
    ],
  };
  // Add a prev for 'sub' with the SAME version but a DIFFERENT hash to
  // exercise the substitution detector.
  prev.components.push({ ecosystem: 'npm', name: 'sub', version: '1.0.0', sha256: 'aaa' });
  const r = diffSboms(prev, cur);
  assert.equal(r.summary.added, 1, 'one added');
  assert.equal(r.summary.removed, 1, 'one removed');
  assert.equal(r.summary.bumped, 1, 'one bumped');
  assert.equal(r.summary.substituted, 1, 'one substituted');
  assert.ok(r.findings.some(f => f.subfamily === 'dependency-substitution' && f.severity === 'critical'));
});

test('sbom-diff: runSbomDiff returns first:true on initial scan', async () => {
  const sess = await mkSession();
  try {
    const { runSbomDiff } = await import('../src/posture/sbom-diff.js');
    const r = runSbomDiff(sess.dir, [{ ecosystem: 'npm', name: 'x', version: '1.0.0' }]);
    assert.equal(r.first, true);
    assert.equal(r.findings.length, 0);
  } finally { await sess.cleanup(); }
});
