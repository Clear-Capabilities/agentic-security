// Tests for batch-3 Claude Code chat enhancements:
//   #3 fix-style-mirror.js
//   #5 threat-model-grounding.js
//   #6 commands/red-team.md (presence + syntax)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { findStyleExamples, _internals as _ism } from '../src/posture/fix-style-mirror.js';
import { applyThreatModel, loadThreatModel, _internals as _itm } from '../src/posture/threat-model-grounding.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'cb3-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"cb3"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── fix-style-mirror ───────────────────────────────────────────────────────

test('fix-style-mirror: finds parameterized-query example in sibling file', async () => {
  const p = await mkProject();
  try {
    await fsp.mkdir(path.join(p.dir, 'src'), { recursive: true });
    await fsp.writeFile(
      path.join(p.dir, 'src', 'safe.js'),
      'export async function getUser(id) {\n  return db.query("SELECT * FROM users WHERE id = $1", [id]);\n}\n',
    );
    await fsp.writeFile(
      path.join(p.dir, 'src', 'unsafe.js'),
      'export async function getUser(id) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n',
    );
    const examples = findStyleExamples(p.dir, {
      family: 'sqli',
      file: path.join(p.dir, 'src', 'unsafe.js'),
    });
    assert.ok(examples.length >= 1);
    assert.match(examples[0].snippet, /\$1.*\[id\]|\[id\].*\$1/s);
    assert.equal(examples[0].file, 'src/safe.js');
  } finally { await p.cleanup(); }
});

test('fix-style-mirror: empty when family has no patterns', () => {
  const examples = findStyleExamples('/tmp', { family: 'no-such-family', file: '/tmp/x.js' });
  assert.deepEqual(examples, []);
});

test('fix-style-mirror: empty when family missing', () => {
  const examples = findStyleExamples('/tmp', { file: '/tmp/x.js' });
  assert.deepEqual(examples, []);
});

// ── threat-model-grounding ─────────────────────────────────────────────────

test('threat-model: crown jewels bump severity', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, 'CLAUDE.md'),
      '# CLAUDE\n\n## Crown jewels\n\n- `src/auth/**`\n- `src/payments/**`\n',
    );
    const findings = [
      { file: 'src/auth/login.js', line: 1, severity: 'medium', family: 'authz' },
      { file: 'src/util/format.js', line: 1, severity: 'medium', family: 'authz' },
    ];
    const r = applyThreatModel(p.dir, findings);
    assert.ok(r.applied >= 1);
    assert.equal(findings[0].severity, 'high', 'crown jewel bumped');
    assert.equal(findings[1].severity, 'medium', 'non-jewel unchanged');
    assert.equal(findings[0].threatModel.crownJewel, true);
  } finally { await p.cleanup(); }
});

test('threat-model: out-of-scope demotes', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, 'CLAUDE.md'),
      '# CLAUDE\n\n## Out of scope\n\n- `playground/**`\n- `examples/**`\n',
    );
    const findings = [{ file: 'playground/demo.js', line: 1, severity: 'critical', family: 'sqli' }];
    const r = applyThreatModel(p.dir, findings);
    assert.equal(findings[0].severity, 'low');
    assert.equal(findings[0].threatModel.outOfScope, true);
  } finally { await p.cleanup(); }
});

test('threat-model: compliance regime tags PII findings', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, 'CLAUDE.md'),
      '# CLAUDE\n\n## Compliance\n\nWe comply with HIPAA and GDPR.\n',
    );
    const findings = [{ file: 'src/users.js', line: 1, severity: 'medium', family: 'pii-exposure' }];
    const r = applyThreatModel(p.dir, findings);
    assert.deepEqual(findings[0].threatModel.compliance, ['HIPAA', 'GDPR']);
  } finally { await p.cleanup(); }
});

test('threat-model: attacker profile stamped on findings', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, 'CLAUDE.md'),
      '# CLAUDE\n\n## Threat actor\n\nWe model a sophisticated APT attacker with nation-state resources.\n',
    );
    const findings = [{ file: 'src/api.js', line: 1, severity: 'high', family: 'sqli' }];
    const r = applyThreatModel(p.dir, findings);
    assert.equal(findings[0].threatModel.attacker, 'apt');
  } finally { await p.cleanup(); }
});

test('threat-model: loadThreatModel returns extracted structure', async () => {
  const p = await mkProject();
  try {
    await fsp.writeFile(
      path.join(p.dir, 'CLAUDE.md'),
      '# CLAUDE\n\n## Crown jewels\n\n- `src/payments/**`\n\n## Compliance\n\nSOC2 Type II.\n\n## Attacker model\n\nScript kiddie / automated scanners.\n',
    );
    const tm = loadThreatModel(p.dir);
    assert.ok(tm.crownJewels.includes('src/payments/**'));
    assert.ok(tm.compliance.includes('SOC2'));
    assert.equal(tm.attacker, 'script-kiddie');
  } finally { await p.cleanup(); }
});

test('threat-model: NO_THREAT_MODEL_GROUNDING disables', async () => {
  const p = await mkProject();
  try {
    process.env.AGENTIC_SECURITY_NO_THREAT_MODEL_GROUNDING = '1';
    try {
      await fsp.writeFile(path.join(p.dir, 'CLAUDE.md'), '## Crown jewels\n\n- `src/**`\n');
      const findings = [{ file: 'src/x.js', line: 1, severity: 'medium', family: 'sqli' }];
      const r = applyThreatModel(p.dir, findings);
      assert.equal(r.applied, 0);
    } finally { delete process.env.AGENTIC_SECURITY_NO_THREAT_MODEL_GROUNDING; }
  } finally { await p.cleanup(); }
});

test('threat-model: _bumpSeverity is monotone', () => {
  assert.equal(_itm._bumpSeverity('low'), 'medium');
  assert.equal(_itm._bumpSeverity('medium'), 'high');
  assert.equal(_itm._bumpSeverity('high'), 'critical');
  assert.equal(_itm._bumpSeverity('critical'), 'critical');
});

// ── red-team command (#6) ─────────────────────────────────────────────────

test('red-team: command file is present + valid frontmatter', () => {
  const fp = path.resolve(import.meta.dirname, '..', '..', 'commands', 'red-team.md');
  assert.ok(fs.existsSync(fp));
  const body = fs.readFileSync(fp, 'utf8');
  assert.match(body, /^---\n[\s\S]*?description:/m);
  assert.match(body, /argument-hint:/);
  assert.match(body, /persona/);
});
