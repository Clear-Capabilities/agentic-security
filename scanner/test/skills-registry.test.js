// Skills registry integrity test.
//
// Every skill in skills/ must:
//   1. Live at skills/<slug>/SKILL.md
//   2. Carry a YAML frontmatter block with `name:` and `description:` keys
//   3. Have name === "agentic-security:<slug>" (matches the directory name)
//   4. Have description ≤ 120 chars (already enforced by lint script;
//      we re-assert here so a missed import in CI still trips the unit-test
//      suite)
//   5. Route to or reference at least one canonical command from the body —
//      skills are model-invoked surfaces that point users at the slash
//      command for explicit invocation.
//
// This test is the load-bearing check that the auto-activating skill
// surface stays internally consistent as the team adds new skills.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILLS_DIR = path.resolve(__dirname, '..', '..', 'skills');
const COMMANDS_DIR = path.resolve(__dirname, '..', '..', 'commands');

function _parseFrontmatter(body) {
  if (!body.startsWith('---\n')) return null;
  const close = body.indexOf('\n---', 4);
  if (close < 0) return null;
  const block = body.slice(4, close);
  const out = {};
  for (const rawLine of block.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    out[m[1]] = v;
  }
  return out;
}

function _listSkills() {
  if (!fs.existsSync(SKILLS_DIR)) return [];
  return fs.readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter(e => e.isDirectory() && !e.name.startsWith('.'))
    .map(e => ({
      slug: e.name,
      file: path.join(SKILLS_DIR, e.name, 'SKILL.md'),
    }))
    .filter(s => fs.existsSync(s.file));
}

function _listCommandNames() {
  if (!fs.existsSync(COMMANDS_DIR)) return new Set();
  return new Set(
    fs.readdirSync(COMMANDS_DIR)
      .filter(n => n.endsWith('.md'))
      .map(n => n.replace(/\.md$/, ''))
  );
}

const skills = _listSkills();
const commandNames = _listCommandNames();

test('skills/ directory has at least the expected core surface', () => {
  // Post-consolidation core surface: secure-coding-guard + security-explain
  // + privacy-data-flow + security-fix-finding + security-rotate-leak
  // + security-scan-on-deploy + add-scan-rule = 7, so 6 is the floor.
  assert.ok(skills.length >= 6, `expected at least 6 skills, got ${skills.length}`);
});

test('every skill carries frontmatter with name + description', () => {
  for (const s of skills) {
    const body = fs.readFileSync(s.file, 'utf8');
    const fm = _parseFrontmatter(body);
    assert.ok(fm, `${s.slug}: missing frontmatter`);
    assert.ok(fm.name, `${s.slug}: missing 'name' frontmatter key`);
    assert.ok(fm.description, `${s.slug}: missing 'description' frontmatter key`);
  }
});

test('skill name matches directory slug', () => {
  for (const s of skills) {
    const body = fs.readFileSync(s.file, 'utf8');
    const fm = _parseFrontmatter(body);
    const expected = `agentic-security:${s.slug}`;
    assert.equal(fm.name, expected,
      `${s.slug}: name="${fm.name}" should match directory: expected "${expected}"`);
  }
});

test('skill descriptions are ≤ 120 chars', () => {
  for (const s of skills) {
    const body = fs.readFileSync(s.file, 'utf8');
    const fm = _parseFrontmatter(body);
    assert.ok(fm.description.length <= 120,
      `${s.slug}: description ${fm.description.length} chars > 120 cap`);
  }
});

test('skill descriptions include an "Activate" or "Activate on" cue', () => {
  // Auto-activating skills depend on the model's skill router reading the
  // description for activation cues. Without an explicit trigger phrase
  // the skill won't reliably fire — it'll just sit there.
  const skipList = new Set([
    'add-scan-rule',   // user-invoked walk-through, not auto-activating
  ]);
  for (const s of skills) {
    if (skipList.has(s.slug)) continue;
    const body = fs.readFileSync(s.file, 'utf8');
    const fm = _parseFrontmatter(body);
    assert.match(fm.description, /[Aa]ctivate/,
      `${s.slug}: description should describe activation triggers ("Activate on …")`);
  }
});

test('every trigger skill references at least one slash command', () => {
  // Skills route users at the canonical slash command for explicit invocation;
  // the body should mention at least one /<command>.
  const skipList = new Set([
    'add-scan-rule',   // standalone workflow
  ]);
  for (const s of skills) {
    if (skipList.has(s.slug)) continue;
    const body = fs.readFileSync(s.file, 'utf8');
    assert.match(body, /\/[a-z][a-z0-9-]+/,
      `${s.slug}: body should reference at least one slash command`);
  }
});

test('any /command referenced by a skill resolves to an existing commands/*.md', () => {
  // Catch typos like /securitya-attestation. Every slash referenced in a
  // skill body must map to a file in commands/. We allow /<plugin>:<cmd>
  // (the fully-qualified form) and plain /<cmd>.
  const reSlash = /\B\/([a-z][a-z0-9-]+)(?:[\s.,)`'"]|$)/g;
  const allowedNotCommands = new Set([
    // Bash and meta — not slash commands.
    'usr', 'bin', 'tmp', 'var', 'etc', 'private',
  ]);
  for (const s of skills) {
    const body = fs.readFileSync(s.file, 'utf8');
    let m;
    while ((m = reSlash.exec(body)) !== null) {
      const cmd = m[1];
      if (allowedNotCommands.has(cmd)) continue;
      // Strip a `--flag` suffix that some references include in-text.
      if (cmd.startsWith('--')) continue;
      // Allow `/well-known/` URL-style mentions.
      if (cmd === 'well-known' || cmd === 'security') continue;
      // Allow MCP tool references like `/explain --narrative`. The base
      // (`explain`) must exist; `--narrative` won't be captured by the
      // regex anyway (the leading `\B` rules out non-word-boundary anchors).
      if (!commandNames.has(cmd)) {
        // Fail with a helpful message but only if the command isn't a known
        // option pattern. We deliberately keep this strict.
        assert.fail(`${s.slug}: references /${cmd} which has no commands/${cmd}.md`);
      }
    }
  }
});
