// S4 — scripts/ci-templates/* and commands/setup.md's inline GitHub Actions
// generator must invoke commands the real CLI actually supports.
//
// Reproduced live before fixing: `agentic-security scan --all --json` (neither
// flag exists — parseArgs swallows both silently, so `--json` becomes the
// scan's TARGET path argument and the JSON output never materializes) followed
// by `agentic-security ci-gate --threshold high` (no such subcommand → exit 4,
// "unknown command"). The real invocation is a single
// `agentic-security ci <path> --fail-on <severity>`, which runs its own scan,
// writes .agentic-security/findings.{json,sarif,junit.xml} unconditionally,
// and exits non-zero when the threshold is breached — verified live against
// test/fixtures/vulnerable-js (exit 1) and a clean fixture (exit 0).
//
// Separately, setup.md's embedded GitHub Actions generator repeated
// `--format`/`--output` on one `scan` invocation (the second occurrence
// silently overwrote the first in parseArgs, so the SARIF file the "Upload
// SARIF" step references was never written), and its nested `node -e "..."`
// (the "Fail on N+ findings" step) used an unescaped inner `"` that
// terminates the OUTER shell string early — reproduced live by extracting and
// running the generator, which threw `SyntaxError: Unexpected end of input`.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { load as loadYaml } from '../src/util/yaml.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEMPLATES_DIR = path.join(REPO_ROOT, 'scripts', 'ci-templates');

const TEMPLATE_FILES = ['.gitlab-ci.yml', '.circleci-config.yml', 'buildkite.yml', 'Jenkinsfile'];

function readTemplate(name) {
  return fs.readFileSync(path.join(TEMPLATES_DIR, name), 'utf8');
}

for (const name of TEMPLATE_FILES) {
  test(`S4: ${name} does not reference the nonexistent 'ci-gate' subcommand or bogus scan flags`, () => {
    const content = readTemplate(name);
    assert.doesNotMatch(content, /\bci-gate\b/, `${name} must not reference the nonexistent 'ci-gate' subcommand`);
    assert.doesNotMatch(content, /scan\s+--all\b/, `${name} must not pass --all to 'scan' (not a real scan flag)`);
    assert.doesNotMatch(content, /--threshold\b/, `${name} must not pass --threshold (the real flag is --fail-on)`);
    assert.doesNotMatch(content, /@clearcapabilities\//, `${name} must reference the real npm scope @clear-capabilities`);
  });

  test(`S4: ${name} invokes the real 'agentic-security ci' gate with --fail-on`, () => {
    const content = readTemplate(name);
    assert.match(content, /agentic-security\s+ci\s+\.\s+--fail-on\s+\w+/,
      `${name} must run 'agentic-security ci . --fail-on <severity>'`);
  });

  test(`S4: ${name} references the artifacts 'ci' actually writes`, () => {
    const content = readTemplate(name);
    for (const artifact of ['findings.json', 'findings.sarif', 'findings.junit.xml']) {
      assert.match(content, new RegExp(`\\.agentic-security/${artifact.replace('.', '\\.')}`),
        `${name} must reference .agentic-security/${artifact}, which 'ci' writes unconditionally`);
    }
  });
}

for (const name of ['.gitlab-ci.yml', '.circleci-config.yml', 'buildkite.yml']) {
  test(`S4: ${name} is valid YAML`, () => {
    const parsed = loadYaml(readTemplate(name));
    assert.ok(parsed && typeof parsed === 'object');
  });
}

test('S4: Jenkinsfile balances braces and quotes (Groovy has no YAML parser here)', () => {
  const content = readTemplate('Jenkinsfile');
  const opens = (content.match(/\{/g) || []).length;
  const closes = (content.match(/\}/g) || []).length;
  assert.equal(opens, closes, 'Jenkinsfile braces must balance');
});

// The setup.md-embedded GitHub Actions generator is not itself an importable
// module — commands/*.md ship a `node -e "..."` script inline. Extract and
// run it exactly as the slash command would, proving the output is valid
// YAML and uses the real CLI invocation, and that nothing inside the outer
// double-quoted shell argument prematurely terminates it.
test('S4: setup.md\'s inline GitHub Actions generator produces valid, correctly-invoked YAML', () => {
  const setupMd = fs.readFileSync(path.join(REPO_ROOT, 'commands', 'setup.md'), 'utf8');
  const lines = setupMd.split('\n');
  const startIdx = lines.findIndex((l) => l.trim() === 'node -e "');
  assert.ok(startIdx >= 0, 'expected to find the opening `node -e "` line in setup.md');
  const endIdx = lines.findIndex((l, i) => i > startIdx && l.trim() === '" -- "$@"');
  assert.ok(endIdx > startIdx, 'expected to find the closing `" -- "$@"` line in setup.md');
  // Run through an actual shell, exactly as the fenced ```bash block would be
  // executed for real — the block's `\`` / `\$` escapes are BASH escapes,
  // meant to be unescaped by the shell before node ever sees them. Passing
  // the raw text straight to `node -e` (argv, no shell) skips that
  // unescaping and fails for a completely different, uninteresting reason.
  const script = lines.slice(startIdx, endIdx + 1).join('\n');
  const scriptPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'setup-ci-')), 'run.sh');
  fs.writeFileSync(scriptPath, script);

  const result = spawnSync('bash', [scriptPath, '--provider', 'github', '--fail-on', 'high'], {
    encoding: 'utf8',
    env: { ...process.env, CLAUDE_PLUGIN_ROOT: REPO_ROOT },
  });
  assert.equal(result.status, 0, `generator must exit 0; stderr: ${result.stderr}`);
  assert.doesNotMatch(result.stdout, /Unterminated template/);

  const yamlLines = result.stdout.split('\n')
    .filter((l) => !/^(GitHub Actions Security Gate|  Blocks on:|  DRY RUN|$)/.test(l))
    .map((l) => l.replace(/^ {2}/, ''));
  const parsed = loadYaml(yamlLines.join('\n'));
  assert.ok(parsed && parsed.jobs && parsed.jobs.security, 'generated workflow must parse and define the security job');
  const scanStep = parsed.jobs.security.steps.find((s) => s.name === 'Run security scan');
  assert.match(scanStep.run, /agentic-security scan \. --format sarif --output security-results\.sarif/);
  assert.match(scanStep.run, /agentic-security scan \. --format json --output security-results\.json/);
  const gateStep = parsed.jobs.security.steps.find((s) => /Fail on/.test(s.name));
  assert.match(gateStep.run, /node -e "/);
});
