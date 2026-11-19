// Convention deviation, value form (src/sast/convention-deviation-values.js):
// a function that passes a caller-supplied value to the primitive its
// siblings in the same file guard first, without the guard.
//
// Every fixture is SYNTHETIC, written from first principles. Each language
// has a vulnerable file and its fixed twin (the guard applied everywhere),
// plus one clean control for a different precision rule: a guard on a
// different value, siblings using different primitives, a minority guard, no
// guarded population, a null check as the only "guard", a loose one-to-one
// pairing, a hand-written exiting check and a guarding helper.
//
// The detector asserts an absence relative to neighbours, so most tests here
// prove that it REFUSES to fire.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanConventionDeviationProject } from '../src/sast/convention-deviation.js';
import {
  analyseValueGuardsInFile, isGuardName, langOf, concernOf, isRelevantFile, MIN_GUARDED_VALUE_SIBLINGS, _valueInternals,
} from '../src/sast/convention-deviation-values.js';
import { runScan } from '../src/runScan.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

function scanDir(lang, kind) {
  const dir = path.join(FIX, `sibling-guard-${lang}`, kind);
  const out = {};
  for (const f of fs.readdirSync(dir)) {
    const rel = `src/${f}`;
    out[f] = scanConventionDeviationProject({ [rel]: fs.readFileSync(path.join(dir, f), 'utf8') })
      .filter(x => x.id.startsWith('convention-deviation:value-guard-omitted:'));
  }
  return out;
}

// lang -> [vulnerable file, expected line, expected CWE, unguarded function, guard]
const EXPECT = {
  js: ['webhooks.js', 26, 'CWE-918', 'updateHook', 'validateWebhookUrl'],
  py: ['report_store.py', 23, 'CWE-22', 'save_draft', 'ensure_inside_root'],
  java: ['OAuthClientService.java', 30, 'CWE-918', 'update', 'validateRedirectUri'],
  kt: ['ImportService.kt', 13, 'CWE-918', 'refreshFeed', 'validateFeedUrl'],
  go: ['docs.go', 27, 'CWE-862', 'ArchiveDoc', 'RequireDocAccess'],
  php: ['AvatarController.php', 27, 'CWE-22', 'import', 'assertSafeFilename'],
  rb: ['packager.rb', 21, 'CWE-78', 'rebuild', 'validate_target!'],
  cs: ['ExportController.cs', 27, 'CWE-22', 'Preview', 'ValidateFileName'],
};

for (const [lang, [file, line, cwe, fn, guard]] of Object.entries(EXPECT)) {
  test(`${lang}: the unguarded sibling fires at its use site, with the guard and siblings as evidence`, () => {
    const res = scanDir(lang, 'vulnerable');
    const f = res[file];
    assert.equal(f.length, 1, `${lang}: expected one finding, got ${JSON.stringify(f.map(x => x.vuln))}`);
    assert.equal(f[0].line, line, 'the finding sits where the guard has to be added (the use site)');
    assert.equal(f[0].cwe, cwe);
    assert.equal(f[0].severity, 'medium');
    assert.equal(f[0].family, 'convention-deviation');
    assert.equal(f[0].parser, 'CONVENTION');
    assert.match(f[0].vuln, new RegExp(`${fn}\\(\\)`));
    assert.ok(f[0].vuln.includes(`${guard}()`), f[0].vuln);
    assert.ok(Array.isArray(f[0].evidenceSiblings) && f[0].evidenceSiblings.length >= 1);
    assert.ok(!f[0].evidenceSiblings.includes(fn), 'the deviating function is not its own evidence');
    assert.ok(f[0].checkedFor, 'an absence claim records what it looked for');
  });

  test(`${lang}: every clean control is silent, including the fixed twin of the vulnerable file`, () => {
    const res = scanDir(lang, 'clean');
    assert.ok(res[file], `${lang}: the clean tree must hold the fixed twin of ${file}`);
    for (const [f, hits] of Object.entries(res)) {
      assert.deepEqual(hits.map(x => x.vuln), [], `${lang}/clean/${f} must produce nothing`);
    }
    assert.ok(Object.keys(res).length >= 2, `${lang}: the clean tree carries a second control`);
  });
}

// ---------------------------------------------------------------------------
// Precision controls, one by one, on inline sources.
// ---------------------------------------------------------------------------

const jsService = (bodies) => `export class S {\n${bodies.join('\n')}\n}\n`;
const run = (file, src) => analyseValueGuardsInFile(file, src, langOf(file));

test('threshold: two guarded against one unguarded fires; one against one only when tight', () => {
  assert.equal(MIN_GUARDED_VALUE_SIBLINGS, 2);
  const g = (n) => `  ${n}(url) {\n    checkSafeUrl(url);\n    return this.http.post(url);\n  }`;
  const u = (n) => `  ${n}(url) {\n    return this.http.post(url);\n  }`;
  assert.equal(run('a.js', jsService([g('a'), g('b'), u('c')])).length, 1);
  // 2 v 2 is not a majority.
  assert.equal(run('a.js', jsService([g('a'), g('b'), u('c'), u('d')])).length, 0);
  // 1 v 1, tight: exactly the value, guard named for its role.
  assert.equal(run('a.js', jsService([g('a'), u('c')])).length, 1);
  // 1 v 1, loose: the guard takes more than the value.
  const loose = `  a(url, opts) {\n    checkSafeUrl(url, opts);\n    return this.http.post(url);\n  }`;
  assert.equal(run('a.js', jsService([loose, u('c')])).length, 0);
  // 1 v 1, loose: the guard is not named for the role or its concern.
  const vague = `  a(url) {\n    checkInput(url);\n    return this.http.post(url);\n  }`;
  assert.equal(run('a.js', jsService([vague, u('c')])).length, 0);
  // 1 v 2 is a minority.
  assert.equal(run('a.js', jsService([g('a'), u('c'), u('d')])).length, 0);
});

test('the guard must take the SAME value that reaches the primitive', () => {
  const src = jsService([
    '  a(name, url) {\n    validateUrl(name);\n    return this.http.post(url);\n  }',
    '  b(name, url) {\n    validateUrl(name);\n    return this.http.post(url);\n  }',
    '  c(name, url) {\n    return this.http.post(url);\n  }',
  ]);
  assert.deepEqual(run('a.js', src), [], 'a guard on another value establishes nothing about this one');
});

test('a guard on the object covers its fields, and a guard on a field covers that field', () => {
  const src = jsService([
    '  a(req) {\n    validateWebhook(req.body.url);\n    return this.http.post(req.body.url);\n  }',
    '  b(req) {\n    validateWebhook(req.body.url);\n    return this.http.post(req.body.url);\n  }',
    '  c(req) {\n    return this.http.post(req.body.url);\n  }',
  ]);
  const f = run('a.js', src);
  assert.equal(f.length, 1);
  assert.equal(f[0].value, 'req.body.url');
});

test('the guard must come BEFORE the use', () => {
  const src = jsService([
    '  a(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  b(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  c(url) {\n    const r = this.http.post(url);\n    validateUrl(url);\n    return r;\n  }',
  ]);
  const f = run('a.js', src);
  assert.equal(f.length, 1, 'a check after the request protects nothing');
  assert.equal(f[0].name, 'c');
});

test('siblings are compared only on the same primitive', () => {
  const src = jsService([
    '  a(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  b(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  c(url) {\n    return this.cache.remember(url);\n  }',
  ]);
  assert.deepEqual(run('a.js', src), []);
});

test('field assignment is a primitive: create() validates before storing, update() does not', () => {
  const py = [
    'class Hook:',
    '    def create(self, url):',
    '        validate_hook_url(url)',
    '        self.url = url',
    '',
    '    def reset(self, url):',
    '        validate_hook_url(url)',
    '        self.url = url',
    '',
    '    def update(self, url):',
    '        self.url = url',
    '',
  ].join('\n');
  const f = run('hook.py', py);
  assert.equal(f.length, 1);
  assert.equal(f[0].name, 'update');
  assert.equal(f[0].line, 11);
  assert.equal(f[0].cwe, 'CWE-918');
});

test('a hand-written exiting check and a guarding helper both count as the guard', () => {
  const src = jsService([
    '  a(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  b(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  c(url) {\n    if (!url.startsWith("https://")) {\n      throw new Error("bad");\n    }\n    return this.http.post(url);\n  }',
    '  d(url) {\n    this.vetted(url);\n    return this.http.post(url);\n  }',
    '  vetted(u) {\n    validateUrl(u);\n    return u;\n  }',
  ]);
  assert.deepEqual(run('a.js', src).map(x => x.name), []);
});

test('an unrelated if with an exit elsewhere does not count as a check of the value', () => {
  const src = jsService([
    '  a(url, n) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  b(url, n) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  c(url, n) {\n    if (n > 3) {\n      this.count(n);\n    }\n    if (url) {\n      this.trace(n);\n    }\n    return this.http.post(url);\n  }',
  ]);
  assert.deepEqual(run('a.js', src).map(x => x.name), ['c']);
});

test('a helper called by a guarded sibling is not a deviation: its caller guarded, one hop up', () => {
  const src = jsService([
    '  a(url) {\n    validateUrl(url);\n    return this.send(url);\n  }',
    '  b(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  c(url) {\n    validateUrl(url);\n    return this.http.post(url);\n  }',
    '  send(url) {\n    return this.http.post(url);\n  }',
  ]);
  assert.deepEqual(run('a.js', src), []);
});

test('option-bag spreads stay with the option-bag rule (no double report)', () => {
  const py = [
    'class Repo:',
    '    def a(self, url, **kwargs):',
    '        check_unsafe_options(kwargs)',
    '        return self.git.clone(url, **kwargs)',
    '    def b(self, url, **kwargs):',
    '        check_unsafe_options(kwargs)',
    '        return self.git.clone(url, **kwargs)',
    '    def c(self, url, **kwargs):',
    '        return self.git.clone(url, **kwargs)',
  ].join('\n');
  assert.deepEqual(run('r.py', py), []);
});

test('test files are not a population (assertions there are guard-shaped by name)', () => {
  assert.equal(isRelevantFile('src/test/foo.js', 'validateUrl(x)'), false);
  assert.equal(isRelevantFile('pkg/foo_test.go', 'ValidateURL(x)'), false);
  assert.equal(isRelevantFile('spec/foo_spec.rb', 'validate_url!(x)'), false);
  assert.equal(isRelevantFile('src/WidgetTest.java', 'validateUrl(x)'), false);
  assert.equal(isRelevantFile('src/widget.js', 'validateUrl(x)'), true);
});

test('guard names: security verbs count; shape checks, factories and lowercase continuations do not', () => {
  for (const n of ['validateUrl', 'check_unsafe_options', 'ValidateFileName', 'RequireDocAccess', 'assertSafeFilename',
    'validate_target!', 'authorize', 'sanitize_path', 'is_safe_url', 'isAllowedHost', 'canEdit', 'ensureAuthorized', 'verify']) {
    assert.equal(isGuardName(n, 'js'), true, n);
  }
  assert.equal(isGuardName('safe_url?', 'rb'), true);
  for (const n of ['require', 'check', 'requireNonNull', 'checkNotNull', 'checkArgument', 'assertEquals', 'AssertionError',
    'checkout', 'validated', 'ensure_dir', 'ensure_list', 'check_array', 'validate_matrix_shape', 'isEmpty', 'canonicalize',
    'canHandle', 'is_valid_index_factory', 'require_relative']) {
    assert.equal(isGuardName(n, 'js'), false, n);
  }
});

test('CWE comes from the guard, then the value role, then the primitive', () => {
  assert.equal(concernOf('RequireDocAccess', 'docid', 's.store.Update').cwe, 'CWE-862');
  assert.equal(concernOf('validateWebhookUrl', 'url', 'this.client.post').cwe, 'CWE-918');
  assert.equal(concernOf('ensure_inside_root', 'name', 'os.path.join').cwe, 'CWE-22');
  assert.equal(concernOf('validate_target!', 'target', 'system').cwe, 'CWE-78');
  assert.equal(concernOf('checkSortColumn', 'column', 'db.query').cwe, 'CWE-89');
  assert.equal(concernOf('validateLabel', 'label', 'this.repo.save').cwe, 'CWE-20');
});

test('string and regex literal contents are masked, so quotes and braces inside them do not break units', () => {
  const src = jsService([
    '  a(url) {\n    validateUrl(url);\n    const re = /["\'{]/g;\n    return this.http.post(url, "}{");\n  }',
    '  b(url) {\n    validateUrl(url);\n    return this.http.post(url, `}${1}`);\n  }',
    '  c(url) {\n    return this.http.post(url, \'{\');\n  }',
  ]);
  assert.deepEqual(run('a.js', src).map(x => x.name), ['c']);
});

test('Go: units, parameters and the authz CWE', () => {
  const src = fs.readFileSync(path.join(FIX, 'sibling-guard-go', 'vulnerable', 'docs.go'), 'utf8');
  const units = _valueInternals.functionUnits('go', _valueInternals.maskStrings(src, 'go'));
  assert.deepEqual(units.map(u => u.name), ['RenameDoc', 'ShareDoc', 'ArchiveDoc']);
  assert.deepEqual(units[2].params, ['ctx', 'user', 'docID']);
});

test('the rule is reachable through a real scan, and the fixed twin is silent through it too', async () => {
  setStateWritesEnabled(false);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sgdev-'));
  try {
    for (const kind of ['vulnerable', 'clean']) {
      const dir = path.join(tmp, kind);
      fs.cpSync(path.join(FIX, 'sibling-guard-js', kind), dir, { recursive: true });
      const { scan } = await runScan(dir);
      const hits = (scan.findings || []).filter(f => String(f.id || '').startsWith('convention-deviation:value-guard-omitted:'));
      if (kind === 'vulnerable') {
        assert.equal(hits.length, 1, `expected the rule through runScan, got ${JSON.stringify((scan.findings || []).map(f => f.vuln))}`);
        assert.equal(hits[0].line, 26);
      } else {
        assert.deepEqual(hits, []);
      }
    }
  } finally {
    setStateWritesEnabled(true);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
