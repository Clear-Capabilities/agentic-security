// FIX-DISCRIMINATION: a throwing validator call is a path-traversal guard.
//
// From GHSA-q939-rpr3-3284 (sshnet/SSH.NET). A malicious SCP server can send
// a file name containing a directory separator, which is then combined into a
// local path and escapes the destination directory. The upstream fix adds a
// throwing validator immediately before each sink:
//
//     EnsureValidLocalName(filename);
//     newDirectoryInfo = Directory.CreateDirectory(
//         Path.Combine(currentDirectoryFullName, filename));
//
// _PATH_GUARD_RE was a closed list of blessed names (basename, GetFileName,
// secure_filename, safe_join, startsWith, …). A project's own validator can
// never appear in such a list, so the finding fired identically on the fixed
// revision — the same closed-enumeration defect already fixed this session in
// ownership-authz (verb list), resource-exhaustion (source vocabulary) and
// redirect-toctou (mitigation shape).
//
// Recognising the SHAPE is safe here because the existing guard machinery
// (_guardMatchNearSinkIdentifier) already requires the guard to mention the
// same identifier that flows into the sink. A bare `Check(somethingElse)`
// nearby does not qualify — pinned by the last test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dropGuardedFindings } from '../src/engine.js';

const FILE = 'ScpClient.cs';
const finding = (line) => ({
  id: `csharp:path:${FILE}:${line}`, file: FILE, line,
  cwe: 'CWE-22', vuln: 'Path Traversal', severity: 'high', parser: 'CSHARP',
});
const keep = (src, line) =>
  dropGuardedFindings([finding(line)], { [FILE]: src }).length === 1;

// Verbatim shape from post/ — the fixed revision.
const GUARDED = [
  'if (directoryCounter > 0)',
  '{',
  '    EnsureValidLocalName(filename);',
  '',
  '    newDirectoryInfo = Directory.CreateDirectory(Path.Combine(currentDirectoryFullName, filename));',
  '}',
].join('\n');

// Verbatim shape from pre/ — the vulnerable revision, no validator.
const UNGUARDED = [
  'if (directoryCounter > 0)',
  '{',
  '    newDirectoryInfo = Directory.CreateDirectory(Path.Combine(currentDirectoryFullName, filename));',
  '}',
].join('\n');

test('REAL CODE: the vulnerable revision is still reported', () => {
  assert.equal(keep(UNGUARDED, 3), true);
});

test('REAL CODE: the upstream validator call silences it (fix-discrimination)', () => {
  assert.equal(keep(GUARDED, 5), false,
    'EnsureValidLocalName(filename) guards the very identifier that reaches Path.Combine');
});

test('other validation verbs in the same shape also count', () => {
  for (const call of ['ValidateFileName(filename);', 'AssertSafeName(filename);', 'RequirePlainName(filename);']) {
    const src = ['{', `    ${call}`, '    var p = Path.Combine(root, filename);', '}'].join('\n');
    assert.equal(keep(src, 3), false, `${call} should read as a guard`);
  }
});

test('REFUSES: a validator on a DIFFERENT identifier is not a guard', () => {
  const src = [
    '{',
    '    EnsureValidLocalName(unrelatedName);',
    '    var p = Path.Combine(root, filename);',
    '}',
  ].join('\n');
  assert.equal(keep(src, 3), true,
    'the guard must mention the identifier that actually reaches the sink');
});

test('REFUSES: bare require() is a module import, not a validator', () => {
  // Caught by the cve-replay corpus gate: `require('koa-send')` matched a
  // `\w{0,40}` verb pattern and silenced two real path-traversal entries
  // (CVE-2018-3774-koa-path, CVE-2018-3811-fs-path-traversal-shape).
  // A validator worth trusting names what it validates, so at least one
  // further word character is now required — which also drops bare
  // `check(` / `assert(`, too generic to read as a containment guard.
  const src = [
    "const send = require('koa-send');",
    'app.use(async (ctx) => {',
    '  await send(ctx, ctx.path, { root: "/" });',
    '});',
  ].join('\n');
  assert.equal(keep(src, 3), true);
});
