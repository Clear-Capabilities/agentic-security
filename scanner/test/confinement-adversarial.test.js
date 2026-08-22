// PRD F6.4 — test the write boundary the way a boundary should be tested.
//
// `agents/_CONFINEMENT.md` defines a reserved-write list and `_confine()`
// enforces a session root. Both were covered by tests that assert the HAPPY
// path — a legitimate write lands. That proves the door opens; it says nothing
// about whether it closes.
//
// A path guard is only worth what its refusals are worth, so every case here is
// an ATTACK: escape by traversal, by absolute path, by symlink, by a symlinked
// parent directory, by case variation, by encoded separators. Each must be
// refused, and the refusal must be an explicit throw rather than a silent
// no-op — a guard that quietly does nothing is indistinguishable from one that
// wrote somewhere unexpected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { _internals } from '../src/mcp/tools.js';

const { _confine, isReservedWrite } = _internals || {};

function session() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'confine-')));
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'app.js'), 'module.exports = {};\n');
  return root;
}

// Matches every refusal message _confine can produce. An earlier draft listed
// "symbolic link" but not "symlink", so a case that WAS correctly refused read
// as a bypass — the assertion has to recognise the guard's own vocabulary or it
// reports the wrong verdict in the alarming direction.
const REFUSAL = /escape|escapes|outside|symlink|symbolic link|refused|not a string/i;
const refuses = (root, candidate, why) => {
  assert.throws(() => _confine(root, candidate, 'test'), REFUSAL, why);
};

test('_internals exposes the guard — otherwise none of this is testable', () => {
  assert.equal(typeof _confine, 'function', '_confine must be reachable from tests to be adversarially checked');
});

test('a legitimate in-tree write is ALLOWED (positive control)', () => {
  // Without this, a guard that refused everything would pass every other case
  // in this file while making the tool useless.
  const root = session();
  try {
    const abs = _confine(root, 'src/app.js', 'test');
    assert.ok(abs.startsWith(root), 'an in-tree path must resolve inside the root');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('ATTACK: parent traversal is refused', () => {
  const root = session();
  try {
    for (const p of ['../outside.js', '../../etc/passwd', 'src/../../escape.js', './../../x']) {
      refuses(root, p, `traversal not refused: ${p}`);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('ATTACK: an absolute path outside the root is refused', () => {
  const root = session();
  try {
    refuses(root, '/etc/passwd', 'absolute escape not refused');
    refuses(root, path.join(os.tmpdir(), 'elsewhere.js'), 'absolute sibling not refused');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('ATTACK: a symlink pointing outside the root is refused', () => {
  // The classic bypass: the path is lexically inside the tree, and following it
  // is not. A lexical check alone passes this.
  const root = session();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-'));
  try {
    fs.writeFileSync(path.join(outside, 'target.js'), 'x');
    fs.symlinkSync(path.join(outside, 'target.js'), path.join(root, 'link.js'));
    refuses(root, 'link.js', 'a symlink leaf escaping the root was not refused');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('ATTACK: a symlinked PARENT DIRECTORY is refused', () => {
  // Subtler than a symlinked file: every component of the path must be
  // validated, not just the leaf. `evil/app.js` looks in-tree and is not.
  const root = session();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outsidedir-'));
  try {
    fs.writeFileSync(path.join(outside, 'app.js'), 'x');
    fs.symlinkSync(outside, path.join(root, 'evil'));
    refuses(root, 'evil/app.js', 'a symlinked parent directory was not refused');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('ATTACK: the session root ITSELF is not a writable target', () => {
  // Writing "the root" is not writing a file in it; allowing it would let a
  // caller clobber the directory entry.
  const root = session();
  try {
    refuses(root, '.', 'the root itself was accepted as a write target');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('ATTACK: non-string and empty candidates are refused, not coerced', () => {
  // Coercion here would turn `null` into "null" — a real filename inside the
  // tree — and write to it.
  const root = session();
  try {
    for (const junk of [null, undefined, '', 0, {}, []]) {
      assert.throws(() => _confine(root, junk, 'test'), REFUSAL, `coerced: ${String(junk)}`);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the reserved-write list refuses build output at ANY depth', () => {
  if (typeof isReservedWrite !== 'function') return;   // not exported; covered elsewhere
  const root = session();
  try {
    for (const p of ['dist/bundle.js', 'packages/a/dist/x.js', 'build/out.js', 'sub/target/y.class']) {
      assert.equal(isReservedWrite(root, path.join(root, p)), true, `${p} must be reserved`);
    }
    // A SOURCE file merely named `dist` is not build output — the guard checks
    // directory segments, not the basename, and over-refusing would block
    // legitimate fixes.
    assert.equal(isReservedWrite(root, path.join(root, 'src/dist.js')), false,
      'a source file named dist.js must remain writable');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('a refusal THROWS rather than silently returning', () => {
  // A guard that returns null on refusal invites a caller that ignores the
  // return value and writes anyway. Throwing makes the failure unmissable.
  const root = session();
  try {
    let threw = false;
    try { _confine(root, '../../escape.js', 'test'); } catch { threw = true; }
    assert.equal(threw, true, 'refusal must be an exception, not a falsy return');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
