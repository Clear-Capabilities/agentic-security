// A per-item predicate used to filter a listing but not enforced on the matching write (CWE-266 / CWE-285),
// src/sast/filter-enforce-asymmetry.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanFilterEnforceAsymmetry as scan } from '../src/sast/filter-enforce-asymmetry.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'filter-enforce-asymmetry');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'GroupRolesResource.java'), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

test('the loop that grants request-supplied roles without the filter predicate is reported at the mutation', () => {
  const code = read('vulnerable');
  const out = scan('GroupRolesResource.java', code);
  assert.deepEqual(out.map((f) => f.line), [lineOf(code, 'group.grantRole(role);')]);
  assert.equal(out[0].cwe, 'CWE-266', 'granting a role is a privilege assignment');
});

test('enforcing the predicate in the loop is silent', () => {
  assert.deepEqual(scan('GroupRolesResource.java', read('clean')), []);
});

test('no filter predicate, a non-privilege mutation, and a loop over a non-parameter', () => {
  assert.deepEqual(scan('A.java', read('vulnerable').replace('.filter(perms::canGrantRole)', '')), []);
  const tag = read('vulnerable').replace(/grantRole\(role\)/, 'attachTag(role)').replace(/addRoles/, 'addTags');
  assert.equal(scan('A.java', tag)[0].cwe, 'CWE-285');
  const local = read('vulnerable').replace('for (RoleRep rep : picked)', 'for (RoleRep rep : defaults)');
  assert.deepEqual(scan('A.java', local), []);
});
