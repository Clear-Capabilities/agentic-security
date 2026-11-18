// Rails controller skipping its auth filter for every action while declaring per-action levels (CWE-287),
// src/sast/rails-skip-auth-filter.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRailsSkipAuthFilter as scan } from '../src/sast/rails-skip-auth-filter.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'rails-skip-auth-filter');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'accounts_controller.rb'), 'utf8');
const F = 'app/controllers/accounts_controller.rb';

test('an unconditional skip of the filter the level declarations rely on is reported at the skip', () => {
  const out = scan(F, read('vulnerable'));
  assert.deepEqual(out.map((f) => f.line), [3]);
  assert.equal(out[0].cwe, 'CWE-287');
});

test('a skip limited with only:/except: (also on a continuation line) is silent', () => {
  assert.deepEqual(scan(F, read('clean')), []);
  const multi = read('vulnerable').replace('skip_before_action :authenticate_for_action', 'skip_before_action :authenticate_for_action,\n                     except: [:reset_password]');
  assert.deepEqual(scan(F, multi), []);
});

test('an unrelated filter, a controller without level declarations, and a non-controller file are silent', () => {
  assert.deepEqual(scan(F, read('vulnerable').replace(':authenticate_for_action', ':set_locale')), []);
  assert.deepEqual(scan(F, read('vulnerable').replace(/^ {2}action_auth_level.*\n/gm, '')), []);
  assert.deepEqual(scan('app/models/account.rb', read('vulnerable')), []);
  assert.deepEqual(scan(F, read('vulnerable').replace(':authenticate_for_action', ':authorize_user_for_course')), [], 'the macro does not belong to that filter');
});
