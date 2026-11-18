// A write handler gated only by read permissions (CWE-285), src/sast/read-permission-write.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanReadPermissionWrite as scan } from '../src/sast/read-permission-write.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'read-permission-write');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'ReadingResource.java'), 'utf8');

test('the write handler guarded by read permissions is reported at its first read guard; the read handler is not', () => {
  const code = read('vulnerable');
  const out = scan('ReadingResource.java', code);
  assert.equal(out.length, 1);
  assert.equal(out[0].line, 16);
  assert.equal(out[0].cwe, 'CWE-285');
  assert.match(out[0].vuln, /writeReadings/);
});

test('the fixed version, with write permissions, is silent', () => {
  assert.deepEqual(scan('ReadingResource.java', read('clean')), []);
});

test('a write with no denial, an annotated GET, and a read token mentioned outside a guard are silent', () => {
  assert.deepEqual(scan('A.java', 'class A {\n  public void saveX(String id) {\n    log(READ_DEVICES);\n    store.save(id);\n  }\n}\n'), []);
  const get = read('vulnerable').replace('    public void writeReadings', '    @GET\n    public void writeReadings');
  assert.deepEqual(scan('ReadingResource.java', get), []);
  assert.deepEqual(scan('test/ReadingResource.java', read('vulnerable')), []);
});
