import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LINEAGE_DIR = path.join(__dirname, '../../src/lineage');

test('obligation-mapping.js, obligation-predicates.js, and decision-story.js never import scenario.js or scenario-engine.js', () => {
  for (const file of ['obligation-mapping.js', 'obligation-predicates.js', 'decision-story.js']) {
    const src = fs.readFileSync(path.join(LINEAGE_DIR, file), 'utf8');
    assert.ok(!src.includes("from './scenario.js'"), `${file} must not import scenario.js`);
    assert.ok(!src.includes("from './scenario-engine.js'"), `${file} must not import scenario-engine.js`);
  }
});
