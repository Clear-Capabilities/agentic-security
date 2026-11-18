// PHP raw SQL built by value substitution (CWE-89), src/sast/php-raw-sql-substitution.js.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanPhpRawSqlSubstitution as scan } from '../src/sast/php-raw-sql-substitution.js';
import { runScan } from '../src/runScan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (kind) => path.join(here, 'fixtures', 'php-raw-sql-substitution', kind);
const lines = (code) => scan('a.php', `<?php\n${code}`).map((f) => f.line - 1);

describe('php-raw-sql-substitution', () => {
  test('a raw query method given a substitution call and no bindings', () => {
    assert.deepEqual(lines("$q->whereRaw(strtr($t, [':v' => $v]));"), [1]);
    assert.deepEqual(lines("$q->orderByRaw(wrap(str_replace(':c', $col, $t)));"), [1], 'one wrapping call');
    assert.deepEqual(lines("DB::raw(sprintf(\"a = '%s'\", $v));"), [1]);
    assert.deepEqual(lines("$q->whereRaw(strtr($t, [\n  ':v' => $v,\n]));"), [1], 'multi-line');
  });

  test('bindings, quoted or numeric values and numeric formats are silent', () => {
    assert.deepEqual(lines("$q->whereRaw(strtr($t, [':v' => '?']), [$v]);"), [], 'bindings argument');
    assert.deepEqual(lines("$q->whereRaw(strtr($t, [':v' => $pdo->quote($v)]));"), []);
    assert.deepEqual(lines("$q->whereRaw(strtr($t, [':v' => (int) $v]));"), []);
    assert.deepEqual(lines("$f = DB::getPdo()->quote($v);\n$q->whereRaw(strtr($t, [':v' => $f]));"), [], 'a local assigned a quoted value');
    assert.deepEqual(lines("$q->whereRaw(sprintf('a > %d AND b < %.2f', $v, $w));"), []);
    assert.deepEqual(lines("$q->whereRaw($sql);"), [], 'not a substitution call');
    assert.deepEqual(lines("// $q->whereRaw(strtr($t, [':v' => $v]));"), [], 'comment');
  });

  test('IN (...) built by implode over a decoded or request array', () => {
    assert.deepEqual(lines('$w = "id IN (" . implode(",", json_decode($s, true)) . ")";'), [1]);
    assert.deepEqual(lines('$w = "id IN (" . implode(",", explode(",", $s)) . ")";'), [1]);
    assert.deepEqual(lines('$w = "id IN (" . implode(",", $_GET[\'ids\']) . ")";'), [1]);
    assert.deepEqual(lines('$w = "id IN (" . implode(",", array_map(\'intval\', json_decode($s, true))) . ")";'), []);
    assert.deepEqual(lines('$w = "id IN (" . implode(",", $ids) . ")";'), []);
  });

  test('fixtures: vulnerable fires on each shape, clean is silent', () => {
    const v = scan('ReportFilter.php', fs.readFileSync(path.join(fx('vulnerable'), 'ReportFilter.php'), 'utf8'));
    assert.deepEqual(v.map((f) => f.line), [7, 15, 20]);
    assert.ok(v.every((f) => f.cwe === 'CWE-89' && f.family === 'sql-injection'));
    assert.deepEqual(scan('ReportFilter.php', fs.readFileSync(path.join(fx('clean'), 'ReportFilter.php'), 'utf8')), []);
  });

  test('end to end through the engine', async () => {
    const hits = async (dir) => [...new Set((await runScan(dir)).scan.findings
      .filter((f) => /^php-(?:rawSubstitution|implodeInList):/.test(f.id)).map((f) => f.line))].sort((a, b) => a - b);
    assert.deepEqual(await hits(fx('vulnerable')), [7, 15, 20]);
    assert.deepEqual(await hits(fx('clean')), []);
  });
});
