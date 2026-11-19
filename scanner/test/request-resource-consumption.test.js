// Request-driven resource consumption: src/sast/request-sized-resource.js (CWE-770 / CWE-400 / CWE-407)
// and src/sast/resource-limit-disabled.js (CWE-770 / CWE-400 / CWE-674). Each vulnerable fixture fires at
// exactly the listed lines; each clean fixture adds only the bound the rule asks for and is silent. The
// refusing cases below pin the precision rules: no request evidence, no finding.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRequestSizedResource } from '../src/sast/request-sized-resource.js';
import { scanResourceLimitDisabled } from '../src/sast/resource-limit-disabled.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (dir, kind, name) => fs.readFileSync(path.join(here, 'fixtures', dir, kind, name), 'utf8');
const sig = (fs_) => fs_.map((f) => `${f.line}:${f.cwe}`).sort();

function pair(fn, dir, name, want, as = `src/${name}`) {
  test(`${dir}/${name}: vulnerable fires at ${want.join(', ')}, clean is silent`, () => {
    assert.deepEqual(sig(fn(as, read(dir, 'vulnerable', name))), [...want].sort());
    assert.deepEqual(fn(as, read(dir, 'clean', name)), []);
  });
}

describe('request-sized allocation, iteration and quadratic work', () => {
  pair(scanRequestSizedResource, 'request-sized-resource-js', 'pad.js', ['6:CWE-770', '7:CWE-770', '8:CWE-770', '19:CWE-407']);
  pair(scanRequestSizedResource, 'request-sized-resource-py', 'views.py', ['10:CWE-770', '16:CWE-770', '25:CWE-407']);
  pair(scanRequestSizedResource, 'request-sized-resource-java', 'ReportController.java', ['13:CWE-770', '21:CWE-400', '31:CWE-407']);
  pair(scanRequestSizedResource, 'request-sized-resource-go', 'handler.go', ['15:CWE-770', '17:CWE-770', '25:CWE-407']);
  pair(scanRequestSizedResource, 'request-sized-resource-php', 'banner.php', ['6:CWE-770', '12:CWE-770', '21:CWE-407']);
  pair(scanRequestSizedResource, 'request-sized-resource-rb', 'reports_controller.rb', ['4:CWE-770', '9:CWE-770', '10:CWE-400'], 'app/controllers/reports_controller.rb');
  pair(scanRequestSizedResource, 'request-sized-resource-kt', 'Routes.kt', ['10:CWE-770', '11:CWE-770']);
  pair(scanRequestSizedResource, 'request-sized-resource-cs', 'BufferController.cs', ['8:CWE-770', '16:CWE-770']);

  test('findings carry the required schema fields', () => {
    for (const f of scanRequestSizedResource('src/views.py', read('request-sized-resource-py', 'vulnerable', 'views.py'))) {
      for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) assert.ok(f[k], k);
      assert.equal(f.family, 'resource-exhaustion');
      assert.equal(f.severity, 'medium');
    }
  });

  test('a bare parameter is not a request value, whatever it is called', () => {
    const js = "function pad(count) {\n  return 'x'.repeat(count) + Buffer.alloc(count);\n}\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', js), []);
    const py = "from flask import Flask\ndef pad(count):\n    return 'x' * int(count)\n";
    assert.deepEqual(scanRequestSizedResource('src/a.py', py), []);
  });

  test('a lower-bound check is not a bound; an upper-bound comparison is', () => {
    const lower = "app.get('/a', (req, res) => {\n  const n = Number(req.query.n);\n  if (n < 1) return res.end();\n  res.send(new Uint8Array(n));\n});\n";
    assert.equal(scanRequestSizedResource('src/a.js', lower).length, 1);
    const upper = lower.replace('if (n < 1)', 'if (n < 1 || n > LIMIT)');
    assert.deepEqual(scanRequestSizedResource('src/a.js', upper), []);
    const reversed = lower.replace('if (n < 1)', 'if (MAX_N < n)');
    assert.deepEqual(scanRequestSizedResource('src/a.js', reversed), []);
  });

  test('a clamp in the argument, a ternary clamp or a validate call silences', () => {
    const base = "app.get('/a', (req, res) => {\n  const n = Number(req.query.n);\n  X\n  res.send(new Uint8Array(SIZE));\n});\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', base.replace('X', '').replace('SIZE', 'Math.min(n, 4096)')), []);
    assert.deepEqual(scanRequestSizedResource('src/a.js', base.replace('X', 'const m = n > CAP ? CAP : n;').replace('SIZE', 'm')), []);
    assert.deepEqual(scanRequestSizedResource('src/a.js', base.replace('X', 'validateSize(n);').replace('SIZE', 'n')), []);
    assert.equal(scanRequestSizedResource('src/a.js', base.replace('X', '').replace('SIZE', 'n')).length, 1);
  });

  test('a loop bounded by the input\'s own length walks held data and is not a finding', () => {
    const js = "app.post('/a', (req, res) => {\n  for (let i = 0; i < req.body.items.length; i++) { use(i); }\n  res.end();\n});\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', js), []);
  });

  test('where a string cannot be a size, a value with no numeric conversion is not a finding', () => {
    const py = "from flask import request\n\n@app.route('/a')\ndef a():\n    n = request.args.get('n')\n    return 'x' * n\n";
    assert.deepEqual(scanRequestSizedResource('src/a.py', py), []);
    assert.equal(scanRequestSizedResource('src/a.py', py.replace("request.args.get('n')", "int(request.args.get('n'))")).length, 1);
    const js = "app.get('/a', (req, res) => res.send(new Array(req.query.n)));\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', js), []);
  });

  test('Python request.* needs a web framework import (an outgoing request is not input)', () => {
    const py = "def build(request):\n    n = int(request.json['n'])\n    return 'x' * n\n";
    assert.deepEqual(scanRequestSizedResource('src/a.py', py), []);
    assert.equal(scanRequestSizedResource('src/a.py', 'from flask import request\n' + py).length, 1);
  });

  test('Ruby params[...] counts only in a controller or routing DSL', () => {
    const rb = "class Builder\n  def run\n    n = params[:n].to_i\n    Array.new(n)\n  end\nend\n";
    assert.deepEqual(scanRequestSizedResource('lib/builder.rb', rb), []);
    assert.equal(scanRequestSizedResource('app/controllers/builder_controller.rb', rb).length, 1);
  });

  test('Go: ranging over a request slice is not an integer range', () => {
    const go = 'package a\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tparts := r.Form["p"]\n\tfor i := range parts {\n\t\t_ = i\n\t}\n}\n';
    assert.deepEqual(scanRequestSizedResource('src/a.go', go), []);
    const goInt = 'package a\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tn, _ := strconv.Atoi(r.FormValue("n"))\n\tfor i := range n {\n\t\t_ = i\n\t}\n}\n';
    assert.equal(scanRequestSizedResource('src/a.go', goInt).length, 1);
  });

  test('body fields are silent in a file that uses a validation library', () => {
    const js = "const Joi = require('joi');\napp.post('/a', (req, res) => {\n  const n = Number(req.body.n);\n  res.send(new Uint8Array(n));\n});\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', js), []);
  });

  test('the result of a lookup keyed by a request value is not a caller-chosen size', () => {
    const js = "app.get('/b/:id', async (req, res) => {\n  const basket = await Basket.findOne({ where: { id: req.params.id } });\n  for (let i = 0; i < basket.Products.length; i++) { use(i); }\n  res.send(new Uint8Array(basket.total));\n});\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', js), []);
  });

  test('benchmark and example directories are skipped', () => {
    const js = "app.get('/a', (req, res) => res.send(new Uint8Array(Number(req.query.n))));\n";
    assert.equal(scanRequestSizedResource('src/a.js', js).length, 1);
    assert.deepEqual(scanRequestSizedResource('bench/a.js', js), []);
    assert.deepEqual(scanRequestSizedResource('examples/a.js', js), []);
  });

  test('a membership check against a Set is not quadratic', () => {
    const js = "app.post('/a', (req, res) => {\n  const seen = new Set();\n  for (const t of req.body.tags) { if (!seen.has(t)) seen.add(t); }\n  res.end();\n});\n";
    assert.deepEqual(scanRequestSizedResource('src/a.js', js), []);
  });

  test('test code is skipped', () => {
    assert.deepEqual(scanRequestSizedResource('test/views.py', read('request-sized-resource-py', 'vulnerable', 'views.py')), []);
  });
});

describe('request size limits disabled, unbounded body reads, archive bombs', () => {
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-js', 'server.js', ['5:CWE-770', '9:CWE-770']);
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-py', 'settings.py', ['3:CWE-770', '4:CWE-770']);
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-py', 'upload.py', ['11:CWE-400', '18:CWE-400']);
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-java', 'UploadServlet.java', ['17:CWE-770', '22:CWE-400']);
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-java', 'application.properties', ['2:CWE-770', '3:CWE-770'], 'src/main/resources/application.properties');
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-go', 'upload.go', ['11:CWE-770', '23:CWE-400']);
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-php', 'import.php', ['6:CWE-400', '14:CWE-400']);
  pair(scanResourceLimitDisabled, 'resource-limit-disabled-rb', 'feeds_controller.rb', ['3:CWE-674', '8:CWE-400'], 'app/controllers/feeds_controller.rb');

  test('a body collector on a loopback-only server is not reachable by a remote caller', () => {
    const js = "const s = http.createServer((req, res) => {\n  const chunks = [];\n  req.on('data', (c) => chunks.push(c));\n});\ns.listen(0, '127.0.0.1');\n";
    assert.deepEqual(scanResourceLimitDisabled('src/a.js', js), []);
    assert.equal(scanResourceLimitDisabled('src/a.js', js.replace("'127.0.0.1'", "'0.0.0.0'")).length, 1);
  });

  test('a -1 outside a Spring application properties file is not a limit', () => {
    assert.deepEqual(scanResourceLimitDisabled('src/other.properties', 'max-file-size=-1\n'), []);
  });

  test('huge_tree needs request input in the file', () => {
    const py = "from lxml import etree\ndef load(path):\n    return etree.parse(path, etree.XMLParser(huge_tree=True))\n";
    assert.deepEqual(scanResourceLimitDisabled('src/a.py', py), []);
  });

  test('decompressing a local file is not an archive bomb from the request', () => {
    const py = "import zlib\ndef load(path):\n    with open(path, 'rb') as f:\n        return zlib.decompress(f.read())\n";
    assert.deepEqual(scanResourceLimitDisabled('src/a.py', py), []);
  });

  test('raw-body with a limit is silent, without one fires', () => {
    assert.equal(scanResourceLimitDisabled('src/a.js', 'const b = await getRawBody(req);\n').length, 1);
    assert.deepEqual(scanResourceLimitDisabled('src/a.js', "const b = await getRawBody(req, { limit: '1mb' });\n"), []);
  });

  test('test code is skipped', () => {
    assert.deepEqual(scanResourceLimitDisabled('tests/settings.py', read('resource-limit-disabled-py', 'vulnerable', 'settings.py')), []);
  });
});
