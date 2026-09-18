// SARD_80_F1 W5.9/W5.10 — two independent, previously-undiscovered PHP taint
// gaps, found while investigating why the SARD PHP corpus's CWE-91/98 stay
// stuck at tp=0 despite a confirmed-working sink (W5.2/W5.5).
//
// W5.9: general array/subscript access (`$arr[key]`, both read and write)
// had NO lowering in the IR at all — a read fell through to
// `{kind:'unknown'}` and a WRITE silently vanished from the CFG entirely
// (not even an `unknown`-kind node). Only the hardcoded superglobal
// special-case (`$_GET['x']` etc.) worked. Separately, a member-chain
// assignment target (`$this->prop = …`) kept its literal `->` separator,
// while `accessPathOf` computes a READ of the same property using `.`
// (`this.prop`) — two different strings that could never match, breaking
// every PHP object-property taint round-trip, even same-scope ones.
//
// W5.10: PHP never emitted `ir.classes` at all, so `dataflow/engine.js`'s
// cross-method field-taint pass (a general, already-C#/Java-proven
// mechanism) had no declared-field list to work from for any PHP class.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '../src/runScan.js';
import { parsePhpFile } from '../src/ir/parser-php.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'php-array-field-'));
}

async function findings(body) {
  const dir = tmpDir();
  try {
    fs.writeFileSync(path.join(dir, 'test.php'), body);
    const { scan } = await runScan(dir, { deep: true });
    return scan.findings || [];
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('IR: a plain array element write is a real assign node (was: silently dropped)', () => {
  const ir = parsePhpFile('a.php', '<?php\n$arr = array();\n$arr[1] = $_GET["x"];\n$y = $arr[1];\n');
  const assigns = Object.values(ir.functions[0].cfg.nodes).filter((n) => n.kind === 'assign');
  const write = assigns.find((n) => n.target === '$arr.1');
  assert.ok(write, `expected an assign node targeting "$arr.1" — got targets: ${assigns.map((n) => n.target).join(',')}`);
  const read = assigns.find((n) => n.target === '$y');
  assert.equal(read.source.kind, 'member', 'expected the array read to lower to a member expression, not unknown');
});

test('IR: a member-chain assignment target uses "." (matching accessPathOf), not literal "->"', () => {
  const ir = parsePhpFile('a.php', '<?php\n$this_obj = new stdClass();\n$this_obj->input = $_GET["x"];\n');
  const assigns = Object.values(ir.functions[0].cfg.nodes).filter((n) => n.kind === 'assign');
  const write = assigns.find((n) => n.target === '$this_obj.input');
  assert.ok(write, `expected target "$this_obj.input" — got: ${assigns.map((n) => n.target).join(',')}`);
});

test('IR: a computed (non-literal) subscript key widens to the container ("*"), not a specific index', () => {
  const ir = parsePhpFile('a.php', '<?php\n$i = 1;\n$arr[$i] = $_GET["x"];\n');
  const assigns = Object.values(ir.functions[0].cfg.nodes).filter((n) => n.kind === 'assign');
  const write = assigns.find((n) => n.target === '$arr.*');
  assert.ok(write, `expected target "$arr.*" for a computed key — got: ${assigns.map((n) => n.target).join(',')}`);
});

test('IR: ir.classes carries declared field names for a PHP class (was: never emitted)', () => {
  const ir = parsePhpFile('a.php', '<?php\nclass Foo {\n  private $bar;\n  public $baz;\n  public function m(){}\n}\n');
  assert.ok(Array.isArray(ir.classes), 'expected ir.classes to be an array');
  const foo = ir.classes.find((c) => c.name === 'Foo');
  assert.ok(foo, 'expected a Foo class entry');
  assert.deepEqual([...foo.fields].sort(), ['bar', 'baz']);
});

test('end-to-end: a plain array element carries taint from $_GET into an XPath sink', async () => {
  const hits = await findings(
    '<?php\n' +
    '$arr = array();\n' +
    '$arr[1] = $_GET["UserData"];\n' +
    '$tainted = $arr[1];\n' +
    '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
    '$xml = simplexml_load_file("users.xml");\n' +
    '$res = $xml->xpath($query);\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(hit, `expected a CWE-91 finding via the array round-trip — got: ${hits.map((f) => `${f.parser}:${f.cwe}`).join(',')}`);
});

test('end-to-end: a same-scope object-property round trip carries taint into an XPath sink', async () => {
  const hits = await findings(
    '<?php\n' +
    '$obj = new stdClass();\n' +
    '$obj->input = $_GET["UserData"];\n' +
    '$tainted = $obj->input;\n' +
    '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
    '$xml = simplexml_load_file("users.xml");\n' +
    '$res = $xml->xpath($query);\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(hit, `expected a CWE-91 finding via the property round-trip — got: ${hits.map((f) => `${f.parser}:${f.cwe}`).join(',')}`);
});

test('end-to-end: a class field set in the constructor taints a sink in a SIBLING method of the same class', async () => {
  const hits = await findings(
    '<?php\n' +
    'class Input {\n' +
    '  private $input;\n' +
    '  public function __construct(){\n' +
    '    $this->input = $_GET["UserData"];\n' +
    '  }\n' +
    '  public function useIt(){\n' +
    '    $query = "//User[username/text()=\'". $this->input . "\']";\n' +
    '    $xml = simplexml_load_file("users.xml");\n' +
    '    $res = $xml->xpath($query);\n' +
    '  }\n' +
    '}\n' +
    '$temp = new Input();\n' +
    '$temp->useIt();\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(hit, `expected a cross-method field-taint CWE-91 finding — got: ${hits.map((f) => `${f.parser}:${f.cwe}`).join(',')}`);
});

test('a field written only from a literal does not taint a sibling method\'s read of it', async () => {
  const hits = await findings(
    '<?php\n' +
    'class Input {\n' +
    '  private $input;\n' +
    '  public function __construct(){\n' +
    '    $this->input = "safe";\n' +
    '  }\n' +
    '  public function useIt(){\n' +
    '    $query = "//User[username/text()=\'". $this->input . "\']";\n' +
    '    $xml = simplexml_load_file("users.xml");\n' +
    '    $res = $xml->xpath($query);\n' +
    '  }\n' +
    '}\n' +
    '$temp = new Input();\n' +
    '$temp->useIt();\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(!hit, 'a hardcoded-literal field must not fire the taint sink');
});

// SARD_80_F1 W3.x — the getter+return interprocedural-composition gap
// documented (not fixed) at W5.10: a field tainted in the constructor,
// read through a GETTER method whose RETURN VALUE is then used by an
// EXTERNAL caller with no arguments. The class-field cross-taint pass in
// engine.js previously cached its result only under the fields-keyed
// summary-cache entry, never the plain empty-context entry an ordinary
// no-arg call site (`$temp->getInput()`) actually consults.
test('end-to-end: a constructor-tainted field read through a GETTER, then used by an EXTERNAL no-arg caller, still reaches the sink', async () => {
  const hits = await findings(
    '<?php\n' +
    'class Input {\n' +
    '  private $input;\n' +
    '  public function __construct(){\n' +
    '    $this->input = $_GET["UserData"];\n' +
    '  }\n' +
    '  public function getInput(){\n' +
    '    return $this->input;\n' +
    '  }\n' +
    '}\n' +
    '$temp = new Input();\n' +
    '$tainted = $temp->getInput();\n' +
    '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
    '$xml = simplexml_load_file("users.xml");\n' +
    '$res = $xml->xpath($query);\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(hit, `expected a CWE-91 finding via the getter+return round-trip — got: ${hits.map((f) => `${f.parser}:${f.cwe}`).join(',')}`);
});

test('a getter returning a field written only from a literal does not taint an external no-arg caller', async () => {
  const hits = await findings(
    '<?php\n' +
    'class Input {\n' +
    '  private $input;\n' +
    '  public function __construct(){\n' +
    '    $this->input = "safe";\n' +
    '  }\n' +
    '  public function getInput(){\n' +
    '    return $this->input;\n' +
    '  }\n' +
    '}\n' +
    '$temp = new Input();\n' +
    '$tainted = $temp->getInput();\n' +
    '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
    '$xml = simplexml_load_file("users.xml");\n' +
    '$res = $xml->xpath($query);\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(!hit, 'a hardcoded-literal field read through a getter must not fire the taint sink');
});

// SARD_80_F1 W5.17 — a sibling gap to the getter+return fix above, found
// investigating PHP's CWE-95 (eval injection) recall: `isCoveredBy`
// deliberately never propagates UP (a set containing only "x.y.z" does not
// cover a query for "x.y" — its own documented, correct precision rule for
// ordinary field reads). But an ARRAY-INDEXED field write
// (`$this->input[1] = $_GET[...]`) taints the access path
// `this.input.1`/`$this.input.1`, not the bare field `this.input` this
// pass's own class-field-taint detection queries — so the getter+return
// mechanism above, already proven for a SCALAR field, silently never
// triggered at all for the array-indexed form (the PHP-Vuln-test-suite-
// generator's own "object/Array" input-indirection sample, confirmed via
// direct reproduction, not corpus access).
test('end-to-end: a constructor-tainted ARRAY-INDEXED field read through a getter, then used by an external no-arg caller, still reaches the sink', async () => {
  const hits = await findings(
    '<?php\n' +
    'class Input {\n' +
    '  private $input;\n' +
    '  public function __construct(){\n' +
    '    $this->input = array();\n' +
    '    $this->input[0] = "safe";\n' +
    '    $this->input[1] = $_GET["UserData"];\n' +
    '    $this->input[2] = "safe";\n' +
    '  }\n' +
    '  public function getInput(){\n' +
    '    return $this->input[1];\n' +
    '  }\n' +
    '}\n' +
    '$temp = new Input();\n' +
    '$tainted = $temp->getInput();\n' +
    '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
    '$xml = simplexml_load_file("users.xml");\n' +
    '$res = $xml->xpath($query);\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(hit, `expected a CWE-91 finding via the array-indexed getter+return round-trip — got: ${hits.map((f) => `${f.parser}:${f.cwe}`).join(',')}`);
});

test('a getter returning an array-indexed field written only from literals does not taint an external no-arg caller', async () => {
  const hits = await findings(
    '<?php\n' +
    'class Input {\n' +
    '  private $input;\n' +
    '  public function __construct(){\n' +
    '    $this->input = array();\n' +
    '    $this->input[0] = "safe";\n' +
    '    $this->input[1] = "safe";\n' +
    '    $this->input[2] = "safe";\n' +
    '  }\n' +
    '  public function getInput(){\n' +
    '    return $this->input[1];\n' +
    '  }\n' +
    '}\n' +
    '$temp = new Input();\n' +
    '$tainted = $temp->getInput();\n' +
    '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
    '$xml = simplexml_load_file("users.xml");\n' +
    '$res = $xml->xpath($query);\n'
  );
  const hit = hits.find((f) => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
  assert.ok(!hit, 'an all-literal array-indexed field read through a getter must not fire the taint sink');
});
