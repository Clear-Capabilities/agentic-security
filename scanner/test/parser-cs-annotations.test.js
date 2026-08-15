// C# ASP.NET Core attribute extraction tests.
//
// Tests that the C# IR parser extracts [FromQuery]/[FromBody]/etc. attributes
// from controller-method parameters and populates fn.paramAnnotations.
// This is part of PRD R14(a) — annotation/decorator-shaped framework sources.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseCSharpFile } from '../src/ir/parser-cs.js';
import { runScan } from '../src/runScan.js';

test('parseCSharpFile: [FromQuery] attribute on a parameter populates fn.paramAnnotations', () => {
  const code = `
public class UserController {
    public string Show([FromQuery] string q) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('UserController.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q'], 'fn.params must stay plain strings, unaffected by this change');
  assert.ok(fn.paramAnnotations, 'expected paramAnnotations to be populated');
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'FromQuery' }]);
});

test('parseCSharpFile: a parameter with no attribute gets no paramAnnotations entry', () => {
  const code = `
public class Helper {
    public string Show(string q) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('Helper.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.ok(!fn.paramAnnotations || fn.paramAnnotations.length === 0, 'no attribute present — paramAnnotations must be absent or empty');
});

test('parseCSharpFile: multiple parameters, only the attributed one is recorded', () => {
  const code = `
public class UserController {
    public string Show([FromQuery] string q, string extra) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('UserController.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.deepEqual(fn.params, ['q', 'extra']);
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'FromQuery' }]);
});

test('parseCSharpFile: stacked attributes [Required][FromQuery] captures all decorators', () => {
  const code = `
public class UserController {
    public string Show([Required][FromQuery] string q) {
        return q;
    }
}
`;
  const ir = parseCSharpFile('UserController.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('Show'));
  assert.deepEqual(fn.params, ['q']);
  assert.ok(fn.paramAnnotations);
  // Both decorators should be captured
  assert.equal(fn.paramAnnotations.length, 2);
  const decoratorNames = fn.paramAnnotations.map(pa => pa.decorator);
  assert.ok(decoratorNames.includes('Required'));
  assert.ok(decoratorNames.includes('FromQuery'));
  // Both should reference the same parameter
  assert.ok(fn.paramAnnotations.every(pa => pa.name === 'q'));
});

test('R14(a) end-to-end: ASP.NET Core [FromQuery] flowing to a SQL sink is detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14a-cs-'));
  fs.writeFileSync(path.join(dir, 'UserController.cs'), `
public class UserController {
    public string Get([FromQuery] string id) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id='" + id + "'");
        return cmd.ExecuteScalar();
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an annotation-sourced SQL injection finding, got ${irFindings.length} IR-TAINT findings`);
});
