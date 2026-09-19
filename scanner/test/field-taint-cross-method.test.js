// Cross-method field taint (SARD_80_F1_SCANNER_PRD.md, Juliet flow variants
// 45 / 65-68): a method writes a tainted value into a class field (static or
// instance) and a DIFFERENT method of the same class reads that field into a
// sink. Before this existed the engine's only field mechanism keyed on the
// `_this_.field` mutated-param shape parser-js.js emits, so every hand-rolled
// parser's flat `sf = data` / `this.inst = data` write was invisible across
// methods, and the reading method's sink never fired.
//
// Every test asserts `parser === 'IR-TAINT'`: a pattern rule firing on the same
// line would otherwise mask a taint-layer miss.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

async function scanSource(name, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-field-taint-'));
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', name), body);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
}

const cmdi = (findings) => findings.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-78');

test('static field written from a source in one method taints a sink in a sibling method', async () => {
  const findings = await scanSource('A.cs', `using System;
using System.Diagnostics;
public class A {
    private static string sf;
    public void Bad() {
        string data = Environment.GetEnvironmentVariable("ADD");
        sf = data;
        BadSink();
    }
    private void BadSink() {
        string data = sf;
        Process.Start("cmd.exe", data);
    }
}
`);
  const hits = cmdi(findings);
  assert.ok(hits.length >= 1, `expected an IR-TAINT CWE-78 finding via the static field, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
  assert.ok(hits.some(f => f.line === 12), `expected the finding on the sink line 12, got lines ${hits.map(f => f.line)}`);
});

test('instance field written via this.field in one method taints a bare read in a sibling method', async () => {
  const findings = await scanSource('B.cs', `using System;
using System.Diagnostics;
public class B {
    private string inst;
    public void Bad() {
        string data = Environment.GetEnvironmentVariable("ADD");
        this.inst = data;
        BadSink();
    }
    private void BadSink() {
        string data = inst;
        Process.Start("cmd.exe", data);
    }
}
`);
  const hits = cmdi(findings);
  assert.ok(hits.length >= 1, `expected an IR-TAINT CWE-78 finding via the instance field, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('a field written only from a literal does not taint its readers', async () => {
  const findings = await scanSource('C.cs', `using System;
using System.Diagnostics;
public class C {
    private static string sfGood;
    public void Good() {
        string data = "constant";
        sfGood = data;
        GoodSink();
    }
    private void GoodSink() {
        string data = sfGood;
        Process.Start("cmd.exe", data);
    }
}
`);
  assert.equal(cmdi(findings).length, 0, `literal-only field must not fire: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('a same-named LOCAL in a sibling method is not confused with a field', async () => {
  const findings = await scanSource('D.cs', `using System;
using System.Diagnostics;
public class D {
    public void Bad() {
        string data = Environment.GetEnvironmentVariable("ADD");
        Console.WriteLine(data.Length);
    }
    private void Other() {
        string data = "safe";
        Process.Start("cmd.exe", data);
    }
}
`);
  assert.equal(cmdi(findings).length, 0, `a local named like another method's local must not cross-taint: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('a tainted field read through a collection element still reaches the sink', async () => {
  const findings = await scanSource('E.cs', `using System;
using System.Collections.Generic;
using System.Diagnostics;
public class E {
    public void Bad() {
        string data = Environment.GetEnvironmentVariable("ADD");
        List<string> list = new List<string>();
        list.Add(data);
        BadSink(list);
    }
    private void BadSink(List<string> list) {
        string data = list[0];
        Process.Start("cmd.exe", data);
    }
}
`);
  const hits = cmdi(findings);
  assert.ok(hits.length >= 1, `expected an IR-TAINT CWE-78 finding via List.Add + indexer, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

// SARD_80_F1 W5.50 — same-class call-string precision, mirroring W5.48's
// cross-class fix: a static field written by MULTIPLE sibling methods with
// DIFFERENT taint values, each immediately calling ITS OWN uniquely-named
// sink method (all still within ONE class this time, not split across two).
// Before this fix, `goodSink()` here would be wrongly seeded as tainted
// purely because `Bad()` (a completely different, unrelated caller) taints
// the same field via a different call path.
test('a same-class sibling sink reached only via a non-tainting writer is NOT seeded as tainted', async () => {
  const findings = await scanSource('F.cs', `using System;
using System.Diagnostics;
public class F {
    private static string data;
    public void Bad() {
        data = Environment.GetEnvironmentVariable("ADD");
        BadSink();
    }
    public void Good() {
        data = "constant";
        GoodSink();
    }
    private void BadSink() {
        string d = data;
        Process.Start("cmd.exe", d);
    }
    private void GoodSink() {
        string d = data;
        Process.Start("cmd.exe", d);
    }
}
`);
  const hits = cmdi(findings);
  const inBadSink = hits.some((f) => f.line >= 12 && f.line <= 15);
  const inGoodSink = hits.some((f) => f.line >= 16 && f.line <= 19);
  assert.ok(inBadSink, `expected BadSink (reached only by the tainting writer Bad()) to still fire: ${JSON.stringify(hits.map(f => f.line))}`);
  assert.ok(!inGoodSink, `expected GoodSink (reached only by the non-tainting writer Good()) NOT to fire: ${JSON.stringify(hits.map(f => f.line))}`);
});

test('a same-class sink with NO discoverable caller still fails closed (stays tainted)', async () => {
  const findings = await scanSource('G.cs', `using System;
using System.Diagnostics;
public class G {
    private static string data;
    public void Bad() {
        data = Environment.GetEnvironmentVariable("ADD");
    }
    private void OrphanSink() {
        string d = data;
        Process.Start("cmd.exe", d);
    }
}
`);
  const hits = cmdi(findings);
  assert.ok(hits.length >= 1, `expected fail-closed (still tainted) with no discoverable caller for OrphanSink: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});
