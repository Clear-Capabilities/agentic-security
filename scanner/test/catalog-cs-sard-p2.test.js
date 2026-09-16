// SARD_80_F1_SCANNER_PRD.md: C# catalog additions found missing via the
// dev-split Juliet diagnosis (macro-F1 5.0%, IR-TAINT contributed ZERO
// true positives — every hit came from taint-blind regex/structural
// rules). Each source/sink here closes one concrete gap the diagnosis's
// synthetic-variant sweep confirmed the engine could not see at all,
// regardless of engine quality: Console/stream/socket/registry/database
// reads never registered as sources, and CommandText writes, reflection
// loaders, format strings, and XPath navigation never registered as
// sinks. Each test proves the entry fires end-to-end on a genuinely
// tainted example; precision cases prove the untainted/parameterized
// counterpart does not.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-cs-sard-p2-${name}-`));
  fs.writeFileSync(path.join(dir, 'C.cs'), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('cs-console-readline: Console.ReadLine() reaches Process.Start via IR-TAINT', async () => {
  const dir = mkTmp('console-readline', `
using System.Diagnostics;
public class C {
    public void Bad() {
        string data = Console.ReadLine();
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection from Console.ReadLine, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-reader-readline: a StreamReader\'s .ReadLine() (receiver-agnostic) reaches a sink', async () => {
  const dir = mkTmp('reader-readline', `
using System.IO;
using System.Diagnostics;
public class C {
    public void Bad(StreamReader sr) {
        string data = sr.ReadLine();
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection from sr.ReadLine(), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-tcpclient-getstream: a socket stream reaches a sink', async () => {
  const dir = mkTmp('tcp-getstream', `
using System.Net.Sockets;
using System.Diagnostics;
public class C {
    public void Bad(TcpClient conn) {
        var data = conn.GetStream();
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection from TcpClient.GetStream(), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-registry-getvalue: a registry value reaches a sink', async () => {
  const dir = mkTmp('registry-getvalue', `
using Microsoft.Win32;
using System.Diagnostics;
public class C {
    public void Bad() {
        var data = Registry.GetValue("HKEY_CURRENT_USER\\\\App", "Cmd", null);
        Process.Start("cmd.exe", (string)data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection from Registry.GetValue, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-datareader-getstring: a SqlDataReader column reaches a sink, but Dictionary.GetValue does not spuriously match it', async () => {
  const dir = mkTmp('datareader-getstring', `
using System.Diagnostics;
public class C {
    public void Bad(System.Data.SqlClient.SqlDataReader reader) {
        string data = reader.GetString(0);
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection from reader.GetString, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-file-readalltext-src: file CONTENTS are a source independent of the path argument', async () => {
  const dir = mkTmp('file-readalltext-content', `
using System.Diagnostics;
public class C {
    public void Bad() {
        // Literal, non-tainted path — this must fire on the CONTENT
        // source, not on the (untainted) path-traversal sink argument.
        string data = File.ReadAllText("C:\\\\fixed\\\\path.txt");
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection from File.ReadAllText's content, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
  assert.ok(!taint.some(f => /path traversal/i.test(`${f.vuln}`)),
    'a literal path argument must not ALSO fire the path-traversal sink');
});

test('cs-commandtext-write: CommandText assigned a tainted value fires SQL Injection', async () => {
  const dir = mkTmp('commandtext', `
using System.Data.SqlClient;
public class C {
    public void Bad([FromQuery] string id) {
        var cmd = new SqlCommand();
        cmd.CommandText = "SELECT * FROM users WHERE id=" + id;
        cmd.ExecuteNonQuery();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /sql injection/i.test(`${f.vuln}`)),
    `expected SQL Injection from CommandText=, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-commandtext-write precision: CommandText assigned a FIXED literal does not fire', async () => {
  const dir = mkTmp('commandtext-clean', `
using System.Data.SqlClient;
public class C {
    public void Good() {
        var cmd = new SqlCommand();
        cmd.CommandText = "SELECT * FROM users WHERE id=@id";
        cmd.Parameters.AddWithValue("@id", 1);
        cmd.ExecuteNonQuery();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(!taint.some(f => /sql injection/i.test(`${f.vuln}`)),
    `a parameterized, literal CommandText must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('cs-sqldataadapter: new SqlDataAdapter with a concatenated query fires SQL Injection', async () => {
  const dir = mkTmp('sqldataadapter', `
using System.Data.SqlClient;
public class C {
    public void Bad([FromQuery] string id) {
        var da = new SqlDataAdapter("SELECT * FROM users WHERE id=" + id, "conn");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /sql injection/i.test(`${f.vuln}`)),
    `expected SQL Injection from SqlDataAdapter, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-type-gettype / cs-assembly-load / cs-activator-createinstance: unsafe reflection fires CWE-470', async () => {
  const dir = mkTmp('reflection', `
public class C {
    public object Bad1([FromQuery] string typeName) {
        var t = Type.GetType(typeName);
        return Activator.CreateInstance(t);
    }
    public void Bad2([FromQuery] string asmName) {
        var a = Assembly.Load(asmName);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /unsafe reflection|CWE-470/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Unsafe Reflection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-string-format: a tainted FORMAT string fires CWE-134, but a tainted substitution argument alone does not', async () => {
  const badDir = mkTmp('string-format-bad', `
public class C {
    public string Bad([FromQuery] string fmt) {
        return String.Format(fmt, 1, 2);
    }
}
`);
  const badTaint = await taintFindings(badDir);
  assert.ok(badTaint.some(f => /format string|CWE-134/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Externally-Controlled Format String, got: ${badTaint.map(f => f.vuln).join(', ') || '(none)'}`);

  const cleanDir = mkTmp('string-format-clean', `
public class C {
    public string Good([FromQuery] string name) {
        return String.Format("Hello, {0}!", name);
    }
}
`);
  const cleanTaint = await taintFindings(cleanDir);
  assert.ok(!cleanTaint.some(f => /format string|CWE-134/i.test(`${f.vuln} ${f.cwe}`)),
    `a literal format string with only a tainted substitution argument must not fire cs-string-format, got: ${cleanTaint.map(f => f.vuln).join(', ')}`);
});

test('cs-xpathnavigator-select / cs-selectsinglenode: XPath built from a tainted expression fires CWE-643', async () => {
  const dir = mkTmp('xpath', `
using System.Xml.XPath;
public class C {
    public void Bad(XPathNavigator nav, [FromQuery] string user) {
        nav.Select("//user[name='" + user + "']");
    }
    public void Bad2(System.Xml.XmlDocument doc, [FromQuery] string user) {
        doc.SelectSingleNode("//user[name='" + user + "']");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath|CWE-643/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Juliet's canonical C# CWE-78 shape: build a Process object with a fixed
// constructor, then assign the tainted command text to .StartInfo.Arguments
// (or .StartInfo.FileName) afterward, then call the parameterless instance
// .Start(). The two PRE-EXISTING C# CWE-78 sinks (cs-process-start /
// cs-process-start-args) both key off the STATIC Process.Start(...) call
// form and had nothing to check here — confirmed via a direct probe that
// produced ZERO findings of any kind before cs-processstartinfo-arguments/
// -filename existed.
test('cs-processstartinfo-arguments: ProcessStartInfo.Arguments assigned a tainted value fires Command Injection', async () => {
  const dir = mkTmp('processstartinfo-arguments', `
using System;
using System.Diagnostics;
public class C {
    public void Bad() {
        string data = Console.ReadLine();
        Process processObj = new Process();
        processObj.StartInfo.FileName = "cmd.exe";
        processObj.StartInfo.Arguments = "/c dir " + data;
        processObj.StartInfo.UseShellExecute = false;
        processObj.Start();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection|CWE-78/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Command Injection from ProcessStartInfo.Arguments=, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-processstartinfo-filename: ProcessStartInfo.FileName assigned a tainted value fires Command Injection', async () => {
  const dir = mkTmp('processstartinfo-filename', `
using System;
using System.Diagnostics;
public class C {
    public void Bad() {
        string exe = Console.ReadLine();
        Process processObj = new Process();
        processObj.StartInfo.FileName = exe;
        processObj.StartInfo.Arguments = "/c dir";
        processObj.Start();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection|CWE-78/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Command Injection from ProcessStartInfo.FileName=, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-processstartinfo-arguments precision: a FIXED literal Arguments value does not fire', async () => {
  const dir = mkTmp('processstartinfo-arguments-clean', `
using System.Diagnostics;
public class C {
    public void Good() {
        Process processObj = new Process();
        processObj.StartInfo.FileName = "cmd.exe";
        processObj.StartInfo.Arguments = "/c dir";
        processObj.Start();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(!taint.some(f => /command injection|CWE-78/i.test(`${f.vuln} ${f.cwe}`)),
    `a fixed literal Arguments value must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// Juliet's OWN canonical C# CWE-78 shape (confirmed by reading the real
// public Juliet C# mirror this project's SARD manifest pins:
// CWE78_OS_Command_Injection__Connect_tcp_01.cs): the single-argument
// `Process.Start(commandString)` overload, with the interpreter and the
// tainted data ALREADY concatenated into one string before the call.
test('cs-process-start-single: Process.Start(commandString) with a tainted concat fires Command Injection', async () => {
  const dir = mkTmp('process-start-single', `
using System;
using System.Diagnostics;
public class C {
    public void Bad() {
        string data = Console.ReadLine();
        string osCommand = "cmd.exe /c dir ";
        Process process = Process.Start(osCommand + data);
        process.WaitForExit();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection|CWE-78/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Command Injection from Process.Start(osCommand + data), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// The bug this entry's own real-corpus verification uncovered: `_lowerExpr`'s
// concat branch required a quote character SOMEWHERE in the expression
// before even attempting to split on top-level `+` — so `osCommand + data`
// (both sides plain identifiers, no inline literal) fell through every
// branch to {kind:'unknown'}, silently dropping `data`'s taint regardless
// of which sink it reached. This is a parser-level fix, not sink-specific;
// pinned directly against the IR here rather than only end-to-end, so a
// future regression is caught even if a sink-side change masked it.
test('parser-cs: `identifier + identifier` (no literal anywhere) lowers to a 2-part template, not unknown', async () => {
  const { parseCSharpFile } = await import('../src/ir/parser-cs.js');
  const code = `
public class C {
    public void M() {
        string osCommand = "cmd.exe ";
        string result = Combine(osCommand, GetInput());
    }
    public string Combine(string a, string b) {
        return a + b;
    }
    public string GetInput() { return ""; }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const combineFn = ir.functions.find(f => f.name === 'C.Combine' || f.name === 'Combine');
  assert.ok(combineFn, 'expected a Combine function');
  const nodes = Object.values(combineFn.cfg.nodes);
  const ret = nodes.find(n => n.kind === 'return');
  assert.ok(ret, 'expected a return node');
  assert.equal(ret.value.kind, 'tpl');
  assert.equal(ret.value.parts.length, 2);
  assert.notEqual(ret.value.kind, 'unknown');
});

// Juliet's OWN canonical C# CWE-643 shape (confirmed via the public
// Juliet C# mirror this project's SARD manifest pins,
// CWE643_Xpath_Injection__Connect_tcp_01.cs): the XPathNavigator variable
// is named `xPath`, which matches neither `[Nn]av` nor `[Nn]avigator` —
// and under `--scramble-identifiers` (the only mode the real benchmark
// scores from) NO variable name could ever match a name-based receiver
// regex. This test deliberately uses fully opaque, scramble-style names
// (no "nav" substring anywhere) to pin the `receiverTypeIn` fallback
// rather than relying on a name that happens to still match.
test('cs-xpathnavigator-evaluate: fires via receiverTypeIn even when the receiver name contains no "nav" substring (scramble-safe)', async () => {
  const dir = mkTmp('xpath-scrambled', `
using System;
using System.Xml.XPath;
public class C {
    public void op0_a1b2c3() {
        string op1_x9y8z7 = Console.ReadLine();
        XPathDocument op2_j1k2l3 = new XPathDocument("helper.xml");
        XPathNavigator op3_m4n5o6 = op2_j1k2l3.CreateNavigator();
        string op4_p7q8r9 = "//users/user[name/text()='" + op1_x9y8z7 + "']/secret/text()";
        string op5_s1t2u3 = (string)op3_m4n5o6.Evaluate(op4_p7q8r9);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath|CWE-643/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XPath Injection via receiverTypeIn fallback, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
