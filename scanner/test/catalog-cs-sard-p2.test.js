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
