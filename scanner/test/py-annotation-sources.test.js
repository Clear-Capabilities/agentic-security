// PRD T3.1 — Python entry-point taint sources via the paramAnnotations
// side-channel.
//
// THE GAP THIS CLOSES. dataflow/catalog.js has supported
// `match.type: 'annotation'` sources since Spring/ASP.NET/NestJS were added,
// and ir/CLAUDE.md documents `fn.paramAnnotations` as the channel they arrive
// on. parser-js.js, parser-cs.js and parser-java.js all populate it. Python
// populated NOTHING — verified by grep before this change: 0 occurrences in
// parser-py.helper.py against 3/4/3 in the others. So no annotation source
// could ever match a Python parameter, however well cataloged, and every
// framework whose trust boundary is a decorated parameter was invisible.
//
// Measured on the independent population, this blocked at least
// GHSA-c5px-58j2-7fqp (an @mcp.tool()-decorated parameter reaching a
// Path(...).open() sink), whose root-cause entry names exactly this gap.
//
// The division of responsibility under test: the IR emits the FACT that a
// decorator exists, and the catalog decides which decorators name a source.
// That is why emitting broadly from the parser is safe — @staticmethod
// resolves to no catalog entry and therefore to no taint — and it is pinned
// below in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

async function taintFindings(filename, src) {
  setStateWritesEnabled(false);
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pyann-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{"name":"t","version":"1.0.0"}');
    fs.writeFileSync(path.join(d, filename), src);
    const { scan } = await runScan(d);
    return (normalizeFindings(scan) || []).filter(f => f.parser === 'IR-TAINT');
  } finally {
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP;
    else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    setStateWritesEnabled(true);
    fs.rmSync(d, { recursive: true, force: true });
  }
}

const SINK = '    return subprocess.run("report " + name, shell=True)';

test('a FastAPI Query(...) parameter is an entry-point source', async () => {
  const f = await taintFindings('api.py', [
    'from fastapi import FastAPI, Query',
    'import subprocess',
    'app = FastAPI()',
    '@app.get("/ping")',
    'def ping(name: str = Query(...)):',
    SINK,
  ].join('\n'));
  assert.equal(f.length, 1, `expected one taint finding, got ${JSON.stringify(f.map(x => x.vuln))}`);
  assert.match(f[0].vuln, /Command Injection/);
});

test('an @mcp.tool() parameter is an entry-point source (agent trust boundary)', async () => {
  const f = await taintFindings('tool.py', [
    'import subprocess',
    '@mcp.tool()',
    'def run_report(name):',
    SINK,
  ].join('\n'));
  assert.equal(f.length, 1, `expected one taint finding, got ${JSON.stringify(f.map(x => x.vuln))}`);
});

test('NEGATIVE CONTROL: a bare function parameter is NOT a source', async () => {
  // The dangerous over-reach would be "any parameter is untrusted", which
  // would taint most of every Python codebase. Identical body, no marker.
  const f = await taintFindings('plain.py', [
    'import subprocess',
    'def run_report(name):',
    SINK,
  ].join('\n'));
  assert.deepEqual(f, [], 'an unmarked parameter must not be tainted');
});

test('NEGATIVE CONTROL: a non-source decorator does not taint (@staticmethod)', async () => {
  // The IR emits @staticmethod as a fact; the catalog must decline it.
  const f = await taintFindings('static.py', [
    'import subprocess',
    'class C:',
    '    @staticmethod',
    '    def run_report(name):',
    '        return subprocess.run("report " + name, shell=True)',
  ].join('\n'));
  assert.deepEqual(f, [], '@staticmethod names no trust boundary and must not taint');
});

test('NEGATIVE CONTROL: Depends(...) is dependency injection, not untrusted input', async () => {
  // FastAPI's Depends() supplies server-side collaborators (db sessions,
  // config). Treating it as a source would taint every injected dependency.
  const f = await taintFindings('dep.py', [
    'from fastapi import FastAPI, Depends',
    'import subprocess',
    'app = FastAPI()',
    '@app.get("/x")',
    'def handler(name = Depends(get_service_name)):',
    SINK,
  ].join('\n'));
  assert.deepEqual(f, [], 'an injected dependency is not attacker-controlled');
});

test('NEGATIVE CONTROL: pathlib Path(...) default does not taint', async () => {
  // FastAPI has a Path(...) marker, but `= Path(...)` is at least as likely to
  // be pathlib. The catalog deliberately omits it; this pins that decision so
  // a future "completeness" edit has to argue with a test.
  const f = await taintFindings('paths.py', [
    'from pathlib import Path',
    'import subprocess',
    'def run_report(name = Path("/tmp")):',
    SINK,
  ].join('\n'));
  assert.deepEqual(f, [], 'pathlib.Path defaults must not be treated as an entry point');
});

// ─────────────────────────────────────────── T3.1 (cont.) CLI entry points
test('argparse parse_args() taints every flag attribute it returns', async () => {
  // sys.argv was already cataloged but is rarely read directly; the idiomatic
  // form is `args = parser.parse_args()` then `args.<flag>`. Tainting the
  // RETURN lets the access-path lattice carry it to each attribute without
  // enumerating flag names.
  const f = await taintFindings('cli.py', [
    'import argparse, subprocess',
    'def main():',
    '    parser = argparse.ArgumentParser()',
    '    parser.add_argument("--host")',
    '    args = parser.parse_args()',
    '    subprocess.run("ping " + args.host, shell=True)',
  ].join('\n'));
  assert.equal(f.length, 1, `expected one taint finding, got ${JSON.stringify(f.map(x => x.vuln))}`);
});

test('PREREQUISITE: an argv-array subprocess call is NOT command injection', async () => {
  // requireKeyword. `subprocess.run([...], capture_output=True)` never invokes
  // a shell, so a tainted element is one opaque argv entry — safe however
  // tainted. Enabling the CLI source above without this fired on 15 argv-array
  // calls across 9 of this repo's own hand-reviewed scripts, each labelled
  // "shell=True" by a sink that never checked the keyword.
  const f = await taintFindings('argv.py', [
    'import argparse, subprocess',
    'def main():',
    '    parser = argparse.ArgumentParser()',
    '    parser.add_argument("--host")',
    '    args = parser.parse_args()',
    '    subprocess.run(["ping", args.host], capture_output=True)',
  ].join('\n'));
  assert.deepEqual(f, [], 'an argv-array call cannot be command injection');
});

test('PREREQUISITE: requireKeyword stays RECALL-PRESERVING under a **splat', async () => {
  // The dangerous inverse of the argv-array case. `shell=True` arriving via
  // `**SHELL_OPTS` is still a real shell invocation, but the keyword set is
  // not enumerable at the call site — so suppressing here would be a false
  // NEGATIVE on exploitable code. The first draft of requireKeyword failed
  // closed and broke bench/cve-replay/deep/py-interproc-cmdi-shape, which
  // exists to pin exactly this shape; the corpus gate caught it.
  const f = await taintFindings('splat.py', [
    'import argparse, subprocess',
    'SHELL_OPTS = {"shell": True}',
    'def main():',
    '    parser = argparse.ArgumentParser()',
    '    parser.add_argument("--host")',
    '    args = parser.parse_args()',
    '    subprocess.call("ping " + args.host, **SHELL_OPTS)',
  ].join('\n'));
  assert.equal(f.length, 1, 'an unenumerable keyword set must not suppress the finding');
});

test('PREREQUISITE: a dict .get() is not an HTTP request (receiver constraint)', async () => {
  // py-requests-get matched a BARE `.get()` with no enforced receiver
  // (receiverTypeIn is a no-op for Python), so ordinary mapping lookups like
  // FRAMEWORK_RUNNERS.get(name) were reported as SSRF.
  const f = await taintFindings('dictget.py', [
    'import argparse',
    'RUNNERS = {"a": 1}',
    'def main():',
    '    parser = argparse.ArgumentParser()',
    '    parser.add_argument("--name")',
    '    args = parser.parse_args()',
    '    return RUNNERS.get(args.name)',
  ].join('\n'));
  assert.deepEqual(f, [], 'a mapping lookup is not an outbound HTTP request');
});

test('NEGATIVE CONTROL: a hardcoded literal through the same sink does not taint', async () => {
  const f = await taintFindings('lit.py', [
    'import subprocess',
    'def main():',
    '    host = "localhost"',
    '    subprocess.run("ping " + host, shell=True)',
  ].join('\n'));
  assert.deepEqual(f, [], 'a constant is not attacker-controlled');
});
