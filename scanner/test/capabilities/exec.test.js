// X-503: structured command execution, descendants and resource limits.
//
// The policy half (what the manifest permits) runs everywhere. The execution
// half runs real process trees under the real boundary and asserts on side
// effects and on `ps`-level liveness, never on a status word. Where no probed
// backend exists the execution tests skip with a loud reason; a skip is a gap.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { decide } from '../../src/capabilities/decide.js';
import { SKIP, bind, ctxFor, run, tmp, alive, sleep } from './helpers.js';

const exists = (p) => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } };
const INTERPRETERS = ['/bin/sh', '/bin/bash', '/bin/zsh', '/bin/dash', '/usr/bin/env', '/usr/bin/xargs', '/usr/bin/awk', '/usr/bin/perl', '/usr/bin/ruby', '/usr/bin/python3', process.execPath].filter(exists);
const pidsIn = (file) => fs.readFileSync(file, 'utf8').split('\n').map((x) => Number(x.trim())).filter((n) => Number.isInteger(n) && n > 1);

function scopedShell(script, w, extra = {}) {
  return bind({
    filesystem: { write: [w], ...(extra.fs || {}) },
    commands: [{ executable: '/bin/sh', interpreter: 'scoped', args: { mode: 'exact', values: ['-c', script] } }, ...(extra.commands || [])],
    resources: extra.resources,
  });
}
const runShell = (script, w, extra = {}, opts = {}) => run(scopedShell(script, w, extra), { executable: '/bin/sh', args: ['-c', script] }, opts);

describe('[X-503.AC01] execution accepts an executable and an argument array; shells and unsupported interpreters are blocked', () => {
  test('only absolute executables and plain-string argument arrays are accepted', () => {
    const bound = bind({ commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const ctx = ctxFor(bound);
    const ok = decide(bound, { kind: 'command', executable: '/bin/echo', args: ['a', 'b'] }, ctx);
    assert.equal(ok.decision, 'allow');
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/echo' }, ctx).decision, 'allow', 'no arguments is an empty array');
    const refusals = {
      'a shell string': { executable: 'echo hello && id', args: [] },
      'a bare name resolved through a search path': { executable: 'echo', args: [] },
      'a relative path': { executable: './echo', args: [] },
      'a parent segment': { executable: '/bin/../bin/echo', args: [] },
      'a string instead of an array': { executable: '/bin/echo', args: 'a b' },
      'a non-string argument': { executable: '/bin/echo', args: ['a', 7] },
      'a NUL byte in an argument': { executable: '/bin/echo', args: ['a\0b'] },
      'an object argument': { executable: '/bin/echo', args: [{ toString: () => 'x' }] },
      'too many arguments': { executable: '/bin/echo', args: new Array(300).fill('x') },
      'a path that is not a file': { executable: '/bin', args: [] },
      'a path that does not exist': { executable: '/bin/definitely-not-a-command', args: [] },
    };
    for (const [name, a] of Object.entries(refusals)) {
      const d = decide(bound, { kind: 'command', ...a }, ctx);
      assert.equal(d.decision, 'deny', name);
    }
    assert.equal(decide(bound, { kind: 'command', executable: '/usr/bin/true', args: [] }, ctx).code, 'command-not-listed');
  });

  test('exact and prefix argument modes pin what a command may be asked to do', () => {
    const bound = bind({
      commands: [
        { executable: '/usr/bin/find', args: { mode: 'exact', values: ['.', '-name', '*.js'] } },
        { executable: '/bin/ls', args: { mode: 'prefix', values: ['-l'] } },
      ],
    });
    const ctx = ctxFor(bound);
    assert.equal(decide(bound, { kind: 'command', executable: '/usr/bin/find', args: ['.', '-name', '*.js'] }, ctx).decision, 'allow');
    assert.equal(decide(bound, { kind: 'command', executable: '/usr/bin/find', args: ['.', '-name', '*.js', '-exec', 'sh', '-c', 'id', ';'] }, ctx).code, 'args-not-permitted');
    assert.equal(decide(bound, { kind: 'command', executable: '/usr/bin/find', args: [] }, ctx).code, 'args-not-permitted');
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/ls', args: ['-l', '/tmp'] }, ctx).decision, 'allow');
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/ls', args: ['/tmp'] }, ctx).code, 'args-not-permitted');
  });

  test('shells, language runtimes and launchers are blocked even when listed with any arguments', () => {
    const bound = bind({ commands: INTERPRETERS.map((e) => ({ executable: e, args: { mode: 'any' } })) });
    const ctx = ctxFor(bound);
    assert.ok(INTERPRETERS.length >= 4, 'the table exercises several interpreters on this host');
    for (const e of INTERPRETERS) {
      const d = decide(bound, { kind: 'command', executable: e, args: ['-c', 'id'] }, ctx);
      assert.equal(d.decision, 'deny', e);
      assert.equal(d.code, 'interpreter-blocked', e);
    }
  });

  test('a script is an interpreter whatever it is called, and one the task can write is refused outright', () => {
    const dir = tmp('x503a-');
    const bin = path.join(dir, 'bin'); const w = path.join(dir, 'w');
    fs.mkdirSync(bin); fs.mkdirSync(w);
    for (const where of [bin, w]) {
      fs.writeFileSync(path.join(where, 'tool'), '#!/bin/sh\necho hi\n');
      fs.chmodSync(path.join(where, 'tool'), 0o755);
    }
    const bound = bind({
      filesystem: { read: [bin], write: [w] },
      commands: [{ executable: path.join(bin, 'tool'), args: { mode: 'any' } }, { executable: path.join(w, 'tool'), args: { mode: 'any' } }],
    });
    const ctx = ctxFor(bound);
    assert.equal(decide(bound, { kind: 'command', executable: path.join(bin, 'tool'), args: [] }, ctx).code, 'interpreter-blocked', 'a #! file is a script');
    assert.equal(decide(bound, { kind: 'command', executable: path.join(w, 'tool'), args: [] }, ctx).code, 'executable-in-writable-root', 'the task could replace it');
  });

  test('a scoped interpreter runs only with its exact declared arguments', () => {
    const bound = bind({ commands: [{ executable: '/bin/sh', interpreter: 'scoped', args: { mode: 'exact', values: ['-c', 'echo pinned'] } }] });
    const ctx = ctxFor(bound);
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/sh', args: ['-c', 'echo pinned'] }, ctx).decision, 'allow');
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/sh', args: ['-c', 'echo other'] }, ctx).code, 'args-not-permitted');
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/sh', args: ['-c', 'echo pinned', 'extra'] }, ctx).code, 'args-not-permitted');
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/sh', args: [] }, ctx).code, 'args-not-permitted');
  });

  test('a secret in an argument is refused: arguments are visible to every process', () => {
    const bound = bind({ commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const ctx = ctxFor(bound, { canaries: ['custom-canary-value-123'] });
    for (const arg of [('sk_' + 'live_4eC39HqLyjWDarjtT1zdp7dc'), 'ghp_' + 'a'.repeat(36), 'AKIAIOSFODNN7EXAMPLE', 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop', 'prefix-custom-canary-value-123-suffix']) {
      const d = decide(bound, { kind: 'command', executable: '/bin/echo', args: ['ok', arg] }, ctx);
      assert.equal(d.code, 'secret-in-argument', arg.slice(0, 12));
      assert.ok(!JSON.stringify(d).includes(arg.slice(-10)), 'the decision does not echo the secret');
    }
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/echo', args: ['hello', '/some/long/path/with-random-looking-name-9f3a1c7b2d'] }, ctx).decision, 'allow', 'ordinary arguments are unaffected');
  });
});

describe('[X-503.AC02] descendants inherit confinement and are terminated on deadline, cancellation or exhaustion, with cleanup evidence', { skip: SKIP }, () => {
  let dir; let w; let outside;
  before(() => {
    dir = tmp('x503b-');
    w = path.join(dir, 'w'); outside = path.join(dir, 'outside');
    fs.mkdirSync(w); fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 's.txt'), 'CANARY-DESCENDANT');
  });

  test('a deadline ends the whole process tree, including a grandchild, and reports the cleanup', async () => {
    const pf = path.join(w, 'dl');
    const script = `sleep 300 & echo $! >> '${pf}'; (sleep 300 & echo $! >> '${pf}'; wait) & wait`;
    const r = await runShell(script, w, { resources: { timeoutMs: 1500 } });
    assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    assert.equal(r.outcome, 'timeout');
    assert.equal(r.timedOut, true);
    const pids = pidsIn(pf);
    assert.ok(pids.length >= 2, 'both background processes started');
    await sleep(150);
    for (const p of pids) assert.equal(alive(p), false, `pid ${p} must be dead`);
    assert.equal(r.cleanup.complete, true);
    assert.deepEqual(r.cleanup.survivors, []);
    assert.ok(['SIGTERM', 'SIGKILL'].includes(r.cleanup.signalled), 'the cleanup says how it ended the tree');
    assert.ok(Array.isArray(r.cleanup.killedPids));
  });

  test('a descendant inherits the file confinement: it cannot read or write outside the roots', async () => {
    const leak = path.join(w, 'leak');
    const script = [
      `( cat '${outside}/s.txt' > '${leak}' ) 2>/dev/null`,
      `( echo x > '${outside}/forged' ) 2>/dev/null`,
      `sh -c "echo y > '${outside}/forged2'" 2>/dev/null`,
      `( sh -c "( cat '${outside}/s.txt' >> '${leak}' ) 2>/dev/null" )`,
      'true',
    ].join('; ');
    const r = await runShell(script, w);
    assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    assert.equal(fs.readFileSync(leak, 'utf8'), '', 'nothing from the protected file reached the writable root');
    assert.ok(!fs.existsSync(path.join(outside, 'forged')) && !fs.existsSync(path.join(outside, 'forged2')));
  });

  test('cancellation terminates the tree and says so', async () => {
    const pf = path.join(w, 'cancel');
    const script = `sleep 300 & echo $! >> '${pf}'; (sleep 300 & echo $! >> '${pf}'; wait) & wait`;
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 700);
    const r = await runShell(script, w, {}, { signal: ac.signal });
    assert.equal(r.outcome, 'cancelled');
    assert.equal(r.cancelled, true);
    await sleep(150);
    for (const p of pidsIn(pf)) assert.equal(alive(p), false);
    assert.equal(r.cleanup.complete, true);
  });

  test('a process that outlives a normal exit is found and ended (orphans)', async () => {
    const pf = path.join(w, 'orphan');
    const script = `sleep 300 & echo $! >> '${pf}'; (sleep 300 & echo $! >> '${pf}') ; true`;
    const r = await runShell(script, w);
    assert.equal(r.outcome, 'exited');
    assert.equal(r.exitCode, 0);
    const pids = pidsIn(pf);
    assert.ok(pids.length >= 1);
    await sleep(150);
    for (const p of pids) assert.equal(alive(p), false, `orphan ${p} must be dead`);
    assert.equal(r.cleanup.complete, true);
    assert.ok(r.cleanup.signalled, 'the run records that a cleanup signal was needed');
  });

  test('exhausting the output budget ends the task and its tree', async () => {
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/usr/bin/yes', args: { mode: 'exact', values: [] } }], resources: { timeoutMs: 10000, maxOutputBytes: 65536 } });
    const t0 = Date.now();
    const r = await run(bound, { executable: '/usr/bin/yes', args: [] });
    assert.equal(r.outcome, 'output-limit');
    assert.equal(r.outputCapped, true);
    assert.ok(r.output.stdout.length <= 65536, `returned output is capped (${r.output.stdout.length})`);
    assert.ok(Date.now() - t0 < 8000, 'the flood did not run to the deadline');
    assert.equal(r.cleanup.complete, true);
  });

  test('a file-size limit stops a runaway write', async () => {
    const big = path.join(w, 'big');
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/bin/dd', args: { mode: 'prefix', values: [] } }], resources: { maxFileSizeKb: 64 } });
    await run(bound, { executable: '/bin/dd', args: ['if=/dev/zero', `of=${big}`, 'bs=1024', 'count=4000'] });
    const size = fs.existsSync(big) ? fs.statSync(big).size : 0;
    assert.ok(size <= 64 * 1024, `the file stopped at ${size} bytes`);
    assert.ok(size < 4000 * 1024);
  });
});

describe('[X-503.AC03] injection, escape, spawning, flooding and orphan vectors are covered and the controller stays responsive', { skip: SKIP }, () => {
  let dir; let w;
  before(() => { dir = tmp('x503c-'); w = path.join(dir, 'w'); fs.mkdirSync(w); });

  test('command substitution and shell metacharacters in arguments stay text', async () => {
    const marks = ['m1', 'm2', 'm3', 'm4'].map((m) => path.join(w, m));
    const args = [`$(touch '${marks[0]}')`, `\`touch '${marks[1]}'\``, `; touch '${marks[2]}'`, `&& touch '${marks[3]}'`, '$HOME', '*', '~', '|', '>/dev/null'];
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const r = await run(bound, { executable: '/bin/echo', args });
    assert.equal(r.status, 'ok', JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    assert.equal(r.output.stdout, `${args.join(' ')}\n`, 'every argument arrived verbatim');
    for (const m of marks) assert.ok(!fs.existsSync(m), `${path.basename(m)} must not exist: nothing was expanded or executed`);
  });

  test('interpreter escapes are refused before anything runs', async () => {
    const marker = path.join(w, 'escape-marker');
    const attempts = [
      ['/usr/bin/env', ['sh', '-c', `touch '${marker}'`]],
      ['/bin/sh', ['-c', `touch '${marker}'`]],
      ['/bin/bash', ['-c', `touch '${marker}'`]],
      ['/usr/bin/xargs', ['touch', marker]],
      ['/usr/bin/awk', [`BEGIN{system("touch '${marker}'")}`]],
      ['/usr/bin/perl', ['-e', `system("touch '${marker}'")`]],
      [process.execPath, ['-e', `require('fs').writeFileSync('${marker}','x')`]],
    ].filter(([e]) => exists(e));
    const bound = bind({
      filesystem: { write: [w] },
      commands: attempts.map(([e]) => ({ executable: e, args: { mode: 'any' } })),
    });
    for (const [e, args] of attempts) {
      const r = await run(bound, { executable: e, args });
      assert.equal(r.status, 'blocked', e);
      assert.equal(r.executed, false, e);
      assert.equal(r.policyCode, 'interpreter-blocked', e);
    }
    assert.ok(!fs.existsSync(marker), 'no escape attempt ran');
  });

  test('a find with -exec is refused by its pinned arguments', async () => {
    const marker = path.join(w, 'find-marker');
    const bound = bind({ filesystem: { read: [w] }, commands: [{ executable: '/usr/bin/find', args: { mode: 'exact', values: [w, '-name', '*.txt'] } }] });
    const r = await run(bound, { executable: '/usr/bin/find', args: [w, '-name', '*.txt', '-exec', '/usr/bin/touch', marker, ';'] });
    assert.equal(r.status, 'blocked');
    assert.equal(r.policyCode, 'args-not-permitted');
    assert.ok(!fs.existsSync(marker));
  });

  test('child spawning: a fork storm is bounded by the deadline and every member ends', async () => {
    const pf = path.join(w, 'storm');
    const script = `i=0; while [ $i -lt 12 ]; do ( sleep 300 & echo $! >> '${pf}'; wait ) & i=$((i+1)); done; wait`;
    const r = await runShell(script, w, { resources: { timeoutMs: 2500 } });
    assert.equal(r.outcome, 'timeout');
    assert.equal(r.cleanup.complete, true, `survivors: ${r.cleanup.survivors}`);
    const pids = pidsIn(pf);
    assert.ok(pids.length >= 8, `the storm started (${pids.length} members recorded)`);
    await sleep(300);
    const live = pids.filter(alive);
    assert.deepEqual(live, [], 'no member of the storm is still running');
  });

  test('the controller stays responsive while a flood, a storm and an orphan run', async () => {
    // Event-loop UTILIZATION, not lag: a controller that blocks on its children keeps the loop busy the whole time (utilization 1.0, measured
    // identically on an idle machine and under 24 CPU burners), while an async one idles waiting (0.002 to 0.05 in both). Wall-clock lag only
    // measures how long the OS left this process descheduled, which a loaded machine makes arbitrarily large for correct code.
    const elu0 = performance.eventLoopUtilization();
    const pf = path.join(w, 'resp');
    const script = `i=0; while [ $i -lt 12 ]; do ( sleep 300 & echo $! >> '${pf}'; wait ) & i=$((i+1)); done; yes > /dev/null & wait`;
    const flood = run(bind({ filesystem: { write: [w] }, commands: [{ executable: '/usr/bin/yes', args: { mode: 'exact', values: [] } }], resources: { maxOutputBytes: 32768, timeoutMs: 8000 } }), { executable: '/usr/bin/yes', args: [] });
    const storm = runShell(script, w, { resources: { timeoutMs: 2500 } });
    const [a, b] = await Promise.all([flood, storm]);
    assert.equal(a.outcome, 'output-limit');
    assert.equal(b.outcome, 'timeout');
    assert.equal(a.cleanup.complete && b.cleanup.complete, true);
    const elu = performance.eventLoopUtilization(elu0).utilization;
    assert.ok(elu < 0.5, `the controller's event loop was busy ${(elu * 100).toFixed(0)}% of the time: it blocked while the children ran`);
  });
});
