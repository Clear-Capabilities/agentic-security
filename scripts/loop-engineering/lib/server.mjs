// Loopback-only, read-only progress dashboard (LOOP-004). No write or stop
// endpoint exists: control happens only through the CLI. All repository text is
// rendered with textContent, never as HTML; requests are restricted by Host and
// Origin (DNS-rebinding and cross-site protection) and by a fixed route table
// (no filesystem path is ever derived from a URL).
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync, statSync, openSync, readSync, closeSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { buildStatus } from './status.mjs';
import { layout } from './state.mjs';
import { redact } from './util.mjs';
import { loadManifest } from './manifest.mjs';

const MAX_SSE = 8;

export const PAGE = (nonce) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Loop progress</title>
<style>
:root{--bg:#fff;--fg:#17202a;--mut:#5d6d7e;--line:#d5d8dc;--ok:#1e8449;--warn:#b9770e;--bad:#c0392b;--bar:#2e86c1;--card:#f8f9f9}
@media (prefers-color-scheme:dark){:root{--bg:#14181c;--fg:#e6eaee;--mut:#9aa7b3;--line:#2c343c;--ok:#58d68d;--warn:#f5b041;--bad:#ec7063;--bar:#5dade2;--card:#1b2127}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:0 0 4px} h2{font-size:14px;margin:18px 0 6px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;margin:8px 0}
.big{font-size:40px;font-weight:700;line-height:1}
.bar{height:10px;background:var(--line);border-radius:5px;overflow:hidden}.bar>i{display:block;height:100%;background:var(--bar)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px}
.mut{color:var(--mut)} .ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top;font-size:13px}
code,pre{font:12px ui-monospace,monospace} pre{white-space:pre-wrap;max-height:260px;overflow:auto;background:var(--card);padding:8px;border:1px solid var(--line);border-radius:6px}
select,button{font:inherit;padding:2px 6px} .pill{display:inline-block;padding:0 8px;border-radius:10px;border:1px solid var(--line);font-size:12px}
</style></head><body><main>
<h1>Implementation progress <span id="runstate" class="pill"></span></h1>
<div class="mut" id="runmeta"></div>
<div class="card"><div class="grid">
 <div><div class="big" id="pct">-</div><div class="mut" id="pctdetail"></div><div class="bar"><i id="pctbar" style="width:0"></i></div></div>
 <div><div class="mut">Heartbeat (controller alive)</div><div id="hb">-</div><div class="mut" style="margin-top:6px">Last substantive progress</div><div id="prog">-</div></div>
 <div><div class="mut">Budget</div><div id="budget">-</div></div>
</div></div>
<div id="alert" class="card bad" hidden></div>
<h2>Summary</h2><pre id="summary"></pre>
<h2>Workstreams</h2><div class="grid" id="wss"></div>
<h2>Categories</h2><div class="grid" id="cats"></div>
<h2>Current work</h2><div class="card" id="current">-</div>
<h2>Active operations</h2><div class="card" id="ops">none</div>
<h2>Requirements <select id="fcat"><option value="">all categories</option></select> <select id="fstate"><option value="">all states</option></select></h2>
<table><thead><tr><th>ID</th><th>State</th><th>Criteria</th><th>Attempts</th><th>Evidence</th><th>Title / unmet / blockers</th></tr></thead><tbody id="rows"></tbody></table>
<h2>Next ready</h2><div class="card" id="next">-</div>
<h2>Recent events</h2><pre id="events"></pre>
<h2>Commands</h2><pre id="cmds"></pre>
</main>
<script nonce="${nonce}">
const $=(i)=>document.getElementById(i);
const t=(tag,txt,cls)=>{const e=document.createElement(tag);if(txt!=null)e.textContent=String(txt);if(cls)e.className=cls;return e};
function ago(iso){if(!iso)return 'never';const s=Math.max(0,Math.round((Date.now()-Date.parse(iso))/1000));return s<120?s+'s ago':Math.round(s/60)+'m ago'}
function clsFor(s){return s==='verified'||s==='completed'||s==='running'?'ok':(s==='blocked'||s==='failed'||s==='crashed'||s==='stale'||s==='timed-out')?'bad':'warn'}
let last=null;
function render(s){
 last=s;
 $('runstate').textContent=s.status;$('runstate').className='pill '+clsFor(s.status);
 $('runmeta').textContent='run '+s.runId+' | '+s.platform+' | manifest v'+(s.manifest&&s.manifest.version)+' ('+(s.manifest&&s.manifest.totals.requirements)+' requirements, '+(s.manifest&&s.manifest.totals.criteria)+' criteria, '+(s.manifest&&s.manifest.totals.weight)+' weight)';
 $('pct').textContent=s.verifiedPercent+'%';
 $('pctdetail').textContent=s.verifiedWeight+'/'+s.totalWeight+' weight | '+s.verifiedRequirements+'/'+s.totalRequirements+' requirements | '+s.passedCriteria+'/'+s.totalCriteria+' criteria | stale '+(s.counts.stale||0)+' blocked '+(s.counts.blocked||0)+' failed '+(s.counts.failed||0);
 $('pctbar').style.width=s.verifiedPercent+'%';
 $('hb').textContent=(s.controller.liveness)+' | '+ago(s.controller.lastHeartbeatAt);
 $('hb').className=s.controller.liveness==='live'?'ok':'bad';
 $('prog').textContent=ago(s.lastSubstantiveProgressAt);
 const b=s.budgets||{},l=s.limits||{};
 $('budget').textContent='attempts '+(b.attemptsUsed||0)+'/'+(l.runMaxAttempts||'?')+' | $'+((b.usdUsed||0).toFixed(2))+' of $'+(l.claudeBudgetUsd||'?')+' (token-derived amounts are estimates)';
 const a=$('alert');const probs=[];
 if(s.statusReason)probs.push(s.statusReason);(s.blockers||[]).forEach(x=>probs.push(x.type+': '+x.detail));
 a.hidden=!probs.length;a.textContent=probs.join(' | ');
 $('summary').textContent=((s.summary&&s.summary.lines)||[]).join('\\n');
 const wss=$('wss');wss.textContent='';
 ((s.summary&&s.summary.workstreams)||[]).forEach(w=>{const d=t('div',null,'card');d.append(t('div',w.label+': '+w.verified+'/'+w.total+' verified'),t('div','stale '+w.stale+' | blocked '+w.blocked+' | failed '+w.failed,'mut'));wss.append(d)});
 const cats=$('cats');cats.textContent='';
 Object.entries(s.categories).forEach(([k,c])=>{const d=t('div',null,'card');d.append(t('div',c.label+': '+c.verifiedPercent+'%'),t('div',c.verifiedRequirements+'/'+c.totalRequirements+' requirements','mut'));const bar=t('div',null,'bar');const i=t('i');i.style.width=c.verifiedPercent+'%';bar.append(i);d.append(bar);cats.append(d)});
 const cur=$('current');cur.textContent='';
 if(s.current){const c=s.current;cur.append(t('div',(c.requirement||'?')+' | '+(c.phase||'')+(c.attempt?' | attempt '+c.attempt:'')+' | turns '+(c.turns||0)));cur.append(t('div','started '+ago(c.startedAt)+(c.deadlineAt?' | deadline in '+Math.max(0,Math.round((c.deadlineAt-Date.now())/1000))+'s':''),'mut'));if(c.pid)cur.append(t('div','pid '+c.pid+(c.workerAlive===false?' (not alive)':''),'mut'));cur.append(t('div','unmet: '+((c.unmetCriteria||[]).join(', ')||'-'),'mut'))}else cur.textContent='idle';
 const ops=$('ops');ops.textContent='';
 (s.activeOperations||[]).forEach(o=>ops.append(t('div',o.label+' | pid '+o.pid+' | deadline in '+Math.max(0,Math.round((o.deadlineAt-Date.now())/1000))+'s')));
 if(!ops.firstChild)ops.textContent='none';
 const fc=$('fcat'),fs=$('fstate');
 const cs=[...new Set(s.requirements.map(r=>r.category))],ss=[...new Set(s.requirements.map(r=>r.state))];
 if(fc.options.length!==cs.length+1){const v=fc.value;fc.length=1;cs.forEach(x=>fc.add(new Option(x,x)));fc.value=v}
 if(fs.options.length!==ss.length+1){const v=fs.value;fs.length=1;ss.forEach(x=>fs.add(new Option(x,x)));fs.value=v}
 const rows=$('rows');rows.textContent='';
 s.requirements.filter(r=>(!fc.value||r.category===fc.value)&&(!fs.value||r.state===fs.value)).forEach(r=>{
  const tr=document.createElement('tr');
  tr.append(t('td',r.id),t('td',r.state+(r.implementedButStale?' (implemented, evidence stale)':''),clsFor(r.state)),t('td',r.criteria.passed+'/'+r.criteria.total),t('td',r.attempts),t('td',r.evidence?(r.evidence.result+' '+(r.evidence.fresh?'fresh':'stale')):'none'));
  const td=t('td',r.title);if(r.unmetCriteria.length&&r.state!=='verified')td.append(t('div','unmet: '+r.unmetCriteria.join(', '),'mut'));r.blockers.forEach(x=>td.append(t('div',x.type+': '+x.detail,'bad')));rows.append(tr.appendChild(td)&&tr)});
 $('next').textContent=(s.nextReady||[]).join(', ')||'none';
 $('events').textContent=(s.recentEvents||[]).map(e=>e.at+' '+e.type+' '+JSON.stringify(Object.fromEntries(Object.entries(e).filter(([k])=>k!=='at'&&k!=='type')))).join('\\n');
 $('cmds').textContent=Object.entries(s.commands||{}).map(([k,v])=>k+': '+v).join('\\n');
}
$('fcat').onchange=()=>last&&render(last);$('fstate').onchange=()=>last&&render(last);
function poll(){fetch('/api/status',{cache:'no-store'}).then(r=>r.json()).then(render).catch(()=>{$('runstate').textContent='dashboard cannot reach status';$('runstate').className='pill bad'}).finally(()=>setTimeout(poll,3000))}
poll();
</script></body></html>`;

export function createDashboard({ repoRoot, runId, host = '127.0.0.1', port = 4317, getStatus = null }) {
  if (host !== '127.0.0.1' && host !== 'localhost') return Promise.reject(new Error('dashboard binds to loopback only'));
  const L = layout(repoRoot, runId);
  let cached = null, cachedAt = 0, building = null;
  const status = () => {
    if (getStatus) return Promise.resolve(getStatus());
    if (cached && Date.now() - cachedAt < 1000) return Promise.resolve(cached);
    if (!building) building = Promise.resolve().then(() => { cached = buildStatus(repoRoot, runId); cachedAt = Date.now(); return cached; }).finally(() => { building = null; });
    return building;
  };
  let allowed = new Set();
  let sse = 0;
  const server = http.createServer((req, res) => {
    const h = String(req.headers.host || '');
    const origin = req.headers.origin;
    const send = (code, body, type = 'application/json; charset=utf-8', extra = {}) => {
      res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Cross-Origin-Resource-Policy': 'same-origin', ...extra });
      res.end(body);
    };
    if (!allowed.has(h)) return send(421, JSON.stringify({ error: 'unrecognised Host header' }));
    if (origin && ![...allowed].some((a) => origin === `http://${a}`)) return send(403, JSON.stringify({ error: 'foreign origin' }));
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(405, JSON.stringify({ error: 'read-only dashboard' }), undefined, { Allow: 'GET, HEAD' });
    let u;
    try { u = new URL(req.url, 'http://x'); } catch { return send(400, JSON.stringify({ error: 'bad url' })); }
    const p = u.pathname;
    if (p === '/' || p === '/index.html') {
      const nonce = randomBytes(12).toString('base64');
      return send(200, PAGE(nonce), 'text/html; charset=utf-8', { 'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` });
    }
    if (p === '/api/status') return status().then((s) => send(200, JSON.stringify(s))).catch((e) => send(500, JSON.stringify({ error: redact(String(e.message)) })));
    if (p === '/api/requirements') return status().then((s) => send(200, JSON.stringify({ runId: s.runId, requirements: s.requirements || [], totals: s.manifest?.totals || null }))).catch(() => send(500, '{"error":"status failed"}'));
    if (p === '/api/events') {
      if (sse >= MAX_SSE) return send(503, JSON.stringify({ error: 'too many event streams' }));
      sse++;
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Content-Type-Options': 'nosniff' });
      const push = () => status().then((s) => { const { requirements, recentEvents, ...slim } = s; res.write(`data: ${JSON.stringify({ ...slim, recentEvents })}\n\n`); }).catch(() => {});
      push();
      const iv = setInterval(push, 2500);
      const done = () => { clearInterval(iv); sse--; };
      req.on('close', done); res.on('error', done);
      return undefined;
    }
    const lm = /^\/api\/logs\/([A-Z]+-\d+)$/.exec(p);
    if (lm) {
      const m = loadManifest(repoRoot);
      if (!m.ok || !m.manifest.requirements.some((r) => r.id === lm[1])) return send(404, JSON.stringify({ error: 'unknown requirement' }));
      return send(200, JSON.stringify({ requirement: lm[1], tail: safeLogTail(L, lm[1]) }));
    }
    return send(404, JSON.stringify({ error: 'not found' }));
  });
  return new Promise((resolve, reject) => {
    let conflict = null;
    const onListening = () => {
      server.off('error', onError);
      const actual = server.address().port;
      allowed = new Set([`127.0.0.1:${actual}`, `localhost:${actual}`]);
      resolve({ server, url: `http://127.0.0.1:${actual}`, port: actual, conflict, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) });
    };
    const onError = (e) => {
      if (e.code === 'EADDRINUSE' && !conflict) { conflict = { requested: port }; server.listen(0, host); return; }
      server.off('listening', onListening);
      reject(e);
    };
    server.on('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

// Latest attempt log for a requirement, bounded and redacted. The prompt file
// is never served.
export function safeLogTail(L, id, max = 6000) {
  try {
    const dirs = readdirSync(L.attemptsDir).filter((d) => d.startsWith(id + '-')).sort();
    const d = dirs[dirs.length - 1];
    if (!d) return '';
    const f = join(L.attemptsDir, d, 'stream.log');
    const st = statSync(f);
    const fd = openSync(f, 'r');
    try {
      const len = Math.min(st.size, max);
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, st.size - len);
      return redact(buf.toString('utf8'));
    } finally { closeSync(fd); }
  } catch { return ''; }
}
export { readFileSync };
