// Release scope reconciliation (threat-model PRD FR-01.2, AC-01B, AC-01C).
//
// An ordinary scan reports its own scope and is never failed by this module. A QUALIFIED release claim reconciles the scan against
// what actually ships: the authoritative build or package inventory, the route manifest and the artifact's source binding. Every
// critical shipped unit and route ends in one of: covered, excluded (with the scope's reason), excepted (a scoped, independently
// verified compensating control that has not expired), unsupported or unknown. The gate is satisfied only when every critical item is
// covered or excepted and the binding is current. A report with no scope (a legacy or non-Git-scoped scan) cannot satisfy it.
//
// Pure: report and declarations in, decision out. No file is read.

const norm = (p) => String(p ?? '').replace(/\\/g, '/').replace(/^\.\//, '');
// `/records/:id`, `/records/{id}` and `/records/<id>` are the same template
const routeKey = (method, path) => `${String(method ?? 'GET').toUpperCase()} ${String(path ?? '').replace(/(?::[A-Za-z_]\w*|\{[^}/]+\}|<[^>/]+>)/g, ':p').replace(/\/+$/, '') || '/'}`;

function exceptionFor(exceptions, kind, key, now) {
  for (const e of exceptions || []) {
    if (!e || e.kind !== kind || norm(e.target) !== norm(key)) continue;
    const c = e.compensatingControl;
    if (!c || !c.id || !c.verifiedBy || c.independent !== true) return { ok: false, reason: 'the exception names no independently verified compensating control' };
    if (!e.expires || !(Date.parse(e.expires) > now)) return { ok: false, reason: e.expires ? 'the exception has expired' : 'the exception has no expiry' };
    return { ok: true, control: c.id, expires: e.expires };
  }
  return null;
}

/**
 * @param {object} report  the JSON report (`scope`, `routes`, `scanRecord`)
 * @param {{shipped?:{path:string,critical?:boolean,provenance?:string}[], routes?:{method:string,path:string,critical?:boolean}[],
 *          artifact?:{sourceCommit?:string}|null, exceptions?:object[], now?:number}} d
 */
export function evaluateReleaseScope(report, d = {}) {
  const now = d.now ?? Date.now();
  const reasons = [];
  const items = [];
  const scope = report && report.scope;
  if (!scope) {
    return { status: 'unresolved', reasons: [{ code: 'scope-missing', detail: 'the report carries no scan scope (a legacy or non-Git-scoped scan), so what it covered cannot be shown' }], items };
  }
  const included = Array.isArray(scope.included) ? new Set(scope.included.map(norm)) : null;
  const skippedByPath = new Map((scope.skipped || []).map((s) => [norm(s.path), s]));
  const skippedUnder = (p) => { for (const [k, s] of skippedByPath) if (k.endsWith('/') ? p.startsWith(k) : (p === k || p.startsWith(`${k}/`))) return s; return null; };

  for (const u of d.shipped || []) {
    const p = norm(u.path);
    let outcome; let reason = null;
    if (included && included.has(p)) outcome = 'covered';
    else if (skippedUnder(p)) { outcome = 'excluded'; reason = skippedUnder(p).reason; }
    else if (!included) { outcome = 'unknown'; reason = 'the scan recorded only counts for its included files (too many to list), so this file cannot be confirmed'; }
    else { outcome = 'unknown'; reason = 'the shipped file is neither in the scan\'s inventory nor among its recorded exclusions'; }
    if (outcome !== 'covered') {
      const ex = exceptionFor(d.exceptions, 'file', p, now);
      if (ex && ex.ok) { outcome = 'excepted'; reason = `compensating control ${ex.control} until ${ex.expires}`; }
      else if (ex) reason = `${reason}; ${ex.reason}`;
    }
    items.push({ kind: 'file', target: p, critical: u.critical !== false, outcome, reason, provenance: u.provenance ?? 'build-inventory' });
  }

  const scanned = new Set((report.routes || []).filter((r) => r && r.path && r.path !== '(file-based)').map((r) => routeKey(r.method, r.path)));
  for (const r of d.routes || []) {
    const key = routeKey(r.method, r.path);
    let outcome = scanned.has(key) ? 'covered' : 'unknown';
    let reason = outcome === 'covered' ? null : 'no route in the scanned code matches this manifest entry';
    if (outcome !== 'covered') {
      const ex = exceptionFor(d.exceptions, 'route', key, now);
      if (ex && ex.ok) { outcome = 'excepted'; reason = `compensating control ${ex.control} until ${ex.expires}`; }
      else if (ex) reason = `${reason}; ${ex.reason}`;
    }
    items.push({ kind: 'route', target: key, critical: r.critical !== false, outcome, reason, provenance: 'route-manifest' });
  }

  const source = report.scanRecord && report.scanRecord.source;
  if (d.artifact && d.artifact.sourceCommit) {
    if (!source || !source.commit) reasons.push({ code: 'binding-unknown', detail: 'the report records no source commit, so the artifact cannot be bound to it' });
    else if (source.commit !== d.artifact.sourceCommit) reasons.push({ code: 'stale-binding', detail: `the artifact was built from ${String(d.artifact.sourceCommit).slice(0, 12)} but the scan was of ${String(source.commit).slice(0, 12)}` });
    else if (source.dirty) reasons.push({ code: 'dirty-input', detail: 'the scanned tree had uncommitted changes, so it is not exactly the artifact\'s source' });
  } else reasons.push({ code: 'artifact-unbound', detail: 'no artifact source commit was declared, so the scan is not bound to what ships' });

  for (const it of items) if (it.critical && it.outcome !== 'covered' && it.outcome !== 'excepted') reasons.push({ code: `${it.kind}-${it.outcome}`, detail: `${it.target}: ${it.reason}` });
  return { status: reasons.length ? 'unresolved' : 'satisfied', reasons, items, inventoryDigest: scope.inventoryDigest ?? null };
}
