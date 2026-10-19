// CLI surface for the detection-and-response loop: `dnr generate|validate|hunt|window|show|status`.
// Non-interactive by construction (no command reads stdin), bounded (log reads have size, line and time budgets), and local:
// nothing here contacts a network or a model, so production logs never leave the machine.
//
// Exit codes: 0 completed and clean, 4 usage or precondition, 1 a stored/produced result failed its own check (validation),
// and for `hunt` a distinct code per verdict so automation cannot read an unanswered question as a clean one:
//   0 NOT_OBSERVED   10 OBSERVED   11 INCONCLUSIVE   12 TELEMETRY_UNAVAILABLE
import fs from 'node:fs';
import path from 'node:path';
import { latestProof } from '../proof-fabric/store.js';
import { buildDetectionIR, validateDetectionIR } from './detection-ir.js';
import { renderDetection, renderAll, FORMATS } from './outputs.js';
import { validateDetection } from './validate.js';
import { huntLogs } from './hunt.js';
import { computeExposureWindow, loadDeployments, formatExposureWindow, artifactCommitMap } from './exposure-window.js';
import { saveRecord, latestRecord, listRecords } from './store.js';
import { buildLifecycleView, formatLifecycleView, loadFindingFromLastScan } from './view.js';

export const HUNT_EXIT = Object.freeze({ NOT_OBSERVED: 0, OBSERVED: 10, INCONCLUSIVE: 11, TELEMETRY_UNAVAILABLE: 12 });
const EXT = { sigma: 'yml', http: 'json', waf: 'conf', 'log-query': 'json', yara: 'yar', spl: 'spl', kql: 'kql', cloudwatch: 'txt', elastic: 'json', yaral: 'yaral', datadog: 'json' };

const usage = () => { console.error('usage: dnr generate <finding-id> [--format sigma|http|waf|log-query|yara|spl|kql|cloudwatch|elastic|yaral|datadog|all] [--out dir] [--allow-unproven]\n       dnr validate <finding-id>\n       dnr hunt <finding-id> --logs <file-or-dir> [--since ISO] [--until ISO]\n       dnr window <finding-id> --deployments <file> [--fix-commit sha] [--environment name]\n       dnr show <finding-id>\n       dnr status <finding-id>'); return 4; };

function ensureDetection(root, id, flags) {
  const existing = latestRecord(root, id, 'detection');
  if (existing && !flags.regenerate) return { ok: true, saved: existing.record };
  const finding = loadFindingFromLastScan(root, id);
  if (!finding) return { ok: false, reason: `Finding ${id} not found in the last scan.` };
  const proofRec = latestProof(root, id);
  const built = buildDetectionIR({ finding, proof: proofRec?.record ?? null, allowUnproven: !!flags['allow-unproven'] });
  if (!built.ok) return { ok: false, reason: built.reason };
  const validation = validateDetection(built.ir);
  const record = { ir: built.ir, validation: { status: validation.status, counts: validation.counts, failures: validation.failures ?? [], reason: validation.reason ?? null }, enabled: validation.status === 'VALIDATED', proof: proofRec?.record ? { recordDigest: proofRec.record.recordDigest ?? null, state: proofRec.record.state ?? null } : null };
  const saved = saveRecord(root, id, 'detection', record);
  if (!saved.ok) return { ok: false, reason: `could not store the detection: ${saved.reason}` };
  return { ok: true, saved: { ...record, recordDigest: saved.digest }, fresh: true };
}

function writeOut(dir, id, ir, formats) {
  // the id names a file: it must be the digest-derived form, never text that arrived from a record on disk
  if (!/^det-[0-9a-f]{12}$/.test(String(ir.id))) { console.error('refusing to write: the detection id is not in its derived form'); return []; }
  fs.mkdirSync(dir, { recursive: true });
  const written = [];
  for (const f of formats) {
    const r = renderDetection(ir, f);
    if (!r.applicable) continue;
    const file = path.join(dir, `${ir.id}.${f === 'log-query' ? 'query' : f}.${EXT[f]}`);
    try { if (fs.lstatSync(file).isSymbolicLink()) { console.error(`refusing to write through a symlink: ${file}`); continue; } } catch { /* does not exist */ }
    fs.writeFileSync(file, r.content);
    written.push(file);
  }
  return written;
}

export async function cmdDnr(args, root) {
  const sub = args._[1];
  const id = String(args._[2] ?? '');
  const flags = args.flags || {};
  if (!sub || !id) return usage();

  if (sub === 'generate') {
    const r = ensureDetection(root, id, { ...flags, regenerate: true });
    if (!r.ok) { console.error(r.reason); return 4; }
    const { ir, validation } = r.saved;
    const want = flags.format ? String(flags.format) : null;
    if (want && want !== 'all' && !FORMATS.includes(want)) { console.error(`unknown format "${want}"; choose one of ${FORMATS.join(', ')}, or all`); return 4; }
    if (flags.json) { console.log(JSON.stringify({ ir, validation, outputs: want && want !== 'all' ? { [want]: renderDetection(ir, want) } : renderAll(ir) }, null, 2)); return validation.status === 'VALIDATED' ? 0 : 1; }
    console.log(`Detection ${ir.id} for ${ir.findingId}: ${ir.payloadClass} (${ir.grounding}, confidence ${ir.confidence})`);
    console.log(`Validation: ${validation.status} (${validation.counts.passed}/${validation.counts.positives + validation.counts.negatives} synthetic cases)${validation.status === 'VALIDATED' ? '; recurrence rule enabled' : '; NOT enabled'}`);
    for (const l of ir.limitations) console.log(`  limitation: ${l}`);
    if (flags.out) { const w = writeOut(path.resolve(String(flags.out)), id, ir, want && want !== 'all' ? [want] : FORMATS); console.log(`Wrote ${w.length} file(s) to ${path.resolve(String(flags.out))}`); }
    else if (want && want !== 'all') { const o = renderDetection(ir, want); console.log(''); console.log(o.applicable ? o.content : `(${want} not applicable: ${o.reason})`); }
    else console.log(`Formats: ${FORMATS.filter((f) => renderDetection(ir, f).applicable).join(', ')} (use --format <name> to print one, --out <dir> to write them)`);
    return validation.status === 'VALIDATED' ? 0 : 1;
  }

  if (sub === 'validate') {
    const rec = latestRecord(root, id, 'detection');
    if (!rec) { console.error(`No detection for ${id}. Run: dnr generate ${id}`); return 4; }
    const errs = validateDetectionIR(rec.record.ir);
    if (errs.length) { console.error(`The stored detection is invalid: ${errs.join('; ')}`); return 1; }
    const v = validateDetection(rec.record.ir);
    if (flags.json) console.log(JSON.stringify(v, null, 2));
    else { console.log(`Validation: ${v.status} (${v.counts.passed}/${v.cases.length} cases)`); for (const c of v.cases.filter((x) => !x.ok)) console.log(`  FAILED: ${c.kind} "${c.name}" ${c.kind === 'positive' ? 'did not fire' : 'fired'}`); if (v.reason) console.log(`  ${v.reason}`); }
    return v.status === 'VALIDATED' ? 0 : 1;
  }

  if (sub === 'hunt') {
    if (!flags.logs) { console.error('dnr hunt needs --logs <file-or-directory>. Nothing was searched.'); return 4; }
    const det = ensureDetection(root, id, flags);
    if (!det.ok) { console.error(det.reason); return 4; }
    const ac = new AbortController();
    const onSig = () => ac.abort();
    process.once('SIGINT', onSig);
    let result;
    try { result = await huntLogs({ ir: det.saved.ir, logsPath: path.resolve(String(flags.logs)), since: flags.since ?? null, until: flags.until ?? null, signal: ac.signal }); } finally { process.off('SIGINT', onSig); }
    const saved = saveRecord(root, id, 'hunt', result);
    if (flags.json) console.log(JSON.stringify({ ...result, stored: saved.ok ? saved.file : null }, null, 2));
    else {
      console.log(`Hunt: ${result.verdict}`);
      console.log(`Logs: ${result.logs.files} file(s), ${result.logs.parsed}/${result.logs.lines} lines parsed${result.window.start ? `, ${result.window.start.slice(0, 10)} to ${result.window.end.slice(0, 10)}` : ', no timestamps'}`);
      if (result.matches.count) console.log(`Matches: ${result.matches.count}${result.matches.firstSeen ? ` (first ${result.matches.firstSeen}, last ${result.matches.lastSeen})` : ''}`);
      for (const s of result.matches.samples.slice(0, 5)) console.log(`  ${s.time ?? 'undated'} ${s.method} ${s.path} [${s.matchedOn}] ${s.valuePreview}`);
      for (const c of result.caveats) console.log(`Caveat: ${c}`);
      console.log(result.statement);
      if (!saved.ok) console.log(`(result not stored: ${saved.reason})`);
    }
    return HUNT_EXIT[result.verdict] ?? 11;
  }

  if (sub === 'window') {
    if (!flags.deployments) { console.error('dnr window needs --deployments <file> (a JSON list of {commit, deployedAt, environment?}; with --artifact-graph, {artifactDigest, deployedAt} is enough). Nothing was computed.'); return 4; }
    const finding = loadFindingFromLastScan(root, id);
    if (!finding) { console.error(`Finding ${id} not found in the last scan.`); return 4; }
    let artifactCommits = null; const graphProblems = [];
    if (flags['artifact-graph']) {
      const docs = [];
      for (const f of String(flags['artifact-graph']).split(',').filter(Boolean)) {
        try { docs.push(JSON.parse(fs.readFileSync(path.resolve(f), 'utf8'))); } catch (e) { graphProblems.push(`artifact graph ${f}: could not be read (${e.code || 'not JSON'})`); }
      }
      const map = artifactCommitMap(docs); artifactCommits = map.commits; graphProblems.push(...map.problems);
    }
    const loaded = loadDeployments(path.resolve(String(flags.deployments)), { environment: flags.environment ?? null, artifactCommits });
    const deployments = loaded.deployments; const problems = [...loaded.problems, ...graphProblems];
    const hunt = latestRecord(root, id, 'hunt')?.record ?? null;
    const telemetry = flags['telemetry-start'] && flags['telemetry-end'] ? { start: flags['telemetry-start'], end: flags['telemetry-end'] } : hunt?.window ?? null;
    const w = computeExposureWindow({ finding, repo: root, deployments, deploymentProblems: problems, fixCommit: flags['fix-commit'] ?? null, telemetry });
    saveRecord(root, id, 'window', w);
    if (flags.json) console.log(JSON.stringify(w, null, 2)); else console.log(`${formatExposureWindow(w)}\n\n${w.statement}`);
    return w.status === 'complete' ? 0 : 1;
  }

  if (sub === 'show') {
    const rec = latestRecord(root, id, 'detection');
    if (!rec) { console.error(`No detection for ${id}.`); return 4; }
    if (listRecords(root, id, 'detection').some((r) => r.tampered)) console.error('WARNING: a stored detection record failed its integrity check and was not used.');
    console.log(JSON.stringify(flags.json ? rec.record : { id: rec.record.ir.id, payloadClass: rec.record.ir.payloadClass, grounding: rec.record.ir.grounding, endpoint: rec.record.ir.endpoint, enabled: rec.record.enabled, validation: rec.record.validation.status, proof: rec.record.proof }, null, 2));
    return 0;
  }

  if (sub === 'status') {
    const v = buildLifecycleView(root, id);
    if (flags.json) console.log(JSON.stringify(v, null, 2)); else console.log(formatLifecycleView(v));
    return 0;
  }
  return usage();
}
