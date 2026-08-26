// Code-derived privacy data inventory + flow graph (assurance-hardening
// PRD FR-406).
//
// Turns the raw signals privacy-taint.js already computes (piiFields,
// findings, policyExemptions — the latter two now carrying sourceName/
// sourceLine, added for this requirement) into per-source-flow inventory
// records, each carrying the PRD's named fields: data class, source,
// transformations, storage, sink/recipient, evidence locations.
//
// "transformations" is honestly disclosed as the literal sentinel
// NOT_MODELED for every record — this engine has no sanitizer/
// transformation tracking for privacy flows specifically; that is FR-403's
// deferred scope (confirmed large this session, needing "an actual
// dataflow-aware rewrite"). Fabricating a transformation chain this engine
// cannot see would be exactly the vacuous-satisfaction failure mode
// FR-405/FR-407 both guard against for their own fields — this module
// applies the identical discipline here rather than inventing partial
// credit.
//
// STORAGE_SINK_KINDS names the subset of privacy-taint.js's sink
// categories that represent data AT REST (file writes, object storage) as
// opposed to data IN TRANSIT (log, response, outbound HTTP, third-party
// SDK, email) — this is what separates the PRD's "storage" field from its
// "sink/recipient" field. It is necessarily incomplete: this engine has no
// sink entries for a database write, a message queue, or most managed
// storage services, so an empty storage array does NOT mean "no storage
// exists" — the artifact says so explicitly rather than implying a
// negative that was never checked.

export const NOT_MODELED = 'not_modeled';
export const STORAGE_SINK_KINDS = new Set(['fileWrite', 's3Upload']);

function _evidenceLocations(record) {
  const locs = [];
  if (record.source) locs.push({ file: record.source.file, line: record.source.line, role: 'source' });
  for (const s of record.storage) locs.push({ file: s.file, line: s.line, role: 'storage' });
  for (const r of record.sinkRecipient) locs.push({ file: r.file, line: r.line, role: 'recipient' });
  return locs;
}

/**
 * Build the data inventory: one record per (data class, source variable)
 * pair actually observed reaching at least one sink, prohibited or
 * policy-permitted. A source with no observed sink at all (declared but
 * never flowed anywhere the annotator's sink catalog recognizes) is NOT
 * included — this is an inventory of REAL, observed flows, not a listing
 * of every regulated-looking field name.
 */
export function buildDataInventory(piiFields, findings, policyExemptions) {
  // Key: `${file}::${sourceName}::${classes.join(',')}` — the same source
  // variable can carry more than one class (e.g. name+PII, ssn+PII), and a
  // record must not merge two variables that happen to share a name across
  // different files.
  const byKey = new Map();

  const declByFileName = new Map(); // `${file}::${name}` -> piiField (for declaredType / line fallback)
  for (const f of piiFields || []) {
    declByFileName.set(`${f.file}::${f.name}`, f);
  }

  function recordFor(file, name, classes, sourceLine) {
    const key = `${file}::${name}::${classes.join(',')}`;
    let rec = byKey.get(key);
    if (!rec) {
      const decl = declByFileName.get(`${file}::${name}`);
      rec = {
        dataClass: classes,
        source: { file, name, line: sourceLine ?? decl?.line ?? null, declaredType: decl?.declaredType || null },
        transformations: NOT_MODELED,
        storage: [],
        sinkRecipient: [],
      };
      byKey.set(key, rec);
    }
    return rec;
  }

  for (const f of findings || []) {
    if (f.family !== 'pii-exposure' || !f.sourceName) continue;
    const rec = recordFor(f.file, f.sourceName, f.piiClass || [], f.sourceLine);
    const entry = { sinkKind: f.sinkKind, file: f.file, line: f.line, status: 'prohibited', severity: f.severity };
    if (STORAGE_SINK_KINDS.has(f.sinkKind)) rec.storage.push(entry);
    else rec.sinkRecipient.push(entry);
  }
  for (const e of policyExemptions || []) {
    if (!e.name) continue;
    const rec = recordFor(e.file, e.name, e.classes || [], e.sourceLine);
    const reasons = (e.rules || []).map(r => r.reason).filter(Boolean);
    const entry = { sinkKind: e.sinkKind, file: e.file, line: e.line, status: 'policy_permitted', reason: reasons[0] || null };
    if (STORAGE_SINK_KINDS.has(e.sinkKind)) rec.storage.push(entry);
    else rec.sinkRecipient.push(entry);
  }

  const records = [...byKey.values()];
  for (const rec of records) rec.evidenceLocations = _evidenceLocations(rec);
  records.sort((a, b) => (a.source.file + a.source.name).localeCompare(b.source.file + b.source.name));
  return records;
}

/**
 * Emit the machine-readable inventory artifact.
 */
export function emitDataInventoryArtifact(records) {
  return JSON.stringify({
    schemaNote: 'Code-derived privacy data inventory (assurance-hardening PRD FR-406). "transformations" is always "not_modeled" — this engine does not track sanitization/masking/encoding for privacy flows (see FR-403). "storage" is best-effort — only file-write and object-storage sinks are recognized; a database, queue, or managed storage service reached through an unrecognized API will not appear here.',
    generatedAt: new Date().toISOString(),
    records,
  }, null, 2);
}

/**
 * Emit a Mermaid flow-graph: one edge per source -> sink/storage
 * relationship, decorated with the data class and whether the flow is
 * prohibited (still an open finding) or policy-permitted.
 */
export function emitDataFlowGraph(records) {
  const lines = [];
  lines.push('# Privacy data flow graph (assurance-hardening PRD FR-406)');
  lines.push('');
  lines.push('Code-derived — one edge per OBSERVED source -> sink/storage flow.');
  lines.push('A red edge is an open (prohibited) finding; a green edge is policy-permitted.');
  lines.push('');
  lines.push('```mermaid');
  lines.push('graph LR');
  const nodeIds = new Map();
  let n = 0;
  function idFor(label) {
    if (!nodeIds.has(label)) nodeIds.set(label, `n${n++}`);
    return nodeIds.get(label);
  }
  if (!records.length) {
    lines.push('  EMPTY["No regulated-data flows observed"]');
  }
  const edgeLines = [];
  const styleLines = [];
  let edgeIndex = 0;
  for (const rec of records) {
    const srcLabel = `${rec.source.name}\\n(${rec.dataClass.join('+')})\\n${rec.source.file}:${rec.source.line ?? '?'}`;
    const srcId = idFor(srcLabel);
    lines.push(`  ${srcId}["${srcLabel}"]`);
    for (const entry of [...rec.storage, ...rec.sinkRecipient]) {
      const sinkLabel = `${entry.sinkKind}\\n${entry.file}:${entry.line}`;
      const sinkId = idFor(sinkLabel);
      lines.push(`  ${sinkId}[["${sinkLabel}"]]`);
      edgeLines.push(`  ${srcId} --> ${sinkId}`);
      const color = entry.status === 'prohibited' ? '#c0392b' : '#27ae60';
      styleLines.push(`  linkStyle ${edgeIndex} stroke:${color}`);
      edgeIndex++;
    }
  }
  lines.push(...edgeLines, ...styleLines);
  lines.push('```');
  return lines.join('\n');
}
