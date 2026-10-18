// Historical hunting (PRD 7, requirement 4): search local logs for requests that have the shape of the proven exploit.
//
// Four outcomes, and the rules for reaching each are deliberately asymmetric:
//   OBSERVED              at least one event matches. A match is a lead, not a verdict of compromise.
//   NOT_OBSERVED          nothing matched AND the evidence was good enough to look: logs readable and parsed cleanly, every
//                         field the detection needs present on the events, the read not cut short, timestamps available.
//   INCONCLUSIVE          nothing matched but one of those conditions failed. This is the honest answer, never NOT_OBSERVED.
//   TELEMETRY_UNAVAILABLE no readable request records at all.
//
// NOT_OBSERVED never means NOT_EXPLOITED, and the result says so in a field a consumer can test (`notExploitedClaim: false`)
// and in a sentence a person reads.
import path from 'node:path';
import { readLogs } from './log-reader.js';
import { evaluateEvent, requiredFields } from './matchers.js';
import { redactValue, fingerprint } from './redact.js';

export const HUNT_VERDICTS = Object.freeze(['OBSERVED', 'NOT_OBSERVED', 'INCONCLUSIVE', 'TELEMETRY_UNAVAILABLE']);
const MAX_SAMPLES = 20;
const MAX_PARSE_FAILURE_RATIO = 0.05;

const STATEMENTS = {
  OBSERVED: (n) => `${n} request(s) have the shape of this exploit. A match is a lead to investigate, not proof of compromise: a scanner or a test could produce the same request.`,
  NOT_OBSERVED: () => 'No matching request was found in the searched logs. This does not establish that the vulnerability was not exploited: exploitation could have used a route, encoding or time these logs do not cover.',
  INCONCLUSIVE: () => 'No matching request was found, but the logs could not support a negative answer. See the caveats; do not read this as "not exploited".',
  TELEMETRY_UNAVAILABLE: () => 'There were no readable request records to search, so nothing can be said about past exploitation.',
};

const FIELD_COUNT_KEY = { method: 'method', path: 'path', query: 'query', body: 'body', headers: 'headers', status: 'status', auth: 'auth' };

export async function huntLogs({ ir, logsPath, since = null, until = null, signal, limits } = {}) {
  const base = { schema: 'agentic-security/hunt-result', version: 1, findingId: ir.findingId, detectionId: ir.id, detectionDigest: ir.digest, notExploitedClaim: false, egress: 'none' };
  const sinceMs = since ? Date.parse(since) : null;
  const untilMs = until ? Date.parse(until) : null;
  if ((since && Number.isNaN(sinceMs)) || (until && Number.isNaN(untilMs))) {
    return { ...base, verdict: 'INCONCLUSIVE', caveats: ['the --since/--until value is not a valid date, so nothing was searched'], matches: { count: 0, samples: [] }, statement: STATEMENTS.INCONCLUSIVE() };
  }
  const sampleList = [];
  let matchCount = 0; let firstSeen = null; let lastSeen = null;
  let undecidable = 0; const undecidableFields = new Set();
  let endpointEvents = 0; let outOfWindow = 0; let undated = 0;

  const stats = await readLogs(logsPath, {
    signal, limits,
    onEvent(ev) {
      if (sinceMs != null || untilMs != null) {
        if (!ev.time) { undated++; return; }
        const t = Date.parse(ev.time);
        if ((sinceMs != null && t < sinceMs) || (untilMs != null && t > untilMs)) { outOfWindow++; return; }
      }
      const r = evaluateEvent(ir, ev);
      if (r.undecidable) { undecidable++; r.missing.forEach((m) => undecidableFields.add(m)); return; }
      if (ir.endpoint && ev.method === ir.endpoint.method) endpointEvents++;
      if (!r.match) return;
      matchCount++;
      if (ev.time) { if (!firstSeen || ev.time < firstSeen) firstSeen = ev.time; if (!lastSeen || ev.time > lastSeen) lastSeen = ev.time; }
      if (sampleList.length < MAX_SAMPLES) sampleList.push({ time: ev.time, method: ev.method, path: redactValue(ev.path, 160), matchedOn: r.matchedOn, valueFingerprint: fingerprint(r.value), valuePreview: redactValue(r.value, 80), status: ev.status });
    },
  });

  const logs = { source: path.basename(String(logsPath)), files: stats.files.length, filesSkipped: stats.filesSkipped, lines: stats.lines, parsed: stats.parsed, failed: stats.failed, truncated: stats.truncated };
  const window = { start: stats.windowStart, end: stats.windowEnd, datedEvents: stats.eventsWithTime };
  const caveats = [];
  const result = (verdict) => ({ ...base, verdict, logs, window, coverage: { requestedWindow: { since, until }, outOfWindow, undated, endpointEvents, requiredFields: requiredFields(ir), fieldAvailability: Object.fromEntries(Object.entries(FIELD_COUNT_KEY).map(([k, key]) => [k, stats.parsed ? Number((stats.fieldCounts[key] / stats.parsed).toFixed(3)) : 0])) }, matches: { count: matchCount, firstSeen, lastSeen, samples: sampleList }, caveats, statement: STATEMENTS[verdict](matchCount) });

  if (stats.unreadable || stats.parsed === 0) {
    caveats.push(stats.unreadable ? 'the log path could not be read' : stats.lines === 0 ? 'the logs contain no lines' : 'no line was recognised as a request record (supported: common/combined access logs, JSON lines)');
    return result('TELEMETRY_UNAVAILABLE');
  }
  if (matchCount > 0) {
    if (stats.truncated.length || stats.aborted) caveats.push(`the read was cut short (${[...stats.truncated, ...(stats.aborted ? ['aborted'] : [])].join(', ')}); more matches may exist`);
    return result('OBSERVED');
  }
  // nothing matched: decide whether a negative answer is supportable
  const failRatio = stats.lines ? stats.failed / stats.lines : 0;
  if (failRatio > MAX_PARSE_FAILURE_RATIO) caveats.push(`${(failRatio * 100).toFixed(1)}% of lines could not be parsed (limit ${MAX_PARSE_FAILURE_RATIO * 100}%)`);
  if (stats.truncated.length || stats.aborted || stats.budgetExhausted) caveats.push(`the read was cut short (${[...stats.truncated, ...(stats.aborted ? ['aborted'] : [])].join(', ') || 'budget'})`);
  if (undecidable > 0) caveats.push(`${undecidable} event(s) lacked a field this detection needs (${[...undecidableFields].join(', ')}), so they could not be judged`);
  if (!stats.eventsWithTime) caveats.push('no event carries a timestamp, so the searched time window is unknown');
  if (stats.filesSkipped.some((f) => f.reason !== 'not-a-log-extension')) caveats.push(`${stats.filesSkipped.filter((f) => f.reason !== 'not-a-log-extension').length} file(s) were skipped (${[...new Set(stats.filesSkipped.map((f) => f.reason))].join(', ')})`);
  if (undated > 0) caveats.push(`${undated} event(s) had no timestamp and were excluded by the requested window`);
  if (!caveats.length && ir.endpoint && endpointEvents === 0) caveats.push('no request to the endpoint appears in the logs at all (informational: nothing to exploit was seen either)');
  const blocking = caveats.some((c) => !c.startsWith('no request to the endpoint'));
  return result(blocking ? 'INCONCLUSIVE' : 'NOT_OBSERVED');
}
