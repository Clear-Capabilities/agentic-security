// Redaction for anything the loop persists or prints from production logs (PRD 7, privacy requirements). A matched log value
// is evidence that an exploit-shaped request existed; it must never also be a copy of a password, a token or regulated data.
// Layered on the proof fabric's secret scrubber (credentials), with the data classes a request log is likely to carry.
import { createHash } from 'node:crypto';
import { scrubDeep } from '../proof-fabric/store.js';

const PATTERNS = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED-EMAIL]'],
  [/\b(?:\d[ -]?){13,19}\b/g, '[REDACTED-NUMBER]'],
  [/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-ID]'],
  [/\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '[REDACTED-CREDENTIAL]'],
  [/\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|session|sid)=[^&\s"']+/gi, (m) => `${m.split('=')[0]}=[REDACTED]`],
  [/\b[A-Za-z0-9+/_-]{40,}={0,2}/g, '[REDACTED-TOKEN]'],
];

/** Redact a string for storage or display, then bound its length. */
export function redactValue(value, max = 120) {
  let t = String(value ?? '');
  for (const [re, rep] of PATTERNS) t = t.replace(re, rep);
  t = scrubDeep(t);
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

/** Stable short fingerprint of the ORIGINAL value, so two sightings of the same payload can be recognised without storing it. */
export const fingerprint = (value) => createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 16);
