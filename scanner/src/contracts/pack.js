// The readable companion of a contract: `threat-pack.md`.
//
// The JSON contract is the machine representation. The pack is prose for people and, when the operator opts in, for a model: system
// purpose, trust boundaries, intended behaviour, review priorities, known controls. Two rules keep it honest. Its digest is bound
// into the contract (`threatPack.digest`) and therefore into every frozen manifest the pack influences, so a changed pack is a changed
// contract. And when the pack and the contract disagree (an invariant named in one and not the other) the result is a reviewable
// diagnostic for the operator, never a model's interpretation of which one is right.
//
// Parsing is deliberately shallow: headings, and invariant identifiers written as `INVARIANT-ID` tokens. Nothing in the pack can
// change policy; `stripUntrustedCommands` from the review path is applied before any model sees it.
import { digestOfBytes } from '../posture/assurance/identity.js';

// A bounded character class, no nested quantifier: the dash structure is checked on the match, not in the pattern.
const INVARIANT_TOKEN = /\b[A-Z][A-Z0-9-]{4,63}\b/g;
const looksLikeInvariantId = (s) => s.includes('-') && !s.endsWith('-') && !s.includes('--') && /[A-Z]/.test(s);
const HEADING = /^(#{1,3})\s+(.+?)\s*$/gm;
export const MAX_PACK_BYTES = 256 * 1024;

export function packDigest(text) { return digestOfBytes(Buffer.from(String(text), 'utf8')); }

/** Headings and the invariant identifiers the prose names. Pure. */
export function parsePack(text) {
  const t = String(text ?? '');
  const headings = [];
  let m;
  while ((m = HEADING.exec(t))) headings.push({ level: m[1].length, title: m[2].slice(0, 200) });
  const ids = new Set();
  while ((m = INVARIANT_TOKEN.exec(t))) if (looksLikeInvariantId(m[0]) && !/^(?:HTTP|HTTPS|JSON|CWE|OWASP|TODO)/.test(m[0])) ids.add(m[0]);
  return { headings, invariantIds: [...ids].sort(), bytes: Buffer.byteLength(t, 'utf8'), digest: packDigest(t) };
}

/**
 * Compare a contract with its pack. `issues` is empty when they agree. Each issue names both sources, so a reviewer sees the
 * disagreement as the two documents state it.
 */
export function reconcilePack(contract, packText) {
  const issues = [];
  if (typeof packText !== 'string') return { ok: false, issues: [{ code: 'pack-unreadable', message: 'the readable companion could not be read' }], parsed: null };
  const parsed = parsePack(packText);
  if (parsed.bytes > MAX_PACK_BYTES) issues.push({ code: 'pack-too-large', message: `the pack is ${parsed.bytes} bytes; the limit is ${MAX_PACK_BYTES}` });
  if (contract?.threatPack?.digest && contract.threatPack.digest !== parsed.digest) {
    issues.push({ code: 'pack-digest-mismatch', message: 'the contract binds a different pack digest; the pack changed after the contract was written, or the contract names another pack', contract: contract.threatPack.digest, pack: parsed.digest });
  }
  const declared = new Set((contract?.invariants || []).map((i) => i.id));
  for (const id of parsed.invariantIds) if (!declared.has(id)) issues.push({ code: 'pack-names-undeclared-invariant', message: `the pack names ${id}, which the contract does not declare`, invariantId: id });
  for (const id of declared) if (!parsed.invariantIds.includes(id)) issues.push({ code: 'pack-omits-invariant', message: `the contract declares ${id}, which the pack never mentions`, invariantId: id });
  return { ok: issues.length === 0, issues, parsed };
}
