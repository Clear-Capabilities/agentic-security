// R2's differentiator — auto-enrol an execution-proven finding as a permanent
// CVE-replay corpus entry.
//
// The compounding asset: a finding that was PROVEN by execution becomes a
// regression test that the baseline gate defends forever. Every exploit the
// pipeline proves once, it can never silently stop detecting.
//
// THE CENTRAL RULE: nothing is written to the corpus that has not been scored.
// The v0.106.0 failure — fixtures committed without verifying they actually
// score, which then broke the gate for everyone — is the exact mistake this
// module must not automate. So enrolment builds the entry in a TEMPORARY
// directory, scans `pre/` and `post/` with the same matcher the gate uses
// (`corpus-match.js`), and moves it into the corpus only on `pre:TP post:TN`.
// A candidate that does not score is discarded and the reason returned. There
// is no force flag and no "probably fine" path.
//
// WHY A FIX IS MANDATORY. An entry needs a `post/` that scores TN, and the
// only honest source of one is a real fix. Enrolment therefore refuses a
// finding with no fixed content rather than synthesising a `post/` by deleting
// the vulnerable line — that would produce an entry that passes for a reason
// unrelated to the vulnerability, which is worse than no entry.
//
// WHY `capability/` AND NOT `regression/`. `regression/` is the CI-gated tier
// and graduation into it is a human decision with a stated policy (five
// consecutive passing snapshots — see bench/cve-replay/CONTRIBUTING.md). An
// automated writer promoting straight into the gated tier would let a machine
// decide what blocks everyone's build. New entries land in `capability/`,
// already passing, and graduate on the existing policy.
//
// NOTHING THROWS (posture convention): every path returns
// `{ok:false, refused:true, reason}` instead.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { preHit, postHit, matcherFor } from './corpus-match.js';

const DEFAULT_TIER = 'capability';

// Entry ids must be safe to use as a directory name and stable across runs.
const ID_SAFE = /^[A-Za-z0-9._-]+$/;

function refuse(reason) { return { ok: false, refused: true, reason }; }

// A finding is enrollable only if the pipeline actually RAN its exploit. This
// re-checks the evidence rather than trusting `proofTier` alone: the tier is a
// string on an object that may have crossed a process boundary, and the
// consequence of trusting a forged one is a permanent corpus entry.
export function isEnrollable(finding) {
  if (!finding || typeof finding !== 'object') return refuse('no finding supplied');
  if (finding.proofTier !== 'execution-proven') {
    return refuse(
      `only execution-proven findings may enrol; this one is '${finding.proofTier || 'untiered'}'. `
      + 'A statically-reasoned finding has not earned a permanent regression entry.',
    );
  }
  const ev = finding.proofEvidence;
  if (!ev || ev.ran !== true) {
    return refuse('proofEvidence does not record a run (ran !== true) — the tier is not backed by evidence');
  }
  if (ev.tier !== 'execution-proven') {
    return refuse(`proofEvidence.tier ('${ev.tier}') disagrees with proofTier — refusing rather than picking one`);
  }
  if (!ev.observed) {
    return refuse('proofEvidence records no observed effect — an execution-proven tier with nothing observed is not evidence');
  }
  return { ok: true };
}

function _slug(s, fallback) {
  const out = String(s || '').trim().replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return out || fallback;
}

/**
 * The entry id. Derived from the finding so re-enrolling the same finding is
 * idempotent (it will be refused as a duplicate) rather than accumulating
 * near-identical entries.
 */
export function entryIdFor(finding) {
  const fam = _slug(finding?.family || finding?.cwe, 'finding');
  const sid = _slug(finding?.stableId || finding?.id, 'unknown');
  return `proven-${fam}-${sid}`.slice(0, 120);
}

/**
 * Build the manifest + file map for a candidate entry, without writing it.
 *
 * @param {object} finding      an execution-proven finding
 * @param {object} opts
 * @param {object} opts.preFiles   rel→content, the VULNERABLE tree
 * @param {object} opts.postFiles  rel→content, the FIXED tree
 */
export function buildCandidate(finding, { preFiles, postFiles, addedAt } = {}) {
  const gate = isEnrollable(finding);
  if (!gate.ok) return gate;

  if (!finding.cwe) return refuse('finding has no cwe — the manifest matcher would be meaningless');
  if (!finding.vuln) return refuse('finding has no vuln — nothing to match on');
  if (!finding.file) return refuse('finding has no file — cannot name the expected file');

  const pre = preFiles && typeof preFiles === 'object' ? preFiles : null;
  const post = postFiles && typeof postFiles === 'object' ? postFiles : null;
  if (!pre || !Object.keys(pre).length) return refuse('no pre/ content supplied — nothing to prove the detector fires on');
  if (!post || !Object.keys(post).length) {
    return refuse(
      'no post/ content supplied. An entry with no fixed tree cannot score post:TN, and '
      + 'synthesising one by deleting the vulnerable code would pass for the wrong reason.',
    );
  }

  // A `post` identical to `pre` cannot be a fix. Catching it here turns a
  // guaranteed post:FP into a clear refusal.
  const same = Object.keys(pre).length === Object.keys(post).length
    && Object.entries(pre).every(([k, v]) => post[k] === v);
  if (same) return refuse('post/ is byte-identical to pre/ — no fix was applied, so the entry cannot score post:TN');

  for (const [label, files] of [['pre', pre], ['post', post]]) {
    for (const [rel, content] of Object.entries(files)) {
      if (typeof content !== 'string') return refuse(`${label}/${rel} content is not a string`);
      if (path.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) {
        return refuse(`${label}/${rel} escapes the entry directory`);
      }
    }
  }

  const id = entryIdFor(finding);
  if (!ID_SAFE.test(id)) return refuse(`derived entry id '${id}' is not a safe directory name`);

  const expectedFile = path.basename(String(finding.file));
  if (!Object.keys(pre).some(rel => path.basename(rel) === expectedFile)) {
    return refuse(`the finding's file '${expectedFile}' is not among the pre/ files — the entry would not test the finding`);
  }

  const manifest = {
    cve: id,
    cwe: finding.cwe,
    family: finding.family || 'unknown',
    language: finding.language || _languageOf(expectedFile),
    summary: `execution-proven ${finding.family || finding.cwe}: ${String(finding.vuln).slice(0, 120)}`,
    expected: {
      file: expectedFile,
      // Match on the exact vuln string this finding carried. A broader regex
      // would let an unrelated detector satisfy the entry.
      vuln_match: _escapeRegex(String(finding.vuln)),
    },
    source: 'execution-proven',
    added_at: addedAt || new Date().toISOString().slice(0, 10),
    provenance: {
      stableId: finding.stableId || null,
      proofBackend: finding.proofEvidence?.backend || null,
      observed: finding.proofEvidence?.observed || null,
      provenAt: finding.proofEvidence?.at || null,
    },
  };

  return { ok: true, id, manifest, preFiles: pre, postFiles: post };
}

function _escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function _languageOf(file) {
  const ext = path.extname(file).toLowerCase();
  return {
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript', '.jsx': 'javascript',
    '.py': 'python', '.java': 'java', '.go': 'go', '.rb': 'ruby',
    '.php': 'php', '.cs': 'csharp', '.rs': 'rust',
  }[ext] || 'unknown';
}

function _writeTree(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
}

/**
 * Materialise a candidate into a staging directory and SCORE it, using the
 * same matcher the corpus gate uses.
 *
 * @param {function} runScan  injected so this module stays free of an engine
 *   import cycle and so tests can drive it without a full scan.
 * @returns {{ok:boolean, status:string, preHit:boolean, postHit:boolean, reason?:string}}
 */
async function scoreCandidate(candidate, runScan, { stagingDir } = {}) {
  const dir = stagingDir || fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-cand-'));
  try {
    const preDir = path.join(dir, 'pre');
    const postDir = path.join(dir, 'post');
    fs.mkdirSync(preDir, { recursive: true });
    fs.mkdirSync(postDir, { recursive: true });
    _writeTree(preDir, candidate.preFiles);
    _writeTree(postDir, candidate.postFiles);
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(candidate.manifest, null, 2) + '\n', 'utf8');

    const matcher = matcherFor(candidate.manifest);
    let pre, post;
    try {
      ({ scan: pre } = await runScan(preDir));
    } catch (e) {
      return { ok: false, status: 'scan-error', preHit: false, postHit: false, reason: `pre/ scan failed: ${e.message}` };
    }
    try {
      ({ scan: post } = await runScan(postDir));
    } catch (e) {
      return { ok: false, status: 'scan-error', preHit: false, postHit: false, reason: `post/ scan failed: ${e.message}` };
    }

    const hitPre = preHit(pre, candidate.manifest, matcher);
    const hitPost = postHit(post, candidate.manifest, matcher);
    const status = `pre:${hitPre ? 'TP' : 'FN'} post:${hitPost ? 'FP' : 'TN'}`;

    if (!hitPre) {
      return {
        ok: false, status, preHit: hitPre, postHit: hitPost, dir,
        reason: 'the detector does not fire on pre/ — the entry would be committed already failing. '
              + 'A PoC proved this finding at runtime but the minimised fixture does not reproduce it statically.',
      };
    }
    if (hitPost) {
      return {
        ok: false, status, preHit: hitPre, postHit: hitPost, dir,
        reason: 'the detector still fires on post/ — the fix does not clear the finding, so the entry cannot score TN.',
      };
    }
    return { ok: true, status, preHit: hitPre, postHit: hitPost, dir };
  } catch (e) {
    return { ok: false, status: 'error', preHit: false, postHit: false, reason: e.message };
  }
}

/**
 * The full path: gate → build → score → commit.
 *
 * Writes into `<corpusRoot>/<tier>/<id>/` ONLY when the candidate scored
 * `pre:TP post:TN`. Anything else leaves the corpus untouched.
 */
export async function enrollProvenFinding(finding, {
  corpusRoot, preFiles, postFiles, runScan, tier = DEFAULT_TIER, addedAt, dryRun = false,
} = {}) {
  if (!corpusRoot) return refuse('no corpusRoot supplied');
  if (typeof runScan !== 'function') return refuse('no runScan supplied — an entry may not be committed unscored');

  const candidate = buildCandidate(finding, { preFiles, postFiles, addedAt });
  if (!candidate.ok) return candidate;

  const dest = path.join(corpusRoot, tier, candidate.id);
  if (fs.existsSync(dest)) {
    return refuse(`entry '${candidate.id}' already exists in ${tier}/ — refusing to overwrite a corpus entry`);
  }

  const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-cand-'));
  try {
    const scored = await scoreCandidate(candidate, runScan, { stagingDir: staging });
    if (!scored.ok) {
      return {
        ok: false, refused: true, id: candidate.id, status: scored.status,
        reason: `not enrolled (${scored.status}): ${scored.reason}`,
      };
    }
    if (dryRun) {
      return { ok: true, dryRun: true, id: candidate.id, status: scored.status, dir: null, manifest: candidate.manifest };
    }

    // Scan state accumulated inside the staged trees must not be committed —
    // it would be scanned as part of the fixture on the next run.
    _stripState(staging);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.renameSync(staging, dest);
    return {
      ok: true,
      id: candidate.id,
      tier,
      status: scored.status,
      dir: dest,
      manifest: candidate.manifest,
      // Said explicitly because a caller that stops here leaves the repo in a
      // state where the gate reports a nudge rather than a pass.
      followUp: 'run `npm run bench:cve-replay:update-baseline` and commit the regenerated corpus-baseline.json',
    };
  } catch (e) {
    return refuse(`enrolment failed: ${e.message}`);
  } finally {
    // If the rename happened, staging no longer exists and this is a no-op.
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

function _stripState(dir) {
  for (const sub of ['pre', 'post']) {
    const s = path.join(dir, sub, '.agentic-security');
    try { fs.rmSync(s, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

// `scoreCandidate` is deliberately NOT exported: an external caller could
// score a candidate and then write it by some other route, which is exactly
// the unscored-write path this module exists to make unavailable. Enrolment
// scores and writes as one operation or not at all.
export const _internals = { DEFAULT_TIER, scoreCandidate, _languageOf, _escapeRegex, _stripState };
