#!/usr/bin/env node
// Mine an independent evaluation population from published security advisories.
//
// WHY THIS EXISTS. bench/cve-replay/ is a regression net whose fixtures and
// labels are both written here, so its detection rate is at the ceiling by
// construction and cannot support an accuracy claim —
// scripts/corpus-provenance-check.mjs says so directly. This produces the other
// instrument: real upstream code, labelled by people who have never seen these
// detectors.
//
// WHAT MAKES A CANDIDATE ADMISSIBLE. An advisory qualifies only if it carries
// BOTH a CWE assigned by the advisory database AND exactly one referenced fix
// commit in a single repository. Both halves matter:
//   - no CWE  => nothing to score against, and inventing one here would
//                reintroduce the self-labelling this whole track exists to
//                escape;
//   - no single fix commit => no way to derive a vulnerable/fixed pair, and
//                guessing which of several commits fixed it is a judgement we
//                would be making about our own test set.
//
// WHAT THIS DOES NOT DO. It does not decide whether an entry is detectable, and
// it never consults the scanner. The mining step must stay blind to the engine's
// opinion — the moment admission depends on whether we find the bug, the
// population stops measuring anything. That is the exact failure the corpus
// provenance check was written to catch, and it is much easier to commit here.
//
// Usage:
//   node bench/independent/mine.mjs                    # default ecosystems
//   node bench/independent/mine.mjs --limit 40
//   node bench/independent/mine.mjs --ecosystem npm,pip
//   node bench/independent/mine.mjs --ecosystem go,rubygems --pages 12 --limit 200

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.join(HERE, 'manifest.json');
const FORGE_CLI = 'gh';

// Extensions the engine has a real IR or detector story for. Mining an advisory
// whose fix touches only, say, documentation would add an entry that can never
// be a true positive and would quietly depress recall.
const SOURCE_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|java|cs|kt|go|php|rb)$/i;

// Paths that are NOT the implementation, and must never become an entry's
// vulnerable file.
//
// A security fix commit almost always touches the fix AND its regression test,
// and often a rebuilt bundle. Taking the first modified source file therefore
// picked a spec file or `dist/` output about a third of the time — measured on
// the first population: 4 of 12 entries had a test or build artifact as their
// PRIMARY file, and 15 of 34 files overall were non-implementation.
//
// That is not a small bias. The vulnerability is in the implementation; a test
// asserts the fix and a bundle is generated. Scoring the engine on either
// grades it against code that was never supposed to contain the bug, and every
// such entry is a guaranteed false negative that looks like a detection
// failure. Recall was being depressed by the sampling, not by the engine.
const NON_IMPLEMENTATION = new RegExp([
  '\\.test\\.', '\\.spec\\.',              // foo.test.ts, foo.spec.js
  '__tests__/', '__mocks__/',
  '(^|/)tests?/',                            // test/ or tests/ at any depth
  '(^|/)e2e/', '(^|/)fixtures?/',
  '\\.d\\.ts$',                              // type declarations carry no logic
  '(^|/)dist/', '(^|/)build/', '(^|/)vendor/',
  '\\.min\\.js$', '\\.bundle\\.js$',
].join('|'), 'i');

export function isImplementationFile(file) {
  return SOURCE_EXT.test(file) && !NON_IMPLEMENTATION.test(file);
}

const LANG_BY_EXT = {
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescript', py: 'python', java: 'java',
  cs: 'csharp', kt: 'kotlin', go: 'go', php: 'php', rb: 'ruby',
};

function forge(args) {
  const r = spawnSync(FORGE_CLI, args, { encoding: 'utf8', shell: false, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) return null;
  try { return JSON.parse(r.stdout); } catch { return null; }
}

// Like forge(), but also returns the `after` cursor from the Link header.
// `gh api -i` prints headers followed by a blank line and then the body.
function forgeWithLink(args) {
  const r = spawnSync(FORGE_CLI, [...args, '-i'], { encoding: 'utf8', shell: false, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) return null;
  const out = String(r.stdout || '');
  const split = out.indexOf('\r\n\r\n') >= 0 ? out.indexOf('\r\n\r\n') + 4 : out.indexOf('\n\n') + 2;
  const head = out.slice(0, split);
  let body = null;
  try { body = JSON.parse(out.slice(split)); } catch { return null; }
  const link = head.split(/\r?\n/).find(l => /^link:/i.test(l)) || '';
  const m = link.match(/[?&]after=([^&>]+)[^>]*>;\s*rel="next"/);
  return { body, next: m ? m[1] : null };
}

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

/** Pull the single {owner, repo, sha} fix commit out of an advisory, or null. */
export function fixCommitOf(advisory) {
  const refs = (advisory?.references || []).filter(r => typeof r === 'string');
  const commits = [];
  for (const r of refs) {
    const m = r.match(/github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{7,40})/i);
    if (m) commits.push({ owner: m[1], repo: m[2], sha: m[3] });
  }
  if (commits.length !== 1) return null;               // ambiguous or absent
  const only = commits[0];
  // A fix spanning repositories is not a single pre/post pair.
  if (commits.some(c => c.owner !== only.owner || c.repo !== only.repo)) return null;
  return only;
}

export function languageOf(file) {
  const ext = String(file).split('.').pop().toLowerCase();
  return LANG_BY_EXT[ext] || null;
}

async function main() {
  const limit = parseInt(arg('limit', '25'), 10);
  const ecosystems = arg('ecosystem', 'npm,pip,go,maven,composer,rubygems').split(',');
  const pages = parseInt(arg('pages', '3'), 10);

  const existing = fs.existsSync(MANIFEST)
    ? JSON.parse(fs.readFileSync(MANIFEST, 'utf8'))
    : { schema: 'agentic-security/independent-population@1', entries: [] };
  const seen = new Set(existing.entries.map(e => e.id));

  const added = [];
  for (const ecosystem of ecosystems) {
    if (added.length >= limit) break;
    // PRD F12.4 — the population has to grow toward 750+, and three pages per
    // ecosystem is where it stops finding anything. Ruby and Go are the measured
    // zeros and are also the scarcest: an advisory needs a CWE and exactly one
    // referenced fix commit, and most Ruby advisories reference a release note
    // rather than a commit. Depth is a flag rather than a bigger constant so a
    // routine top-up stays cheap.
    // CURSOR pagination, not page numbers.
    //
    // This loop used `&page=N`, and the advisories endpoint IGNORES it — page 1
    // and page 2 return byte-identical results, verified by hand. So every run
    // since this file was written saw only the FIRST 100 advisories per
    // ecosystem and the population was capped at that by construction: mining
    // rubygems twelve pages deep added exactly one entry, and it looked like
    // scarcity rather than a bug. The endpoint paginates by an `after` cursor
    // handed back in the Link header, which is what this follows now.
    let cursor = null;
    for (let page = 1; page <= pages && added.length < limit; page++) {
      const url = `/advisories?type=reviewed&ecosystem=${ecosystem}&per_page=100` + (cursor ? `&after=${cursor}` : '');
      const res = forgeWithLink(['api', url]);
      const list = res && res.body;
      cursor = res && res.next;
      if (!Array.isArray(list) || list.length === 0) break;

      for (const a of list) {
        if (added.length >= limit) break;
        const cwe = a?.cwes?.[0]?.cwe_id;
        if (!cwe) continue;                                  // unlabelled: skip
        if (seen.has(a.ghsa_id)) continue;

        const refs = (a.references || []).map(r => (typeof r === 'string' ? r : r?.url)).filter(Boolean);
        const fix = fixCommitOf({ references: refs });
        if (!fix) continue;

        // Resolve the commit to its changed source files and its parent.
        const commit = forge(['api', `repos/${fix.owner}/${fix.repo}/commits/${fix.sha}`]);
        const parent = commit?.parents?.[0]?.sha;
        if (!parent) continue;

        const files = (commit.files || [])
          .filter(f => f.status === 'modified' && isImplementationFile(f.filename || ''))
          .map(f => f.filename)
          .slice(0, 5); // a sprawling fix is a poor single-CWE test case
        // An advisory whose fix touched only tests or build output tells us
        // nothing about detection and is skipped entirely rather than admitted
        // with a file that cannot contain the bug.
        if (files.length === 0) continue;

        added.push({
          id: a.ghsa_id,
          cve: a.cve_id || null,
          cwe,
          // Provenance is the whole point of this population: record WHO
          // labelled it, so nothing self-authored can drift in unnoticed.
          labelSource: 'github-security-advisory',
          severity: a.severity || null,
          summary: (a.summary || '').slice(0, 160),
          repo: `${fix.owner}/${fix.repo}`,
          fixCommit: commit.sha,
          parentCommit: parent,
          files,
          language: languageOf(files[0]),
          minedAt: new Date().toISOString(),
        });
        seen.add(a.ghsa_id);
        process.stderr.write(`  + ${a.ghsa_id}  ${cwe}  ${fix.owner}/${fix.repo}  (${files.length} file(s))\n`);
      }
    }
  }

  const out = { ...existing, entries: [...existing.entries, ...added] };
  out.entries.sort((a, b) => (a.id < b.id ? -1 : 1)); // deterministic ordering
  fs.writeFileSync(MANIFEST, JSON.stringify(out, null, 2) + '\n');
  process.stderr.write(`\n${added.length} new entr(y|ies); ${out.entries.length} total in manifest.\n`);
  if (added.length === 0) {
    process.stderr.write('No new admissible advisories found. An advisory needs BOTH a CWE and\n' +
      'exactly one referenced fix commit touching source files.\n');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { process.stderr.write(`mine failed: ${e.message}\n`); process.exit(1); });
}
