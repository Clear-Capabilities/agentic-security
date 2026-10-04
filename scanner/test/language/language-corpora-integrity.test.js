// QA-001: independent Haskell and Nix/NixOS corpora, labels and anti-cheating controls.
// Suite: language-corpora-integrity.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  sha256, fingerprint, normalizeSource, reviewLabel, reviewPrivacy, integrityProblems, checkPair,
  renameLocals, addMisleadingComments, reflowWhitespace, scramblePath, evaluateFixProposal, stripComments,
} from './corpora/lib.mjs';
import { build, holdoutHashes, DATA, HERE } from './corpora/generate.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..'); // scanner/
const read = (rel) => fs.readFileSync(path.join(DATA, rel), 'utf8');
const readJson = (rel) => JSON.parse(read(rel));
const walk = (dir, out = []) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== 'node_modules' && e.name !== '.agentic-security') walk(p, out); } else out.push(p);
  }
  return out;
};
const LANG = { haskell: 'haskell', nix: 'nix' };

// Everything below is loaded from the committed data on disk, not regenerated.
const labels = readJson('labels/cases.json');
const cases = labels.map((c) => {
  const source = read(`sources/${c.ecosystem}/${c.id}/${c.path}`);
  return { ...c, source, fingerprint: fingerprint(LANG[c.ecosystem], source), normalized: normalizeSource(LANG[c.ecosystem], source) };
});
const manifest = readJson('manifest.json');
const by = (eco) => cases.filter((c) => c.ecosystem === eco);
const count = (xs, f) => xs.filter(f).length;

// Reviewer used as the oracle for metamorphic checks: path-blind and comment-blind by construction.
const analyze = (lang, family, text) => reviewLabel(lang, family, text);

test('[QA-001.AC01] minimum cases, families and unknown counts per ecosystem (section 9.1)', () => {
  for (const [eco, minTotal, minEach] of [['haskell', 500, 250], ['nix', 400, 200]]) {
    const cs = by(eco);
    const vuln = count(cs, (c) => c.label === 'vulnerable');
    const safe = count(cs, (c) => c.label === 'safe');
    const unknown = count(cs, (c) => c.label === 'unknown');
    const families = new Set(cs.filter((c) => c.label !== 'unknown').map((c) => c.family));
    assert.ok(vuln + safe >= minTotal, `${eco}: ${vuln + safe} labeled < ${minTotal}`);
    assert.ok(vuln >= minEach && safe >= minEach, `${eco}: vulnerable=${vuln} safe=${safe}`);
    assert.ok(families.size >= 12, `${eco}: ${families.size} families`);
    assert.ok(unknown >= 40, `${eco}: ${unknown} unknown`);
    // coverage is across origins, not repeated copies of one example
    const origins = new Set(cs.filter((c) => c.label !== 'unknown').map((c) => c.group));
    assert.ok(origins.size >= 12 * 2 * 10, `${eco}: only ${origins.size} distinct origins`);
  }
});

test('[QA-001.AC01] split policy: 50/20/30 by origin, holdout has >=5 vulnerable and >=5 safe per family', () => {
  for (const eco of ['haskell', 'nix']) {
    const labeled = by(eco).filter((c) => c.label !== 'unknown');
    const share = (s) => count(labeled, (c) => c.split === s) / labeled.length;
    assert.ok(Math.abs(share('train') - 0.5) < 0.08, `${eco} train ${share('train')}`);
    assert.ok(Math.abs(share('validation') - 0.2) < 0.08, `${eco} validation ${share('validation')}`);
    assert.ok(Math.abs(share('holdout') - 0.3) < 0.08, `${eco} holdout ${share('holdout')}`);
    for (const family of new Set(labeled.map((c) => c.family))) {
      for (const label of ['vulnerable', 'safe']) {
        const n = count(labeled, (c) => c.family === family && c.label === label && c.split === 'holdout');
        assert.ok(n >= 5, `${eco}/${family}/${label}: holdout has ${n}`);
      }
    }
  }
});

test('[QA-001.AC01] integrity checks pass on the corpus and fail on duplicate or same-origin leakage', () => {
  assert.deepEqual(integrityProblems(cases), []);
  const a = cases.find((c) => c.split === 'holdout' && c.label === 'safe');
  const t = cases.find((c) => c.split === 'train' && c.ecosystem === a.ecosystem);
  // exact duplicate of a holdout source placed in train
  const dup = { ...t, id: 'leak-1', source: a.source, fingerprint: fingerprint(LANG[a.ecosystem], a.source), normalized: a.normalized };
  assert.ok(integrityProblems([...cases, dup]).some((p) => p.startsWith('duplicate-source:')));
  // same content after renaming locals and stripping comments: the normalised fingerprint must still collide
  const renamed = addMisleadingComments(LANG[a.ecosystem], renameLocals(LANG[a.ecosystem], a.source));
  const mut = { ...t, id: 'leak-2', source: renamed, fingerprint: fingerprint(LANG[a.ecosystem], renamed), normalized: normalizeSource(LANG[a.ecosystem], renamed) };
  assert.ok(integrityProblems([...cases, mut]).some((p) => p.startsWith('duplicate-normalized:')), 'a scrambled copy must be caught as a duplicate');
  // one origin group split across train and holdout
  const straddle = { ...t, id: 'leak-3', group: a.group, split: 'train', source: `${t.source}\n-- x`, fingerprint: 'unique-fp', normalized: `${t.normalized}\nzz` };
  assert.ok(integrityProblems([...cases, straddle]).some((p) => p.startsWith('group-straddles-splits:')));
  // a family absent from holdout cannot pass
  const noHold = cases.map((c) => (c.family === a.family && c.split === 'holdout' ? { ...c, split: 'train', group: `${c.group}#moved` } : c));
  assert.ok(integrityProblems(noHold).some((p) => p.startsWith('holdout-too-small:')));
});

test('[QA-001.AC01] labels are independently reviewed: reviewer reproduces every label from comment-stripped source', () => {
  const disagree = cases.filter((c) => reviewLabel(LANG[c.ecosystem], c.family, c.source) !== c.label);
  assert.deepEqual(disagree.map((c) => c.id), []);
  // the reviewer is a distinct implementation: it has a rule for every scored family and none of its code is in the templates
  const fam = (eco) => new Set(by(eco).filter((c) => c.label !== 'unknown').map((c) => c.family));
  const unreviewed = [...fam('haskell')].concat([...fam('nix')]).filter((f) => reviewLabel(f.includes('-') && fam('nix').has(f) ? 'nix' : 'haskell', f, '') === undefined);
  assert.deepEqual(unreviewed, []);
  // a wrong label would be caught
  const c0 = cases.find((c) => c.label === 'safe');
  assert.notEqual(reviewLabel(LANG[c0.ecosystem], c0.family, cases.find((c) => c.family === c0.family && c.label === 'vulnerable').source), 'safe');
});

test('[QA-001.AC01] holdout hashes are frozen and match both disk and a fresh build', () => {
  assert.equal(manifest.frozen, true);
  const ds = build();
  const fresh = holdoutHashes(ds);
  assert.deepEqual(manifest.holdoutHashes, fresh, 'holdout drifted from the frozen manifest');
  for (const [id, h] of Object.entries(manifest.holdoutHashes)) {
    const c = cases.find((x) => x.id === id);
    if (c) assert.equal(sha256(c.source), h, `${id} on disk differs from frozen hash`);
  }
  assert.equal(manifest.holdoutRollup, sha256(Object.entries(manifest.holdoutHashes).map(([k, v]) => `${k}:${v}`).join('\n')));
  assert.ok(Object.keys(manifest.holdoutHashes).length > 300);
  // every holdout case on disk is frozen, none is missing
  assert.equal(count(cases, (c) => c.split === 'holdout') + count(readJson('labels/privacy.json'), (c) => c.split === 'holdout'), Object.keys(manifest.holdoutHashes).length);
  // labels on disk equal a fresh build (determinism)
  assert.deepEqual(ds.cases.map((c) => [c.id, c.label, c.split]), cases.map((c) => [c.id, c.label, c.split]));
});

test('[QA-001.AC01] privacy lineage, supply-chain, fix and mutation-pair fixtures meet section 9.1 minimums', () => {
  const priv = readJson('labels/privacy.json');
  for (const eco of ['haskell', 'nix']) {
    const p = priv.filter((x) => x.ecosystem === eco);
    assert.ok(count(p, (x) => x.expected === 'flow') >= 100, `${eco} positive field-to-sink`);
    assert.ok(count(p, (x) => x.expected === 'no-flow') >= 100, `${eco} negative field-to-sink`);
    assert.ok(count(p, (x) => x.split === 'holdout' && x.expected === 'flow') >= 5);
    assert.ok(count(p, (x) => x.split === 'holdout' && x.expected === 'no-flow') >= 5);
    assert.ok(new Set(p.map((x) => x.kind)).has('sibling-field'), 'field-sibling negatives present');
  }
  for (const x of priv) {
    const dir = x.ecosystem === 'haskell' ? 'src/Privacy.hs' : 'configuration.nix';
    assert.equal(reviewPrivacy(LANG[x.ecosystem], read(`sources/privacy-${x.ecosystem}/${x.id}/${dir}`), x.field), x.expected, x.id);
  }
  const supply = readJson('labels/supply.json');
  const fixes = readJson('labels/fixes.json');
  const pairs = readJson('labels/pairs.json');
  for (const eco of ['haskell', 'nix']) {
    assert.ok(count(supply, (s) => s.ecosystem === eco) >= 20, `${eco} supply variants`);
    assert.ok(count(fixes, (f) => f.ecosystem === eco && f.expected.accepted) >= 20, `${eco} accepted fixes`);
    assert.ok(count(fixes, (f) => f.ecosystem === eco && !f.expected.accepted) >= 10, `${eco} rejected fixes`);
    assert.ok(count(pairs, (p) => p.ecosystem === eco && p.relation === 'preserve') >= 30, `${eco} preserving pairs`);
    assert.ok(count(pairs, (p) => p.ecosystem === eco && p.relation === 'change') >= 30, `${eco} changing pairs`);
  }
  // supply fixtures are checked against an independent parse of their own files
  for (const s of supply) {
    const dir = `sources/supply-${s.ecosystem}/${s.id}`;
    if (s.ecosystem === 'nix' && s.expected.resolution === 'locked') {
      const lock = JSON.parse(read(`${dir}/flake.lock`));
      for (const i of s.expected.inputs) assert.equal(lock.nodes[i.name].locked.rev, i.rev);
    } else if (s.ecosystem === 'nix') {
      for (const i of s.expected.inputs) assert.ok(read(`${dir}/flake.nix`).includes(`${i.name}.url`) && !/\/[0-9a-f]{40}"/.test(read(`${dir}/flake.nix`)));
    } else if (s.kind === 'freeze') {
      for (const p of s.expected.packages) assert.ok(read(`${dir}/cabal.project.freeze`).includes(`any.${p.name} ==${p.version}`));
    } else if (s.kind === 'stack') {
      for (const p of s.expected.packages) assert.ok(read(`${dir}/stack.yaml`).includes(`- ${p.name}-${p.version}`));
    } else {
      for (const p of s.expected.packages) assert.ok(new RegExp(`${p.name} ${p.constraint.replace(/[.^]/g, '\\$&')}`).test(read(`${dir}/app.cabal`)));
    }
  }
  // fix evaluator decisions match the recorded expectations
  for (const f of fixes) {
    const before = read(`sources/fix-${f.ecosystem}/${f.id}/before/${f.targetPath.startsWith('.') ? 'target' : f.targetPath}`);
    const after = read(`sources/fix-${f.ecosystem}/${f.id}/after/proposal`);
    assert.deepEqual(evaluateFixProposal(LANG[f.ecosystem], f.family, before, { after, targetPath: f.targetPath }), f.expected, f.id);
  }
});

test('[QA-001.AC02] engine source cannot reach ground truth, labels, case names or the reviewer', () => {
  const needles = [/test\/language\/corpora/, /corpora\/data/, /qa001-v1/, /labels\/(cases|pairs|privacy|supply|fixes|backport)\.json/, /REVIEW_RULES/, /reviewLabel/, /holdoutHashes/, /\.\.\/test\//];
  const files = [...walk(path.join(ROOT, 'src')), ...walk(path.join(ROOT, 'bin'))].filter((f) => /\.(js|mjs|cjs)$/.test(f));
  assert.ok(files.length > 50);
  const hits = [];
  for (const f of files) {
    const t = fs.readFileSync(f, 'utf8');
    for (const n of needles) if (n.test(t)) hits.push(`${path.relative(ROOT, f)}: ${n}`);
  }
  assert.deepEqual(hits, []);
  // labels live outside the scanned sources tree
  assert.ok(!walk(path.join(DATA, 'sources')).some((f) => f.endsWith('.json') && !/flake\.lock$/.test(f)), 'no label JSON inside sources/');
});

test('[QA-001.AC02] scanned sources carry no answers: opaque ids and paths, no comments, no label words', () => {
  const words = /vulnerab|insecure|unsafe|sanitiz|CWE-|false.positive|\bTODO\b|\bsafe\b|\bsecure\b/i;
  for (const f of walk(path.join(DATA, 'sources'))) {
    const rel = path.relative(path.join(DATA, 'sources'), f);
    const [, id, ...rest] = rel.split(path.sep);
    assert.match(id, /^(hs|nx)[a-z]?-[0-9a-f]{10}$/, rel);
    assert.ok(!words.test(rest.join('/')) || /^(before|after|base|mutant)\//.test(rest.join('/')), `label word in path ${rel}`);
    if (/\/(base|mutant)\//.test(rel) && /decoy|marker/.test(rel)) continue;
  }
  for (const c of cases) {
    const lang = LANG[c.ecosystem];
    assert.equal(stripComments(lang, c.source).replace(/\{-#[\s\S]*?#-\}/g, ''), c.source.replace(/\{-#[\s\S]*?#-\}/g, ''), `${c.id} has comments`);
    assert.ok(!/vulnerab|insecure|CWE-|sanitiz|false.positive/i.test(c.source), `${c.id} names its own label`);
  }
});

test('[QA-001.AC02] identifier, comment and path scrambling preserves verdicts; semantic changes flip them', () => {
  // 1. recorded pairs
  const pairs = readJson('labels/pairs.json');
  let checked = 0;
  for (const p of pairs) {
    const dir = `sources/pair-${p.ecosystem}/${p.id}`;
    const base = read(`${dir}/base/${p.basePath}`);
    const mutant = read(`${dir}/mutant/${p.mutantPath}`);
    const rec = { language: LANG[p.ecosystem], family: p.family, relation: p.relation, base: { path: p.basePath }, mutant: { path: p.mutantPath } };
    assert.ok(checkPair(analyze, rec, { base, mutant }), `${p.id} (${p.relation}/${p.transform}) verdict`);
    if (p.relation === 'preserve') assert.ok(base !== mutant || p.basePath !== p.mutantPath, `${p.id} mutation is a no-op`);
    else assert.notEqual(analyze(rec.language, p.family, base), analyze(rec.language, p.family, mutant));
    checked++;
  }
  assert.ok(checked >= 120);
  // 2. every corpus case under each scramble, computed here rather than read back
  for (const c of cases) {
    const lang = LANG[c.ecosystem];
    const v = analyze(lang, c.family, c.source);
    for (const m of [renameLocals(lang, c.source), addMisleadingComments(lang, c.source), reflowWhitespace(c.source)]) {
      assert.equal(analyze(lang, c.family, m), v, `${c.id} verdict moved under scrambling`);
    }
  }
  // 3. path scrambling cannot matter: the analysis interface has no path input, and scrambled paths carry decoy words
  const sp = scramblePath('src/Svc.hs');
  assert.match(sp, /vuln_secure_marker/);
  assert.equal(analyze.length, 3);
});

test('[QA-001.AC02] the harness catches an analyzer that cheats by reading comments or paths', () => {
  const pairs = readJson('labels/pairs.json').filter((p) => p.relation === 'preserve');
  const commentReader = (lang, family, text) => (/sanitized upstream|hardened per audit/.test(text) ? 'safe' : reviewLabel(lang, family, text));
  const pathReader = (lang, family, text, p) => (/vuln_secure_marker|ok_fixed/.test(p || '') ? 'safe' : reviewLabel(lang, family, text));
  let commentCaught = 0; let pathCaught = 0;
  for (const p of pairs) {
    const dir = `sources/pair-${p.ecosystem}/${p.id}`;
    const texts = { base: read(`${dir}/base/${p.basePath}`), mutant: read(`${dir}/mutant/${p.mutantPath}`) };
    const rec = { language: LANG[p.ecosystem], family: p.family, relation: p.relation, base: { path: p.basePath }, mutant: { path: p.mutantPath } };
    if (p.transform === 'decoy-comments' && !checkPair(commentReader, rec, texts)) commentCaught++;
    if (p.transform === 'path-scramble' && !checkPair(pathReader, rec, texts)) pathCaught++;
  }
  assert.ok(commentCaught >= 5, `comment-reading analyzer escaped (${commentCaught})`);
  assert.ok(pathCaught >= 5, `path-reading analyzer escaped (${pathCaught})`);
  // and a name-keyed answer table (case id -> verdict) is useless on scrambled copies of unseen text
  const table = new Map(cases.map((c) => [sha256(c.source), c.label]));
  const lookup = (lang, family, text) => table.get(sha256(text)) ?? 'unknown';
  const wrong = cases.filter((c) => c.label !== 'unknown' && lookup(LANG[c.ecosystem], c.family, renameLocals(LANG[c.ecosystem], c.source)) !== c.label);
  assert.ok(wrong.length > cases.length / 2, 'answer-table analyzer must fail once text is scrambled');
});

test('[QA-001.AC03] safe fixtures are tagged near misses and use realistic supported libraries and options', () => {
  const tagProof = {
    sanitizer: /takeFileName/, guard: /\bif\b/, allowlist: /isPrefixOf|`elem`/, parameterized: /\?"/, 'argv-separator': /"--"/,
    escaper: /toHtml|toValue|escapeShellArg/, mkForce: /lib\.mkForce/, kdf: /Argon2|PBKDF2/, csprng: /getRandomBytes|randomBytesGenerate/,
    bound: /\bmin\b|BL\.take/, redaction: /length|redact/, 'total-parser': /readMaybe|listToMaybe/, 'hardened-attrs': /setCookieHttpOnly = True/,
    'owner-scope': /AND owner = \?/, 'auth-guard': /header "Authorization"[\s\S]*status401/, 'runtime-path': /\/run\//, 'content-pin': /sha256-/,
  };
  for (const c of cases.filter((x) => x.label === 'safe')) {
    assert.ok(c.nearMiss, `${c.id} safe case has no near-miss tag`);
    if (tagProof[c.nearMiss]) assert.match(c.source, tagProof[c.nearMiss], `${c.id} tag ${c.nearMiss} not evidenced in source`);
  }
  const tags = (eco) => new Set(by(eco).filter((c) => c.label === 'safe').map((c) => c.nearMiss));
  for (const t of ['sanitizer', 'guard', 'parameterized', 'allowlist']) assert.ok(tags('haskell').has(t), `haskell ${t}`);
  assert.ok(tags('nix').has('mkForce'));
  assert.ok(count(by('nix'), (c) => c.label === 'safe' && c.nearMiss === 'mkForce') >= 20);
  assert.ok(count(by('haskell'), (c) => c.label === 'safe' && c.nearMiss === 'sanitizer') >= 10);
  // conditional / unresolved cases wrap real unmodeled constructs, are labelled unknown, and are never reported as vulnerable or safe
  const unk = cases.filter((c) => c.label === 'unknown');
  assert.ok(unk.some((c) => c.nearMiss === 'conditional') && unk.some((c) => c.nearMiss === 'unresolved-construct'));
  for (const c of by('nix').filter((x) => x.label === 'unknown')) assert.match(c.source, /lib\.(mkIf|mkDefault|mkOptionDefault|optionalAttrs|mkMerge)|mkOverride 900|import \.\//);
  for (const c of by('haskell').filter((x) => x.label === 'unknown')) assert.match(c.source, /^#if|\$\(|foreign import|^class Sink|import (qualified )?(Vendor|Legacy|Internal)\./m);
  // realistic supported libraries and NixOS options
  const hsLibs = new Set();
  for (const c of by('haskell')) for (const m of c.source.matchAll(/^import (?:qualified )?([A-Z][\w.]*)/gm)) hsLibs.add(m[1].split('.').slice(0, 2).join('.'));
  for (const lib of ['Database.SQLite', 'Network.HTTP', 'Web.Scotty', 'Web.Cookie', 'Text.Blaze', 'Crypto.KDF', 'System.Process', 'System.Directory']) assert.ok(hsLibs.has(lib), `missing library ${lib}`);
  const nixOpts = new Set();
  for (const c of by('nix')) for (const m of c.source.matchAll(/^  ((?:services|nix|security|networking|systemd|environment|programs)\.[a-zA-Z]+)/gm)) nixOpts.add(m[1]);
  assert.ok(nixOpts.size >= 9, `only ${nixOpts.size} NixOS option roots`);
  for (const o of ['services.openssh', 'nix.settings', 'security.sudo', 'services.nginx', 'networking.firewall', 'systemd.services']) assert.ok(nixOpts.has(o), `missing ${o}`);
});

test('[QA-001.AC03] backport near misses: a fix on an older line makes lower versions safe; patch evidence is recognised', () => {
  const { records, nixPatch } = readJson('labels/backport.json');
  const cmp = (a, b) => { const x = a.split('.').map(Number); const y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };
  const affected = (r, v) => r.ranges.some((g) => cmp(v, g.introduced) >= 0 && cmp(v, g.fixed) < 0);
  const naive = (r, v) => cmp(v, r.ranges.map((g) => g.fixed).sort(cmp).pop()) < 0 && cmp(v, r.ranges.map((g) => g.introduced).sort(cmp)[0]) >= 0;
  let divergences = 0;
  for (const r of records) {
    assert.equal(r.synthetic, true);
    assert.ok(r.cases.length >= 9);
    for (const { version } of r.cases) {
      if (affected(r, version) !== naive(r, version)) divergences++;
    }
    // each record has an exact-boundary pair: last affected and the fixed version
    for (const g of r.ranges) { assert.ok(r.cases.some(({ version }) => cmp(version, g.fixed) === 0 && !affected(r, version))); assert.ok(r.cases.some(({ version }) => affected(r, version))); }
  }
  assert.ok(divergences >= 6, 'fixtures must separate a range-aware matcher from a newest-fixed-version matcher');
  assert.ok(nixPatch.length >= 6);
  for (const p of nixPatch) {
    const t = read(`sources/backport-nix/${p.id}/configuration.nix`);
    assert.equal(/patches = .*\.patch/.test(t) && t.includes(p.advisory), p.expected === 'patched-by-backport', p.id);
  }
  assert.ok(nixPatch.some((p) => p.expected === 'patched-by-backport') && nixPatch.some((p) => p.expected === 'unpatched'));
});

test('[QA-001.AC04] every dataset is licensed and pinned; imports without license and pin are rejected', () => {
  const prov = JSON.parse(fs.readFileSync(path.join(HERE, 'provenance.json'), 'utf8'));
  const problems = (entry) => {
    const p = [];
    if (!/^[A-Za-z0-9.+-]+$/.test(entry.license || '')) p.push('license');
    if (entry.origin === 'generated-in-repo') {
      if (entry.pin !== 'manifest.json#contentRollup') p.push('pin');
    } else if (!(/^[0-9a-f]{40}$/.test(entry.pin || '') || /^sha256:[0-9a-f]{64}$/.test(entry.pin || ''))) p.push('pin');
    if (entry.origin !== 'generated-in-repo' && !/^https:\/\//.test(entry.url || '')) p.push('url');
    return p;
  };
  assert.ok(prov.sources.length >= 7);
  for (const s of [...prov.sources, ...prov.externalImports]) assert.deepEqual(problems(s), [], s.dataset || s.name);
  // negative: unlicensed or unpinned imports fail
  assert.deepEqual(problems({ origin: 'import', url: 'https://example.org/x', license: 'MIT', pin: 'main' }), ['pin']);
  assert.ok(problems({ origin: 'import', url: 'https://example.org/x', pin: 'a'.repeat(40) }).includes('license'));
  assert.ok(problems({ origin: 'import', license: 'MIT', pin: 'a'.repeat(40) }).includes('url'));
  // the pin in the manifest is real: recompute it from the data on disk
  const ds = build();
  const recomputed = readJson('manifest.json').contentRollup;
  assert.match(recomputed, /^[0-9a-f]{64}$/);
  const hs = prov.sources.filter((s) => s.dataset.startsWith('haskell')).length;
  assert.equal(hs, 1);
  assert.ok(ds.cases.length === cases.length);
  // an unmet requirement is declared, not simulated: no real advisory and no canary entry exists in the data
  const gaps = prov.gaps.map((g) => g.requirement).join('\n');
  assert.match(gaps, /real pinned HSEC/);
  assert.match(gaps, /Haskell canary/);
  assert.match(gaps, /Nix\/NixOS canary/);
  assert.ok(prov.gaps.every((g) => ['not-obtained', 'not-run'].includes(g.status) && g.reason));
  assert.ok(!fs.existsSync(path.join(DATA, 'sources', 'advisories')) && !fs.existsSync(path.join(DATA, 'sources', 'canary')));
  assert.ok(readJson('labels/backport.json').records.every((r) => r.synthetic === true), 'synthetic records must not pose as real advisories');
});

test('[QA-001.AC04] no document claims NIST SARD provides Haskell or Nix cases', () => {
  const prov = JSON.parse(fs.readFileSync(path.join(HERE, 'provenance.json'), 'utf8'));
  assert.equal(prov.benchmarks.nistSard.haskell.status, 'not-obtained');
  assert.equal(prov.benchmarks.nistSard.nix.status, 'not-obtained');
  const repo = path.resolve(ROOT, '..');
  const docs = [path.join(repo, 'README.md'), path.join(HERE, 'README.md'),
    ...['docs', 'bench'].flatMap((d) => (fs.existsSync(path.join(repo, d)) ? walk(path.join(repo, d)) : []))]
    .filter((f) => f.endsWith('.md') && !/node_modules|\/(pre|post)\//.test(f));
  const claim = [];
  const negated = /\b(no|not|never|none|without|neither|nor|does not|do not|cannot|unless|absent|n't)\b/i;
  for (const f of docs) {
    for (const [i, line] of fs.readFileSync(f, 'utf8').split('\n').entries()) {
      if (/(SARD|Juliet)/i.test(line) && /\b(Haskell|Nix|NixOS)\b/i.test(line) && !negated.test(line)) claim.push(`${path.relative(repo, f)}:${i + 1}`);
    }
  }
  assert.deepEqual(claim, []);
  // the checker does flag a real claim
  const sample = 'NIST SARD provides Haskell and Nix test cases.';
  assert.ok(/(SARD|Juliet)/i.test(sample) && /\b(Haskell|Nix)\b/i.test(sample) && !negated.test(sample));
  assert.ok(negated.test(fs.readFileSync(path.join(HERE, 'README.md'), 'utf8').split('\n').find((l) => /SARD/.test(l))));
  // no SARD/Juliet-shaped input is present in the Haskell/Nix corpora
  assert.ok(!cases.some((c) => /juliet|sard/i.test(c.id) || /Juliet|SARD/.test(c.source)));
});
