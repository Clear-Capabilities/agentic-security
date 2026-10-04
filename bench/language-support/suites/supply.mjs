// Supply-chain fixtures (PRD 9.2): declared versus resolved dependency graphs for Haskell manifests and Nix flake inputs, and
// advisory replay over version ranges. Each case is exact (the same packages, versions, scopes and pins), or it fails.
import { readJson, source, REPO } from '../lib.mjs';
import { analyzeHaskellManifests } from '../../../scanner/src/language/haskell-manifests.js';
import { analyzeNixInputs } from '../../../scanner/src/language/nix-inventory.js';
import { AdvisoryDb, evaluateComponents } from '../../../scanner/src/language/haskell-sca.js';
import { overlayEvidence } from '../../../scanner/src/language/nix-sca.js';

const key = (x) => JSON.stringify(x, Object.keys(x).sort());
const same = (a, b) => JSON.stringify([...a].map(key).sort()) === JSON.stringify([...b].map(key).sort());

function haskellObserved(c, files) {
  const r = analyzeHaskellManifests(files, {});
  if (c.kind === 'cabal') {
    const deps = r.dependencies.filter((d) => d.name !== 'base');
    return { resolution: deps.every((d) => !d.resolvedVersion) ? 'declared-ranges' : 'resolved', packages: deps.map((d) => ({ name: d.name, constraint: d.declaredRange, scope: d.componentKind === 'test-suite' ? 'test' : 'library' })) };
  }
  return { resolution: r.lockedPackages.length ? 'resolved-exact' : 'unresolved', packages: r.lockedPackages.map((p) => ({ name: p.name, version: p.version })) };
}

function nixObserved(files) {
  const r = analyzeNixInputs({ files });
  const declared = (r.flakes[0] && r.flakes[0].declared) || [];
  const inputs = declared.map((d) => ({ name: d.name, ...(d.lockedFetch && d.lockedFetch.rev ? { rev: d.lockedFetch.rev } : {}), pinned: !!(d.locked && d.lockedFetch && d.lockedFetch.rev) }));
  const follows = declared.flatMap((d) => (d.nestedFollows || []).map((n) => ({ from: d.name, input: n.path.join('.'), to: n.follows })));
  return { resolution: inputs.length && inputs.every((i) => i.pinned) ? 'locked' : 'unresolved', inputs, follows };
}

// An independent oracle for PVP-ordered range membership (not the engine's code): [introduced, fixed) intervals.
const cmp = (a, b) => { const x = a.split('.').map(Number); const y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };
const affected = (ranges, v) => ranges.some((r) => cmp(v, r.introduced) >= 0 && cmp(v, r.fixed) < 0);

export async function runSupply() {
  const supply = readJson('labels/supply.json');
  const out = { manifests: { total: 0, exact: 0, wrong: [] } };
  for (const c of supply) {
    const files = Object.fromEntries(c.files.map((f) => [f, source(`supply-${c.ecosystem}`, c.id, f)]));
    let obs;
    try { obs = c.ecosystem === 'haskell' ? haskellObserved(c, c.files.map((f) => ({ path: f, text: files[f] }))) : nixObserved(files); } catch (e) { obs = { error: String(e && e.message) }; }
    const exp = c.expected;
    const list = c.ecosystem === 'haskell' ? 'packages' : 'inputs';
    const ok = obs[list] && obs.resolution === exp.resolution && same(obs[list], exp[list]) && (c.ecosystem === 'haskell' || same(obs.follows, exp.follows || []));
    out.manifests.total++;
    if (ok) out.manifests.exact++; else out.manifests.wrong.push({ id: c.id, kind: c.kind, observed: obs, expected: exp });
  }
  const bp = readJson('labels/backport.json');
  const rangeOut = { total: 0, correct: 0, wrong: [] };
  for (const rec of bp.records) {
    const events = [...rec.ranges].sort((a, b) => cmp(a.introduced, b.introduced)).flatMap((r) => [{ introduced: r.introduced }, { fixed: r.fixed }]);
    const db = new AdvisoryDb({ records: [{ id: rec.id, aliases: [], affected: [{ package: { ecosystem: 'Hackage', name: rec.package }, ranges: [{ type: 'ECOSYSTEM', events }] }] }], source: 'synthetic', generatedAt: '2026-10-01T00:00:00Z', now: Date.parse('2026-10-03T00:00:00Z') });
    for (const k of rec.cases) {
      const got = evaluateComponents([{ name: rec.package, version: k.version, declaredRange: null }], db).findings.length > 0;
      const want = affected(rec.ranges, k.version);
      rangeOut.total++;
      if (got === want) rangeOut.correct++; else rangeOut.wrong.push({ advisory: rec.id, version: k.version, engine: got, oracle: want });
    }
  }
  const patchOut = { total: 0, correct: 0, wrong: [], note: 'name-only patch evidence is never a verified fix: patched-by-backport means patch evidence is present, not that the advisory is closed' };
  for (const x of bp.nixPatch) {
    const text = source('backport-nix', x.id, 'configuration.nix');
    const ev = overlayEvidence({ 'configuration.nix': text });
    const hasPatch = Object.values(ev).some((p) => (p.patches || []).some((q) => String(q.name).includes(x.advisory)));
    const got = hasPatch ? 'patched-by-backport' : 'unpatched';
    patchOut.total++;
    if (got === x.expected) patchOut.correct++; else patchOut.wrong.push({ id: x.id, engine: got, expected: x.expected });
  }
  out.advisoryRanges = rangeOut; out.nixPatchEvidence = patchOut;
  out.provenance = { synthetic: true, note: 'range records are synthetic; the real pinned HSEC records are exercised by test/haskell/haskell-sca.test.js (HS-009)' };
  void REPO;
  return out;
}
