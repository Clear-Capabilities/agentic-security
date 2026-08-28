// Subprocess helper for direct-SCA fixtures in this corpus.
//
// engine.js resolves its OSV disk cache from `os.homedir()` at MODULE LOAD
// TIME (`scanner/src/engine.js`'s `_CACHE_DIR`), so pointing a scan at a
// throwaway, pre-seeded cache means pointing `HOME` there BEFORE `runScan` is
// ever imported — something an in-process runner cannot do once the real
// engine module is already loaded for the SAST-kind fixtures. This mirrors
// `scanner/test/helpers/sca-provenance-scan.mjs`, the same pattern the
// provenance pipeline-integration test suite already uses for exactly this
// reason.
//
// HARD OFFLINE, not belt-and-braces. `AGENTIC_SECURITY_OFFLINE=1` gates the
// EPSS/KEV enrichers but not queryOSV's own POST to api.osv.dev — verified
// directly in that upstream test file's own comment. Killing `fetch` outright
// makes this whole process structurally incapable of reaching the network, so
// the only advisory data that can reach the scored result is what the runner
// seeded into HOME's cache before spawning this file.
//
// argv: <fixtureRoot>. Emits `scan.supplyChain`, findingProvenance included,
// as JSON on stdout.
globalThis.fetch = async (url) => {
  throw new Error(`network disabled in provenance-accuracy sca helper (attempted: ${url})`);
};

const HERE = new URL('.', import.meta.url);
const { runScan } = await import(new URL('../../scanner/src/runScan.js', HERE));

const [, , fixtureRoot] = process.argv;
const { scan } = await runScan(fixtureRoot, { network: false });
const out = (scan.supplyChain || []).map((sc) => ({
  type: sc.type,
  name: sc.name || null,
  isDirect: sc.isDirect === true,
  osvId: sc.osvId || null,
  findingProvenance: sc.findingProvenance || null,
}));
process.stdout.write(JSON.stringify(out));
