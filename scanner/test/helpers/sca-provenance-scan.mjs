// Subprocess helper for the SCA-provenance case in
// test/dataflow/provenance-pipeline-integration.test.js.
//
// Runs in a CHILD process purely so `HOME` can be pointed at a throwaway
// directory: engine.js resolves its OSV cache from `os.homedir()` at module
// load time, so redirecting the cache means redirecting HOME before the import
// happens — which an in-process test cannot do. The upside is that the test
// neither reads nor writes the developer's real `~/.claude` cache, and cannot
// pass merely because that cache happened to be warm.
//
// argv: <fixtureRoot>. Emits the supplyChain shape we assert on as JSON on
// stdout.

// HARD OFFLINE. Not belt-and-braces — load-bearing.
//
// AGENTIC_SECURITY_OFFLINE=1 gates the EPSS and KEV enrichers but NOT
// queryOSV's own POST to api.osv.dev, which was verified directly: a run with a
// cold HOME and OFFLINE=1 still came back with live GHSA ids. So the env var
// alone does not make a scan hermetic, and a test relying on it would keep
// silently passing via the network. Killing `fetch` outright makes this process
// structurally incapable of reaching the network, so the only data that can
// reach the assertions is what the test seeded into the cache. queryOSV wraps
// its fetch in try/catch and falls back to cache, which is exactly the
// real-world offline path this reproduces.
//
// Must run BEFORE the engine import, so the stub is in place for module-load
// side effects too.
globalThis.fetch = async (url) => {
  throw new Error(`network disabled in hermetic test helper (attempted: ${url})`);
};

const { runScan } = await import('../../src/runScan.js');

const [, , fixtureRoot] = process.argv;

const { scan } = await runScan(fixtureRoot);
const out = (scan.supplyChain || []).map((sc) => ({
  type: sc.type,
  name: sc.name || null,
  osvId: sc.osvId || null,
  isDirect: sc.isDirect === true,
  depChain: sc.depChain || [],
  provenance: sc.findingProvenance
    ? {
        status: sc.findingProvenance.status,
        limitations: sc.findingProvenance.limitations || [],
        method: sc.findingProvenance.method,
        confidence: sc.findingProvenance.confidence || null,
        findingOrigin: sc.findingProvenance.findingOrigin || null,
      }
    : null,
}));
process.stdout.write(JSON.stringify(out));
