// Measures the repository's SCC computation on one synthetic graph (child
// process, so peak RSS belongs to this graph alone). Compares what it reports
// against the properties the generator derived by construction.
import { generate } from './generate.mjs';
import { computeScc, verifyScc } from '../../../scanner/src/graph/scc.js';

export function measureSynthetic({ family, n, seed, verify = true }) {
  const t0 = process.hrtime.bigint();
  const g = generate(family, n, seed);
  const tGen = Number((process.hrtime.bigint() - t0) / 1000000n);
  const t1 = process.hrtime.bigint();
  const r = computeScc({ nodes: g.nodes, edges: g.edges });
  const tScc = Number((process.hrtime.bigint() - t1) / 1000000n);
  let largest = 0;
  let recursive = 0;
  for (const c of r.components) {
    if (c.members.length > largest) largest = c.members.length;
    if (c.recursive) recursive++;
  }
  const observed = { sccCount: r.components.length, largestScc: largest, recursiveComponents: recursive, edgeCount: g.edges.length };
  const matches = Object.keys(g.expected).every((k) => g.expected[k] === observed[k]);
  let verified = null;
  let tVerify = null;
  if (verify) {
    const t2 = process.hrtime.bigint();
    const v = verifyScc({ nodes: g.nodes, edges: g.edges }, r);
    tVerify = Number((process.hrtime.bigint() - t2) / 1000000n);
    verified = v.ok;
  }
  return {
    family, n, seed, digest: g.digest, expected: g.expected, observed, matchesExpected: matches,
    verifyScc: verified,
    timesMs: { generate: tGen, scc: tScc, verify: tVerify },
    peakRssMb: Math.round(process.resourceUsage().maxRSS / 1024),
  };
}
