# bench/dag results

Commit `c72f03970f08` (worktree had uncommitted changes), mode **full**, reps 1, wall clock 304s, darwin-arm64, 8 CPUs, 16 GB, Node v24.20.0. Generated 2026-10-25T15:11:41.919Z.

Timing and memory below are raw measurements from this host and are not part of the equality check. Everything else is deterministic and is what `--check` compares.

## Per-language results (natural code)

| Language | Units (ok/total) | Files | Labeled sample | Precision | Recall | Graph completion rate | Truncated query rate | p50 / p95 ms (n) | Peak RSS MB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| js | 4/4 | 125 | TP 5 FP 20 FN 0 TN 2 (excluded 2) | 20.0% (5/25) | 100.0% (5/5) | 100.0% (4/4) | 0.0% (0/222) | 1069 / 6786 (4) | 347 |
| haskell | 5/5 | 115 | TP 16 FP 0 FN 0 TN 3 (excluded 3) | 100.0% (16/16) | 100.0% (16/16) | 100.0% (5/5) | 0.0% (0/33) | 1422 / 8612 (5) | 378 |
| nix | 3/3 | 295 | TP 6 FP 11 FN 0 TN 0 (excluded 1) | 35.3% (6/17) | 100.0% (6/6) | 100.0% (3/3) | n/a (0) | 71639 / 74755 (3) | 638 |

Denominators. Precision = TP / (TP + FP) over labeled sites the scanner reported on. Recall = TP / (TP + FN) over labeled positive sites. Completion rate = units whose lineage graph reports status `complete` over units that produced a graph. Truncated query rate = path queries that hit a budget over call-statement sink sites (the number of path queries the graph builder issues; the builder does not export a separate query count, so this denominator is an approximation, stated here rather than hidden). p95 over a small number of units is close to the maximum; with `--reps` it is over repeated samples of the same units, not over more projects.

Line-precise view (a finding without a line number is NOT credited to any label, so only line-level matches count as reported):

| Language | Labeled sample | Precision | Recall |
| --- | --- | --- | --- |
| js | TP 1 FP 7 FN 4 TN 15 (excluded 2) | 12.5% (1/8) | 20.0% (1/5) |
| haskell | TP 16 FP 0 FN 0 TN 3 (excluded 3) | 100.0% (16/16) | 100.0% (16/16) |
| nix | TP 6 FP 11 FN 0 TN 0 (excluded 1) | 35.3% (6/17) | 100.0% (6/6) |

## Held-out subset

A label is held out when the first byte of sha256(label id) is divisible by 3. The split depends on the id only. Nothing in this benchmark tunes the scanner, and the scanner was not edited by this workstream; the held-out subset exists so that anyone who does tune against the development labels has a subset they must leave alone. Disclosure: the same person wrote every label and chose negatives after looking at which sites the scanner reported on, so even the held-out subset is not independent of the labeller.

| Language | Development | Held-out |
| --- | --- | --- |
| js | TP 3 FP 13 FN 0 TN 2 (excluded 2); P 18.8% (3/16); R 100.0% (3/3) | TP 2 FP 7 FN 0 TN 0 (excluded 0); P 22.2% (2/9); R 100.0% (2/2) |
| haskell | TP 11 FP 0 FN 0 TN 2 (excluded 3); P 100.0% (11/11); R 100.0% (11/11) | TP 5 FP 0 FN 0 TN 1 (excluded 0); P 100.0% (5/5); R 100.0% (5/5) |
| nix | TP 5 FP 8 FN 0 TN 0 (excluded 1); P 38.5% (5/13); R 100.0% (5/5) | TP 1 FP 3 FN 0 TN 0 (excluded 0); P 25.0% (1/4); R 100.0% (1/1) |

## Labeled sample by class

| Language / class | TP | FP | FN | TN |
| --- | --- | --- | --- | --- |
| haskell/cookie-flags | 1 | 0 | 0 | 0 |
| haskell/open-redirect | 0 | 0 | 0 | 0 |
| haskell/unbounded-body | 3 | 0 | 0 | 0 |
| haskell/unsafe-boundary | 2 | 0 | 0 | 0 |
| haskell/weak-hash | 1 | 0 | 0 | 0 |
| haskell/weak-rng | 1 | 0 | 0 | 0 |
| haskell/xss | 8 | 0 | 0 | 3 |
| js/csrf | 0 | 0 | 0 | 0 |
| js/open-redirect | 4 | 4 | 0 | 0 |
| js/path-traversal | 0 | 1 | 0 | 0 |
| js/privacy-log | 0 | 3 | 0 | 0 |
| js/sync-io | 0 | 2 | 0 | 0 |
| js/xss | 1 | 10 | 0 | 2 |
| nix/nix-script | 0 | 4 | 0 | 0 |
| nix/nix-secret | 0 | 7 | 0 | 0 |
| nix/pam-empty-password | 1 | 0 | 0 | 0 |
| nix/root-service | 5 | 0 | 0 | 0 |

File-level credits (a finding without a line number credited to every same-class label in its file): 17 of 69 scored labels.

## Controlled multi-service fixture

Authored for this benchmark, HTTP api to queue worker to storage to HTTP reporting. Reported separately from natural-code metrics. Labels live outside the scanned tree and the sources carry no labels or comments.

| Label | Type | Verdict | Construct | Outcome |
| --- | --- | --- | --- | --- |
| ms:F1 | flow | positive | http -> queue | TP (reached, sink kind differs) |
| ms:F2 | flow | positive | http -> queue (numeric coercion keeps the data flow) | TP (reached, sink kind differs) |
| ms:F3 | flow | positive | http -> storage | TP (sink kind matches) |
| ms:F4 | flow | positive | queue -> storage (cross-service boundary) | FN |
| ms:F5 | flow | positive | storage -> http response | FN |
| ms:F6 | flow | positive | storage -> http response | FN |
| ms:N1 | flow | negative | no request data: Date.now() timestamp | TN |
| ms:N2 | flow | negative | configuration value is not request data | TN |
| ms:N3 | flow | negative | wrong topic: the audit queue carries only a constant, so no request field reaches audit.line | TN |
| ms:S1 | site | positive | stored value into html via concat | FN |
| ms:S2 | site | negative | escapeHtml applied to the stored value | TN |
| ms:S3 | site | negative | audit lines are a constant string end to end | TN |
| ms:S4 | site | positive | stored profile bio into html | FN |

Fixture totals: TP 3 FP 0 FN 5 TN 5. Recall 37.5% (3/8), precision 100.0% (3/3). 5 missed positives are scanner gaps (for example boundary handoffs the lineage graph does not join), recorded rather than hidden.

## Synthetic injected mutants (verdict flips, not natural-code metrics)

| Mutant | Kind | Base reported | After reported | Expected after | Correct | Flipped |
| --- | --- | --- | --- | --- | --- | --- |
| mut:remove-sanitizer | remove-sanitizer | false | false | true | NO | no |
| mut:wrong-sanitizer-family | wrong-sanitizer | false | false | true | NO | no |
| mut:add-sanitizer | add-sanitizer | false | false | false | yes | no |
| mut:inject-site | inject-flow | false | true | true | yes | yes |
| mut:inject-flow | inject-flow | false | true | true | yes | yes |
| mut:break-flow | break-flow | true | false | false | yes | yes |

Correct after mutation: 66.7% (4/6). Expected flips achieved: 60.0% (3/5). A mutant whose base verdict already equals the expected one cannot show a flip and is counted only under "correct".

## Incremental reuse

| Unit | Summary units | Restorable | Changed files | Changed units | Reused | Invalidated | Warm/cold parity | Cold ms | Warm ms | Warm after edit ms | Cold after edit ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fixture | 12 | 12 | 1 | 3 | 9 | 3 | equal (3 findings) | 389 | 133 | 126 | 128 |
| fastify/examples | 90 | 90 | 1 | 5 | 85 | 5 | equal (10 findings) | 779 | 245 | 238 | 213 |

Counts are persisted summary units (functions the taint engine analysed), selected with the engine's own `diffFileHashes` and `pickReusableSummaries`; the edit appends one function to one JS file. Parity compares the findings of an incremental warm scan with a cold scan of the same edited tree.

## Evidence replay

Status: **skipped**. scanner/src has no witness-bundle module; there is no evidence bundle to replay

## Synthetic graph families (SCC computation)

| Family / nodes | Edges | SCCs | Largest SCC | Matches construction | verifyScc | SCC ms | Peak RSS MB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| chain/1000 | 999 | 1000 | 1 | yes | ok | 4 | 55 |
| chain/10000 | 9999 | 10000 | 1 | yes | ok | 33 | 90 |
| chain/100000 | 99999 | 100000 | 1 | yes | ok | 199 | 341 |
| chain/1000000 | 999999 | 1000000 | 1 | yes | ok | 2261 | 1415 |
| ring/1000 | 1000 | 1 | 1000 | yes | ok | 4 | 54 |
| ring/10000 | 10000 | 1 | 10000 | yes | ok | 24 | 76 |
| ring/100000 | 100000 | 1 | 100000 | yes | ok | 143 | 212 |
| ring/1000000 | 1000000 | 1 | 1000000 | yes | ok | 1605 | 1012 |
| fanin/1000 | 999 | 1000 | 1 | yes | ok | 5 | 55 |
| fanin/10000 | 9999 | 10000 | 1 | yes | ok | 38 | 91 |
| fanin/100000 | 99999 | 100000 | 1 | yes | ok | 207 | 332 |
| fanin/1000000 | 999999 | 1000000 | 1 | yes | ok | 2596 | 1404 |
| fanout/1000 | 999 | 1000 | 1 | yes | ok | 5 | 55 |
| fanout/10000 | 9999 | 10000 | 1 | yes | ok | 35 | 86 |
| fanout/100000 | 99999 | 100000 | 1 | yes | ok | 204 | 291 |
| fanout/1000000 | 999999 | 1000000 | 1 | yes | ok | 2188 | 1214 |
| scc-rich/1000 | 1942 | 125 | 8 | yes | ok | 7 | 55 |
| scc-rich/10000 | 19496 | 1250 | 8 | yes | ok | 38 | 85 |
| scc-rich/100000 | 195562 | 12500 | 8 | yes | ok | 387 | 298 |
| scc-rich/1000000 | 1953580 | 125000 | 8 | yes | ok | 3931 | 1272 |

Seeded generators (seed fixed in run.mjs); every graph carries a SHA-256 digest of its edge list in the baseline. Largest size this run: 1,000,000 nodes (host memory permitting). These measure `src/graph/scc.js` on call-graph-shaped inputs; they do not run the taint engine on a million-node program.

## Units

| Unit | Language | Status | Files | Findings | Graph nodes / edges / flows | Graph status | ms (median) | Peak RSS MB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| express/lib | js | ok | 6 | 1 | 5 / 0 / 0 | complete | 746 | 218 |
| express/examples | js | ok | 70 | 96 | 10 / 7 / 7 | complete | 6786 | 347 |
| fastify/lib | js | ok | 31 | 10 | 6 / 0 / 0 | complete | 1824 | 344 |
| fastify/examples | js | ok | 18 | 10 | 5 / 4 / 4 | complete | 1069 | 214 |
| scotty/Web | haskell | ok | 11 | 2 | 4 / 0 / 0 | complete | 725 | 213 |
| scotty/examples | haskell | ok | 17 | 12 | 8 / 0 / 0 | complete | 1422 | 216 |
| yesod/yesod-core | haskell | ok | 44 | 4 | 7 / 0 / 0 | complete | 2549 | 378 |
| yesod/yesod-form | haskell | ok | 28 | 0 | 3 / 0 / 0 | complete | 706 | 318 |
| yesod/yesod-auth | haskell | ok | 15 | 4 | 6 / 0 / 0 | complete | 8612 | 350 |
| home-manager/modules/services | nix | ok | 218 | 47 | 2 / 2 / 2 | complete | 71639 | 638 |
| nixpkgs-subset/nixos/modules/security | nix | ok | 36 | 50 | 2 / 5 / 5 | complete | 74755 | 335 |
| nixpkgs-subset/nixos/modules/services/web-servers | nix | ok | 41 | 74 | 3 / 2 / 2 | complete | 71553 | 352 |

## Pinned projects

| Project | Commit | License | Resolved this run |
| --- | --- | --- | --- |
| express | 1c6f1b0fe400 | MIT | yes |
| fastify | d40c30d2a680 | MIT | yes |
| scotty | b5f4dfbdbd6c | BSD-3-Clause | yes |
| yesod | 4d3fcc460fab | MIT | yes |
| home-manager | c216bf5a1f17 | MIT | yes |
| nixpkgs-subset | 728418d220a2 | MIT | yes |

## Limitations

- The labeled sample is 69 hand labels across 6 projects, chosen by reading sink sites. It is a sample, not a census: recall is over the positives the labeller found, not over every vulnerability in the projects.
- Negatives were mostly chosen at sites the scanner had reported on, with a smaller number of unreported sinks added as true negatives. Precision is therefore a statement about the labeled flagged sites, not a population false-positive rate.
- Natural vulnerable examples are scarce. Most positives are example-app patterns (reflected parameters, Referer redirects) and framework weaknesses (fast hash, non-cryptographic session ids), not exploitable production bugs.
- Labels were written by one person who saw the scanner output. The held-out subset is a discipline for future tuning, not independent ground truth.
- Line-less structural findings are credited at file granularity (reported above).
- Not measured here: false source attribution and impossible call/return witnesses. The graph export does not expose a per-witness field/call-return check, and no label set for them exists yet. They stay open requirements rather than being reported as zero.
- Evidence replay is skipped while no witness-bundle module exists (see the Evidence replay section).
- Haskell and Nix are analysed statically and never built or evaluated. Nix selections are bounded subsets (see the manifest for roots and exclusions); the Nix numbers say nothing about the rest of nixpkgs or Home Manager.
- Single run per unit by default; p50/p95 are over units (or over repeated samples with --reps) on one host. They are not a reference-host performance claim.
- Synthetic families exercise the SCC computation only. They are not a substitute for a SBOM or conformance program for Haskell or Nix.

