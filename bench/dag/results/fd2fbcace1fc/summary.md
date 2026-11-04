# bench/dag results

Commit `fd2fbcace1fc`, mode **full**, reps 1, wall clock 200s, darwin-arm64, 8 CPUs, 16 GB, Node v24.20.0. Generated 2026-11-04T21:49:32.726Z.

Timing and memory below are raw measurements from this host and are not part of the equality check. Everything else is deterministic and is what `--check` compares.

## Per-language results (natural code)

| Language | Units (ok/total) | Files | Labeled sample | Precision | Recall | Graph completion rate | Truncated query rate | p50 / p95 ms (n) | Peak RSS MB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| js | 4/4 | 125 | TP 5 FP 3 FN 0 TN 19 (excluded 2) | 62.5% (5/8) | 100.0% (5/5) | 100.0% (4/4) | 0.0% (0/222) | 443 / 4050 (4) | 412 |
| haskell | 5/5 | 115 | TP 14 FP 0 FN 2 TN 3 (excluded 3) | 100.0% (14/14) | 87.5% (14/16) | 100.0% (5/5) | 0.0% (0/35) | 877 / 1686 (5) | 447 |
| nix | 3/3 | 295 | TP 6 FP 2 FN 0 TN 9 (excluded 1) | 75.0% (6/8) | 100.0% (6/6) | 100.0% (3/3) | n/a (0) | 45310 / 68539 (3) | 801 |

Denominators. Precision = TP / (TP + FP) over labeled sites the scanner reported on. Recall = TP / (TP + FN) over labeled positive sites. Completion rate = units whose lineage graph reports status `complete` over units that produced a graph. Truncated query rate = path queries that hit a budget over call-statement sink sites (the number of path queries the graph builder issues; the builder does not export a separate query count, so this denominator is an approximation, stated here rather than hidden). p95 over a small number of units is close to the maximum; with `--reps` it is over repeated samples of the same units, not over more projects.

Line-precise view (a finding without a line number is NOT credited to any label, so only line-level matches count as reported):

| Language | Labeled sample | Precision | Recall |
| --- | --- | --- | --- |
| js | TP 5 FP 3 FN 0 TN 19 (excluded 2) | 62.5% (5/8) | 100.0% (5/5) |
| haskell | TP 14 FP 0 FN 2 TN 3 (excluded 3) | 100.0% (14/14) | 87.5% (14/16) |
| nix | TP 6 FP 2 FN 0 TN 9 (excluded 1) | 75.0% (6/8) | 100.0% (6/6) |

## Held-out subset

A label is held out when the first byte of sha256(label id) is divisible by 3. The split depends on the id only. The benchmark itself never tunes the scanner. The scanner precision changes recorded in docs/implementation-status/dag-improvements.md were diagnosed from the labeled false-positive sites of BOTH columns (the baseline lists every site), so for those changes the held-out column is not held out; what guards against fitting is that each change is a general rule with a both-directions test in bench/mutation and the recall gates unchanged. Anyone who tunes further should leave the held-out subset alone. Disclosure: the same person wrote every label and chose negatives after looking at which sites the scanner reported on, so even the held-out subset is not independent of the labeller.

| Language | Development | Held-out |
| --- | --- | --- |
| js | TP 3 FP 1 FN 0 TN 14 (excluded 2); P 75.0% (3/4); R 100.0% (3/3) | TP 2 FP 2 FN 0 TN 5 (excluded 0); P 50.0% (2/4); R 100.0% (2/2) |
| haskell | TP 10 FP 0 FN 1 TN 2 (excluded 3); P 100.0% (10/10); R 90.9% (10/11) | TP 4 FP 0 FN 1 TN 1 (excluded 0); P 100.0% (4/4); R 80.0% (4/5) |
| nix | TP 5 FP 2 FN 0 TN 6 (excluded 1); P 71.4% (5/7); R 100.0% (5/5) | TP 1 FP 0 FN 0 TN 3 (excluded 0); P 100.0% (1/1); R 100.0% (1/1) |

## Labeled sample by class

| Language / class | TP | FP | FN | TN |
| --- | --- | --- | --- | --- |
| haskell/cookie-flags | 1 | 0 | 0 | 0 |
| haskell/open-redirect | 0 | 0 | 0 | 0 |
| haskell/unbounded-body | 3 | 0 | 0 | 0 |
| haskell/unsafe-boundary | 0 | 0 | 2 | 0 |
| haskell/weak-hash | 1 | 0 | 0 | 0 |
| haskell/weak-rng | 1 | 0 | 0 | 0 |
| haskell/xss | 8 | 0 | 0 | 3 |
| js/csrf | 0 | 0 | 0 | 0 |
| js/open-redirect | 4 | 0 | 0 | 4 |
| js/path-traversal | 0 | 0 | 0 | 1 |
| js/privacy-log | 0 | 0 | 0 | 3 |
| js/sync-io | 0 | 0 | 0 | 2 |
| js/xss | 1 | 3 | 0 | 9 |
| nix/nix-script | 0 | 2 | 0 | 2 |
| nix/nix-secret | 0 | 0 | 0 | 7 |
| nix/pam-empty-password | 1 | 0 | 0 | 0 |
| nix/root-service | 5 | 0 | 0 | 0 |

File-level credits (a finding without a line number credited to every same-class label in its file): 0 of 69 scored labels.

## Controlled multi-service fixture

Authored for this benchmark, HTTP api to queue worker to storage to HTTP reporting. Reported separately from natural-code metrics. Labels live outside the scanned tree and the sources carry no labels or comments.

| Label | Type | Verdict | Construct | Outcome |
| --- | --- | --- | --- | --- |
| ms:F1 | flow | positive | http -> queue | TP (sink kind matches) |
| ms:F2 | flow | positive | http -> queue (numeric coercion keeps the data flow) | TP (sink kind matches) |
| ms:F3 | flow | positive | http -> storage | TP (sink kind matches) |
| ms:F4 | flow | positive | queue -> storage (cross-service boundary) | TP (sink kind matches) |
| ms:F5 | flow | positive | storage -> http response | TP (sink kind matches) |
| ms:F6 | flow | positive | storage -> http response | TP (sink kind matches) |
| ms:N1 | flow | negative | no request data: Date.now() timestamp | TN |
| ms:N2 | flow | negative | configuration value is not request data | TN |
| ms:N3 | flow | negative | wrong topic: the audit queue carries only a constant, so no request field reaches audit.line | TN |
| ms:S1 | site | positive | stored value into html via concat | FN |
| ms:S2 | site | negative | escapeHtml applied to the stored value | TN |
| ms:S3 | site | negative | audit lines are a constant string end to end | TN |
| ms:S4 | site | positive | stored profile bio into html | FN |

Fixture totals: TP 6 FP 0 FN 2 TN 5. Recall 75.0% (6/8), precision 100.0% (6/6). 2 missed positives are scanner gaps (a site label needs the taint engine to see the flow, a flow label needs the lineage graph to join it), recorded rather than hidden.

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
| fixture | 0 | 0 | 1 | 0 | 0 | 0 | equal (3 findings) | 209 | 91 | 71 | 68 |
| fastify/examples | 0 | 0 | 1 | 0 | 0 | 0 | equal (3 findings) | 298 | 110 | 94 | 102 |

Counts are persisted summary units (functions the taint engine analysed), selected with the engine's own `diffFileHashes` and `pickReusableSummaries`; the edit appends one function to one JS file. Parity compares the findings of an incremental warm scan with a cold scan of the same edited tree.

## Evidence replay (witness bundles)

For each sink with a reconstructed witness, up to 60 per unit (sinks in id order, a path that crosses a call boundary preferred), a bundle is built from the real hop stream with `buildWitnessBundle`, signed with an ephemeral Ed25519 key, and replayed offline with `verifyWitness` against the exact artifacts (graph, provenance export, source blobs). Replay success is replayed / built. The bundles are built in-process from `runFieldIdentityAnalysis` with `recordHop`, the same way the witness-bundle tests do; a scan does not persist the hop stream, so there is no `attest --witness` path to measure.

| Unit | Sinks with a path | Bundles attempted | Build refused | Built | Replayed | Replay failed | Built across a call boundary | Replayed across a call boundary | Complete overall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fixture/multiservice | 5 | 5 | 0 | 5 | 100.0% (5/5) | 0 | 0 | n/a (0) | 100.0% (5/5) |
| fixture/callreturn | 7 | 7 | 0 | 7 | 100.0% (7/7) | 0 | 7 | 100.0% (7/7) | 100.0% (7/7) |
| express/lib | 2 | 2 | 0 | 2 | 100.0% (2/2) | 0 | 0 | n/a (0) | 100.0% (2/2) |
| express/examples | 36 | 36 | 0 | 36 | 100.0% (36/36) | 0 | 0 | n/a (0) | 100.0% (36/36) |
| fastify/lib | 15 | 15 | 0 | 15 | 100.0% (15/15) | 0 | 14 | 100.0% (14/14) | 33.3% (5/15) |
| fastify/examples | 4 | 4 | 0 | 4 | 100.0% (4/4) | 0 | 0 | n/a (0) | 100.0% (4/4) |
| **all** | 69 | 69 | 0 | 69 | 100.0% (69/69) | 0 | 21 | 100.0% (21/21) | 85.5% (59/69) |

Replay failure codes: none. Build refusals: none.

Tamper rejection, on the first 40 replayable bundles of each unit. The unmodified bundle replaying (above) is the control for each row.

| Tamper | Rejected |
| --- | --- |
| a recorded edge changed and the bundle re-signed (only replay can catch it) | 100.0% (69/69) |
| a recorded edge changed, signature left alone | 100.0% (69/69) |
| a bound source file altered | 100.0% (69/69) |
| the graph artifact replaced by a different graph | 100.0% (69/69) |

A rejection rate is over the tamper kinds listed. It says nothing about tamper kinds not tried (a changed transfer model, a swapped provenance export with a consistent digest).

## False source attribution

A reported flow is a false attribution when the source field it names is not the field the hand label says reaches that sink. Definitions and the labelling method are in `lib/attribution.mjs` and `labels/real-flows.json`. This is not a recall measure: a flow the scanner did not report is not examined.

Controlled multi-service fixture: 8 flows reported, 8 examined (the flow's source file is the source file of a positive flow label), 0 not examined. Correct: 87.5% (7/8). False attributions (sibling or spurious field): 12.5% (1/8). Reported flows matching a negative label (a field that must not reach that sink): 0.0% (0/3) of the negative labels. Positive labels with no matching reported flow: 0.

Limit: two of the three reported flows end in the same unresolved sink, so the fixture cannot tell the `note` flow from the `qty` flow by sink; it can only catch a field that no positive label for that file names.

| Reported fields | Sink | Source files | Positive-label fields for that source file | Outcome |
| --- | --- | --- | --- | --- |
| note | sink/http-response | api/server.js, reporting/server.js, worker/consumer.js | bio, note, qty | correct |
| qty | queue/queue | api/server.js, reporting/server.js, worker/consumer.js | bio, note, qty | correct |
| note | sink/http-response | api/server.js, reporting/server.js, worker/consumer.js | bio, note, qty | correct |
| qty | store/database | api/server.js, reporting/server.js, worker/consumer.js | bio, note, qty | false |
| note | store/database | api/server.js, reporting/server.js, worker/consumer.js | bio, note, qty | correct |
| bio | sink/http-response | api/server.js, reporting/server.js | bio, note, qty | correct |
| bio | store/database | api/server.js, reporting/server.js | bio, note, qty | correct |
| note | queue/queue | api/server.js, reporting/server.js, worker/consumer.js | bio, note, qty | correct |

| Natural unit | Flows reported | Labeled | Unlabeled | Correct field | Wrong (sibling) field | Spurious (no flow) | Source kind differs from label |
| --- | --- | --- | --- | --- | --- | --- | --- |
| express/lib | 0 | 0 | 0 | n/a (0) | n/a (0) | n/a (0) | n/a (0) |
| express/examples | 9 | 7 | 2 | 85.7% (6/7) | 0.0% (0/7) | 14.3% (1/7) | 0.0% (0/7) |
| fastify/lib | 0 | 0 | 0 | n/a (0) | n/a (0) | n/a (0) | n/a (0) |
| fastify/examples | 4 | 4 | 0 | 100.0% (4/4) | 0.0% (0/4) | 0.0% (0/4) | 25.0% (1/4) |
| **all** | 13 | 11 | 2 | 90.9% (10/11) | 0.0% (0/11) | 9.1% (1/11) | 9.1% (1/11) |

The two lib roots report no flows, so they contribute no denominator. Eleven flows is a small sample; one spurious flow moves the rate by nine points.

## Call/return realizability of reconstructed witnesses

Every sink with a reconstructed witness is queried in a version 1 store (the default) and a version 2 store (`correlationVersion: 2`) built from the same seeds. Each returned witness is walked source to sink by a checker that does not use invocation ids: a return edge must come back through the call site, caller activation and callee activation last entered. A witness that does not is impossible. A witness that begins inside a callee and returns to its caller has an unmatched return, which is realizable and not counted. Cap: 2000 sinks per store (not reached).

| Unit | Sinks v1 / v2 | Witnesses v1 / v2 | Crossing a call boundary v1 / v2 | Impossible v1 | Impossible v2 | v2 mismatched edges pruned | v2 unbalanced-call terminals | v2 context-widened |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fixture/multiservice | 5 / 5 | 5 / 5 | 0 / 0 | n/a (0) | n/a (0) | 0 | 0 | 0 |
| fixture/callreturn | 7 / 7 | 24 / 8 | 17 / 8 | 35.3% (6/17) | 0.0% (0/8) | 4 | 0 | 0 |
| express/lib | 2 / 2 | 2 / 2 | 0 / 0 | n/a (0) | n/a (0) | 0 | 0 | 0 |
| express/examples | 36 / 35 | 48 / 47 | 0 / 0 | n/a (0) | n/a (0) | 0 | 0 | 0 |
| fastify/lib | 15 / 15 | 125 / 93 | 48 / 56 | 0.0% (0/48) | 0.0% (0/56) | 0 | 0 | 0 |
| fastify/examples | 4 / 4 | 4 / 4 | 0 / 0 | n/a (0) | n/a (0) | 0 | 0 | 0 |

All units: impossible witnesses v1 9.2% (6/65), v2 0.0% (0/64) (denominator: witnesses that cross at least one call or return edge). Natural units with a nonzero denominator in either version: fastify/lib; every other natural unit shows n/a (nothing crosses a call boundary), so it says nothing about the versions. The v1 and v2 stores enumerate their sinks independently (version 2 value-versions its nodes), so the sink counts can differ.

## Synthetic graph families (SCC computation)

| Family / nodes | Edges | SCCs | Largest SCC | Matches construction | verifyScc | SCC ms | Peak RSS MB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| chain/1000 | 999 | 1000 | 1 | yes | ok | 2 | 55 |
| chain/10000 | 9999 | 10000 | 1 | yes | ok | 20 | 90 |
| chain/100000 | 99999 | 100000 | 1 | yes | ok | 98 | 334 |
| chain/1000000 | 999999 | 1000000 | 1 | yes | ok | 1229 | 1405 |
| ring/1000 | 1000 | 1 | 1000 | yes | ok | 1 | 54 |
| ring/10000 | 10000 | 1 | 10000 | yes | ok | 11 | 77 |
| ring/100000 | 100000 | 1 | 100000 | yes | ok | 61 | 211 |
| ring/1000000 | 1000000 | 1 | 1000000 | yes | ok | 891 | 1010 |
| fanin/1000 | 999 | 1000 | 1 | yes | ok | 3 | 55 |
| fanin/10000 | 9999 | 10000 | 1 | yes | ok | 20 | 91 |
| fanin/100000 | 99999 | 100000 | 1 | yes | ok | 96 | 332 |
| fanin/1000000 | 999999 | 1000000 | 1 | yes | ok | 1277 | 1423 |
| fanout/1000 | 999 | 1000 | 1 | yes | ok | 2 | 55 |
| fanout/10000 | 9999 | 10000 | 1 | yes | ok | 19 | 86 |
| fanout/100000 | 99999 | 100000 | 1 | yes | ok | 103 | 290 |
| fanout/1000000 | 999999 | 1000000 | 1 | yes | ok | 1195 | 1209 |
| scc-rich/1000 | 1942 | 125 | 8 | yes | ok | 2 | 55 |
| scc-rich/10000 | 19496 | 1250 | 8 | yes | ok | 16 | 91 |
| scc-rich/100000 | 195562 | 12500 | 8 | yes | ok | 113 | 307 |
| scc-rich/1000000 | 1953580 | 125000 | 8 | yes | ok | 1109 | 1611 |

Seeded generators (seed fixed in run.mjs); every graph carries a SHA-256 digest of its edge list in the baseline. Largest size this run: 1,000,000 nodes (host memory permitting). These measure `src/graph/scc.js` on call-graph-shaped inputs; they do not run the taint engine on a million-node program.

## Units

| Unit | Language | Status | Files | Findings | Graph nodes / edges / flows | Graph status | ms (median) | Peak RSS MB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| express/lib | js | ok | 6 | 1 | 5 / 0 / 0 | complete | 443 | 292 |
| express/examples | js | ok | 70 | 84 | 10 / 9 / 9 | complete | 4050 | 412 |
| fastify/lib | js | ok | 31 | 10 | 6 / 0 / 0 | complete | 1301 | 387 |
| fastify/examples | js | ok | 18 | 3 | 5 / 4 / 4 | complete | 430 | 259 |
| scotty/Web | haskell | ok | 11 | 7 | 6 / 0 / 0 | complete | 844 | 333 |
| scotty/examples | haskell | ok | 17 | 18 | 9 / 2 / 2 | complete | 1021 | 317 |
| yesod/yesod-core | haskell | ok | 44 | 2 | 8 / 0 / 0 | complete | 1686 | 447 |
| yesod/yesod-form | haskell | ok | 28 | 0 | 3 / 0 / 0 | complete | 572 | 335 |
| yesod/yesod-auth | haskell | ok | 15 | 2 | 6 / 0 / 0 | complete | 877 | 341 |
| home-manager/modules/services | nix | ok | 218 | 35 | 1 / 0 / 0 | complete | 68539 | 801 |
| nixpkgs-subset/nixos/modules/security | nix | ok | 36 | 37 | 2 / 1 / 1 | complete | 39871 | 557 |
| nixpkgs-subset/nixos/modules/services/web-servers | nix | ok | 41 | 54 | 1 / 0 / 0 | complete | 45310 | 517 |

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
- Evidence replay, false source attribution and call/return realizability are measured in the sections above on the JS/TS units, the multi-service fixture and the call/return fixture only. Haskell and Nix units are not part of these measurements.
- The real-flow attribution labels (labels/real-flows.json) were written after listing the flows the scanner reported, so they judge those flows and are not independent of it.
- Haskell and Nix are analysed statically and never built or evaluated. Nix selections are bounded subsets (see the manifest for roots and exclusions); the Nix numbers say nothing about the rest of nixpkgs or Home Manager.
- Single run per unit by default; p50/p95 are over units (or over repeated samples with --reps) on one host. They are not a reference-host performance claim.
- Synthetic families exercise the SCC computation only. They are not a substitute for a SBOM or conformance program for Haskell or Nix.

