# Miss forensics

Run `a72968195aa1`. Localized false negatives: **272** of 278 scored; localized true positives: 6. Reconciles: **true**.

| Category | Misses |
|---|---|
| no_detector_candidate | 151 |
| parse_ir_gap | 5 |
| missing_source_or_sink | 81 |
| alias_or_callgraph_gap | 7 |
| sanitizer_misclassification | 0 |
| guard_or_suppression | 0 |
| reachability_demotion | 0 |
| wrong_file_or_cwe | 27 |
| tool_or_setup_incomplete | 1 |
| unlabelled_ambiguity | 0 |

## Ranked clusters

| # | Category | Stage: reason | Count | Share | Sample ids |
|---|---|---|---|---|---|
| 1 | no_detector_candidate | sink-modelling: no-detector-rule-fired | 151 | 55.5% | GHSA-225x-3jhx-wh4q, GHSA-23hp-3jrh-7fpw, GHSA-248r-7h7q-cr24, GHSA-26gq-p25f-99cp, GHSA-28f5-38xr-jh2w |
| 2 | missing_source_or_sink | source-modelling: no-source-in-defect-file | 44 | 16.2% | GHSA-26w5-6g95-gj28, GHSA-2956-977x-2w3r, GHSA-29g5-m8v7-v564, GHSA-2cp2-2r3c-7p7r, GHSA-2rr5-8q37-2w7h |
| 3 | missing_source_or_sink | source-modelling: no-source-recognized | 27 | 9.9% | GHSA-242p-4v39-2v8g, GHSA-3496-9g83-7v6x, GHSA-3hrf-2gc2-mx32, GHSA-4249-gjr8-jpq3, GHSA-4jwf-m4wg-8p66 |
| 4 | wrong_file_or_cwe | attribution: right-location-wrong-family | 22 | 8.1% | GHSA-32h4-44jj-c5vx, GHSA-382c-vx95-w3p5, GHSA-39pv-4j6c-2g6v, GHSA-3f7w-8rr8-f37f, GHSA-47pj-3jcm-6whg |
| 5 | missing_source_or_sink | sink-modelling: no-sink-recognized-near-defect | 10 | 3.7% | GHSA-386q-5hp3-95m9, GHSA-45pq-889g-fcgh, GHSA-8359-h9fx-j6v9, GHSA-8m8r-38jm-f355, GHSA-95px-34x5-p37h |
| 6 | alias_or_callgraph_gap | propagation: source-and-sink-recognized-no-flow | 7 | 2.6% | GHSA-2j2x-hqr9-3h42, GHSA-8h25-q488-4hxw, GHSA-cxwf-qc32-375f, GHSA-vvp7-h4fj-m28w, GHSA-vx6p-q4gj-x6xx |
| 7 | parse_ir_gap | parser-ir: no-function-lowered | 5 | 1.8% | GHSA-2c47-m757-32g6, GHSA-53g2-mvcc-q9x3, GHSA-53p3-c7vp-4mcc, GHSA-8r6m-32jq-jx6q, GHSA-g9jg-w8vm-g96v |
| 8 | wrong_file_or_cwe | attribution: right-file-and-family-wrong-line | 4 | 1.5% | GHSA-7v5m-pr3q-6453, GHSA-v8fg-2rw7-q452, GHSA-vr8q-g5c7-m54m, GHSA-wg2q-39h6-66x9 |
| 9 | tool_or_setup_incomplete | scan-execution: scan-timeout | 1 | 0.4% | GHSA-794g-x443-36f7 |
| 10 | wrong_file_or_cwe | attribution: finding-has-no-line | 1 | 0.4% | GHSA-4xfr-4p46-gc6p |

Unscored entries (5) are not misses: timeout 5.

Reproduce: `node bench/independent/forensics.mjs --run a72968195aa1`
