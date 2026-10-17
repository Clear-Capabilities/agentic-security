# Cross-scan analysis cache (E6-04)

An opt-in cache of per-file detector results, kept between scans. Switch it on with `AGENTIC_SECURITY_ANALYSIS_CACHE=1`. It is off by default: nothing is read or written without it.

## What was found first

Before building anything, the existing "incremental" mechanisms were tested against a cold scan.

| Mechanism | Finding |
|---|---|
| `AGENTIC_SECURITY_INCREMENTAL=1` (`dataflow/incremental.js`) | Gives the right answer and saves nothing. The summaries it persists are keyed by file path (`key.split('::')[0]` cuts a function id down to its first segment), and they are re-seeded under keys the engine never looks up. Even with matching keys it could not help: the engine's pre-pass recomputes every function on every scan. `version.json` records the scanner version as `unknown`, and the rules key is the size of the catalog, not its content. Its parity test passes because nothing is reused. |
| `AGENTIC_SECURITY_RESUME=1` (`posture/scan-checkpoint.js`) | A crash-safe journal for resuming an interrupted scan. It is deleted when a scan completes, so a later scan reuses nothing. Replaying a record also lost the sharing between a finding and its `source`/`sink` entries, so findings came back without the `flowStatus` and `riskStatus` later passes add to them. |

The first is left as it is and listed as unresolved. The second is the foundation of the new cache, with the replay defect fixed.

## What the cache is

The per-file detector stage (the 121 wrapped detectors and their friends) is 37% of a deep scan. Its result for one file depends on that file's path and content, on a small set of cross-file inputs, and on the scanner and its configuration. A record is reused only when all of those are unchanged.

| Input | How it is covered |
|---|---|
| the file's own content | SHA-256 per record; only that file is re-analysed when it changes |
| engine version, ruleset version, bundle digest | in the global key; any change discards the cache |
| dependency manifests | in the global key |
| every `AGENTIC_SECURITY_*` switch | in the global key (except the two that only choose whether a cache is used) |
| the project index (constants, properties, the e-commerce flag), the Java tainted-method index, the operator's `rules.yml` and its signature | one digest of all of them, in the global key. A change to any of these discards the cache, because another file's result may now be wrong |

Everything that is not the per-file stage runs on every scan: cross-file taint, deep analysis, SCA and its feeds, annotation, compliance. Feed freshness therefore cannot go stale through the cache.

## Safety properties

- **Authenticated.** Records and the header carry an HMAC made with this installation's key. A cache file carried in from somewhere else, or committed to a repository, fails verification and is discarded whole. A forged record with a recomputed plain checksum is discarded; so is a header with a wrong or missing signature.
- **Damage tolerant.** A torn tail, garbage, an empty file and a wrong format version each produce a cold scan with a named reason, never an error or a partial result.
- **No second copy of a secret.** A file whose result contains a secret-shaped value (cloud key, token, private key, password assignment, payment card) is not cached and is analysed afresh every time. The skip count is reported in the scan's checkpoint metadata. The cache is also registered as confidential state.
- **Side effects stay.** MCP configuration files, whose analysis compares against a recorded baseline, are never cached. A file with a detector error or a timeout is not cached, so scan health reports it every time.
- **Bounded.** The file is compacted after each completed scan to one line per file still in the scan.

## Evidence that a warm scan equals a cold scan

`scanner/test/engineering-excellence/e6-04-analysis-cache.test.js`:

- Targeted scenarios, each comparing a warm scan with a cold scan of the same tree and the same on-disk history: edit an entrypoint, fix a vulnerability, change a cross-file dependency (adding or removing the e-commerce model that another file's finding depends on), add and remove files, change a scanner switch, add, remove and replace an operator rule. Where a change must alter the result, the test first shows the cold results differ, so the comparison is not over two identical answers.
- Planted, forged, damaged and foreign caches.
- A broad sweep (`EE_E604_SWEEP=1`, recorded in `data/analysis-cache-sweep.json`): every fixture directory with at most 120 files, four mutations each (edit a file, change a constant, add a file, remove a file): **437 comparisons over 156 directories, 1152 file results reused, 0 mismatches.**

The sweep found one mismatch on its first run. It was not the cache: a scan also records an SBOM history that the next scan compares with ("dependency removed since previous release"), so a warm scan that had a previous scan and a cold scan in a fresh directory differed. The cold arm now runs the same earlier scan without the cache, so the arms differ only in whether the cache was used.

## What it saves

`npm run ee:analysis-cache` (data in `data/analysis-cache.json` and `data/analysis-cache-deep.json`). Corpus `scanner/src/sast`, 122 files, 1.33 million characters, 8-core arm64 Mac that was running other work, five runs per arm, medians.

| Scan | Detectors only, wall ms | Deep analysis on, wall ms |
|---|---|---|
| cold | 1685 | 2820 |
| warm, nothing changed | 925 (45.1% less) | 2013 (28.6% less) |
| warm, 1 file changed | 982 (41.7% less) | 2001 (29.0% less) |
| warm, 10 files changed | 1081 (35.8% less) | 2020 (28.4% less) |

Between 109 and 118 of 122 file results were reused; the rest were not cacheable (secret-bearing, errors, or skipped as dense). Each warm result equals the cold result for the same tree.

The saving is real and bounded: about 29% with deep analysis, which is the CLI default outside CI, and about 45% without it. It is not the 2x the performance plan hopes for. Deep analysis, cross-file passes and annotation are 60% or more of a deep scan and are not cached, and they dominate a one-file change.

## What this does not do

- Deep (taint) analysis is not incremental. Making it so needs the engine to skip unchanged functions in its pre-pass and main loop and to prove that no global, field or class-hierarchy channel carries a change to an unchanged function. That is a separate piece of work with its own soundness argument.
- Timings were taken on a loaded machine and on one corpus of JavaScript; Python, Java and the other languages were not timed.
- The cross-file inputs listed above were found by reading the cascade and by the sweep. A detector that starts reading a new cross-file input would make a cached result stale until that input is added to the digest; the sweep is the guard for that.
- The old `AGENTIC_SECURITY_INCREMENTAL` mechanism is unchanged.
