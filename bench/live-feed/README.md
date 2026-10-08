# Live Hackage advisory feed: measurement against real projects and real OSV

The opt-in feed (`AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE=1`, `scanner/src/language/haskell-advisory-feed.js`) is unit-tested against a
stand-in server. This harness measures it against real Haskell projects and the real `api.osv.dev` `Hackage` ecosystem.

It needs the network and tens of minutes to hours. It is **not** part of `npm test` or any gate. Results are in `RESULTS.md` and
`results.json`; this file is the procedure.

## Files

| File | Purpose |
|------|---------|
| `corpus.json` | The projects: name, version, source URL, `sha256` of the exact tarball used, how versions are resolved (`declared`, `freeze`, `lock`, `cabal-plan`). Chosen by availability, not at random. |
| `run.mjs` | `fetch`, `plan`, `scan`, `merge`, `report`. |
| `request-log.mjs` | Preloaded into the scanner with `node --import`; counts every outbound HTTP request from outside the scanner. |
| `eval-statuses.mjs` | Re-evaluates a project against the snapshot the scan just wrote, to expose per-package / per-advisory statuses (the scan result carries findings only). |
| `report.mjs` | Builds the tables in `RESULTS.md` from `results.json` and `adjudication.json`. |
| `adjudication.json` | The per-finding verdicts. **Assessed by the model that ran the harness, not by a human.** |

## Procedure

Everything third-party lives outside the repository. Pick a scratch directory `$LF` (default: the OS temp dir).

```bash
export LIVE_FEED_CACHE=$LF/cache LIVE_FEED_WORK=$LF/work LIVE_FEED_CABAL_DIR=$LF/cabal
cd <repo root>

# 1. Download the tarballs (sequential, identifies itself in the User-Agent, 0.5 s apart) and verify every sha256 in corpus.json.
node bench/live-feed/run.mjs fetch

# 2. (only for the `cabal-plan` entries) one cabal package-list download, then plans at the pinned index state. Needs cabal + ghc.
CABAL_DIR=$LIVE_FEED_CABAL_DIR cabal update          # the index-state in corpus.json must be <= what this fetched
node bench/live-feed/run.mjs plan

# 3. Scan. Per project: cold live scan (fresh operator config), warm re-scan inside the TTL (same config),
#    offline scan with --no-network, offline scan with AGENTIC_SECURITY_OFFLINE=1 (both with the live opt-in still set).
node bench/live-feed/run.mjs scan                    # add --shard 0/4 --results shard-0.json to run slices in parallel, then:
node bench/live-feed/run.mjs merge shard-0.json shard-1.json ...   # writes bench/live-feed/results.json

# 4. Tables
node bench/live-feed/run.mjs report
```

`scan` options: `--only id,id`, `--limit N`, `--shard k/n`, `--results FILE`, `--resume`, `--timeout-min N` (per scan, default 20),
`--keep-work` (keep each scan's JSON output), `--skip-repeats` (cold scan only).

## What is isolated

* `XDG_CONFIG_HOME` is a fresh directory per project and phase, so the operator snapshot the feed writes (`hackage-advisories.json`)
  never touches the real operator configuration. The warm run reuses the cold run's directory on purpose.
* `HOME` is one isolated directory for the whole run, so the KEV / EPSS caches never touch the real home.
* Scans run `scanner/bin/agentic-security.js` from source (no bundle), with default flags and `--format json`.

## What is measured, and how

| Quantity | Source |
|----------|--------|
| Wall time of the whole scan | harness stopwatch around the child process |
| CPU time of the whole scan | `/usr/bin/time -p` user+sys (does not inflate when the machine is busy; wall time does) |
| Machine load | 1-minute load average sampled when each scan starts |
| Lookup-step time | first OSV request start to last OSV request end, from `request-log.mjs` (a span, includes the concurrent record fetches); also the sum of per-request times |
| Packages looked up, batches, records fetched, failed records, next-page tokens | `request-log.mjs` (the batch response is parsed there) |
| Covered / uncovered packages | snapshot `covered` map vs the packages the scan evaluates (`eval-statuses.mjs`) |
| Why a package is uncovered | failed record request, next-page token, or neither (= validation or an unexplained drop) |
| Second run inside the TTL | OSV requests and times of the second scan on the same config |
| Statuses | `evaluateComponents` rows (affected, possibly-affected, not-affected, unknown, ghc-component:*, no-advisories, feed-incomplete) |
| Scan health | `scanHealth.status` and conditions in the scan JSON |
| Offline | request count (any host) and `scanHealth` of the two offline scans |

## Limits you must carry when quoting a number

* Projects are chosen by availability and by wanting a spread, not at random. Several Hackage packages are library tarballs with only
  declared ranges; most application tarballs have only `stack.yaml` with a resolver (which the scanner cannot resolve offline).
* Wall time depends on the machine and its load at that moment. `RESULTS.md` records the load average next to the timings.
* The OSV Hackage feed changes daily; every number is a statement about the feed on the date in `RESULTS.md`.
* The adjudication labels are the harness-running model's reading of the advisory text and ranges. They are not a human review.
