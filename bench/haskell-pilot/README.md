# Haskell pilot capture and replay

Two commands for the pilot milestones: M0 (reproduce and baseline) and the coverage-accounting release target. Nothing here holds pilot data: the snapshot, its exclusions and the captures live wherever the pilot engineer keeps them.

## Capture

```
node bench/haskell-pilot/pilot.mjs capture --root <snapshot> --out <dir> [--label <name>] [--exclusions <file.json>]
```

Scans the snapshot in deep mode under Git scope and writes `<dir>/<label>/report.json` (the full report) and `<dir>/<label>/capture.json`: the command, the scanner version and revision and the snapshot's revision and dirty files (the scan record), the scope and ignore policy, the parse budgets, the exclusions and the coverage measure.

The coverage measure uses eligible `.hs` files as the denominator, failures included:

- every eligible Haskell file has a parse and flow-analysis status;
- at least 95% parse;
- at least 90% complete the required semantic passes;
- every incomplete entry point and every file left by a parse budget is named.

The command exits 1 when any of these is not met, and prints why.

Exclusions are frozen. The first capture into an output directory records the digest of the exclusions (`FROZEN-exclusions.json`); a later capture with a different set is refused, so the denominator cannot be moved after a result is seen. Every exclusion needs a reason:

```json
{ "exclusions": [ { "path": "vendor/legacy", "reason": "third-party code the pilot team does not own" } ] }
```

## Replay

```
node bench/haskell-pilot/pilot.mjs compare <before-report.json> <after-report.json>
```

Diffs two reports of the same snapshot finding by finding (stable id, or file, line and CWE): kept, lost, new, per-CWE counts, and every lost high or critical finding. For M0, `before` is the pilot's original report and `after` a capture with the current pinned release.

This is a finding diff, not recall. Without adjudicated labels a lost finding may be a fixed false positive or a lost true positive; each one needs a reviewer before it counts either way. The recall and precision targets are measured by `bench/haskell-core-families` once its independent, adjudicated cases exist.
