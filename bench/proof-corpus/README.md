# proof-corpus

Scans large third-party open-source repositories to produce reproducible
evidence about language coverage, detection quality, and operational behaviour
at scale. See `docs/PROOF_CORPUS_PRD.md` for the full rationale.

## Running

```bash
cd scanner
npm run build                                          # the bench refuses a stale bundle
node ../bench/proof-corpus/runner.mjs --only ghost,superset
```

Options: `--only <ids>`, `--refresh-pins`, `--no-determinism`, `--out <dir>`.

## Pinning

Targets are pinned to full commit SHAs so a re-run months later produces the
same numbers. A target with `"commit": null` is refused; run `--refresh-pins`
to resolve each `ref` to a SHA and rewrite the manifest. Advancing a pin is
therefore always a reviewable diff.

## Clone cache

Clones are blobless (`--filter=blob:none --depth 1`) and live outside the
repository, by default under `~/.claude/agentic-security/proof-corpus-cache`.
Override with `AGENTIC_SECURITY_PROOF_CACHE`. Nothing third-party is ever
committed to this tree.

## What is and is not committed

`results/summary.json` holds aggregate metrics and is committed.
`results/raw/` holds findings and SARIF for live third-party projects and is
gitignored — unreviewed findings against software people run in production are
not ours to publish (PRD §9.1).

## Phase-1 status

Two targets validated end-to-end on 2026-07-25.

| Target | Licence | Parse coverage | Deterministic | Wall | Peak RSS |
|---|---|---|---|---|---|
| ghost | MIT | 94% (javascript) | yes | 100s | 2795 MB |
| superset | Apache-2.0 | 90% overall — javascript 100%, python 74% | yes | 77s | 3086 MB |

Both scans exited with code 3 (per the CLI's exit-code contract: `0` clean,
`1` low/medium, `2` high, `3` critical, `4` error) — a successful scan run
that surfaced critical-severity findings, not a failure.

### Known gaps surfaced by this run

- **Superset's Python parse coverage (74%) falls short of the plan's 85%
  acceptance bar.** JavaScript coverage is strong on both targets (ghost 94%,
  superset 100%); the gap is specific to Python parsing on this codebase and
  is recorded here rather than smoothed over. Investigating the Python IR
  parser's failure modes on Superset is follow-up work.
- **Call-graph edge resolution is low on both targets**: ghost resolved
  5,819 of 118,356 edges (4.9%); superset resolved 4,004 of 69,959 edges
  (5.7%). This reflects the k=1 monovariant, largely intra-file resolution
  documented in `scanner/src/dataflow/CLAUDE.md`, not a bench defect — a
  genuine finding about cross-file call resolution on large real-world
  repositories.
- **Peak RSS is high on both targets** (~2.8 GB ghost, ~3.1 GB superset),
  reflecting the cost of building IR for parse-coverage measurement across a
  large repository, as anticipated in the plan's accepted-cost note.

The remaining eight targets are in the manifest but unpinned; Phase 2 brings
them online.
