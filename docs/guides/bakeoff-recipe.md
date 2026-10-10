# Bake-off recipe

How to compare this engine with other tools on one workload, and what the comparison is and is not allowed to claim.
The machinery is `scanner/src/posture/evaluation/bakeoff.js`; the commands are in `scripts/evaluation.mjs`.

This repository names no other tool. A comparator is a generic slot (`comparator-a`, `comparator-b`, ...) that you map to
whatever you run on your own machine. Nothing here depends on any particular tool being installed, licensed or reachable.

## What a bake-off pins

A comparison is only worth reading if nothing is silently different between the runs, so the manifest pins all of this before
any result exists:

| Field | What it pins |
| --- | --- |
| `workload` | the target ids and a digest over their tree digests; every participant must run exactly this workload |
| `scope` | the languages and vulnerability families in scope |
| `participants[].provider` | provider and model per participant; `{"model": null}` for a tool that uses none |
| `verification.standard` | one sentence stating what counts as a confirmed defect; all participants are judged by it |
| `limits` | per-target timeout, wall-clock limit and spend ceiling, the same for everyone |
| `failurePolicy` | always `count-as-misses`: a timeout, crash or missing result is a miss, never a dropped row |

A worked manifest is `docs/guides/bakeoff/manifest.example.json`. Check one with:

```
node scripts/evaluation.mjs bakeoff-validate docs/guides/bakeoff/manifest.example.json
```

It exits 0 when the manifest is complete and the workload digest is honest (recomputed from the listed targets), and 1 with the
reasons otherwise. A slot name that is not `this-engine` or `comparator-<letter>` is refused, so a product name cannot end up in a recipe.

## Adapters, and `not evaluated`

An adapter tells the judge whether a slot can run on this machine:

```json
{ "available": false, "reason": "not-installed", "detail": "free text" }
```

`reason` is one of `not-installed`, `no-licence`, `no-provider-access`, `not-configured`, `platform-unsupported`, `operator-declined`.
A slot with an unavailable adapter, or no adapter, is reported `not-evaluated` with that reason. It is not a zero, not a loss and not
quietly left out; it appears in the report with its reason, and no statement is made about it. `docs/guides/bakeoff/adapters.example.json`
shows two unavailable comparators next to the engine.

## Running one

1. Freeze the workload and write the manifest (`workloadDigestOf` in `bakeoff.js` computes the digest).
2. For each available participant, run it over the workload under the manifest's limits and write its results as
   `{ "<entry id>": { "pre": [{ "cwe": "CWE-89" }], "post": [] } }`, with the workload digest and verification standard it ran under.
   Findings are matched by CWE alone, identically for every participant, so nobody is scored on another tool's vocabulary.
3. Judge it:

```
node scripts/evaluation.mjs bakeoff-judge docs/guides/bakeoff/manifest.example.json \
  --entries docs/guides/bakeoff/entries.example.json \
  --runs docs/guides/bakeoff/runs.example.json \
  --adapters docs/guides/bakeoff/adapters.example.json
```

## What the report claims

- **Comparison.** Over the entries every compared participant completed (the intersection), with each participant's own completion
  count beside it. Two tools scored over different subsets are not comparable, so they are never shown as if they were.
- **End to end.** Per participant, with every failure or missing result counted as a miss. Both views are published; neither replaces the other.
- **Accuracy and cost claims** exist only between participants that were actually evaluated, on the identical workload, under the
  identical verification standard. A participant that ran a different workload or standard is flagged and left out of the comparison.
  A cost claim additionally needs every compared participant to have reported a measured cost; otherwise it is withheld with the reason.
- **Superiority is never claimed.** `superiority` is always `none claimed`. The report states measured figures and their basis;
  whether one figure is meaningfully larger than another is for the reader, with the raw counts in front of them.
- **With one participant evaluated** there is nothing to compare; the report says so and claims nothing.

## What a bake-off here does not do

It does not rank tools in general, does not stand in for the sealed real-code gates (see `docs/guides/evaluation-reporting.md`),
and does not turn a comparator's absence into a result. The miniature, offline reproduction of the measuring path is in
`docs/guides/miniature-reproduction.md`.
