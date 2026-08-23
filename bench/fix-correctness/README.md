# Fix correctness — against the fix the maintainers actually shipped

**PRD F6.3.** For every entry in `bench/independent` the upstream **fix commit** is
already materialised as `post/`. That is a rare thing — a genuinely third-party ground
truth for *remediation* rather than detection — and until this existed nothing read it.

## Results — engine 0.142.0, 45 entries

| | |
|---|---:|
| entries scanned | 45 (0 unscored) |
| localized true positives | 6, across 2 entries |
| **fix synthesized** | **0 / 6 = 0%** |
| location agreement | 0/0 — nothing to compare |
| approach agreement | 0/0 |

What the maintainers did, on the findings the engine got right:

| remediation | findings |
|---|---:|
| add-guard (an authorization assertion) | 5 |
| rewrite-pattern (a linear-time regex, for ReDoS) | 1 |

## Zero is the answer, and it is a scope result rather than a bug

`posture/deterministic-fix.js` has exactly **two** rules — weak-hash → sha256, and TLS
verification off → on — and both are JS/Python only. The independent population is
injection, authorization and resource-exhaustion classes across seven languages. The two
surfaces barely intersect.

Widening the synthesizer to guess at an authorization check would produce patches that
pass `verify_fix` — the finding does disappear — while changing behaviour. That is
precisely the failure mode F6.1 exists to catch, and the narrow design is correct.

The measured position is: **the engine synthesizes fixes for two weakness classes, and on
real third-party code those classes did not occur.** That belongs in the published
failure rate (F6.5), not in a remediation claim with an unstated denominator.

## What is compared, and why not more

Semantic equivalence between two patches is undecidable in general, and hand-waving about
it would be worse than no bench. So three specific, checkable things:

1. **Synthesis coverage** — of the real findings the engine gets right on real code, for
   how many can it produce a fix at all?
2. **Location agreement** — does our patch change the lines the maintainers changed? A
   fix of the right class in the wrong place is not a fix.
3. **Approach agreement** — both diffs are classified into a remediation category
   (parameterize, encode, validate, replace-api, add-guard, rewrite-pattern,
   remove-code) and compared. Coarse on purpose: a category is checkable.

`remove-code` is a category in its own right and is never folded into agreement. A fix
that deletes the vulnerable code satisfies "the finding disappeared" and is almost never
what upstream did.

Only findings the engine got **right** are counted. Measuring fix synthesis on a false
positive would measure how well the tool remediates things that are not there.

## Honest limits

- **n = 6.** 45 of 1004 entries were scanned; a full run is a multi-hour job. Scale it
  with `FIX_CORRECTNESS_LIMIT`.
- **One entry contributes five of the six findings.** Both counts are reported —
  per-finding and per-entry — because a per-finding rate alone reads as five independent
  data points when it is one codebase.
- **Category agreement is a proxy.** Two diffs in the same category can still be
  materially different fixes.

## Two bugs in this bench, and both produced a confident wrong answer

Recorded because each is a shape worth recognising, and because both briefly blamed the
engine.

1. **`changedLineRanges` takes paths, not contents** — it shells out to `diff` — and
   returns `null` on bad input rather than throwing. Passing file bodies made every range
   null, `isLocalized` was false for everything, and the bench reported zero localized
   true positives with total confidence.
2. **Static imports are hoisted.** A top-level `import` of the engine put its module graph
   in place *before* `disableStateWrites()` ran, so the first scan wrote
   `.agentic-security/` into the corpus and the tree-integrity guard correctly refused to
   score anything — every entry came back UNSCORED. The engine is now imported
   dynamically, after the seal. The ordering is load-bearing, not stylistic.

## Running it

```bash
cd scanner
FIX_CORRECTNESS_LIMIT=45 npm run bench:fix-correctness
```

Needs `bench/independent` materialised (`node bench/independent/fetch.mjs`). Offline
after that.
