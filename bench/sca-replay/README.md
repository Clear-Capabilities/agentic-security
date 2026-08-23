# SCA replay — accuracy against third-party labels

**PRD F3.1.** Before this existed, supply chain and SCA was the largest
unmeasured surface in the product: `posture/` carried SBOM, license, EPSS,
reachability and OSV/KEV enrichment, and **no bench scored any of it.** It is
also the surface a customer can most easily verify independently — an SCA
result is checkable against a public advisory database in minutes — which makes
an unmeasured claim here the most expensive kind to be wrong about.

## What it measures

Thirteen real repositories, pinned at resolved commit SHAs, across seven
ecosystems. Only manifests and lockfiles are fetched: this is an instrument for
dependency resolution and advisory matching, not source analysis.

| | |
|---|---|
| **Measured** | dependency enumeration (direct **and** transitive), version extraction, ecosystem attribution, and whether an advisory that applies to a pinned version is reported |
| **Not measured** | whether the advisory database is *right*. Both sides read the same public source, so a wrong advisory is wrong on both sides and cancels. |

Saying that plainly matters more than the number.

## Why the labels are not just "ask the engine"

The obvious construction — ask the engine for the dependency list, ask the
advisory database which are vulnerable — measures nothing, because the engine
would be scored against its own component list and its recall would be 100% by
construction. That is the exact defect `scripts/corpus-provenance-check.mjs`
already reports about `bench/cve-replay`.

So `label.mjs` enumerates dependencies with **its own readers**, written for
this bench, sharing no code with `scanner/src`. Both sides then ask the same
public database about the versions they found. **Where they disagree, one of
them read the lockfile wrong — and that is the entire measurement.**

## Scoring domain

The labeller's readers cover what they cover. If every engine finding outside
that enumeration counted as a false positive, the bench would punish the
*engine* for the *labeller's* blind spots, and the way to score better would be
to see less. So:

```
D  = components the labeller enumerated
P  = the subset of D the advisory database says is vulnerable
E  = what the engine reported

TP            = E ∩ P
FN            = P \ E                  the engine missed a labelled vulnerability
FP            = (E ∩ D) \ P            the engine flagged a version the database says is clean
OUT-OF-LABEL  = E \ D                  reported, NOT scored — the labeller never saw it
```

`OUT-OF-LABEL` is printed prominently rather than buried. A large number there
is a finding about **this bench**, not about the engine.

### Two denominators, both published

- **version-level** — "is *this pinned version* reported vulnerable"
- **package-level** — "does the report mention this package at all"

They differ because the engine collapses findings that share one advisory id
into a single row, listing the rest under `dependents[]`. That is the right
default for a report a human reads, and it is not a recall failure. A team
upgrading one dependency needs the version-level number; a team asking "am I
exposed to anything in lodash" needs the package-level one. Publishing only the
higher figure would be flattering and dishonest; publishing only the lower
understates what the tool actually tells you.

## Results — engine 0.142.0, labels 2026-08-23

| slice | version recall | precision | package recall |
|---|---:|---:|---:|
| **all** | **307/394 = 77.92%** | **307/307 = 100%** | **306/316 = 96.84%** |
| development | 248/324 = 76.54% | 100% | 247/250 = 98.80% |
| **held-out** | **59/70 = 84.29%** | **100%** | 59/66 = 89.39% |

Per ecosystem:

| ecosystem | version recall | package recall |
|---|---:|---:|
| Go | 40/40 = 100% | 100% |
| crates.io | 5/5 = 100% | 100% |
| PyPI | 29/30 = 96.67% | 100% |
| RubyGems | 58/69 = 84.06% | 89.23% |
| npm | 161/229 = 70.31% | 98.08% |
| Packagist | 14/21 = 66.67% | 100% |
| Maven | 0/0 — see limits | — |

The held-out slice scores *above* the development slice, which is the result
that matters: nothing here was fitted to the entries used while building it.

## What the first run found

The instrument earned itself in one run. Its first numbers were **10.89%
overall, npm 0.91%, Go 2.73%, Packagist 0%** — and every one traced to a
concrete defect, not to tuning:

1. **`readTree` skipped any file over 500 KB before deciding what kind of file
   it was.** npm/cli's `package-lock.json` is 666 KB, next.js's
   `pnpm-lock.yaml` is 910 KB, magento2's `composer.lock` is 501 KB. On every
   project big enough for supply-chain risk to matter, the lockfile was
   dropped and SCA silently fell back to whatever exact versions appeared in
   `package.json` — direct dependencies only, while the headline claim of the
   feature is transitive reachability.
2. **`go.sum` was never admitted**, though `_parseGoSum` and its dispatch entry
   had always existed. The same "wired but never invoked" shape as
   `rate-limit.js`, `k8s-admission` and `install-script`.
3. **Only the exact basename `requirements.txt` was admitted.** flask ships
   `requirements/dev.txt` and scored 0 of 11.
4. **Go versions were truncated three separate times.**
   `v0.0.0-20210903162142-ad29c8ab022f` became `0.0.0` — not a shorter version
   but a different, nonexistent one, collapsing every pseudo-versioned module
   in a tree onto one key. Fixing it took Go from 5.28% to **100%**.
5. **The typosquat detector produced 166 critical/high findings across these
   13 repositories and zero of them were typosquats** — `ms ~ ws`,
   `acorn ~ cors`, `ajv ~ ava`, `six ~ tox`. Absolute edit distance is
   meaningless on short names. See `scanner/src/sca/CLAUDE.md`.

## What the bench itself got wrong

Recorded because a measuring instrument that hides its own errors is worth less
than one that does not, and because both errors briefly pointed the blame at
the engine.

- **Go `go.sum` `/go.mod`-only lines.** The first labeller counted every line,
  making prometheus look like 1828 dependencies. A module listed only with a
  `/go.mod` hash was *considered* by version selection and never downloaded, so
  it is not shipped. The real count is 187. The Go recall this bench first
  published was an artefact of this file.
- **`dependents[]` went unread.** The runner scored only each finding's primary
  package and counted the collapsed duplicates as misses.
- **Ruby platform gems.** `nokogiri (1.12.5-arm64-darwin)` and
  `(1.12.5-x86_64-linux)` are builds of one version with one advisory between
  them; counting each separately inflated the denominator.
- **express was marked a negative control** on the theory that a project
  without a lockfile has only ranges. express pins every dependency exactly, so
  its manifest *is* a lockfile — and 15 correct engine findings were being read
  as invention.

## Honest limits

- **Maven scores 0/0.** The labeller refuses to resolve a version that lives in
  a parent POM it does not fetch, so dubbo yields 7 components and no
  positives. That is an absent measurement, not a passing one, and Maven should
  not be read as covered.
- **13 entries is small.** Per-ecosystem figures with denominators in the tens
  carry wide error bars; the aggregate is the more stable number.
- **Both sides consult the same advisory database.** See "What it measures".
- **Reachability is reported but not scored here.** Whether a demotion was
  *correct* needs its own labelled set — that is F3.2's claim, and this bench
  publishes the demotion rate without asserting its accuracy.

## Running it

```bash
cd scanner
npm run bench:sca-replay:fetch    # materialise manifests + lockfiles (needs gh)
npm run bench:sca-replay:label    # third-party labels via the advisory database
npm run bench:sca-replay          # score, write RESULT.json
```

Per-entry detail for held-out entries is withheld unless `--show-heldout` is
passed, so the development loop cannot be run against them.

A measurement, not a gate: it needs the network and takes minutes, so it is not
in the pre-push path. `scanner/test/dep-file-admission.test.js` is the cheap
regression net for the defects it found.
