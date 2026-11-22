# Python and TypeScript real-code development sets

Measures the default scan on real Python and TypeScript web applications, by hand labels, the way `bench/dag/dev-haskell` does for
Haskell. It exists because the synthetic shape batteries that steered the 0.219.0 and 0.220.0 taint rounds score every shape they
contain and say nothing about the default scan's precision on real projects, and because the independent bench's labels are mostly not
taint-shaped (the taint layer scored 0 localized true positives on its Python and JavaScript entries across two rounds). Nothing here reads
or runs a sealed set; none of these repositories is a population repository of `bench/independent`.

## The sets

| Set | Projects (pinned commits in `manifest-<set>.json`) | Role |
| --- | --- | --- |
| python | healthchecks, redash, mealie, paperless-ngx, netbox, wger, pgadmin4, full-stack-fastapi-template | Django, Flask and FastAPI applications |
| typescript | documenso, formbricks, umami, ghostfolio, hoppscotch, vendure, directus, twenty | Next.js, NestJS and Node API applications (tRPC, Prisma, TypeORM, knex) |

`acquire.mjs --set=<set>` fetches exactly the pinned commits into `.cache/` (gitignored). The pins are the default branches as of
2026-11-21 (`git ls-remote HEAD`); a pin is never moved by a script.

## Protocol

1. `scan-all.mjs --set=<set>` runs the default scan (deep analysis on, as the CLI does outside CI; state writes off), two projects at a
   time (the Python helper subprocess degrades under load), and keeps the findings located in the set's language files in `results/<set>/`.
2. `sample.mjs --set=<set>` draws the sample: seed **20261121**, strata are the finding's vulnerability class (path-traversal variants
   merged), a cap of 12 per stratum so no class dominates, and each stratum is split alternately into a **tuning** half and a
   **verification** half from the seeded shuffle, before any site is read.
3. Each sampled site is labelled by reading the code (`build-labels-<set>.mjs`, one sentence of reasoning per site) from the behaviour of
   the code only: is attacker-controlled data reachable to the dangerous operation, across a real trust boundary, without effective
   neutralisation. Comments, names and commit messages are not evidence. TP = a real weakness at that site; FP = not a vulnerability.
   A label is never edited after seeing scanner output except to correct a clear mistake, logged in `LABEL-CHANGES.md`.
4. Fixes are designed on the tuning half; `score.mjs --set=<set>` reports each half separately.
5. `bench/realcode-precision/runner.mjs --check` (`npm run bench:realcode-precision:check`) holds what the engine reports at every
   labelled site for EQUALITY against `bench/realcode-precision/baseline.json`: a regression fails, and so does an improvement nobody
   recorded. `--update-baseline` re-records after a reviewed change.

**Limits, stated plainly.** One labeller; the verification half is read by the same person who designs the fixes, so it is not blind to
the classes fixed (the Haskell work added a fresh set for that reason; none exists here yet). Sixteen projects, pinned once. The sample
measures precision of what the default scan reports; recall against flows nobody flagged is not measured here.
