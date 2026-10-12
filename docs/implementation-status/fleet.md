# Implementation status: Organization-Wide Security Graph + Distributed Scan Fabric (PRD 4)

**Percent complete:** a real, tested, working slice of the scanning and blast-radius requirements. Most of the
PRD's larger asks (enterprise graph with Internet-facing/regulated-data overlay, natural-language query, SQLite
job store, persisted job queue with lease/retry) are explicitly not built — see below.

**Current phase:** tests written and passing against the real CLI; documentation done.

**Branch:** `feature/fleet-graph` (based on `feature/proof-fabric`, not yet merged).

**Completed:**
- Fleet manifest (`fleet.yaml`): organization + repositories[{id, path}] + workers + perRepoTimeout, closed-world
  validated (unknown key, duplicate id, non-kebab id, unresolvable path, out-of-range workers, bad duration all
  refuse the whole manifest) — `fleet-manifest.js`, 13 unit tests.
- Cross-repository dependency graph built from each repo's own manifest (package.json/go.mod/Cargo.toml/
  requirements.txt/pyproject.toml name + dependencies), with transitive blast-radius computation — `fleet-graph.js`.
- CLI: `fleet init|scan|status|resume|query --depends-on`, reusing the EXISTING `posture/fleet.js` (`runFleet`:
  bounded concurrency, resumable checkpoint, per-repo isolation, honest rollup) for the scanning half — `cli.js`.
- Killer scenario, with a GROUNDED real finding (not asserted away): a 4-repository synthetic org
  (frontend, payments-api, shared-auth-lib, payments-worker) where only `shared-auth-lib` has an actual
  command-injection vulnerability the deterministic engine finds; `fleet query --depends-on shared-auth-lib`
  correctly reports `frontend` and `payments-api` at depth 1 and `payments-worker` at depth 2, through the real
  transitive dependency chain. `test/fleet/fleet-cli.test.js`, against the real spawned CLI.

**A real bug found and fixed before any test caught it structurally.** The first draft of `cli.js` wrapped the
result of `runScan()` in an extra `{ scan }` object, but `runScan()` already returns `{ scan, meta }` — so every
repository's scan result was double-wrapped, and `runFleet`'s internal `_summarise()` silently read zero findings
from every repository (it reads fields defensively rather than throwing on the wrong shape, so nothing crashed —
it just reported "4 repo(s) scanned, 0 finding(s)" for a fixture that should have had a real vulnerability).
Caught by manually running the CLI against a real fixture and noticing zero findings where there should have been
some — not by the first version of the automated test, whose fixture at the time also happened to use a
vulnerability shape the deterministic engine does not actually flag (an unlabeled function parameter reaching
`exec`, with no recognized untrusted source). Both are fixed: the double-wrap, and the fixture, which now uses the
same confirmed-detected command-injection shape (`req.body.host` into `child_process.exec`) already used elsewhere
in this repository's own fixtures.

**Not done (the larger PRD asks):**
- No "Internet-facing" or "reaches regulated data" overlay — `fleet query` answers dependency reachability only.
  The fuller PRD query ("every Internet-facing app that can reach PCI data through this component") needs the
  existing deployment-boundary graph's trust-zone model layered on top; not attempted here.
- No natural-language query parser — `--depends-on <repo-id>` is the one supported shape.
- No SQLite-backed storage. The PRD explicitly asks for SQLite with an abstraction allowing Postgres/remote workers
  later; this reuses the existing flat-JSON fleet checkpoint instead. `posture/portfolio/backend.js` (from the
  prior differentiation PRD) already has exactly the abstraction (probe/lease/local-or-shared backend) a SQLite
  implementation would plug into — genuinely the right next step, not done here.
- No persisted, independently resumable job queue with per-job lease/retry states. `posture/portfolio/
  work-units.js`/`scheduler.js` already provide that, for a different, heavier, operator-only surface; this
  feature deliberately reuses the lighter-weight `runFleet` instead, which is in-process bounded concurrency, not
  a durable job queue.
- Matching across repositories is by declared package name only; two repos sharing a name under different
  ecosystems are not disambiguated (disclosed, tested, not solved).

**Blockers:** none structural — the remaining items are additional engineering (notably: wiring the existing
deployment-boundary graph in for the Internet-facing/regulated-data overlay), not an external dependency.

**Last verified commands (this session):**
- `cd scanner && node --test test/fleet/*.test.js test/fleet.test.js` → 66 pass, 0 fail.
- Manual end-to-end run against a real 4-repository fixture (captured in
  [`docs/guides/fleet.md`](../guides/fleet.md)): a real command-injection finding in the shared library, correctly
  propagated through the blast-radius query at the right depths.
