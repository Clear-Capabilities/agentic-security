# Deterministic Context Intelligence

**Maturity:** Preview. See the [capability registry](../capabilities.yaml) and the [maturity model](../how-it-works/maturity-model.md).

`agentic-security context` builds, for each entry point of a program, one small, inspectable, hash-bound bundle of the code that decides whether that entry point is safe. It does this with static analysis only. Optionally, it then asks a model one focused question about each bundle and checks that every claim the model makes points at real lines.

It is opt-in and additive. The default scan, `hunt` and every other command behave exactly as before.

## What it does and does not do

- `context build` makes no model call and no network call. It resolves entry points, follows calls from each handler, keeps the code that matters for authentication, role checks, ownership and tenant scoping, and writes a numbered source bundle plus a manifest.
- A bundle is `complete` only when nothing material was left unresolved, omitted, capped or split. `complete` means the evidence is complete. It never means the route is safe.
- `context review` sends one frozen bundle and one question to your configured model, through the same egress policy and redaction as `hunt`. Model output is a hypothesis. Citations are checked against the bundle, severity comes only from the existing confirmation tier, and a model cannot raise it.
- Nothing here claims an accuracy figure. The evaluation suite is synthetic (see below).

## Quick start

```bash
agentic-security context build --root .          # no model, no network
agentic-security context inspect --route "GET /docs/:id" --show-context
agentic-security context verify                  # re-check stored bundles against their hashes and the source
agentic-security context review --question authz-idor --local-only   # needs a configured model endpoint
agentic-security context status
```

Output goes to `.agentic-security/context-intelligence/` (bundles, manifests, review results, queue checkpoints, reports). It holds excerpts of your source, so treat it like the source tree. The directory is regenerable and `context cleanup` removes unreferenced old bundles (it refuses anything under a legal hold).

## Entry points and dispositions

Each entry point is `resolved`, `partially_resolved`, `unresolved` or `excluded_by_policy`, with the reasons. An unresolved handler still gets a manifest (integrity `unavailable`) so the gap is visible instead of silent. Kinds: `http` always; `webhook`, `queue`, `cron`, `upload` and `cli` where the existing entry-point inventory recognises them.

## Integrity and protection states

Each bundle records `complete`, `partial` or `unavailable`, and the reasons. Per protection dimension (authentication, authorization-role, ownership) the manifest states one of:

| State | Meaning |
|---|---|
| `present` | a control precedes the first sensitive operation |
| `not_present` | the resolved context is complete and contains no such control |
| `not_seen` | not found in what was resolved, but the context is not complete |
| `not_resolved` | an unresolved call could contain it |
| `omitted_due_to_budget` | the code was left out by the token budget |
| `evaluated_and_ineffective` | the control exists but runs after the sensitive operation |

Each control is marked `observed` (literal evidence) or `inferred` (by name), with its basis. A `present` state also carries `strength`: `observed` when the text shows the control, `inferred` when only a name suggests it. An ownership filter counts only when the owner or tenant field and the principal sit in the same clause (`{ ownerId: req.user.id }`, or `owner_id = ?` with the principal passed in the same call); an owner word and a principal that merely share a statement do not. A predicate such as `isOwner(...)` called as a bare statement throws its answer away and is reported as `evaluated_and_ineffective`.

## Profiles and budgets

`--profile compact|standard|extended` (about 8k, 32k, 100k tokens). Token counts are a characters-divided-by-four estimate and are labelled as such. Telemetry-only helpers are pruned with a stated reason; a helper that touches data or a security control is never pruned. A budget too small for the security-relevant code produces `omitted_due_to_budget` and a `partial` bundle, never a silent drop.

## Question packs

`authz-idor`, `authz-function`, `cross-route-consistency`, `transaction-integrity`, `external-failure`, `sensitive-audit`, `business-invariant`. Each is one self-contained prompt with a pinned version. Source is fenced as data, the model is told it has no tools, and it must cite before it concludes. The route label comes from a route string in the repository, so it is placed inside the fence as sanitised data and never in the instruction text. A citation must name lines inside the bundle, span at most 60 lines, and carry a claim that is about the cited text. `no_issue_observed` is kept only when it cites a control the deterministic pass also found and that the text shows; otherwise it becomes `insufficient_evidence`.

## Review runs

`context review` runs a bounded queue: concurrency limits, retries with backoff for retryable errors, a shared cooldown, and budgets for calls, wall time and (only if you supply a price) estimated cost. Each job ends in `succeeded`, `partial`, `failed`, `timed_out`, `skipped_by_policy` or `cancelled`. A job with no verified result is reported as missing coverage, not as a clean result, and `--strict` exits 3 when any exist. Results are cached by job key, so an unchanged bundle costs nothing on a rerun. Checkpoints are sealed with a hash and a tampered checkpoint is ignored and reported.

Remote models need an explicit approval. A loopback endpoint (`127.0.0.1`, `::1`, `localhost`) needs none. Any other endpoint is refused with `remote-endpoint-not-approved` until you pass `--allow-remote` (or set `review.allowRemote`), and approval then still goes through the egress policy and redaction; it never replaces them. `--local-only` stays available as a hard stop. Everything the command prints has control characters and bidirectional marks replaced, because route strings and file names come from the repository.

`--export-batch` writes a provider-neutral request file and `--import-batch <file> --batch-id <id>` imports results with the same citation checks. Uploading is your step. No provider batch API is called.

## Compiler metadata (Haskell, optional)

Set `semanticMetadata.mode` to `import` and `haskellHieDir` to a directory holding `hie-export.json` (schema `hie-export/1`). The importer is read-only: it never runs GHC or any build, validates every described file against the source snapshot hash, requires every reference to name a callee that the cited line of the cited declaration actually contains, and degrades to the static graph on any mismatch. An unresolved static call that the compiler resolves is marked superseded; a disagreement is flagged as a conflict and keeps the bundle partial. Producing the export is a separate operator step. Automatic metadata builds are blocked because running a compiler on untrusted source needs a sandbox proof this build does not have.

## Evaluation

`agentic-security context eval --suite fixtures --split dev --baseline deterministic,hunt,dci` runs a bundled synthetic suite: eleven small cases in JavaScript, Python and Haskell, each with a vulnerable and a fixed variant. A scripted rule-based reader stands in for a model, so runs are reproducible and cost nothing. Because the same authors wrote the cases and the reader, the scorecard states plainly that it describes the machinery on synthetic cases and supports no accuracy claim about real code.

- Intervals use the repository's grouped bootstrap. Fewer than 10 independent cases is reported as `unmeasured`, and precision, recall, F1 and calls per true positive are then `withheld` in the report: the counts are shown, the estimates are not. The CSV carries a `synthetic` column on every row.
- The holdout split is scored through a ledger that counts every use, and a non-default prompt variant is refused on it unless the run is declared `--final`.
- A leakage audit checks that neither the corpus nor any prompt contains the label vocabulary.
- The compiler-enriched comparison is `blocked` when no export is shipped for a case.
- Each system also reports an economics block: median, P95 and P99 context tokens (characters divided by four), model calls, calls per true positive and wall time. No price is assumed, so no dollar figure is shown unless you supply one. Wall time is excluded from the reproducibility hash.
- Reports are written as JSON, CSV and Markdown with the suite, protocol and scorecard hashes and a replay command.

## Capability status

`verified` means reproducible fixture tests cover the build half. `experimental` means it works on fixtures with no accuracy claim. Review quality is experimental everywhere.

| Area | Status |
|---|---|
| JavaScript and TypeScript HTTP routes (Express-style) | verified |
| Haskell HTTP routes (through the existing web model) | verified |
| Python decorator routes and FastAPI Depends() guards | experimental |
| Webhook, queue, cron, upload, cli surfaces | experimental |
| Compiler metadata import (`hie-export/1`) | experimental |
| Other languages' routes | unsupported (no fixtures) |
| Automatic compiler metadata build | blocked |
| Provider batch API | blocked |

## Configuration

`.agentic-security/context-intelligence.json` (operator-authored, never written by the scanner). Unknown or unsafe values are reported and ignored. See `src/context-intelligence/config.js` for the schema and defaults.
