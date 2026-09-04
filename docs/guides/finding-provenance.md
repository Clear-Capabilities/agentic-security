# Finding provenance

**Goal:** know which commit introduced a finding, when, by whom, and how
confident that answer is — resolved from real git history, not guessed from
`git blame` (which answers "who last touched this line," a different and
usually wrong question).

**Prerequisites:** a git repository. For plain `scan`, also the
`--provenance` flag (see the default split below). For a worked example of
reading a finding's evidence end to end, see
[Finding evidence walkthrough](../walkthroughs/finding-evidence.md).

Provenance defaults differently depending on the command:

- **`scan` defaults it OFF.** It resolves commit history for every finding,
  which takes real time — measured on a 207-file tree, it moved
  time-to-first-finding from ~5s to ~45s. That is the wrong cost to impose
  on a first scan, so `scan` asks you to opt in rather than paying for it
  unasked. Any provenance-shaped flag turns it on (`--provenance`,
  `--provenance-since`, `--provenance-timeout`, `--require-provenance`,
  `--include-author-email`, `--pseudonymize-authors`).
- **`ci` defaults it ON.** A CI run is exactly the case where the extra
  time is the right trade — you're producing the evidence a gate or an
  auditor will read, not waiting interactively on a first result. This is
  what `--assurance strict` (see [CI setup](ci-setup.md)) checks
  completeness of.

Outside a git repository, provenance costs nothing regardless of command.

---

## What it is

Every finding a scan produces — SAST, secrets, direct and transitive SCA
dependencies, and business-logic findings with a real source line — carries a
`findingProvenance` record. For a SAST finding, the engine replays the
finding's own detection predicate against historical git blobs to find the
commit that made it first become true, then confirms the predicate was false
in that commit's parent — a structural check, not a heuristic. For a direct
dependency, it's the commit that moved the declared version in
`package.json` / `requirements.txt` into an advisory's vulnerable range; for
a transitive dependency, the commit that changed the lockfile-resolved
version the same way.

Alongside the origin commit, a record carries: the branch/PR the change
entered through, a lifecycle ledger of introduce/remediate/reintroduce events
(persisted at `.agentic-security/provenance/lifecycle.json`), evidence nodes
(source/sink/manifest, each a `path:line:commit` triple), and a confidence
level with the reasons behind it.

## Reading a record

`findingProvenance.status` is always one of six values — there is no path
that leaves it unset:

| Status | Meaning |
|---|---|
| `complete` | The introducing commit was found and its parent boundary was verified. |
| `partial` | Something is known (an earliest-observable commit, a rename lineage) but the boundary couldn't be verified — a shallow clone, an advisory with no `introduced` bound, or a file that was renamed after introduction all land here. |
| `uncommitted` | The finding exists only in the working tree; there is no commit to attribute it to yet. |
| `not_available` | Provenance wasn't attempted for this finding — `--no-provenance`, or a finding kind provenance doesn't cover (see **What never gets a real origin**, below). |
| `budget_exhausted` | The scan's provenance time budget ran out before this finding was reached. Never cached — it describes the run, not the repository. |
| `error` | Resolution was attempted and failed (a git error, a malformed finding). |

A shallow clone can never reach `complete`. `findingProvenance.confidence`
is `high` / `medium` / `low` / `unknown`, always paired with `reasons[]`
explaining why.

**Where it shows up.** JSON, SARIF, CSV, Markdown, and HTML output all carry
`findingProvenance` on every finding. In plain CLI text output it's included
per finding with `scan --verbose --firehose`. `mttr.js` reports `ageBasis`
(`finding_origin` | `earliest_observable` | `uncommitted` | `first_observed`)
and `provenAgeDays` alongside ordinary wall-clock `ageDays`, so remediation
age can be read against when the bug actually entered the codebase, not just
when the scanner first saw it.

## `--provenance deep`: non-linear history

The default (`standard`) walk only follows a commit's first parent. Deep mode
(`--provenance deep`) additionally explores every parent of a merge commit,
which can resolve an origin standard mode misses (the introducing change
entered through a non-first-parent branch of a merge), and detects reverts
and cherry-picks — surfaced as `findingOrigin.revertOf` / `.cherryPickOf`.
Deep mode costs more — it does real extra git work, not just a flag flip.

## Only a complete scan can close a finding

The lifecycle ledger's remediation pass turns a finding's *absence* into "this
was fixed" — sound only when the scan actually looked everywhere it could
have found it. A `--changed-since` / `--pr` scan, or any caller-supplied file
list (the MCP `scan_diff` tool, the LSP's on-save scan), records new and
reintroduced findings normally but closes nothing; entries it didn't look at
stay open until a full scan says otherwise.

## What never gets a real origin, by design

Three synthetic finding producers — `license-policy:`, `deploy-platform:`,
and `stack-playbook:` — describe dependency, deployment, or policy *state*
rather than a source line a commit introduced. They carry a fixed placeholder
line number, so running them through git-blame-style resolution would produce
a plausible-looking but meaningless commit attribution. They are excluded by
id-prefix and stay permanently `not_available`. This is a deliberate scope
boundary, not a gap.

`logic-claims.js` findings are **not** in this category — they do go through
real origin resolution. They have a narrower limitation instead: they are
appended late in the pipeline, so a nested historical replay cannot reproduce
them, and a claim whose origin needs a multi-commit history walk will settle
at `partial` rather than `complete`.

---

## Privacy defaults

- **Author email is withheld by default** from every output format (JSON,
  CLI text, SARIF, the auditor walkthrough) — pass `--include-author-email`
  to include it.
- **`--pseudonymize-authors`** replaces `authorName` with a stable
  `Contributor-XXXXXXXX` pseudonym (derived from the real name/email, stable
  across runs for the same person) instead of withholding it outright — for
  when you need to compare "who introduced what" without a raw name in the
  output. This also pseudonymizes PR reviewer logins and CODEOWNERS entries
  when provider enrichment is configured (see below).
- Identity is never inferred from usernames, local git config, or
  commit-message mentions — only from the commit's own recorded author.

## Policy flags

| Flag | Effect |
|---|---|
| `--require-provenance` | Reports any finding with unresolved provenance (outside `complete`/`uncommitted`) as a `scanHealth` condition and downgrades `scanHealth.status` to `partial`. **Flags only — never changes the exit code by itself.** |
| `--assurance strict` (on the `ci` subcommand) | Treats any finding whose provenance status is outside `complete`/`uncommitted` as making the scan incomplete, and **fails the build** the same way it fails on any other failed/skipped analyzer. This is the mechanism that actually gates on provenance completeness. |

`--require-provenance` and `--assurance strict` are independent: the first
only ever flags, the second can fail a CI build.

---

## Commands

```bash
# Standard resolution — the flag IS required; a bare `scan` has no provenance
agentic-security scan . --provenance

# Non-linear history: merges, reverts, cherry-picks
agentic-security scan . --provenance deep

# Skip provenance entirely (findings report not_available)
agentic-security scan . --no-provenance

# Don't walk history earlier than a ref
agentic-security scan . --provenance-since v1.0.0

# Whole-scan provenance time budget, in milliseconds (default 60000)
agentic-security scan . --provenance-timeout 30000

# Privacy
agentic-security scan . --include-author-email
agentic-security scan . --pseudonymize-authors

# Policy
agentic-security scan . --require-provenance

# ci resolves provenance by default — no --provenance flag needed here
agentic-security ci . --assurance strict
```

**Signed, portable evidence for one finding:**

```bash
# Sign a provenance bundle for every finding that has one
agentic-security attest --provenance

# ...or scope to a single finding — note this is a POSITIONAL value to
# --provenance itself, not a separate --id flag, and a different argument
# shape from `scan`'s own `--provenance <standard|deep>`:
# `attest --provenance deep` looks for a finding literally named "deep".
agentic-security attest --provenance <finding-id>

# Verify with only the public key — no access to the original scan needed
agentic-security verify-attestation <bundle.json> --public-key <path>
```

A provenance evidence bundle proves its **contents are unmodified since
signing** — origin commit, confidence, evidence attribution, all under one
Ed25519 signature. It does **not** independently re-verify that the origin
commit is correct; read `confidence.level` and `limitations` inside the
bundle for that. This is the same tamper-evidence-vs-correctness distinction
the ordinary finding evidence bundle makes (`doesNotProve` in
`posture/evidence-bundle.js`) — a signed record of a claim is not the same
thing as the claim being true.

**Cross-repository lineage** (a root-commit origin — one with no parent in
the current repo — can be linked back across a prior fork/split):

`.agentic-security/repo-lineage.json`:

```json
{ "linkedFrom": { "path": "../old-repo-clone", "atCommit": "abc1234" } }
```

Local clones only — no remote fetch. Resolution is conservative: the content
at the linked line must actually **match**, not merely exist, before an
origin is reported, and the result discloses that it crossed a repository
boundary rather than reading like an ordinary same-repo answer.

**GitHub/GitLab PR metadata + CODEOWNERS**, opt-in, configured at
`.agentic-security/provenance-providers.yml` (or
`AGENTIC_SECURITY_GITHUB_TOKEN` / `AGENTIC_SECURITY_GITLAB_TOKEN`), lands on
`findingProvenance.providerEnrichment` for `complete`-status findings, capped
per scan.

---

## Known limitations — read before relying on this for anything load-bearing

- **Renamed files degrade to `partial`.** A finding in a file renamed after
  introduction does not resolve to its true pre-rename origin commit — this
  is a known, traced gap, not fixed as of this release.
- **Known-origin accuracy: 92.3% (12/13)** measured on the labeled corpus,
  against a PRD target of ≥98%.
- **Provenance coverage: 91.2% (311/341)** measured on this project's own
  repository, against a target of ≥95%. All 30 shortfall findings resolve to
  `partial` — reduced confidence, not a pipeline failure — none land on
  `error` or `not_available`.
- **Performance overhead is real and currently well over target.**
  Cold-cache: roughly 27x wall-clock (p95) against a target of ≤1.3x (≤30%
  overhead); warm-cache is roughly 2x. Memory overhead cold is roughly 13x
  against a ≤1.2x target. If you provenance-scan a large repository on every
  CI run with a cold cache, budget for this.
- **Shallow clones degrade to `partial`, and say so.** The status carries
  the reason and, where resolvable, the boundary commit it stopped at —
  never a silent `complete`.
- **Three synthetic finding producers never get a real origin, by design** —
  see "What never gets a real origin," above. (`logic-claims.js` findings DO
  get real resolution; they just tend to settle at `partial` on a multi-commit
  walk.)

## The compliance boundary

A provenance record is repository history, not organizational proof. The
auditor walkthrough (`compliance --walkthrough <framework>`) states this
explicitly next to any control evidence it derives from a finding's origin:
provenance establishes repository history for technical evidence — it does
not prove developer intent, control operation outside code, organizational
compliance, or certification.

---

## Related

- [Compliance](compliance.md) — how a provenance-derived "earliest proven
  origin" feeds an auditor walkthrough, and what it deliberately doesn't
  claim
- [CI setup](ci-setup.md) — `--assurance strict` alongside the other CI gates
- [Configuration & env vars](../reference/configuration.md) — provenance env
  vars and `.agentic-security/` state files
- [CLI reference](../reference/cli.md)
