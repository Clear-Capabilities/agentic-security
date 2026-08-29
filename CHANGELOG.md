# Changelog

> **A note on `docs/*_PRD.md` references below.** Product requirement documents in
> this project are removed once their workstreams land — the durable parts move
> into the code and tests that enforce them, where they cannot drift out of date.
> Entries below cite PRD files that were live at the time of that release and no
> longer exist. They are left as written: a changelog records what was true when
> it was written, and rewriting past entries to hide a since-deleted file would
> make the history less accurate, not more.




## 0.145.0 — Finding Provenance ships, and two audits find what the first one missed

Every finding now carries a `findingProvenance` record answering "when did this
enter the codebase, and how sure are we?" — resolved from Git history, not
guessed. It is **opt-in**: pass `--provenance` (or any provenance flag, e.g.
`--provenance-since`, `--require-provenance`) on a scan of a Git repository.

It is opt-in rather than on-by-default because the release gate measured what
on-by-default costs: time-to-first-finding over a 207-file tree went 4.5s to
45s. That is a 7.6x regression on the one metric this product's own benchmark
calls the binding constraint for its ICP — "how long until the FIRST useful
result, not aggregate F1" — and resolving commit history for every finding is
not what a first-time user is waiting on. CI, compliance and triage callers
that want provenance ask for it explicitly and pay the cost knowingly.

**What it resolves.** For a SAST finding: the commit that introduced it, found
by replaying the finding's own predicate against historical blobs (`git blame`
answers "who last touched this line", which is a different and usually wrong
question) and then confirming the predicate was FALSE in that commit's parent.
For a direct dependency: the commit that moved the declared version in
`package.json`/`requirements.txt` into an advisory's vulnerable range. Alongside
the origin commit: the branch/PR the change entered through, the evidence nodes
(source/sink/manifest, each as a path:line:commit triple), a confidence level
with its reasons, and a lifecycle ledger of introduce/remediate/reintroduce
events at `.agentic-security/provenance/lifecycle.json`.

**Only a complete scan can close a finding.** The ledger's remediation pass turns
a finding's *absence* into the claim "this was fixed," which is sound only when
the scan actually looked everywhere it could have found it. A `--changed-since` /
`--pr` scan, or any caller-supplied file list (the MCP `scan_diff` tool, the LSP's
on-save scan), therefore records new and reintroduced findings normally but closes
nothing — the entries it did not look at stay open until a full scan says
otherwise. For the same reason the ledger is written only when the scan target is
a real directory: a scan of a path that does not exist resolves its state
directory by walking up from the current working directory, and would otherwise
write a verdict about a project it never read.

**It refuses to guess.** Every record carries a terminal `status`, and there is
no path that leaves the field absent: `complete`, `partial` (history could not
confirm a parent boundary — a shallow clone, or an advisory with no `introduced`
bound), `uncommitted` (the finding exists only in the working tree),
`not_available`, `budget_exhausted`, or `error`. A shallow clone can never reach
`complete`. Author emails are redacted from every output format unless
`--include-author-email` is passed.

**New flags** (`agentic-security scan --help` documents all seven):
`--provenance <standard|deep>`, `--no-provenance`, `--provenance-since <ref>`,
`--provenance-timeout <ms>`, `--include-author-email`, `--pseudonymize-authors`,
`--require-provenance`. `deep` mode performs real non-linear DAG analysis (see
the M3 subsection below) — it is no longer a stub that silently runs `standard`.
`--require-provenance` reports unresolved provenance as a scan-health condition
and downgrades `scanHealth.status` to `partial`; it never changes the exit code
by itself — see the M2 subsection below for the mechanism that does.
`--verbose --firehose` prints the provenance block per finding in text output.
See [`docs/guides/finding-provenance.md`](docs/guides/finding-provenance.md)
for the full user-facing writeup.

### M2: format parity, compliance/MTTR/fix-lifecycle surfacing, and `--assurance strict` can now fail the build

M0+M1 landed provenance resolution and the JSON/text surfaces above. M2 threads
that data through every other output and, for the first time, gives provenance
completeness the power to fail a CI build.

- **Format parity.** SARIF, CSV, Markdown, and HTML output now all carry each
  finding's `findingProvenance`, matching what JSON already had — a consumer no
  longer has to switch formats to see it.
- **Compliance evidence.** Auditor-walkthrough and NIST Privacy Framework gap
  findings now carry `controlRefs` (the finding ids backing a control's gap
  determination) and `derivedProvenance` (the earliest proven open condition
  among those findings, with a `confidence` level and stated `limitations`).
- **MTTR.** `mttr.js` reports `ageBasis` (`finding_origin` | `earliest_observable`
  | `uncommitted` | `first_observed`) and `provenAgeDays` alongside the existing
  wall-clock `ageDays`, so age-to-remediate can be read against the commit that
  actually introduced the finding, not just when the scanner first saw it.
- **Fix records.** Every fix-history entry now carries a `provenanceAtFix`
  snapshot — the finding's `findingProvenance` as it stood at the moment the fix
  was applied — so a later audit can see what was known at fix time, not just
  what is knowable now.
- **`--assurance strict` can now fail the build over incomplete provenance.**
  This is the behavior change that matters most, and it is a genuinely new
  failure mode, not a rewording of `--require-provenance` above: strict mode
  (`--assurance strict`) now treats any finding whose `findingProvenance.status`
  is outside `[complete, uncommitted]` as making the scan incomplete, and fails
  the same way it already fails on a failed or skipped analyzer. `--require-provenance`
  is unchanged by this — it still only flags and never fails the exit code.
  `--assurance strict` is the new, separate mechanism that does fail it. See the
  `KNOWN INTERACTION` comment in `scanner/src/pipeline/assurance-mode.js` for a
  known, disclosed consequence: transitive `vulnerable_dep`, `unpinned_dep`, and
  `no_lockfile` supply-chain findings are stamped `not_available` today (the
  latter two are a category error — there is no commit that introduced a
  *missing* lockfile — not merely a deferral), so `--assurance strict` will fail
  on nearly any real project with a dependency manifest until that gap closes.

### M3: real non-linear history, transitive-dependency provenance, missing-control regressions, PR/CODEOWNERS enrichment

- **`--provenance deep` now does real work.** Instead of the M0–M2 stub that
  accepted the flag and silently ran `standard`, deep mode walks every parent
  of a merge commit (not just the first), which resolves origins standard
  mode's first-parent-only walk cannot see, and detects reverts and
  cherry-picks — surfaced as `findingOrigin.revertOf` / `.cherryPickOf` — via
  a real unified-diff inversion.
- **Transitive-dependency provenance is now live-wired**, not merely
  modeled: `transitive-sca.js` re-derives lockfile ancestry per historical
  commit to find the commit that moved a *lockfile-resolved* (not
  manifest-declared) dependency into an advisory's vulnerable range.
- **Missing-control regressions** — a previously-observed safeguard (today:
  `sast/rate-limit.js`'s findings) disappearing — can now resolve a real
  origin via `missing-control-resolver.js`.
- **Optional GitHub/GitLab PR-metadata + CODEOWNERS enrichment**
  (`findingProvenance.providerEnrichment`) is live for `complete`-status
  findings, configured via `.agentic-security/provenance-providers.yml` /
  `AGENTIC_SECURITY_GITHUB_TOKEN` / `AGENTIC_SECURITY_GITLAB_TOKEN`, capped
  per scan.

### M4: signed provenance evidence bundles, cross-repository lineage, an AI-authorship hook

- **`agentic-security attest --provenance`** signs a per-finding provenance
  record (origin commit, confidence, evidence attribution) with the same
  Ed25519 key material as the existing finding-evidence bundle mechanism;
  `verify-attestation` auto-detects and verifies it against a public key
  alone. Note the flag-shape collision with `scan`: on `attest`, `--provenance`
  takes an optional *finding id*, not a mode — `attest --provenance deep`
  looks for a finding literally named `deep`.
- **Cross-repository lineage.** An operator-declared
  `.agentic-security/repo-lineage.json` can link a root-commit origin (a
  finding whose earliest commit has no parent in the current repo) across a
  prior, local-clone-only fork/split history. Resolution is conservative:
  content at the linked line must actually match, not merely exist, before
  an origin is reported, and the record discloses the boundary crossing
  explicitly.
- **An extensible AI-authorship verifier registry**
  (`registerAIAuthorshipVerifier` / `resolveAIAuthorship`) now stamps every
  SAST `findingOrigin` with an `aiAuthorship` field; no verifier is
  registered today, so it defaults honestly to `{status:'unknown', verifier:null}`.
- **Fleet-wide rollups** (`fleet.js`) now surface provenance-proven
  remediation debt. Fleet MTTR is honestly disclosed rather than fabricated:
  real remediation-timing data isn't reachable from the production fleet
  driver without new state, so `rollupFleet` distinguishes "never tracked"
  from "tracked, zero remediations" instead of reporting a misleading number.

### PRD completion: injection hardening, evidence-digest binding, retention split, and the first real coverage/accuracy measurements

- Author names and commit summaries are now sanitized against terminal
  control-character and Markdown/HTML injection everywhere they reach a
  human (FR-PROV-026).
- The run-attestation digest and provenance cache key are now genuinely
  bound to the PRD-named inputs they claim to cover, including
  detector/ruleset version.
- Symlink-escape protection added to the git evidence layer.
- **`--pseudonymize-authors`** (new flag, listed above) replaces raw
  commit-author names with a stable `Contributor-XXXXXXXX` id — for when you
  need to compare "who introduced what" without a raw name in the output.
  Honored everywhere `--include-author-email`'s redaction already was,
  including PR-reviewer logins and CODEOWNERS entries from provider
  enrichment.
- The provenance cache now lives in its own top-level, independently-retained
  state directory (`.agentic-security/provenance-cache/`), split from the
  permanent lifecycle ledger (`.agentic-security/provenance/lifecycle.json`),
  so cache eviction can never touch permanent history.
- **Two PRD success metrics are now genuinely measured and published, not
  just designed:** known-origin accuracy (12/13 = 92.3% on the labeled
  corpus, against a ≥98% target) and provenance coverage (311/341 = 91.2% on
  this repository's own tree, against a ≥95% target — all 30 shortfall
  findings resolve to `partial`, not `error`/`not_available`, so the gap is
  reduced confidence rather than pipeline failure).
- `scan.secrets` and blameable `scan.logicVulns` entries now go through real
  origin resolution (real stableIds, real git history) instead of a
  permanent `not_available` placeholder.

### Second-audit remediation: a hostile-repository RCE closed, and further honesty fixes

An independent second audit of the completed Finding Provenance PRD found
one security-critical gap and several places where a metric or a claim
wasn't as real as it read. All fixed this release:

- **Security fix (1 of 2).** Git subprocess calls in the provenance pipeline
  are now hardened against a hostile repository's own `.git/config` (e.g. a
  malicious `core.fsmonitor`), `.gitattributes` `textconv` drivers, and
  external `diff` drivers — a repository could previously trigger arbitrary
  code execution merely by being scanned, provenance on or off. The sweep
  covers every git invocation in the scanner, not just the provenance
  module, and a source-level guard now fails the build if a future `git
  diff` call site omits `--no-ext-diff`. Removing the shell from two
  remaining `execSync` call sites also closed a command-injection path via
  attacker-controlled filenames.
- **Security fix (2 of 2), found while reviewing a performance optimization
  in this same release.** A change that fused the parent-commit lookup into
  an existing `git show` placed that field after the author name in a
  delimiter-separated record. Git preserves a literal `0x1f` inside an
  author name, so an outside contributor choosing their own author name
  could shift the parse and select the bytes read as the parent commit.
  Because a parent whose blobs cannot be fetched is indistinguishable from
  one that genuinely lacks the finding, this could manufacture a
  `status: 'complete'` origin with **HIGH confidence** for a boundary that
  was never verified — a fabricated certainty claim that would then flow
  into signed evidence bundles. The field now sits behind the commit hash
  only, with hex validation as defense in depth. Both directions are pinned
  by a regression test.
- The provenance cache key and evidence digest are now genuinely bound to
  the running detector/ruleset version (previously always `null` in
  practice), so upgrading the scanner correctly invalidates stale cached
  provenance.
- `ageBasis` and `provenAgeDays` are now rendered wherever a finding's age is
  shown, not only written to `last-scan.json`.
- Provenance coverage is now wired into the real, running scorecard-generation
  path (see "PRD completion" above for the number) instead of always
  reporting "unmeasured."
- **Performance measurement is now honest end-to-end**, and the honest
  numbers are a real miss against target: real p95 (n=20) over both cold and
  warm cache arms, and a genuine two-sided memory comparison (not a one-arm
  heap delta). Measured this release — cold-cache time ~27x wall-clock p95
  against a ≤1.3x (≤30% overhead) target, warm-cache ~2x; cold-cache memory
  ~13x against a ≤1.2x target. `bench:provenance-accuracy:check` is now
  wired into the pre-push gate so the known-origin-accuracy number can no
  longer silently rot.
- The PRD's **required compliance-evidence disclaimer** ("Provenance
  establishes repository history for technical evidence. It does not prove
  developer intent, control operation outside code, organizational
  compliance, or certification.") now appears next to every
  provenance-derived origin the auditor walkthrough renders
  (`compliance --walkthrough`), and user-facing documentation for the whole
  feature now exists at
  [`docs/guides/finding-provenance.md`](docs/guides/finding-provenance.md).
- **Not fixed, disclosed honestly:** a finding in a file renamed after
  introduction still degrades to `status: 'partial'` rather than resolving
  its true pre-rename origin commit. Known and traced, not fixed this round.

### Breaking: SCA finding ids change for manifest-declared dependencies

Direct dependencies declared in `package.json` / `requirements.txt` now carry the
manifest **line number** where they are declared, and `report/index.js`'s
`fingerprint()` folds that line into the finding id. This was necessary for
provenance — an SCA finding had no line, so every `vulnerable_dep` from one
manifest previously hashed to the SAME id and could not be told apart — but it
means those ids are **not stable across this upgrade**.

Concretely: any triage verdict, baseline entry, or suppression keyed on the OLD
id of a `package.json`- or `requirements.txt`-declared dependency finding will no
longer match and is effectively orphaned. Affected state:
`.agentic-security/baseline.json`, triage memory, and `disable:`/suppression
entries naming an SCA finding id. Transitive dependencies (resolved from a
lockfile, not declared in a manifest) are unaffected, as are all SAST, secrets,
and business-logic findings.

**There is no automatic migration**, and that is deliberate rather than an
oversight — id aliasing would have to be carried indefinitely to be safe, and
the orphaned entries fail open (a finding reappears) rather than closed (a real
finding stays hidden). Re-triage or re-baseline the affected SCA findings after
upgrading; `agentic-security scan --set-baseline` regenerates the baseline in one
step.

## 0.144.0 — Assurance hardening closes Epic E2, and an independent audit finds what "verified" missed

The assurance-hardening PRD (`docs/implementation/assurance-hardening-*`)
closes 72 of its 73 requirements this release. Epic E2 ("analyzer supervision
and scan health" — the claim that a scan can say, honestly, whether it
actually completed) is now fully closed, 8 of 8. The one requirement left
open (FR-401's "types" element — real type inference over the Layer-1 IR) is
a deliberate, documented scope decision, not an oversight: see its own
section below.

### An independent 16-agent audit found 4 real gaps in requirements this project had already marked "verified"

Before continuing forward implementation, the session was asked to verify the
PRD was truly complete. Sixteen independent agents, briefed only with each
requirement's literal PRD text (not this project's own tracking files), each
re-checked one previously-"verified" requirement against the real code. 12 of
16 held up. 4 did not — all fixed and re-verified in the same pass:

- **A broken scan could still say "Safe to deploy."** `scanHealth.status`
  (added by an earlier requirement) was computed correctly but never read by
  the actual human-facing verdict — a scan that hit an annotator exception or
  timed out on files, with zero findings, still printed a clean bill of
  health. `toShipVerdict` now checks `scanHealth.status` before it says
  anything is safe.
- **"Approvals, exceptions, and suppressions" only had identity verification
  wired for one of the three nouns.** `posture/suppressions.js` never checked
  a suppression's `justification_signed_by` against the approver registry a
  sibling requirement had already built — a suppression could be filed under
  anyone's name with no verification at all. Fixed by threading the same
  registry through.
- **A "privacy-preserving" feedback module persisted the exact thing it
  promised not to.** A caller-supplied finding id — which, for a real
  finding, embeds its file path — was stored verbatim instead of hashed.
  Fixed by substituting the finding's stable id or a genuine SHA-256 hash.
- **Two detectors were silently exempt from the fault-isolation work a prior
  requirement claimed was complete for "every detector."** `scanWeb3Advanced`
  and `scanK8sAdmission` were called directly instead of through the
  isolating wrapper, so an exception thrown by either would silently discard
  every OTHER detector's findings for that file. The original verification
  had grepped for a call-site count that could not distinguish a wrapped call
  from an unwrapped one sharing the same substring.

Three of these four were the same failure class repeating: a mechanism proven
correct in a unit test, never checked against the real, human-facing (or
caller-facing) entry point it was supposed to protect. A fifth requirement
(the privacy IR adapter, below) was found to be a genuine partial — 2 of its
8 named elements were real, the rest were stubs or silently merged — and was
honestly downgraded rather than left mismarked.

### Coverage ledgers: every analyzer now has one real, computed status per file

`pipeline/coverage-ledger.js` is a new, drift-guarded registry of all 121
real per-file analyzer call sites (extracted from the engine's own cascade
code, not hand-maintained), each tagged always-applicable,
extension-gated, or policy-gated. Combined with the fault-isolation and
per-file-timeout work from earlier requirements, this computes exactly one
terminal status — completed, failed, timed out, or skipped by policy — for
every (file, analyzer) pair a scan actually ran. `scanHealth.analyzers`,
previously a hardcoded `null`, is now this real summary; a detector that
throws on even one file now demotes scan status, a gap that had no signal
before.

### `--assurance advisory|standard|strict`

A new `agentic-security ci` flag, running alongside the existing `--fail-on`
and `--policy` gates rather than replacing either. `strict` fails the build
outright when `scanHealth.status` is not `complete` — a failed, timed-out, or
silently policy-skipped analyzer; an annotator exception; a stale
vulnerability feed (see below); or a CI environment that silently downgraded
deep analysis (see below) all now have one build-failing consequence, in
addition to whatever `--fail-on`'s severity threshold already does.
`advisory` and `standard` report the same signal but never gate — the PRD's
own acceptance criterion only specifies strict mode's behavior in full.

### CI can no longer silently downgrade deep analysis without saying so

Requesting `--deep` in a CI environment without the explicit
`AGENTIC_SECURITY_DEEP_IN_CI=1` override already fell back to pattern-only
analysis; what was missing was that decision showing up anywhere a human or
a build gate would see it. It's now a real `scanHealth` condition, visible in
the human headline (never "Safe to deploy" under a silent downgrade), in
`ci`'s own stderr, and failable under `--assurance strict`.

### Stale vulnerability feeds, calibration data, and rulesets are now visible — and can fail strict policy

Four independent freshness signals, each reusing an already-computed
staleness check rather than inventing a new one, now feed `scanHealth`:

- The CISA KEV catalog's existing staleness tracking is wired through for
  the first time.
- The engine's own EPSS enrichment path (a separate, duplicate
  implementation from `posture/epss.js`'s — a pre-existing duplication, not
  introduced here) gained the same kind of per-entry age tracking KEV
  already had.
- The seed calibration table (`calibration-seed.json`) now carries a real,
  git-derived generation timestamp and is checked against a 180-day
  threshold.
- Custom rule packs (`.agentic-security/rules/*.yml`) can now opt into a
  `review-interval-days` / `reviewed-at` freshness check — deliberately not
  based on file mtime, since a CI checkout resets mtimes on every run,
  which would make an mtime-based check silently blind in CI, the one place
  a strict-mode failure matters most.

Found while wiring this: this development machine's own, real, previously
invisible EPSS disk cache had a genuine stale entry — a live demonstration
of exactly the gap this requirement closes, not a synthetic test case.

### Checkpointed scans now invalidate only what actually changed

Interrupted-scan resume (`AGENTIC_SECURITY_RESUME=1`) previously discarded an
entire checkpoint — every already-completed file's work — if a single
scanned file changed, was added, or was removed. Run identity is now split
into a GLOBAL component (engine version, ruleset version, running bundle,
dependency manifests, environment switches — a change to any of these still
discards everything, because those affect how every file would be analyzed)
and a PER-FILE content hash on each checkpoint record. Changing one file now
re-analyzes only that file; every other already-checkpointed file still
resumes. A global discard now names what changed
(`"engine version changed (0.143.0 -> 0.144.0)"`); a per-file invalidation
names why (`"content changed since it was checkpointed"`).

### The privacy IR adapter now supplies 7 of its 8 named elements — "types" is a deliberate exception, not a gap

An earlier requirement claimed the privacy taint engine's IR adapter
supplied "declarations, types, assignments, calls, parameters, returns,
storage, and sinks." An independent check found only 2–3 of the 8 were
real: types was a hardcoded `null`, assignments and parameters were merged
into one undifferentiated bucket, returns and storage were absent
entirely. That requirement was honestly downgraded rather than left
mismarked. This release closes parameters, assignments (now distinctly
tagged), returns, and storage — the last of these by reindexing a
stored-taint registry the engine already computes for an unrelated
correlation, not by adding new detection logic.

"Types" remains unimplemented, on purpose. A narrow, TypeScript-only signal
is technically possible — type-annotation AST nodes survive into this
codebase's own Babel visitor before TypeScript's own preset strips them —
but supplying it means modifying the shared JS/TS parser every SAST, taint,
and privacy consumer depends on, for a benefit that would only ever cover
one of roughly ten supported languages. That trade was judged not worth the
risk to already-correct, heavily-relied-on infrastructure, and is recorded
as a deliberate scope decision rather than attempted as an unproven partial
fix.

### A real CI-only test failure, caught by hosted CI rather than the local gate

Two `privacy-ir-adapter.test.js` tests requested deep analysis via the
`{deep: true}` runScan option and asserted `scanHealth.deepAnalysis.enabled
=== true`. That held locally but failed on the hosted CI runner: the engine
downgrades deep mode under `CI=true` unless a second opt-in
(`AGENTIC_SECURITY_DEEP_IN_CI`) is also set, and this codebase's own
`test:ci-parity` static checker — built specifically to catch this class of
bug after a near-identical 2026-08-19 incident — incorrectly treats the
`{deep:true}` OPTION shape as exempt from needing that opt-in ("does not go
through the env gate," per its own comment). That reasoning is wrong: the
option and the environment variable are two different ways to set the same
internal `_deepRequested` flag, and both go through the identical
`_inCi`/`_deepInCiAllowed` gate afterward. Fixed by passing `deepInCi: true`
explicitly on both tests. The checker's incorrect exemption for the
`{deep:true}` shape is a known, separately-tracked gap — roughly forty other
test files use that same option, and this incident does not establish which
of them are actually exposed to it; auditing that is future work, not done
inside this release.

### npm publish no longer pays for the release gate twice

`.github/workflows/release.yml`'s publish job ran the full uncached release
gate as an explicit step, then called `npm publish` — which triggers
scanner/package.json's `prepublishOnly`, itself `build && sync-changelog &&
release-check.mjs`. Read from v0.143.0's actual workflow log: the explicit
step took **280s**, and the one inside `npm publish` took **318s**, ten
seconds later, on the same commit, same checkout, same runner. Caching could
not have closed that gap by design — this workflow always passes `--no-cache`
(a cross-machine cache would reintroduce the reproducibility claim
`posture/attestation.js` explicitly declines to make), so the first run never
wrote anything for the second to reuse. That is ~600s of a release entirely
spent proving the same thing twice.

`npm publish` now runs with `--ignore-scripts`, so `prepublishOnly` does not
fire on the publish step. This is safe here specifically because it would not
be safe in general: the three explicit steps immediately above it (build,
changelog sync, gate) already did everything `prepublishOnly` would, so
nothing it produces is missing from disk by the time `npm publish` runs. The
local publish path is untouched — `scanner/package.json`'s `prepublishOnly`
stays fully wired, because a local `npm publish` has no preceding gate step to
make it redundant (root `CLAUDE.md`'s "Two publish paths" section still
applies there unchanged). `test/release-workflow.test.js` pins the flag, pins
that the three steps it stands in for still run first, and adds a tripwire: if
`scanner/package.json` ever gains a `prepack`/`postpack` script,
`--ignore-scripts` would silently skip it too, and that test fails until its
effect is reproduced as an explicit step. Both new checks confirmed to fail
when the fix is reverted, and the file is restored byte-identical after.

### `npm test`: one `node --test` invocation instead of eleven

`npm test` chained eleven separate `npm run test:<scope>` processes in series
— `node --test` already runs a multi-file invocation's files CONCURRENTLY
against the same cores, so eleven separate processes were paying eleven
startup costs while getting zero overlap ACROSS scopes: `test:posture` could
not start until `test:sast` had entirely finished. Repeated standalone timings
on this machine put the old chain at roughly 258s and a single combined
invocation over the same 397 files at 111-154s, run five times with an
identical 3955/3955/0 (later 3964/3964/0, once this section's own tests were
added) result every time — this machine has been under sustained load all
session (`uptime` reports a load average over 5 on 8 cores while this was
written), so the absolute local number is noisy; the authoritative figure is
whatever the next hosted-CI run reports, on a dedicated runner. The mechanism
is not in question: it is the same tests, run once instead of eleven times.

`scripts/run-unit-tests.mjs` derives its file list from the existing
`test:<scope>` scripts rather than hand-maintaining a second list — a
duplicated list is exactly the shape that silently drifts (add a file to
`test:sast`, forget to add it here, and the combined run quietly covers less
than `npm run test:sast` alone does). It refuses to run if a `test:*` script
using `node --test` is not accounted for in its `SCOPES` list, both as a hard
failure from the script itself and as a named test
(`test/run-unit-tests.test.js`) so the drift guard is visible in the suite,
not just as a side effect nobody reads. `test/cpp-dataflow.test.js` and
`test:python` are deliberately NOT folded in: cpp-dataflow sets its feature
flag at module load rather than inside a test, and when included in the
combined invocation its 26 tests silently contributed **zero** results to the
totals — not a failure, not a skip, just absent — for a reason not chased to
ground; python is a different runtime entirely. Both still run, as their own
separate steps, exactly as before.

`test/discovery-wiring.test.js`'s "a scope is wired into the full gate" check
previously grepped the `test` script's text for the literal substring
`test:discovery` — true when `npm test` was a literal chain, meaningless once
it calls a derivation script instead (the substring never appears in the new
`test` script whether or not discovery's files are covered). Rewritten to
assert discovery's files are actually present in the union the runner
computes, which is a stronger claim than the substring match ever was: it
would have caught the runner's own extraction regex silently missing this
scope's files, which the substring match could not have.

### The JetBrains plugin builds again — and its support floor moved

`jetbrains-plugin` had been red in CI, classified INFORMATIONAL, and treated as
a known toolchain gap. It was not a toolchain gap. LSP4IJ dropped IntelliJ 233
support at its 0.18.0 release, so the pinned `com.redhat.devtools.lsp4ij:0.19.4`
could never resolve against the pinned IDE 2023.3.6:

```
Plugin 'com.redhat.devtools.lsp4ij:0.19.4' is not compatible to: IC-233.15026.9
```

There is no configuration that supports IntelliJ 2023.3 *and* a maintained
LSP4IJ. **`sinceBuild` moves 233 → 242**: IntelliJ 2023.3 and 2024.1 are no
longer supported by this plugin. That is LSP4IJ's floor, not a preference. The
build also moves off `org.jetbrains.intellij` 1.17.4 — the superseded major,
which Gradle 9 cannot apply at all — onto the IntelliJ Platform Gradle Plugin
2.18.1, which removes the reason CI had to pin Gradle 8.10.

`untilBuild` is now open rather than `251.*`. The old cap had already gone stale
(2025.2 exists), and a stale cap reaches the user as "plugin incompatible" on an
IDE that would have worked.

**Two defects the passing build was hiding.** Once it compiled, `buildPlugin`
exited 0 and produced a zip — and `verifyPluginProjectConfiguration` reported,
in text nothing was reading, that (1) the plugin was compiled for Java 17
against a platform requiring Java 21, and (2) the Kotlin stdlib was being
double-bundled, putting a 1.7 MB `kotlin-stdlib-2.1.0.jar` in the distribution
next to 5 KB of plugin code and leaving the platform's class loader free to
resolve stdlib classes from either. Both are fixed; the distribution zip went
from 1.59 MB to 4 KB. The CI job now **fails on that verifier's output**, since a
warning nothing fails on is a warning nobody reads, and it unpacks the zip to
confirm the `factoryClass` named in `plugin.xml` is actually in the jar — an
empty zip passed the old check.

**A defect introduced by this fix, caught before it shipped.** The new CI step
pipes Gradle into `tee` so a later step can grep the verifier's output. A `run:`
step's default shell is `bash -e {0}` — no `pipefail` — so the pipeline's exit
status is *tee's*, and a failed build would have reported success. That is the
same "green gate that verifies nothing" this entire change is about, reintroduced
by the change itself. Both pipe-to-tee steps in the workflow now set
`set -o pipefail`, including the pre-existing one in `determinism-attest`: that
job is BLOCKING, and without pipefail it could upload an empty attestation —
including on `attest-fixture.mjs`'s own zero-findings refusal — for
`determinism-compare` to compare against.

The guard added for it was itself broken twice, in opposite directions, and only
running the negative control in both found them: it first matched the word
`pipefail` inside the comment explaining the fix (so deleting the real line still
passed), then matched `| tee` inside a comment (so a correct workflow failed). A
guard fooled by its own documentation is worse than no guard, because it reads as
coverage.

**A committed Gradle wrapper.** `ide/jetbrains/README.md` told contributors to
run `./gradlew` for a long time while no wrapper existed; CI pinned a Gradle
version in the workflow instead, so the two could drift. The wrapper is now
committed and pins the Gradle distribution by SHA-256 — verified to reject a
tampered checksum, which `gradle wrapper` does not configure by default and
which is not optional in this repository.

**The classification stays INFORMATIONAL, and why.** Making a job that downloads
a full IntelliJ distribution into a release blocker trades one failure mode for a
worse one. The lesson taken instead: everything checkable without the network
moves into the blocking offline gate. `test/ide-surfaces.test.js` now asserts
that the JDK CI provisions equals the `jvmToolchain` the build asks for, that the
committed wrapper exists and pins its distribution by checksum, that the README's
stated support floor is the `sinceBuild` the artifact declares, and that an
LSP4IJ ≥ 0.18 is never paired with a `sinceBuild` below 242. Each was confirmed
to fail when its subject is broken.

## 0.143.0 — OSCAL output, and the finding an OSCAL document must refuse to make

`--format oscal` was documented in `commands/compliance.md` long before anything
implemented it. In 0.139.0 that was corrected to an explicit refusal rather than
left aspirational. This release makes it real, in both places the request asked
for: any scan, and any framework assessment.

```bash
agentic-security scan . --format oscal
agentic-security compliance --report <framework> --format oscal
agentic-security compliance --format oscal          # NIST Privacy Framework 1.1
```

Both emit NIST [OSCAL](https://pages.nist.gov/OSCAL-Reference/models/) 1.1.2
`assessment-results`. `--report <fw>` is also now a real CLI synonym for
`--walkthrough <fw>`; the slash command had always spelled it that way, and it
previously reached the frameworks only through an inlined script in `commands/`.

**The interesting part is what these documents refuse to say.** An OSCAL
`finding` is a statement about a control, and its `status.state` is binary:
satisfied or not-satisfied. There is no "unknown" and no "we did not look". So:

- **A raw scan emits no findings at all.** Observations (what the scanner saw)
  and risks (what it would mean), and a `reviewed-controls` block that says
  plainly that no catalog was in scope. A SQL-injection hit is not an opinion
  about a control; emitting one would publish a CWE→control mapping nobody
  wrote. `include-all` is likewise absent — it would assert this scan reviewed
  every control of an unnamed catalog.
- **A control the engine could not decide carries no finding.** `manual`
  controls, and on the privacy path `engine-gap` controls — where NIST rates the
  control code-testable and *this scanner has no check for it* — become
  observations with method `EXAMINE`. Calling them satisfied would be a false
  compliance claim; calling them not-satisfied would blame the assessed system
  for a hole in the tool.

The distinction OSCAL cannot express rides along as an `assessment-status`
property, so nothing is lost by the conversion. Full mapping table in
`docs/OSCAL.md`.

**A bug this found in itself.** The first adapter mapped `present` to satisfied,
`partial` to not-satisfied, and everything else to unassessed. `evaluateFramework`
also returns `absent` — signals exist and not one cleared, the strongest failure
it can express — and the catch-all silently relabelled it "requires human
judgement", deleting real control failures from the document and attaching a
remark that was false. It was caught by running the exporter against a bundled
framework and reading the output. There is now no catch-all: the mapping is
exhaustive, and an unrecognised upstream status is reported *as* unrecognised,
naming itself as an exporter defect rather than making a claim about the control.

**Two more defects the checking found, both invisible at emit time.** OSCAL's
`assessment-assets` — the block that identifies what performed the assessment —
is scoped to the *result*, not the document (`assessment-results/local-definitions`
carries objectives-and-methods and activities, and nothing else), and it requires
at least one `assessment-platforms` entry. The first draft had it at document
level with no platform. Both produce a document that emits cleanly and fails
validation, which is precisely the failure mode of a format claim nobody ran
through a validator.

**Control identifiers are rewritten, and the originals kept.** OSCAL's `token`
datatype is an NCName. The CCPA catalog bundled with this engine uses ids like
`§1798.100`, which is not one — emitting it raw produces a document a validator
rejects at the first control, the usual failure mode of an OSCAL export that was
never run through one. Ids are sanitised to legal tokens and the publisher's
original is carried on every observation and finding as `source-control-id`.

**Checked, and the checks were checked.** `test/oscal-conformance.test.js` (15
tests) validates required fields, the constrained datatypes (`uuid`, `token`,
`dateTime-with-timezone`), the closed value sets, and referential integrity —
every `*-uuid` and `#fragment` must resolve inside the document. It also pins the
doctrine above, which is not a schema property and would otherwise be one
refactor from reversing. Three deliberate regressions (neutering the token
sanitiser, the deterministic uuid shaping, and the no-findings rule) were each
confirmed to fail the suite before the source was restored. Scope is stated in
the file: structural validation, not full JSON-Schema validation against NIST's
published schema — fetching it at test time breaks the no-network rule and
vendoring it adds a file that rots silently. Same call, same reasoning, as
`test/sbom-conformance.test.js`.

`oscal` joins the `format-determinism` gate, so two emits of one scan are
byte-identical and an attestation over the document still verifies. That gate
also exposed a real gap: every conformance test ran the `crypto.randomUUID()`
branch, leaving the `--deterministic` branch — the one an attestation is
actually taken over — untested. A digest slice is not a legal uuid; roughly 15
in 16 fail on the variant nibble alone. It is now covered explicitly.

**Also:** the two load-bearing caveats (ordinal scores are not probabilities;
benchmark-tuned F1 does not generalize) now come from one exported constant
rather than being spelled out inside `toSARIF`. SARIF carries them as run
notifications, OSCAL as back-matter resources, from the same source — two copies
of a caveat is one copy that goes stale, and the stale one is always the one
somebody reads. The three inline "is this a machine format" lists in the CLI
became one set, for the same reason: each new format previously had to be added
to all three or it got human chatter interleaved into its output.


## 0.142.0 — The last five PRD items, and three criteria that now fail on evidence

0.141.0 built instruments for the surfaces that had none. This closes the
remainder of `docs/WORLD_CLASS_HARNESS_PRD.md`: four of the five items found
live engine bugs, and the fifth re-derived the headline the whole document rests
on. Three success criteria now **fail** — measured, rather than unknown.

### A sanitizer could be undone and the flow still read as clean

`he.decode(escapeHtml(req.query.name))` reaching an HTML sink was reported
**sanitized**. The decode puts back exactly what the escape removed, so this was
a missed XSS presented as a clean flow.

Nothing modelled reversal: the catalog holds sanitizers, a decoder is the
opposite, so it was never even recorded on the path. Fixed across three layers —
the taint walk now collects un-sanitizer callees, the gate maps them to the
family they reverse (percent-decoding does **not** undo HTML escaping, so a flat
list would be wrong), and the finding-projection allowlist had to learn the new
field. That last one is why the fix looked inert through three rounds of
debugging.

Found by the mutation gate, which went from 12 to **34 cases** — the five
detector families 0.141.0 shipped had owed a metamorphic pair and an adversarial
near-miss and had none.

### The CloudFormation ingress rule was keyed on YAML key order

`- CidrIp:` first and `- IpProtocol:` first are the same template — YAML mappings
are unordered — and only the second matched. The rule was keyed on the author's
formatting, which is syntax, not meaning. Also caught by the mutation gate, by
the metamorphic case that exists for exactly this.

### Every reachability demotion we could adjudicate was wrong

Reachability was reported as a demotion *rate*, and that rate was **0 for every
entry by construction**: `bench/sca-replay` fetched lockfiles, so the analysis
had no source to walk. A number that is structurally zero looks like a
measurement and is not one.

With source fetched and scored against an import-level oracle: **3 adjudicable
demotions, 3 false-unreachable — 100% wrong, in the missed-exploit direction.**
`express`/`cookie`, `express`/`send`, `poetry`/`requests` — each demoted to
`info` and out of the report, each verified by hand as genuinely imported.

Three defects behind it:

- **Failure to prove reachability was reported as proof of unreachability.** A
  site the analysis could not reason about became a positive claim. It is now
  `unknown`, a state the code already used elsewhere.
- **A project with no routes was still asked "reachable from a route?"** For a
  library that question has no answer — its callers are its users, not in the
  tree.
- **`_enclosingFn` knew two of four declaration forms.** `res.cookie = function
  (…)` — how most of the JS ecosystem defines a public method — was invisible, so
  the scan attributed call sites to unrelated functions further up the file. It
  now also tracks whether the enclosing function is **exported**, because a
  public-API function with no in-tree caller is the normal case, not dead code.

**If you use SCA reachability to triage, this affected you**: findings were being
demoted out of your report on projects that genuinely import the vulnerable
package.

### The VS Code extension had never been type-checked

`typescript` is now a devDependency and `npm run typecheck` runs in CI. It found
errors immediately: the tsconfig declared no `types` at all, so `process`,
`setTimeout` and `NodeJS.Timeout` were every one of them unresolved — `@types/node`
was installed and nothing consumed it — plus two implicit `any` parameters. The
build is esbuild, which strips types without checking them, so none of this had
ever surfaced.

Neovim and JetBrains are now smoke-tested in CI too. JetBrains is classified
**informational**: it downloads a full IntelliJ distribution, so red there is more
often the network than this code, and a habitually-red gate stops being read.

## The population re-measured — and it is worse

991 scored entries at engine 0.141.0 (the code that ships here), against 315 at
0.138.0 before:

| | before | **now** |
|---|---:|---:|
| localized recall | 3.56% | **2.83%** |
| localized precision | 44.00% | **36.36%** |
| fix-discrimination | 81.8% | **71.43%** |
| held-out recall | — | **2.93%** |

**The headline fell because the question got harder.** The corpus tripled once
the advisory miner could page past the first hundred entries per ecosystem, and
what it pulled in is recent, TypeScript-heavy and dominated by authorization
classes. Held-out tracks development almost exactly, so nothing is fitted.

**Ruby 0% → 3.20%. Go 0% → 1.19%.** Both measured zeros are off zero, on
populations 8× and 1.2× their old size. **PHP is the new zero, at 0/73.**

Two of this release's own fixes are confirmed on real code rather than their own
fixtures: the Ruby `File.join` rule earns `lsegal/yard`, and `CONVENTION` earns
its first localized true positive ever on GitPython — the family recorded as
permanently silent until it turned out to be mislocalized by five lines.

### Three success criteria now fail, on evidence

- **Fix-discrimination is 71.43%**, below its 80% floor. 8 of 28 findings still
  fire on the code the fix produced — those detected an API, not a vulnerability.
- **Taint contributes 1 of 28** localized true positives. It was 1 of 12; the
  count did not move while the population tripled. Deep mode also costs 5 extra
  false positives and **loses** a Go finding that pattern-only makes.
- **Compliance still has no accuracy instrument** — the last feature measured by
  nothing.

### Measured and deliberately not fixed

- **The agent trust-boundary delta is 0 of 0 — undefined, not zero.** The
  population now holds 28 entries of real MCP-server code; the engine produces no
  localized true positives on any of them, so there is nothing for the boundary
  modelling to have contributed to. It is not silent there — 21 findings per
  entry, all on the advisory's own files, none of the labelled class. WRONG-CWE,
  on the most differentiated surface in the product.
- **Reachability now demotes nothing** on the source-bearing corpus. The false
  demotions are gone; whether the new caution is correct needs applications with
  real routes, which those four entries are not.

## Also

- A whole-population benchmark run **wedged** at 0.0% CPU after 4.5 hours, taking
  every already-scored entry with it. `bench/independent/runner.mjs` now takes
  `--offset`/`--limit` and `merge-chunks.mjs` reassembles the slices,
  **recomputing** every aggregate from the per-entry rows and refusing to write
  unless that reproduces each chunk's own numbers exactly. It caught two of its
  own bugs that way.
- A guard-shaped method NAME on a declaration line (`def check_static_cache(`) no
  longer counts as a containment guard, which had been silently dropping path
  findings inside any method called `check*` / `validate*` / `ensure*`.

## 0.141.0 — Six new instruments, and the seven live bugs they found

The previous release fixed five bugs found by measuring. This one builds the
instruments that do the measuring for the surfaces that had none — SCA, secrets,
IaC, prompt injection, remediation, and the IDE/MCP surfaces — and then fixes
what they reported. Every number below is reproducible with a command in
`bench/*/README.md`.

None of the improvements came from tuning. They came from files that were never
read, patterns that could never fire, and versions that were silently rewritten.

### SCA never read a transitive dependency tree on any real project

`readTree` skipped **any file over 500 KB before deciding what kind of file it
was.** npm/cli's `package-lock.json` is 666 KB, next.js's `pnpm-lock.yaml` is
910 KB, magento2's `composer.lock` is 501 KB. On every project big enough for
supply-chain risk to matter, the lockfile was dropped and SCA fell back to
whatever exact versions appeared in `package.json` — direct dependencies only,
while the headline claim of the feature is transitive reachability.

Manifests now have their own, much larger cap. The 500 KB cap on **code** files
is unchanged: that one protects the analysis path and was never the problem.

Two more admission gaps in the same area: `go.sum` was never admitted though
`_parseGoSum` and its dispatch entry had always existed, and only the exact
basename `requirements.txt` was matched — so `requirements/dev.txt`, which is
what pallets/flask ships, scored 0 of 11.

**Measured effect (`bench/sca-replay`, 13 real repos, 7 ecosystems, labels from
the advisory database via readers that share no code with the engine): version
recall 10.89% → 77.92% at 100% precision, held-out 84.29%.**

### Go dependency versions were rewritten into versions that do not exist

`v0.0.0-20210903162142-ad29c8ab022f` became `0.0.0` in three separate places —
not a shorter version but a different one, collapsing every pseudo-versioned
module in a tree onto a single key. **Go went from 5.28% to 100%** once versions
survived intact.

This also corrupted the emitted SBOM, which is the worse half: an SBOM saying
`golang.org/x/net@0.0.0` is wrong in a document other people are supposed to
rely on.

### The typosquat detector reported 166 findings, none of them typosquats

Across 13 real repositories, at critical and high severity: `ms ~ ws`,
`acorn ~ cors`, `ajv ~ ava`, `six ~ tox`, `arg ~ yargs`, `bail ~ babel`. Every
one is a legitimate, popular package; `ms` is a top-50 npm package.

Absolute edit distance is meaningless on short names — two edits on a
four-character name changes half of it, and every two-character package is one
edit from every other. Now Damerau-Levenshtein, so a transposition (`lodahs` for
`lodash`, the commonest real typo) costs 1 rather than 2, gated on
`distance / min(len) ≤ 0.25`.

### The VS Code extension had never been able to find the scanner

It looked for the bundle under a hardcoded
`…/agentic-security/0.1.0/scanner/dist/…`, and Claude Code caches a plugin under
its **plugin** version — 0.128.2, 0.136.9, 0.139.1, never 0.1.0. `0.1.0` was the
extension's own version pasted into the wrong path, so the fallback could not
resolve on any install and every user got *"scanner not found."*

Nothing tested it, because the function read `vscode.workspace` and could not be
imported outside a VS Code host. The resolver is now a pure function that
discovers the version instead of hardcoding one, prefers `CLAUDE_PLUGIN_ROOT`,
and is covered by 15 tests plus a CI job that fails on a stale committed bundle.

### Three IaC formats had no rules at all

CloudFormation, Bicep and Helm chart values scored **0** against every control
tested — not weak rules, no rules, and for CloudFormation no file admission
either, since a template is a `.yaml` that no path predicate recognises.

`bench/iac-coverage` scores **verdict flip**: a control counts only when the
misconfigured variant fires *and* the hardened one stays silent. That caught
something a recall-only bench never would — `FROM ubuntu@sha256:…`, the most
tightly pinned form a Dockerfile can use, was reported as *"ubuntu:latest
(floating tag)"* because the digest was matched but not captured. A false
positive on the hardened configuration tells the people who did the right thing
that they did the wrong one.

**Coverage 8/14 → 23/26**, with the three still open marked as needing semantic
analysis rather than another pattern.

### Credential patterns that could never fire

`CRED_PREFILTER` is a whole-file gate: `scanCredentials` returns early unless
that one regex matches, so a pattern whose trigger token is missing is dead code
however correct it is. The generic "Password in URL" rule was in exactly that
state.

Also absent entirely: `postgres://user:pass@host/db` and `mongodb+srv://…` —
among the commonest real leaks there are — plus GitLab, DigitalOcean, Azure
Storage, Supabase and HubSpot tokens. Only `jdbc:` was covered.

**Format coverage 60% → 92.11%, with correct silence at 28/28** on a hard
negative set of lockfile integrity fields, git SHAs, content digests, Terraform
state ids and a security rule file that defines key formats.

### Prompt-injection patterns that were correct and far too literal

The override rule required the object noun to be one of seven words, so *"Forget
all previous **tasks**"* and *"Ignore all preceding **orders**"* missed.
Exfiltration could not match *"show me all your prompt texts"*.

**Recall 6.08% → 18.25% against `deepset/prompt-injections` (Apache-2.0, 263
injections and 399 legitimate prompts), precision and correct-silence at 100%
throughout.** Reported per technique, because an aggregate hides which one is
weak: role-play 100%, exfiltration 60%, override 41.86%.

And the engine caught its own author — the widened pattern was flagged by this
project's own ReDoS detector on the self-scan gate, twice, before it was
rewritten as a flat alternation that scores identically.

## Measured, published, and deliberately not "fixed"

- **Fix synthesis produces a patch for 0 of 6** real true positives on
  third-party code (`bench/fix-correctness`, scored against the upstream fix
  commit). The deterministic synthesizer has two rules, both JS/Python; the real
  population is injection and authorization across seven languages. Widening it
  to guess at an authorization check would produce patches that pass
  verification while changing behaviour.
- **German prompt injection scores 2.30% against English's 28.57%.** Patching it
  because *this corpus* is German would be fitting to the benchmark.
- **Datadog, Vercel and Algolia keys stay undetected.** They are a bare run of
  hex; a pattern for "32 hex characters" would fire on every content digest and
  checksum in existence.
- **`CODEGEN` produces nothing on any of the five advisories in its own header.**
  Measured dead, and left for a deliberate retire-or-fix decision rather than
  removed silently.

## Also

- The advisory miner **was not paginating** — the API ignores `&page=N` — so the
  evaluation population was capped at ~100 advisories per ecosystem by
  construction. Fixed via the `Link` cursor: **315 → 1004 entries**, Ruby 32 →
  250, Kotlin 0 → 2.
- `File.join(<root>, …, <variable>)` reaching a filesystem call with no traversal
  guard is now detected for Ruby (CWE-22), the dominant real-world shape the
  existing rule could not reach.
- A guard-shaped method **name** on a declaration line (`def check_static_cache(`)
  no longer counts as a containment guard, which was silently dropping path
  findings inside any method called `check*`/`validate*`/`ensure*`.
- MCP is now smoke-tested end to end over stdio through the shipped binary, with
  both write tools asserted to refuse out-of-tree paths in both directions.

## 0.140.0 — Five shipped bugs, found by measuring instead of reading

Every fix here is a defect that was live in 0.139.1. None came from the feature
backlog; all five came from measuring the engine against real code and taking
failing signals seriously instead of explaining them away.

### `scan --format sarif` produced INVALID SARIF in CI

The CLI dispatches every command as `process.exit(await cmdX(args))`, and
`process.exit()` does not flush an asynchronous stdout. stdout is asynchronous
exactly when it is a pipe — every `> results.sarif`, `| jq`, and CI capture — so
output was discarded at the 64 KiB pipe boundary, mid-token, with a normal exit
status. On one directory that was 65,536 bytes emitted of 390,177: roughly 83%
of the document silently dropped.

**If you upload SARIF to code scanning, this affected you on any project large
enough to matter.** A TTY and a file both flush synchronously, which is why it
looked fine by hand and broke in automation.

### LLM01 — Prompt Injection — could never fail

Detectors emit the finding family as `<family>-<rule-slug>`
(`prompt-injection-http-user-input-in-llm-`), while the compliance evaluator
resolved `family:prompt-injection` as an exact key. It matched nothing, so the
control reported as evidenced no matter what the scan found. The first control
of the OWASP LLM Top 10 was structurally incapable of failing, along with ASVS
V5.1 and NIST AI 600-1 MG-3.2-005.

Two further compliance defects in the same matching code: an empty family
bucket rendered as `✓ no open critical/high findings`, so two controls (ASVS
V7.1, NIST Privacy CT.DP-P1) read `present` on every scan of every project; and
a first attempt at fixing that wrongly declared four live families
unevidenceable, degrading 15 working controls. Both directions are now gated —
a control with no possible evidence cannot read `present`, and a family with a
producer cannot be declared a gap.

### `--deterministic` did not produce deterministic output

Four of ten emitted formats differed run to run: CycloneDX/SPDX document ids and
a CycloneDX bom-ref fallback from `crypto.randomUUID()`, a PoC marker from
`Math.random()`, and per-file wall-clock timings (which also determined the
sort ORDER, so blanking the values alone would not have been enough).

**An attestation over an SBOM was therefore unverifiable** — the point of
signing an artifact is that someone can regenerate and compare it.

### 62% of concurrency findings on Go were false positives

The lock guard matched a bare receiver (`defer mu.Unlock()`) but not a qualified
one (`defer s.mu.Unlock()`), which is how a mutex held as a struct field is
always written. The acquire pattern always matched the qualified form, so the
two halves of the rule had disagreed since it was written — and the most
idiomatic CORRECT code was the most likely to be reported. Measured: 170 of 273
findings on a Go sample were false positives. Those findings also carried no
CWE, so they were invisible to every CWE-keyed report.

### New gates

- `test/stdout-flush.test.js` — spawns the real CLI through a real pipe
- `test/format-determinism.test.js` — every emitted format, byte-compared
- `test/compliance-mapping-liveness.test.js` — both vacuous-pass directions
- `test/concurrency-cwe.test.js` — per-lock guard discrimination
- `bench/family-producers/OBSERVED.json` — 213 families observed across 331
  real scan roots, recorded explicitly as a LOWER BOUND

### Scope

The world-class-harness PRD is **partially delivered**. F10.5 (determinism as a
published property) is complete. F10.2 is half done — the enforcement half
landed; the measurement half needs detectors to declare their families, because
this release proved no textual search can enumerate them. Roughly 35 PRD items
remain, several blocked on design decisions rather than implementation.

## 0.139.1 — The same scanner, published with provenance

**The shipped artifact is functionally identical to 0.139.0.** Only two commits
separate them, and neither is in the published package: a test-harness timeout
(`test/` does not ship) and a dependency hold (`.dependency-holds.json` does not
ship). Nothing about how the scanner behaves has changed.

This release exists for one reason: **0.139.0 was published without a provenance
attestation.** It went out from a maintainer's laptop because the CI token
lacked write access on the scoped package, so every tag-triggered publish failed
at `PUT` with `E404` — after having already signed provenance to the Sigstore
transparency log. The token has been replaced and verified (a re-run now returns
`E403 "cannot publish over the previously published versions"`, which is the
registry authenticating the write and rejecting only the duplicate version), so
this is the first release published by CI with `--provenance`.

For a security scanner that argues its case on *provable, measurable,
reproducible*, "you can cryptographically verify this artifact was built from
this commit in this repository" is a product property rather than a formality.
Provenance is signed at publish time and cannot be retrofitted, which is why it
takes a version number rather than an amendment to the last one.

Fixes carried along, neither user-visible:

- **`test/audit-cli.test.js` budgeted 4 s for a CLI that takes ~2.7 s idle** — a
  1.5× margin in a suite that runs files concurrently. It failed as `status:
  null` on a *different* test each run, was unreproducible in isolation, and
  blocked a release push on a commit whose entire diff was 8 lines of JSON.
  Now 30 s (~11× idle), still bounded so a genuinely hung CLI fails rather than
  stalls.
- **`@types/vscode` is held rather than upgraded.** It declares the VS Code API
  surface the extension compiles against and should track `engines.vscode` — the
  *oldest* supported host — not the newest published types. Chasing latest lets
  the extension compile against APIs absent from hosts it claims to support, and
  that failure lands as a runtime `TypeError` in a user's editor. The hold
  records a pre-existing mismatch (`engines ^1.95.0` vs types `^1.125.0`) for a
  deliberate decision at review time, since narrowing the supported host range
  is a product call, not a dependency bump.


## 0.139.0 — Two detectors that were dead, a confinement rule that was documented but unenforced, and a new Go rule

Every defect in this release is the same shape: **a control that exists, is
documented, and does not hold end-to-end.** Unit tests passed in every case.
Only checks that exercised the whole pipeline found them.

### Two detectors produced nothing through a real scan

Both worked when called directly and returned zero through `runScan` — the
`rate-limit.js` signature (a rule that discarded 100% of its own findings,
project-wide, from the day it was written).

- **`k8s-admission`** — `_isIaCFile` admitted YAML as Kubernetes only when the
  path contained a directory literally named `k8s/`. Its own comment claimed the
  caller also checked for `kind:`; nothing ever did. **Manifests under
  `deploy/`, `manifests/`, `charts/`, `kubernetes/` or the repository root were
  invisible** — which is where most projects actually put them. Now admitted on
  CONTENT (`apiVersion:` and `kind:` at line-start within the first 2 KB),
  because the set of directory names people use is unbounded and the file
  format is not.

  The fix had to be applied at **both** admission gates: `runScan` admits a file
  into `fileContents`, and then `runFullScan` independently re-filters that same
  list with `shouldScan()`. With only the first opened, the predicate returned
  true, the walker collected the files, and the scan still returned zero.

- **`install-script`** — `package.json` is routed to `depFileContents` and fails
  `shouldScan()`, so the per-file SAST loop never visited it and
  `scanInstallScripts` was wired in but never invoked. Fixed on the manifest
  path rather than by admitting `package.json` into the SAST loop, which would
  push a manifest through all ~117 code detectors to satisfy one rule.

Measured blast radius rather than assumed: 16 of 1129 YAML files in this tree
are newly admitted (1.4%), all in fixtures and caches. Self-scan unchanged.

### `_CONFINEMENT` rule 3 was documented and unimplemented

`agents/_CONFINEMENT.md` states three refusal rules for every edit-capable agent
and for the MCP write tools. The code enforced two. Rule 3 — *"a backup, lock, or
build-output file (`*.bak`, `*.lock`, `dist/`, `build/`, `target/`)"* — was not
enforced at all.

The tests failed by **successfully writing**, which is what makes this more than
pedantry: `scanner/dist/` holds the shipped bundle, which carries its own
SHA-256 integrity sidecar precisely because its contents matter. `apply_fix`
would have rewritten it and reported success. A contract an agent is instructed
to follow, enforced less strictly than it claims, is worse than no contract.

Build output is matched as a **path segment at any depth** — `packages/web/dist/`
is the normal shape — while a source file *named* `dist.js` or `build.py` stays
writable.

### New: `sibling-guard-omission` (CWE-22, Go)

From `GHSA-95cv-r8x4-vh75`: two fields of one request struct reach a filesystem
rename and the project's **own** guard is applied to only one. High precision by
construction — the rule never decides what a guard *is*, it observes one being
applied to a sibling, so every finding reduces to "this file guards X and forgets
Y", falsifiable from a single screen of code, with the guard name and both field
names carried as evidence.

Fires on the real advisory in `pre` and goes silent there in `post`. FP budget
measured across 72 real Go packages: **1.12%** of findings, max 5 per repo.

**It could never have shipped without a second fix.** `dropGuardedFindings` drops
a CWE-22 finding when its window contains a containment guard — and for this
family the window *always* contains one, because the guard on the sibling **is**
the finding. The centralized precision filter was reading the evidence of the bug
as proof of safety and would have deleted 100% of the family regardless of
detector quality. Exemption keyed on `family`, deliberately narrow.

A false positive in this rule was then found on real code (an `\n` escape read as
a path separator) and fixed, with a regression test written from that code.

### Instruments

- **The shipped LSP is smoke-tested.** `bin/agentic-security-lsp.js` ships inside
  the JetBrains and Neovim plugins and was referenced by no test, script or
  workflow. It now runs as a subprocess speaking real LSP over stdio —
  `initialize` → `didOpen` → `publishDiagnostics` → `shutdown` → `exit` — plus a
  malformed-frame survival case.
- **Per-language layer attribution** on the independent population, with taint's
  attributable share stated outright each run.
- **Gate integrity** (P0 of `docs/WORLD_CLASS_HARNESS_PRD.md`): CI-parity checks
  so the local gate cannot disagree with hosted CI; layer-recall gates on
  equality rather than a floor, so an unrecorded *improvement* fails too; a
  shared per-entry bench watchdog; and a detector-liveness guard that requires
  every rule fixture to produce a finding *through* `runScan`. That guard is what
  found both dead detectors above.


## 0.138.0 — Findings come from code, not comments; container taint; a benchmark that can no longer hang

### Comment blindness, enforced instead of documented

`src/sast/CLAUDE.md` has always named this as its first gotcha for detector
authors — "Comments confuse detectors. Always go through `blankComments()`" —
but nothing enforced it, so whether a rule ignored comments depended on whether
its author remembered. A probe over nine languages, in which *every* dangerous
construct sat inside a comment and the only executable statement was
`return 1`, produced **15 findings from code that can never run**. Three
independent defects, each fixed after a failing test proved it:

- `runFullScan` handed the **raw** file to every SAST module. 64 of 117 modules
  called `blankComments()` themselves; roughly 40 of the rest ran regexes over
  raw text. The per-file dispatch now computes one comment-blanked,
  offset-preserving view and passes it to 99 detector call sites.
- The engine's own `stripNoise()` understood `//` and `/* */` but **not `#`**,
  so every engine-internal regex pass leaked on Python/Ruby/shell/HCL comments.
  All 15 call sites now pass a path, and the mapping is language-aware because
  it has to be: `#` opens a comment in Python but is `#include`/`#region` in the
  C family, and `//` is a comment in C-family languages but **floor division in
  Python**, where blanking it would delete real code.
- `blankComments()` let a `'`/`"` string span a newline. An odd number of quotes
  on one line — which regex literals produce routinely; `/"(?:sh|bash)"\s*,\s*(?!"[^"]*")/`
  has seven — left the scanner stuck in string mode for the **entire rest of the
  file**, silently disabling comment stripping from that point on. Found on this
  repository's own `sast/go-extended.js`, where it resurrected a false positive
  from a comment six lines below such a regex.

Ruby `=begin`/`=end` blocks are now stripped too (a `#`-only pass left them
wholly intact).

**Measured, finding-by-finding rather than by totals.** Self-scan on this
repository fell 458 → 427: **33 findings removed, all 33 on comment lines, zero
real findings lost**; the 2 added were previously *masked* by the string-mode
defect. On the 315-entry independent population of real upstream advisories,
localized precision rose **40.74% → 44.00%** with true positives unchanged at
11 — the fix buys precision, not recall, which is exactly what was predicted
once it was established that none of the credited true positives sat on a
comment line. Deliberately still reading raw source: the prompt-injection
family (for an agentic tool, instructions hidden in a comment *are* the attack),
the secrets scanners (a committed credential is leaked whether or not its line
executes), and `scanTodosNearSecurity`, whose entire subject is comments.

The property is pinned end-to-end by `test/comment-blindness.test.js`, including
a positive control and a Python-floor-division guard, so a regression surfaces
as a test failure rather than as quietly inflated findings.

### Container / collection-element taint (PRD T3.3)

Probed ten container shapes before writing anything, which showed the JS array
cases already worked. Coverage went from 5/10 to 9/10:

- A computed write with a non-literal key (`bag[k] = tainted`) lowers to access
  path `bag.*`, and `'*'` is a *literal* property name, not a wildcard — the
  lattice propagates only downward from a prefix, so the write was unreachable
  from every correctly-computed read. An unknown key could be any key, so it now
  widens to the container.
- `Map.set` / `Set.add` joined the mutator list.
- **The mutator rule required `callee.kind === 'member'`, a shape only Babel
  emits**, so container writes in Python/Ruby/PHP/Go/Java/C#/Kotlin never matched
  at all. The miss was invisible because a PY-SAST pattern rule caught the same
  sink.
- `__setitem__` is in the mutator list because `parser-py.js` lowers a Python
  subscript *assignment* to a call node, not an assign node — established by
  dumping the IR, not by inference.

**Reported as capability, not as a recall gain:** `bench:layer-recall` is
unchanged at 116/215 and the dataflow-shaped subset unchanged at 115/137,
because the corpus holds no container-shaped entries. Pinned by
`test/container-taint.test.js`, including two precision cases that must *not*
fire.

### Performance

The comment work initially cost **19.7%** of end-to-end scan time on a 307-file
entry, because `stripNoise` is called ~15× per file and an interpreted character
loop had replaced two native regex passes. A single-slot memo (safe because the
engine processes one file at a time and `fileContents[p]` returns the same
string *reference*) plus a rewrite of `blankComments` to emit bulk slices
instead of per-character appends brought that to **5.7%**. Byte offsets and line
counts are preserved exactly — every finding's line number depends on it.

### The independent benchmark could hang indefinitely

A full run wedged at entry 186 of 315 on `GHSA-hcm8-x79p-wx2w` (apache/camel,
649 MB): process alive, state `S`, 0.0% CPU, no progress for six hours, killed
with 129 entries never scored. Reproduced on a clean checkout, so it was
pre-existing. `runScan` carries a deep-mode walltime budget and a per-file
timeout, but nothing bounded a whole-entry scan. There is now a per-entry
watchdog (`AGENTIC_SECURITY_BENCH_ENTRY_TIMEOUT_MS`, default 600 s) that marks
the entry UNSCORED — the harness's own documented doctrine for an entry that
could not be run, never a miss. The run that produced this release's numbers
named 6 such entries (all Java, all very large) and completed.

Worth stating plainly: **every independent-population figure published before
this release came from a harness that could silently stall partway through.**

### Documentation corrected

`docs/METRICS.md`'s taint table was ~5× stale (23/210 = 11%; actual 116/215 =
54%) and its central claim that kotlin still had **0%** taint recall was false
(48%). Both `bench/layer-recall/baseline.json` and the table are regenerated.
The cause is recorded alongside the fix, because it is a gate-design lesson:
`bench:layer-recall:check` compares against a **floor**, so an improvement from
31 to 116 passed it exactly as a no-change run would.

Also fixed two long-standing lifecycle failures: `jsUnits` — Theme 6's JS/TS
extractor, which carries 6 of the 10 known sibling-omission entries — was wired
into production with **no test at all**, and now has four; and a stale
`profile.js::DEFAULTS` dead-code allowlist entry was removed.


## 0.137.1 — Dependabot policy for the deliberately-vulnerable fixtures

Housekeeping release. Adds `.github/dependabot.yml` so Dependabot leaves the
intentionally-vulnerable fixture directories alone — `examples/demo-app`,
`scanner/test/fixtures/**`, and `bench/**` pin old, known-vulnerable
dependencies on purpose so the SCA/SBOM/CVE detectors and the tutorials have
real findings to surface (and `scanner/test/demo-app.test.js` asserts a CVE
finding on a pinned dep). An `ignore: "*"` entry suppresses both version- and
security-update PRs for those directories. The real trees (`scanner/`,
`ide/vscode/`) get no version-update entries — their currency stays enforced by
the `dependency-currency` release gate — and repo-level security updates still
cover them.

No engine or detector changes.

## 0.137.0 — detection-gap remediation Themes B+D, C, E, plus R9, the R16 close-out, and the docs overhaul

Seven independent slices of `docs/DETECTION_GAP_REMEDIATION_PRD.md` land
together here (R6, R8, R9, R10, R11, R13, R14(a), R14(b), R16), alongside the
world-class docs overhaul (`docs/DOCS_OVERHAUL_PRD.md`). Each has its own
subsection below, and each subsection carries its own verification paragraph —
the numbers in one do not describe the other.

### Docs overhaul — a learning layer, an accuracy pass, and an anti-rot gate

The product had a strong evidence layer (architecture, metrics, compliance
maps) and no learning layer. This release adds one, and repairs what was false.

- **A deliberately-vulnerable demo app** at `examples/demo-app/` — ~10 files
  spanning every pillar (SQLi, missing auth, eval, MD5 hashing, prompt
  injection, hardcoded key, Dockerfile hygiene, vulnerable deps). Its promised
  findings are pinned by `scanner/test/demo-app.test.js` (wired into
  `test:smoke`) so a detector change can't silently make the tutorials lie. It
  is outside the self-scan gate's target set, so it never perturbs that gate.
- **A 15-minute quickstart** (`docs/guides/quickstart.md`) and **six
  task-oriented how-to guides** — scanning, fixing, SBOM/AI-BOM, compliance, CI
  setup, leaked-secret response — plus a **CLI reference**, a **configuration &
  env-var reference**, and a **docs hub** (`docs/README.md`). Every command
  shown was run against the demo app before being documented.
- **Accuracy pass** — repaired every false/contradictory claim the doc survey
  found: version drift across four manifests (`gemini-extension.json` was
  ~60 versions stale), the model-cost-optimizer default contradiction, the
  compliance `--gap` row, a skill pointing at a deleted command file (revoke-URL
  matrix restored inline), the README's `hunt`-is-a-slash-command claim, and
  `secure --tour`/`--daily` documented-but-unimplemented (now implemented).
- **New anti-rot gate** — `scripts/check-doc-drift.mjs --gate` fails on any
  dangling internal link across README/docs/commands/skills/agents; wired into
  the release gate as `doc-links` and proven both directions. Manifest
  version-sync now also covers `gemini-extension.json`.
- **Two output-correctness fixes surfaced while documenting:** the CycloneDX/
  SPDX SBOM tool version was hardcoded `0.7.0` — now stamped from the real
  engine version via `meta.engineVersion`. And `js-yaml` was bumped
  `5.2.3 → 5.3.0` to clear the dependency-currency gate.

Verification: `test:smoke` 30/30 (includes the two demo-app contract tests),
`sbom` 3/3, `release-check` 49/49, `check-doc-drift --gate` clean and
fails-on-planted-break. Full `npm test` + the release gate run on push.

### R9 — Java call-graph edges existed in the CFG but never reached the call graph

`ir/parser-java.js` never emitted `fn.calls`, leaving every Java function's
call-graph edges permanently empty (`callgraph.js` reads `fn.calls`
exclusively). Wired the same shared, language-agnostic call-extraction helper
six other parsers already use — no new extraction logic, matching the
identical precedent set by Ruby's earlier fix. A final-review fix wave
rebuilt the bundle, corrected doc overclaims, and added a resolution proof
test (`test/parser-java-calls.test.js`, 94 lines).

### R16 — independent population re-measured; the finding is the absence of movement

Re-ran `bench/independent` (110 GHSA-labelled entries, fresh fetch, scan
state wiped) after seven PRD themes landed since the last measurement. Result
is identical, entry for entry, to the 2026-08-09 run — same TP/FP/FN/TN, same
per-language split, same recall across all ~40 CWE categories. Reported
plainly rather than explained away: the independent population has zero
Java/C#/Kotlin/PHP/Ruby/Go entries, so R8/R9 could not have moved it
structurally; Theme A (the plan's own hypothesized dominant lever, which also
landed after the baseline) plus R6/R10/R11/R13/R14(a) could have moved a
JS/TS/Python entry and none did. This measurement cannot distinguish "fix
doesn't occur in these 110 entries' shapes" from "effect masked elsewhere in
the same scan" — only that the net observable outcome per entry is unchanged.
The PRD backlog is closed on this basis.

### Theme B+D (R6, R10, R11) — semantic grounding and interprocedural completeness

Closes three of the five open items in `docs/DETECTION_GAP_REMEDIATION_PRD.md`'s
Theme B ("semantic grounding of matching") and Theme D ("interprocedural
completeness"). R7 and R12 — filed under the same two themes — turned out to
already be landed (commit `553f9a5`, swept in opportunistically alongside
Theme A's nine fixes).

- **Class Hierarchy Analysis is now wired into the deep pipeline** —
  prerequisite infrastructure for R6 and R11. `ir/class-hierarchy.js` and the
  receiver-type heuristic (`dataflow/receiver-context.js`) were both already
  built and unit-tested but never consulted at scan time; `dataflow/index.js`
  now builds CHA once per scan and threads it through every `callContext`.
  Landing this exposed a real, independent pre-existing bug in
  `class-hierarchy.js` itself: its method-qid parser assumed a dot-joined
  `"ClassName.method"` shape, but the parser's actual qid format for a class
  method is `::`-joined (`file.js::ClassName::method@line`) — so `cha.classes`
  was silently empty for every JS/TS class, and CHA-based resolution could
  never have worked at all until this was fixed. The only prior test for
  `buildClassHierarchy` had hand-mocked a qid in the wrong shape, which is why
  this went unnoticed.
- **R6 — catalog sink matching is now gated by CHA-inferred receiver type.**
  A bare-name sink like `.query()` or `.get()` previously matched on ANY
  receiver project-wide (`cache.query(x)` scored identically to
  `db.query(x)`). An opt-in `match.receiverTypeIn` catalog field is now
  declared on the 5 highest-FP-risk bare-name entries (`js-sql-query`,
  `js-sql-execute`, `py-requests-get` x2, `rb-erb-new`). Unknown receiver type
  never suppresses a match — only a confidently resolved, non-matching type
  does.

  **Coverage is not uniform across those 5, and the honest summary is that
  only the two JS entries do real work.** The gate can only fire when CHA
  actually resolves a receiver type, and CHA's `typeOfVar` is populated from
  exactly one shape: a local `let/const x = new Foo()` whose IR carries the
  `isNew` marker — emitted today by the JS/TS, Java and C# parsers only.
  So `rb-erb-new` is effectively inert: `ERB.new(x)`'s receiver is a bare
  identifier that is never `new`-assigned, so the type is always unknown and
  the entry always stays permissive. The two `py-requests-get` entries are
  inert for the same reason (Python has no `new`, so its parser emits no
  marker). Both are harmless — an inert gate is a permissive gate, and the
  pattern layer's match survives untouched — but "applied to 5 entries"
  should not be read as "gating 5 entries."
- **R10 — a call nested inside another expression now consults the callee's
  own taint summary.** `sink(getUserInput())` previously only checked
  `getUserInput()`'s own arguments for taint (the call's return-taint was
  invisible outside assignment-RHS and bare-statement position, the only two
  places the summary cache was consulted). `exprTaint`'s `'call'` case now
  also resolves and consults the callee's summary, via the same shared
  resolver R11 uses.
- **R11 — a JS/TS member call (`svc.save(x)`) now resolves interprocedurally
  when CHA traces the receiver to one unambiguous, assignment-tracked local
  variable.** Previously refused unconditionally (a bare dotted-name guess
  risks inventing an edge between two unrelated same-named methods). This
  landed narrower than originally scoped: it deliberately still refuses
  `this.field.method()` resolution. An early implementation reused R6's full
  receiver-type heuristic, including its two name-guess fallbacks
  (`this.field` PascalCase-to-class guessing, bare-identifier soft-labeling) —
  safe for R6's weaker consequence (mis-gating an *existing* catalog match),
  but review found that reusing the same guesses for R11's stronger
  consequence (fabricating a *new* interprocedural call-graph edge) let a
  same-named unrelated variable resolve to the wrong class purely by name
  coincidence. R11 now calls `classOfVar` directly, trusting only genuinely
  assignment-tracked local types, and an ambiguous or unresolved receiver
  (including every `this.field` shape) still safely refuses to resolve rather
  than guessing — matching this PRD's own stated caution that R11 should stay
  unimplemented rather than ship with degraded precision.

Two narrower gaps surfaced during R11 implementation and were deliberately
left unfixed as out of scope (recorded as candidate future work in
`docs/DETECTION_GAP_REMEDIATION_PRD.md`'s new "Status updates" section): CHA's
variable-type tracking is scoped to the exact enclosing function (a
module-scope instance referenced from inside a closure/route-handler can't be
typed there), and taint-argument recognition only handles bare-identifier or
one-level member-access call arguments (a two-level access like
`req.query.cmd` passed directly is invisible to it).

- **A wiring-and-verification pass on this work caught R6 suppressing a real
  finding, and the fix landed the same way it was found: with a gate.**
  `bench:layer-recall:check` — which exists precisely to catch a layer going
  quiet on a language it used to cover — flagged `js/ts` taint recall
  dropping 7 → 6. Root cause: `_receiverTypeFor` fell back to returning the
  receiver's own bare identifier name (e.g. `c`) whenever `classOfVar`
  couldn't verify a type, and the caller then treated that name as a
  confidently-resolved non-match rather than as "unknown" — a direct
  violation of R6's own "unknown != clean" rule. Concretely:
  `const c = mysql.createConnection({}); c.query(tainted)` (a `mysql`
  connection assigned via a factory call rather than `new X()`, the exact
  shape `CVE-2021-22214-node-sqli-shape` exercises) was silently dropped by
  the taint engine, because `'c'` doesn't match the SQL receiver allow-list —
  even though it's a genuine, tainted SQL sink. `bench:cve-replay:check`
  stayed green throughout, because a different, non-taint layer happened to
  still catch this same corpus entry — the corpus gate answers "was it
  detected at all," not "by which layer," which is exactly the blind spot
  `bench:layer-recall:check` exists to close. Fixed by removing the
  bare-identifier fallback: a non-`this` receiver is now trusted only when
  `classOfVar` genuinely resolves it, mirroring the fix already applied to
  R11 above. This is exactly the kind of near-miss the full gate sequence
  (test, corpus, mutation, layer-recall) exists to catch before it ships, and
  it did.
- **That fix was too narrow, and the whole-branch review caught it: the same
  bug class had three more instances in the same function.** The round-4 fix
  above removed the bare-identifier fallback but kept the `this.field`
  PascalCase guess, on the reasoning that it wasn't implicated in *that*
  regression. It was implicated in the identical one. `receiverTypeAtCall`'s
  `this`-branch structurally cannot return `null` — it PascalCases the field
  name and returns it — so every `this.<field>.method()` call was treated as a
  confidently-resolved type, and only field names that happened to collide
  with the allow-list vocabulary survived. `this.dbConn.query(req.query.q)`
  and `this.readReplica.query(req.query.q)` are both real SQL injections, both
  reported by the pre-branch base commit, and both were silently absent from
  this branch — not demoted, gone, with no other layer catching them. Two more
  instances alongside it: for a multi-segment chain like `svc.db.query(x)` the
  code resolved `parts[0]` — the chain ROOT — answering "what type is `svc`?"
  when the receiver is `svc.db`, a property path CHA never types at all; and
  `buildClassHierarchy`'s `typeOfVar` walker accepted any PascalCase callee as
  a constructor, so `const q = BuildCache()` was confidently mistyped as class
  `BuildCache`. All three were name-or-shape guesses being trusted as
  resolutions.

  Rather than a fourth one-off patch, `_receiverTypeFor` now states the one
  thing CHA can actually verify and refuses everything else: a receiver chain
  of exactly two dot-separated parts (`x.method`), resolved through
  `classOfVar`. `this`-rooted and multi-segment chains return `null` —
  unknown, permissive. `parser-js.js` now emits the `isNew` marker on
  `NewExpression` (matching what the Java and C# parsers already emit) and
  `buildClassHierarchy` requires it, so a PascalCase *factory* call is no
  longer mistaken for a constructor. Separately, the `receiverTypeIn`
  vocabularies were exact-anchored (`^(?:db|pool|conn…)$`) from back when the
  value reaching them could be a bare variable name; now that only real class
  names arrive, `DatabaseConnection`, `PrismaClient` and `MySQLConnection` all
  failed the allow-list and were suppressed, while only a class literally
  named `Db` passed — the existing test passed solely because its fixture was
  named `class Db`. Those four patterns are now substring matches
  (`rb-erb-new`'s `^ERB$` stays anchored: one exact class, not a vocabulary),
  and `Cache` still correctly suppresses.

  The claim two bullets up — "unknown receiver type never suppresses a match"
  — was false on the `this.field` path for the whole of this branch's life
  until now. It is true again, and it is now gated rather than asserted:
  `bench/mutation/` gained a detection dimension and four R6 cases, two of
  them metamorphic renames (`class Db` → `class DatabaseConnection`,
  `this.db` → `this.dbConn`) that a vocabulary-keyed gate cannot survive, plus
  an adversarial non-DB receiver so that simply deleting the gate cannot pass
  either. Both metamorphic cases fail on the pre-fix engine. Three rounds of
  this same false-negative class shipped behind human review; the mutation
  gate is what makes a fourth fail loudly instead.

**Verification — Theme B+D (R6, R10, R11) only:** full test gate green
(`npm test`, 3146 tests), corpus (214/214, no drift), mutation (9/9
verdict-flip, and non-zero exit confirmed against the pre-fix engine) and
layer-recall (214/214 detected, per-language taint counts equal to baseline)
all green. These figures predate the R13 work below, which was gated
separately; see R13's own verification paragraph for the current totals.

### Theme E (R13) — flow-modeling coverage, both sub-fixes

- **R13(a) — a member-write assignment target (`el.innerHTML = tainted`) is
  now consulted against the sink catalog.** The taint engine previously only
  checked call expressions against the sink catalog; a plain property
  assignment with no call syntax at all — the PRD's own success metric,
  `el.innerHTML = req.query.x` — was structurally invisible regardless of
  taint. `dataflow/catalog.js` gains a small member-write sink table and
  `matchMemberWriteSink(targetPath, file)`; `dataflow/engine.js` consults it
  on assignment targets alongside the existing call-sink path.
- **R13(b) — a for-of loop variable now carries the iterated expression's
  taint into the loop body.** `for (const item of req.body.items) { eval(item) }`
  — the PRD's other stated success metric — previously read `item` as clean:
  the shared Babel loop visitor never bound the for-of loop variable to what
  it iterates. `ir/parser-js.js`'s loop visitor now synthesizes an
  `item = <iterated expr>` assignment in its `enter()` hook, scoped strictly
  to `ForOfStatement`; the other four loop-statement types that funnel
  through the same shared visitor (`for`, `while`, `do-while`, `for-in`) are
  pinned byte-identical in CFG output by a dedicated regression test, since
  a shared-visitor edit is the single riskiest shape of change this plan
  made.

  **This one took three extra fix rounds, and all three are worth recording
  honestly.** First: a second, generic Babel visitor
  (`VariableDeclarator`) also fires for the for-of binding's own
  `const item` declarator and runs after the loop visitor's `enter()` but
  before the body, silently overwriting the just-synthesized assignment
  with `source:unknown` — fixed with a guard skipping that declarator.
  That guard's first version was over-broad: it skipped *any*
  `ForOfStatement` `left` declarator, which also deleted the same visitor's
  pre-existing destructuring taint-KILL nodes and regressed
  `for (const {cmd} of SAFE) eval(cmd)` to a false positive (the
  destructured `cmd` should shadow and clear an outer tainted `cmd` of the
  same name, and briefly stopped doing so). Narrowed to
  `path.node.id?.type === 'Identifier'` so only the simple-identifier shape
  the loop visitor actually synthesizes for is skipped; destructuring falls
  through unaffected, now pinned by a regression test.

  Second, and unrelated to the guard bug: R13(b)'s new taint capability made
  a genuinely pre-existing, independent bug newly reachable inside the
  scanner's *own* `ir/type-stubs.js` — `catalog.js`'s `js-exec` entry
  matches any `X.exec(tainted)` by bare property name with no receiver-type
  check, so `RegExp.exec()` calls newly carrying taint via the for-of fix
  got misidentified as `child_process.exec` command injection. Confirmed
  independent of the loop change (reproduces on a trivial non-loop fixture)
  and traced to a catalog entry that predates this PRD entirely
  (`f0d7e03`). Required a `bench/self-scan/BASELINE.json` update
  (`dataflow/index.js: 0→5`, `ir/type-stubs.js: 6→10`), not a code fix —
  logged as its own open gap in `docs/DETECTION_GAP_REMEDIATION_PRD.md`
  rather than patched here, since the real fix needs CHA to type
  regex-literal-assigned variables first.

  Third, found by the final whole-branch review: narrowing the guard fixed
  destructuring but left the shape the guard now *owns* with no kill at all.
  `const`/`let` in a for-of head is a **block-scoped** binding, and this
  engine's taint model has no block scoping — so once the loop variable was
  bound to the iterable's taint, that state flowed straight past the loop's
  exit and over-tainted a same-named OUTER variable:
  `let item = 'safe'; for (const item of req.body.items) {} eval(item)`
  reported a Code Injection finding that the pre-R13 engine correctly called
  clean, because the generic `VariableDeclarator` visitor used to emit a
  taint-KILL there and the guard suppresses it. That directly violated this
  work's own "strictly additive — never remove or alter an existing finding"
  constraint. The loop visitor now records the bound name in `enter()` and
  re-emits the kill in `exit()`, on the loop's normal exit edge
  (`header → exit-noop → kill → post-loop code`), so in-loop taint
  reachability is untouched and only the post-loop read is cleared. The
  bare-assignment form (`for (x of ...)`, no `const`/`let`) deliberately gets
  **no** kill — that binding is function-scoped and its value legitimately
  survives the loop; killing it would itself have been a regression. Both
  directions are now pinned by tests.

Both sub-fixes are covered end-to-end and at the unit level by
`test/member-write-and-loop-taint.test.js` (12 tests), wired into
`test:dataflow`.

**Verification — R13 only:** full gate green — `npm test` (3158 tests, 0
failures), corpus (214/214, no drift), mutation (12/12 mutant verdicts
correct, of which 9/9 are verdict-flip cases), layer-recall (js/ts taint recall unchanged at 7/38 vs. baseline's 7/36 — R13
lands via dedicated unit tests rather than new corpus entries, so no
taint-layer increase was expected or observed here) and self-scan (green
against the baseline this same work already updated).

### Theme E (R14(b)) — non-JS top-level IR

Closes the other half of Theme E's R14 item: Python (CST parser and regex
fallback), PHP, and Ruby now synthesize a `<module>` function wrapping
top-level statements, mirroring the JS `<module>` pattern
(`ir/parser-js.js:264,557`) that already existed. Before this, a flat
vulnerable script with no wrapping function or class — `<?php
system($_GET['cmd']);`, a bare `system(params[:cmd])` in Ruby, a bare
`os.system(request.args)` at Python module scope — had zero Layer-2
taint-analysis coverage in these three languages, regardless of how
obviously tainted the flow was, simply because the IR layer never extracted
top-level statements into any CFG at all. Unlike JS's unconditional
`<module>` creation, all three new paths only synthesize the function when
the file actually has top-level statements worth lowering, to keep the
change's blast radius on existing function-only fixtures at zero.

Landing this also surfaced (and fixed) a real, independent severity bug:
the dead-code demotion in `dataflow/engine.js` only exempts functions whose
name matches `/handler|route|controller|middleware|endpoint/i` from being
downgraded one severity tier when the call graph records no caller — but a
synthetic `<module>` function is *never* called by anything (module scope
has no caller by construction), so every finding this work would have added
was about to land one tier too low (critical → high, etc.) the moment it
shipped. `<module>`-scoped findings are now exempt from dead-code demotion
outright. **This is a severity-tier fix for existing JS `<module>` findings
too** — nothing new is detected by it, but any JS top-level finding that was
previously silently demoted now reports at its correct severity.

End-to-end coverage: `test/r14b-module-level-e2e.test.js` runs a real
`runScan` against a minimal flat script in each of the three languages
(plus Python's regex-fallback path separately) and asserts an `IR-TAINT`
finding comes back — proving the PRD's actual success metric, not just
correct IR shape. Wired into `test:dataflow`.

**Verification — R14(b) only:** `test:dataflow` (625/625, includes the 4 new
end-to-end tests), `npm test` (3176 tests, 0 failures on an isolated rerun —
two transient `spawnSync`-timeout failures surfaced under heavy parallel
system load on the first two attempts, in `audit-cli.test.js` and
`triage-command.test.js`, neither of which this work touches, and both
cleared on rerun), corpus (214/214, no drift), mutation (9/9 verdict-flip
correct), layer-recall (no taint-layer regression; python/php/ruby taint
counts unchanged from baseline, as expected — this work lands via dedicated
unit tests, not new corpus entries) and self-scan (no drift).

### Theme E (R14(a)) — annotation/decorator-shaped framework sources

Closes the other half of Theme E's R14 item, left open when R14(b) landed.
Framework sources expressed as parameter annotations/decorators — Spring's
`@RequestParam`/`@PathVariable`/`@RequestBody`/`@RequestHeader`, ASP.NET
Core's `[FromQuery]`/`[FromBody]`/`[FromForm]`/`[FromRoute]`/`[FromHeader]`,
NestJS's `@Query()`/`@Body()`/`@Param()`/`@Headers()` — had no catalog
representation at all: the catalog only matched callables and member reads,
and an annotation is neither. A controller method whose only taint source
was a decorated parameter was invisible to deep mode regardless of how
directly it flowed to a sink.

A new `annotation` catalog match kind (`dataflow/catalog.js`) is now
consulted at every one of the taint engine's 8 `analyzeFunction` entry
points via `_unionAnnotationTaint` (`dataflow/engine.js`), against a new
IR side-channel field, `fn.paramAnnotations`, populated by three language
extractors: `ir/parser-cs.js` (C#/ASP.NET Core attributes), `ir/parser-js.js`
(NestJS decorators), and `ir/parser-java.js` (Spring annotations). The Java
extractor also fixes a genuine, independent gap-fill that came bundled with
the annotation work: Java parameter names were never extracted at all
before this (`params: []` unconditionally) — real parameter names and
Spring annotations are now both pulled from the same `formalParameterList`
CST walk.

**Accepted false-positive risk, documented rather than silently shipped:**
matching is on the *bare* decorator/attribute name only (`ANNOTATION_INDEX`
is keyed by `pa.decorator`, `dataflow/catalog.js`'s `matchAnnotationParams`)
— there is no import-binding or namespace/package check confirming the
decorator actually came from Spring/ASP.NET Core/NestJS. A user-defined
decorator or attribute that happens to share one of these names (a custom
`@Query()` in an unrelated JS library, a hand-rolled `[FromHeader]`
attribute) would be treated as a tainted parameter source. This is the same
risk class R6 (`docs/DETECTION_GAP_REMEDIATION_PRD.md`) already accepted and
documented for bare-name sink matching before it grew a `receiverTypeIn`
companion gate; R14(a) has no equivalent gate yet, and none of the three
extractors have the type/import information available to build one today.
Left as a known, accepted gap rather than blocking the whole feature on it.

Per-task summary: Task 1 (catalog schema) needed one fix round (a missing
provenance filter, a latent bug). Task 2 (engine plumbing across all 8
`analyzeFunction` call sites) needed two: round 1's own review found the
wiring solid but test coverage only jointly proved 2 of 8 sites, and while
closing that gap it also made two wrong "impossible to isolate" claims about
two further sites that the re-review refuted with real repros and round 2
fixed properly. Two genuinely pre-existing, unrelated bugs were found along
the way and logged in the PRD rather than fixed: a class-field cross-taint
pass that has been dead code since v0.66.0, and a cross-file finding
line-number mis-attribution bug. Task 3 (C# extraction) needed one fix round
(stacked attributes on one parameter only captured the first) and surfaced a
third data point for the PRD's own R8 item (parenthesized attribute
arguments break the pre-existing C# method-detection regex), logged not
fixed. Task 4 (JS/TS extraction) needed one fix round (a defaulted-parameter
decorator was silently dropped by a type-check bug). Task 5 (Java extraction
+ real parameter extraction) needed one fix round (fully-qualified
annotations recorded the wrong decorator name); its own review specifically
investigated whether Java's dropped varargs parameters could cause
positional param/annotation misattribution and confirmed they cannot, for
any code that actually compiles.

Task 6 (this entry) ran the full verification gate rather than trusting each
task's own scoped tests, and it earned its keep twice over — two genuinely
new, real issues, both fixed, neither papered over.

First, the full `npm test` run (not exercised by any single task in
isolation) surfaced a real gap: the four new NestJS catalog entries
(`js-nestjs-query`, `js-nestjs-body`, `js-nestjs-param`, `js-nestjs-headers`)
were missing the `provenance` label every JS source entry is required to
carry (`test/phase7-extensions.test.js`, scoped to `test:sast`, which none
of Tasks 1-5's own isolated `test:dataflow` runs exercised). Fixed by adding
the same provenance values already used for the equivalent Express `req.*`
sources (`url-param`/`http-body`/`path-param`/`header`).

Second, `bench:self-scan:check` flagged a brand-new finding in
`ir/parser-cs.js` itself: Task 3's new `attrRegex` had two independent
`\s*` quantifiers both able to consume the same whitespace run when the
overall match fails (no closing `]`) — a textbook adjacent-quantifier
ReDoS. Verified as a genuine vulnerability, not a detector false positive,
by direct timing measurement, end-to-end reachable through
`parseCSharpFile` on an adversarial `.cs` file, not just an isolated
microbenchmark: 2.4 seconds on a 64,000-character input, extrapolating to
roughly ten minutes at 1MB.

The first fix round moved the leading `\s*` inside the optional
parenthesized-argument group — genuinely linear (re-verified: 0.49ms at
200,000 chars) — but the engine's own `safe-regex`-backed ReDoS heuristic
still flagged that version, so that round accepted a
`bench/self-scan/BASELINE.json` bump (`ir/parser-cs.js: 3→4`) as the
resolution. A task review caught that this repo already has precedent for
a cleaner fix to the exact same situation: commit `6bd394c`
(`class-hierarchy.js`) hit an identical "safe-regex flags a pattern that's
actually safe" case and resolved it by restructuring into two
independently-safe alternatives rather than accepting the drift, reasoning
explicitly that this "avoids relying on any one detector's judgment call."
Applying that same pattern here — two alternatives (no-args and
with-args) instead of one optional group, decorator name read from
`match[1] || match[2]` — passes `safe-regex` as `true`, independently
re-verified linear (0.63ms at 256,000 chars), and produces byte-identical
matches across a 12-shape sweep against the first round's already-fixed
version. **No baseline bump was needed after all**:
`bench/self-scan/BASELINE.json` was reverted to its pre-Task-6 state
(`ir/parser-cs.js: 3`, `scanner/src` total 621) once the restructured
regex stopped tripping the heuristic.

**Verification — full gate re-run after all fixes:** `test:dataflow`
670/670. `npm test` — all 12 scoped sub-scripts report `fail 0`
(`test:smoke` 28, `test:glob`, `test:sast` 553, `test:posture` 1330,
`test:dataflow` 670, `test:mcp` 102, `test:report` 111, `test:bench-modules`
70, `test:lifecycle`, plus C++-dataflow and Python suites), no `npm error`
anywhere in the run. `bench:cve-replay:check` 214/214 baselined entries, no
drift. `bench:mutation:check` 9/9 verdict-flip correct (5/5 metamorphic
hold, 4/4 adversarial flip). `bench:layer-recall:check` reports no
taint-layer recall regression across any language — expected, since R14(a)
lands via dedicated unit tests, not new corpus entries, matching R13's and
R14(b)'s own precedent. `bench:self-scan:check` clean with **zero drift
from the pre-Task-6 baseline** — the ReDoS false positive is gone rather
than accepted, matching commit `6bd394c`'s own outcome exactly.
`test/parser-cs-annotations.test.js` 5/5 after the restructure. Bundle
rebuilt (`dist/agentic-security.mjs` + `.sha256`) after each regex change;
`npm run smoke` against the rebuilt bundle correctly reports critical/high
findings on the deliberately-vulnerable fixture (exit code 3, this CLI's
documented "critical findings present" convention), and the underlying
`test:smoke` suite (28/28) already passed as part of the full gate above.

**Full Theme E (R13 + R14) is now complete.**

### Theme C (R8) — braced control-flow body recursion, four languages

Closes the single highest-leverage IR defect this project's whole
detection-gap audit found. Java, C#, Kotlin, and PHP's statement splitters
previously dropped or mangled the body of any braced control-flow statement
(`if`/`for`/`try`/`switch`/`while`/`do`/`when`) — not just losing branch
structure, but silently deleting the statements inside, or folding them into
a bogus node. Since real-world sinks in these languages overwhelmingly sit
inside exactly this shape (try-with-resources in Java, `using`/`try` in C#,
`try`/`when` in Kotlin, `try`/`foreach` in PHP), this capped deep-mode taint
recall near zero for all four regardless of any catalog or interprocedural
work already landed elsewhere in this PRD. All four now recurse into these
bodies with a real (statement-linear) CFG walk.

- **Java** (`ir/parser-java.js`) — `walkStmts` additively extended to also
  recurse into `for`/`try`/`switch`/`do`/bare-block statements. Fixed a
  self-caught bug in the implementation plan's own draft code before it
  shipped: try-with-resources' `catch`/`finally` were being read off the
  wrong CST node, which would have silently dropped catch/finally for the
  single most idiomatic JDBC pattern. One fix round closed two further
  gaps: enhanced-for's loop variable now carries real taint provenance
  (synthesized assign, mirroring `parser-js.js`'s `ForOfStatement`
  pattern), and Java 14+ arrow-form `switch` (`case 1 -> …`) is now
  recognized.
- **PHP** (`ir/parser-php.js`) — the statement splitter now flushes on a
  closing `}` (previously only `;`), with `try`/`switch` recognizers and a
  recursion guard added. This was the hardest task in the plan (3 fix
  rounds, all substantially about line-number precision, not detection
  shape) — see `docs/DETECTION_GAP_REMEDIATION_PRD.md`'s R8 status entry
  for the full round-by-round narration. Fixing the splitter this way also
  resolved a pre-existing bug where `if`/`while`/`foreach` bodies were
  already being mis-split before this task touched them.
- **C#** (`ir/parser-cs.js`) — C# had no control-flow handling at all
  before this; `_buildCfg` was built from scratch, ported from
  `parser-cpp.js`'s proven recurse-into-braces pattern. One fix round:
  `using (...) { }` and `lock (...) { }` bodies were invisible — `using`
  being the canonical ADO.NET wrapper around exactly the sinks this task
  targets, this was a real, significant gap.
- **Kotlin** (`ir/parser-kt.js`) — new recursive `_buildCfg` mirroring C#'s,
  with Kotlin-specific adaptations for its trailing-lambda call syntax and
  `when` expression arms. Zero fix rounds during implementation — the
  cleanest of the four tasks, in part because each implementer was briefed
  on the previous tasks' hard-won lessons before starting.

**Verification found and fixed a genuine regression this PRD's own new code
introduced**, not papered over: `bench:self-scan:check` flagged
`ir/parser-kt.js`'s new trailing-lambda regex as a ReDoS — the identical
defect class as this same changelog's R14(a) C# `attrRegex` finding (an
optional group sandwiched between two `\s*` quantifiers), independently
confirmed genuinely quadratic by direct timing. Fixed the same way that
precedent was: restructured into two mutually-exclusive alternatives,
re-verified linear and byte-identical across a 15-shape sweep. A second,
unrelated ReDoS in the same file's variable-declaration regex was found
during that investigation and traced to a commit five months predating this
PRD — left unfixed and logged as a candidate future item, since it wasn't
introduced by this work.

**Measured `bench/layer-recall` impact: 0 of 4 languages — an honest
result, not the one originally expected, and corrected once more after
this entry's first draft mis-attributed PHP's gain.** Baseline before:
`java 1/25, kotlin 0/20, c# 1/21, php 1/23`. Measured after: `java 1/25
(unchanged), kotlin 0/20 (unchanged), c# 1/21 (unchanged), php 2/23 (+1)`.
PHP's `+1` is real, but it is **not R8's** — commit-swap A/B testing shows
the pre-R8 `parser-php.js` still reproduces 2/23, while the pre-R14(b)
`parser-php.js` (an earlier, unrelated PRD item — PHP's `<module>`
top-level lowering) drops it back to 1/23. None of the corpus's `pre/`
fixtures — the state the benchmark actually scores — place a sink
genuinely inside a control-flow body for any of the four languages this
task touched. The underlying capability this task fixed is completely real
and independently proven, just not by this corpus: each language's own new
dedicated `runScan` unit test (`test/parser-{java,cs,kt,php}-control-flow.test.js`)
directly asserts a sink nested inside an `if`/`try`/`for`/`switch` body is
now detected where it wasn't before. `bench/layer-recall/baseline.json`
still updated to the measured counts (`entriesScored` 210→214, `php` 1→2,
plus an unrelated `js/ts` 7→8 catch-up from this baseline file not having
been regenerated since 2026-08-11 — no language decreased) — the baseline
update is correct regardless of attribution, since it reflects the
engine's actual current state. A follow-up item: this corpus needs a
fixture per language with a sink genuinely inside a control-flow body (not
a guard clause) before it can measure R8's impact at all.

**Full gate:** `test:dataflow` 725/725 (rerun clean after the ReDoS fix).
`npm test` — all 12 scoped sub-scripts green (`test:smoke` 28, `test:glob`
13, `test:sast` 553, `test:posture` 1330, `test:dataflow` 725, `test:mcp`
102, `test:report` 111, `test:bench-modules` 70, `test:lifecycle` 216,
`test:eval` 23, `test:discovery` 79, C++-dataflow 26, plus the Python script
suite). `bench:cve-replay:check` 214/214, no drift. `bench:mutation:check`
9/9 verdict-flip correct. `bench:self-scan:check` clean with zero drift
from the pre-R8 baseline after the fix.

## 0.136.10 — detection-gap remediation Theme A: dedup, family, and calibration for deep mode

An architectural audit of the SAST/taint pipeline (`docs/DETECTION_GAP_REMEDIATION_PRD.md`)
found nine structural gaps behind missed real-world vulnerability classes. This
release lands Theme A, the fixes on the production detection path:

- **Dead-code demotion silently downgraded nearly every finding.** A field-name
  mismatch (`.to`/`.size` vs the real `.callee`/Array shape) meant `calledQids`
  was always effectively empty, so any function not named `handler`/`route`/
  `controller`/`middleware`/`endpoint` — including most real sinks — got
  demoted one severity notch on every deep-mode scan that ever ran.
- **Half the sanitizer catalog was unreachable.** 191 of 381 sanitizer entries
  use dotted callees (`Encode.forHtml`, `filepath.Clean`, `validator.isEmail`)
  indexed under the full dotted key, but every lookup path reduced to the
  callee's last segment — so these entries could never be retrieved. Catalog
  lookup now tries the full dotted key before falling back to the last segment,
  the behavior its own header comment already promised.
- **A sanitizer-blind kill switch.** `builtin-summaries` deleted taint outright
  at ~15 name-matched builtins (`parseInt`, `encodeURIComponent`,
  `DOMPurify.sanitize`...) regardless of threat family, contradicting the
  engine's own documented doctrine that sanitizers demote, never kill —
  `x = encodeURIComponent(t); db.query(x)` silently lost its SQLi finding.
  Now demotes through the same family-scoped sanitizer gate every other path
  uses.
- **Three bench-shape leaks were opt-out instead of opt-in**, violating this
  repo's own documented convention (`AGENTIC_SECURITY_BENCH_SHAPE=1` to enable,
  never `AGENTIC_SECURITY_BLIND_BENCH` to disable): a Juliet path-prefix
  category filter with no env check at all, and two Java answer-key mechanisms
  gated the wrong direction.
- **Cross-file import resolution was dead code with zero callers.** `fileContents`
  was never threaded into `buildCallGraph`, so its re-export/import-binding
  resolution never ran — two same-named functions in unrelated files collided
  by bare name on every scan.
- **The points-to graph was built and then never wired in.** `AGENTIC_SECURITY_POINTS_TO=1`
  computed a real alias graph but `runTaintEngine` never copied it onto
  `callContext`, so the opt-in flag caught nothing. A second bug in
  `aliasesForVar` (stripping only the first `::` instead of the qid's full
  prefix) was fixed alongside it, since the qid itself always contains
  multiple `::` segments.
- **Guard recognition was flow-insensitive.** `dropGuardedFindings` matched a
  guard-shaped regex anywhere in a −25/+5 line window with zero correlation to
  the sink's actual tainted identifier, killing real SSRF/path findings
  whenever unrelated guard-shaped text sat nearby. Rewritten to require the
  guard match to appear near one of the sink's own argument identifiers.
  Reachability annotation was also fixed to record "unknown" rather than
  "unreachable" for languages with no call-graph data — only a strict `false`
  should demote a finding, and absence of evidence isn't evidence of absence.
- **Deep mode was unreachable from the MCP and LSP integration surfaces.**
  `scan_diff` and `scanFile` never enabled deep mode, so the interprocedural
  taint engine — the thing most likely to catch a real cross-function
  vulnerability — never ran from either integration.
- **Deep-mode (IR-TAINT) findings bypassed the entire finding pipeline.** They
  were appended *after* dedup, clustering, stable-ID assignment, family
  backfill, confidence, and calibration had already run once, so a sink caught
  by both the regex layer and deep mode produced two findings — one of them
  permanently unscored (no family, no calibrated confidence, no reachability
  demotion, no mitigation annotation). Deep-mode findings now enter the same
  pre-dedup pool as every other detector's output and ride the identical
  pipeline. Fixing this exposed two further latent bugs it's now safe to state
  plainly: dedup's winner-selection didn't prefer a real interprocedural
  taint-walk finding over a same-severity flat pattern match at the same sink
  (an IR-TAINT finding could lose a tie and take its sanitizer/chain evidence
  down with it), and root-cause clustering keyed its "same sink" bucket on a
  generic catalog rule id rather than a per-line signal, so two unrelated
  `eval()` calls in one file could collapse into a single reported finding the
  moment deep-mode findings started reaching that annotator. Both are fixed.

Verification for all nine items: full test gate green, CVE-replay corpus
214/214 with zero drift, metamorphic/adversarial mutation gate 6/6, self-scan
precision gate re-baselined against three fully root-caused (not blindly
accepted) drifts, and the pre-push gate's per-language taint-recall check
confirmed no regression. `@vercel/ncc` (dev-only build dependency) was also
bumped 0.44.1 → 0.45.0 to clear the release gate's dependency-currency check.

R3 (route deep-mode findings through the full annotator pipeline) was the last
item in Theme A. Themes B–E of the same PRD — semantic type/import-aware
matching, control-flow-blind-parser fixes for Java/C#/Kotlin/PHP, deeper
interprocedural completeness, and DOM/loop-element flow modeling — remain open
and are tracked in `docs/DETECTION_GAP_REMEDIATION_PRD.md`.

## 0.136.9 — the real bug: the single-file bundle was never actually self-contained

0.136.8's diagnostic logging answered the question immediately:

```
Error [ERR_MODULE_NOT_FOUND]: Cannot find module
'.../scanner/dist/449.index.js' imported from
'.../scanner/dist/agentic-security.mjs'
```

`dist/agentic-security.mjs` is documented and committed as a self-contained
single-file bundle — `.gitignore`'s own comment says the reusable
`scan.yml` workflow fetches *only that one file* from
raw.githubusercontent.com so downstream users need no install step. That
was never quite true. `bin/agentic-security.js` lazily loads each
subcommand's implementation with `await import('../src/...')` — about 58
call sites, deliberately, so running `agentic-security scan` doesn't pay
the cost of loading every posture/discovery/compliance module `agentic-security
compliance` or `agentic-security hunt` would need. `ncc` code-splits every
one of those into its own `dist/NNN.index.js` chunk rather than inlining
it, and the chunk is loaded at runtime via a path relative to the bundle's
own location on disk — but `.gitignore` only ever allowlisted the main
`.mjs`, its sha256 sidecar, and the compliance-frameworks data. All 38
chunk files were silently gitignored. `.claude/settings.local.json`-style
invisible: they exist on any machine that has ever run `npm run build`
locally (which is every contributor's, permanently, from the first
`npm install`), so nobody — human or gate — had a checkout that lacked
them until this release's hosted CI runs did.

This is the third occurrence of the identical bug class in this file's own
history — `.gitignore` already carries a comment about the same thing
happening to `compliance-frameworks/` data before ("the shipped CLI
silently listed ZERO frameworks and exited 0"). Same shape both times: a
single tracked entry point quietly depends on sibling files nobody
allowlisted.

Fixed by allowlisting `scanner/dist/*.index.js` and committing all 38
current chunks (744 KB), and by adding a permanent regression guard
(`test/dist-chunks-tracked.test.js`, wired into `test:lifecycle`) that
diffs `dist/*.index.js` on disk against `git ls-files dist` and fails
loud, by name, the moment a future build produces a chunk nobody
allowlisted — rather than waiting for a lazy code path to hit it in
production. Verified RED against the pre-fix git state (all 38 chunks
correctly reported untracked) and GREEN after staging them.

## 0.136.8 — instrumenting a real, still-unexplained hosted-CI-only failure

0.136.7's hosted release run got past every other check and failed on
exactly one: `test/mttr.test.js`'s CLI-wiring test, which asserts a real
`agentic-security scan` reports an `mttr` field in `last-scan.json`. That
field comes from a deliberately best-effort code path in `cmdScan`
(`bin/agentic-security.js`) wrapped in a bare `catch { /* MTTR is
best-effort — never block a scan write */ }` — correct as a product
decision (a scan must never fail because a secondary metric couldn't be
computed), but it means whatever throws inside that block has never been
visible to anyone, including this investigation.

This is now confirmed NOT the shared-runner flakiness 0.136.5/0.136.6
blamed it as: reran the identical failed job against the identical commit
(`gh run rerun --failed`, no code change) and got the exact same failure,
same file, same line, same message, a fourth consecutive time. Extensive
local reproduction attempts — simulating `CI=true`/`GITHUB_ACTIONS=true`,
running the full 1328-test `test:posture` scope concurrently to match CI's
exact invocation shape, invoking the real bundled CLI directly under the
same env vars — all passed cleanly. Whatever this is, it is deterministic
on GitHub's hosted runner and has not reproduced anywhere else tried so far.

Rather than keep guessing, the silent catch now logs the actual error to
stderr whenever `CI`/`GITHUB_ACTIONS` is set (or `AGENTIC_SECURITY_MTTR_DEBUG=1`
locally), and the test's own assertion message now includes the scan
subprocess's stderr. Scan behavior is unchanged — this is instrumentation
only, shipped specifically to get a real answer out of the next hosted run
instead of another guess.

## 0.136.7 — the doc-drift checker was resolving paths outside the repo

0.136.6's hosted release run failed on a check this same audit added a few
releases ago: `check-doc-drift.mjs`'s own regression test, "the real
repository currently has zero mechanically-checkable drift," flagged root
CLAUDE.md's documented (and correctly gitignored) `.claude/settings.local.json`
reference as a dangling path.

The actual defect was in `resolveCandidate`'s search bases, not in the
reference: for a CLAUDE.md near the repo root, one of the fallback bases is
"two directories up from the CLAUDE.md's own directory" — meant for nested
CLAUDE.md files reaching back toward the repo root, but for the ROOT
CLAUDE.md itself that lands OUTSIDE the checkout entirely, in whatever
happens to be the parent of wherever the repo was cloned. On the
maintainer's laptop that's their home directory, which happens to contain
an unrelated, machine-global `~/.claude/settings.local.json` from ordinary
Claude Code usage — so the checker "resolved" the reference against a file
that has nothing to do with this project, passed locally, and failed on a
clean CI checkout where no such coincidence exists. `resolveCandidate` now
rejects any candidate base or resolved path outside the repo root, and
`settings.local.json` — genuinely optional, gitignored, user-created — joins
the checker's existing known-example-basename allowlist as a second,
independent fix.

Reproduced without touching CI: moved the local override file aside,
confirmed the existing regression test still passed (proving the checker was
resolving against something else entirely), traced it to the home-directory
escape, fixed both the escape and the allowlist gap, verified clean with the
file present and absent, then restored it.

## 0.136.6 — correction: the "flaky" dataflow tests were a real, deterministic gap

0.136.5's entry below called a cluster of `test:dataflow` failures on the
hosted runner resource-contention flakiness, because a second, simultaneous
workflow run of the identical commit showed a completely different failure
and neither reproduced locally. That diagnosis was wrong, and the actual
cause is more interesting: 13 test files pass `runScan(dir, { deep: true })`
to exercise the interprocedural taint engine directly, but never opt into
`AGENTIC_SECURITY_DEEP_IN_CI` — and `engine.js` deliberately auto-disables
deep mode under any detected CI environment unless that second flag is also
set, precisely so a pathological file can't hang a CI pipeline. Every one of
those 13 files has therefore been silently CI-broken (never actually
exercising the deep engine there, only recording the "skipped in CI"
placeholder finding) since the day it was written — invisible until this
release's tag push put 62 accumulated commits through hosted CI for the
first time. Reproduced deterministically with `CI=true node --test
<file>.test.js` locally (no CI service required), fixed by threading
`deepInCi: true` alongside `deep: true` at all 21 call sites across those 13
files, and confirmed both directions: `npm test` is clean with `CI` unset
and with `CI=true` set.

The earlier flakiness diagnosis wasn't entirely wrong — the *other* workflow
run's single MTTR-wiring failure genuinely didn't reproduce on a third run
and remains unexplained — but it was wrong about *this* failure cluster,
which was 100% reproducible once isolated with the right environment
variable rather than blamed on shared-runner load.

## 0.136.5 — the release workflow gets its own missing dependency

0.136.4 was tagged and its release workflow ran — for the first time ever,
since the 60-odd commits it carried had accumulated across many local
sessions without a single hosted-CI push. The gate caught a real gap in
itself: `nist-catalog-freshness` (a check this same release adds, see below)
shells out to `scripts/nist-compliance/build-catalog.py`, which needs
`openpyxl` to read the source workbook. That's present on the maintainer's
machine via a system Python install, but nothing installs it on the hosted
runner — so the check could never have passed there. `release.yml` now
installs it explicitly before the gate runs.

The same CI run also showed roughly a dozen dataflow tests fail — a
completely different set than the *other* workflow (`ci.yml`) failed on the
same commit at the same time (one flaky MTTR-wiring test, no overlap with the
dataflow set). Neither set reproduces locally, isolated or otherwise. That
non-overlap is the signature of resource-contention flakiness on a shared
runner, not a deterministic regression, so it isn't chased further here — but
it's worth knowing about if a future release gate flakes on `npm test` again.

Per the project's own precedent (see 0.136.1 below): a tag that failed to
publish stays where it is rather than being moved. 0.136.4 is that tag. This
ships as 0.136.5 instead, otherwise identical.

## 0.136.4 — dominance-correct implicit-flow taint, and wiring three dead-reachable tools

A capability-PRD follow-up audit found several places where a real, tested
mechanism existed in the code but nothing in the product could actually reach
it. This release closes those gaps rather than documenting them further.

**`implicit-flow.js` now uses real dominance, not a depth counter.** The
branch-scoping check for implicit taint (does a constant-argument sink sit
*inside* a tainted branch, or after it closes?) was a path-dependent DFS
depth-counter, which cannot distinguish a join point from a nested branch and
both over- and under-attributes depending on CFG shape. It's replaced with a
proper dominance check (`ssa.js`'s `computeDominators`, already used for φ-node
placement, now exported and reused here) plus a predecessor-count "sole
parent" test — needed because an else-less `if`'s CFG lowering links the
condition directly to the join node, which a naive dominance check alone would
still misread as a branch root. `dataflow/engine.js`'s implicit-flow post-pass
is split into two correctly-scoped passes: a sink-call-must-be-inside-the-
branch check for constant-argument leaks, and an ungated check for
already-tainted-variable-as-argument leaks, which don't need the sink itself
to be branch-local.

**Three previously-dead mechanisms are now reachable.** `verify_fix`'s PoC-
recheck leg always reported `not-requested` — the caller never had the PoC to
pass it, so it's now looked up server-side from the finding's own
`last-scan.json` entry. `fix-honesty-gate.js`'s deterministic honesty checks
(vague-assurance residual prose, unbacked false-positive verdicts) were fully
built and consulted by the verifier, but `fixMeta` was never in `apply_fix` or
`verify_fix`'s MCP schema, so no caller could ever supply one; a dishonest
`fixMeta` now blocks the write itself, not just the report. `verifyRunAttestation`
had no CLI caller at all — `verify-attestation` now auto-detects a
run-attestation shape and re-scans the target to check it reproduces the
attested digest, backed by two new release-gate checks
(`attestation-self-check`, `nist-catalog-freshness`).

**Stale docs, fixed instead of flagged.** `docs/compliance/{nist-ai-600-1,
owasp-asvs}-coverage.md` carried static control tables that drifted from the
live evaluator; both now point at the `/compliance` walkthrough/report instead
of duplicating data that can go stale. The ASVS doc also had a genuine
version mismatch (4.0.3 vs. the 5.0 catalog actually in use). A new
`scripts/check-doc-drift.mjs` catches this class of staleness mechanically —
it resolves every backtick-quoted path/export reference in a CLAUDE.md file
against the real filesystem — after this audit found several by hand.

**CVE-replay corpus:** four new capability entries (IaC open-ingress, LLM
system-prompt injection, MCP untrusted-install, API missing-auth/BFLA),
closing four of six previously-flagged zero-coverage categories; each verified
`pre:TP post:TN` against the real runner before joining the baseline. SBOM and
SCA-reachability are documented in `bench/cve-replay/CONTRIBUTING.md` as
structurally unable to fit this corpus's binary presence/absence schema —
they're covered by their own test suites instead.

CMP-1's family-alias table also closed three more gaps
(`k8s-pod-security-privileged`, `mcp-audit.js`'s `agent-tool-exec` backfill,
dependency-confusion family tagging).

**No functional change from 0.136.2.** This version exists for one reason, and
it is worth stating plainly rather than dressing up: 0.136.2 reached npm from a
maintainer's laptop, not from CI, so it carries **no provenance attestation** —
nothing ties that tarball to this repository or this commit beyond trust in the
publisher.

npm will not accept a re-publish of an existing version, so obtaining provenance
requires a new one. 0.136.3 is that, and nothing else.

The release path itself was already proven end to end on 0.136.2: the gate passed
on a clean runner, npm signed a provenance statement and recorded it in the
Sigstore transparency log, and only the final registry upload was rejected —
because the token in CI was not authorized to publish. With a valid automation
token that last step completes, and the attestation that was already being
generated actually lands.

Verify it yourself once published:

```
npm view @clear-capabilities/agentic-security-scanner@0.136.3 --json | jq .dist.attestations
```

`null` means it went out unattested again. `dist.signatures` is NOT the same
thing — the registry signs every package it serves; provenance is the separate
Sigstore statement binding the artifact to its source.

## 0.136.2 — authenticate the gate on the path that actually runs it

0.136.1 removed the self-deadlock and the release workflow got further: every
gate check passed, then `npm publish` failed with *"the forge CLI is not
authenticated"*.

The gate runs **twice** in that job. Once as an explicit `Release gate` step,
which sets `GH_TOKEN` and passed. Then again inside `npm publish`, which
triggers `prepublishOnly` — and that step set only `NODE_AUTH_TOKEN`. The second
run had no token, could not read hosted CI, and refused.

The gate was right to refuse: unverifiable is not green, and the remedy it
suggests — `--allow-unverified-ci` — would have published without proving the
commit was green at all. So the fix is to authenticate it, not to relax it.
`checks: read` is now declared explicitly too; the gate passed without it on the
default token, but depending on an undeclared default is how a tightened default
becomes a mystery failure a year later.

The same shape as the deadlock it follows: a control that works on the path
that was tested, and fails on the path that actually ships.

## 0.136.1 — the release gate stops deadlocking on itself

`npm publish` had been impossible since 0.135.0, and the cause was not the one I
reported. Not a missing npm token: **the release gate was waiting for itself.**

The release workflow's job is named `publish`. The gate runs inside that job,
queries hosted CI for HEAD, sees a check run named `publish` that is
`in_progress` — itself — and requires it to finish before allowing the release.
It never can. Every tag push failed this way with all nine real checks green, and
the resulting `publish: failure` then blocked local publishes too, which is the
error that finally surfaced it.

`.github/required-checks.json` gains a third category, **self**, beside blocking
and informational. A self check is EXCLUDED, not trusted: it cannot report a
conclusion until the gate it contains has already passed, so requiring it is a
deadlock and believing it would be believing a check that has not run. The file
already insisted every check be classified deliberately — this is the category
that was missing, and its absence meant `publish` fell through to the safe
default of blocking, which was exactly wrong here.

Proven in three directions, because excluding a check must not weaken a gate:
a pending self check no longer blocks, a FAILED self check no longer blocks, and
a genuinely red blocking check still does. Verified against live CI state:
`PASS Hosted CI is green for HEAD`.

v0.135.0 and v0.136.0 were tagged but never reached npm for this reason. The
tags stay where they are — a public tag is not moved — so this ships as 0.136.1.

## 0.136.0 — NIST Privacy Framework 1.1, and the frameworks that never shipped

### A privacy compliance scan that says what it did not check

All 104 PF 1.1 controls, assessed on every scan, artifacts at
`.agentic-security/privacy-framework.{json,md}`. Each gap is emitted as an
ordinary finding (`family: privacy-compliance`, `CWE-359`) carrying an actionable
remediation, so `/fix` handles it like anything else.

The design turns on one column in NIST's own workbook. PF 1.1 rates each control
for code-testability — **23 yes, 33 partial, 48 no** — and that rating says a
control *could* be assessed from source, not that this engine assesses it.
Collapsing the two is how a privacy report marks "the organizational mission is
communicated" as PASSED because no rule fired against it, and someone hands that
to an auditor. So every control lands in exactly one stated bucket:

| Bucket | Meaning |
|---|---|
| gap | mapped to an engine signal, and that signal is failing — the only bucket that emits a finding |
| not assessed | NIST rates it code-testable, this engine has no signal — named, never a pass |
| manual | NIST rates it not code-testable — governance, outside any scanner's reach |
| satisfied | mapped, and the signal is clean |

Measured on a live fixture: 9 gaps, 20 satisfied, 27 not assessed, 48 manual.
The satisfied rate is reported over the **29 assessed** controls, never over 104.

A **vacuous-satisfaction guard** was added after the module's own test caught it:
a `family:`-mapped control clears when no findings of that family are open, which
is equally true of a scan that read zero files. Pointing the tool at an empty
directory was reporting privacy controls as satisfied on the strength of having
looked at nothing. Now every mapped control degrades to *not assessed* and the
summary says so.

Findings are opt-in (`AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1`). The assessment
always runs and persists; appending findings by default would change every
severity count and gate verdict downstream, and a compliance opinion should not
silently become someone's build failure.

### A real `compliance` subcommand

```
agentic-security compliance [--gap] [--list] [--walkthrough <id>]
                            [--format cli|json|md] [--fail-on gap]
```

`/compliance --privacy` was documented as a mode with no binary behind it. It
reads `last-scan.json` rather than re-scanning — a compliance answer is a
statement about a scan that happened. With no scan to read it exits **2** rather
than assessing an empty project. Exit codes: 0 report produced, 1 only with
`--fail-on gap` and a failing control, 2 nothing to assess.

### Every bundled framework had been invisible from the published artifact

Running the new subcommand from the shipped bundle printed nothing and exited 0.
`auditor-walkthrough` resolves its data directory from `import.meta.url` — inside
the bundle that is `dist/`, and `dist/compliance-frameworks/` never existed
because the build only emitted the `.mjs`. `listFrameworks` catches the readdir
failure and returns `[]`.

So GDPR, ASVS, NIST AI 600-1 — all nine — worked perfectly from source and were
**silently absent from the npm package**. Nothing caught it because every test
ran against `src/`. The build now copies the data next to the bundle, the data is
tracked in git for the same reason the bundle is, and a test drives the BUNDLE so
it cannot regress.

Twice in this release, testing the shipped artifact rather than the source found
something the whole suite was blind to.

### Also

Removed all remaining PRD documents, repairing 18 files that referenced them.
`bench/proof-corpus`'s section-level citations (parse-coverage rule, acceptance
criterion 2, criterion 4, the disclosure boundary) are now stated inline and
owned by the files that depend on them — the rationale outlived the document.

## 0.135.0 — a scan stops modifying what it scans, and the benchmark stops flattering

Two findings, one of which reverses something this project previously reported.

### `--no-state`: a scan is an observation again

Pointing the engine at a directory used to write **10 files** into it. For a user
that means CI asserting a clean tree fails after a scan, and scanning a
dependency or a customer's code leaves artifacts in a tree they own. Worse, our
own output contains CWE identifiers, so a second scan could read the first
scan's conclusions as source.

`AGENTIC_SECURITY_NO_STATE=1` (and `--no-state`) now adds **zero paths** while
reporting byte-identical findings. Both halves are asserted, and the test was
proven to FAIL with the switch off — the switch must change what is written,
never what is found. The engine also skips `.agentic-security/` when walking, so
our output can never become our input.

Three defects were found in the guard meant to enforce this, each worth more
than the line that fixed it:

- **`git status` is not sufficient evidence.** Git does not track empty
  directories, so an earlier revision reported a CLEAN tree while still creating
  `sbom-history/` and `fix-history/`. Directory creation is mutation: it fails on
  a read-only mount and is litter in someone else's repo. The acceptance test
  compares full path listings.
- **The guard was blind to `bin/`** — where the three largest artifacts
  (`findings.json`, `last-scan.json`, `.sig`) are written. A seam guard that
  cannot see the CLI entry point misses the primary writer.
- **The detector counted documentation as a violation**, then over-corrected: a
  glob inside `// .agentic-security/rules/*.yml` opened a block comment that
  consumed 12,198 characters and hid a real violation. Comment-strip order is
  now load-bearing and asserted in both directions.

Stated plainly: 55 modules still build state paths by hand and remain on a
migration ledger. What changed permanently is that a 56th cannot be added.

### The independent recall figure was wrong, and the correction is downward

Benchmark trees had been contaminated by the engine's own state files (220
polluted trees, 544 carrying `CWE-` strings). Fixing that coincided with a second
change — restricting matches to the files the advisory's fix commit touched — and
recall fell from a previously reported 33.6% to 12.7%.

Attributing that fall to the wrong cause would have been the same reasoning error
as the contamination, pointed the other way, so the runner now scores both ways
in one pass:

| | advisory-local (**the claim**) | wide (diagnostic) |
|---|---|---|
| recall | **12.7%** (14/110) | 33.6% (37/110) |
| precision | **50.0%** (14/28) | 50.0% (37/74) |
| F1 | **0.203** | 0.402 |

The wide figure is identical to the pre-purge number. **The contamination was
real and had to be fixed, but it was not inflating the measurement** — every one
of the 20.9 points comes from the benchmark becoming honest about *where* a
finding has to be. 12.7% is the true recall, and it always was.

It is published as a low number rather than quietly requalified, because the
point of owning the instrument is to be able to trust it when it disagrees.


## 0.134.0 — the loop closes, and the logic tier learns how to be wrong

The remaining PRD epics. Two of them are new capability; the other two are the
same idea applied twice — a claim nobody can disagree with is the weakest thing
this engine emits, so both new tiers ship with the machinery to refute
themselves.

### Two more proof classes, and neither needed a running application

`sql-injection` and `path-traversal` join the three existing classes. The PRD
assumed both would wait on a running-app harness; they did not, because the
harness was never where the proof lived.

- **SQL injection is settled at the driver boundary.** Either the payload
  arrives inside the query TEXT or it arrives as a bound parameter — the first
  is the vulnerability by definition and the second is the fix by definition,
  and no schema, rows or live server are needed to tell them apart. The PoC
  stubs the driver with a recorder and writes the marker only when the payload
  shows up inside something recognisably SQL. A parameterised query reaches
  `proof-failed` by **execution**, not by reading the source.
- **Path traversal is settled by what comes back.** A sentinel is planted
  outside the served directory and the marker is written only if its content —
  or, for `sendFile`, its resolved path — comes back out of the handler. A
  `basename` guard is refuted by running it.

Both directions are pinned by tests that execute in the real sandbox. Classes
still absent (IDOR, SSRF, XSS) are now documented as decisions with reasons
rather than gaps: a PoC built on invented application state proves something
about the invention.

Fixed along the way: the webhook PoC wrote its marker after a top-level `await`
guarded by an **unref'd** timer, so a handler that never replied let Node exit
with the promise pending and the marker check never ran. The test asserting
"no decision writes no marker" had been passing without reaching the line it
was testing. Timer is now ref'd and cleared, with a positive control asserting
the process reaches exit 0.

### The autonomous loop, wired to real stages

`scripts/autopilot.mjs` connects the loop to a real scan, a real sandboxed
exploit, a deterministic-then-model fix, and the real gate. End-to-end tests run
the whole thing against a live HTTP endpoint, including the one that matters: a
patch that changes the file, reads like a fix, and would satisfy any "did the
scanner go quiet?" check is **refused and never written**, because the exploit
still fires against it.

The CLI refuses to start without a confinement backend (the verdict requires
executing something) and refuses a dirty git tree by default (the test leg
writes the candidate patch to disk and restores it in a `finally`; a clean tree
is what makes a crash recoverable). A verified fix reached with no test runner
detected is counted and reported separately — the exploit stopped firing, but
nothing checked the application still works.

### The business-logic tier learns how to be wrong

The deterministic half already existed. The reviewing agent's half was prose:
it asserted that a handler lets one user act on another's resource, and nothing
in the finding gave a second party anything to disagree with. It was the only
tier in this engine with no way to be wrong.

`posture/logic-claims.js` adds three offline lenses that can refute one —
citation (the file exists and the line is inside it), quotation (the quoted
snippet is at the cited line), corroboration (a "no authentication" claim
against a handler that plainly authenticates). Verdicts go through the existing
producer/verifier separation, so a lens can never vote on a claim it produced;
that is why the lenses are deterministic code and not another prompt. Refuted
claims are quarantined, never deleted and never severity-touched.

### A comparison harness that ships no opinion about who the competition is

`posture/comparison.js` + `scripts/comparison.mjs` score this engine
head-to-head against participants **the operator supplies**. The repository
ships the harness and the answer key and names no tool — a test enforces that.

Two properties are the entire module. Every rate is computed over the
**intersection** of corpus entries *all* participants completed, because a tool
that crashed on the forty hardest entries and was scored over the remaining
hundred and seventy looks like it beat one that completed everything, and the
difference is invisible in the output. And an entry a participant could not run
is **unscored**, never counted as a miss: counting a crash as a false negative
penalises a tool for a harness problem, counting it as a pass rewards it for
one. Matching is CWE-only so nobody is scored on this engine's vocabulary.

No comparison figures are published in this repository. Running other vendors'
tools and publishing the numbers is the operator's call, not the harness's.

### The suppression pragma never worked

Found while suppressing a false positive in this release's own new code.
`// agentic-security-ignore: <rule-id>` is documented in `CLAUDE.md` and
`pr-comment.js` tells every reviewer to use it — and **nothing implemented it**.
It has been advertised and inert. A dead suppression mechanism is worse than an
absent one: the developer writes the pragma, sees the finding again, and
concludes the scanner is noisy rather than that the pragma is dead.

Now implemented in `engine.js`, applied after dedupe and after every cross-file
pass so it covers a finding whichever analysis produced it. Line-scoped, matched
against the finding's id / vuln / CWE / family, and **logged** to the same
ledger custom rules use so `--include-suppressed` can show it. Every test
carries a positive control — the same file without the pragma must still
produce the finding, or "0 findings" would prove the suppression works and
equally prove the detector stopped firing.

## 0.133.0 — two ways findings could be silently deleted, both closed

Four rounds of adversarial premortem against this repository's own artifacts.
Two rounds found working exploits in shipped code; both are fixed and both are
pinned by tests that run the original attack. The rest is measurement honesty —
several gates turned out to prove less than they claimed, including one defect
this effort introduced and then caught.

### Security

- **A signature anyone could forge could disable any detector.**
  `verifyLastScan` accepted a second key derived as
  `sha256(<constant salt> + ':' + hostname)`. The salt is a constant in
  published, npm-shipped source and a hostname is not a secret. Because the
  `disable:` list in `rules.yml` is gated on that verification, a signature
  forged from public information alone switched off arbitrary detectors and the
  scan reported clean. Demonstrated end to end: a command-injection finding went
  from 1 reported to 0, and back to 1 after the fix.

  This had been known and fixed once already. The 0.62.0 entry below introduced
  the per-install key precisely because the old one was "hostname-derived and
  publicly forgeable in CI / containers", and kept legacy verification "for one
  release to migrate existing signed scans". It was still accepted **seventy
  minor releases later**. A migration window nobody closes is not a migration
  window; it is the vulnerability, kept. Verification now accepts exactly one
  key. Signatures made under the legacy key stop verifying — intended, and it
  fails closed.

- **The LLM validator cache was a finding-deletion primitive.** A cache hit
  assigned a verdict directly, and a `reject` verdict drops a finding. The cache
  was read with a bare `JSON.parse(readFileSync(...))`, so planting one file
  under `.agentic-security/llm-cache/` deleted a critical finding with no model
  call and no network. The key is derivable by anyone with repo access, and CI
  restoring a cache directory between runs delivers it without a repo write at
  all. Cache entries are now HMAC-signed with the same mechanism `last-scan.json`
  already used; an unsigned, tampered or foreign-keyed entry is a MISS, never a
  verdict.

- **A `reject` can no longer delete a strongly-provenanced finding.** The code
  asserted that prompt-injecting the validator was harmless because "the worst
  an attacker can produce is escalate". That was false: the challenge/nonce
  cross-check defends against forged and replayed responses, not against a model
  persuaded by source it legitimately read. Findings from real analysis
  (taint-proven, multi-sink, execution-proven) are now demoted to `escalate`
  rather than dropped, so the guarantee is structural instead of asserted.

- **Coverage reduction is now visible in the artifact.** A `disable:` that took
  effect produced findings that were simply absent — indistinguishable from
  clean code to whoever reads the report. `suppressedRules` now carries the
  count, per-rule severity breakdown, example locations and the AUTHORITY the
  suppression ran under, so a signed suppression reads differently from an
  env-var opt-out. Authorised suppressions are reported too: a signature proves
  who asked, not that the hidden findings stopped existing.

- **Signatures carry key provenance** (`env` / `per-install` / `ephemeral`).
  `env` means whoever set the environment could have signed the run; `ephemeral`
  means the key could not be persisted and the signature will never verify
  again. Neither was inferable from the digest.

- **The suppression quorum has a floor of 2.** `AGENTIC_SECURITY_LEARN_QUORUM=1`
  was honoured, so a single triage verdict could suppress a finding — and with
  family+path matching, a whole family across a path. The root guidance warned
  about exactly this; the code did not enforce it.

### Measurement honesty

- **The corpus is fitted to the detectors it measures, and now says so.** 98% of
  entries are self-authored synthetic fixtures and none come from the
  disclosed-PoC tier. `npm run corpus:provenance` prints the composition on every
  run and fails a commit that lands a detector together with the corpus entries
  exercising it — caught against real history, including one such commit in this
  very effort. This stops the loop tightening; it does not make the corpus
  independent, and the docs no longer imply otherwise.

- **The precision gate covered 6% of the source.** It ran over `hooks/` and
  `scripts/` — 22 files — while `scanner/src` (383 files, the entire product) sat
  outside it. Now 240 files. The `scanner/src` count is published as a DRIFT
  TRIPWIRE, explicitly not hand-reviewed and explicitly not a precision figure,
  because a scanner's own source contains sink patterns as data.

- **The determinism gate exercised only the layer that cannot vary.** The
  original fixture produced findings from regex and structural detectors alone. A
  second fixture now drives the interprocedural taint engine and the Python
  parser, digests are compared per fixture so a divergence names the layer, and
  the comparator fails if the deep fixture degraded to the syntactic layer on any
  machine.

- **The scorecard gate could not detect a stale scorecard.** It compared only the
  engine version, so a document measured over 200 corpus entries passed while the
  corpus held 210 — every published rate computed over a population that no
  longer existed. It now compares the population too.

- **The independent-evaluation gate passed on a 4-sample smoke fixture** its own
  README says must never be cited, because its thresholds had been calibrated to
  pass. It now uses the README's own figures, treats exceeded calibration targets
  as violations rather than notes, and refuses to emit a pass over the built-in
  fixture however the thresholds are set. It fails today, correctly.

- **Claims re-scoped to what is measured.** The roadmap carries a "What the gates
  do not prove" section, states outright that the false-positive-rate goal is not
  met, and points at the two harnesses built for that gap — both of which need
  data, not code. R13 is downgraded from "landed" to "mechanism landed, no
  observation pipeline": nothing constructs its ledger, so it can never downgrade
  anything.

### Fixed along the way

- **The validator cache had never persisted a single entry.** `safeWriteState`
  refused every directory nested under `.agentic-security/`, so `llm-cache/`,
  `fix-history/` and `sbom-history/` were all unwritable while a
  `validator-cache stats|gc` subcommand managed a cache that was always empty.
  Found by a positive-control test asserting a legitimately written entry
  round-trips.

- **Sandbox timeouts now use SIGKILL.** The kernel does not deliver
  default-action signals to a PID namespace's pid 1 from outside it, so SIGTERM
  was dropped and a payload ran to completion against a 1200 ms budget — measured
  in CI at 30057 ms. Proof execution also gained its own aggregate wall-clock
  budget, because a count cap bounds nothing in time.

- **Cost reporting stopped presenting an estimate as spend.** The endpoint's
  usage report was discarded, so the ledger always booked the pre-call worst
  case. Usage is now plumbed through, and any estimated component renders as
  "at most $X" with the reason.

## 0.132.0 — a proven exploit becomes a permanent regression test

The corpus stops being only a regression net and starts being fed by the engine
itself. Every claim below was verified by a command in the session that made it.

- **Execution-proven findings auto-enrol as corpus entries.** This was R2's
  differentiator and the last missing piece of it. A finding whose
  proof-of-concept RAN in the sandbox and produced the predicted effect can now
  be turned into a permanent `pre:TP post:TN` corpus entry, so every exploit
  proved once is defended against its own regression forever. Demonstrated end
  to end rather than in a unit test: a real command-injection finding was proved
  in the sandbox, its fix supplied the `post/` tree, and the entry was enrolled
  and scored by the real gate — **the baseline moved 199 → 200**. Proven in the
  other direction too: with the entry's `pre/` neutered the gate reports
  `REGRESSED (1)` and exits non-zero.
- **Nothing reaches the corpus unscored.** The entry is built in a temporary
  directory, `pre/` and `post/` are scanned, and it is moved into the corpus
  only on `pre:TP post:TN`. There is no force flag, and the scoring function is
  unexported so no caller can score by one route and write by another — the
  v0.106.0 mistake (fixtures committed without verifying they score) is the one
  thing an automated writer must never industrialise. Scoring itself now lives
  in one module shared by the enroller and the corpus runner, so the two cannot
  drift apart; the refactor was proven behaviour-preserving at 199/199, no drift.
  New entries land in `capability/`, never the CI-gated `regression/` tier — a
  machine must not decide what blocks everyone's build.
- **`verify_fix` now runs the proof-of-concept against the candidate patch.** A
  re-scan only proves the DETECTOR stopped firing, which a cosmetic edit
  achieves; re-running the exploit proves the hole is shut. Still-exploitable
  after the patch is a hard failure. Deliberately asymmetric: a PoC that could
  not run is recorded `inconclusive` and excluded from the verdict, because
  reading "could not prove it" as "fixed" is exactly the false confidence this
  leg exists to prevent. Both directions were executed against the real sandbox.
- **Time-to-validated-fix is now measured and reported**, closing R5. Every
  verification stage is timed and appended to a per-project log, and the
  reported distribution is deliberately hard to flatter: failed attempts never
  enter the validated median (they short-circuit, so blending them makes a worse
  pipeline look faster), "no test suite to run" is bucketed apart from "tests
  passed", and per-stage timings come from validated runs only. Percentiles are
  nearest-rank — every figure shown is a duration some run actually took — and
  are flagged unreliable below n=10 rather than quoted as settled.
- **Cross-machine determinism now has a gate behind it.** A dependency-free
  fixture is scanned on two operating systems and the run-attestation digests
  must match. The comparator refuses every route to a meaningless pass: fewer
  than two attestations, two runs from the same platform, a zero-finding digest,
  mismatched canonicalisations, unparseable input. Each refusal was fired
  deliberately and confirmed to exit non-zero.

Honest limits, stated rather than implied:

- The enrolment loop is **not yet automatic end to end**. Nothing in the scan
  pipeline attaches a proof-of-concept to a finding or promotes proof tiers, so
  a scan never produces an `execution-proven` finding on its own; PoCs come from
  the generator and are proved at enrol time. Automatic attachment during a scan
  is the remaining work.
- The cross-machine determinism jobs have **not yet run in CI**, so no second
  machine has actually been compared. Same-machine repeatability is verified.
  The attestation's own "does not prove" statement is unchanged and stays
  correct either way: one attestation is one run on one machine.
- The sandbox wall-clock timeout stops the **direct child, not the process
  tree**, on both backends. No test asserts a backgrounded grandchild dies.

Also in this release:

- **Documentation corrected against evidence.** The roadmap and the sandbox and
  posture guides still described the kernel-namespace backend as "implemented,
  unverified" after CI had already proved otherwise; they now cite the run
  (Ubuntu 24.04, kernel 6.17.0-1020-azure, 41 assertions, 0 failures, all eight
  escape cases). The corpus entry count was three tiers and 14 entries out of
  date.
- **Dependency advisories cleared** in the extension tree and `@types/node`
  brought current in both trees.

## 0.131.0 — decorated files stop vanishing; the Linux sandbox is verified

Two correctness fixes, both found by pushing measurement further than the last
release did.

- **Decorator syntax is now accepted by the IR frontend.** The parser was told
  about TypeScript and JSX but not decorators, so it rejected the ENTIRE file on
  the first `@tracked` it met — no error, no warning, just findings that never
  existed. Measured on a live third-party target: **4,023 of 4,271 JavaScript
  files parsed before, 4,262 after** — 239 files, roughly 6% of that project,
  were invisible to the scanner and are now analysed. `decorators-legacy` plus
  `decoratorAutoAccessors` was chosen over the modern `decorators` variant
  because the modern one cannot parse TypeScript parameter decorators; it would
  have swapped one blind spot for another. No new dependency. Guarded by a
  regression test proven in both directions — 5/5 pass with the fix, 4 fail
  without it.
- **The kernel-namespace sandbox now confines writes, and is verified.** It
  previously confined network only and had never been executed. It now enters a
  private mount namespace, rebinds every mount read-only except the sandbox
  root, and drops the entire capability set before exec so a payload cannot
  rebind the tree writable. A CI job relaxes the host restriction on
  unprivileged user namespaces and runs the real escape suite: a write outside
  the root is blocked with no file created, and outbound egress is blocked. The
  verifier exits non-zero unless that suite actually RAN, so a skip can never be
  read as a pass. Execution-proof on Linux no longer rests on an unexercised
  backend.

Also in this release:

- **A quadratic blowup in the root-cause sweep**, which ran on every full scan:
  it re-split the whole corpus into lines once per finding and kept a record per
  finding x matching line. The largest benchmark corpus went from dying after
  55+ minutes to **exit 0, 933 MB peak, 330s** — smaller and roughly ten times
  faster, with metrics identical before and after.
- **Benchmark corpora are fetched by pinned commit** instead of guessing a clone
  depth; six corpora had never been scoreable because their pin sat more than
  100 commits back.
- **A pre-push gate** runs bundle integrity, the full suite, the corpus baseline
  and the precision baseline before anything leaves the machine, plus branch
  protection requiring green checks to merge.
- **A dependency-currency release gate**: any advisory at moderate or above
  fails with no opt-out; anything behind latest fails unless explicitly held
  with a stated reason and a review date that expires.
- **The glob dependency was replaced by the platform built-in** — 92 to 73
  production packages — after a differential over 320 trees and 1,419,229 paths
  showed zero differences.

`npm test` 2072/0; cve-replay 199/199; self-scan no drift; proof corpus
ghost/superset/godot all 100% parse coverage.

## 0.130.0 — the roadmap's first ten: provable security over orchestration parity

A capability roadmap (`docs/ROADMAP.md`) plus its first ten items, derived from a
survey of the current agentic security-review field. The strategic call: that
field cannot state a false-positive rate or prove it did not regress, because its
core is a model call. This project's core is a deterministic engine behind three
gates, so the work doubles down on provable, measurable, reproducible.

- **Execution sandbox** (`src/sandbox/`) — fail-closed confined execution. Verified
  by execution: writes outside the sandbox root blocked, network blocked, wall-clock
  overrun terminated, benign work still succeeds. With no confinement primitive
  available, execution is REFUSED, never run unconfined.
- **Execution-verified findings** (`posture/execution-proof.js`) — a finding can be
  promoted to `execution-proven` by running its proof-of-concept in the sandbox.
  Proof is a marker file, never an exit code, because the sandbox cannot reliably
  distinguish a denied run from a clean exit. `proof-failed` is a triage signal,
  NOT a false-positive verdict.
- **Published accuracy scorecard** (`npm run scorecard`) — detection and correct-
  silence rates sliced by language and CWE, every figure with its denominator,
  regeneration-stable. F1 deliberately omitted: no labelled real-world population
  exists to measure precision over, and the document says so.
- **Determinism attestation** (`posture/attestation.js`) — an order-independent
  signed digest. Cross-machine reproducibility is explicitly NOT claimed.
- **Fixes must pass your tests** (`posture/test-runner.js`) — `verifyFix` previously
  proved only that the finding disappeared, which deleting the feature also
  achieves. It now runs the project's own suite, and says so when the suite ran
  against unpatched code.
- **Relevance ranking** (`posture/relevance.js`) — re-ranks by entry-point
  reachability. Recall-preserving: nothing deleted, severity never touched,
  `unreachable` only on positive evidence.
- **Enforced verification separation** (`posture/verification-separation.js`) — a
  verifier cannot rubber-stamp its own finding.
- **Resumable scans** (`posture/scan-checkpoint.js`) — opt-in via
  `AGENTIC_SECURITY_RESUME=1`, crash-safe, conservatively invalidated.
- **Secret redaction** (`llm-validator/redact.js`) — credentials removed before any
  code leaves the machine; ordinary code passes through byte-unchanged.

Also: dependencies updated to latest (Babel 7→8 with the removed preset options
migrated, js-yaml 4→5 with an empty-input shim). One dependency deliberately held
back: bumping the grammar runtime silently drops all six long-tail language
grammars, so it stays pinned and the reason is documented.

`npm test` 1989/0; cve-replay 199/199; self-scan no drift.

## 0.129.0 — closing two taint-engine recall gaps

Two defects were found by execution on the merged tree, each silencing real findings across
every supported language. Both are now fixed, measured, and gated.

- **Sinks are matched on assignment right-hand sides** (`dataflow/engine.js`). The engine only
  ever sink-matched in statement position, so `db.query(tainted)` was reported while
  `const rows = db.query(tainted)` was silent — in every language. The sink-matching logic is
  now extracted into shared helpers called from both `case 'call'` and `case 'assign'` rather
  than duplicated, and the pre-existing statement-position path is unchanged (measured control:
  `1/1` before and after; assignment position `0/0 -> 1/1`).
- **`match.type:'global'` catalog entries are indexed and reachable** (`dataflow/catalog.js`).
  All 10 global entries were unreachable from `matchSource()` — including `$_GET`/`$_POST`/
  `$_REQUEST`, the canonical PHP taint sources, in a language that already had interprocedural
  analysis. A new `GLOBAL_INDEX`, plus lookup-side sigil normalization (`_globalKey()`) so PHP's
  `$` prefix matches sigil-free catalog keys, takes catalog reachability `0/10 -> 10/10` with
  language scoping preserved.
- **Seven self-scan false positives eliminated at source.** Raising sink recall exposed
  pre-existing catalog imprecision: `py-yaml-load`/`py-pickle-load` matched bare callee `load`
  with no receiver constraint, so ordinary `json.load(fh)` was flagged as unsafe deserialization.
  Each finding was inspected individually and all seven were false positives; the entries are now
  pinned to their receiver. **Nothing was baselined** — `bench/self-scan/BASELINE.json` is
  unchanged and the gate is green on the source fix.
- **New**: `bench/engine-recall` before/after harness (`npm run bench:engine-recall`) and
  `bench/engine-recall/RESULTS.md`, the full measurement record including what the fixes cost.
- **Corpus 197 -> 199**: two deep-tier entries, each verified missed-before / found-after against
  its specific fix.

Known trade, recorded rather than papered over: pinning the receiver drops `import yaml as y;
y.load(f)` and `from yaml import load; load(x)`, which are now covered at no layer. A corpus guard
was attempted and deliberately withheld because it would score `pre:TN`; closing it needs
import-alias resolution in the Python IR. Separately, `10/10` is catalog reachability, not
end-to-end recall — only PHP is proven end to end; Ruby's deep engine does not complete those
flows (pre-existing). Both are documented in `RESULTS.md` §3 and §8.

`npm test` 1854/0; cve-replay 199/199; self-scan no drift.

## 0.128.2 — compliance attestation accuracy + quieter self-scans

Two fixes surfaced while dogfooding the compliance flow on this repo:

- **Fixed a compliance-attestation path bug** (`posture/auditor-walkthrough.js`). Three
  evidence checks (`mcp-tools`, `security-fixer`, `pre-edit-bodyguard`) carried a literal
  `.../` placeholder path that `path.join(scanRoot, STATE, '.../x')` could never resolve, so
  they read **"not present" for every project** — falsely dragging OWASP LLM08/LLM09 (and any
  framework mapping to those modules) to "manual/not-present". A `.../` sentinel now resolves
  against the scan root itself. On a self-attestation this flips LLM09 → satisfied and makes
  LLM08 honestly partial.
- **Repo `ignorePaths` for meaningful self-scans** (`.agentic-security/rules.yml`). Added
  `bench/**` and `scanner/test/fixtures/**` so a repo-root `/scan` no longer counts the ~600
  intentionally-vulnerable benchmark corpora and test fixtures as findings. Safe: `rules.yml`
  is loaded from the exact scan root only, so the cve-replay runner (which scans each
  pre/post fixture as its own root) and the unit tests are unaffected — corpus gate stays
  185/185.

`npm test` 1695/0; cve-replay 185/185.

## 0.128.1 — patch dependency vulnerabilities (11 Dependabot alerts → 0)

Security maintenance. Cleared all 11 open Dependabot alerts by updating the two lockfiles to
patched versions (all within-major bumps, no breakage):

- **`scanner/`** — `js-yaml` 4.1 → 4.3.0 (GHSA-h67p-54hq-rp68, quadratic-complexity DoS via merge
  keys). `js-yaml` is inlined into the shipped bundle, so `dist/agentic-security.mjs` was rebuilt;
  full gate re-run green (`npm test` 1695/0, cve-replay 185/185).
- **`ide/vscode/`** — `undici` → 7.28.0 (incl. one high), `form-data` → 4.0.6 (high),
  `markdown-it` → 14.3.0, `esbuild` → 0.28.1, `js-yaml` → 4.3.0. All transitive under
  `@vscode/vsce`/`esbuild`; lockfile-only, `npm audit` now reports 0.

`npm audit` is clean (0 vulnerabilities) in both packages.

## 0.128.0 — the agentic methodology layer + a simpler command surface

Two things landed together this release: a set of default-on **methodology annotators** that
layer agentic-hunter discipline on top of the deterministic engine, and a **consolidation** of
the command and skill surface so there's less to remember.

**Methodology layer (7 additions, all v1, all tested — see `docs/AGENTIC_METHODOLOGY_PRD.md`):**

- **Default falsification pass** (`posture/falsification.js`) — for each taint finding it tries
  to *disprove* the finding by locating a context-matched control on the path, and demotes +
  quarantines the ones it can block. Recall-preserving (never removes a finding, never touches
  severity — like the proof gate); genuine cve-replay `pre` vulns still fire (0 false blocks,
  corpus 185/185 intact). Opt out with `AGENTIC_SECURITY_NO_FALSIFICATION=1`.
- **Attack-surface completeness inventory** (`posture/entrypoint-inventory.js`) — enumerates
  every entry point (HTTP / queue / cron / CLI / env / upload / webhook) with a disposition
  each, on `scan.entrypointInventory`.
- **Root-cause sweep** (`posture/root-cause-sweep.js`) — from a confirmed finding, searches the
  repo for sibling instances detectors missed, with a `found = candidates + mitigated`
  accounting invariant, on `scan.rootCauseSweep`.
- **Meta-security hardening** (`util/untrusted.js` + `docs/AGENT_THREAT_MODEL.md`) — a tested
  threat model treating attacker-authored finding text as untrusted input; escaping wired into
  the PR/issue/ticket render paths.
- **Capability-based model routing** (`posture/model-routing.js`) — stamps `finding.dispatchModel`
  (strongest for crypto/auth/critical, mid for injection, cheapest for low-sev hardening) for
  cost-sensitive subagent dispatch.
- **Self-improving recall harness** (`bench/realworld-recall/`) — LLM-judged (offline-degrading)
  recall on real repos + a miss-analyzer that names the pipeline stage that dropped a finding
  and proposes the fix. Bench-only; never in the product scan path.
- **Deterministic fix-honesty gates** (`posture/fix-honesty-gate.js`) — a residual-risk
  hand-wave guard, a cited-file:line requirement for FP/safe verdicts, and FULL/MITIGATION/
  WORKAROUND completeness tiers; the previously-orphaned test loop is now wired into
  `apply_fix` behind `AGENTIC_SECURITY_FIX_RUN_TESTS=1`.

**Simpler surface (no functionality removed — everything folds to a mode + alias):**

- Commands **12 → 10**: `/ci` folded into `/setup --ci` (+ new `/setup --predeploy`), and
  `/three-agent-review` into `/triage --deep`. Old names still resolve via the
  legacy-alias-redirect hook.
- Skills **11 → 7**: the four write-time guards merged into `secure-coding-guard`, and the two
  explainers into `security-explain`.

**Docs:** README + ARCHITECTURE + HARNESS_COMPATIBILITY refreshed with accurate surface counts
(17 MCP tools, 10 commands, 7 skills, 5 hook events, 9 sub-agents); the SAST/SCA improvement PRD
audited and marked (16 of 25 shipped, 9 partial). Full `npm test` green (1695 tests); cve-replay
corpus 185/185, no drift.

## 0.127.0 — cost advisor: an actual choice, not just a tip

The model-cost advisor (`hooks/model-cost-advisor.js`) has always been advisory
only — a `systemMessage` tip you read and act on yourself, by design, because a
`UserPromptSubmit` hook cannot pause for interactive input or change the model/
effort (verified against the current Claude Code hooks reference before writing
any of this, not assumed from the hook's own pre-existing comments). This
release adds a real choice on top of that hard limit, without giving up the
zero-token guarantee for anyone who doesn't opt in.

- **New opt-in `"interactive": true`** (`.agentic-security/model-optimizer.json`,
  default `false`). On a qualifying prompt, the hook now additionally emits
  `hookSpecificOutput.additionalContext` — billed as input tokens, unlike the
  free `systemMessage` — directing Claude to call `AskUserQuestion` with three
  options: keep current defaults; get the exact `/model`/`/effort` command to
  run yourself (Claude cannot switch its own running model — no exception
  exists); or apply the cheaper model/effort to Claude's own delegated
  Task/Agent-tool sub-agent dispatches for the rest of the session — the one
  axis Claude can genuinely act on directly. Every other install keeps today's
  zero-token behavior unchanged; only projects that explicitly opt in pay for
  the interactive path, and only on prompts that already qualify for a tip.
- The chosen sub-agent override is **sticky for the session** — persisted to
  `.agentic-security/model-optimizer-state.json` (extending the existing state
  file rather than adding a new one) and cleared at the next `SessionStart`,
  which already does a bare overwrite of that file. A cooldown
  (`interactiveCooldownTurns`, default 3) stops the directive from re-firing
  its token cost if Claude doesn't act on it (e.g. a non-interactive/scripted
  invocation).
- Fixed a real bug the new shape would otherwise have hit: `dispatch-user-
  prompt.js`'s `mergeOutputs` previously let the legacy-alias-redirect's
  `additionalContext` and the advisor's new `additionalContext` clobber each
  other if both fired on the same prompt (independent triggers, so this can
  genuinely co-occur) — now joined instead of last-write-wins.
- `commands/setup.md`'s `--model-optimizer` gained a matching `--interactive`
  flag; `CLAUDE.md` documents the durable instruction for applying a saved
  sub-agent override on future dispatches, respecting existing static
  `model:` frontmatter pins (`security-triager.md`, `sca-triager.md`) and the
  "task needs more capability" carve-out.

Also added `SECURITY.md` (vulnerability disclosure policy).

## 0.126.0 — closing the find→fix loop: verified auto-fix, CWE-434/306, Fable 5 pricing

The largest remediation-side release to date. Prior to this, findings could be
*found* at scale but not *fixed* at scale — of the 677 findings on this repo's own
scan, zero could be mechanically applied. This release closes that loop end to end
while adding the detection classes and workflow polish the closed loop needed.
Full detail and rationale: `docs/FIND_AND_FIX_LOOP_PRD.md` (implemented; the file
itself is removed post-implementation per its own instructions).

**Remediation — a verified patch path for every finding, not just the ones with a
stored replacement.**
- `apply_fix` (MCP) now accepts a caller-supplied `patch` (a files map) and
  **re-verifies it inline** — rescan-clean, no new ≥medium finding, lint-clean —
  before writing. Previously `apply_fix` refused any finding without a stored
  `fix.replacement`; now a template-only or description-only finding (the vast
  majority) can be fixed, because the bytes are proven safe at write time instead
  of trusted at synthesis time.
- **Deterministic zero-LLM patch synthesis** (`posture/deterministic-fix.js`) for
  safe, context-independent classes — weak hash (md5/sha1→sha256), TLS
  verify-off→on — materialized on demand by `synthesize_fix` and still gated by
  the same inline verifier before `apply_fix` writes it.
- Regression tests are wired into the fix loop: `synthesize_fix` surfaces the
  scan's existing PoC-derived `regression_test` so a fix ships with a test that
  fails pre-fix and passes post-fix.
- `/fix --all` and `/find-and-fix-everything` now run independent findings in
  **parallel** (serializing only same-file findings), never halt on the first
  test failure, and publish the running **auto-fix acceptance rate**.
- `/fix --sca` surfaces its **upgrade break-rate** (build/test-verified upgrades
  are the default; the break-rate is how often an "available" upgrade actually
  wasn't safe to take).
- MTTR / SLA tracking is now live: every scan stamps `firstSeenAt`/`ageDays` and
  surfaces an SLA-breach summary (`critical` 7d / `high` 30d / …).
- The Layer-3 LLM validator gained a first-class Anthropic preset
  (`AGENTIC_SECURITY_LLM_PRESET=anthropic`) — previously BYO-endpoint only, so the
  FP-suppression layer was reachable with just a key instead of a hand-built
  endpoint.

**Detection.**
- New **CWE-434 unrestricted file-upload detector** (JS/Python) — a whole CWE
  class that had zero coverage: unguarded Multer configs and writes that use the
  client-supplied filename as the destination.
- New **CWE-306 missing-authentication** rule: an unauthenticated destructive
  route (DELETE, or id-taking PUT/PATCH) fires only when the app authenticates
  elsewhere in the codebase — so auth-detection is proven to work before the rule
  trusts a "no auth found" signal, keeping it high-precision even on all-public
  files.
- Corrected stale documentation in `scanner/src/ir/CLAUDE.md`: the Python CST
  parser's `match`-case bodies, walrus bindings, destructuring, and comprehension
  filters were already fully lowered and taint-propagating — verified end-to-end
  with new flow tests, not just parser-shape tests.
- The independent-eval gate (`bench/independent-eval/`) is now **active**
  (`aggregateF1`/`perFamilyRecall` floors instead of `null`) — proven to fail on a
  deliberate regression and pass at the current corpus result.

**Hooks & cost.**
- Pricing tables across all five rate-table copies now include **Fable 5
  ($10/$50 per MTok)** and Sonnet 5 — previously a Fable 5 session wasn't even
  priced by the cache-economics reporter, and the cost advisor couldn't reason
  about the flagship model at all.
- Two mechanical subagents (`security-triager`, `sca-triager`) pinned to Haiku.
- The two `UserPromptSubmit` hooks and three `PreToolUse` (Edit) hooks were each
  consolidated into a single dispatcher process — halving/thirding the per-turn
  node spawns. The security-critical bodyguard block is proven to survive
  consolidation (a dedicated regression test asserts the exit-2 deny still
  fires first and short-circuits the advisory hooks).
- The post-edit hook now offers a one-tap auto-fix inline when a fresh finding is
  mechanically fixable, instead of only pointing at `/fix-all`.
- The model-cost optimizer now ships **on by default** (`mode: "advise"`) with a
  predicted-vs-realized savings ledger.

**Workflow.**
- `scan --watch` wires the existing (previously unwired) watch-mode daemon:
  continuous incremental re-scan on file change with a risk-delta status line.
- Opt-in, offline-degrading **live-secret validation**
  (`--validate-secrets`) — labels a detected secret `live`/`dead`/`unknown` via a
  read-only provider "whoami" check (GitHub, Stripe, OpenAI, SendGrid), so "this
  key is LIVE" is distinguished from "you have a high-entropy string."
  `--secret-history` (git-history sweep) was already wired; this release adds
  the liveness half.
- Diff-scoped scans (`--pr` / `--changed-since`) now default `--incremental` on,
  since a changed-file set is exactly the incremental cache's designed case.

## 0.125.0 — multi-provider LLM cost + prompt-cache linter (Cache Economics v2, phase 1)

First slice of the Cache Economics v2 PRD (`docs/CACHE_ECONOMICS_V2_PRD.md`) — the
foundation (P1 provider detection, P2 provider catalog) + the flagship analyzer (F1
cache-hygiene + P3 per-provider model/depth recommendation). The optimizer now reaches
beyond this Claude Code session into the user's **own AI-app code**, across providers.

- **Provider catalog** (`scanner/src/posture/provider-catalog.js`): a dated, no-network
  snapshot of Anthropic / OpenAI / Google Gemini / xAI — model ladder ($/1M rates), the
  "depth" knob (effort / reasoning_effort / thinkingBudget), and the cache model
  (explicit vs automatic vs implicit). Prices are sourced, not hardcoded-in-logic, with a
  `SOURCED_AT` staleness date.
- **LLM cost/cache detector** (`scanner/src/sast/llm-cost-advisor.js`, `scanLlmCost`):
  provider-aware, gated on detecting an LLM SDK (low FP), emits **advisory** findings —
  (1) *prompt-cache killer*: a timestamp/UUID/random value baked into a prompt prefix
  that defeats caching; (2) *over-provisioned*: a flagship model at high depth, with the
  catalog's cheaper model + lower depth **in that provider's framework** as the fix
  (e.g. an OpenAI app → "gpt-5.4 at reasoning_effort=low"). Severity `low`/`info` so it
  never inflates security counts.

Remaining PRD phases (F2 measured cost, F3 TTL, F4 compaction, F5 pre-warm, F6 cross-
session warmth, F7 self-tuning; full P4 per-provider economics) ship next.

## 0.124.1 — fix: narration no longer prints a broken location

Now that v0.124.0 surfaces `narration` prominently inline, a pre-existing template
bug became visible: some narrations read `app.js:?` / `app.js:undefined` because the
location was interpolated before the finding's line was finalised.

- `scanner/src/posture/flow-narration.js`: the location is redundant (the finding
  header already shows `file:line`), so the family templates are now
  location-agnostic, and `_routeOf()` (generic fallback + LLM prompt) falls back to
  the file alone — or "this endpoint" — instead of emitting `:undefined` / `:?`.
- Regression test in `test/flow-narration.test.js` asserts no template renders a
  broken location when the line is absent.

## 0.124.0 — inline finding depth (no second command for "why it fired")

The depth `/triage --explain` produces now renders **inline** in the finding views,
assembled from fields already on the finding (`narration` + `whyFired` + fix) — so the
default per-finding view answers "why does this matter / how does it fire / how do I
fix it" without a separate command. Addresses the "only ~2 sentences per finding"
feedback. Presentation only — no detector/severity changes.

- **Inline explain block** (`scanner/src/report/index.js`): every per-finding surface
  now shows `why:` (the impact narration), `how:` (the `whyFired` detector + source→sink
  flow, with sanitizers/guards/reachability under `--verbose`), and `fix:`. Wired into
  the firehose list (`toCLI`), the pro table (a compact one-line "why"), and the HTML
  report ("Why it matters" / "How it fires" blocks). Default trims the narration to two
  sentences; `--verbose` shows the full narrative + fix code. Degrades gracefully when a
  finding lacks the fields (e.g. SCA).
- **`--firehose` actually lists findings now.** Previously it only lowered the
  confidence threshold while the vibecoder verdict showed no per-finding list; it now
  appends the full per-finding list (with the inline depth) so "Show ALL findings" does.

## 0.123.0 — report clarity: risk-demotion labels, depth discoverability, HTML export docs

Acting on user feedback that findings could overstate severity, that explanations
felt thin, and that the browser report was hard to find. No detector/severity logic
changed — these are presentation + docs improvements in `scanner/src/report/`.

- **"Likely lower risk" labels.** A high/critical finding the reachability /
  exploitability / confidence pipeline has already marked down now renders a visible
  `↓ likely lower risk — …` note (not reachable in prod / sanitized / low
  exploitability / low confidence) in the CLI firehose, the pro table, and the HTML
  report. Severity stays canonical (SARIF/exit codes/baselines unchanged) — this only
  annotates, so a hardcoded rule severity isn't taken at face value.
- **Depth is discoverable.** The one-screen ship verdict now points to
  `/triage --explain <id>` (the why-it-fired narrative + data-flow trace + fix) and to
  the shareable HTML report, so users don't conclude the terse default is all there is.
- **HTML report surfaced in the README.** Documents `scan . --format html --output
  report.html` (self-contained browser page: severity charts, STRIDE, filterable
  findings) alongside json / md / sarif / csv.

## 0.122.0 — cache economics Phase B (depth-first, subagent offload, cost HUD)

Completes the cache-economics program (PRD `docs/CACHE_ECONOMICS_PRD.md`, F4–F6) on
top of the v0.121.0 measured foundation. All in `hooks/model-cost-advisor.js`,
`hooks/lib/transcript.js`, and `scanner/src/posture/cache-economics.js`.

- **F4 — depth-first routing.** A model switch is now chosen over a cache-safe effort
  drop only when it saves *materially* more (`A.savings ≥ B.savings × (1 +
  depthFirstMargin)`, default 0.25). Effort is the primary lever; switching is the
  break-even-gated exception.
- **F5 — subagent offload.** For a simple one-off whose cheap-model switch is
  cache-blocked (deep warm cache), the advisor suggests running it as a **Haiku
  subagent** — full cheap-model savings without discarding the main session's cache.
  Config `subagentAdvice` (default true).
- **F6 — cost HUD + cache budget.** `cache-statusline` CLI prints a one-line HUD
  (`$ spent · % cached · $/turn`) for a Claude Code `statusLine` command and writes
  `.agentic-security/cache-telemetry.json`; the `query_cache_telemetry` MCP tool gains
  a `statusline` field. A soft `sessionBudgetUsd` biases the `costQualityTradeoff`
  dial toward cheaper as real session spend (priced from the transcript) approaches it.

## 0.121.0 — prompt-cache economics (measured, cache-aware cost optimization)

Cache-economics core (PRD `docs/CACHE_ECONOMICS_PRD.md`, features F1–F3). Turns
Claude Code's own transcript usage into a dollarized, cache-aware view of token
cost. No network, advisory-only.

- **F1 — cache telemetry + report.** New `scanner/src/posture/cache-economics.js`
  parses per-turn `usage` (cache read/write at 0.1× / 1.25×–2× input) and reports
  cache-hit %, $ saved by caching, $ wasted on avoidable misses, $/turn, and a
  per-model breakdown. Surfaced as the `cache-report` CLI subcommand (documented as
  `/posture --cache`) and the read-only `query_cache_telemetry` MCP tool.
- **F2 — silent-invalidator detector ("cache bodyguard").** Retrospectively
  attributes cache drops to model-switch / TTL-gap / prefix-change (shown in the
  report), plus a live PreToolUse hook (`hooks/cache-invalidator-guard.js`) that warns
  before an edit to a cache anchor (`CLAUDE.md`, `.claude/settings*.json`) with the
  estimated re-warm cost. Throttled; `AGENTIC_SECURITY_QUIET` / `…_CACHE_GUARD=off`.
- **F3 — break-even + TTL-aware switching.** `hooks/model-cost-advisor.js` now reads
  the *real* cached size from the transcript (`hooks/lib/transcript.js`), shows a
  model switch's break-even ("worth it past ~N more turns"), suppresses switches that
  won't pay off (preferring a cache-safe effort drop), and treats a cache gone cold
  past the TTL as free to switch. New config: `ttlSeconds`, `breakEvenMaxTurns`.

Also lands the OpenRouter-derived advisor controls that F3 builds on: a
**`costQualityTradeoff` 0–10 dial** (replaces the one-sided `minSavingsUsd` gate;
0 = never downgrade, 10 = cheapest) and the initial per-prompt **cache-rewarm
penalty** that prefers a cache-preserving effort drop over a model switch.

F4–F6 (depth-first formalization, subagent-offload advice, cost HUD/statusline) are
specced in the PRD and ship next.

## 0.120.0 — model-cost optimizer (per-prompt model + depth advisor)

New opt-in Claude Code plugin feature; no functional change to the scanner.

- `hooks/model-cost-advisor.js` (UserPromptSubmit): scores each prompt with a
  zero-token local heuristic (length, code fences, file mentions, stack traces,
  cheap vs. expensive verbs) and, when a strictly cheaper model + reasoning depth
  would likely do the job, prints a one-line tip with the estimated token-cost
  savings. Advisory only — Claude Code hooks cannot set the model or effort, so
  the user taps `/model` + `/effort`. The tip is delivered via `systemMessage`
  (out-of-band), never `additionalContext`, so the advisor itself costs no tokens.
- `hooks/session-start-model-capture.js` (SessionStart): records the session
  model to `.agentic-security/model-optimizer-state.json` — the only channel for
  it, since there is no `$CLAUDE_MODEL` — and the advisor falls back to a
  configurable `assumedModel` when it is absent.
- Config `.agentic-security/model-optimizer.json` (`{ mode, minSavingsUsd,
  assumedModel }`), default **off**; kill switch
  `AGENTIC_SECURITY_MODEL_OPTIMIZER=off`.
- `/setup --model-optimizer [--min-savings <usd>]` enables it (config write only;
  the hooks are already registered in `hooks/hooks.json`).
- Docs: `docs/MODEL_COST_OPTIMIZATION_PRD.md` (spec, R1–R11) and
  `docs/MODEL_COST_OPTIMIZATION.md` (user guide). Tests:
  `hooks/model-cost-advisor.test.js` (10 cases).

## 0.119.2 — plugin manifest validation fixes

Manifest/packaging hotfix; no functional change to the scanner.

- `commands/fix.md`: quoted the `description:` frontmatter value. The unquoted
  colon-space (`Remediate findings: --one …`) parsed as a nested YAML mapping,
  which `claude plugin validate` rejected — and would have caused the command to
  load with all frontmatter fields silently dropped at runtime.
- `.claude-plugin/plugin.json`: dropped the unknown `vendor` field (Claude Code
  ignores it at load time; the company already lives in `author`).
- Removed stray gitignored `.agentic-security/` runtime artifacts (regenerated
  DPIA/threat-model output) from under `agents/` and `commands/`, where the
  validator was mis-reading them as plugin agents/commands.

`claude plugin validate` now passes; the two remaining warnings
(`agents/_CONFINEMENT.md` and the root `CLAUDE.md`) are by-design per the
underscore-doc convention enforced in `plugin-self-check.test.js`.

## 0.119.1 — packaging: exclude internal scan-state from the npm tarball

Packaging-only hotfix for the `@clear-capabilities/agentic-security-scanner` npm
package; no functional change to the scanner or the plugin.

- The published tarball had ballooned to 23.5 MB / 565 files because the `files`
  allowlist pulled in `src/**/.agentic-security/` and `bin/.agentic-security/` —
  the dogfooded self-scan state (findings.json, last-scan.json, scan-history,
  threat-model). `npm pack` runs from `scanner/` and does not consult the
  repo-root `.gitignore`, and a root `.npmignore` is ignored when a `files` field
  is present, so the carve-out is done with negation entries in `files`
  (`!**/.agentic-security`, `!**/.agentic-security/**`). The tarball is now
  7.9 MB / 393 files with no scan-state.

## 0.119.0 — SAST/SCA capability program (PRD R1–R25, ex-R14)

Implements the `docs/SAST_SCA_IMPROVEMENT_PRD.md` backlog — 24 of 25
recommendations (DAST-lite/R14 intentionally out). Every change shipped with a
fixture + test and the corpus gate held at 185/185.

**Core engine**
- **R1**: deep interprocedural taint (IR + field-/value-context-sensitive) is now
  ON by default for local/interactive CLI scans, budgeted, CI-off-by-default
  (`--no-deep` / `AGENTIC_SECURITY_DEEP=0` opt-out).
- **R23**: fixed the incremental cache cold-start no-op (it never persisted a
  baseline), with an end-to-end regression test.
- **R4**: collection-element taint (`arr.push(tainted); sink(arr[i])`) on by
  default; implicit/control-dependence flow wired in opt-in
  (`AGENTIC_SECURITY_IMPLICIT_FLOW=1`).
- **R2**: bounded k=1 call-string context sensitivity, opt-in
  (`AGENTIC_SECURITY_KCFA_CALLSTRING=1`); default-off keys are byte-identical.
- **R3**: deep-flow parity extended to **Go + Kotlin** — call-shaped sources
  (`r.FormValue()`), string callees (`db.Query`), Go string-concat lowering,
  Go `database/sql` sinks. (PHP/Ruby/C# parser concat-lowering remains.)
- **R17**: per-finding corroboration ("one issue, many signals") + rank tiebreak.
- **R13**: "provably safe" is a first-class verdict (`--hide-proven-safe`).
- **R5**: context-aware sanitizer adequacy (HTML-escape before a shell/SQL sink).
- **R6**: non-HTTP entrypoint taint (queue consumers / scheduled tasks / serverless).

**SCA / supply chain**
- **R7**: import-aware function-level reachability (JS/TS + Python) — resolves
  aliased/namespace imports, gated to files that import the package.
- **R12**: deterministic decision-first verdict per dependency
  (AUTO_MERGE_PATCH / WAIT_FOR_PATCH / MANUAL_REVIEW / ACCEPT_RISK / WONT_FIX).
- **R11**: OpenVEX export (`--format vex`) from reachability verdicts.
- **R9**: static malicious install-script analysis (download-exec / base64-exec /
  env-exfil lifecycle hooks).
- **R10**: Gradle transitive dependency graph.
- **R8**: container-image OS-package inventory (dpkg/apk).

**Detection surfaces, validation, workflow**
- **R20**: agent-loop taint (untrusted RAG/tool content → high-privilege tool).
- **R19**: route-level BOLA/BFLA over the API inventory.
- **R21**: RBAC role-tier authorization consistency.
- **R22**: cross-service dataflow (client-call → matched route edge inference).
- **R18**: semantic IaC (Terraform with variable resolution).
- **R16**: independent-eval harness (per-family precision/recall/F1 + gate).
- **R24**: PR-native net-new CI gate (`--fail-on-new`).
- **R15**: git-history secret sweep (`--secret-history`).
- **R25**: auto-fix acceptance-rate metric (surfaced in `apply_fix`).

Several latent bugs were found and fixed along the way (the dead `implicit-flow`
module, an `Object.assign`-taint path silently dying on a `const` binding, the
IR-TAINT conversion dropping the `implicit` flag). Each opt-in/partial item and
its remainder is tracked in the PRD rollup.

## 0.118.2 — Scanner F1 benchmark: restore F1 to 91.3% (3 FPs removed)

The "Scanner F1 benchmark" CI job (`test/benchmark/bench.js`, separate from the
cve-replay corpus) was failing. Root-caused three false positives and fixed all
three at the detector level (no baseline edit):

- **ReDoS double-flag** (introduced in v0.118.0): `scanRegexReDoS` (the
  multi-language NFA detector) ran on all languages including JS, double-flagging
  regexes already covered by `scanReDoS`. Restricted to the languages
  `scanReDoS` misses string-form regexes in (java/cs/kt/py/php); js/rb stay with
  `scanReDoS`.
- **rule-library-shape SQLi-in-string** (pre-existing): `js-framework-structural`
  matched a `db.query(\`…\`)` that was the *content* of a rule-definition string.
  Added a same-line string-literal guard.
- **secret double-count** (pre-existing): a split API key was reported twice —
  once by `secret-concat` (CWE-798) and once as a High-Entropy Credential
  Candidate. Drop the entropy candidate when a named secret detector already
  flagged the same `file:line`.
- **Measured: bench F1 90.3% → 91.3%, FP 20 → 17;** cve-replay corpus unchanged
  at 185/185 F1=1.000; full gate green.

## 0.118.1 — README: Language coverage section

Documents the 8 first-class languages (JS/TS, Python, Java, Kotlin, Go, Ruby,
PHP, C#) and the cross-language vuln-class coverage built out over v0.108–0.118
(SQLi, command/code/LDAP/XPath injection, XSS, SSRF, XXE, deserialization,
secrets, weak hashing/ciphers, static IV, CSRF, open redirect, response
splitting, ReDoS), measured by the blind, regression-gated 185-entry CVE-replay
corpus at F1=1.000. Docs + version only; no src/bundle/corpus change.

## 0.118.0 — Multi-CWE gap fill: 167→185 corpus, matrix to 152/160 cells

Closes the remaining detector-backed gaps across five CWEs in one batch, via
detector extensions (each verified pre:TP post:TN; no corpus regression).

- **`redos-nfa.js`** (CWE-1333): the multi-language NFA detector (was dormant)
  now wired in for Java/C#/Kotlin, plus PHP/Ruby string-form regex extractors.
  Go intentionally not scanned — its `regexp` package is RE2 (linear-time).
- **`weak-password-hash.js`** (CWE-916): added Ruby, C#, Kotlin, PHP MD5/SHA1
  forms. Password-context-gated; bcrypt/argon2 nearby suppresses.
- **`open-redirect.js`** (CWE-601): added Go, Ruby, C#, Kotlin sinks, with
  allow-list recognition and literal-target exemption.
- **`ruby.js`** (CWE-502): `Marshal.load`/`YAML.load` on a non-literal arg.
  **`go-structural.js`** (CWE-502): `encoding/gob` decode of untrusted bytes.
  **`php.js`** (CWE-918): cURL / fopen-wrapper fetch of a `$_GET`-controlled URL.
- **18 new corpus entries.** Not filled (intentional): CWE-1321 prototype
  pollution in 7 non-JS languages, and CWE-1333 in Go (RE2) — 8 cells empty by
  design. **Corpus 167 → 185; matrix 134 → 152/160 (95%).** F1=1.000; gate green.

## 0.117.0 — Cross-language XPath injection (CWE-643) + 7 corpus entries

Extends `xpath-injection.js` from Java/Python/JS to PHP, Go, Ruby, C#, Kotlin
(`DOMXPath`, `SelectNodes`/interp, Nokogiri `.xpath`, xmlpath/htmlquery,
`javax.xml.xpath`). All string-literal matching is embedded-quote-tolerant — an
expression like `"//user[@name='" + x` embeds the attribute delimiter quote
(also fixed a latent miss in the existing Java/Python patterns). Two issues
caught pre-commit (a Kotlin post:FP, a test-author `${u}` JS-interpolated before
the scanner). **Corpus 160 → 167; matrix 127 → 134/160.** F1=1.000; gate green.

## 0.116.0 — Cross-language CSRF detection (CWE-352) + 3 corpus entries

Extends `csrf.js` to Go (gin/echo/fiber/chi, net/http mux), Rails routes, and
ASP.NET MVC `[HttpPost]` action attrs. Defence recognition added (gorilla/csrf,
nosurf, `protect_from_forgery`, `[ValidateAntiForgeryToken]`/IAntiforgery).
Token-auth exemption: `[ApiController]` + explicit Bearer is CSRF-safe; bare
`[Authorize]` is not (cookie auth is the ASP.NET default). **Corpus 157 → 160;
matrix 124 → 127/160.** F1=1.000; gate green.

## 0.115.0 — Java reflected XSS (CWE-79): fills last XSS cell

Adds Java to `xss-reflected-multilang.js` — servlet `response.getWriter()`
write/print + `PrintWriter`, building an HTML string by concat. Static literals
and OWASP/Commons/ESAPI encoders excluded. The reflected-XSS row (CWE-79) is now
complete across all 8 languages. **Corpus 156 → 157; matrix 123 → 124/160.**
F1=1.000; gate green.

## 0.114.0 — Cross-language weak-cipher detection (CWE-327) + 3 corpus entries

Extends `crypto-protocol.js` weak-cipher detection to the Go (`crypto/des`,
`crypto/rc4`), PHP (`openssl_encrypt`/legacy `mcrypt_*` weak algos), and Ruby
(`OpenSSL::Cipher` DES/RC4/Blowfish) idioms. AES-GCM stays clean. **Corpus
153 → 156; matrix 120 → 123/160.** F1=1.000; gate green.

## 0.113.0 — Cross-language static-IV detection (CWE-329) + 7 corpus entries

Extends `crypto-protocol.js` static-IV detection to JVM (`IvParameterSpec`/
`GCMParameterSpec` from a zero array), C# (zero `.IV`), PHP (empty/`str_repeat`
IV), Ruby (fixed-literal IV), and Go (zero `make([]byte,…)` with a CBC/CTR mode,
suppressed when filled from `crypto/rand`). CSPRNG-derived IVs stay clean across
all languages. **Corpus 146 → 153; matrix 113 → 120/160.** F1=1.000; gate green.

## 0.112.0 — Cross-language HTTP response splitting (CWE-113) + 7 corpus entries

Extends `response-splitting.js` across all 8 languages (added Go, Ruby, C#,
Kotlin header sinks) and fixes two latent bugs: the PHP value was read from the
header-NAME capture group (never fired), and the request-scope param heuristic
is generalized from Java to Java/Kotlin/C#. Sanitizer recognition extended
(Python chained `.replace`, Ruby `gsub`/`delete`, Go `NewReplacer`/`ReplaceAll`,
PHP `str_replace`) so fixed forms stay clean. Biggest single matrix gain this
session. **Corpus 139 → 146; matrix 106 → 113/160.** F1=1.000; gate green.

## 0.111.0 — Cross-language XXE detector (CWE-611) + 3 corpus entries

Extends `xxe.js` (Java/Python) to PHP, Go, Ruby. Each non-JVM XML stack is
XXE-safe by default, so the detector flags the explicit external-entity opt-in
(PHP `LIBXML_NOENT`/`DTDLOAD`, Go `Strict=false`/custom Entity map, Nokogiri
`noent`/`dtdload`/`replace_entities`) rather than the default-safe parse.
**Corpus 136 → 139; matrix 103 → 106/160.** F1=1.000; gate green.

## 0.110.0 — Cross-language code-injection detector (CWE-94) + 4 corpus entries

New `code-injection-multilang.js` closes the CWE-94 gap in Java/C#/Go/Kotlin
(JS/Python/Ruby `eval` stay with the flow engine). Flags dynamic
code/expression evaluators on a non-literal argument — Java/Kotlin
(`ScriptEngine.eval`, GroovyShell, SpEL, MVEL, OGNL), C# (Roslyn `CSharpScript`,
`DataTable.Compute`), Go (yaegi/gomacro `interp.Eval`, `text/template` parse of a
non-literal body). A literal argument does not match. **Corpus 132 → 136; matrix
99 → 103/160.** F1=1.000; gate green.

## 0.109.0 — Cross-language LDAP injection detector (CWE-90) + 6 corpus entries

Extends `ldap-injection.js` from JS/Java/Python to PHP, Go, C#, Ruby, Kotlin.
Per-language filter patterns gated by an LDAP attribute set (uid/cn/mail/…) so
it doesn't fire on generic `key=value`. Two precision guards (both fix real FPs
found while building): a backtrack-proof call-guard so an escaped call at the
concat isn't flagged, and a file-level escape-API guard (`ldap_escape`,
`EscapeFilter`, `escape_filter_chars`, …) for escape-then-use spanning lines.
**Corpus 126 → 132; matrix 93 → 99/160.** F1=1.000; gate green.

## 0.108.1 — Corpus scale-up batch 3 — 117→126, matrix 84→93 cells

9 verified harvest entries across previously-empty cells the scanner already
detects (no detector change): CWE-798 {java,go,ruby,php}, CWE-916 {java,go,php},
CWE-918 {ruby}, CWE-601 {java}. Two discipline notes encoded in the generator so
they don't recur: placeholder `AKIA…EXAMPLE` keys read as pre:FN (the secrets
scanner correctly skips placeholders — regenerated with realistic keys), and a
guarded open-redirect "fixed" variant read as post:FP (the detector doesn't yet
recognize allow-list guards — post now uses literal targets). **126/126
F1=1.000; gate exit 0.**

## 0.108.0 — Corpus scale-up to 117 + baseline CI gate + cross-language XSS

Squashes the v0.106.0–v0.107.3 development churn (7 commits, several corrective)
into one coherent release.

- **Corpus 101 → 117 entries**, all pre:TP post:TN, F1=1.000, verified blind
  (manifest outside the scanned trees; identical under
  `AGENTIC_SECURITY_BLIND_BENCH=1`). Batch 2 harvest (11) + cross-language
  reflected XSS (5).
- **`xss-reflected-multilang.js`** (new): taint-independent reflected XSS for
  Go/Ruby/PHP/C#/Kotlin (input into an HTML response via concat/interp), each
  with a per-language output-encoder exclusion. JS/Python XSS stays with the
  flow engine.
- **Corpus baseline CI gate** (the process fix): `corpus-baseline.json` records
  the verdict for every entry; `runner.mjs --check-baseline`/`--update-baseline`
  + npm scripts. The gate fails on any drift — a regressed entry, a removed
  entry, or a new entry that does not pass. First `.github/workflows/ci.yml`
  (repo had no CI): runs `npm test`, verifies the committed bundle matches
  source, runs the corpus gate.
- **CLAUDE.md gains the "Verification discipline" section.** 117/117, gate exit 0.

## 0.105.0 — Corpus scale-up batch 1 (Tier 4) — 88→101, matrix 64→77 cells

First batch of the cve-replay scale-up toward 500, prioritized by empty
CWE×language cells. 13 new capability entries across 9 previously-empty cells
(CWE-338 weak PRNG, CWE-94, CWE-352, CWE-22, CWE-502), each verified pre:TP
post:TN. Two additive detector extensions unlock them: `weak-randomness.js`
gains snake_case carriers + Java/Kotlin/C# PRNG patterns (CWE-338; SecureRandom
stays clean), and `php.js`/`ruby.js` gain structural path traversal (CWE-22).
**Corpus stays F1=1.000; matrix 64 → 77/160.**

## 0.104.0 — Close remaining corpus FN/FP — cve-replay F1 0.929 → 1.000

Implements the full remaining recall+precision backlog. Aggregate cve-replay now
TP=88 FP=0 FN=0 TN=88 (F1=1.000); every language and CWE slice at F1=1.000.

- **`secret-concat.js`** (new): language-agnostic hardcoded-secret split across
  concatenated literals — reassembles `'AKIA'+'IOSF…'`/`'ghp'+'_…'`/`'sk'+'_live_…'`
  and matches provider prefixes (CWE-798).
- **`crypto-protocol.js`**: pyca/cryptography zero/static IV (CWE-329).
  **`weak-randomness.js`**: camelCase security carrier; reclassified CWE-330 →
  CWE-338. **`php.js`**: structural SQLi covers deprecated `mysql_query`.
  **`js-framework-structural.js`**: libxmljs XXE (CWE-611).
  **`python-structural.js`**: embedded-quote-tolerant literal matching +
  `open()`/`send_file` path traversal (CWE-22). **`csrf.js`**: Symfony support.
- **Precision (`engine.js` `dropGuardedFindings`)**: reflected-XSS
  output-encoding guard (drop CWE-79 when the value passed through a *captured*
  HTML escaper); `dedupeFindingsWithEvidence` prefers an interprocedural flow
  finding over a flat structural match at the same sink.

## 0.103.0 — Go recall: structural detectors (PRD Tier 1)

- **`go-structural.js`** (new): SQL injection via a `database/sql` query method
  built with `fmt.Sprintf` or string concat (CWE-89), and path traversal via
  `os.Open`/`os.ReadFile`/etc. built with concat or `fmt.Sprintf` (CWE-22).
  High precision: parameterized queries (`db.Query("… ?", x)`) and
  canonicalized paths (`filepath.Base` + `strings.HasPrefix`) have no
  Sprintf/concat in the sink argument, so they don't match.
- The centralized guard pass (`dropGuardedFindings`) gained Go path-guard
  tokens (`filepath.Base`/`Abs`, `HasPrefix`).
- **Measured: 2 FN → TP** (gin-sqli, go-path). **Go F1 0.75 → 1.000;** corpus
  FN 12 → 10; aggregate **F1 0.916 → 0.929.** No new FPs; full gate green.

## 0.102.0 — JS/Python framework recall: structural detectors (PRD Tier 1)

JavaScript and Python were the weakest languages (F1 ~0.75) — their remaining
FNs were framework handlers where input arrives via a framework source
(`@Query`, `ctx.query`, `request.GET`) and is concatenated into a sink, which
the taint engine misses without a modeled source.

- **`js-framework-structural.js`** (new): SQLi via `.query`/`.execute` concat /
  template-literal (TypeORM/mysql/NestJS, CWE-89); koa-send path traversal
  (CWE-22); `ctx.body` reflected XSS, suppressed by `escape()` (CWE-79);
  NestJS `HttpService.get` SSRF (CWE-918); deep-merge prototype pollution,
  suppressed by a `__proto__`/`FORBIDDEN_KEYS` filter (CWE-1321).
- **`python-structural.js`** (new): Flask `render_template_string` built from
  input — reflected XSS + SSTI (CWE-79; a Jinja `{{ }}` template is safe and
  does NOT match); Django `.raw`/`.extra` and `cursor.execute` built with
  concat / f-string / `%`-operator format (CWE-89; the `%s` parameterized
  placeholder form does NOT match).
- High precision (verified on the corpus pre/post pairs + a regression the
  unit test caught: `execute("… %s", [v])` is the *safe* DB-API placeholder,
  not `%`-format injection).
- **Measured: 8 FN → TP** (flask-xss, hoek, koa-path, koa-xss, nestjs-sqli,
  node-sqli, django, nestjs-ssrf). **Corpus FN 20 → 12; aggregate F1 0.861 →
  0.916.** JavaScript 0.76 → 0.90, Python 0.82 → 0.88. No new FPs; full gate green.

## 0.101.0 — SSRF/path guard recognition: precision (PRD #1)

The recall work (v0.98–v0.100) lifted aggregate F1 ~0.50 → ~0.80 but surfaced a
precision problem: the scanner flagged **14 *fixed* files as still-vulnerable**
(precision ~0.83) — mostly SSRF, where the fix adds a host allow/deny check, and
path traversal, where the fix adds a containment guard. Multiple independent
detectors decided SSRF/path with no shared notion of "this sink is hardened."

- **`ssrf-cloud-metadata.js`**: rule #1 no longer flags the `169.254.169.254`
  literal when it sits in a deny-list / host-comparison guard (the remediation,
  not the vuln).
- **`engine.js` `dropGuardedFindings(findings, fc)`** — a single, centralized
  pass after all detectors that drops a CWE-918 finding when the sink window has
  a host allow/deny check (deny/allow-list, `getHost`/`hostname` comparison,
  RFC1918/metadata prefix check, `ipaddress`/`getaddrinfo`/`ssrf-req-filter`), or
  a CWE-22 finding when the window has a path containment guard
  (`basename`/`GetFileName`/`secure_filename`/`send_from_directory`, or
  canonicalize + `startsWith`). Uniform across every emitter (regex, structural,
  per-language flow, PY-SAST, CSHARP, GO). The window is **comment-stripped** so
  a "no allow-list / 169.254…" vuln comment can't read as a guard. Opt out:
  `AGENTIC_SECURITY_NO_GUARD_RECOGNITION=1`.
- **Measured: corpus false-positives 14 → 2** (the 2 remaining are XSS
  escape-html recognition — a different family, next up). **Precision ≈ 0.97;
  aggregate F1 0.80 → 0.861 — past the 0.85 target.** Java + C# now 1.000;
  Python/Go/PHP at 0 FP. **Zero recall loss** (vulnerable-tier TP=68 unchanged) —
  the invariant that proves the guards don't hide real flows.
- New `guard-recognition.test.js`; full gate green.

## 0.100.0 — Java/Spring + C# recall: structural detectors (PRD Tier 1)

Continues the recall-led PRD. The flow-based `csharp.js` and AST/bench Java
modules miss standalone methods whose tainted-by-convention parameter has no
in-file source; Java has no string templates, so the shape is concatenation.

- **`java-structural.js`** (new): SQLi (executeQuery/createQuery + concat,
  CWE-89), command injection (Runtime.exec/ProcessBuilder + concat, CWE-78),
  path traversal (new File/Paths.get + concat, CWE-22, suppressed by
  canonical/normalize/startsWith guards), SSRF (new URL/URI from a non-literal,
  CWE-918, suppressed by a host allow/deny guard).
- **`csharp-structural.js`** (new): hardcoded credential in a const/static
  field — including the **split-concat evasion** (`"sk_" + "live_…"`) that
  defeats plain secret regexes (CWE-798, value gated on length/known-prefix so
  header-name constants aren't flagged); guarded SSRF via WebClient/HttpClient
  (CWE-918).
- **Measured: 5 more FN → TP** (spring-path, spring-ssrf, spring-sqli,
  cs-hardcoded, cs-ssrf). Both modules return clean on the fixed versions.
- **Session total: corpus false-negatives 35 → 20** (Kotlin 6 + Ruby/PHP 4 +
  Java/C# 5 = 15 FN closed). Additive, language-scoped, no regressions. New
  `java-csharp-structural.test.js` + fixtures; full gate green.

Note: spring-ssrf / cs-ssrf still show a pre-existing `post:FP` from other
detectors on the fixed file (not introduced here) — a precision item for later.

## 0.99.0 — Ruby + PHP recall: structural injection detectors (PRD Tier 1)

Continues the recall-led PRD down the corpus FN list. Same root cause as
Kotlin: the fixtures route request data through a local var
(`name = params[:name]` / `$f = $r->query->get(...)`) before the sink, so the
existing rules — which require the literal `params`/`$_GET` token on the sink
line — miss them.

- **`ruby.js`**: structural ActiveRecord SQLi (`.where("… #{x}")` / concat,
  CWE-89) and shell cmdi (backtick / `system` / `exec` with `#{}` or concat,
  CWE-78).
- **`php.js`**: structural shell cmdi (`shell_exec`/`exec`/`system`/`proc_open`
  with `'…' .` concat or `"… $var"` interpolation, CWE-78) and raw SQLi
  (`DB::raw`/`whereRaw`/`mysqli_query` with concat/interp, CWE-89).
- High precision: parameterized queries (`.where('… ?', x)`,
  `DB::select('…?', [$x])`), array-form exec (`proc_open(['gzip',$f])`,
  `Open3.capture2('finger', user)`) do **not** match.
- **Measured: 4 more FN → TP** (rails-sqli, rails-cmdi, symfony-cmdi,
  laravel-sqli). **Total corpus FN this session: 35 → 25** (Kotlin 6 + Ruby/PHP
  4). Purely additive, language-scoped, no regressions. New
  `ruby-php-structural.test.js` + fixtures; full gate green.

Deferred: symfony-csrf (CSRF is a state-change/token detector, FP-prone as a
regex — needs framework-aware modeling, not a structural injection rule).

## 0.98.0 — Kotlin recall: close all 6 corpus false-negatives (roadmap Tier 1)

First execution of the "perfect SAST" PRD, which leads with **recall** (the
measured CVE-replay F1 ≈ 0.50 is a missed-detection problem). Kotlin was the
worst single language — 6 FNs across SQLi/cmdi/path/SSRF/XXE/deser — because
those fixtures are standalone DAO/handler methods with a tainted-by-convention
parameter and no in-file taint source, so the taint engine saw nothing.

- **`sast/kotlin.js`** gains taint-independent **structural** detectors: a
  dangerous sink built with a Kotlin string template (`${x}`) or concat
  (`"…" +`) is the injection shape regardless of variable names —
  SQLi (CWE-89), command injection (CWE-78), path traversal (CWE-22). Plus
  guarded SSRF (CWE-918, suppressed when a host allow/deny check is present),
  insecure XML config XXE (CWE-611, suppressed when secure-processing is set),
  and `ObjectInputStream.readObject` deserialization (CWE-502).
- High precision: a parameterized query / array-form exec / literal URL / XML
  factory with `setFeature(...)` does **not** match. Verified on the corpus
  pre/post pairs — all 6 vulnerable fixtures fire, all 6 fixed versions stay
  clean (scanner-level).
- **Measured result: 6 Kotlin FN → TP; total corpus false-negatives 35 → 29.**
  No regressions (purely additive, `.kt`-scoped). New `kotlin-structural.test.js`
  + fixtures; full gate green.

Establishes the per-family/per-language porting pattern; next: Rails/Laravel/
Symfony/Gin/Spring SQLi+cmdi and the remaining second-tier FNs.

## 0.97.0 — Tree-sitter foundation for long-tail languages (roadmap #8)

First step of bringing languages with no first-class IR parser
(rust/solidity/cpp/c/go/swift/dart) onto real AST analysis.

- **Optional, ABI-pinned dependency:** `web-tree-sitter` 0.20.8 +
  `tree-sitter-wasms` 0.1.13 as **optionalDependencies**, marked `--external`
  in the ncc build so the committed bundle never embeds WASM (verified: bundle
  stays ~3.5 MB and contains only the external `require`, not the grammars).
- **`ir/tree-sitter-loader.js`** — lazy, cached, graceful. Loads the runtime +
  grammar at runtime and returns null when absent, so the scanner stays fully
  bootable offline / without the optional deps (long-tail languages fall back
  to the existing pattern detectors).
- **`sast/tree-sitter-sinks.js`** — first AST-accurate detector, gated behind
  `AGENTIC_SECURITY_TREE_SITTER=1`: Rust shell-spawn command injection (CWE-78,
  `Command::new("sh").arg("-c").arg(<dynamic>)`). Anchoring on real AST nodes
  means the same pattern in a comment or string literal does NOT false-match —
  the precision win over regex.
- Opt-in + optional-dep gated ⇒ default scan behavior and the committed bundle
  are unchanged. Tests + full gate green.

Next on #8: more languages/rules (Solidity dangerous primitives, Go `exec`),
and eventually CFG construction to route long-tail languages through the full
taint engine.

## 0.96.0 — Surface coverage honesty + make the corpus reporter runnable

Completes the measurement threads from 0.91/0.95 — the data existed but wasn't
usable. No detection changes.

- **Coverage line in the scan report.** `toCLI` now renders a one-line
  blind-spot summary from `_scanMeta`: files scanned, which languages got flow
  analysis (`flow=[…]`) vs pattern-only, how many files were skipped, and the
  unmodeled-sink-candidate count. The #5/#6 data is finally visible to users
  instead of sitting unread in the JSON.
- **`bench/cve-replay/corpus-status.mjs`** — a runnable report for #10:
  `node bench/cve-replay/corpus-status.mjs [--gaps|--json]` prints progress
  toward the 500-entry target and the empty CWE×language cells. On the current
  corpus: 88/500 entries, 64/160 cells covered, 96 gaps (thinnest: ruby/go/php).

### Deliberately NOT done this round
- **#8 long-tail languages onto the IR** — needs a tree-sitter dependency
  (can't be installed/bundle-validated in this environment) or five hand-written
  parsers. A dependency decision, not a safe single-pass change.
- **#1 full** — context-tagged taint lattice (core-engine rewrite).

## 0.95.0 — Stored taint (#2, opt-in) + corpus coverage reporter (#10)

- **#2 — Second-order / stored taint** (`sast/stored-taint.js`, **opt-in** via
  `AGENTIC_SECURITY_STORED_TAINT=1`). Flags a value read from a persistence
  store (DB/cache) that flows into an injection sink (XSS/SQLi/cmd/code)
  without re-validation — the stored-XSS / second-order-SQLi shape the forward
  taint engine can't see across the persistence boundary. Lower confidence by
  design (stored data isn't always attacker-controlled), so OFF by default:
  enabling it cannot change default scan behavior.
- **#10 — Corpus coverage reporter** (`posture/corpus-status.js`). Turns the
  CVE-replay corpus into an actionable map: progress toward the 500-entry
  target and exactly which CWE×language cells have zero ground-truth entries.
  Measures the existing corpus only — it never fabricates entries. This is the
  measurement substrate that makes scaling the corpus prioritizable.

Tests for both; full gate green.

### Still genuinely open (need a decision or are research-grade)
- **#8 long-tail languages onto the IR** — five net-new IR parsers, or a
  tree-sitter dependency (which conflicts with the offline-degradation rule).
  This is a dependency decision, not a quick fix.
- **#1 full** — context-tagged taint lattice (a core-engine rewrite); the
  practical wrong-context slice already ships.

## 0.94.0 — Same-file-preference call resolution (roadmap #3)

The cross-file resolver (`ir/callgraph.js` `resolve()`) was name-based: a bare
name defined in several files (`handler`, `save`, `query`, …) resolved to
whichever file Map was iterated first, mis-targeting interprocedural taint to a
same-named function in an unrelated file (wrong-target FPs and missed-target
FNs).

- `resolve(name, callerFile)` now **prefers the caller's own file** when it
  defines the name — overwhelmingly the intended callee. The taint engine
  threads the caller's file at all three resolution sites (assign-call,
  plain-call, higher-order callback).
- **Backward-compatible by construction:** with no `callerFile` or no local
  match, the original resolution order is unchanged, so no resolution edge is
  ever dropped (no new false negatives). The full gate — incl. interproc-k2's
  context test, deep-taint, calibration — stays green.
- New `test/callgraph-resolve.test.js`.

## 0.93.0 — CSV/formula injection (CWE-1236) + scoped validation-lib sanitizers (#7)

- **CSV / formula injection** (`sast/csv-injection.js`, CWE-1236): flags user
  data written to a CSV/spreadsheet writer without neutralizing leading formula
  characters (`= + - @` / tab). High precision — requires a CSV-write API + a
  user-taint hint on the same statement and no formula-escape helper nearby.
- **#7 validation-library sanitizers (correct, narrow):** zod `safeParse`/
  `parseAsync` and class-validator `validateOrReject` are now modeled as
  sanitizers **scoped to `mongo-operator` (NoSQL/operator injection) ONLY**.
  Validating a typed shape defeats operator injection, but a validated string
  is still an XSS/SQL payload — so they are deliberately NOT tagged for those
  families (a blanket tag would cause false negatives). Distinctive callees
  only, to avoid colliding with `JSON.parse`.

Fixtures + tests for both; full gate green.

## 0.92.0 — Front-end hygiene detectors (3 verified-missing, additive)

New `sast/frontend-hygiene.js` — three high-precision client-side detectors,
each a verified coverage gap (no prior matches in the detector tree). All
additive: they emit new finding classes and cannot reduce existing detection.

- **Reverse tabnabbing (CWE-1022):** `<a target="_blank">` without
  `rel="noopener"` — the opened page can rewrite `window.opener`. (low)
- **Missing Subresource Integrity (CWE-353):** a cross-origin
  `<script>` / stylesheet `<link>` with no `integrity=` — a compromised CDN
  runs in your origin. Skips same-origin/relative assets. (medium/low)
- **Angular sanitizer bypass (CWE-79):** `DomSanitizer.bypassSecurityTrust*`
  on a non-literal value explicitly disables Angular's XSS protection on
  attacker-influenced data. Skips constant-string arguments. (high)

Fixtures + 6 tests; full gate green.

## 0.91.0 — Coverage honesty (#5+#6) + wrong-context encoding (#1 slice)

Additive precision/trust features that cannot reduce existing detection.

### #5 + #6 — Analysis-coverage honesty report
- New `posture/coverage-report.js`. `_scanMeta` now publishes the scanner's
  blind spots: per-language **analysis tier** (which languages got the IR +
  taint engine vs. pattern-only — c/c++/rust/swift/solidity/dart are
  pattern-only today), a `filesDenseSkipped` counter (dense files were
  previously dropped with no count), and **unmodeled-sink candidates** —
  dangerous-call shapes (eval/exec/deserialize/yaml.load/…) with no finding on
  their line, i.e. recall blind spots to verify.

### #1 (practical slice) — Wrong-context output encoding (CWE-79)
- New `sast/wrong-context-sanitizer.js` flags an HTML-entity encoder
  (`escapeHtml`/`htmlspecialchars`/`he.encode`/`lodash.escape`) applied to a
  value used in a URL context (`href`/`src`/`location`). HTML-entity encoding
  does NOT neutralize `javascript:`/`data:` schemes, so the value is still XSS
  while looking sanitized. High precision: excludes `encodeURIComponent` (a
  different, non-XSS mistake) and suppresses when a URL-scheme allow-list is
  near. Fixtures + tests; full gate green.

### Deferred (need core-engine work or carry correctness traps — not faked)
- **#1 (full):** context-tagged taint through the lattice — the engine's taint
  is binary and can't express "sanitized-for-HTML vs -for-JS". Core change.
- **#7 validation libraries:** modeling zod/joi/etc. as blanket sanitizers
  would cause FALSE NEGATIVES — a schema-validated string is still an XSS/SQL
  payload. Needs schema-type awareness (validation defeats type-confusion /
  NoSQL-operator injection, not output injection). Deferred deliberately.
- **#2 stored/second-order taint, #3 import/type-aware call resolution,
  #8 long-tail languages onto the IR, #10 corpus scale** — each its own lift.

## 0.90.0 — Context-sensitive taint completed + bounded (roadmap #2, FR-SEM-2)

The interprocedural engine was already value-context sensitive at the
assign-call site (a distinct summary per entry-taint-state, computed lazily;
v0.66). This release completes and bounds it.

- **Plain-call sites now lazily compute context-specific summaries too.**
  Previously the plain (non-assign) call site only did a cache `get`, so a
  param mutated *only* when the callee is invoked with tainted input was
  missed there. It now mirrors the assign-call site (compute under the actual
  tainted-arg context on a miss).
- **Per-function context cap** in `SummaryCache` bounds the number of distinct
  non-empty entry contexts kept per function so lazy per-call-site computation
  can't blow up. Over the cap → reuse the empty-entry (monovariant) summary.
  Tunable via `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS` (default 16; **0 = pure
  monovariant**, a clean kill-switch).
- **Docs corrected:** `summaries.js` and `dataflow/CLAUDE.md` previously called
  the engine "k=1 monovariant / one summary under empty entry." It is in fact
  value-context sensitive; the real remaining limits are call-string (k>1)
  sensitivity and param-level (not access-path-level) entry granularity.
- New `test/kcfa-context.test.js` (context-sensitivity + cap + kill-switch +
  clear); full gate green.

## 0.89.0 — Per-language metrics (#9) + roadmap audit (#3, #5 already shipped)

Continuing the multi-language SAST roadmap. Investigation revealed several
items were already implemented — so this release delivers the one genuinely
missing safe item (#9) and corrects the record, rather than re-building what
exists.

### #9 — Per-language precision/recall (new)
- `holdout-eval.js` now records a `language` per labeled sample (explicit
  `language` field or derived from the `file` extension) and exposes
  `perLanguage()` + `summarizePerLanguage()`.
- `evaluateHeldOut` returns a `perLanguage` breakdown and **flags any language
  whose precision trails the aggregate by >0.15** (n≥20) — the regression an
  aggregate would otherwise mask (a 90%-JS corpus hiding poor Ruby precision).
- New tests in `test/holdout-eval.test.js`.

### #3 — Already implemented; doc corrected
Audit found mutated-parameter taint (`applyAtCallSite`), higher-order callback
taint (`_higherOrderInvocations` fed back into the worklist), and recursion via
a multi-pass fixed point (`MAX_FP_ITERS`) were all shipped in v0.66 and covered
by `interproc-k2` / `closure-capture` / `phase6-taint` tests. The stale
`dataflow/CLAUDE.md` "what we do NOT model" section is corrected.

### #5 — Already at parity
The source/sink catalog already spans Spring, ASP.NET, Gin, Echo, Fiber, Chi,
Gorilla, Buffalo, Laravel, Symfony, Rails, Sinatra, Ktor, JDBC/JPA/Hibernate,
Dapper/ADO across all 8 languages. No new work needed.

### Still deferred (research-grade; will ship as their own releases)
#1 universal IR (no tree-sitter dep; `universal-ir.js` unwired), #2 k-CFA
context-sensitivity (FR-SEM-2), #4 auto-derived library summaries, #7 dynamic
dispatch + type inference, #8 incremental-by-default (needs a cold==warm gate),
#10 LLM closed-loop validator. These are not faked into the engine.

## 0.88.0 — Proof-gate precision pass (multi-language SAST roadmap #6)

First flagship of the "perfect multi-language SAST" program: report only
provably-feasible flows, and demote — never drop — flows we can prove are
clean or infeasible.

- **New `dataflow/proof-gate.js`** consolidates the engine's two independent
  flow-proof signals (`provenClean` from `proven-clean.js`, `_provenUnreachable`
  from `exploit-prover.js`) into one verdict per finding:
  `finding.proof = { verdict: 'feasible' | 'proven-clean' | 'proven-infeasible' | 'unproven', reasons[] }`.
- **Wired the previously-dead `proven-clean.js`** into `runDeepAnalysis` — SQL
  sinks reached only through a parameterizer are now proven clean by default.
- **Recall-preserving demotion:** proven-clean / proven-infeasible findings get
  lowered `confidence` + `confidenceTier` + `exploitabilityTier` (and rank below
  feasible findings), but **`severity` is left untouched** so a heuristic proof
  can never hide a finding from a severity-based CI gate.
- Default on; opt out with `AGENTIC_SECURITY_NO_PROOF_GATE=1`. New
  `test/proof-gate.test.js`; full gate green.

Remaining roadmap items (#1 universal IR, #2 k-CFA, #3 dormant taint paths,
#4 library summaries, #5 framework catalog parity, #7 dynamic dispatch,
#8 incremental-by-default, #9 per-language metrics, #10 LLM gate) ship as
their own benchmarked releases.

## 0.87.0 — Sharpen the 12

Ergonomics + power features for the 12-command surface left after the
v0.86.0 consolidation.

### Cross-cutting
- **Legacy-alias redirect hook** (`UserPromptSubmit`, `hooks/legacy-alias-redirect.js`):
  typing a removed alias (`/status`, `/show-findings`, `/harden`, …) now
  injects context that maps it to the new dispatcher mode, so the request
  still runs. Covers all 44 removed aliases.
- **Trend-aware `/secure` router**: compares the last two scans and shows a
  `↑ / → / ↓` arrow with what changed (never invents a trend from one scan).
- **Bare-invocation mode menus** and uniform `--json` documented across the
  dispatchers.
- **Task-oriented `/secure --help`** + an old→new alias map.

### Per-command
- `/scan --pick` — interactive mode menu.
- `/fix --checkpoint` — run a batch fix on a throwaway git branch (atomic revert).
- `/compliance --gap` — Not-Compliant worklist with the exact closing command per control; `--format oscal|json` machine-readable export.
- `/supply` — offer to bundle safe patch/minor upgrades into one PR after `--check`.
- `/posture` (bare) — combined dashboard (status + grade + trend).
- `/find-and-fix-everything` — auto checkpoint branch + PR-ready summary.
- `/triage` — order findings likely-FP-first from triage history.
- `/three-agent-review` — echo the call/wall-time budget before running.
- `/ci` — validate generated workflow YAML + offer a PR.
- `/labs` — graduation-status table for experimental modes.
- `/setup --all` — install hooks + CI + bodyguard + destructive-guard in one pass.

## 0.76.0 — Command consolidation: 80 → 38 slash commands

Simplified the command surface from 80 individual slash commands down to
38 by merging related commands into consolidated routers with flags.
No functionality removed — all logic preserved behind flags on fewer,
more discoverable parent commands.

### New consolidated commands

| New command | Absorbed | Routing |
|---|---|---|
| `/audit` | db-audit, auth-audit, rate-limit-check, webhook-audit, env-check, csp-cors, deploy-check, launch-check, llm-cost-ceiling, prompt-firewall | `--target <area>` or `--all` |
| `/threat` | threat-model, personas, playbook, bounty, adversary, attack-surface, trust-boundary, spof | `--view <name>` |
| `/llm` | llm-redteam, jailbreak-detector, llm-eval | `--mode redteam\|jailbreak\|eval` |
| `/ci` | ci-gate, predeploy-gate, install-hooks | default / `--predeploy` / `--hooks` |
| `/generate` | privacy-docs, disaster-playbook, social-media, security-tests | `--type privacy\|disaster\|social\|tests` |
| `/scanner` | self-test, diff-scan, scan-baseline, concurrency-bugs, spec-drift | `--self-test` / `--diff` / `--baseline` / `--concurrency` / `--spec-drift` |

### Commands absorbed into existing commands

- `/why-fired` → `/explain --provenance --finding <id>`
- `/why-not` → `/explain --gap <CWE>`
- `/install-script-audit` → `/supply-chain-check --show install-scripts`
- `/vendor-audit` → `/supply-chain-check --show vendored`

### Deleted deprecated aliases (11)

ci-gate-multi, rotate-key-auto, trim-dead-code, trim-dependencies,
story-explain, security-badge, security-onepager, trust-page,
dep-pinning, dep-freshness, dep-alternatives.

## 0.75.1 — /agent-harness-assessment + interactive compliance routing + README badge relocation

Three follow-ups to the 0.75.0 surface:

**Renamed `/executive-summary` → `/agent-harness-assessment`.** The
previous name framed this as a finance-style report. The actual artifact
is an assessment of the AI-agent harness: a CISO/buyer reading it wants
to know whether to trust an AI agent working in this project, not just
see a posture grade. The new name reflects the audience.

**Interactive compliance step.** After printing the six-control
assessment, the command now asks (via AskUserQuestion) which compliance
frameworks the reader wants generated NOW — NIST AI 600-1, OWASP ASVS,
OWASP LLM Top 10 (2025), or none. For each selection, the model invokes
`/compliance-report <fw>` with the matching positional argument
(`nist`, `asvs`, `llm`) so an auditor-ready file lands on disk. The
Compliance section in the assessment now says what evidence COULD be
produced; the interactive step closes the loop to evidence that EXISTS.

**README "Status badge" section relocated** from the top-of-README hero
region into the Security Pros section, between the 5-minute pro setup
and the full pro catalog. Adopting the badge is a pro-shaped step
(it requires CI wiring + a baseline scan). Three example badges now
render on three distinct lines via trailing `<br>` so the severity
ladder is legible at a glance.

## 0.75.0 — /executive-summary: CISO-facing six-control posture report

New top-level command for buyer-questionnaire / diligence / CISO use.
`/executive-summary` prints a plain-English briefing of the six harness
controls (Tool access, Guardrails, Feedback loops, Audit evidence,
Failure mode, Compliance) with live status indicators drawn from the
current project state — hook activation, scan-signature presence,
audit-log entry count, remote-witness configuration, compliance artifacts.

Each control renders four named subsections modeled on `/explain`:
**What it does** (2-3 paragraphs of plain English), **Specifically**
(the concrete enumerated list of allows/blocks/intercepts), **What would
have to go wrong for this to fail** (threat model in one paragraph), and
**Live status (this project)** (verifiable indicators). The "Specifically"
block names actual reserved paths, every shell command intercepted, every
code-edit pattern blocked, every audit-log property, every refusal point,
and every compliance artifact format — so a reviewer can verify the claim
without opening any source file.

Flags: `--format md` for markdown output; `--output PATH` writes to disk
(typically `EXECUTIVE_SUMMARY.md` for buyer questionnaires).

## 0.74.2 — npm package + version alignment

First release published to npm under the org that owns the scope:
`@clear-capabilities/agentic-security-scanner`. Adds a bin alias
`agentic-security-scanner` (→ same dist bundle) so the documented
`npx @clear-capabilities/agentic-security-scanner secure .` resolves
an executable. Aligns the source-tree version with the npm registry
after the 0.74.1 metadata-only publish.

## 0.74.0 — viral surface: PoC video gen + security-tutor skill + personality voices + compare runner

Four shareability lifts.

### Auto-recorded PoC scripts — `scanner/src/poc-video.js`
For findings with `_exploitInput` (v0.71 symbolic prover), generate a
self-contained script the operator runs against their own staging URL:
- **playwright**: TypeScript test that drives the exploit live + records video. Default for UI-driven exploits.
- **curl**: bash script with verbose tracing + payload-acceptance assertion. Default for backend exploits.
- **http**: RFC 7230-style raw request pastable into Postman/Insomnia.

The generator does NOT execute anything; produces share-grade evidence the operator runs against their OWN environment.

### Educational mode skill — `skills/security-tutor/SKILL.md`
Auto-activates when the user asks "why is X dangerous", references a finding-id and asks for context, or has mechanically accepted ≥3 fixes in a row. Walks the finding Socratically: identify source/sink/sanitizer, ask user to propose the payload BEFORE showing the fix, verify understanding with follow-up traps. CWE-specific Socratic patterns table covers 8 families.

### Security personality voices — `scanner/src/personality.js`
Three tone modes wrapping any rendered report: **sage** (calm, default), **cassandra** (alarmist), **vince** (drill-sergeant). Same findings, dramatically different shareability. `AGENTIC_SECURITY_PERSONALITY` env selects. Only the framing changes — technical content stays identical.

### Compare runner framework — `scanner/src/compare.js`
Bring-your-own-tool side-by-side comparison. User supplies the other tool's invocation + field map; we render a Markdown card with overlap / unique / severity-disagreement sections. Framework is generic — no competitor-specific adapters shipped.

### Test totals
**847 scanner tests pass / 0 fail** (up from 832).

## 0.73.0 — technical depth: IFDS summary edges + type-stub filter + cross-repo federation

Three technical-depth lifts. v0.71 shipped IFDS scaffolding with bottom
summaries; v0.70 added type-stubs but didn't thread them into the
engine; v0.68 added cross-lang within a single repo but not cross-repo.
v0.73 closes all three loops.

### IFDS full summary edges — `scanner/src/dataflow/ifds.js`

The v0.71 IFDS solver used bottom summaries (every callee was assumed
clean → no interprocedural facts flowed). v0.73 adds:
- `summaries: Map<qid|entryFact, Set<exitFact>>` records per-function
  summary edges
- `pendingReturns: Map<qid|entryFact, [{fn,returnNode,callerEntry}]>`
  registers callers waiting on more summary facts
- `_entryFactForCall(callNode, currentFact, callee)` derives callee's
  entry fact from a call site
- `_mapReturnFact(callNode, exitFact, callerCurrent)` translates exit
  facts back into caller namespace
- Summary reuse: second call to same (callee, entry fact) is O(1)

This is what makes IFDS polynomial in practice rather than re-solving
every call site.

### Type-stub-aware filter — `scanner/src/dataflow/stub-aware-filter.js`

Post-pass after the taint engine. Consults the project's TS/.pyi/JAR
type stubs (loaded by v0.70's `ir/type-stubs.js`) and demotes findings
whose source type cannot carry the vulnerability metacharacters:

| Family | CWE | Safe types (demoted) |
|--------|-----|----------------------|
| XSS    | CWE-79 | number, boolean, Date, RegExp, bigint |
| SQLi   | CWE-89 | number, boolean, Date, bigint |
| Cmd    | CWE-78 | number, boolean, bigint |
| Path   | CWE-22 | number, boolean |
| SSRF   | CWE-918 | number, boolean |

Severity drops one tier (critical → high → medium → low → info); never
drops the finding. Operator sees `_stubTypeDemoted: true` + reason.

Gate: `AGENTIC_SECURITY_TYPE_STUBS=1` (same flag as the v0.70 stub
loader).

### Cross-repo federation — `scanner/src/dataflow/cross-repo.js`

The intra-repo `cross-lang-openapi.js` posture module shipped in v0.66
ties a single repo's client call to its server route. v0.73 ships the
inter-repo lift: `buildFederatedGraph(specs)` walks a SET of OpenAPI
specs from different repos, finds shared `(method, path)` endpoints
with overlapping field schemas, and emits federated edges. Each edge
becomes a `CROSS-REPO` finding (`CWE-829`, `family: cross-repo-taint`)
showing both repos + the shared fields in the trace.

Use case: scan the auth-service repo + the billing-service repo
together; the scanner detects that `/users/{id}` is published by auth
and consumed by billing, with shared fields `email + bio`. A taint in
auth's response surfaces in billing's input — both teams now own the
sanitization contract.

### Test totals
**832 scanner tests pass / 0 fail** (up from 811).

## 0.72.1 — CI template + README adopts the v0.72 viral features

Patch release. Two adoption follow-ups for v0.72's viral features.

### CI template defaults to advisor-tone PR comment

`.github/workflows/scan.yml` — new `pr-comment-mode` input (default
`"advisor"`, alternative `"findings-table"`):

- **advisor** (new default): runs `pr-delta --base origin/<base_ref>` to
  compute the security DELTA between PR and base, then pipes the JSON
  into `pr-comment` to render the security-advisor's note. The comment
  shows only what THIS PR introduced/resolved, with CWE narrative + fix
  snippet + blocking-merge footer.
- **findings-table** (legacy): the prior critical/high count table.
  Available behind the input flag for adopters who prefer it.

Downstream consumers automatically get the new comment style on next CI
run. Opt back to the legacy table by passing `pr-comment-mode: findings-table`
to the reusable workflow.

### README adopts the status badge + leaderboard pitch

`README.md`:
- Stale `version-0.64.0` badge bumped to `version-0.72.1`.
- New badge row entry: `[![agentic-security](...)]()`.
- New "Status badge for your README" section with paste-ready Markdown,
  three example states (passing / high / critical), and self-host
  instructions for users who don't want to depend on `agentic-security.dev`.
- New "Public leaderboard (preview)" section pointing at the v0.72
  `leaderboard-row` backend.

### Test totals
**811 scanner tests pass / 0 fail** (unchanged from 0.72.0).

## 0.72.0 — viral features: shadowscan delta + advisor-tone PR comment + live badge + leaderboard backend

Three viral-lever features built to compound: every PR generates a
screenshotable advisor's note (not a wall of findings), every repo can
wear a live security badge (pull-marketing), and every scan's data shape
is ready for a public leaderboard.

### #5 Shadowscan / security-DELTA on PR — `scanner/src/pr-delta.js`

`computePrDelta(root, { baseRef, headRef })` scans both refs in-memory
(no checkout, via `git show <ref>:<path>`), diffs by `stableId`, and
emits:
- `introduced` — findings in head not in base
- `resolved`   — findings in base not in head
- `persistent` — same stableId both sides
- `shifted`    — same stableId but severity or CWE changed
- `summary.net` — per-severity head − base delta

New CLI:
```
agentic-security pr-delta --base origin/main [--head HEAD] [--json]
                          [--fail-on-introduced]
```

### #1 Advisor-tone PR comment — `scanner/src/pr-comment.js`

`renderPrComment(delta, { repoName, prNumber, prTitle })` produces a
single Markdown comment that reads like a person, not a table. Three
auto-detected modes:
- **clean** (no delta) → "Safe to merge."
- **resolves-only** → "This PR resolves N finding(s)... Nice cleanup."
- **needs-work** → narrative + per-finding paragraph with CWE 'why'
  text + remediation snippet + blocking-merge footer for critical/high.

CWE narrative table covers 19 families with one-sentence "why does this
matter" explanations. The mode is what gets **screenshotted** — security
tool output that reads like an advisor, not a SARIF dump.

New CLI:
```
agentic-security pr-comment [--in delta.json | --base <ref>]
                            [--repo <slug>] [--pr <n>] [--title <text>]
# Reads JSON delta from --in, --base (recomputes), or stdin.
```

### #2 Live SVG badge — `scanner/src/badge.js`

`renderBadge({ format, style, scanRoot, scan })` emits a shields.io-style
SVG (or JSON for frontend renderers) summarizing the latest scan:
`agentic-security: crit 0 · high 2 · med 5 · 4h ago`. Color driven by
highest non-zero severity. Two styles: `flat` (default) + `for-the-badge`.

New CLI:
```
agentic-security badge [--format svg|json] [--style flat|for-the-badge]
```

Reads from `.agentic-security/last-scan.json`. The badge is intended as
a README ornament that doubles as pull-marketing — every adopting repo
becomes a billboard.

### Leaderboard backend — `scanner/src/leaderboard.js`

`leaderboardRowFor({ scanRoot, repo })` builds one row of the future
public leaderboard data: posture grade A-F, severity counts, top CWE,
last-scan age, delta trend (`improving`/`flat`/`regressing` from
`scan-history.jsonl` if present), and the badge URL/Markdown snippet
ready to paste. `rankRows(rows)` sorts by critical → high → grade.

Public hosting of `agentic-security.dev/leaderboard` is deferred — this
release ships the data side so the future site is a thin frontend.

New CLI:
```
agentic-security leaderboard-row --repo owner/name [--root <dir>]
```

### Test totals
**811 scanner tests pass / 0 fail** (up from 792).

### Migration
All four features are additive opt-in CLI subcommands. CI templates can
adopt `pr-delta | pr-comment` to replace findings-dump comments without
breaking the existing scan-and-comment flow. README badge adoption is
manual (paste a Markdown snippet).

## 0.71.1 — dependency hygiene + CodeQL ignore-list for scanner/

Patch release. No behavior change.

### Dependency bumps
- `@types/node`: `^20.0.0` → `^24.0.0` (scanner + vscode). Node 20 reached
  EOL in 2026-04; tracking the current LTS.
- `scanner/package.json` `engines.node`: `>=20.0.0` → `>=22.0.0`.
- `vscode/package.json` `@types/vscode` + `engines.vscode`: `^1.85.0` →
  `^1.95.0` (the engine pair stays consistent so VSCE doesn't warn).

Other deps already current and unchanged: `@babel/*` 7.x, `@vercel/ncc`
0.38.x, `js-yaml` 4.x, `safe-regex` 2.x, `fast-glob` 3.x, `esbuild` 0.25.x,
`@vscode/vsce` 3.x. GitHub Actions in workflows already on v5/v8.

### CodeQL ignore-list

The scanner directory contains the taint engine itself — full of SAST
patterns, hardcoded fixture credentials, eval() shapes, raw SQL strings.
Any other SAST (including GitHub CodeQL) flags these as vulnerabilities,
producing noise that drowns out real findings.

Two new files:
- `.github/codeql/codeql-config.yml` — 15-entry `paths-ignore` covering
  `scanner/**`, `bench/**`, `vscode/dist/**`, all test fixtures, the
  `.bench-cache/**` tree, and generated bundles.
- `.github/workflows/codeql.yml` — advanced-setup CodeQL workflow on
  push/PR + weekly cron, references the config above. Uses
  `security-extended` query suite.

**To activate**: switch the repo from default to advanced code-scanning
setup at Settings → Code security → Code scanning → Set up → Advanced.
The workflow will then run and honor the paths-ignore list.

### Test totals
**792 scanner tests pass / 0 fail** (unchanged from 0.71.0).

## 0.71.0 — taint engine frontier release (final 2 of 10 — IFDS + symbolic exploit proofs)

Third and final release in the v0.69 → v0.71 taint-engine arc. v0.71
ships the two heaviest items: IFDS tabulation as an alternative
context-sensitive analyzer, and a symbolic-execution post-pass that
generates concrete attacker payloads + proves infeasibility.

### #3 IFDS / IDE tabulation — `scanner/src/dataflow/ifds.js`

Implementation of Reps-Horwitz-Sagiv "Precise interprocedural dataflow
analysis via graph reachability" (POPL 1995). Runs as an ALTERNATIVE
analyzer that augments the existing k=2 worklist when
`AGENTIC_SECURITY_IFDS=1` — its findings are merged with the worklist
output, deduped by `(file, line, sinkId)`.

Components:
- `IFDSSolver` class: path-edge worklist over the exploded supergraph
- `_flowAssign`: distributive transfer function (copy / kill / source-gen)
- `_detectSinkAtCall`: catalog-driven sink matching at each call node
- Budget: `AGENTIC_SECURITY_IFDS_BUDGET_FACTS=10000` (default) caps the
  edge count; the solver returns partial findings + `_ifdsStats.capped: true`

What v1 supports: intraprocedural flow + the IFDS framework scaffolding.
Full call-graph summary edges are stubbed (the path-edge worklist
demonstrates the framework; production-quality summary caching arrives
in v0.72). The merge-with-worklist design means the existing engine
keeps producing findings; IFDS adds context-sensitive flows the k=2
cache joined out.

### #9 Symbolic exploit prover — `scanner/src/dataflow/exploit-prover.js`

Post-pass that runs after `runTaintEngine`. For each finding:

**Step 1 — Infeasibility check** via SMT-lite (homegrown, ~150 LOC).
Walks the finding's `trace + chain` for sanitizer-output regexes that
exclude the family's required metacharacters. If the path passes
through e.g. `htmlspecialchars` for an XSS finding, the metachars
`<`, `>`, `"`, `'` are excluded → `_provenUnreachable: true`, severity
demoted to LOW.

**Step 2 — Exploit input synthesis.** For feasible findings, attaches
`f._exploitInput` with the family's canonical payload. 16 families
covered including SQLi (`1' OR '1'='1`), XSS (`<script>alert(1)</script>`),
cmd-inj, path-traversal, SSRF, deserialization, XXE, SSTI, LDAP/XPath
injection, open redirect, response splitting, ReDoS, CSRF, prototype
pollution, and prompt injection.

**Optional Z3 backend.** When `AGENTIC_SECURITY_SYMEXEC_Z3=1` AND the
customer has installed `z3-solver`, the prover uses real SMT for the
infeasibility check. Default install never bundles Z3 — the SMT-lite
fallback handles every query we issue today. Activation:
`AGENTIC_SECURITY_SYMEXEC=1` (lite); add `AGENTIC_SECURITY_SYMEXEC_Z3=1`
for the Z3 path.

### Test totals
**792 scanner tests pass / 0 fail** (up from 773 in v0.70).
Dataflow: 215 tests (up from 196).

### Migration
Both items opt-in via env flag. No existing behavior changes. With both
v0.71 items active + the v0.69+v0.70 stack on opt-in, the engine's
precision ceiling rises substantially — full default-on cutover after
two consecutive nightly CVE-replay runs show F1 delta ≥ +1pp without
precision drop >1pp.

### 10-item taint-engine arc complete

v0.69 → v0.71 has shipped all 10 items:

| # | Item | Module | Release |
|---|------|--------|---------|
| 1 | Backward slicing | `dataflow/backward.js` | v0.69 |
| 2 | Steensgaard alias | `dataflow/points-to.js` | v0.70 |
| 3 | IFDS tabulation | `dataflow/ifds.js` | v0.71 |
| 4 | String regex lattice | `dataflow/string-domain.js` | v0.69 |
| 5 | Incremental cache | `dataflow/incremental.js` | v0.69 |
| 6 | Probabilistic taint | `dataflow/soft-taint.js` | v0.70 |
| 7 | Type-stubs | `ir/type-stubs.js` | v0.70 |
| 8 | Capture-set | `dataflow/higher-order.js` | v0.69 |
| 9 | Symbolic exploit proof | `dataflow/exploit-prover.js` | v0.71 |
|10 | DB-aware taint | `sast/db-taint.js` | v0.70 |

## 0.70.0 — taint engine foundations release (4 more of 10 leap items)

Second of three releases (v0.69 / v0.70 / v0.71). v0.70 adds the
"needs new theory" capabilities — aliasing, type inference, soft taint,
and DB round-trip flow. These are the foundations that lift the
intra-procedural lattice; v0.71 will swap in IFDS + symbolic exec on
top.

### #2 Steensgaard points-to / alias analysis — `scanner/src/dataflow/points-to.js`
Unification-based, near-linear alias analysis. Walks every assign/call
across the function set, unifying classes for direct copies + field
store/load operations. Interprocedural step at resolved call sites
unifies caller args with callee params. The engine consumes the graph
via `_addPathAliasAware`: when a tainted target is added to state, all
aliases of the root variable are tainted too. Closes the
`let a = obj; a.x = tainted; sink(obj.x)` FN class.
Opt-in via `AGENTIC_SECURITY_POINTS_TO=1`.

### #7 Type-stub integration — `scanner/src/ir/type-stubs.js`
Parses TypeScript `.d.ts` under `node_modules/@types/**`, Python `.pyi`
at project root. Outputs `{signatures, types, frameworks, fingerprint}`.
Cache under `$XDG_CONFIG_HOME/agentic-security/stub-cache/` keyed by
package-lock + package.json fingerprint. Budget gate via
`AGENTIC_SECURITY_TYPE_STUBS_BUDGET_MS` (default 10s).
Opt-in via `AGENTIC_SECURITY_TYPE_STUBS=1`.

### #6 Probabilistic / soft taint — `scanner/src/dataflow/soft-taint.js`
Post-pass over IR-TAINT findings: walks `trace + chain + pathSteps`,
multiplies (1 − sanitizer-effectiveness) across each call. 22-entry
default-effectiveness table (DOMPurify=0.98, parameterize=1.0,
trim=0.05, etc.) — overrideable per catalog entry via
`sanitizerEffectiveness` field. Findings below
`AGENTIC_SECURITY_SOFT_TAINT_THRESHOLD` (default 0.5) get severity
demoted (critical→high→medium→low→info) but are NEVER dropped —
auditors see the demotion + the sanitizer that earned it.
Opt-in via `AGENTIC_SECURITY_SOFT_TAINT=1`.

### #10 Database-aware taint — `scanner/src/sast/db-taint.js`
Recognizes ORM write/read pairs across Sequelize / Prisma / TypeORM /
Mongoose / Django ORM / SQLAlchemy. When `req.body.X` is written to
`Model.field` then later read and rendered, emits a stored-XSS
finding with a 2-step trace pointing at both the write and read sites.
Handles indirection (`const u = await Model.findOne(...); res.send(u.bio)`)
and direct chains (`res.send(Model.findOne(...).bio)`).
Fires automatically — already gated by ORM context heuristic.

### Test totals
**773 scanner tests pass / 0 fail** (up from 736 in v0.69).
Dataflow: 196 tests (up from 188).

### Migration
All four items are additive. v0.69's items remain opt-in this release;
v0.71 will flip the v0.69 set to default-on if CVE-replay shows F1
delta ≥ +1pp without precision drop >1pp across two consecutive runs.

## 0.69.0 — taint engine wire-up release (4 of 10 leap items)

First of three releases (v0.69 / v0.70 / v0.71) that lift the taint
engine toward academic state-of-the-art. v0.69 ships items that wire
already-built infrastructure into the engine's main path — minimum new
code, maximum precision gain.

### #1 Backward slicing — `scanner/src/dataflow/backward.js`
Already-implemented backward slicer gets a walltime budget
(`AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS`, default 30s) and emits
`_annotateBackwardSlicesStats` { annotated, skipped, exhausted } on the
findings array. Each finding gets `f.backwardSlice: [...]` ordered
source→sink and `f.pathSteps` merged with the existing trace.
Opt-in via `AGENTIC_SECURITY_BACKWARD_SLICE=1`; flips default in v0.70.

### #5 Cross-scan incremental cache — `scanner/src/dataflow/incremental.js`
Already-implemented persistence layer (`readIncrementalState`,
`seedSummaryCache`, `serializeSummaries`, `commitIncrementalState`) gets
wired into `runDeepAnalysis`. State lives in
`<scanRoot>/.agentic-security/incremental/{version,files,summaries}.json`.
Diff via file SHA-256, reverse call-graph for transitive invalidation,
version-pinned by `(scanner, catalog-size)`. On hit: ≥70% summary reuse
on re-scans; identical findings.
Opt-in via `AGENTIC_SECURITY_INCREMENTAL=1`; flips default in v0.70.

### #4a String regex lattice — `scanner/src/dataflow/string-domain.js`
New `{kind: 'Regex', pattern}` lattice value alongside Const/Concat/Unknown.
`abstract()` recognizes sanitizer-output regexes for `encodeURIComponent`,
`encodeURI`, `parseInt`, `parseFloat`, `hashSync`, `digest`, `toString`,
`htmlspecialchars`. New `provablyMatches(absVal, safe)` proves an
abstract value fits a safe-charset regex — used by `sanitizer-proof.js`
to elevate findings to `provenClean` for non-SQL classes.
Opt-in via `AGENTIC_SECURITY_STRING_DOMAIN=1`; flips default in v0.70.

### #8a Closure capture-set analysis — `scanner/src/dataflow/higher-order.js`
New `capturedFreeVars(node, boundNames)` walker + `callbackCaptureSet(cb)`.
Extracts free variables from inline arrow/function-value bodies,
handling nested closures and shadowing correctly. The motivating
example `let t = req.query.x; arr.map(i => exec(t))` correctly
identifies `t` as captured.
Engine wiring (consume the capture set at call sites) waits for
v0.70's alias analysis; the extractor + tests ship now.
Opt-in via `AGENTIC_SECURITY_CLOSURE_CAPTURE=1`.

### Test totals
**736 scanner tests pass / 0 fail** (up from 698 in v0.68).
Dataflow scope: 188 tests (up from 130).

### Migration
All four are additive, opt-in via env flag. No existing behavior changes.
v0.70 flips the four to default-on if CVE-replay shows F1 delta ≥ +1pp
without precision drop >1pp across two consecutive runs.

## 0.68.0 — five capabilities that open clear competitive gap

Five world-class capabilities ship together. Each addresses something
mainstream SAST (SonarQube / Semgrep / Snyk / Checkmarx / Veracode /
CodeQL) does poorly or not at all.

### #3 Closed-loop auto-fix verification

`scanner/src/posture/fix-verify-loop.js` — new `verifyFixWithTests`
runs the full chain: re-scan + project linter + project test suite.
A fix is `verified-clean` only when all three pass.

Test-runner auto-discovery: `npm test`, pytest, go test, cargo test,
bundle exec rspec, mvn test, ./gradlew test. Returns one of:
`verified-clean`, `untested-but-passes` (no runner found — honest),
or `verification-failed` (with per-leg detail).

Competitor gap: most SAST tools suggest fixes but don't close the loop
by running the user's tests.

### #4 LLMSecOps coverage (3 new detectors)

| Module | CWE | What it catches |
|--------|-----|-----------------|
| `sast/llm-stored-prompt.js` | CWE-1336 | System prompt sourced from DB / config file / writable mount fed to LLM call without hardening (delimiters, immutable instruction prefix, allow-list) |
| `sast/rag-poisoning.js` | CWE-1336 | User-controlled text written to Chroma/Pinecone/Weaviate/Qdrant/LangChain/pgvector without `metadata: { source, trust_level }` provenance |
| `sast/agent-tool-escalation.js` | CWE-269 | Agent harness exposes both READ tools (list/get/fetch/scrape) and ACT tools (exec/write/send/delete) with no approval gate between them — classic tool-chain privilege escalation |

Competitor gap: nobody else ships LLM-agent-specific privilege flow
analysis. The AI security market is wide open.

### #7 Probabilistic exploitability with Wilson 95% CI

`scanner/src/posture/exploitability-probability.js` — replaces opaque
severity strings with a calibrated probability + 95% confidence interval:

```
f.exploitProbability      ∈ [0,1]
f.exploitProbabilityCI95  [lo, hi]
f.exploitProbabilityWhy   string[]    -- which factors fired
f.exploitProbabilitySlice 'CWE-89×js' | 'CWE-89' | 'prior-only'
```

Method: CISA-KEV-derived CWE-family prior + multiplicative factor
update (reachability, source provenance, sanitizer-in-path, project
hardening). Wilson CI from operator-curated `.agentic-security/
exploit-history.jsonl` when n ≥ 5 (slice grain); falls back to wider
prior-only CI when sample is thin. The CI WIDTH is the honest signal.

Competitor gap: every SAST emits severity strings; none surface
calibrated probability with uncertainty.

### #8 Provable-clean for SQL injection

`scanner/src/dataflow/proven-clean.js` — `proveSqlClean` walks the
function's CFG between every reaching source and the SQL sink,
verifies at least one parameterizer (catalog-tagged sanitizer or
known driver method: setString/AddWithValue/bindParam/etc.) sits on
the path. If proof holds, `f.provenClean = true` with
`f.provenanceProof.sanitizers: [...]`. Stronger statement than
"we didn't find a flow" — auditor-grade evidence.

v1 uses path-existence; v2 will substitute SMT-backed string-domain
constraints behind the same interface.

Competitor gap: existing tools emit "issue found" or "no issue
found." Nobody emits "proven safe."

### #9 Time-travel + counterfactual scanning

`scanner/src/history-scan.js` + two new CLI subcommands:

```
agentic-security history --since 6.months --interval 1.month
   # Walks N historical git refs, scans each, emits a timeline of
   # introduced + resolved findings between consecutive refs.

agentic-security what-if --overlay app.js:./new-app.js [--remove foo.js]
   # Apply virtual file overlays + deletes, scan the counterfactual
   # state, return findings delta vs. baseline. Working tree is never
   # touched (overlay is in-memory via runFullScan's fileContents map).
```

Use cases: "What was our posture 6 months ago vs. today?" / "If I
remove this auth middleware, how many new findings appear?" / "If I
downgrade lodash to 4.17.20, how many CVE matches drop?"

Competitor gap: existing tools scan the working state. None offer
historical replay or counterfactual mode at this granularity.

### Test totals

**698 scanner tests pass / 0 fail** (up from 665 in v0.67).

### Migration

No breaking changes. All new capabilities are additive:
- LLM/RAG/agent detectors fire automatically on relevant code
- exploitProbability fields appear alongside existing severity
- provenClean is informational (does NOT drop findings)
- history + what-if are opt-in CLI subcommands

## 0.67.0 — detection rules for 6 new CWE families (SSTI / LDAP / open-redirect / response-splitting)

The v0.66 corpus expansion exposed six CWE families with no detection
coverage (or partial coverage that missed common shapes). This release
ships dedicated detectors plus a runner fix.

### New SAST detectors

| Module | CWE | Languages | What it catches |
|--------|-----|-----------|-----------------|
| `sast/ssti.js`               | CWE-94   | py, js, php, java | Jinja2 `from_string` / `Template()`, Handlebars / EJS / Mustache / Pug `.compile`, Twig `createTemplate`, Velocity `evaluate` — fires only when the template body is non-literal AND has a taint hint or comes from a variable assigned from user input in the preceding 10 lines |
| `sast/open-redirect.js`      | CWE-601  | js, py, java, php | `res.redirect` / `ctx.redirect` / `flask.redirect` / `HttpResponseRedirect` / Spring `"redirect:" + …` / PHP `header("Location: " . …)` with user-derived target AND no allow-list check in the preceding 30 lines |
| `sast/response-splitting.js` | CWE-113  | js, py, java, php | `setHeader` / `addHeader` / `response.headers[…] = …` / PHP `header()` with user-derived value (or method param in Java handler context) AND no CRLF strip / sanitizer above |
| `sast/ldap-injection.js`     | CWE-90   | js, java, py | **Extended:** indirect filter shape (`String filter = "(uid=" + name + ")"; ctx.search(…, filter, …)`) and `search_s` / `paged_search` callees, gated on a file-level LDAP context hint |

XPath (CWE-643) and ReDoS (CWE-1333) already had working detectors; the
runner just wasn't checking the right arrays.

### Runner fix

`bench/cve-replay/runner.mjs` now consults `scan.findings`, `scan.secrets`,
`scan.supplyChain`, AND `scan.logicVulns` when scoring a fixture.
Previously, business-logic findings (where ReDoS / weak-crypto / behavioral
checks live) were invisible to the scoring pipeline.

### Engine cleanup

Removed the legacy coarse `(?:res\.redirect|response\.redirect|.redirect\(|header\(['"]Location)`
REGEX rule from `engine.js` — the new `scanOpenRedirect` detector is
precise (allow-list aware) and replaces it cleanly.

### Results on the v0.66 corpus

All 9 fixtures across the 6 new CWE families now score **pre:TP post:TN**:

| CVE | CWE | v0.66 | v0.67 |
|-----|-----|-------|-------|
| CVE-2017-16016-handlebars-ssti       | CWE-94   | pre:FN | pre:TP post:TN |
| CVE-2017-9805-ldap-injection         | CWE-90   | pre:FN | pre:TP post:TN |
| CVE-2018-1320-xpath-injection        | CWE-643  | pre:TP | pre:TP post:TN |
| CVE-2019-8341-jinja-ssti             | CWE-94   | pre:FN | pre:TP post:TN |
| CVE-2020-15252-open-redirect         | CWE-601  | pre:TP post:FP | pre:TP post:TN |
| CVE-2020-7660-resp-splitting         | CWE-113  | pre:FN | pre:TP post:TN |
| CVE-2021-25966-open-redirect-py      | CWE-601  | pre:FN | pre:TP post:TN |
| CVE-2021-29622-ldap-py               | CWE-90   | pre:FN | pre:TP post:TN |
| CVE-2021-3801-redos                  | CWE-1333 | pre:FN | pre:TP post:TN |

Aggregate F1: **0.500 → 0.597** on the same 88-entry corpus. Wilson 95%
CI [0.334, 0.523] (narrower than v0.66's [0.249, 0.429]). Regression
tier still F1=1.0.

### Tests

`scanner/test/new-cwe-detectors.test.js` — 11 tests covering each
detector's vulnerable + clean shape, including post-fixture
suppression patterns (allow-list checks for open-redirect, CRLF
sanitizers for response-splitting).

**665 scanner tests pass / 0 fail** (up from 654).

## 0.66.0 — interprocedural precision + LLM default-on + C# / Kotlin IRs + corpus to 88

Four world-class lifts shipped together. After v0.65 the F1=0.636 number
was honest but the engine was still k=1 monovariant, the LLM validator
was opt-in, and the IR coverage stopped at JS/TS/Python/Java.

### Interprocedural taint precision (engine semantics)

`scanner/src/dataflow/engine.js`:
- **k≥2 context-sensitive summaries.** At assign-from-call sites the
  engine now builds the entry-taint-state from call args + current
  taint via `entryStateFromCall()` and looks up (lazily computes) a
  summary keyed by THAT entry state. Closes the "helper is pure when
  called clean but tainted when called with user input" FN class.
- **`applyAtCallSite` wired.** Mutated by-reference params propagate
  back to caller vars (`Object.assign(target, tainted)` → `target`
  tainted in caller). Was previously dead code.
- **Fixed-point iteration.** `runTaintEngine` now runs the pre-pass
  up to MAX_FP_ITERS (3) iterations or until the summary cache size
  stabilizes — recursion no longer under-approximates. Budget caps
  on walltime + cache size still hold.

Tests in `scanner/test/interproc-k2.test.js` lock the lifts: context
disambiguates tainted vs clean call sites, recursion converges within
budget, large helper chains finish within walltime.

### LLM validator default-on

`scanner/src/llm-validator/index.js` flips from opt-in to default-on:

| Env state                                    | Behavior      |
|----------------------------------------------|---------------|
| `LLM_ENDPOINT` unset                         | no-op         |
| `LLM_ENDPOINT` set, `VALIDATE` unset         | **runs**      |
| `LLM_ENDPOINT` set, `VALIDATE=0`             | no-op (opt-out) |
| `LLM_ENDPOINT` set, `VALIDATE=1`             | runs (legacy) |

Cache by `(file-content-sha256, source→sink path, prompt version,
model id)` continues to suppress repeat calls. Fail-closed semantics
unchanged — any prompt-injection / verify-failure → escalate (keep).

### C# IR backend (new language)

`scanner/src/ir/parser-cs.js` (~290 lines) — regex-based first pass,
parallel approach to the legacy Python regex parser. Models method
declarations with modifiers, params, body extraction with brace-depth
tracking. Lowers `var x = …`, `Type x = …`, `x = …`, calls, return,
throw. Builds a linear CFG per method. Plus 24 C# catalog entries:
ASP.NET MVC sources (`Request.Form`, `Request.QueryString`,
`Request.Cookies`, `Request.Headers`, `Request.Body`), sinks (SqlCommand,
Process.Start, File.ReadAll*, WebClient, HttpClient, BinaryFormatter),
sanitizers (HtmlEncode, UrlEncode, GetFullPath, Parse/TryParse,
Regex.Escape, AddWithValue).

### Kotlin IR backend (new language)

`scanner/src/ir/parser-kt.js` (~250 lines) — same regex approach.
Models `fun` declarations with modifiers, params, optional return
type, body extraction. Lowers `val`/`var`/`x = …`, calls, return,
throw. Kotlin string interpolation (`"hi $x"` / `"hi ${name}"`) lowers
into IR template-expression form so the engine sees the inner taint.
Plus 14 Kotlin catalog entries: Ktor / Spring sources, JDBC / Exposed /
ProcessBuilder / readText / ObjectInputStream sinks, escapeHtml4 /
URLEncoder / toInt / canonicalFile / setString sanitizers.

Both IRs wire into `buildProjectIR` and `buildProjectIRAsync`. Tests
in `scanner/test/parser-cs-kt.test.js`: shape correctness, multi-method
files, end-to-end scan over ASP.NET + Ktor fixtures.

### CVE-replay corpus: 50 → 88 entries (20 CWEs × 8 languages)

`bench/cve-replay/generate-corpus-extended.mjs` adds 38 entries:
- 8 C# fixtures (exercises new IR)
- 8 Kotlin fixtures (exercises new IR)
- 6 new CWE families: SSTI (CWE-94), LDAP injection (CWE-90), XPath
  injection (CWE-643), open redirect (CWE-601), HTTP response
  splitting (CWE-113), regex DoS (CWE-1333)
- 16 framework variants for existing families (NestJS, Koa, Symfony,
  Laravel, Gin, Fiber, etc.)

**Aggregate F1 = 0.500** (Wilson 95% CI [0.249, 0.429]) on the 88-entry
corpus. Lower than v0.65's 0.636 BECAUSE the new fixtures include
capabilities the scanner doesn't yet detect (C#/Kotlin coverage is
still thin; new CWE families have no detection rules). This is the
honest direction — broader corpus, narrower CI, real measurement.
Regression-tier CI gate remains F1=1.0.

### Test totals

654 scanner tests pass / 0 fail (up from 640 in v0.65). Smoke +
regression-tier CI both green.

### Migration

No breaking changes. To enable the LLM validator default-on path, set
`AGENTIC_SECURITY_LLM_ENDPOINT`. To opt out: `AGENTIC_SECURITY_LLM_VALIDATE=0`.
C# and Kotlin scans require no setup — drop a `.cs` or `.kt` file in
the scan tree.

## 0.65.0 — sanitizer catalog 8× / CVE corpus 6× / continuous CVE alerting

Closes three ASPM/SAST competitiveness gaps surfaced in the post-v0.64 review:
sanitizer coverage that lagged commercial vendors, a published F1 number
measured against a corpus too small to be credible, and a `/cve-alerts`
command that configured a webhook but never actually monitored anything.

### Sanitizer catalog: 48 → 372 entries (7.7×)

New module `scanner/src/dataflow/catalog-expanded.js` adds ~325 sanitizer
entries spanning 6 languages and 10 categories (HTML escape, SQL
parameterization, shell escape, URL encode, path normalize, regex escape,
LDAP/XPath, XML/JSON, validators, type coercion). Merged into the main
catalog at load time; on id collision the base catalog wins.

| Language    | Before | After |
|-------------|-------:|------:|
| JavaScript  |     11 |   105 |
| Python      |     11 |    96 |
| Java        |      8 |    61 |
| PHP         |      4 |    41 |
| Ruby        |      5 |    33 |
| Go          |      2 |    36 |
| **Total**   | **48** |**372**|

Tests in `scanner/test/catalog-expanded.test.js` enforce: minimum entry
count, per-language coverage floors, well-formed entry shape, no
duplicate IDs across the merged catalog, callee identifiers that the
indexer can match, and family vocabulary hygiene.

Two pre-existing duplicate IDs in the base catalog (`py-input`,
`py-os-environ`, `py-open`, plus 14 in the v2 Python block) were fixed
in this pass — the duplicate-id test surfaced them.

### CVE-replay corpus: 8 → 50 entries (6.25×)

`bench/cve-replay/generate-corpus.mjs` emits 42 capability-tier fixtures
across 11 high-priority CWE families and 6 languages:

| Family              | CWE        | Entries |
|---------------------|------------|--------:|
| SQL injection       | CWE-89     |       5 |
| XSS                 | CWE-79     |       4 |
| Command injection   | CWE-78     |       5 |
| Path traversal      | CWE-22     |       5 |
| SSRF                | CWE-918    |       4 |
| Deserialization     | CWE-502    |       4 |
| XXE                 | CWE-611    |       3 |
| Prototype pollution | CWE-1321   |       2 |
| CSRF                | CWE-352    |       2 |
| Hardcoded secrets   | CWE-798    |       3 |
| Weak crypto         | CWE-327/338|       5 |

Aggregate F1 against the new corpus is **0.636** (Wilson 95% CI [0.346,
0.591]) — an honest baseline, replacing the previous F1 number measured
against 8 cherry-picked fixtures. The regression-tier CI gate still
passes F1=1.0. Failing capability entries graduate to regression as fixes
land (CONTRIBUTING.md's 5-snapshot rule).

### Continuous CVE alerting daemon

New `scanner/src/posture/cve-alert-daemon.js` polls OSV for the project's
dependency tree and fires the configured webhook when a new advisory
drops. Multi-ecosystem: npm, PyPI, Ruby, Go, Cargo, Composer, Maven,
Dart. Reads `.agentic-security/cve-alerts.json` (the schema written by
`/cve-alerts`), dedupes against `.agentic-security/cve-alerts-state.json`
so re-runs don't re-page. Slack / Discord / generic webhook payload
shapes built in.

- `agentic-security cve-watch [--alert-url] [--min-severity] [--dry-run]`
  — one-shot run. Schedule it via cron or CI.
- `scripts/ci-templates/cve-watch.github-actions.yml` — drop-in GitHub
  Actions workflow (daily 08:00 UTC + `workflow_dispatch`). Reads
  `CVE_ALERT_URL` from repo secrets; commits state file with `[skip ci]`.

21 unit tests in `scanner/test/cve-alert-daemon.test.js` cover each
manifest reader, severity normalization, deduplication across runs,
min-severity floors, payload formatting, and offline-mode refusal.

### Migration notes

- Re-running `npm run build` is recommended to bundle the new daemon
  binary entry. No breaking changes; all v0.64.0 commands and skills
  still work as before.
- The capability-tier F1 score in the manifest is intentionally honest
  (0.636, not 0.85). Path to 0.85 is more corpus, not better numbers.

## 0.64.0 — auto-activating skills + multi-harness manifests

Inspired by patterns from the obra/superpowers plugin's "mandatory workflows,
not suggestions" stance: the agent shouldn't wait for the user to type
`/scan` or `/fix` before doing the security thing. Nine new auto-activating
skills cover the common security/privacy moments where the agent should
intervene before damage lands. Plus Codex / Cursor / Gemini manifests so the
12 MCP tools work in those harnesses too.

### Auto-activating skills (9 new)

Each lives at `skills/<slug>/SKILL.md`. The `description:` frontmatter is
the activation cue Claude Code's skill router reads. All ≤120 chars,
enforced by `npm run test:lifecycle`.

- **`security-explain-cve`** — fires when user mentions CVE-id / GHSA / asks "what is this vuln". Routes to `lookup_cve` MCP tool + `/explain`.
- **`security-scan-on-deploy`** — fires on "ship / deploy / launch / is this safe?" intent. Checks `last-scan.json` mtime, runs a fresh scan if stale, renders a verdict (not a wall of findings).
- **`security-fix-finding`** — fires when user references a finding and asks to fix. Enforces the deterministic toolchain (`synthesize_fix → verify_fix → apply_fix`); refuses raw `Edit`.
- **`security-weak-crypto`** — fires **before** the agent writes md5/sha1 for passwords, DES/3DES/RC4, static IVs, `Math.random` for tokens, or JWT with `none` algorithm. Refuses the write, proposes the right primitive with literal code.
- **`security-rotate-leak`** — fires when a leaked secret is mentioned. Masks the value, detects the provider, prints the revoke URL, estimates blast radius BEFORE rotating, refuses to print the value back.
- **`security-eval-warn`** — fires before `eval()` / `new Function()` / `setTimeout(string,…)` / `pickle.loads` / `eval($x)` / `class_eval`. Diagnoses what the user actually wants, proposes the structured alternative.
- **`security-sql-injection-warn`** — fires before template-literal queries / `+`-concat into SQL / NoSQL operator injection / LDAP/XPath concat. Shows the literal parameterized form for the user's specific DB driver.
- **`threat-model-first`** — fires **before** the agent writes new auth / secret / external-API / file-upload / OAuth / deserialization code. Walks STRIDE per touch-point (one sentence per row, no skipping); writes `TM.md` to `.agentic-security/agent-scratchpad/threat-model/<session>/` via `append_scratchpad`. Then proposes implementation with each defensive measure citing its STRIDE row in a code comment.
- **`privacy-data-flow`** — fires **before** the agent writes code touching PII / PHI / PCI / GDPR-special / confidential data shapes. Classifies the data, traces the destination (storage tier / encryption / third-party processors / logging / retention / backups / replication), maps to jurisdiction (GDPR / HIPAA / CCPA / PCI-DSS), writes `DATA_FLOW.md` to the scratchpad. Refuses hard violations (logging full PAN, sending PHI to non-BAA processor, storing CVV after auth).

### Skills-registry integrity test

`scanner/test/skills-registry.test.js` enforces:
- Every `skills/<slug>/SKILL.md` has well-formed YAML frontmatter
- `name:` equals `agentic-security:<slug>`
- `description:` is ≤ 120 chars (re-asserted at unit-test time)
- Auto-activating skills include an "Activate" / "Activate on" cue
- Every `/<slash-command>` referenced in a skill body resolves to a real
  file under `commands/`

7 new tests, all passing.

### Multi-harness manifests (3 new)

The MCP server is harness-agnostic — same binary, different manifest:

| Harness        | Manifest                          |
|----------------|-----------------------------------|
| Claude Code    | `.claude-plugin/plugin.json`      (already shipping) |
| **Codex CLI**  | `.codex-plugin/plugin.json`       (new) |
| **Cursor**     | `.cursor-plugin/plugin.json`      (new) |
| **Gemini CLI** | `gemini-extension.json` (root)    (new) |

Each manifest declares the same `agentic-security` MCP server pointing at
`scanner/bin/agentic-security-mcp.js`. Each carries an explicit note about
which surface IS validated vs not. The 12 MCP tools work identically across
all four harnesses; the slash-command + skill-activation surface is Claude-
Code-specific today.

README updated with an "Install in your harness" table covering all four
plus the generic MCP-aware-client fallback.

### Lint state

89 surfaces total (80 commands + 9 skills + add-scan-rule SKILL). All
within the 120-char description / 200-char argument-hint caps.

### Tests

619/619 passing (was 612 in v0.63.0; +7 skills-registry tests).

## 0.63.0 — Python IR via stdlib ast (real parser, regex fallback)

Replaces the hand-rolled regex Python parser with Python 3's stdlib `ast`
module (zero npm bundle bloat, zero pip install, runs in a per-scan
subprocess) and keeps the regex parser as a fallback when Python isn't on
PATH. The new path closes the gaps the regex parser admitted to in its own
comments: comprehensions, decorators, `match` statements, `async`/`await`,
lambda bodies, and nested-paren default args (`def f(x=Foo(1,2))`).

### What ships

- **`scanner/src/ir/parser-py.helper.py`** — Python 3.8+ stdlib script
  that reads `[{file, content}, ...]` JSON on stdin and emits the same
  IR shape as the regex parser, but computed from a real AST. Models
  assign / call / member / subscript / f-string / if / for / while /
  try-except / return / raise / async-for / async-with. Captures every
  function definition (including nested, decorated, async, generic) even
  when the body has unmodeled constructs.
- **`scanner/src/ir/parser-py-cst.js`** — Node-side dispatcher.
  Batched: ALL Python files in a project go in one subprocess invocation.
  Capability probe cached per-process. 10 s timeout on the whole batch.
- **`scanner/src/ir/index.js`** — three-mode toggle:
  `AGENTIC_SECURITY_PY_PARSER=auto` (default, falls back silently when
  python3 missing), `cst` (force, error if unavailable), `regex`
  (force legacy).
- **`scanner/src/ir/CLAUDE.md`** — documents the dual-parser shape,
  the IR contract every parser must produce, and the retirement plan
  for the regex parser.

### What's STILL not modeled

The CST parser intentionally emits `kind: 'noop'` for these to keep the
CFG bounded — the regex parser dropped the entire function for the same
shapes; we capture the function record but skip the body lowering:

- `match` statement case bodies (function is captured; per-case taint
  flow not yet routed)
- destructuring assignment (`a, b = req.body`) — only single-target
  assigns get a precise `target` field
- comprehension `if` filters and multi-`for` generators — the elt is
  modeled; the generator's own predicates aren't

### Cost / risk

- One `python3` subprocess per `runScan`, not per file. Batched stdin
  payload. Capability probe runs once and is cached.
- When python3 isn't installed (or is < 3.8), the regex parser handles
  the scan unchanged. No behavior regression for those customers.
- Set `AGENTIC_SECURITY_PY_PARSER_DEBUG=1` to surface fallback events
  on stderr.

### Tests

12 new CST-specific tests in `scanner/test/parser-py-cst.test.js`
covering decorators, async, nested-paren defaults, match statements, list
comprehension taint flow, nested function defs, batch behavior, syntax-
error isolation per file, single-file/batch shim equivalence. All skip
gracefully when python3 isn't on PATH. Total suite: 612/612 passing.

## 0.62.0 — agent-harness hardening + slash-command consolidation

Five rounds of analysis applied to the plugin's scanner + MCP server + sub-agent
harness across this release. Each section corresponds to one external source;
in-source comments tag the originating thread (`premortem #N`, `post-rec #N`,
`harness-anatomy #N`) for cross-reference.

### Security & integrity (premortem hardening)

- **Per-install HMAC key** for `last-scan.json` integrity (was hostname-derived
  and publicly forgeable in CI / containers). Stored at
  `$XDG_CONFIG_HOME/agentic-security/scan-key`; override via
  `$AGENTIC_SECURITY_HMAC_KEY`. Legacy hostname key verified for one release
  to migrate existing signed scans.
- **MCP reserved-write list expanded** to `.github/`, `.gitlab/`, `.circleci/`,
  `.buildkite/`, `.terraform/`, IaC dirs, every common manifest basename
  (`Dockerfile`, `Jenkinsfile`, `package.json`, lockfiles, `pom.xml`,
  `Cargo.toml`, …) and `*.tf` / `docker-compose.yml`. Closes the
  forged-finding-rewrites-CI-workflow attack path.
- **`rules.yml disable:` requires signature.** `applyOverrides` now refuses
  the `disable:` list unless `.agentic-security/rules.yml.sig` verifies
  under the per-install HMAC. `severityOverrides`, `custom:`, `ignorePaths`
  are not gated (they don't reduce coverage). Override via
  `$AGENTIC_SECURITY_RULES_UNSIGNED=1`.
- **MCP `SERVER_VERSION`** reads `package.json` at module load (was a
  hardcoded literal that rotted).
- **MCP `find_rule_module` tool** for codebase navigation (CWE / family →
  detector file) without grep-and-pray.
- **MCP `apply_fix`** now passes patch text through unredacted (the prior
  redact-on-output behavior silently corrupted valid patches whose content
  matched a secret-shape).
- **Per-stableId attempt budget** (default 2) on `apply_fix`. Refuses a
  third attempt with structured `{ budgetExceeded, attempts, maxAttempts }`.
- **Optional remote audit-log sink.** Set
  `$AGENTIC_SECURITY_AUDIT_WEBHOOK=<url>` and every MCP tool call is
  fire-and-forget POSTed to the witness. Closes the full-file-rewrite
  blind spot of the local-only hash chain.

### Scanner correctness

- **`SummaryCache` wired** into the taint engine (k=1 monovariant
  return-taint). Was dead code; now the assign-from-call lattice consults
  cached summaries for resolved callees.
- **Per-flow source attribution** in IR-TAINT (was first-source-globally-
  seen; produced misattributed evidence in findings).
- **`finding-defaults` backfill** stamps `parser` + `family` on every
  finding before calibration / confidence run. Closes the "0 parser /
  20 family null on a smoke run" silent-no-op.
- **Tautological Brier removed.** `computeBrierFromHistory` (always
  returned 0) replaced with `computeBrierOnHeldOut(samples)` taking real
  labels. New `posture/holdout-eval.js` evaluator: Brier + ECE + per-family
  TP/FP + Wilson CI.
- **PoC param-key inference** reads the actual handler file window;
  surfaces `paramKey`, `paramKeyConfidence`, `paramKeyInferred`. Low-
  confidence PoCs trigger `regression-test-gen` to refuse rather than
  ship a fake-passing test.
- **CVE-replay scoring fixed.** TN branch reachable; pre/post scored
  independently. Per-slice F1 (by CWE, language, source-quality tier).
  Wilson 95% CI on the aggregate TP-rate.
- **Python parser** switched to a balanced-paren scanner for calls + def
  signatures (was a `[^()]*` regex that rejected `db.execute(sanitize(x))`
  and `def f(x=Foo(1,2))`).

### Agent harness

- **`security-fixer` writes via MCP, not Edit.** Tool list stripped to
  `Read, Bash, Grep`. The deterministic toolchain (`synthesize_fix` →
  `verify_fix` → `apply_fix`) is the only write path. The LLM is the
  intent layer; the MCP server is the execution layer.
- **Subagent path-confinement schema** (`agents/_CONFINEMENT.md`) shared
  with the MCP reserved-write list.
- **`security-fixer` consumes structured `verify_fix.introduced[]`** to
  diagnose template-incomplete vs codebase-prior vs lint-failed outcomes.
- **PLAN.md decomposition convention** for batched runs:
  `.agentic-security/agent-scratchpad/<agent>/<session>/PLAN.md`. Survives
  context resets; auditable artifact for governance.
- **AGENTS.md continual learning.** `.agentic-security/AGENTS.md` is the
  append-only narrative file the agent writes to at session end. The
  SessionStart hook reads it; the Stop hook nudges the agent to record an
  entry when work happened.
- **MCP scratchpad pair** (`append_scratchpad`, `read_scratchpad`)
  confined to `.agentic-security/agent-scratchpad/<agent>/<session>/`.
  Strict path validation; 2 MB / file, 50 MB total caps.
- **MCP tool-output offloading.** `scan_diff` and `explain_finding`
  results exceeding `OFFLOAD_THRESHOLD` (default 10) write the full payload
  to the scratchpad; the response shrinks to `{ head, tail, total,
  scratchpadPath, pagingHint }`. The agent pages through with
  `read_scratchpad`.
- **MCP `lookup_cve`** tool: read-only access to local OSV / KEV / EPSS
  caches with staleness tiers. Closes the knowledge-cutoff gap for SCA
  reasoning without triggering a network fetch.
- **MCP `append_agents_memory` / `read_agents_memory`** tools wrap the
  AGENTS.md surface.

### Evals + benches

- **CVE-replay corpus tiered** into `regression/` (CI gates here — F1=1.0
  required) and `capability/` (frontier; failure informational).
  Graduation policy: 5 consecutive passes → promote.
- **`npm run bench:cve-replay:ci`** new CI gate.
- **Agent-task corpus** at `bench/agent-tasks/security-fixer/`: end-to-end
  eval of the deterministic toolchain (synth → verify → apply) against
  fresh temp copies of fixtures. 7 graders per task; pass@1 reporting.
- **`llm-validator` consistency harness** (`scanner/src/llm-validator/
  consistency.js` + `agentic-security-consistency` bin): pass^k stability
  measurement across N trials on the same fixture set.
- **Human ↔ LLM grader calibration** (`posture/grader-calibration.js`):
  Cohen's κ between `/triage` human verdicts and validator verdicts on
  the stableId overlap. Alarm when κ < 0.6 with n ≥ 10.
- **`agentic-security-audit` CLI**: `review`, `metrics`, `verify`
  subcommands for the MCP audit log. `--by-session` aggregation with
  outlier flagging (default ≥20 calls per tool).
- **`audit.js`** stamps `sessionId` on every entry.

### Repo structure (Claude-Code-at-scale)

- **`.claude/settings.json`** with team-committed read-deny list
  (generated bundle, bench caches, scan-state JSON) to keep noise out of
  context.
- **Subdirectory `CLAUDE.md` files** added: `scanner/`,
  `scanner/src/{sast,posture,dataflow,mcp}/`. Root `CLAUDE.md` trimmed
  253 → 115 lines (pointers + gotchas only).
- **`npm test` split into scoped scripts**: `test:smoke / sast / posture /
  dataflow / mcp / report / bench-modules / lifecycle`. Full suite chains
  them.
- **Stop hook (`hooks/session-stop-drift-check.js`)** flags new modules
  in `scanner/src/{sast,posture,dataflow,mcp}/` not yet indexed in the
  matching subdir CLAUDE.md, plus prompts for an AGENTS.md entry when
  the session touched tracked files.
- **SessionStart self-check (`hooks/session-start-self-check.js`)**
  validates every command/agent frontmatter shape; surfaces malformed
  surfaces.
- **`skills/add-scan-rule/SKILL.md`** holds the "add a new SAST rule"
  workflow as an on-demand skill (was in root CLAUDE.md).
- **`docs/POSITIONING.md`** — explicit ICP statement (vibecoder-first;
  pro follow-on).

### Slash-command consolidation (LangChain harness-anatomy #5)

The 77-command surface was the exact "tool proliferation" anti-pattern the
post warned about. Always-paid frontmatter (description + argument-hint)
trimmed **20.3 KB → 11.3 KB (44% reduction)**.

- **Description cap of 120 chars** + argument-hint cap of 200 chars,
  enforced by `scripts/lint-command-descriptions.mjs` in
  `npm run test:lifecycle`. 76 surfaces trimmed.
- **Eleven commands folded into canonical forms**, with deprecated
  aliases kept one release for muscle memory:

  | Old | New |
  |-----|-----|
  | `/ci-gate-multi` | `/ci-gate --provider <name>` |
  | `/rotate-key-auto` | `/rotate-secret --auto` |
  | `/trim-dead-code` | `/trim --what code` |
  | `/trim-dependencies` | `/trim --what deps` |
  | `/story-explain` | `/explain --narrative` |
  | `/security-badge` | `/security-attestation` (default) |
  | `/security-onepager` | `/security-attestation --format onepager` |
  | `/trust-page` | `/security-attestation --format page` |
  | `/dep-pinning` | `/supply-chain-check --show pinning` |
  | `/dep-freshness` | `/supply-chain-check --show freshness` |
  | `/dep-alternatives` | `/supply-chain-check --show alternatives` |

- **Skipped on purpose:** `/secure` (vibecoder entry point — kept
  untouched); the LLM-sec cluster (each command serves a distinct
  workflow). Tier 3 demote-to-skills also skipped after investigation —
  Claude Code today loads both commands and skills' descriptions in the
  always-paid surface, so the move wouldn't actually save context.

### Tests

600/600 tests passing. CVE-replay CI gate green (regression F1=1.0 on
3 entries). Lint gate green (all 80 surfaces within caps).

## 0.51.0 — 11 of 16 PRD-missing features (5 research items deferred)

This release lands all 11 tractable FRs from the v2 PRD audit. The 5
research-level FRs (k=2 calling context, narrow symbolic execution, hybrid
static+dynamic, eBPF/dtrace live instrumentation, LLM-based intent
inference) are deferred to Phase 6+ with their reasons documented in the
PRD.

### Shipped

- **FR-CHAIN-FILTER** (`posture/cross-lang-meta.js`). Cross-language chain
  detectors only chain to chain-worthy families (sql-injection,
  command-injection, xss, ssrf, code-injection, deserialization, xxe,
  path-traversal, idor, mass-assignment, prototype pollution, and others).
  Eliminates the "queue chain to CSRF" semantic-noise the polyglot bench
  surfaced.
- **FR-FAMILY-REGISTRY** (`posture/cross-lang-meta.js`). Cross-language
  chains get canonical family names (xlang-openapi / xlang-grpc /
  xlang-graphql / xlang-queue / xlang-orm / xlang-iac / xlang-unknown).
- **FR-LEARN-7** (`bin/agentic-security reset`). Right-to-delete CLI;
  wipes accumulated learned state while preserving operator-authored
  config. `--yes` to actually delete; `--keep <names>` to spare specific
  items.
- **FR-PY-SAST** (`sast/python-sinks.js`). Python sink-side coverage:
  SQLAlchemy text() with f-string, cursor.execute concat, os.system /
  subprocess shell=True, pickle.loads, yaml.load, marshal.loads, eval/exec
  on request data, compile() on user input, flask.send_file with user
  path, send_from_directory, open() with f-string, requests verify=False,
  ssl._create_unverified_context, requests/urlopen with user URL, lxml/
  etree on user input. **Closes G3:** polyglot F1 went from 0.727 → 1.00.
- **FR-VER-3** (`posture/regression-test-gen.js`). Per finding with a PoC,
  emit a framework-idiomatic regression test (Jest for Node, pytest for
  Python). Surfaced as `f.regression_test = { lang, framework, filename,
  runHint, code }`.
- **FR-LIVE-HARNESS** (`posture/verifier-target.js`). Schema for
  `.agentic-security/verifier-target.yaml` describing how to bring up the
  customer's app (docker-compose or command shape). The `verify --live`
  CLI auto-discovers it. Safety: `command` shape requires a known-good
  start pattern unless `AGENTIC_SECURITY_VERIFY_TARGET_OK=1`.
- **FR-XSAT-7** (`posture/iam-policy.js`). AWS IAM policy auditing.
  Curated dangerous-actions list (iam:*, s3:*, lambda:*, ec2:*, dynamodb:*,
  rds:*, secretsmanager:*, kms:*). Flag Effect=Allow + wildcard resource
  + no Condition.
- **FR-XSAT-8** (`posture/container-runtime.js`). Dockerfile + k8s
  manifest + ECS task def. Detects USER root, privileged: true,
  hostNetwork, hostPID, runAsUser: 0, capabilities ALL/SYS_ADMIN,
  /var/run/docker.sock bind-mount, ADD with remote URL.
- **FR-LOGIC-1 + FR-LOGIC-2 + FR-LOGIC-7** (`posture/business-logic.js`).
  AuthZ matrix construction (per-resource consistency check + IDOR
  detection on mutation routes with :id but no ownership/role check),
  state-machine extraction (catches writes outside the declared status
  set), and negative-test-gap detection (auth route + happy-path test +
  no 401/403 assertion = miss).
- **FR-LOGIC-6** (`posture/flow-narration.js`). Per high-severity finding,
  emit a one-paragraph attacker→impact→cost narrative. Template fallback
  for 10 CWE families; opt-in LLM mode via
  `AGENTIC_SECURITY_FLOW_NARRATION_LLM=1`.
- **FR-LEARN-6** (`posture/rule-synthesis.js`, `agentic-security rule-synth`).
  Read triage-feedback.json, cluster FP verdicts by family + dir prefix,
  propose a YAML suppression rule when ≥ 5 verdicts cluster. Proposes —
  doesn't activate.
- **FR-SDLC-5** (`report/index.js::toSTIX`). `--format stix` emits a STIX
  2.1 bundle with one Vulnerability + Indicator + Relationship SDO per
  finding. CWE external_references; x_* custom properties for severity,
  calibrated confidence, exploitability, verifier verdict.
- **FR-SDLC-9** (`posture/policy-gate.js`, `--policy <file.rego>`).
  Policy-as-code gate. External OPA binary preferred; embedded mini-DSL
  evaluator for the common case. Supports == != > < >= != comparisons
  on `finding.<field>` and `sprintf("...", [args])` for messages.

### Deferred (Phase 6+ research)

- FR-SEM-2 k=2 calling-context — requires dataflow engine refactor
- FR-SEM-5 narrow symbolic execution — needs KLEE-style backend
- FR-SEM-6 hybrid static+dynamic — needs customer app instrumentation
- FR-VER-5 eBPF/dtrace live instrumentation — Linux/macOS only, opt-in
- FR-LOGIC-5 intent inference — LLM-based; pending prompt-injection-safe design

### Tests, bench, integrity

- 295 + 26 + 2 unit tests pass (was 240 before this release).
- Synthetic-bench F1 = 100% (baseline updated; new IDOR expected entry added
  for orm-raw-sql:15 — AuthZ-matrix detector finds a genuine missing
  ownership check that wasn't previously caught).
- Polyglot bench F1 = 100% (was 72.7%; Python SAST coverage closed G3 gap).
- No dead exports.

### Honesty correction

The PRD v2 said all 16 missing features. This release ships 11; 5 are
honestly deferred. The PRD-v3 update (next session) should reflect this
delivery state.

## 0.50.0 — next-gen SAST Phase 1 complete (5 of 5 units)

Closes Phase 1 of `docs/PRD-next-gen-sast-phase1.md`. The two units queued
from v0.49.0 (P1.2 verifier sandbox, P1.4 polyglot bench) are now wired.

### Shipped & wired

- **P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7).** New
  module `scanner/src/posture/verifier.js`. Consumes the `f.poc` artifacts
  from P1.1 and assigns a per-finding `verifier_verdict`:
  - `verified-exploit` — PoC ran against a live target and exited 0
  - `verified-by-llm` — Layer-3 LLM accepted the finding
  - `verified-sanitizer-absence` — pattern-based proof that no sanitizer
    appears in a ±10 line window around the sink (9 vuln families covered)
  - `unverified-by-design` — CWE family where v1 explicitly doesn't ship a PoC
  - `cannot-verify` — sandbox error, missing target, PoC validation failed

  PoC static validation refuses destructive shell payloads, hardcoded cloud
  metadata IPs, runaway-length code, and Node PoCs without a deterministic
  `process.exit(...)`. Sandbox execution mode (opt-in via
  `AGENTIC_SECURITY_VERIFY_LIVE=1` + `AGENTIC_SECURITY_VERIFY_TARGET=<url>`)
  runs each PoC under Docker with `--cap-drop=ALL --memory=256m --read-only
  --user=nobody`; falls back to subprocess with `ulimit` when Docker isn't
  available. Fail-closed: any error → `cannot-verify`, never silent drop.
  New CLI subcommand `agentic-security verify [--finding <id>] [--live
  --target <url>]` re-runs the verifier loop on `last-scan.json` and
  persists the verdicts. Smoke on `vulnerable-js` fixture: 7 findings get
  `verified-sanitizer-absence` static proofs; 2 get `unverified-by-design`;
  the rest are `cannot-verify` pending live execution.

- **P1.4 — Cross-language polyglot benchmark (G3).** New `bench/polyglot/`
  with a tiny dependency-free YAML parser, the runner `runner.mjs`, and 4
  starter cases:
  - 01 HTTP→Python SQL (canonical Phase-2 detector gap — Python SAST)
  - 02 Queue→Python cmd (same gap; queue chain detected; sink not yet)
  - 03 ORM round-trip (Node-only; mass-assignment + data-exposure TPs)
  - 04 HTTP→Node SQL (clean end-to-end test of the OpenAPI cross-asset bridge)

  Default mode `recall-only` measures "does the chain fire where it
  should?" rather than penalizing incidental findings (header-hardening,
  CSRF on test routes, body-parser DoS warnings). Set `mode: strict` in a
  manifest for full-precision scoring. Current overall F1 = 72.7%; PRD G3
  target is 85%; the 27pp gap is Python-side detector coverage (Phase 2).
  New `npm run bench:polyglot`.

### Tests, bench, integrity

- 19 new tests in `test/verifier.test.js` (validation, sanitizer proofs,
  verdict assignment, batch annotation, fail-closed defense-in-depth).
- All 218 + 26 + 2 unit tests pass.
- Synthetic-bench F1 still 100%.
- Polyglot bench F1 72.7% (above 30% v1 floor; below 85% G3 target — the
  gap is documented in `bench/polyglot/README.md`).
- No new dead exports.

### Honesty correction

The PRD's G2 target ("≥80% of high+/critical findings ship with a verified
PoC") is not measured yet — that requires a labeled run-against-target,
which the v1 verifier supports via `--live --target` but we haven't built
a target harness. v1 ships the framework; the labeled measurement is
Phase 5 work.

## 0.49.0 — next-gen SAST Phase 1 (3 of 5 units)

Implements 3 of the 5 Phase-1 shippable units from
`docs/PRD-next-gen-sast-phase1.md` (parent `docs/PRD-next-gen-sast.md`).
The two queued for the next session are noted at the end.

### Shipped & wired

- **P1.1 — PoC generator framework (FR-VER-2).** New module
  `scanner/src/posture/poc-generator.js` ships runnable proof-of-concept
  files for the top-10 CWE families from the parent PRD: SQL injection,
  command injection, XSS, path traversal, SSRF, code injection, CSRF, open
  redirect, XXE, and insecure deserialization. Each PoC is a self-contained
  Node script with one `fetch()` call, evidence-pattern detection, and a
  deterministic exit code (0 = exploit demonstrated, 1 = not demonstrated, 2
  = error). Templates respect a safety policy: no destructive shell commands,
  no real cloud-metadata IPs, no outbound network beyond localhost. Smoke:
  scanning `test/fixtures/vulnerable-js` produces 8 PoCs across 6 distinct
  CWE families. Findings get a new `f.poc = { lang, kind, cwe, family, runHint, code }`
  field surfaced in normalizeFindings and SARIF. Families without v1 template
  coverage get `f.poc = null` and a documented entry in
  `poc-cwe-map.js::NO_POC_FAMILIES`.
- **P1.3 — Brier-calibrated confidence (FR-UX-1, FR-UX-2).** New module
  `scanner/src/posture/calibration.js` turns the ordinal `confidence` score
  into a calibrated probability with 95% Wilson confidence interval. Per
  finding: `calibrated_confidence`, `calibrated_confidence_ci`,
  `calibrated_n`, `calibration_reason` (set when null — "insufficient-samples"
  / "no-family" / "no-history"). Seed corpus in
  `calibration-seed.json` covers 20 vuln families from the OWASP Benchmark +
  Juliet labeled runs; the customer's `.agentic-security/validator-metrics.json`
  overrides per-family when sample count is higher. Calibration is honest
  about uncertainty: `MIN_SAMPLES_FOR_CALIBRATION = 30`. The PRD G1 target
  (Brier ≤ 0.10 on a held-out labeled set) is queued for Phase 5; this ships
  the framework, the math, and the seed data.
- **P1.5 — Cross-language message queues (FR-XSAT-4).** New module
  `scanner/src/posture/cross-lang-queues.js` indexes producer and consumer
  call sites for Kafka (kafkajs, kafka-clients, confluent-kafka), AWS SQS
  (aws-sdk, boto3), RabbitMQ (amqplib, pika, Spring `RabbitTemplate`), Redis
  Streams (XADD / XREAD across Node, Python, Go), and Google Pub/Sub. When
  producer and consumer agree on a topic name and the consumer file has a
  high+ finding, we emit a `cross_language: true` chain back to the producer
  (and vice-versa). Severity is demoted one tier so the chain doesn't double-
  count in severity bucketing. Honest about uncertainty: only literal-string
  topic matches; constant-folded names left for Phase 2.

### Tests, bench, integrity

- 14 new tests in `test/poc-generator.test.js` (PoC coverage + safety).
- 9 new tests in `test/cross-lang-queues.test.js`.
- 14 new tests in `test/calibration.test.js` (Wilson + Brier + annotation).
- All 199 + 26 + 2 unit tests pass.
- Synthetic-bench F1 still 100%.
- No new dead exports; `test/no-dead-modules.test.js` both subtests pass.

### Queued for next session

- **P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7).** Needs
  Docker integration, network isolation, and a sandbox-escape test. The PoC
  generator already produces files; the verifier executes them in isolation.
- **P1.4 — Cross-language polyglot benchmark (G3).** Needs fixture builds
  across Node → Python → Java → Postgres. Measures the cross-asset claims
  we've now made for HTTP/gRPC/GraphQL/ORM/IaC/Queues.

### Honesty correction

The parent PRD claimed v1.0.0 ships at ~15 months. This release is one
session of work; we're at ~v0.49.0 on a path to v0.50.0 (Phase-1 release).
The PRD's G1 (Brier ≤ 0.10 on a held-out set) is not yet measured — the
shipped calibration is on the SEED corpus, which is by definition not held
out. We surface this in the `_caveat` field of `calibration-seed.json`.

## 0.48.0 — fourth-round premortem + CI bench failure

### Bench regression fix

The synthetic-bench CI job started failing at v0.47.0. Two issues:

- **Root-cause clustering over-merged across detectors.** Two distinct
  detectors (structural `Open Redirect` and `host-header`) that share CWE-601
  on the same `res.redirect(...)` line were collapsing into one finding,
  hiding the host-header bug. `sinkKey` now includes `f.parser` so two
  detectors never merge. Empty `sinkExpr` keys are skipped (was bucketing all
  rate-limit findings into one).
- **Two expected entries pointed at the same post-clustered line.** Cleaned
  up `expected.json` for `orm-raw-sql` and added six new `csrf` family
  expected entries for fixtures that legitimately lack CSRF protection.
  Baseline refreshed.

### Node 20 deprecation

Bumped `actions/{checkout,setup-node,upload-artifact}` to v5 and
`actions/github-script` to v8 (Node 24 native). Dropped the
`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround env.

### Fourth-round premortem — 15 findings closed

- **4R-1**: rule-pack signing is fail-closed in CI. When `CI=true` (and the
  common variants) and no signing keys are configured, pass-through mode
  refuses rather than silently accepting. Opt-in via
  `AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1`.
- **4R-2**: `scanner/dist/agentic-security.mjs` is now correctly tracked in
  `.gitignore`. The previous "Not committed" comment lied — the bundle was
  always committed, the comment was wrong. Now `dist/*` is ignored except
  `agentic-security.mjs` and `agentic-security.mjs.sha256`.
- **4R-3**: `scan.yml` downloads the bundle with checksum verification. New
  `scanner-ref` workflow input lets callers pin to a release tag or commit SHA
  for supply-chain hardening. `scanner/dist/agentic-security.mjs.sha256` is
  generated by `npm run build` and committed.
- **4R-4**: catalog `filterByProvenance` memoizes per (entries, mode) so the
  taint hot path no longer allocates a fresh array per match.
- **4R-5**: LSP `_depCache` is granularly invalidated on manifest save — only
  the saved file's entry is refreshed, not the whole project tree.
- **4R-6**: `no-dead-modules.test.js` has a sister "allowlist decay" check.
  Stale ALLOWLIST entries (25 of them, from v0.47.0) were removed.
- **4R-7**: `version.js` warns to stderr when `package.json` can't be read
  instead of silently falling back to `'unknown'`.
- **4R-8**: `applyFix` accepts `stableId` from the caller (`bin/` and `mcp/`)
  rather than re-deriving via `findingId`, which rotates on line-shift.
- **4R-9**: fix-history stale-lock reap is PID-aware. Only unlinks when the
  PID is dead OR the file's old AND the PID is unkillable. Atomic re-read of
  the lockfile before unlink avoids racing a fresh acquirer.
- **4R-10**: SARIF emits a tri-state `signatureStatus: 'verified' | 'unsigned'
  | 'pass-through'` field. The legacy `_unsigned` / `_passThroughSigning`
  flags are emitted alongside for one release of grace.
- **4R-11**: CLI and Markdown reports now render `validator_verdict` so SCA
  findings tagged `not-applicable` aren't invisible to the reader.
- **4R-12**: custom-rules deadline is per-scanRoot, accumulating across calls
  within a process. New `resetCustomRulesBudget(scanRoot)` for long-lived LSP
  scans; wired into the LSP server.
- **4R-13**: `prepublishOnly` refuses to overwrite a locally-edited
  `scanner/CHANGELOG.md` that differs from the canonical `../CHANGELOG.md`.
- **4R-14**: new `scripts/nist-compliance/test_regex_redos.py` asserts every
  import regex runs in linear time on pathological input — guards against
  re-introducing the `(?:[^)]|\n)+?` ReDoS fixed in `e0c669b`.
- **4R-15**: `PROMPT_VERSION` is now a public export of `llm-validator/index.js`.
  The `validator-cache gc` subcommand no longer reaches through the
  underscore-prefixed `_internal` private API and fails loudly if the version
  can't be read.

### Honesty note

All 15 fourth-round findings are closed without dead code (verified by the
no-dead-modules test). The bench failure was a real regression introduced
in v0.47.0 (clustering by CWE alone) — caught by CI, fixed by adding
`f.parser` to the cluster key.

## 0.47.0 — third-round premortem remediation

Third adversarial premortem identified 17 findings against the v0.46.0
remediation. All 17 are now closed. Highlights:

- **3R-1: integration test for dead exports** — new `test/no-dead-modules.test.js`
  walks `scanner/src/{posture,llm-validator,dataflow,lsp,ir,mcp}` and asserts
  every exported symbol has at least one external call site (`.js` files and
  `commands/*.md`). Allowlist for legitimate library-style exports. Closes the
  recurring "wired in code review, dead in code" failure mode.

- **3R-2 / 3R-3: single-sourced version** — `scanner/src/posture/version.js`
  reads `scanner/package.json#version` at module load; SARIF `tool.driver.version`
  and `CURRENT_RULESET_VERSION` now derive from it instead of independently
  hardcoded constants that diverged on every release.

- **3R-4: signing graceful degradation** — `rule-pack-signing.js` operates in a
  pass-through mode when both bundled and project keys are absent. One audit
  warning per session; findings carry `_passThroughSigning:true`. Set
  `AGENTIC_SECURITY_STRICT_SIGNING=1` to disable pass-through.

- **3R-5: CLI keygen safety rails** — `agentic-security-rule keygen` refuses
  `--out` paths under `.agentic-security/`; warns on non-TTY stdout without
  `--out`; writes private-key files mode 0600. `--i-understand-private-keys`
  to override.

- **3R-6: provenance surfaced in reports** — `normalizeFindings` carries
  `_unsigned` and `_passThroughSigning` through; SARIF `result.properties`
  emits `unsigned:true` / `passThroughSigning:true`; SARIF
  `invocations[].properties` now includes `rulesetVersion`, `rulesetVersionSource`,
  and `rulesetVersionMismatch` for trend attribution.

- **3R-7: requiresReAudit is now load-bearing** — `bench-realworld.js` reads
  curated expected JSONs' `requiresReAudit:true`, emits a stderr warning per
  affected corpus, and tags the corpus result with
  `requiresReAudit:true` so consumers know its F1 is informational.

- **3R-8: global deadline for custom rules** — `applyCustomRules()` now caps
  the total scan time across all files and all rules at 30s (overridable via
  `AGENTIC_SECURITY_CUSTOM_RULES_BUDGET_MS`), guarding against ReDoS sprees
  across many files even when each individual regex respects its 200ms budget.

- **3R-9: LSP dep-cache invalidation on manifest save** — saving any
  `package.json`/`pyproject.toml`/`Cargo.toml`/etc. now invalidates the cached
  dep snapshot before re-scanning, so freshly added vulnerable packages and
  removed ones reflect immediately in editor diagnostics.

- **3R-10: catalog OFFICIAL_ONLY is per-match** — `AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY=1`
  is now read per source/sink match instead of once at module load, so CI lanes
  that toggle strict mode just before invocation are actually honored.

- **3R-11: validator preflight handles SCA locators** — findings with
  `parser:'SCA'` or `pkg`/`component`/`purl` set are tagged
  `validator_verdict:'not-applicable'` rather than `'unvalidated'`, which
  was misleading for findings that an LLM cannot meaningfully judge.

- **3R-12: applyFix recover() cross-checks against last-scan.json** — the
  fix-history log entry records the matching finding's stableId at apply
  time; `recover()` after a crash now tags promoted entries as
  `applied-stale` when the finding has vanished from last-scan.json.

- **3R-13: file lock around log writes** — concurrent `applyFix`, `recover`,
  and `undo` invocations no longer race the `log.json` write; serialization
  via `log.lock` with 30s stale-lock reaping and 5s contention timeout.

- **3R-14: validator-cache GC subcommand** — `agentic-security validator-cache
  stats|gc [--older-than N] [--dry-run]` prunes `.agentic-security/llm-cache/`
  by age and prompt-version mismatch.

- **3R-15: tier cutoffs stable under 2-decimal rounding** — confidence tier
  (`high|medium|low|very-low`) is now derived from the 2-decimal display value,
  so a finding reported as "0.75" never lands in two tiers depending on the
  viewer's rounding.

- **3R-16: CHANGELOG ships with npm package** — `prepublishOnly` copies
  CHANGELOG.md into `scanner/`; added to `package.json#files`. The repo-root
  copy remains canonical; the in-package copy is gitignored.

- **3R-17: fix-history log compaction** — `agentic-security undo --compact
  [--retain-days N] [--prune-backups]` archives terminal entries (reverted,
  failed, applied-stale) older than the retention window into
  `log-archive-YYYY-MM.json`, optionally pruning their `.bak` files.

### Honesty correction

No claims in this release exceeded what shipped. v0.47.0 closes the 17
third-round premortem findings against v0.46.0 cleanly; the round-4 premortem
will surely find more, and that is fine.

## 0.46.0 — second-round premortem remediation + honesty correction

### Honesty correction for v0.45.0

The v0.45.0 commit message (`3acca6b fix(security): premortem remediation —
all 15 findings`) claimed all 15 first-round premortem findings were
remediated. A second-round adversarial premortem identified five of those
"closures" as dead code or wire-up regressions:

- `posture/fix-history.js::recover()` was exported but never called from
  any startup path → pending entries from a crashed `applyFix` accumulated
  forever. **Now fixed**: wired into `runScan.js` at top of every scan.

- `posture/ruleset-version.js::stampScan()` / `effectiveVersion()` were
  exported but never imported → ruleset-pinning was documentation only.
  **Now fixed**: wired into `runScan.js` to stamp every scan result.

- `posture/validator-metrics.js::recordTriage()` was exported but the
  `/triage` slash command did not invoke it → per-CWE production metrics
  never accumulated. **Now fixed**: `/triage` now calls `recordTriage` on
  every verdict (subject to the new symmetric learn gate).

- The custom-rules pipeline tagged unsigned RULES with `_unsigned: true`
  but the per-finding emitter (`toFinding`) did not copy the marker →
  the audit chain promised by the warning log did not exist in the data.
  **Now fixed**: findings now carry `_unsigned: true` when their rule does.

- `engine.js:6941` called the LLM validator with `concurrency: 4`,
  overriding the validator's `concurrency: 1` determinism default →
  cache-cold runs produced non-deterministic SARIF in the same commit
  that promised determinism. **Now fixed**: respects `AGENTIC_SECURITY_LLM_CONCURRENCY` env (default 1).

### Other second-round fixes

- **String-aware JSON parser** in the LLM validator. Previous
  `parseLastJsonObject` ignored string-state and could be fooled by braces
  inside JSON string literals. Rewritten to walk forward with full string-
  and escape-state tracking, then return the LAST valid candidate.

- **Empty file/line pre-flight** in `validateOne`. A validator response of
  `{"file":"","line":0,...}` trivially satisfied the cross-check on findings
  without precise location. Now refused with `unvalidated`.

- **Protected signing trust root**: trusted keys come from a built-in
  constant (`BUNDLED_OFFICIAL_KEYS`); project-local `.agentic-security/trusted-keys.json`
  is refused unless `AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1` is set
  (audit-logged). A PR contributor can no longer bootstrap a key into trust.

- **Key revocation**: trusted-keys.json `crl[]` honored (signature-hash
  blacklist); `revokedAt` field on each key honored (signatures dated after
  revocation refused).

- **`agentic-security-rule` CLI** for `keygen` / `sign` / `verify` with a
  first-time setup walkthrough and explicit private-key-handling warnings.

- **Symmetric AGENTIC_SECURITY_LEARN gate**: `/triage` no longer writes
  verdicts to `triage-feedback.json` without explicit opt-in. Prevents an
  attacker from poisoning the file in advance of someone flipping the
  read-side flag.

- **Worklist deadline check**: deep-mode taint engine honors `deadlineMs`
  inside `analyzeFunction`'s worklist (every 128 iterations). Pathological
  CFGs can no longer hold past the global timeout.

- **LSP loads dep-manifest files**: per-save scan in `lsp/server.js` now
  pre-walks the project tree once for `package.json` / `pom.xml` / `.proto`
  / `.graphql` / `.tf` so SCA + cross-language passes have their inputs.

- **SARIF notifications for caveats**: `tool.driver.notifications` and
  `invocations.toolExecutionNotifications` now carry the load-bearing
  warnings (priority scores are ordinal, OWASP Benchmark numbers are
  benchmark-tuned). Customer CI ingesters see them without reading docs.

- **Re-sanitization on cache read**: validator reasoning passes through
  `sanitizeReasoning` again on cache hit (defense in depth against any
  future write-path regression).

- **Provenance + requiresReAudit fields** added to all 25 bootstrapped GT
  files under `bench/.../expected/`. Machine-readable signal that the
  bootstrap origin is self-referential.

### What this commit honestly does NOT close

- BUNDLED_OFFICIAL_KEYS is empty — a production deployment needs the
  maintainers to generate a real keypair, distribute the private key
  offline, and ship the public key. Today's effective behavior is "no
  official keys, project keys via opt-in."
- The CVE-replay corpus is still 1 starter entry (G1 second half remains
  not delivered).
- Real-world Java F1 generalization is still unmeasured.

## 0.45.0 — first-round premortem remediation

(See commit 3acca6b. Some closures were dead-code; see honesty correction
above.)

## 0.44.0 — multi-session items: gRPC/GraphQL/ORM cross-lang, IDE plugins

## 0.43.0 — small engineering items: MCP verify_fix/synthesize_fix,
SentQL path predicates, conversation-context hook, fix-plan,
per-CWE metrics

## 0.42.0 — Layer 1 IR + Layer 2 interprocedural taint, F1=0.907 on
OWASP Bench v1.2 (blind, strict)
