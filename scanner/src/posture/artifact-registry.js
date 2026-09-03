// State artifact registry (assurance-hardening PRD, Milestone 0/1, FR-701/FR-703).
//
// `bin/agentic-security.js`'s `cmdReset` used to delete from two hardcoded
// Sets (WIPE / WIPE_DIRS) — an enumeration that had drifted badly behind the
// state artifacts this codebase actually writes under `.agentic-security/`.
// This module is the registry FR-701 asks for: every known artifact, with an
// explicit classification, built by auditing every `statePath(...)` call
// site in `src/` and `bin/` (not guessed from filenames — several looked
// like generated output by name but turned out, on reading their actual
// read/write call sites, to be operator- or agent-authored INPUT).
//
// Two classifications:
//   - 'generated': written by the scanner itself, safe to delete — the next
//     scan/command regenerates it. `cmdReset` removes these by default.
//   - 'operator-config': hand-authored (or agent-authored, for
//     logic-claims.json) input the scanner only reads. Deleting it on reset
//     would be data loss, not cleanup — `cmdReset` always preserves these.
//
// Corrections this audit made to the assurance-hardening PRD's own evidence
// table (A-10), which had assumed these were straightforwardly "missing from
// the wipe list, therefore should be added": `logic-claims.json` is read-only
// from engine.js (an external reviewing agent authors it); `current-intent.md`
// has no writer anywhere in src/ or bin/ (developer-authored);
// `exploit-history.jsonl`'s own header comment calls it an "operator-curated
// record"; `cve-alerts.json`'s own header comment calls it "Configuration...
// read from"; `network-policy.json` is documented as an Inputs-section
// artifact in network-policy-import.js. All five are classified
// 'operator-config' here — the registry closes the reset-completeness gap
// without introducing a NEW data-loss bug in the process.
//
// This module implements FR-701 (this registry) and FR-703 (registry-driven
// reset). FR-702 (TTL by artifact class) is implemented here too, as an
// additive `retentionClass` field: 'cache' | 'scan' | 'evidence' | 'ticket'
// | 'backup' | undefined, matching the acceptance criterion's own named
// list verbatim ("expired caches, scans, evidence, tickets, and backups").
// DELIBERATELY CONSERVATIVE: only entries that unambiguously fit one of
// those five categories carry a class. Ongoing accumulated state whose
// deletion would be a real loss rather than cleanup — calibration data
// (validator-metrics.json, triage-feedback.json), the continual-learning
// memory file (AGENTS.md), daemon dedup state (cve-alerts-state.json), the
// gamification streak counter, an operator-set regression baseline
// (baseline.json, set via --set-baseline — functionally closer to
// operator intent than scanner output even though it is written by the
// scanner) — are left with NO retention class rather than forced into the
// nearest-sounding bucket. A class-less 'generated' artifact is completely
// unaffected by FR-702's enforcement; it is still deleted unconditionally
// by an ordinary `reset` (FR-703's own behavior, unchanged).
//
// See retention-policy.js for the default/max TTL values per class, the
// optional operator-override file, and the actual expiry check — kept in
// a separate module rather than grown into this one, the same "registry
// vs. policy" separation this session's egress/policy.js and
// compliance-policy.js already establish.
//
// FR-706 (export/deletion manifests) is implemented in
// posture/state-lifecycle-report.js, consuming this registry directly (an
// export walks the FULL registry, not just the 'generated' half `reset`
// acts on — see that module's header).
//
// FR-705 (encryption of confidential state classes): an additive
// `confidential: true` field, enforced by posture/encryption-provider.js.
// DELIBERATELY CONSERVATIVE, Phase 1 of a staged rollout (see that
// module's own header for the full rationale): only `compliance-
// evidence.json`/`.md` are marked in this pass — both have exactly one,
// well-isolated writer function (compliance-policy.js's emitEvidenceJsonLd/
// emitEvidenceMarkdown) and zero other production readers besides that
// same module and the verify-attestation CLI path, both already updated to
// transparently decrypt. Candidates explicitly DEFERRED, with reasons:
// `mcp-audit.log`/`egress-audit.log` (hash-CHAINED NDJSON — each entry's
// hash covers the previous entry, so per-write whole-file encryption would
// need the chain to be computed over plaintext before encrypting, a real
// design question left for its own pass), `dpia.md`/`ropa.md`/`data-
// inventory.json` (written via engine.js's own internal helper, a larger
// blast radius to verify safely), `last-scan.json`/`findings.json` (read
// directly as plain JSON by dozens of commands — encrypting these needs a
// decrypt-on-read hook at every one of those call sites, a much larger,
// separate migration in the same spirit as E2's own deferred scope).

export const ARTIFACT_REGISTRY = [
  // ── Generated: scan output, caches, and system-maintained ledgers ──────
  { name: 'validator-metrics.json', kind: 'file', classification: 'generated' },
  { name: 'triage-feedback.json', kind: 'file', classification: 'generated' },
  { name: 'scan-history.json', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'last-scan.json', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'last-scan.json.sig', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  // Sub-project E, increment 5: the Data Flow Explorer's DataFlowGraph v1
  // document + signature, written by bin/agentic-security.js alongside
  // last-scan.json whenever AGENTIC_SECURITY_LINEAGE_DEEP=1 produced a
  // graph. NOT to be confused with the similarly-named, already-registered
  // `repo-lineage.json` below — that one is an operator-authored
  // cross-repo provenance declaration (classification 'operator-config',
  // never written by the scanner); this one is scanner-generated scan
  // output derived from the user's own source (dataElements[].dataClasses
  // included), so it belongs in the 'generated'/'scan' bucket `reset`
  // clears by default, same as last-scan.json itself.
  { name: 'lineage-graph.json', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'lineage-graph.json.sig', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  // M4 deliverable #8 (FR-503 §14, DFG-022, sub-project 8a): the "Data-Flow
  // Time Machine" foundation — one commit-keyed GraphSnapshot per scan,
  // written by src/lineage/graph-snapshot.js's persistGraphSnapshot(),
  // additively alongside (never replacing) lineage-graph.json above. Same
  // 'generated'/'scan' bucket for the same reason: fully scanner-derived,
  // regenerable by re-scanning at that commit.
  { name: 'lineage-snapshots', kind: 'dir', classification: 'generated', retentionClass: 'scan', source: 'src/lineage/graph-snapshot.js (persistGraphSnapshot)' },
  // M5 deliverable #7 (FR-505 §7.12, AC-29): the Runtime-Corroborated
  // Digital Twin's observation store — one immutable whole file per adapter
  // import, written by src/lineage/observation-store.js's
  // persistObservationImport(), mirroring lineage-snapshots/'s own
  // directory-of-files shape re-keyed commit -> import.
  { name: 'runtime-observations', kind: 'dir', classification: 'generated', retentionClass: 'evidence', confidential: true, source: 'src/lineage/observation-store.js (persistObservationImport)', note: 'FR-505 requires an observation store follow artifact encryption, RETENTION, RESET, access-control and no-egress rules. That is why this is `generated` (a plain `reset` MUST be able to delete it) rather than `operator-config`, and why it carries a real retentionClass — deliberately NOT the `remediation`/`legal-holds.json` no-retention call one section down, and deliberately NOT `provenance`\'s permanent-history call. This DOES stretch `generated`\'s usual definition — a rescan does not re-derive an import, the operator re-imports it — and that stretch is disclosed here rather than hidden: FR-505\'s explicit reset requirement breaks the tie. `confidential: true` is enforced by observation-store.js calling maybeEncryptForWrite/maybeDecryptForRead itself (posture/encryption-provider.js), the same per-writer opt-in compliance-evidence.json makes — the flag alone enforces nothing.' },
  { name: 'shadow-findings.json', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'mcp-audit.log', kind: 'file', classification: 'generated', retentionClass: 'evidence' },
  { name: 'egress-audit.log', kind: 'file', classification: 'generated', retentionClass: 'evidence', note: "FR-604 per-call egress audit log — hash-chained NDJSON written by egress/audit.js's recordEgressCall, never read as config" },
  { name: 'hook-throttle.json', kind: 'file', classification: 'generated', retentionClass: 'cache' },
  { name: 'tickets.json', kind: 'file', classification: 'generated', retentionClass: 'ticket' },
  { name: 'streak.json', kind: 'file', classification: 'generated' },
  { name: 'findings.json', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'findings.sarif', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'findings.csv', kind: 'file', classification: 'generated', retentionClass: 'scan' },
  { name: 'llm-cache', kind: 'dir', classification: 'generated', retentionClass: 'cache' },
  { name: 'fix-history', kind: 'dir', classification: 'generated', retentionClass: 'backup' },
  { name: 'fix-plans', kind: 'dir', classification: 'generated', retentionClass: 'scan' },
  // The following were confirmed missing from the old hardcoded WIPE/
  // WIPE_DIRS sets (A-10) and confirmed GENERATED by reading their write
  // call sites (engine.js, or the module named in `source`).
  { name: 'dpia.md', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'engine.js (_safeWriteState)' },
  { name: 'ropa.md', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'engine.js (_safeWriteState) — FR-407 RoPA scaffold, dataflow/privacy-governance.js' },
  { name: 'data-inventory.json', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'engine.js (_safeWriteState) — FR-406 code-derived data inventory, dataflow/privacy-inventory.js' },
  { name: 'data-flow-graph.md', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'engine.js (_safeWriteState) — FR-406 mermaid flow graph, dataflow/privacy-inventory.js' },
  { name: 'privacy-framework.json', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'posture/privacy-framework.js' },
  { name: 'privacy-framework.md', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'posture/privacy-framework.js' },
  { name: 'ifds-summaries.json', kind: 'file', classification: 'generated', retentionClass: 'cache', source: 'dataflow/ifds-precise.js (cache)' },
  { name: 'exploit-bundles.json', kind: 'file', classification: 'generated', retentionClass: 'scan', source: 'engine.js (_safeWriteState)' },
  { name: 'cve-alerts-state.json', kind: 'file', classification: 'generated', source: 'posture/cve-alert-daemon.js' },
  { name: 'compliance-evidence.json', kind: 'file', classification: 'generated', retentionClass: 'evidence', confidential: true, source: 'posture/compliance-policy.js' },
  { name: 'compliance-evidence.md', kind: 'file', classification: 'generated', retentionClass: 'evidence', confidential: true, source: 'posture/compliance-policy.js' },
  { name: 'ATTRIBUTIONS.md', kind: 'file', classification: 'generated', retentionClass: 'scan', source: 'posture/license-attributions.js' },
  { name: 'NOTICE', kind: 'file', classification: 'generated', retentionClass: 'scan', source: 'posture/license-attributions.js' },
  { name: 'accepted.json', kind: 'file', classification: 'generated', source: 'posture/suppressions.js (soft-accept save path)', note: 'already self-managing per-entry expiry (FR-1004-adjacent) — no additional class-level TTL' },
  { name: 'triage.json', kind: 'file', classification: 'generated', source: 'posture/triage.js (_save)' },
  { name: 'pqc-migration-plan.json', kind: 'file', classification: 'generated', retentionClass: 'scan', source: 'posture/pqc-migration-plan.js' },
  { name: 'pqc-migration-plan.md', kind: 'file', classification: 'generated', retentionClass: 'scan', source: 'posture/pqc-migration-plan.js' },
  // controls.json lives under compliance/<framework>/ — registering the
  // parent directory covers it and any other per-framework artifact.
  { name: 'compliance', kind: 'dir', classification: 'generated', retentionClass: 'evidence', source: 'posture/auditor-walkthrough.js' },
  { name: 'attestations', kind: 'dir', classification: 'generated', retentionClass: 'evidence', source: 'posture/evidence-bundle.js' },
  { name: 'auditor-walkthroughs', kind: 'dir', classification: 'generated', retentionClass: 'evidence' },
  { name: 'incremental', kind: 'dir', classification: 'generated', retentionClass: 'cache', source: 'dataflow/incremental.js (cache)' },
  { name: 'model-rescan', kind: 'dir', classification: 'generated', retentionClass: 'scan' },
  { name: 'sca-upgrade-history', kind: 'dir', classification: 'generated', retentionClass: 'scan' },
  { name: 'scan-baselines', kind: 'dir', classification: 'generated', retentionClass: 'scan', source: 'posture/pr-augment.js' },
  { name: 'agent-scratchpad', kind: 'dir', classification: 'generated', retentionClass: 'cache', source: 'mcp/tools.js (append_scratchpad)' },
  // Finding Provenance (M0/M1, split per PRD Section 8 retention task). Used
  // to be one directory with two writers sharing it, which meant they could
  // not get different retention treatment — `cmdReset`/`findExpiredArtifacts`
  // only ever operate on exact TOP-LEVEL `.agentic-security/` directory
  // names, never on a `/`-qualified sub-path. Now physically split:
  //   - posture/provenance/cache.js writes provenance-cache/<hash>.json — a
  //     pure HEAD-keyed memo of resolved origins, safely regenerable, no
  //     correctness dependency on being preserved. Gets retentionClass:
  //     'cache' (7-day default / 30-day max TTL, RETENTION_DEFAULTS.cache).
  //   - posture/provenance/lifecycle.js writes provenance/lifecycle.json +
  //     .lock — the introduce/remediate/reintroduce ledger. Deliberately NO
  //     retentionClass: this is permanent history, not a cache; auto-expiring
  //     it would silently lose lifecycle events a report may already have
  //     cited. `reset` (without `--expired`) still clears it, which is
  //     explicit operator action, unlike TTL-driven auto-expiry.
  // Old-location cache files (`provenance/cache/*.json`, written before this
  // split) are DELIBERATELY NOT migrated — see cache.js's own comment and the
  // commit that introduced this split. They are simply orphaned: invisible to
  // this registry, un-swept by reset/retention, silently ignored by the new
  // code, and harmless to leave until a human deletes them by hand.
  { name: 'provenance-cache', kind: 'dir', classification: 'generated', retentionClass: 'cache', source: 'posture/provenance/cache.js -- pure HEAD-keyed memo, safely regenerable, no correctness dependency on being preserved' },
  { name: 'provenance', kind: 'dir', classification: 'generated', source: 'posture/provenance/lifecycle.js -- the introduce/remediate/reintroduce ledger. Deliberately NO retentionClass: this is permanent history, not a cache; auto-expiring it would silently lose lifecycle events a report may already have cited.' },
  { name: 'AGENTS.md', kind: 'file', classification: 'generated', source: 'posture/agents-memory.js' },
  { name: 'AGENTS.md.archive', kind: 'file', classification: 'generated', source: 'posture/agents-memory.js' },
  { name: 'baseline.json', kind: 'file', classification: 'generated', source: 'bin/agentic-security.js (--set-baseline)', note: 'operator-set intent, functionally closer to operator-config than scan output — no auto-expiry' },
  // These two were found by the completeness guard (test/artifact-registry-
  // completeness.test.js) to have a read call site (leaderboard.js,
  // posture/findings-memory.js respectively) but NO writer anywhere in src/
  // or bin/ — likely dead/aspirational read paths from a scan-history
  // storage scheme that was refactored away. Registered as 'generated'
  // rather than left unclassified: nothing about a per-scan history log/
  // directory suggests hand-authored config, so if a future change starts
  // writing either, the safe default (delete on reset, like scan-history.json)
  // is already in place rather than accidentally falling to operator-config.
  { name: 'scan-history.jsonl', kind: 'file', classification: 'generated', retentionClass: 'scan', note: 'no current writer found — see completeness-guard test comment' },
  { name: 'scan-history', kind: 'dir', classification: 'generated', retentionClass: 'scan', note: 'no current writer found — see completeness-guard test comment' },

  // FR-706: the last-action proof artifacts `reset` and `export` write —
  // see posture/state-lifecycle-report.js's header for why each is a single
  // overwritten "last action" file rather than an ever-growing log.
  { name: 'deletion-report.json', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'posture/state-lifecycle-report.js (via bin/agentic-security.js cmdReset)' },
  { name: 'export-report.json', kind: 'file', classification: 'generated', retentionClass: 'evidence', source: 'posture/state-lifecycle-report.js (via bin/agentic-security.js cmdExport)' },

  // M5 governance editing workflow final-review fix round 1 (I5): backups
  // of recipient-profiles.json written by `governance propose-edit --yes`,
  // mirroring the `fix-history` directory precedent above — one directory
  // entry covers every timestamped .bak file inside it, since the registry
  // only supports exact-name matches, never a per-file timestamped name.
  { name: 'recipient-profiles-backups', kind: 'dir', classification: 'generated', retentionClass: 'backup', note: 'per-edit backups written by `governance propose-edit --yes`, mirrors the fix-history/ precedent — one directory entry covers every timestamped .bak file inside it' },

  // M5 deliverable #8 (FR-304 "declared" half): backups of
  // cross-repo-links.json written by `federate declare --yes`, mirrors
  // the `recipient-profiles-backups` precedent immediately above
  // exactly.
  { name: 'cross-repo-links-backups', kind: 'dir', classification: 'generated', retentionClass: 'backup', note: 'per-declare backups written by `federate declare --yes`, mirrors the recipient-profiles-backups/ precedent — one directory entry covers every timestamped .bak file inside it' },

  // ── Operator-config: hand-authored (or agent-authored) input, never wiped ──
  { name: 'rules.yml', kind: 'file', classification: 'operator-config' },
  { name: 'rules', kind: 'dir', classification: 'operator-config' },
  { name: 'rules-proposed', kind: 'dir', classification: 'operator-config', note: 'proposed rules awaiting human review — not yet approved config, but not scanner-regenerable either' },
  { name: 'license-policy.yml', kind: 'file', classification: 'operator-config' },
  { name: 'trusted-keys.json', kind: 'file', classification: 'operator-config' },
  { name: 'ruleset-version.json', kind: 'file', classification: 'operator-config', note: 'pinning intent, hand-set' },
  { name: 'risk-config.yml', kind: 'file', classification: 'operator-config' },
  { name: 'egress-policy.yml', kind: 'file', classification: 'operator-config', note: 'FR-601 egress policy (mode: allow/deny/local-only, allowedProviders/deniedProviders) — read by egress/policy.js, never written by the scanner' },
  { name: 'integrations.yml', kind: 'file', classification: 'operator-config' },
  { name: 'profile.yml', kind: 'file', classification: 'operator-config' },
  { name: 'sca-policy.yml', kind: 'file', classification: 'operator-config' },
  { name: 'suppressions.yml', kind: 'file', classification: 'operator-config', note: 'audit-tier suppression config; only ever loaded, never saved, by posture/suppressions.js' },
  { name: 'network-policy.json', kind: 'file', classification: 'operator-config', note: 'documented as an Inputs-section artifact in posture/network-policy-import.js, not a scanner-written digest' },
  { name: 'privacy-taxonomy.json', kind: 'file', classification: 'operator-config', note: 'FR-402 privacy data-classification taxonomy overrides/additions — read by dataflow/privacy-taxonomy.js, never written by the scanner' },
  { name: 'privacy-policy.json', kind: 'file', classification: 'operator-config', note: 'FR-404 privacy sink policy (which class-to-sink flows are explicitly permitted) — read by dataflow/privacy-sink-policy.js, never written by the scanner' },
  { name: 'privacy-governance.json', kind: 'file', classification: 'operator-config', note: 'FR-407 DPIA/RoPA governance field overrides (purpose, lawful basis, retention, etc.) — read by dataflow/privacy-governance.js, never written by the scanner' },
  { name: 'compliance-severity-policy.json', kind: 'file', classification: 'operator-config', note: 'FR-502 per-framework/default open-finding severity threshold override — read by posture/auditor-walkthrough.js, never written by the scanner' },
  { name: 'authorized-approvers.json', kind: 'file', classification: 'operator-config', note: 'FR-1002 identity/role registry for high-impact fix approvals — read by fix/approver-registry.js, never written by the scanner' },
  { name: 'policy-bundles', kind: 'dir', classification: 'operator-config', note: 'FR-1001 signed organization/repository/environment policy bundles (organization.json/repository.json/environment.json) — distributed by an org and placed by the operator, read by posture/policy-bundle.js, never written by the scanner' },
  { name: 'policy-bundle-public-key.pem', kind: 'file', classification: 'operator-config', note: 'FR-1001 public key an operator installs to verify org-distributed policy bundles — read by posture/policy-bundle.js, never written by the scanner' },
  { name: 'retention-policy.yml', kind: 'file', classification: 'operator-config', note: 'FR-702 per-retention-class TTL overrides (clamped to a built-in per-class maximum) — read by posture/retention-policy.js, never written by the scanner' },
  { name: 'legal-holds.json', kind: 'file', classification: 'operator-config', note: 'FR-707 legal holds ({artifact, owner, reason, expires_at}) — read by posture/retention-policy.js and bin/agentic-security.js cmdReset; WRITTEN by the CLI (legal-hold add/remove), but classified operator-config (not generated) deliberately: a plain `reset` must never be able to delete the very record protecting other artifacts from deletion' },
  { name: 'remediation', kind: 'dir', classification: 'operator-config', note: 'M5 deliverable #6 remediation work-item ledger (items.jsonl + items.lock) — an APPEND-ONLY record of human decisions: owner assignment, approvals, manual attestations, and accepted-risk exceptions with approver/reason/scope/expiration. WRITTEN by the CLI (`remediation open|update|verify|accept-risk|reopen-check --yes`) but classified operator-config, not generated, deliberately — the same call legal-holds.json makes one entry up: a plain `reset` must never be able to delete the audit trail AC-31 depends on, and nothing regenerates it from a rescan. Deliberately NOT the `provenance` entry\'s `generated` classification (see its own note above): that ledger is scan-derived history a rescan can rebuild; this one is human decisions that cannot be. No retentionClass for the same reason legal-holds.json has none — auto-expiry would silently delete an accepted-risk exception a report may already cite.' },
  { name: 'calibration-feedback.jsonl', kind: 'file', classification: 'operator-config', note: 'FR-806 opt-in calibration ground truth ({at, findingId, outcome: accept-risk|realized-incident, predicted*, note}) — WRITTEN by the CLI (calibration-feedback record), but classified operator-config like exploit-history.jsonl: real, hard-to-recreate customer-reported ground truth, never scanner-regenerable, so a routine reset must never delete it' },
  { name: 'encryption-policy.yml', kind: 'file', classification: 'operator-config', note: 'FR-705 encryption provider/required opt-in policy ({provider: local-key, required: true|false}) — read by posture/encryption-provider.js, never written by the scanner' },
  { name: 'provenance-providers.yml', kind: 'file', classification: 'operator-config', note: 'Finding Provenance M3 §3.4 GitHub/GitLab provider enrichment opt-in ({token} or provider-scoped tokens) — read by posture/provenance/providers/config.js, never written by the scanner; env vars (AGENTIC_SECURITY_GITHUB_TOKEN/AGENTIC_SECURITY_GITLAB_TOKEN) take precedence when set' },
  { name: 'repo-lineage.json', kind: 'file', classification: 'operator-config', note: 'Finding Provenance M4 §4.2 cross-repository lineage declaration ({linkedFrom: {path, atCommit}}) — read by posture/provenance/repo-lineage.js, never written by the scanner; the linked path is verified as a real local git repo before use, no remote fetch' },
  { name: 'recipient-profiles.json', kind: 'file', classification: 'operator-config', note: 'FR-506 recipient/subprocessor governance profiles — hand- or agent-authored via `governance propose-edit`, never scanner-regenerable, so a routine reset must never delete it' },
  { name: 'cross-repo-links.json', kind: 'file', classification: 'operator-config', note: 'M5 deliverable #8 (FR-304 "declared" half) — declared local<->remote node links between two independently-scanned repos, written via `federate declare --yes`, never scanner-regenerable, so a routine reset must never delete it' },
  { name: 'logic-claims.json', kind: 'file', classification: 'operator-config', note: 'authored by an external reviewing agent; engine.js only ever reads it (fs.readFileSync, never written)' },
  { name: 'current-intent.md', kind: 'file', classification: 'operator-config', note: 'developer-authored; no writer exists anywhere in src/ or bin/' },
  { name: 'exploit-history.jsonl', kind: 'file', classification: 'operator-config', note: 'own header comment: "operator-curated record of past confirmed exploits"' },
  { name: 'cve-alerts.json', kind: 'file', classification: 'operator-config', note: 'own header comment: "Configuration is read from"; state lives in the separate cve-alerts-state.json, which IS generated' },
  // Pre-existing gap, found by M5 deliverable #7's own scoping investigation
  // and fixed here rather than left: posture/runtime-correlation.js reads
  // these three filenames via `statePath(scanRoot, n)` with a VARIABLE, so
  // test/artifact-registry-completeness.test.js's own PATTERNS regexes (which
  // require a string literal) never saw them and never demanded registration.
  // An unregistered state artifact means `reset` does not know about it and
  // retention cannot reach it. Operator-config, not generated: these are
  // hand-supplied eBPF/APM trace exports the scanner only ever reads.
  { name: 'runtime-trace.jsonl', kind: 'file', classification: 'operator-config', note: 'eBPF/APM runtime trace consumed by posture/runtime-correlation.js\'s own trace loader (deliberately not named by its literal export here — no-dead-modules.test.js scans note strings too, and naming it would make it look, wrongly, like a real call site) — operator-supplied, never scanner-written; $AGENTIC_SECURITY_RUNTIME_TRACE_PATH overrides the location entirely' },
  { name: 'runtime.jsonl', kind: 'file', classification: 'operator-config', note: 'alternate filename for runtime-trace.jsonl — see posture/runtime-correlation.js\'s DEFAULT_TRACE_NAMES' },
  { name: 'ebpf-trace.jsonl', kind: 'file', classification: 'operator-config', note: 'alternate filename for runtime-trace.jsonl — see posture/runtime-correlation.js\'s DEFAULT_TRACE_NAMES' },
];

export function listGeneratedArtifacts() {
  return ARTIFACT_REGISTRY.filter(a => a.classification === 'generated');
}

export function listOperatorConfigArtifacts() {
  return ARTIFACT_REGISTRY.filter(a => a.classification === 'operator-config');
}

export function isRegisteredArtifact(name) {
  return ARTIFACT_REGISTRY.some(a => a.name === name);
}

export function classificationOf(name) {
  return ARTIFACT_REGISTRY.find(a => a.name === name)?.classification ?? null;
}

// FR-705: is this artifact marked as containing sensitive content an
// operator may want encrypted at rest? Deliberately a SEPARATE flag from
// classification/retentionClass — confidentiality is about content
// sensitivity, not about who writes it or how long it lives. See
// encryption-provider.js for the enforcement side (the fail-closed gate
// this flag feeds) and its own header for which artifacts are marked here
// in this first, deliberately conservative pass, and why others are not.
export function confidentialOf(name) {
  return ARTIFACT_REGISTRY.find(a => a.name === name)?.confidential === true;
}

// FR-702: which retention class (if any) governs this artifact's TTL. Only
// 'generated' artifacts can carry one — an 'operator-config' entry is never
// auto-expired regardless of what this returns (retention-policy.js's own
// caller enforces that ordering, not this function).
export function retentionClassOf(name) {
  return ARTIFACT_REGISTRY.find(a => a.name === name)?.retentionClass ?? null;
}

export function listArtifactsWithRetentionClass() {
  return ARTIFACT_REGISTRY.filter(a => a.classification === 'generated' && a.retentionClass);
}
