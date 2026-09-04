# State & retention

Everything the scanner writes lives under `.agentic-security/` at your
project root — never in the scanner's own install tree. This page is the
governance reference for that directory: what's in it, whether it's sensitive,
how long it's kept, and what `reset` does and doesn't touch. For the env-var
and policy-*file* side of configuration (what each file *does*), see
[Configuration & environment variables](../reference/configuration.md).

Source of truth for everything below: `scanner/src/posture/artifact-registry.js`
(the classification of every artifact), `scanner/src/posture/retention-policy.js`
(the TTL table), and `scanner/src/posture/encryption-provider.js` (the
encryption behavior). All three are enforced by tests, not just documented —
`test/artifact-registry-completeness.test.js` fails the build if a new state
artifact ships unregistered.

---

## Two classifications

Every artifact under `.agentic-security/` is one of:

- **`generated`** — written by the scanner itself. Safe to delete: the next
  scan or command regenerates it. `reset` deletes these by default.
- **`operator-config`** — hand-authored (or agent-authored) input the scanner
  only ever *reads*. Deleting it on `reset` would be data loss, not cleanup —
  `reset` always preserves these, unconditionally.

A handful of `generated` artifacts also carry a **`retentionClass`**
(`cache` / `scan` / `evidence` / `ticket` / `backup`), which subjects them to
the TTL table below via `reset --expired`. Not every `generated` artifact has
one — ongoing state whose deletion would be a real loss rather than routine
cleanup (calibration data, the `AGENTS.md` continual-learning memory file, an
operator-set `--set-baseline`) is deliberately left classless: it's still
deleted by a plain `reset`, just never auto-expired by age.

A separate, orthogonal flag, **`confidential`**, marks an artifact as
containing sensitive content that should be encrypted at rest when an
encryption provider is configured (see Encryption, below). It says nothing
about classification or retention — an artifact can be `generated` *and*
`confidential` at the same time, and as it happens all three artifacts
currently marked `confidential` in the registry are `generated`.

---

## Artifact table

**Sensitive?** reflects the `confidential` flag as currently set in the
registry — a deliberately conservative Phase 1 (see Encryption below). A
`No` here means "not yet marked for at-rest encryption," not an assessment
that the file's contents are harmless: `last-scan.json` and `findings.json`
both contain full finding detail (file paths, code context, secret
locations) and are still `No` today, because encrypting them needs a
decrypt-on-read hook at every one of the dozens of commands that read them
directly as plain JSON — deferred, disclosed, and unfinished, not silently
decided to be fine.

**Retention** cites the class's `defaultDays` from the TTL table below (the
`maxDays` ceiling applies once an operator overrides it in
`retention-policy.yml`). "None" means the artifact is never auto-expired by
age, regardless of classification.

### Generated (deleted by a plain `reset`)

| Artifact | Purpose | Sensitive? | Retention | Deleted by Reset |
|---|---|---|---|---|
| `last-scan.json` (+ `.sig`) | Canonical last-scan output, HMAC-signed | No | scan — 90d default | Yes |
| `lineage-graph.json` (+ `.sig`) | Data Flow Explorer `DataFlowGraph v1` document | No | scan — 90d default | Yes |
| `lineage-snapshots/` | Commit-keyed graph history (`dataflow diff`) | No | scan — 90d default | Yes |
| `runtime-observations/` | Imported runtime telemetry for the Digital Twin | **Yes** | evidence — 365d default | Yes |
| `findings.json` / `.sarif` / `.csv` | Findings in JSON / SARIF / CSV | No | scan — 90d default | Yes |
| `scan-history.json` | Scan history for trend / report-card | No | scan — 90d default | Yes |
| `shadow-findings.json` | Findings from `shadow: true` custom rules | No | scan — 90d default | Yes |
| `exploit-bundles.json` | Exploit bundle data | No | scan — 90d default | Yes |
| `ATTRIBUTIONS.md` / `NOTICE` | License attribution output | No | scan — 90d default | Yes |
| `pqc-migration-plan.json` / `.md` | Post-quantum crypto migration plan | No | scan — 90d default | Yes |
| `model-rescan/` | Model-rescan output | No | scan — 90d default | Yes |
| `sca-upgrade-history/` | SCA dependency-upgrade history | No | scan — 90d default | Yes |
| `scan-baselines/` | PR-augment baseline snapshots | No | scan — 90d default | Yes |
| `scan-history.jsonl`, `scan-history/` | No current writer (dead read paths, registered defensively) | No | scan — 90d default | Yes |
| `mcp-audit.log` | MCP tool-call audit log | No | evidence — 365d default | Yes |
| `egress-audit.log` | Hash-chained per-call egress audit log | No | evidence — 365d default | Yes |
| `dpia.md` / `ropa.md` | DPIA / RoPA governance scaffolds | No | evidence — 365d default | Yes |
| `data-inventory.json` / `data-flow-graph.md` | Code-derived privacy data inventory + flow graph | No | evidence — 365d default | Yes |
| `privacy-framework.json` / `.md` | NIST Privacy Framework 1.1 assessment | No | evidence — 365d default | Yes |
| `compliance-evidence.json` / `.md` | Signed compliance evidence | **Yes** | evidence — 365d default | Yes |
| `compliance/` | Per-framework compliance artifacts (`controls.json`, …) | No | evidence — 365d default | Yes |
| `attestations/` | Signed Ed25519 evidence bundles (`attest`) | No | evidence — 365d default | Yes |
| `auditor-walkthroughs/` | Auditor walkthrough narratives | No | evidence — 365d default | Yes |
| `deletion-report.json` | Last `reset`'s manifest of what it deleted/preserved | No | evidence — 365d default | Yes |
| `export-report.json` | Last `export`'s manifest | No | evidence — 365d default | Yes |
| `hook-throttle.json` | Editor-hook throttle state | No | cache — 7d default | Yes |
| `llm-cache/` | LLM response cache | No | cache — 7d default | Yes |
| `ifds-summaries.json` | Interprocedural taint-summary cache | No | cache — 7d default | Yes |
| `incremental/` | Incremental dataflow cache | No | cache — 7d default | Yes |
| `agent-scratchpad/` | MCP `append_scratchpad` notes | No | cache — 7d default | Yes |
| `provenance-cache/` | HEAD-keyed finding-provenance memo | No | cache — 7d default | Yes |
| `tickets.json` | Synced ticket-integration state | No | ticket — 180d default | Yes |
| `fix-history/` | Applied-fix backups (`undo` reads these) | No | backup — 30d default | Yes |
| `recipient-profiles-backups/` | Per-edit `.bak` of `recipient-profiles.json` | No | backup — 30d default | Yes |
| `cross-repo-links-backups/` | Per-declare `.bak` of `cross-repo-links.json` | No | backup — 30d default | Yes |
| `fix-plans/` | Oversized-patch fallback fix plans | No | scan — 90d default | Yes |
| `validator-metrics.json` | LLM-validator accuracy metrics | No | None | Yes |
| `triage-feedback.json` | Feedback for the active-learning loop | No | None | Yes |
| `streak.json` | Gamification streak counter | No | None | Yes |
| `cve-alerts-state.json` | CVE-alert daemon dedup state | No | None | Yes |
| `accepted.json` | Soft-accepted (suppressed) findings — self-expiring per entry | No | None | Yes |
| `triage.json` | Interactive-triage state | No | None | Yes |
| `provenance/` (`lifecycle.json` + `.lock`) | Introduce/remediate/reintroduce ledger — permanent history | No | None (never auto-expired) | Yes |
| `AGENTS.md` / `AGENTS.md.archive` | Continual-learning memory file | No | None | Yes |
| `baseline.json` | Operator-set regression baseline (`--set-baseline`) | No | None | Yes |

### Operator-config (never touched by `reset`)

| Artifact | Purpose | Sensitive? | Retention | Deleted by Reset |
|---|---|---|---|---|
| `rules.yml` | Custom rules, severity overrides, ignore paths, gated `disable:` entries | No | None | No |
| `rules/*.yml` | Custom YAML pattern rules | No | None | No |
| `rules-proposed/` | Proposed rules awaiting human review | No | None | No |
| `license-policy.yml` | Allow/deny/review policy for the license gate | No | None | No |
| `trusted-keys.json` | Trusted signing keys | No | None | No |
| `ruleset-version.json` | Ruleset version pin | No | None | No |
| `risk-config.yml` | Risk-in-dollars inputs — see [Risk in dollars](../guides/risk-dollars.md) | No | None | No |
| `egress-policy.yml` | Network egress allow/deny policy | No | None | No |
| `integrations.yml` | Third-party integration config | No | None | No |
| `profile.yml` | Operator profile (`profile set\|show`) | No | None | No |
| `sca-policy.yml` | Supply-chain policy | No | None | No |
| `suppressions.yml` | Audit-tier suppression config (load-only) | No | None | No |
| `network-policy.json` | Network-policy digest input | No | None | No |
| `privacy-taxonomy.json` | Privacy data-classification taxonomy overrides | No | None | No |
| `privacy-policy.json` | Privacy sink policy (permitted class→sink flows) | No | None | No |
| `privacy-governance.json` | DPIA/RoPA governance field overrides | No | None | No |
| `compliance-severity-policy.json` | Per-framework open-finding severity threshold override | No | None | No |
| `authorized-approvers.json` | Identity/role registry for high-impact fix approvals | No | None | No |
| `policy-bundles/` | Signed org/repository/environment policy bundles | No | None | No |
| `policy-bundle-public-key.pem` | Public key to verify org-distributed policy bundles | No | None | No |
| `retention-policy.yml` | Per-class TTL overrides (this page's own knob — see below) | No | None | No |
| `legal-holds.json` | Legal holds — this page's own subject (see below) | No | None | No |
| `remediation/` (`items.jsonl` + `items.lock`) | Append-only remediation work-item ledger — owner, approvals, accepted-risk exceptions | No | None | No |
| `calibration-feedback.jsonl` | Opt-in calibration ground truth (`calibration-feedback record`) | No | None | No |
| `encryption-policy.yml` | Encryption provider/required policy (see below) | No | None | No |
| `provenance-providers.yml` | GitHub/GitLab enrichment tokens | No | None | No |
| `repo-lineage.json` | Cross-repository lineage declaration | No | None | No |
| `recipient-profiles.json` | Recipient/subprocessor governance profiles | No | None | No |
| `cross-repo-links.json` | Declared local↔remote cross-repo node links | No | None | No |
| `logic-claims.json` | Business-logic claims from an external reviewing agent | No | None | No |
| `current-intent.md` | Developer-authored intent doc | No | None | No |
| `exploit-history.jsonl` | Operator-curated record of past confirmed exploits | No | None | No |
| `cve-alerts.json` | CVE-alert configuration | No | None | No |
| `runtime-trace.jsonl`, `runtime.jsonl`, `ebpf-trace.jsonl` | Operator-supplied eBPF/APM runtime trace (alternate filenames) | No | None | No |

---

## TTL by retention class

`reset --expired` (as opposed to a plain `reset`, which deletes every
`generated` artifact unconditionally) deletes only `generated` artifacts past
their TTL for their class:

| Class | Default | Max |
|---|---|---|
| `cache` | 7 days | 30 days |
| `scan` | 90 days | 365 days |
| `evidence` | 365 days | 1095 days |
| `ticket` | 180 days | 730 days |
| `backup` | 30 days | 180 days |

An operator can lower (never raise past `Max`) the default for a class via
`.agentic-security/retention-policy.yml`:

```yaml
cache:
  defaultDays: 3
evidence:
  defaultDays: 730
```

A class not mentioned, or no file at all, uses the defaults above unmodified.
This is a **purge**, not an archive — expired artifacts are deleted, not moved
anywhere. An operator who wants to retain a copy before purging should
`export` first (below) or back up `.agentic-security/` by their own means.

An artifact under an active [legal hold](#legal-hold) is never reported as
expired and is never deleted by either form of `reset`, regardless of its age.

---

## Encryption

One provider is implemented: **`local-key`** — AES-256-GCM with a per-install
key generated the first time encryption is actually used, stored at
`$XDG_CONFIG_HOME/agentic-security/encryption-key` (a separate key file from
the HMAC signing key `integrity.js` already keeps in the same directory —
never the same key reused for two cryptographic purposes). Override the key
via `AGENTIC_SECURITY_ENCRYPTION_KEY` (64 hex chars).

Encryption is opt-in and off by default. Nothing is encrypted until an
operator writes `.agentic-security/encryption-policy.yml`:

```yaml
provider: local-key
required: true
```

- No file, or `required: false` with no provider configured — every
  `confidential` artifact writes exactly as it always has (plaintext).
- `required: true` with a working provider — every `confidential` artifact is
  written as an encrypted envelope; reads are transparently decrypted.
- **Fail-closed:** `required: true` with no working provider available means
  the write is refused outright (`{ok:false}`) — checked *before* any bytes
  touch disk, so a misconfigured required-encryption setup can never fall back
  to writing a confidential artifact in plaintext.

**Scope exclusions (Phase 1, deliberate).** Only `compliance-evidence.json`,
`compliance-evidence.md`, and `runtime-observations/` are currently marked
`confidential` in the registry. `last-scan.json` / `findings.json` are
explicitly excluded — dozens of commands read them directly as plain JSON, so
encrypting them needs a decrypt-on-read hook at every one of those call
sites, a separate, larger migration. `mcp-audit.log` / `egress-audit.log` are
also excluded: both are hash-chained NDJSON where each entry's hash covers
the previous entry, and per-write whole-file encryption would need the chain
computed over plaintext before encrypting — a real design question left for
its own pass.

**`export` does not decrypt.** Copying a `confidential` artifact via
`export --out <dir>` (below) copies whatever bytes are on disk — the
encrypted envelope if encryption is configured, plaintext otherwise. There is
no decrypt-on-export step.

---

## Export

```
agentic-security export [--root <dir>] --out <dir>
```

Copies every **currently-present** registered artifact — `generated` *and*
`operator-config` alike, classification does not gate inclusion — from
`.agentic-security/` into `<dir>`, alongside `export-manifest.json`: one entry
per item, `{name, classification, retentionClass, status, sha256}` (`sha256`
is `null` for directories, computed for files). A copy of the same report is
also kept under `.agentic-security/export-report.json` as the "last export"
record. Unlike `reset`, an export is a snapshot for an operator's own
records, migration, or legal-preservation purposes — not a deletion decision
— so it deliberately reaches artifacts `reset` would never touch.

---

## Legal hold

```
agentic-security legal-hold add --artifact <name> --owner <id> --reason <text> [--expires <date>]
agentic-security legal-hold remove --artifact <name>
agentic-security legal-hold list [--all]
```

A hold is **identity-bound** (`--owner`, required), **reasoned** (`--reason`,
required — "we might need this later" is rejected), and **time-bounded where
applicable** (`--expires` is optional; omitting it is an indefinite hold, not
an error). Holds are recorded in `.agentic-security/legal-holds.json` itself
— which, as the table above shows, is `operator-config` and so is never
touched by `reset` on its own account. `--artifact` must name a real
registered artifact (from the table above); a typo is rejected rather than
silently accepted. `legal-hold list` (add `--all` to include expired/removed
ones) is the audit trail.

A held artifact is excluded from deletion in **both** `reset` paths: the
TTL-driven `reset --expired` (via `retention-policy.js#findExpiredArtifacts`)
and a plain `reset --yes`, which otherwise deletes every registered
`generated` artifact unconditionally.

---

## Related

- [Configuration & environment variables](../reference/configuration.md) —
  env vars and the policy-file catalog (what each file configures, not its
  retention).
- [CLI reference](../reference/cli.md) — full flag listing for `reset`,
  `export`, and `legal-hold`.
- [Risk in dollars](../guides/risk-dollars.md) — `risk-config.yml`, the one
  operator-config file that changes the *content* of dollar-figure findings
  rather than scanner behavior.
