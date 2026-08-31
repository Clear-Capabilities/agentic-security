# Configuration & environment variables

Two ways to configure the scanner: **environment variables** (mostly on/off
toggles and endpoints) and **files under `.agentic-security/`** (per-project
policy and state). This page is the single reference for both.

---

## Environment variables

All are prefixed `AGENTIC_SECURITY_`. The ones you're most likely to touch:

### LLM features

| Variable | Effect |
|---|---|
| `AGENTIC_SECURITY_LLM_ENDPOINT` | The LLM endpoint. **Setting this is what turns on** the Layer-3 validator (default-on once configured) and enables `hunt`. With none set, all LLM features stay a no-op — no surprise network calls. |
| `AGENTIC_SECURITY_LLM_VALIDATE` | Set to `0` to opt *out* of LLM validation even when an endpoint is configured. |
| `AGENTIC_SECURITY_LLM_MODEL` | Model name for LLM calls. |
| `AGENTIC_SECURITY_LLM_API_KEY` | API key for the endpoint. |
| `AGENTIC_SECURITY_LLM_MAX_USD` | Hard spend ceiling for a run's LLM calls. |

### Analysis depth & scope

| Variable | Effect |
|---|---|
| `AGENTIC_SECURITY_DEEP` | Force deep (interprocedural) mode on. |
| `AGENTIC_SECURITY_PROVE` | Run the sandboxed PoC-execution pass (promotes findings to `execution-proven`). |
| `AGENTIC_SECURITY_RESUME` | Resume an interrupted scan from its checkpoint instead of restarting. |
| `AGENTIC_SECURITY_PRIVACY_FRAMEWORK` | Emit NIST Privacy Framework 1.1 gaps as fixable findings (see [compliance](../guides/compliance.md)). |
| `AGENTIC_SECURITY_OFFLINE` | Skip all network (OSV/registry/EPSS) — same as `--no-network`. |
| `AGENTIC_SECURITY_LINEAGE_DEEP` | Opt in to building the Data Flow Explorer lineage graph during a scan. Independent of `AGENTIC_SECURITY_DEEP` — see `src/lineage/DESIGN_GRAPH_BUILDER.md` §9.5. |
| `AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS` | Soft budget (ms) for the lineage graph build; measured, not enforced by interruption — an over-budget build still completes and emits an info finding. Default `300000`. |
| `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` | Per-function distinct-context cap for the lineage engine's interprocedural summary cache. Default `16`. |

### Finding provenance

Set by `scan`'s own `--provenance*` / `--*-author-*` flags — see the
[finding provenance guide](../guides/finding-provenance.md) for the full
picture. Documented here because they can also be set directly, e.g. from a
CI environment that doesn't invoke the CLI flags:

| Variable | Effect |
|---|---|
| `AGENTIC_SECURITY_NO_PROVENANCE` | Same as `--no-provenance`: skip git-history resolution, findings report `not_available`. |
| `AGENTIC_SECURITY_PROVENANCE_MODE` | `standard` (default) or `deep` — same as `--provenance <mode>`. |
| `AGENTIC_SECURITY_PROVENANCE_SINCE` | Same as `--provenance-since <ref>`: don't walk history earlier than this ref. |
| `AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS` | Whole-scan provenance budget in milliseconds — same as `--provenance-timeout`. |
| `AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL` | Same as `--include-author-email`: keep author emails in output (withheld by default). |
| `AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS` | Same as `--pseudonymize-authors`: replace author names with a stable `Contributor-XXXXXXXX` id. |
| `AGENTIC_SECURITY_GITHUB_TOKEN` / `AGENTIC_SECURITY_GITLAB_TOKEN` | Token for optional PR-metadata/CODEOWNERS provider enrichment; takes precedence over a token in `provenance-providers.yml`. |

### Turning a detector off

Most detectors have a `AGENTIC_SECURITY_NO_<NAME>` kill switch (e.g.
`AGENTIC_SECURITY_NO_CLOUD_IAM`, `AGENTIC_SECURITY_NO_ML_SUPPLY`,
`AGENTIC_SECURITY_NO_FALSIFICATION`). Set it to `1` to disable that pass. Run a
scan with `AGENTIC_SECURITY_DEBUG=1` to see which passes ran.

### Integrity & signing

| Variable | Effect |
|---|---|
| `AGENTIC_SECURITY_HMAC_KEY` | Override the per-install HMAC key (hex) used to sign `last-scan.json`. Default is a random per-install key at `$XDG_CONFIG_HOME/agentic-security/scan-key`. |
| `AGENTIC_SECURITY_RULES_UNSIGNED` | Allow `rules.yml` `disable:` entries without a verified signature (see below). |

### Notifications

`AGENTIC_SECURITY_SLACK_WEBHOOK`, `AGENTIC_SECURITY_DISCORD_WEBHOOK`,
`AGENTIC_SECURITY_TEAMS_WEBHOOK`, `AGENTIC_SECURITY_PAGERDUTY_KEY`,
`AGENTIC_SECURITY_ALERT_WEBHOOK`.

### Benchmark isolation

`AGENTIC_SECURITY_BENCH_SHAPE=1` enables answer-key reading (Juliet/OWASP
markers), off by default; `AGENTIC_SECURITY_BLIND_BENCH=1` forces it off. Never
enable bench-shape for a real scan.

> This is the commonly-used subset. The scanner recognizes many more toggles;
> `grep -rho 'AGENTIC_SECURITY_[A-Z_]*' scanner/src` from a checkout lists every
> one.

---

## Files under `.agentic-security/`

This directory lives at your project root. Everything in it is written there
(never into the scanner's own tree), and all of it is gitignored except the
files you author.

### State (generated — safe to delete, regenerated on next scan)

| File | Written by | Read by |
|---|---|---|
| `last-scan.json` (+ `.sig`) | every scan | every downstream command; the canonical output |
| `lineage-graph.json` (+ `.sig`) | a scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1` | the Data Flow Explorer's `DataFlowGraph v1` document for the scanned project |
| `findings.json` | every scan | digest, quick reads |
| `*-history.json`, `streak.json` | scans over time | trend / report-card |
| `privacy-framework.{json,md}` | compliance assessment | `/compliance` |
| `fix-metrics.jsonl` | the fix loop | MTTR / acceptance-rate reporting |
| `scan-checkpoint.jsonl` | a resumable scan | `--resume` |
| `provenance/lifecycle.json` | every scan (git repos) | [finding provenance](../guides/finding-provenance.md) — the introduce/remediate/reintroduce ledger; **not** subject to normal cache expiry, since it's permanent history |
| `provenance-cache/` | provenance resolution | provenance resolution — a pure `HEAD`-keyed memo, safe to delete, subject to normal cache retention |

`last-scan.json` is signed with the per-install HMAC key; tampering with it
outside the scanner makes the next read warn and re-scan.

### Policy (author these yourself — they change behavior)

| File | Purpose |
|---|---|
| `rules.yml` | Custom rules, severity overrides, ignore paths, and gated `disable:` entries |
| `rules/*.yml` | Custom YAML pattern rules (test with `rule test <glob>`) |
| `forbidden-apis.yml` | Per-project API denylist for the write-time bodyguard |
| `license-policy.yml` | Allow/deny/review licenses for the supply-chain license gate |
| `compliance/<id>/controls.json` | Bring-your-own compliance controls |
| `provenance-providers.yml` | Opt-in GitHub/GitLab PR-metadata + CODEOWNERS enrichment config (token per provider) — see [finding provenance](../guides/finding-provenance.md) |
| `repo-lineage.json` | Cross-repository lineage link (`{linkedFrom: {path, atCommit}}`) for a root-commit finding origin — local clones only, no remote fetch |

### The `rules.yml` gate

`disable:` entries — the ones that *reduce* coverage — take effect only when a
sibling `.sig` verifies under the per-install HMAC key, or when
`AGENTIC_SECURITY_RULES_UNSIGNED=1` is set. This stops a malicious PR from
silently disabling a detector. The non-coverage-reducing keys
(`severityOverrides`, `custom:`, `ignorePaths`) are **not** gated.

A custom rule marked `shadow: true` writes to
`.agentic-security/shadow-findings.json` and is excluded from CI gates — for
trialing a rule before it blocks anything.

---

## Suppression pragma

Line-scoped, in the source itself:

```js
someRiskyThing(); // agentic-security-ignore: <rule-id>
```

Matches the finding's rule id, vuln, CWE, or family. A bare
`// agentic-security-ignore` suppresses everything on the line. Every
suppression is logged and shown by `scan --include-suppressed`. See
[scanning](../guides/scanning.md#suppressing-a-finding).

---

## Related

- [CLI reference](cli.md)
- [Cost optimization](../MODEL_COST_OPTIMIZATION.md) — the model-cost advisor's own config
