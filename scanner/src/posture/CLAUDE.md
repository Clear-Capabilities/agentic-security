# scanner/src/posture/

Annotators that run **after** every detector has emitted, plus state stores read by slash commands. 90+ modules — almost all small. Pattern: each module exports a function the engine wires into the annotation pipeline (`annotateX(findings, ctx)`), or a state-read/write helper (`loadX(scanRoot)`).

## What goes where (categories, not exhaustive)

**Annotation pipeline (mutate findings in place — order matters in `engine.js`)**
`finding-defaults` → `stable-id` → `clustering` → `reachability-filter` → `confidence` → `calibration` → `exploitability` → `mitigation-composite` → `persona-prioritization` → `why-fired`. The order is encoded in `engine.js`; if you add an annotator, decide whether it consumes upstream signals (confidence, family, parser) and place it after those.

**Calibration + held-out evaluation** — `calibration.js`, `calibration-drift.js`, `validator-metrics.js`, `holdout-eval.js`. The seed corpus lives at `calibration-seed.json`; held-out labels are taken via `loadLabeledJsonl`. Brier and ECE both live in `holdout-eval.js`; never reintroduce a "fit-on-the-table" version.

**Cross-language taint** — `cross-lang-{openapi,grpc,graphql,orm,queues,meta}.js`. Each parses a contract artifact (`openapi.json`, `*.proto`, `*.graphql`, queue config) and emits a chain finding when the same data crosses a language boundary into another module's finding.

**Risk amplification** — `epss.js`, `kev` (in `version.js`), `blast-radius.js`, `crown-jewels.js`, `exploitability.js`, `bounty-prediction.js`, `risk-in-dollars` (lives in `scripts/`, not here).

**Secrets lifecycle** — `secret-history.js` (git-history blob sweep for committed-then-removed secrets, behind `--secret-history`), `secret-live-check.js` (opt-in, offline-degrading live/dead/unknown labeling via a read-only provider "whoami"; behind `--validate-secrets`).

**Production-posture ingest** — `auth-posture-import.js`, `network-policy-import.js`, `telemetry-ingest.js`, `waf-ingest.js`, `feature-flags.js`. These read customer-side YAML and convert to mitigation flags consumed by `mitigation-composite.js`.

**Fix lifecycle** — `fix-history.js` (apply + backup + recover), `fix-verify.js` (closed-loop re-scan + lint), `fix-plan.js` (oversized-patch fallback), `regression-test-gen.js`, `deterministic-fix.js` (safe context-independent literal-swap patch synthesis — md5/sha1→sha256, TLS verify-off→on — materialized on demand by `mcp/synthesize_fix`; every patch still passes through `apply_fix`'s inline verify before it lands).

**Agentic verification** — `verifier.js`, `verifier-target.js`, `verifier-ephemeral.js`, `harness-discovery.js`, `adversary-agent.js`, `defender-agent.js`, `auditor-agent.js`, `three-agent-pipeline.js`.

**Integrity + signing** — `integrity.js` (per-install HMAC for `last-scan.json`), `rule-pack-signing.js`. The HMAC key lives at `$XDG_CONFIG_HOME/agentic-security/scan-key`; override via `$AGENTIC_SECURITY_HMAC_KEY`. Premortem-derived; do not regress to hostname-derived.

**Rule lifecycle** — `custom-rules.js` (YAML pattern DSL), `rule-overrides.js` (`disable:` gated on signature), `rule-packs.js`, `rule-synthesis.js` (proposes suppressions from triage feedback), `ruleset-version.js`.

**Posture artifacts** — `sbom.js`, `aibom.js`, `api-inventory.js`, `threat-model.js`, `trust-boundary-diagram.js`, `stack-playbook.js`, `deploy-platform.js`, `license-policy.js`, `material-change.js`, `mttr.js`, `streak.js`, `scorecard.js`, `security-trend.js`.

**Why this fired** — `why-fired.js`. Runs LAST so it reflects every annotation. Customer-facing provenance.

## Conventions

- **Mutate or copy?** Annotators that set finding fields mutate in place. Helpers that derive a *new* finding list (clustering, dead-code) return a new array.
- **State files.** All state goes under `.agentic-security/` (scan root) or `~/.config/agentic-security/` (per-install). Never write to the scanner source tree.
- **Annotation order matters.** If your annotator reads `f.confidence`, run it after `annotateConfidence`. If it reads `f.exploitability`, run it after `annotateExploitability`. Wire in `engine.js`, not in `index.js`.
- **No throwing.** Every annotation in `engine.js` is wrapped `try { … } catch (_) {}`. Your annotator must degrade gracefully — set `null` on the field and continue.
- **Dead-module test.** `npm run test:lifecycle` fails the build if you export a public symbol from a posture module that no other source file imports. Wire it in `engine.js` (or allowlist it with a written reason in `test/no-dead-modules.test.js`).

## Gotchas

- The seed `calibration-seed.json` is small (n < 30 for several families). Don't treat it as a held-out set — that's `holdout-eval.js`'s job, against an externally-supplied JSONL.
- `learning.js` (active-learning loop) is **opt-in** behind `AGENTIC_SECURITY_LEARN=1` and has a quorum gate. Do not lower the quorum default without thinking about what a malicious-PR-author could suppress.
- `why-fired.js` is the provenance surface customers screenshot. If you change its shape, downstream reports break — bump a version string and migrate consumers.
