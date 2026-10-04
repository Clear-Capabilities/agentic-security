# Fixing vulnerabilities

**Goal:** go from a finding to a fix that is *proven safe before it touches
your disk*.

**Prerequisites:** a scan has run (`.agentic-security/last-scan.json` exists).
The guided fix loop runs in **Claude Code** — that's the primary path shown
here; the bare-CLI equivalents are noted where they exist.

---

## The loop

```
triage → fix → verify (automatic) → applied, or rejected
```

1. **Triage** — decide what's worth fixing.
2. **Fix** — the tool composes a patch.
3. **Verify** — every patch passes a gate *before* it's written.
4. **Applied** if it passes; **not written** if it doesn't.

---

## 1. Triage

```text
/agentic-security:triage --show
/agentic-security:triage --explain <finding-id>
```

- `--show` ranks the open findings by risk (severity × exploitability), deduped.
- `--explain <id>` gives the plain-English why, the source-to-sink data-flow
  trace, and the recommended fix for one finding.

Finding ids look like `crypto-weak-hash:auth.js:11` or
`ir-taint:server.js:11:js-sql-query`. Get them from `--show`, or from
`scan . --format json`.

You can also validate a finding is real before spending effort on it —
`/agentic-security:triage --validate <id>` builds a proof-of-concept for
classes where that's possible.

---

## 2. Fix one finding

```text
/agentic-security:fix --finding <id>
```

The tool produces a patch one of three ways, in order of preference:

- **Deterministic, zero-LLM** for safe, context-independent classes (a weak
  hash swapped for SHA-256, TLS verification re-enabled) — no model call, no
  guessing.
- **Agent-composed** for everything else — the common case, where the fix
  depends on surrounding code.
- **From a stored template** when the rule ships one.

**In the terminal**, the CLI applies a fix directly only when the finding
carries a ready-made replacement:

```bash
npx @clear-capabilities/agentic-security-scanner fix --finding <id> --preview --root .
npx @clear-capabilities/agentic-security-scanner fix --finding <id> --apply   --root .
```

For findings that need a composed patch (most), run the `/agentic-security:fix`
command in Claude Code — that's where the compose-and-verify loop lives.

---

## 3. Verification is automatic — and non-negotiable

Every patch, however it was produced, must clear the same gate before it's
written:

- **Re-scan clean** — the finding is actually gone afterward.
- **No new ≥ medium finding** — the fix didn't introduce something worse.
- **Lint-clean** — your linter still passes.
- **Tests still pass** — the project's own test suite (when one is detected).
- **Fix-honesty gate** — a residual-risk guard rejects hand-wavy "adequately
  handled" claims, so a partial fix can't masquerade as complete.

A patch that fails any leg **is not written.** When the scan built a
proof-of-concept for the finding, the generated regression test ships with the
fix — it fails before the patch and passes after.

Each fix carries an honest completeness tier: **FULL**, **MITIGATION**, or
**WORKAROUND**, computed from mechanical signals (did the sink change? are all
callers routed through the fix? does a test flip from fail to pass?).

---

## Fix everything at once

```text
/agentic-security:find-and-fix-everything
```

This is the "just make it safe" path: it scans, then fixes across severities.
Independent findings fix **in parallel**, and a single failing verification
doesn't halt the batch — every finding gets a `fixed` / `skipped` / `refused`
verdict and the run reports its own **acceptance rate**.

`/agentic-security:fix --all` does the fix half on an existing scan.

---

## Haskell and Nix fixes

`fix --finding <id> --preview` and `--apply` route Haskell and Nix findings to their own fixers, which share one lifecycle
with the rest of the tool: a backup is written first, the change appears in `undo --list`, and `undo` restores the file byte
for byte.

- **Haskell** fixes five shapes: SQL parameterisation, shell-string to argument list, HTML escaping, SHA-256 for a weak
  hash, and log redaction. Each is labelled **FULL**, **MITIGATION** or **WORKAROUND** by what it changes and what it costs.
  The patch is applied at the dangerous call even when the finding is reported at the call that reaches it.
- **Nix** edits the definition that **wins by priority** (not the first match), and carries a tier: `full-source-edit`,
  `source-edit-requires-relock` (regenerate `flake.lock` yourself), `guidance-only` or `blocked`. A secret in the store is
  always guidance: moving a credential is a human decision.
- **Gates**, for both: the path stays inside the project, the result still parses, and a rescan shows the finding gone and
  **no new finding at medium or above**. A fix that fails a gate is reported with the reason and writes nothing; one the
  fixers do not support says so instead of inventing a patch.
- **Compiler or evaluator verification** is opt-in and runs only when the tool exists; otherwise the gate reads `not-run`.
- **Dependency upgrades** are source edits with an honest tier. For a declared Hackage dependency with a known fixed version,
  `fix --finding <id>` raises the bound in the manifest that declares it (`constraints-only (not re-resolved)`: nothing was
  re-resolved, so it is **not** a confirmed fix; a generated plan or freeze file is evidence, never edited). For a flake input,
  `fix --finding <id> --to <ref>` retargets the input and is `source-edit-requires-relock`: `flake.lock` is left untouched and
  no hash is invented. Both are reversible with `undo`.

See the real previews in [Haskell](haskell.md#fixes) and [Nix and NixOS](nix-nixos.md#fixes).

## Undo

Every applied fix is backed up and revertible:

```bash
npx @clear-capabilities/agentic-security-scanner undo          # revert the most recent fix
npx @clear-capabilities/agentic-security-scanner undo --list   # see the history
```

---

## Security debt over time

Every scan stamps each finding's age and flags anything past its remediation
SLA (critical: 7 days, high: 30, …), so debt is visible instead of silently
accumulating. See it via `/agentic-security:posture --report-card`.

---

## Related

- [Scanning](scanning.md) · [Responding to a leaked secret](leaked-secrets.md)
- [CI setup](ci-setup.md) — stop new vulns from merging in the first place
