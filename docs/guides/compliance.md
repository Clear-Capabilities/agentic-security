# Compliance

**Goal:** produce an auditor-ready attestation for a framework, and find the
gaps you need to close — without the tool ever claiming assurance it didn't
earn.

**Prerequisites:** a scan has run. Compliance assessment reads the last scan
rather than re-scanning. Commands are shown as Claude Code
(`/agentic-security:compliance …`); a real CLI subcommand
(`agentic-security compliance …`) backs the privacy and gap flows.

---

## Pick a framework

```text
/agentic-security:compliance --list
```

Bundled frameworks include:

| Framework | Id |
|---|---|
| NIST AI 600-1 — Generative AI Profile | `nist-ai-600-1` |
| NIST Cybersecurity Framework 2.0 | `nist-csf-2` |
| NIST Privacy Framework 1.1 | `nist-privacy-1-1` |
| OWASP ASVS 5.0 | `owasp-asvs-5` |
| OWASP Top 10 for LLM Applications 2025 | `owasp-llm-top-10` |
| EU AI Act | `eu-ai-act` |
| GDPR · HIPAA Security Rule · CCPA | `gdpr` · `hipaa-security-rule` · `ccpa` |

You can also bring your own controls at
`.agentic-security/compliance/<id>/controls.json`.

---

## Three things you can produce

### A report (attestation)

```text
/agentic-security:compliance --report <framework>
```

Generates the auditor-ready attestation that maps your scan results to the
framework's controls.

### A walkthrough (narrative + evidence)

```text
/agentic-security:compliance --walkthrough <framework>
```

Adds a step-by-step auditor narrative with per-control evidence mapping — the
document you hand to someone who needs to see *how* each control was assessed.

### A gap worklist

```text
/agentic-security:compliance --gap <framework>
```

Filters to the controls that aren't clearing, each with its observations. It's
a worklist of what isn't passing — not a magic per-control fix button.

---

## The honesty model — why this won't inflate your score

The most important thing to understand: **a compliance opinion should never
manufacture assurance.** Every control lands in exactly one of four buckets,
and the bucket is always shown:

| Bucket | Meaning |
|---|---|
| **gap** | Mapped to an engine signal, and that signal is failing — the only bucket that emits a finding |
| **not assessed / engine-gap** | Code-testable, but this engine has no signal for it — disclosed by name, never counted as passed |
| **manual** | Governance/policy, outside any scanner's reach |
| **satisfied** | Mapped, checked, and passing |

The satisfied rate is reported over the controls **actually assessed**, never
over the full control count. For NIST Privacy Framework 1.1, for example, only
23 of 104 controls are fully code-testable — a report that quietly marked the
other 81 "passed" would be manufacturing assurance an auditor would rely on.
This tool tells you exactly how much of the framework it did *not* check.

---

## Gaps become fixable findings

For the privacy framework, each gap is emitted as an ordinary finding
(`family: privacy-compliance`, `CWE-359`) with an actionable remediation — so
`/agentic-security:fix` handles it like any other finding. This is opt-in, so a
compliance opinion doesn't silently become your build failure:

```bash
AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1 npx @clear-capabilities/agentic-security-scanner scan .
```

The assessment always writes `.agentic-security/privacy-framework.{json,md}`
regardless of the flag; the flag only controls whether gaps join
`scan.findings`.

---

## Exit codes (for CI)

The CLI `compliance` subcommand exits **0** when a report is produced, **2**
when there's no scan to assess, and **1** only when you ask it to fail with
`--fail-on gap`:

```bash
npx @clear-capabilities/agentic-security-scanner compliance --fail-on gap
```

---

## Related

- [SBOM & AI-BOM](sbom-and-ai-bom.md) — evidence several frameworks ask for
- [Coverage maps](../compliance/) — what each framework's controls map to
- [Fixing vulnerabilities](fixing-vulnerabilities.md)
