# Fix

<!-- seo: title="Fix: What is the safest remediation?" description="Stage 8 of the Agentic Security assurance lifecycle: What is the safest remediation?" -->

**Stage 8 of 10.** What is the safest remediation?

**Maturity of this stage:** see the table below. Every capability carries its own label.

A fix is a candidate until it passes verification. Three sources produce one:

- a rule's stored fix;
- a **deterministic, zero-model swap** for context-independent classes (a weak hash to SHA-256, TLS verification re-enabled);
- an **agent-composed patch** for a finding with no stored fix.

Every patch is previewed, backed up and revertible (`agentic-security undo`). When the scan built a proof of concept, a regression test ships with the fix: it fails before the patch and passes after.

```bash
agentic-security fix --finding <id> --preview --root .
agentic-security fix --finding <id> --apply
```

When no mechanical fix exists, the CLI says so instead of inventing one. On the demo app's SQL injection the captured output was:

```text
No mechanical fix is available for this finding. Use the security-fixer subagent (default `fix` mode), or configure AGENTIC_SECURITY_LLM_PRESET=ollama for an AI-assisted proposal, then apply with `--apply`.
```

In Claude Code, the `security-fixer` agent composes the patch through the deterministic toolchain (`synthesize_fix`, `verify_fix`, `apply_fix`); it does not edit files directly.

**Evidence this stage creates:** A candidate patch, a backup and, where one was built, a regression test.

## Capabilities at this stage

<!-- generated:capabilities:fix:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Fix synthesis](../guides/fixing-vulnerabilities.md) | Fix | **GA** | A candidate patch, deterministic or agent-composed, with a preview, a backup and a revert path. A patch is never written without passing verification. |
<!-- generated:capabilities:fix:end -->

## Read more

- [Fixing vulnerabilities](../guides/fixing-vulnerabilities.md)
- [Responding to a leaked secret](../guides/leaked-secrets.md)
- [Verified remediation](../trust/verified-remediation.md)

---

Previous: [Trace](../trace/README.md) · Next: [Verify](../verify/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
