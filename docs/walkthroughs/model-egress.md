# Walkthrough: model egress policy

**Goal:** see, with real output, that every outbound call this codebase
makes to an LLM provider is decided — allowed or denied — **before** a
prompt is built and **before** any HTTP client dials out, and that a denied
call leaves a persisted, tamper-evident audit trail instead of a silent
no-op.

This is the mechanism behind [Architecture](../ARCHITECTURE.md)'s "Egress
policy" paragraph: `egress/policy.js`'s `evaluateEgress()` decides whether a
call goes out at all; `egress/redact.js`'s `redactPayload()` decides what's
in it once it's allowed to. They are two separate gates, and only the first
one can produce a `'deny'`.

---

## Run It

Write an operator policy — this is the real example shape, every key below
is a genuine field `evaluateEgress()` reads:

```bash
mkdir -p .agentic-security
```

`.agentic-security/egress-policy.yml`:

```yaml
mode: local-only            # allow (default) | deny | local-only
allowedProviders: [anthropic]
deniedPaths: ["secrets/**"]
maxContextTokens: 8000
redactPii: true
proprietaryPaths: ["internal/**"]
customerDataPatterns: ["ACCT-\\d{8}"]
regulatedProfile:
  requireApprovedProviders: true
approvedProviders:
  anthropic: { dpaStatus: signed, baaStatus: signed, retentionPolicy: "zero-retention" }
```

Then configure an LLM endpoint (this is what turns the Layer-3 validator
on — see [Configuration reference](../reference/configuration.md)) and run
a normal scan:

```bash
AGENTIC_SECURITY_LLM_ENDPOINT=https://api.example-llm.test/v1/chat agentic-security scan .
```

The endpoint above is a remote HTTPS host, not a loopback address, and it
isn't `anthropic` — so this policy's `mode: local-only` and
`allowedProviders: [anthropic]` both have grounds to deny it. Read what
actually happened from the audit trail, not from the scan's own exit code:

```bash
cat .agentic-security/egress-audit.log
```

---

## What You'll See

Real captured `.agentic-security/egress-audit.log` — one line per
evaluated call, hash-chained (each entry's `prev` is the SHA-256 of the
line before it, so tampering breaks the chain from that point forward, the
same technique `mcp/audit.js` uses for MCP tool calls):

```json
{"ts":"2026-09-04T01:17:28.999Z","sessionId":"29737-m9kz29","purpose":"llm-validator","provider":"api.example-llm.test","model":"unknown","region":null,"policy":{"policySource":"config"},"outcome":"deny","reason":"egress mode is 'local-only' and the endpoint is not a loopback address","byteCount":null,"tokenCount":null,"contentHash":null,"prev":"GENESIS"}
{"ts":"2026-09-04T01:17:29.000Z","sessionId":"29737-m9kz29","purpose":"llm-validator","provider":"api.example-llm.test","model":"unknown","region":null,"policy":{"policySource":"config"},"outcome":"deny","reason":"egress mode is 'local-only' and the endpoint is not a loopback address","byteCount":null,"tokenCount":null,"contentHash":null,"prev":"ac50c589ef8c736d020d18dbfc060b0ebb995293db7f0c4ccd2840f44738cf0d"}
```

Notice what's *not* there: no prompt text, no code excerpt, no finding
content — `byteCount`/`tokenCount`/`contentHash` are all `null` because a
denied call never got far enough to build a payload to measure. That's by
design, documented in `egress/audit.js`'s own header: *"this module accepts
a byte count, a token estimate, and a content HASH — never the text
itself."*

---

## What It Means

- **The decision object has no `'redact'` value.** `evaluateEgress(ctx)`
  returns exactly `{allowed, decision, reason, provider, policySource,
  purpose}` where `decision` is `'allow'` or `'deny'` — never `'redact'`.
  Redaction is a completely separate module (`egress/redact.js`) that only
  ever runs on a payload for a call that egress policy has *already*
  allowed. Conflating the two would misrepresent what actually happened to
  a denied call: nothing was redacted, because nothing was ever built.

- **Three real modes, read from `egress-policy.yml`'s `mode:` key (or the
  `AGENTIC_SECURITY_EGRESS_MODE` env var, which wins if set):** `'allow'`
  is the default — no config file and no override means every call is
  evaluated but none is blocked by mode alone. `'deny'` blocks everything.
  `'local-only'` blocks everything that isn't a loopback address, using the
  same literal-only `isLoopbackUrl` check the local-endpoint preset uses
  for its own guarantee — which is what fired in the captured log above.
  There's also a blunt kill switch independent of any config file:
  `AGENTIC_SECURITY_EGRESS_DENY=1` denies every call, reason `"AGENTIC_SECURITY_EGRESS_DENY=1
  is set"`.

- **This runs before the prompt exists, not after.** The real call site,
  `llm-validator/index.js:464-475`:

  ```js
  const egressDecision = evaluateEgress({ scanRoot, purpose: 'llm-validator', endpoint: cfg.endpoint, role: 'validate', model: cfg.model });
  if (!egressDecision.allowed) {
    finding.validator_verdict = 'unvalidated';
    finding.unvalidated = true;
    finding._validatorError = 'egress-policy-denied';
    finding._egressDecision = egressDecision;
    finding.llmValidationStatus = MODEL_STATUS.POLICY_BLOCKED;
    recordEgressCall({ scanRoot, decision: egressDecision, ctx: { model: cfg.model, region: null } });
    return { verdict: 'unvalidated', error: 'egress-policy-denied', egressDecision };
  }
  ```

  This is line 464 of `renderPrompt`'s caller, and `renderPrompt` itself
  — the function that actually builds the text sent to a model — doesn't
  run until later in the same function. A `'deny'` here means
  `renderPrompt` is never called at all for that finding. The same gate
  covers every other real caller in the codebase that can dial an LLM
  endpoint: `discovery/llm-invoke`'s single- and consensus-endpoint paths,
  `adversary-agent`'s default path, flow-narration, and the SCA function
  extractor — verified in `egress/policy.js`'s own header by tracing every
  reference to `AGENTIC_SECURITY_LLM_ENDPOINT` in the codebase.

  A denied finding still gets tagged, not just dropped: `llmValidationStatus:
  'policy-blocked'` is one of five real values (`egress/policy.js`'s sibling
  module `llm-validator/model-status.js`'s `MODEL_STATUS`) — the other four
  are `'model-disabled'` (nothing configured at all), `'unavailable'` (the
  call was attempted and failed), `'malformed'` (a response came back but
  wasn't usable), and `'completed'` (a real verdict was produced). Only
  `'policy-blocked'` distinguishes "something was configured but a policy
  said no" from "nothing was configured to begin with" — that's the entire
  reason FR-606 introduced it.

  **One caveat worth knowing before you go looking for these fields:**
  `finding._egressDecision` and `finding.llmValidationStatus` exist on the
  in-memory finding while a scan runs, but `agentic-security scan .
  --format json`'s output is built by `report/index.js`'s
  `normalizeFindings()`, which projects each finding through an explicit
  field allowlist — and neither of those two fields is on it. The audit
  log above is the reliable, persisted place to see a real deny decision;
  don't expect to find `_egressDecision` by grepping scan JSON output.

- **Redaction is a separate, four-pass pipeline, and it runs regardless of
  what egress policy decided** — it's the content-level companion, not a
  fifth decision value. `redactPayload({text, filePath, scanRoot})` returns
  `{text, redactions, categories: {proprietaryPath, secrets, pii,
  customerData}}`. Real captured example, redacting one span that hits all
  four categories against the policy above:

  ```json
  {
    "text": "\nconst apiKey = \"[REDACTED-SECRET]\";\nconst patient = { email: \"[REDACTED-PII]\", ssn: \"[REDACTED-PII]\" };\nconst acct = \"[REDACTED-CUSTOMER-DATA]\";\n",
    "redactions": 4,
    "categories": { "proprietaryPath": 0, "secrets": 1, "pii": 2, "customerData": 1 }
  }
  ```

  The four passes run in a fixed order so an earlier, more specific pass
  never fights a later, more general one over the same span:
  1. **Proprietary paths** (`proprietaryPaths` globs) — whole-span
     replacement (`[REDACTED-PROPRIETARY-CONTENT]`) that short-circuits
     every other pass; there's nothing left to redact once the whole
     excerpt is gone.
  2. **Secrets** — reuses `llm-validator/redact.js`'s `redactSecrets`
     verbatim (API keys, tokens, PEM blocks, connection-string passwords,
     high-entropy literals).
  3. **PII/PHI/PCI/FIN** — keyed off `dataflow/privacy-taxonomy.js`'s field
     vocabulary, default **on** (`redactPii: false` to opt out).
  4. **Customer data** — operator-authored regex only
     (`customerDataPatterns`); no built-in default, because unlike PII
     there's no generic shape for "our internal account-number format" the
     engine could safely guess.

  This is exactly what runs at `llm-validator/index.js`'s own last choke
  point before a prompt is assembled — both the code excerpt and the
  finding snippet are passed through `redactPayload` there, separately, so
  a redaction bug in one span can't be reasoned about as covering the
  other.

---

## Try It Yourself

Flip the config's `mode` to `deny` (or skip the file entirely and set
`AGENTIC_SECURITY_EGRESS_MODE=deny` for a one-off run) and re-scan with the
same endpoint — every entry in the audit log should show `"outcome":"deny"`
with `"reason":"egress mode is 'deny'"` instead of the local-only reason
above. An **allowed** call is audited too, just at a different point:
`llm-validator/index.js:527` calls `recordEgressCall` again once the
redacted prompt actually exists, so an `"outcome":"allow"` line carries
real `byteCount`/`tokenCount`/`contentHash` — never the payload text
itself — where a denied line's are all `null` because nothing was ever
built to measure.

To see `redactPayload` directly rather than inferring it from a scan, call
it from a script (there's no dedicated CLI flag for this — the function is
what actually runs inline during prompt construction):

```js
import { redactPayload } from './scanner/src/egress/redact.js';

const result = redactPayload({
  text: 'const apiKey = "sk_live_EXAMPLE_NOT_A_REAL_KEY_0000000";',
  scanRoot: '.',
});
console.log(result);
```

---

## Go Deeper

- [Architecture](../ARCHITECTURE.md) — the one-paragraph summary this
  walkthrough expands on, in context with scan health and coverage.
- [Configuration reference](../reference/configuration.md) — the
  `AGENTIC_SECURITY_LLM_*` env vars that turn the validator on in the first
  place (`AGENTIC_SECURITY_EGRESS_MODE`/`AGENTIC_SECURITY_EGRESS_DENY` are
  real, read directly by `egress/policy.js`, but not yet listed there).
- [Finding evidence](finding-evidence.md) — how `validator_verdict` and the
  rest of a finding's LLM-validation fields read once a call *is* allowed.
