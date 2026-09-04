# OWASP ASVS scanner coverage map

**Framework version:** OWASP Application Security Verification Standard 5.0

This page previously enumerated the ASVS **4.0.3** standard by chapter (~162 requirements) and
claimed specific coverage/partial/not-covered counts per chapter. Two things were wrong with
that: the engine-consumed mapping (`scanner/src/posture/compliance-frameworks/owasp-asvs-5.json`)
is versioned **5.0**, not 4.0.3 (a version mismatch this page itself introduced, found during the
Stage 6 correctness audit), and it holds only **10** hand-curated controls, not 162 — the static
table matched neither the real standard's requirement count nor what the engine actually
assesses, and nothing gated it against drifting further.

Unlike NIST AI 600-1, there is no separate full-spreadsheet ASVS scanner in this repository —
`owasp-asvs-5.json` is the only ASVS mapping that exists. Get the current, correct answer with:

```bash
/compliance --walkthrough owasp-asvs-5      # narrative, per-control evidence
/compliance --report owasp-asvs-5           # same evaluation, attestation framing
/compliance --report owasp-asvs-5 --format json      # structured {control, status, observations}[]
```

Each control's `status` is `present` (every mapped signal is clean), `partial` (some signal
present but not all clear, or an unverifiable `rule:` mapping), `absent` (mapped, but nothing
passed), or `manual` (no automated mapping — requires human attestation). Requires a prior scan
(`/scan --all`) — the report is a statement about a scan that happened, not a live re-scan.

**10 curated controls is intentionally narrow, not a hidden gap.** The mapping favors a small
set of high-confidence, code-detectable ASVS 5.0 requirements (authentication enforcement,
access control, injection classes, crypto/TLS posture, secrets handling) over attempting broad
coverage of a ~350-requirement standard most of which (session-management minutiae, formal
verification, organizational process) is not code-detectable at all. Extending the mapping means
adding entries to `owasp-asvs-5.json`, not editing this page — see `docs/standards/README.md`.
