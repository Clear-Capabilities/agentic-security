# Independent precision results

Date: 2026-10-26
Scanner version: 0.186.1
Labels digest: 4fd5cb4e8703105c82662f68e3edea808ec9f39c5bf3af3215c8b30d2afd4163

MEASUREMENT ONLY. See README.md and USE-LOG.md.

## Per language

| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson |
|---|---|---|---|---|---|---|---|---|
| javascript | 252 | 7 | 53 | 0 | 192 | 60 | 11.7% | 5.8% to 22.2% |
| nix | 282 | 4 | 55 | 1 | 222 | 59 | 6.8% | 2.7% to 16.2% |

## Per vulnerability class (classes with at least one label)

| group | flagged | tp | fp | ambiguous | unlabeled | tp+fp | precision | 95% Wilson |
|---|---|---|---|---|---|---|---|---|
| javascript | <fn>() acts on a resource without checking its lifecycle state | 11 | 0 | 3 | 0 | 8 | 3 | 0.0% | 0.0% to 56.1% |
| javascript | <fn>() looks up or mutates by request-supplied 'id' with no ownership check | 31 | 0 | 4 | 0 | 27 | 4 | 0.0% | 0.0% to 49.0% |
| javascript | <fn>() looks up or mutates by request-supplied 'uid' with no ownership check | 4 | 0 | 1 | 0 | 3 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | AuthZ: jwt.verify called without algorithms allow-list | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | Docker Service Publishes Sensitive Port N to Host | 8 | 3 | 0 | 0 | 5 | 3 | 100.0% | 43.9% to 100.0% |
| javascript | Eternal Token: JWT issued without expiresIn / exp claim | 4 | 0 | 1 | 0 | 3 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | GraphQL Mutation Block (Verify Field-Level Auth) | 4 | 0 | 1 | 0 | 3 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | JWT Sign (Verify Algorithm Pinned) | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | Known-Broken Code Marker Near Security-Sensitive Logic | 36 | 1 | 8 | 0 | 27 | 9 | 11.1% | 2.0% to 43.5% |
| javascript | Mass Assignment (req.body Direct to Model) | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | Missing Timeout on Outbound HTTP Request (DoS) | 17 | 3 | 3 | 0 | 11 | 6 | 50.0% | 18.8% to 81.2% |
| javascript | ORM Collection Query Without Pagination Limit (DoS) | 57 | 0 | 12 | 0 | 45 | 12 | 0.0% | 0.0% to 24.3% |
| javascript | Path Normalization Gap — extension extraction without null-byte/traversal sanitization | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | Pipeline: OIDC id-token: write without explicit aud restriction | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | Potential Indirect IDOR — findAll Without Ownership Scope | 12 | 0 | 3 | 0 | 9 | 3 | 0.0% | 0.0% to 56.1% |
| javascript | Regex ReDoS — Catastrophic Backtracking | 5 | 0 | 1 | 0 | 4 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | SQL Injection (Template Literal) | 5 | 0 | 1 | 0 | 4 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | SQL Injection — query built with template literal / concat (JS/TS) | 6 | 0 | 1 | 0 | 5 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | SQL Injection | 4 | 0 | 1 | 0 | 3 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | SSRF | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% |
| javascript | Stack Trace in Code (Risk of Exposure) | 3 | 0 | 2 | 0 | 1 | 2 | 0.0% | 0.0% to 65.8% |
| javascript | Synchronous Blocking I/O (DoS Risk in Server Context) | 6 | 0 | 2 | 0 | 4 | 2 | 0.0% | 0.0% to 65.8% |
| javascript | Timing-Unsafe Comparison — secret/HMAC compared with === instead of timingSafeEqual | 4 | 0 | 2 | 0 | 2 | 2 | 0.0% | 0.0% to 65.8% |
| javascript | Weak hash algorithm (MDN / SHA-N / MDN / MDN) used | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% |
| nix | Command Injection (os.popen / os.execlp) | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% |
| nix | Credential written as a literal in Nix source | 31 | 0 | 9 | 0 | 22 | 9 | 0.0% | 0.0% to 29.9% |
| nix | Hardcoded Secret | 26 | 0 | 4 | 0 | 22 | 4 | 0.0% | 0.0% to 49.0% |
| nix | High-Entropy Credential Candidate | 21 | 0 | 6 | 0 | 15 | 6 | 0.0% | 0.0% to 39.0% |
| nix | Known-Broken Code Marker Near Security-Sensitive Logic | 5 | 0 | 1 | 0 | 4 | 1 | 0.0% | 0.0% to 79.3% |
| nix | Nix interpolation reaches a shell command unescaped | 122 | 0 | 23 | 0 | 99 | 23 | 0.0% | 0.0% to 14.3% |
| nix | Pipeline: GitHub Action pinned to floating tag | 3 | 2 | 0 | 0 | 1 | 2 | 100.0% | 34.2% to 100.0% |
| nix | Pipeline: Third-party action pinned to major-version tag (mutable) | 3 | 1 | 0 | 0 | 2 | 1 | 100.0% | 20.6% to 100.0% |
| nix | Pre-quantum EDN (edN) — replace with ML-DSA-N before CRQC arrives | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0.0% to 79.3% |
| nix | SQL Injection (f-string SQL assigned to variable) | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% |
| nix | SSH accepts password authentication | 5 | 0 | 2 | 0 | 3 | 2 | 0.0% | 0.0% to 65.8% |
| nix | Secret value reaches the world-readable Nix store | 4 | 0 | 1 | 0 | 3 | 1 | 0.0% | 0.0% to 79.3% |
| nix | Shell evaluates a variable as code in a generated script | 2 | 0 | 1 | 0 | 1 | 1 | 0.0% | 0.0% to 79.3% |
| nix | TLS certificate verification disabled — MITM-vulnerable | 2 | 1 | 0 | 0 | 1 | 1 | 100.0% | 20.6% to 100.0% |
| nix | Unquoted shell expansion in a destructive command | 15 | 0 | 4 | 0 | 11 | 4 | 0.0% | 0.0% to 49.0% |
| nix | unsafe block — review for memory-safety invariants | 8 | 0 | 1 | 1 | 6 | 1 | 0.0% | 0.0% to 79.3% |

## Denominators and how to read them

- precision = tp / (tp + fp). Ambiguous sites are excluded from the denominator and counted separately.
- "unlabeled" are flagged sites that were NOT in the labeled random sample (the sample is a seeded random draw of 60 flagged sites per language, not the full flagged set) or are new since labeling. They are never counted. Precision is therefore an estimate for the flagged population of each language from the sample, not a census.
- Stale labels (labeled sites no longer flagged): 0.
- Intervals treat the sample as a simple random sample of sites. Sites cluster within files and rule families, so the true uncertainty is wider than shown. Per-class rows are small samples; read the intervals, not the point values.

## Limitations

- Labeled by one LLM agent reading source; not a human audit and not the scanner authors. No second labeler, so labeler disagreement is unmeasured.
- Scan roots and projects were chosen by the labeler (see manifest.json); projects are not a random draw of the ecosystem.
- Labels reflect the state of each project at the pinned commit, acquired on the date in manifest.json.
- The flagged set covers findings, logic vulnerabilities and secrets with a code line of at least 1; dependency and file-level findings (line 0) are out of scope. Test directories are excluded.
- "Weakness at that site" was judged with the rule's name as the claim; a site that is a real but differently-named weakness counts as fp for that rule.
