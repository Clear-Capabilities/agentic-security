# OWASP ASVS scanner coverage map

> **⚠ Known-stale (disclosed, Stage 6 correctness audit).** This table enumerates the full ASVS
> 4.0.3 standard by chapter (~162 requirements), but the engine-consumed
> `scanner/src/posture/compliance-frameworks/owasp-asvs-5.json` currently holds only 10 curated
> controls — this table matches neither the full standard's real requirement count nor what the
> engine actually assesses. No generator produces this file from the JSON, and nothing gates it
> against drift (see `docs/standards/README.md`, and the same disclosure on the NIST AI 600-1
> coverage map). Do not cite the counts below.

**Framework version:** OWASP Application Security Verification Standard 4.0.3

This table maps OWASP ASVS Level 1 and Level 2 requirements to scanner rules.
Level 3 (formal verification) requirements are almost entirely out of automated tool scope.

## Coverage summary (Level 1 + Level 2 combined)

| Chapter | Requirements | Covered | Partial | Not covered |
|---|---:|---:|---:|---:|
| V1: Architecture | 14 | 2 | 3 | 9 |
| V2: Authentication | 18 | 6 | 4 | 8 |
| V3: Session management | 14 | 4 | 2 | 8 |
| V4: Access control | 12 | 5 | 3 | 4 |
| V5: Validation / sanitization | 20 | 10 | 4 | 6 |
| V6: Cryptography | 16 | 8 | 3 | 5 |
| V7: Error handling / logging | 8 | 2 | 2 | 4 |
| V8: Data protection | 10 | 4 | 2 | 4 |
| V9: Communication security | 8 | 4 | 2 | 2 |
| V10: Malicious code | 4 | 2 | 1 | 1 |
| V11: Business logic | 6 | 2 | 2 | 2 |
| V12: Files and resources | 8 | 4 | 2 | 2 |
| V13: API and web service | 14 | 6 | 4 | 4 |
| V14: Configuration | 10 | 5 | 2 | 3 |
| **Total** | **162** | **64** | **36** | **62** |

> ~40% covered, ~22% partial. Numbers validated against ASVS 4.0.3 on 2026-05-18.

## Selected control-level mappings

### V2: Authentication verification

| Req | Description | Scanner rule | Status |
|---|---|---|---|
| 2.1.1 | Passwords ≥ 12 chars | `sast/authz.js` — weak password policy | Partial |
| 2.3.1 | Initial passwords randomly generated | `sast/cpp.js`/`sast/engine` — weak RNG | **Covered** |
| 2.4.1 | Passwords stored with bcrypt/scrypt/Argon2 | `sast/authz.js` — MD5/SHA1 password hash | **Covered** |
| 2.5.4 | No default credentials | `secrets/` — hardcoded credential scan | **Covered** |
| 2.7.1 | OTP / MFA not logged | — | Not covered |
| 2.8.1 | Time-based OTP valid ≤ 30s | — | Not covered |
| 2.10.1 | Secrets not in source code | `secrets/` — all hardcoded secret rules | **Covered** |

### V3: Session management

| Req | Description | Scanner rule | Status |
|---|---|---|---|
| 3.2.1 | Session tokens ≥ 128 bits entropy | `sast/authz.js` — weak session token | **Covered** |
| 3.2.3 | Session tokens stored securely | `sast/client-side.js` — localStorage tokens | **Covered** |
| 3.3.1 | Logout invalidates server-side session | — | Not covered |
| 3.4.1 | Cookies have Secure attribute | `sast/authz.js`; `sast/client-side.js` | **Covered** |
| 3.4.2 | Cookies have HttpOnly attribute | `sast/authz.js` | **Covered** |
| 3.4.5 | Cookies have SameSite attribute | `sast/authz.js` | Partial |

### V5: Validation, sanitization, encoding

| Req | Description | Scanner rule | Status |
|---|---|---|---|
| 5.2.1 | Untrusted HTML sanitized | `sast/client-side.js` — dangerouslySetInnerHTML | **Covered** |
| 5.2.2 | SQL parameterisation used | `sast/engine` — sql-injection detectors | **Covered** |
| 5.2.3 | Command injection prevented | `sast/cpp.js`; `sast/engine` — command-injection | **Covered** |
| 5.2.4 | LDAP injection prevented | `sast/engine` — LDAP injection | **Covered** |
| 5.2.5 | XPath injection prevented | `sast/engine` — XPath injection | **Covered** |
| 5.2.6 | XML external entities disabled | `sast/xxe.js` | **Covered** |
| 5.2.8 | Open redirects validated | `sast/client-side.js` — open redirect | **Covered** |
| 5.3.3 | Output encoding applied contextually | `sast/client-side.js` — XSS | Partial |
| 5.4.1 | Memory allocation validated | `sast/cpp-dataflow.js` — alloc-size-overflow | Partial |
| 5.5.1 | Serialized objects validated | `sast/java-deserialization.js`; `sast/csharp.js` | **Covered** |

### V6: Cryptography

| Req | Description | Scanner rule | Status |
|---|---|---|---|
| 6.2.1 | Cryptographic modules use FIPS-validated | — | Not covered |
| 6.2.2 | No custom crypto | `sast/engine` — weak-crypto detectors | Partial |
| 6.2.3 | Random values from CSPRNG | `sast/cpp.js`; `sast/engine` — weak-rng | **Covered** |
| 6.2.4 | Keys ≥ recommended lengths | `sast/authz.js` — JWT/RSA key size | Partial |
| 6.2.5 | No deprecated hash algorithms | `sast/engine` — MD5/SHA1 | **Covered** |
| 6.2.6 | No deprecated ciphers | `sast/engine` — DES/RC4 | **Covered** |
| 6.3.1 | GUIDs use version 4 | — | Not covered |
| 6.4.1 | Key material not hardcoded | `secrets/` — private-key detectors | **Covered** |

### V9: Communication security

| Req | Description | Scanner rule | Status |
|---|---|---|---|
| 9.1.1 | TLS used for all communications | `sast/engine` — insecure-http | **Covered** |
| 9.1.2 | TLS 1.2+ required | — | Not covered |
| 9.2.1 | Client certs validated | — | Not covered |
| 9.2.2 | Pinned certs used (mobile) | — | Not covered |

## How to generate an attestation report

```bash
/compliance --report asvs
```

The command produces `owasp-asvs-attestation.md` mapping scan findings to ASVS requirements.
Requirements not covered by the scanner are listed with "Manual verification required."
