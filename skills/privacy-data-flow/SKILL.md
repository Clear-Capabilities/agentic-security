---
name: agentic-security:privacy-data-flow
description: Privacy review before handling user data. Activate on PII/PHI/PCI shapes (email, SSN, CC, MRN). Writes DATA_FLOW.md.
---

# Skill — privacy data-flow review

Activates **before** you write code that reads, stores, transmits, or logs
a piece of user data that may be classified PII / PHI / PCI / regulated.
Privacy violations almost always look fine in code review — they're
violations because of *where the data goes*, not what the line of code
says. This skill makes the destination visible BEFORE the data flows.

## When to fire

You're about to call `Edit` / `Write` with a body that touches one of
these data shapes:

**PII (general identifiability)**
- Email, phone, full name, date of birth, physical address, IP address,
  geolocation, government IDs (driver's license, passport, voter ID).
- Field names: `email`, `phone`, `dob`, `ssn`, `address`, `lat`/`lon`,
  `national_id`, `tax_id`, `student_id`.

**PHI (HIPAA)**
- Medical record number, prescription, diagnosis (ICD code), patient ID,
  insurance plan, treatment history.
- Field names: `mrn`, `patient_id`, `diagnosis`, `icd_code`, `prescription`,
  `treatment_plan`, `insurance_plan`.

**PCI (PCI-DSS)**
- Primary Account Number (PAN), CVV, card expiration, magnetic-stripe
  data, IBAN, full bank account number.
- Field names: `pan`, `card_number`, `cc_num`, `cvv`, `cvc`, `iban`,
  `bank_account`, `track_data`.

**Special category (GDPR Art. 9 / CCPA "sensitive personal info")**
- Race / ethnicity, religion, political opinions, sexual orientation,
  biometric / genetic data, trade-union membership.

**Confidential business**
- API keys, private keys, internal source code excerpts, customer lists,
  unannounced product names.

## What to do

1. **Pause before the Edit.** Don't write the code yet. Surface the
   data-class question.

2. **Classify the data.** For each user-data field the code touches,
   answer:
   - Class: PII / PHI / PCI / GDPR-Special / Confidential / Public.
   - Sensitivity: High (legal exposure) / Medium (reputational) / Low.

3. **Trace the destination.** Where does this field GO from this
   line of code? Walk the data flow:

   | Stage | Question |
   |-------|----------|
   | **Storage tier** | Database table? Cache (Redis)? Log file? Disk? In-memory? |
   | **Encryption at rest** | Is the storage tier encrypted? Per-row or per-disk? Key managed where? |
   | **Encryption in transit** | TLS required? Mutual TLS? Cert pinning? |
   | **Third-party processors** | Does this field reach: Stripe, Supabase, Clerk, Auth0, Sentry, PostHog, Segment, Mixpanel, OpenAI, Anthropic, AWS S3, Cloudflare, …? |
   | **Logging** | Does it appear in stdout, error logs, exception traces, request logs, audit logs? Is it redacted? |
   | **Retention** | How long is it kept? Where's the deletion trigger? Is "right to be forgotten" wired up? |
   | **Backups** | Does the backup include this field? Are backups encrypted? Same retention? |
   | **Replication** | Does the data cross a region boundary? Which? |

4. **Map to jurisdiction.** Which laws apply?
   - **GDPR** (EU users / EU operations): special category data needs
     explicit consent + lawful basis; cross-border transfer needs SCC.
   - **HIPAA** (PHI, US): BAA required with every processor; audit log
     mandatory; encryption at rest + in transit required for ePHI.
   - **PCI-DSS** (card data, anywhere): tokenize whenever possible;
     never log full PAN; segment the network.
   - **CCPA / CPRA** (California users): right to delete + right to
     opt-out of sale; sensitive personal info has stricter controls.
   - **State laws** (US): CPA, VCDPA, CTDPA — each has variants.

5. **Cite the existing controls** if they're in the codebase:
   - SECURITY.md / privacy policy already mentions this data class?
   - `.agentic-security/last-scan.json` flags it under crown-jewels?
   - Is there a `data_classes:` rule in `.agentic-security/rules.yml`?

6. **Write the result to the scratchpad via MCP**:

   ```
   append_scratchpad({
     path: ".agentic-security/agent-scratchpad/privacy/<session>/DATA_FLOW.md",
     content: "<the classification + flow + jurisdiction block>"
   })
   ```

7. **Propose the literal implementation** that satisfies every
   requirement that DOES apply. For each defensive measure, cite the
   regulation row in a code comment (e.g. `// GDPR Art. 32: encryption
   at rest`).

8. **Refuse outright** if the implementation would violate hard rules:
   - Logging full PAN → refuse. Use `xxxx xxxx xxxx 1234` masked form.
   - Sending PHI to a non-BAA-signed processor → refuse.
   - Storing CVV anywhere after authorization → refuse (PCI-DSS 3.2).
   - Sending special-category GDPR data without explicit consent flag
     in the request → refuse.

## What to write in DATA_FLOW.md

```markdown
# DATA_FLOW.md — privacy review for <feature/file>

## Field: <patient.diagnosis>
Date:        2026-05-20T14:32:00Z
File:line:   src/api/patient.ts:142
Construct:   `await db.patients.update({ where: { id }, data: { diagnosis } })`

### Classification
Class:       PHI (HIPAA)
Sensitivity: High
Field type:  ICD-10 code + free-text notes

### Flow
Storage tier:         postgres `patient_records` table (RDS, encrypted at rest with KMS)
Encryption transit:   TLS 1.3 (mTLS via the app's VPC to the DB)
Third-party seen by:  Sentry (error context — REDACTED via beforeSend hook)
                      Datadog (DOES NOT see — patient_id is hashed in logs)
                      OpenAI (DOES NOT see — diagnosis is never sent to LLM features)
Logging:              audit_log table (success only); error logs do NOT include
                      the value (redacted upstream)
Retention:            7 years per HIPAA 164.530(j); deletion via
                      DELETE_PATIENT_DATA function with BAA evidence
Backups:              encrypted; same 7y retention
Replication:          us-east-1 only; no cross-region replication

### Jurisdiction
HIPAA:        Yes — covered entity. BAA in place with Sentry, AWS, Datadog.
GDPR Art. 9:  Yes for EU patients — explicit consent flag (`consents.research`)
              required for any analytical use of diagnosis.
CCPA:         Sensitive personal info; opt-out flow at /privacy/opt-out.

### Decisions
- Diagnosis updates audit-logged with actor + before/after hash.
- LLM features (`summarizeHistory()` server-side helper) read a REDACTED view that strips
  free-text notes; only ICD codes flow through.
- Webhooks fired on update DO NOT include the diagnosis field
  (only `patient_id` + `event: diagnosis_updated`).

### Open questions
- Cross-border data flow on customer migration to EU region: do we
  need to negotiate SCC with Sentry before turning on EU?
- Patient export request: current PDF includes diagnosis verbatim; is
  that the right level of detail for the right-of-access response?
```

## Don't

- Don't write the code without classifying the data first.
- Don't trust "the user said it's fine to log." Logging PII / PHI / PCI
  almost always violates something even when the user is OK with it.
- Don't claim "we don't have GDPR users." Anyone visiting from the EU
  triggers GDPR scope. The question is whether you have CONTROLS for
  the case — not whether you have the users today.
- Don't paste the field's actual value into chat. Use a redacted form
  in DATA_FLOW.md too (the file lives in the scratchpad but is
  greppable; treat it like a security document).
- Don't write DATA_FLOW.md once per session and assume it covers every
  new field. Each new field touch-point gets its own block in the
  same DATA_FLOW.md.

## Canonical commands

- `/compliance --report` — generate PRIVACY.md + cookie banner from the stack
- `/compliance --report nist-ai-600-1|owasp-asvs-5|owasp-llm-top-10` — generate automated technical-control evidence
- `/scan --all` followed by `/triage --show --threat-model` — surface
  data-class findings the scanner already detected

## Why this is here

The `/compliance --report` slash produces a privacy artifact AFTER the project
is built. This skill produces a per-field data-flow record **before**
the field is written. The two are complementary — privacy-docs is the
post-hoc summary; this is the pre-write gate.
