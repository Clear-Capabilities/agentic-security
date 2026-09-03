# M5, Governance Editing Workflow (deliverable #5): scoping

Per the M5 top-level scoping doc's own row for deliverable #5: flagged
as "genuinely the riskiest single item in Milestone 5," recommending
its own dedicated scoping investigation before any implementation plan.
This document grounds that investigation against the real codebase and
draws a materially narrower, disclosed scope line than the M5 doc's own
row implied was likely.

## What the PRD actually requires (a real correction to the M5 doc's own framing)

The load-bearing PRD text is line 1324 — a five-part contract, not a
dedicated acceptance criterion:

> "Saving scenarios, classification/governance edits, remediation
> state, attestations, policy changes, and external-system writes
> require an explicit write preview, schema validation, backup/version
> guard, user confirmation, and append-only audit event."

Nothing in this text mandates an HTTP/interactive surface specifically
— "user confirmation" is satisfied by a CLI confirmation prompt or flag
as much as by a web UI's own confirm button.

**A real, load-bearing correction found this session, before any plan
was written**: the Milestone 5 exit gate (PRD line ~1854, "AC-26,
AC-29, and AC-31") names **no acceptance criterion for this
deliverable at all**. It appears only in the deliverables bullet list
(line ~1852), with zero gating force on M5's own exit. This is
genuinely different from every other M5 deliverable shipped this
session (language coverage, large-graph pagination, What-If Simulator,
Blast-Radius Impact Assessment all had real, named ACs their own final
reviews checked against) — there is no `AC-governance-*` anywhere in
the PRD text. This does not make the feature unimportant, but it does
mean a materially narrower first cut cannot be accused of failing a
named exit criterion, since none exists.

`DFG-023` (`P1 | Governance/classification override workflow |
DFG-014, secure write service`) and `DFG-041` (Blast-Radius/
Remediation) are both real backlog rows — the M5 top-level doc's own
dependency claim (`DFG-041` partially depends on `DFG-023`) is
accurate. "Secure write service" is never defined anywhere else in the
PRD (confirmed: exactly one other mention, an unrelated line).

## What already exists (confirmed by direct investigation this session)

- **`apply_fix`'s real write gate is stronger than the M5 doc's own
  framing implied.** The M5 doc claims "every existing write precedent
  ... is shaped around re-running tests as validation, which does not
  transfer." Confirmed partially wrong: `apply_fix`
  (`scanner/src/mcp/tools.js:599`) requires `confirm: true` **plus a
  valid HMAC signature** on the proposed fix before writing anything —
  a real, reusable "propose → confirm → cryptographically-verify →
  write" shape. The re-run-tests half genuinely doesn't transfer to
  config data with no test suite to re-run, but the confirm+signature
  gate structure does, and is the more load-bearing half to reuse
  anyway.
- **`http-server.js`'s route table is confirmed 100% read-only in
  spirit** — 5 real routes, all GET except one (`POST
  /api/v1/query`, `http-server.js:67`), which is itself a read-only
  filtered graph query, never a write. **A real correction to the M5
  doc's own claim**: `MAX_REQUEST_BODY_BYTES = 64*1024`
  (`http-server.js:33`) is described there as "currently unused" — it
  is not; it is actively enforced at the request-handling layer
  (`http-server.js:240`) for any request carrying a body, already
  wired for the `/api/v1/query` POST route. No CSRF token exists
  anywhere in this server. The only auth is the session token carried
  in the URL fragment (the Wire sub-project's own established
  mechanism, Milestone 3) — this authenticates a READER, not a
  write-authorizer; a genuine HTTP write route would need a second,
  separate confirmation mechanism at minimum, real new security
  engineering this sub-project does not attempt.
- **`recipient-profiles.json` (FR-506) is confirmed a real, viable
  reuse target.** `validateRecipientProfile`
  (`scanner/src/lineage/recipient-profile.js:107`) and
  `loadRecipientConfig`
  (`scanner/src/lineage/recipient-registry.js:260`) are both real,
  already-shipped, already-tested. Of the PRD's own 5-part contract
  (preview, validation, backup/version guard, confirmation, audit
  event) mapped onto a real 7-step write path (read current config,
  accept a proposed edit, validate, diff/preview, confirm, atomic
  write, audit log): validation already exists; a real, directly
  reusable **audit-log primitive already exists** —
  `scanner/src/mcp/audit.js`'s `auditCall({sessionRoot, tool, args,
  outcome, reason})` appends to `.agentic-security/mcp-audit.log`
  (already OWASP-MCP08-hardened, already shipped, already used by the
  two existing write tools). Diff/preview has a real structural
  precedent in M4's own `computeGraphDiff` shape (compare
  before/after, report what changed) even though the entity being
  diffed here is a config file, not a graph. Propose/confirm/
  atomic-write are genuinely new but small — a `fs.writeFileSync` with
  a real backup-copy-first step is the entire "backup/version guard"
  clause.

## Design ruling: CLI-only first cut, HTTP write surface explicitly deferred

Given (a) no PRD acceptance criterion gates this deliverable at all,
(b) the PRD's own 5-part contract never mandates HTTP/interactivity,
(c) every M4/M5 deliverable shipped this session has been CLI-first
with zero UI/HTTP-write work, and (d) a genuine HTTP write route needs
real, separately-scoped security engineering (CSRF protection, a
write-authorization mechanism distinct from the existing read-only
session token) that this sub-project should not improvise under time
pressure — **this sub-project ships a CLI-only workflow**:

```
agentic-security governance propose-edit --file recipient-profiles.json
  --patch <patch-file.json> --output <preview-file> [--yes]
```

Covering the PRD's own 5-part contract exactly:
- **Write preview**: `--output` (or stdout) shows the proposed
  before/after diff before anything is written.
- **Schema validation**: reuses `validateRecipientProfile` (and its
  own `_isValidRecipientConfigEntry`-shaped per-entry checks) —
  a validation failure is a clear, non-writing error.
- **Backup/version guard**: the current file is copied to a
  timestamped backup path before the new content is written; a
  version/digest check on the current file (via a content hash)
  refuses to proceed if the file changed since the patch was computed
  against it (a real "someone else edited this concurrently" guard).
- **User confirmation**: `--yes` is required to actually write (its
  absence prints the preview and exits without writing — a dry-run by
  default, matching this session's own established "never write
  without an explicit signal" discipline).
- **Append-only audit event**: reuses `auditCall`'s own real,
  already-shipped, already-hardened mechanism (`src/mcp/audit.js`),
  writing to the same `.agentic-security/mcp-audit.log` the two
  existing write tools already use — not a new audit log format.

This is honestly disclosed as a first cut, not the full "governance
editing workflow" the PRD's richer vision (an interactive, in-product
review/approve UI) implies — the HTTP-server-side interactive write
surface (new routes, CSRF protection, a write-authorization mechanism)
remains real, unattempted, separately-scoped future work, matching this
sub-project's own explicit deferral of the same class of risk the M5
top-level doc itself flagged.

## Scope: `recipient-profiles.json` only, not a general config-editing framework

This sub-project targets exactly one config file
(`recipient-profiles.json`, FR-506) — the one file this codebase
already has real, tested, per-entry validation logic for. A general
"edit any governance-shaped config file" framework is out of scope; a
future increment extending this pattern to `privacy-policy.json`
(FR-408) or `privacy-governance.json` would follow the identical
shape, but is not built here.

## Out of scope (disclosed, not built)

- The HTTP-server interactive write surface (new POST routes, CSRF
  protection, a write-authorization mechanism distinct from the
  existing read-only session token) — the genuinely risky part this
  document's own ruling defers entirely.
- Any frontend/UI work.
- A general config-editing framework beyond `recipient-profiles.json`.
- Multi-user approval workflows (a second person approving a first
  person's proposed edit) — the PRD's own text says "user
  confirmation," singular, which this design satisfies with `--yes`;
  a real multi-party approval chain is separate, larger scope.
- Reopening/versioning history beyond the single timestamped backup
  file this design writes — a full version-history browser is not
  built.
