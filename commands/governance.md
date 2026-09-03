---
description: Propose a validated, reviewable edit to recipient-profiles.json — preview, then --yes to write.
argument-hint: "propose-edit [path] --patch <file.json> [--output <file>] [--yes] [--base-digest <hex>]"
---

## Governance propose edit

Proposes a validated, reviewable edit to the operator-declared recipient
governance config (`recipient-profiles.json` — third-party and
cross-border recipient facts, FR-506). CLI-only: no PRD acceptance
criterion gates this deliverable at all — the PRD's own richer
"interactive review/approve UI" vision is deliberately out of scope
here; the HTTP-server-side interactive write surface (new routes, CSRF
protection, a write-authorization mechanism beyond the existing
read-only session token) is real, separately-scoped future work, not
attempted by this command.

Without `--yes`, previews the diff against the current file and writes
nothing — the default, safe mode. With `--yes`, re-validates the patch,
checks the version guard, backs up the current file, writes the new
content atomically, and appends a real, auditable event to
`.agentic-security/mcp-audit.log` — every write is backed up and
audited, with no exception.

### Options

| Flag | Required | Notes |
|---|---|---|
| `--patch <path-to-json>` | Yes | The `{"recipients": {...}}` patch file — an RFC-7396-style JSON MERGE PATCH against the current config, applied at the recipient-key level, never a full replacement of the whole file. Each key named in `recipients` **REPLACES that key's entire entry** (a named entry is never deep-merged with its old value). A key set to `null` **DELETES** that recipient — this is the only way to remove one. **A key NOT mentioned in the patch at all is left untouched** in the written file. A malformed patch file, or a recipient entry that fails `isValidRecipientConfigEntry`'s validation, is a clear exit-1 error, and nothing is written. |
| `--output <file>` | No | Where the preview/result report is written. Omitting this prints the report to stdout instead. |
| `--yes` | No | Perform the real write (backup + atomic write + audit event). Omitted, this is a dry-run preview only — the diff is computed and reported, the real file is never touched. |
| `--base-digest <hex>` | No | A SHA-256 digest of the config file content the patch was computed against. If the file's real current digest doesn't match, the write is refused as a concurrent-edit conflict (exit 2) — before any validation or write happens. Omitting this flag skips the version-guard check entirely. When the project has no `recipient-profiles.json` yet, the digest to compute is `sha256('{"recipients":{}}')` (the compact, no-whitespace literal — distinct from the pretty-printed JSON a real write produces, since a digest is only ever compared to another digest, never to file bytes). |

Exit codes: `0` on success (both the dry-run-preview path and the real
write path); `1` when the patch itself fails validation (never writes,
never backs up); `2` on a usage/argument error (missing `--patch`, an
unreadable/malformed `--patch` file) or a version-guard rejection (the
file changed since `--base-digest` was computed).

### Examples

```
/governance propose-edit --patch patch.json --output preview.json
/governance propose-edit --patch patch.json --yes
/governance propose-edit --patch patch.json --yes --base-digest a1b2c3...
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs governance "$@"
exit $?
```
