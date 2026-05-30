---
name: agentic-security:threat-model-first
description: Walk STRIDE before adding auth / secret / external-API code. Activate on jwt / bcrypt / fetch / oauth / cipher / exec.
---

# Skill — threat-model before you write

Activates **before** you add or edit code that crosses a security
trust boundary. The cheapest place to fix a security bug is the moment
before you write it. This skill front-loads the threat modeling so the
implementation that follows is informed.

## When to fire

You're about to call `Edit` / `Write` with a body that introduces or
modifies one of these touch-points:

- **Authentication / session**: `jwt.sign`, `jwt.verify`, `bcrypt.hash`,
  `bcrypt.compare`, `passport.use`, `next-auth`, `Clerk`, `Auth0`,
  any code that reads/writes a session cookie.
- **Authorization / RBAC**: any `if (user.role === …)`, `requireRole`,
  `@PreAuthorize`, `before_action :authorize`, middleware that
  decides who can see what.
- **Secret handling**: `process.env.X` reading something that looks
  like a key, any `crypto.createCipheriv`, key generation, KMS calls.
- **External API**: `fetch(<url-from-input>)`, `axios.get(<url>)`,
  `requests.get(<url>)`, any HTTP call where the URL is user-derived.
- **OAuth flows**: `redirect_uri`, `state` parameter, PKCE setup,
  token exchange handlers.
- **File upload**: `multer`, `busboy`, `req.files`, `flask.request.files`,
  anything that touches user-supplied files.
- **Code-exec primitives**: `exec`, `spawn`, `subprocess`, `os.system`,
  `Runtime.exec` — the user-input cases are covered by
  `security-eval-warn` separately; this skill covers the
  threat-model angle.
- **Deserialization**: `pickle.loads`, `yaml.load`, `JSON.parse` of
  untrusted input, `xml.etree`.

## What to do

1. **Pause before the Edit.** Don't write the code yet. Tell the user
   you're going to threat-model first.

2. **Generate a session id** if one doesn't exist for this conversation.
   `tm-<YYYY-MM-DD>-<short hash of file path>` is fine.

3. **Walk STRIDE per touch-point.** For the specific construct the
   user is about to introduce, work through:

   | Letter | Category | Question to answer |
   |--------|----------|--------------------|
   | **S** | Spoofing | Who can claim to be a legitimate caller? What proves they are? Is the auth check before OR after the action? |
   | **T** | Tampering | Can the input be modified in transit? Is it signed / HMAC'd? Are the right fields integrity-protected? |
   | **R** | Repudiation | Is there an audit log? Does it survive deletion? Can the actor deny doing X? |
   | **I** | Information disclosure | What data does this code see / return / log? Is it the minimum? Are errors leaking schema / paths / secrets? |
   | **D** | Denial of service | What's the cost per request? Is there a rate limit? Can the input cause unbounded resource use (regex, JSON depth, image dimensions)? |
   | **E** | Elevation of privilege | Does the code path let a lower-privilege actor reach higher-privilege state? Is there a TOCTOU window? |

   For each letter, write ONE sentence. If a category doesn't apply
   for this specific touch-point, write "n/a — <one-line reason>".
   Don't skip categories; the skip itself is a decision worth recording.

4. **Write the result to the scratchpad via MCP**:

   ```
   append_scratchpad({
     path: ".agentic-security/agent-scratchpad/threat-model/<session>/TM.md",
     content: "<the STRIDE block + the construct + the file:line>"
   })
   ```

   Future turns in this session (and future agents) read this file
   to know what was already considered. Don't re-do the analysis.

5. **Propose the literal implementation** that satisfies every STRIDE
   row. Show the code. Highlight which row each defensive measure
   addresses (e.g. `// addresses S: signature verified before use`).

6. **Commit-as-you-go**: every time you add a defensive measure, cite
   the STRIDE row it addresses in a code comment. This is the
   compliance-cite-as-you-go pattern — auditors read your code as
   the threat-model artifact.

## What to write in TM.md

Structured. The file is meant to be greppable later:

```markdown
# TM.md — threat model for <feature/file>

## Touch-point: <jwt.verify in src/auth/middleware.ts>
Date:      2026-05-20T14:32:00Z
Agent:     <name of the agent that wrote this>
Construct: `jwt.verify(token, secret, { algorithms: ['RS256'] })`

### STRIDE
S: Token signature verifies via the project's public key. Caller's
   identity is established at this point; no other check trusts the
   `Authorization` header before this runs.
T: HMAC inside JWT signature covers the full payload. Custom claims
   ARE inside the signed envelope.
R: Audit log on auth events written to .audit_log (table); deletions
   require service-role; rotation in pg_audit weekly.
I: On verify failure, return 401 with NO detail string (don't leak
   "expired" vs "invalid signature"); both 401.
D: Rate-limit /auth/* to 10/sec/IP via Cloudflare; jwt verify itself
   is O(1) and bounded by signature math.
E: n/a — token only encodes user_id + role; role transitions go
   through a separate `POST /admin/promote` endpoint that requires admin.

### Decisions
- algorithms: ['RS256'] explicit (NOT 'none'; NOT the unverified
  jwt.decode())
- Cookie: httpOnly + Secure + SameSite=Lax
- TTL: 15 min access + 30 day refresh in separate http-only cookie

### Open questions
- Refresh-token rotation: still using sliding window; should switch
  to rotation-on-use before public launch.
```

## Don't

- Don't skip STRIDE rows. The skip is itself a decision; record it.
- Don't write the implementation without the TM.md first.
- Don't reuse a TM.md from a different touch-point. Each construct
  needs its own. The S row for `jwt.verify` is different from the
  S row for `bcrypt.compare`.
- Don't make the TM.md a wall of text. One sentence per row, max.
  If you can't say it in a sentence, you don't understand it yet.
- Don't bless the implementation if any STRIDE row is "I don't know."
  Stop and ask the user.

## Canonical commands

- `/posture --threat --view model` — auto-derived STRIDE from the last scan
- `/posture --threat --view personas` — per-attacker-persona prioritization
- `/posture --threat --view spof` — counterfactual: which control, if removed, exposes the most

## Why this is here

The `/posture --threat --view model` slash produces a STRIDE table from a completed scan.
This skill produces one **before** the code is written. The two are
complementary — pre-write TM.md catches design flaws; post-scan STRIDE
catches what made it through.
