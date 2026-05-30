---
name: agentic-security:security-weak-crypto
description: Warn before writing weak crypto. Activate when agent is about to write md5/sha1 for passwords, DES/RC4, or static IVs.
---

# Skill — refuse weak crypto

Activates **before** you write code that uses a cryptographically broken
primitive. This is a "stop before the damage" skill — not a post-hoc
warning. By the time the scanner flags it, the code is already on disk.

## When to fire

You're about to call `Edit` / `Write` with a body that contains any of:

- **Hashing passwords with MD5 / SHA-1 / SHA-256**:
  `crypto.createHash('md5'|'sha1'|'sha256')` followed by `update(password)`,
  `hashlib.md5(password)`, `MessageDigest.getInstance("MD5")`, etc.
- **DES / 3DES / RC4** as the cipher:
  `crypto.createCipheriv('des'|'des-ede3'|'rc4', …)`, `Cipher.getInstance("DES")`,
  `from Crypto.Cipher import DES`.
- **Static IV** in any AES mode: `Buffer.alloc(16)`, hardcoded `Buffer.from('00000…')`,
  `bytes(16)` in Python, etc.
- **Math.random / random.random()** for security-sensitive randomness
  (tokens, session ids, password reset links).
- **JWT with `none` algorithm** or no signature verification.

## What to do

**Stop. Refuse the edit. Propose the right primitive.**

1. **Name the bug class** in plain English. "MD5 is unsuitable for
   password hashing — it's GPU-brute-forceable at ~100 GH/s."
2. **Cite the right primitive** for what they're trying to do:
   - Passwords → `bcrypt`, `scrypt`, `argon2`. Show the import.
   - Symmetric encryption → AES-GCM with a per-message random IV.
   - Tokens → `crypto.randomBytes(32).toString('hex')` (Node),
     `secrets.token_urlsafe(32)` (Python).
   - JWT → explicit `algorithms: ['RS256']` (or `HS256` with a
     long secret), `jwt.verify(...)` not `jwt.decode(...)`.
3. **Show the literal replacement** as a 3-line code block. Not a
   description — the actual code.
4. **Offer `/fix` if the file is already saved.** If the user already
   pushed it, route to `/fix --one <id>` after a scan picks it up.
5. **Don't proceed with the original Edit.** Force the user (or the
   parent agent) to confirm before writing the weak version.

## Don't

- Don't write the weak version and *then* warn. The order matters —
  you're a bodyguard, not a code reviewer.
- Don't accept "it's just for X" / "the user said so" justifications.
  If MD5 is fine here (e.g., file-hash deduplication, not password
  storage), confirm the use case BEFORE writing.

## Canonical commands

- `/setup --bodyguard` — make this skill mandatory on every Edit/Write
- `/scan --secrets` — pick up weak-crypto findings the bodyguard missed
- `/fix --one <id>` — close any md5/sha1-password finding already flagged
