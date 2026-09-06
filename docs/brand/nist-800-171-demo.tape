# NIST SP 800-171 Rev. 3, assess, remediate, re-assess.
#
# Regenerate:  vhs docs/brand/nist-800-171-demo.tape      (run from the repo root)
# Requires:    vhs (charmbracelet), jq, and a built bundle:  cd scanner && npm run build
#
# The Hide block stages a scratch copy of examples/demo-app and symlinks the built
# bundle onto PATH, so the recorded commands read like a normal install. Everything
# after `Show` is real, real scans, real OSCAL documents, real control-state
# changes. Every number on screen was produced by the command above it.
#
# NOTE for editors: vhs 0.11's parser rejects escaped double quotes inside a
# `Type "..."` argument. Every command below is therefore written without any
# double quote at all, that is why the jq filters use @tsv and .control.function
# rather than string literals. Keep it that way or the tape stops parsing.
#
# The scan and the report are joined with `;`, NOT `&&`: `scan` exits non-zero
# when it finds anything (3 = critical), so `&&` short-circuits and the report
# never runs. That produced a GIF full of jq file-not-found errors.

Output docs/brand/nist-800-171-demo.gif

Set Shell bash
Set FontSize 15
Set Width 1360
Set Height 720
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 20ms

Hide
Type "export REPO=$PWD && export STAGE=$(mktemp -d)"
Enter
Type "cp -R examples/demo-app/. $STAGE/ && mkdir -p $STAGE/bin"
Enter
Type "ln -s $REPO/scanner/dist/agentic-security.mjs $STAGE/bin/agentic-security"
Enter
Type "export PATH=$STAGE/bin:$PATH && cd $STAGE && clear"
Enter
Show

Type "# A contractor app handling CUI. Does it meet NIST SP 800-171 Rev. 3?"
Enter
Sleep 1500ms

Type "agentic-security scan . > /dev/null 2>&1 ; agentic-security compliance --report nist-800-171-r3 --format oscal > before.json"
Enter
Sleep 6s

Type "# OSCAL assessment-results. What did it actually decide?"
Enter
Sleep 800ms
Type "jq -c '[.results[0].findings[]|.target.status.state]|group_by(.)|map({(.[0]):length})|add' before.json"
Enter
Sleep 3s

Type "# 46 decided, of 97. The other 51 are organisational -- physical security,"
Enter
Type "# training, personnel. No scanner can judge those, so they are recorded as"
Enter
Type "# observations, never as a fabricated verdict."
Enter
Sleep 3s

Type "clear"
Enter
Sleep 400ms

Type "# A failing control names the code responsible:"
Enter
Sleep 800ms
Type "agentic-security compliance --report nist-800-171-r3 --format json | jq -r '.[]|select(.controlRefs|length>0)|[.control.id,.control.function]|@tsv'"
Enter
Sleep 4s

Type "# 03.13.11 Cryptographic Protection is not an abstract gap. It is auth.js:11."
Enter
Sleep 1200ms
Type "sed -n '9,12p' auth.js"
Enter
Sleep 3s

Type "clear"
Enter
Sleep 400ms

Type "# Remediate: unsalted MD5 to salted scrypt, hardcoded key to environment."
Enter
Sleep 1200ms
Type "perl -pi -e 's/function hashPassword\(password\)/function hashPassword(password, salt)/' auth.js"
Enter
Sleep 800ms
Type "perl -pi -e 's/^const PAYMENT_API_KEY = .*/const PAYMENT_API_KEY = process.env.PAYMENT_API_KEY;/' auth.js"
Enter
Sleep 800ms
Type "perl -pi -e 's/crypto.createHash..md5...update.password..digest..hex../crypto.scryptSync(password, salt, 64).toString(\x27hex\x27)/' auth.js"
Enter
Sleep 800ms
Type "perl -pi -e 's|// Passwords hashed with MD5.*|// Salted scrypt (03.05.07, 03.13.11).|' auth.js"
Enter
Sleep 800ms
Type "sed -n '9,12p' auth.js"
Enter
Sleep 3s

Type "clear"
Enter
Sleep 400ms

Type "# Re-assess."
Enter
Sleep 600ms
Type "agentic-security scan . > /dev/null 2>&1 ; agentic-security compliance --report nist-800-171-r3 --format oscal > after.json"
Enter
Sleep 6s
Type "jq -c '[.results[0].findings[]|.target.status.state]|group_by(.)|map({(.[0]):length})|add' after.json"
Enter
Sleep 3s

Type "# 03.13.11, read from each document -- before, then after:"
Enter
Sleep 800ms
Type "jq -r '.results[0].findings[]|[.target.status.state,.title]|@tsv' before.json | grep 03.13.11 | cut -c1-54"
Enter
Sleep 2500ms
Type "jq -r '.results[0].findings[]|[.target.status.state,.title]|@tsv' after.json | grep 03.13.11 | cut -c1-54"
Enter
Sleep 3s

Type "# Two controls satisfied. No regressions. Evidence an assessor can read."
Enter
Sleep 3500ms
