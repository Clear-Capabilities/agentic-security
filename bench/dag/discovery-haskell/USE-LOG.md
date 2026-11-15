# Use log (discovery set)

A development set. Every reading of its results that led to an engine change is recorded here, so a number quoted from it is read with that in mind.

| date | who | use | engine changes afterwards |
| --- | --- | --- | --- |
| 2026-11-02 | lead | Acquired the six projects (never scanned before), scanned once, read every flagged site and labelled it (`labels.json`). Hoogle reported nothing at first; its handler was dropped by two parser gaps (a `where` at the alternatives' column, `;`-separated statements on one line), found by reading the parser's own errors on the file, fixed generally, pinned on synthetic code, and the project rescanned (0 to 2 flagged, both read and labelled). Servant's 78 route-contract findings were one cause (a monorepo's example contract); the detector now scopes a contract to its package, pinned on synthetic trees. No rule was changed for any labelled site's verdict. | parser: the two layout rules; posture: `contractScope` |
| 2026-11-14 | lead | Re-read the three servant-auth-server cookie sites while working the fresh-set false positives (0.195.38). `scan.mjs --only=servant` before and after: flagged 8 to 5, the one true positive (`Internal.hs:1047`) kept. | The cookie rule: an XSRF-named cookie is readable by design (HttpOnly not required), an attribute set from configuration or by another helper over a handed-in record is `info` ("not judged"), a literal-valued cookie carries no credential (`haskell-security-rules.js`; pinned in `test/haskell/haskell-real-code-round2.test.js`). |
