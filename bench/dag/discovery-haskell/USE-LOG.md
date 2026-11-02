# Use log (discovery set)

A development set. Every reading of its results that led to an engine change is recorded here, so a number quoted from it is read with that in mind.

| date | who | use | engine changes afterwards |
| --- | --- | --- | --- |
| 2026-11-02 | lead | Acquired the six projects (never scanned before), scanned once, read every flagged site and labelled it (`labels.json`). Hoogle reported nothing at first; its handler was dropped by two parser gaps (a `where` at the alternatives' column, `;`-separated statements on one line), found by reading the parser's own errors on the file, fixed generally, pinned on synthetic code, and the project rescanned (0 to 2 flagged, both read and labelled). Servant's 78 route-contract findings were one cause (a monorepo's example contract); the detector now scopes a contract to its package, pinned on synthetic trees. No rule was changed for any labelled site's verdict. | parser: the two layout rules; posture: `contractScope` |
