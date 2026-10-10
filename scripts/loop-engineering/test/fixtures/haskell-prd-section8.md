# Haskell and Nix/NixOS PRD, section 8 structure fixture

This file is a committed structural copy of section 8 of the (untracked) Haskell and Nix/NixOS PRD: the same requirement IDs, weights, dependencies and suite keys, with placeholder titles and acceptance text. It exists so the controller tests do not depend on that document being present in a checkout (it is untracked by convention). The comparison with the real document is the separate maintainer check `npm run test:loop-real-prd`.

## 8. Atomic implementation requirements

**57 required requirements, 220 total weight points, 202 acceptance criteria**

### LOOP-001 — Fixture requirement LOOP-001

Weight: 3 | Dependencies: none | Verification suite: `loop-manifest`

Structural stand-in for the real requirement text.

Acceptance:

- **LOOP-001.AC01:** Placeholder acceptance text for LOOP-001.AC01.
- **LOOP-001.AC02:** Placeholder acceptance text for LOOP-001.AC02.
- **LOOP-001.AC03:** Placeholder acceptance text for LOOP-001.AC03.

### LOOP-002 — Fixture requirement LOOP-002

Weight: 5 | Dependencies: LOOP-001 | Verification suite: `loop-watchdog`

Structural stand-in for the real requirement text.

Acceptance:

- **LOOP-002.AC01:** Placeholder acceptance text for LOOP-002.AC01.
- **LOOP-002.AC02:** Placeholder acceptance text for LOOP-002.AC02.
- **LOOP-002.AC03:** Placeholder acceptance text for LOOP-002.AC03.
- **LOOP-002.AC04:** Placeholder acceptance text for LOOP-002.AC04.

### LOOP-003 — Fixture requirement LOOP-003

Weight: 3 | Dependencies: LOOP-001, LOOP-002 | Verification suite: `loop-background`

Structural stand-in for the real requirement text.

Acceptance:

- **LOOP-003.AC01:** Placeholder acceptance text for LOOP-003.AC01.
- **LOOP-003.AC02:** Placeholder acceptance text for LOOP-003.AC02.
- **LOOP-003.AC03:** Placeholder acceptance text for LOOP-003.AC03.
- **LOOP-003.AC04:** Placeholder acceptance text for LOOP-003.AC04.

### LOOP-004 — Fixture requirement LOOP-004

Weight: 3 | Dependencies: LOOP-001, LOOP-003 | Verification suite: `loop-dashboard`

Structural stand-in for the real requirement text.

Acceptance:

- **LOOP-004.AC01:** Placeholder acceptance text for LOOP-004.AC01.
- **LOOP-004.AC02:** Placeholder acceptance text for LOOP-004.AC02.
- **LOOP-004.AC03:** Placeholder acceptance text for LOOP-004.AC03.
- **LOOP-004.AC04:** Placeholder acceptance text for LOOP-004.AC04.

### LOOP-005 — Fixture requirement LOOP-005

Weight: 5 | Dependencies: LOOP-001, LOOP-002 | Verification suite: `loop-evidence`

Structural stand-in for the real requirement text.

Acceptance:

- **LOOP-005.AC01:** Placeholder acceptance text for LOOP-005.AC01.
- **LOOP-005.AC02:** Placeholder acceptance text for LOOP-005.AC02.
- **LOOP-005.AC03:** Placeholder acceptance text for LOOP-005.AC03.
- **LOOP-005.AC04:** Placeholder acceptance text for LOOP-005.AC04.

### LOOP-006 — Fixture requirement LOOP-006

Weight: 3 | Dependencies: LOOP-003, LOOP-004, LOOP-005 | Verification suite: `loop-recovery`

Structural stand-in for the real requirement text.

Acceptance:

- **LOOP-006.AC01:** Placeholder acceptance text for LOOP-006.AC01.
- **LOOP-006.AC02:** Placeholder acceptance text for LOOP-006.AC02.
- **LOOP-006.AC03:** Placeholder acceptance text for LOOP-006.AC03.
- **LOOP-006.AC04:** Placeholder acceptance text for LOOP-006.AC04.

### CORE-001 — Fixture requirement CORE-001

Weight: 2 | Dependencies: LOOP-006 | Verification suite: `capability-ledger`

Structural stand-in for the real requirement text.

Acceptance:

- **CORE-001.AC01:** Placeholder acceptance text for CORE-001.AC01.
- **CORE-001.AC02:** Placeholder acceptance text for CORE-001.AC02.
- **CORE-001.AC03:** Placeholder acceptance text for CORE-001.AC03.

### CORE-002 — Fixture requirement CORE-002

Weight: 3 | Dependencies: CORE-001 | Verification suite: `language-discovery`

Structural stand-in for the real requirement text.

Acceptance:

- **CORE-002.AC01:** Placeholder acceptance text for CORE-002.AC01.
- **CORE-002.AC02:** Placeholder acceptance text for CORE-002.AC02.
- **CORE-002.AC03:** Placeholder acceptance text for CORE-002.AC03.
- **CORE-002.AC04:** Placeholder acceptance text for CORE-002.AC04.

### CORE-003 — Fixture requirement CORE-003

Weight: 3 | Dependencies: CORE-001 | Verification suite: `language-contracts`

Structural stand-in for the real requirement text.

Acceptance:

- **CORE-003.AC01:** Placeholder acceptance text for CORE-003.AC01.
- **CORE-003.AC02:** Placeholder acceptance text for CORE-003.AC02.
- **CORE-003.AC03:** Placeholder acceptance text for CORE-003.AC03.

### HS-001 — Fixture requirement HS-001

Weight: 5 | Dependencies: CORE-002, CORE-003 | Verification suite: `haskell-parser`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-001.AC01:** Placeholder acceptance text for HS-001.AC01.
- **HS-001.AC02:** Placeholder acceptance text for HS-001.AC02.
- **HS-001.AC03:** Placeholder acceptance text for HS-001.AC03.
- **HS-001.AC04:** Placeholder acceptance text for HS-001.AC04.

### HS-002 — Fixture requirement HS-002

Weight: 5 | Dependencies: HS-001 | Verification suite: `haskell-ir`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-002.AC01:** Placeholder acceptance text for HS-002.AC01.
- **HS-002.AC02:** Placeholder acceptance text for HS-002.AC02.
- **HS-002.AC03:** Placeholder acceptance text for HS-002.AC03.
- **HS-002.AC04:** Placeholder acceptance text for HS-002.AC04.

### HS-003 — Fixture requirement HS-003

Weight: 5 | Dependencies: HS-002 | Verification suite: `haskell-injection`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-003.AC01:** Placeholder acceptance text for HS-003.AC01.
- **HS-003.AC02:** Placeholder acceptance text for HS-003.AC02.
- **HS-003.AC03:** Placeholder acceptance text for HS-003.AC03.
- **HS-003.AC04:** Placeholder acceptance text for HS-003.AC04.

### HS-004 — Fixture requirement HS-004

Weight: 3 | Dependencies: HS-002 | Verification suite: `haskell-security-rules`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-004.AC01:** Placeholder acceptance text for HS-004.AC01.
- **HS-004.AC02:** Placeholder acceptance text for HS-004.AC02.
- **HS-004.AC03:** Placeholder acceptance text for HS-004.AC03.

### HS-005 — Fixture requirement HS-005

Weight: 5 | Dependencies: HS-002, HS-003, HS-004 | Verification suite: `haskell-taint`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-005.AC01:** Placeholder acceptance text for HS-005.AC01.
- **HS-005.AC02:** Placeholder acceptance text for HS-005.AC02.
- **HS-005.AC03:** Placeholder acceptance text for HS-005.AC03.
- **HS-005.AC04:** Placeholder acceptance text for HS-005.AC04.

### HS-006 — Fixture requirement HS-006

Weight: 5 | Dependencies: HS-002, HS-005 | Verification suite: `haskell-web-auth`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-006.AC01:** Placeholder acceptance text for HS-006.AC01.
- **HS-006.AC02:** Placeholder acceptance text for HS-006.AC02.
- **HS-006.AC03:** Placeholder acceptance text for HS-006.AC03.
- **HS-006.AC04:** Placeholder acceptance text for HS-006.AC04.

### HS-007 — Fixture requirement HS-007

Weight: 3 | Dependencies: CORE-002, CORE-003 | Verification suite: `haskell-manifests`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-007.AC01:** Placeholder acceptance text for HS-007.AC01.
- **HS-007.AC02:** Placeholder acceptance text for HS-007.AC02.
- **HS-007.AC03:** Placeholder acceptance text for HS-007.AC03.

### HS-008 — Fixture requirement HS-008

Weight: 5 | Dependencies: HS-007 | Verification suite: `haskell-resolved-graph`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-008.AC01:** Placeholder acceptance text for HS-008.AC01.
- **HS-008.AC02:** Placeholder acceptance text for HS-008.AC02.
- **HS-008.AC03:** Placeholder acceptance text for HS-008.AC03.

### HS-009 — Fixture requirement HS-009

Weight: 5 | Dependencies: HS-002, HS-008 | Verification suite: `haskell-sca`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-009.AC01:** Placeholder acceptance text for HS-009.AC01.
- **HS-009.AC02:** Placeholder acceptance text for HS-009.AC02.
- **HS-009.AC03:** Placeholder acceptance text for HS-009.AC03.
- **HS-009.AC04:** Placeholder acceptance text for HS-009.AC04.

### HS-010 — Fixture requirement HS-010

Weight: 5 | Dependencies: HS-003, HS-004, HS-005, HS-007, HS-009 | Verification suite: `haskell-remediation`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-010.AC01:** Placeholder acceptance text for HS-010.AC01.
- **HS-010.AC02:** Placeholder acceptance text for HS-010.AC02.
- **HS-010.AC03:** Placeholder acceptance text for HS-010.AC03.
- **HS-010.AC04:** Placeholder acceptance text for HS-010.AC04.

### HS-011 — Fixture requirement HS-011

Weight: 3 | Dependencies: HS-005, HS-006, HS-009, HS-010, X-002, X-004, X-010, QA-001 | Verification suite: `haskell-support-gate`

Structural stand-in for the real requirement text.

Acceptance:

- **HS-011.AC01:** Placeholder acceptance text for HS-011.AC01.
- **HS-011.AC02:** Placeholder acceptance text for HS-011.AC02.
- **HS-011.AC03:** Placeholder acceptance text for HS-011.AC03.

### NIX-001 — Fixture requirement NIX-001

Weight: 5 | Dependencies: CORE-002, CORE-003 | Verification suite: `nix-parser-ir`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-001.AC01:** Placeholder acceptance text for NIX-001.AC01.
- **NIX-001.AC02:** Placeholder acceptance text for NIX-001.AC02.
- **NIX-001.AC03:** Placeholder acceptance text for NIX-001.AC03.

### NIX-002 — Fixture requirement NIX-002

Weight: 5 | Dependencies: NIX-001 | Verification suite: `nixos-module-resolution`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-002.AC01:** Placeholder acceptance text for NIX-002.AC01.
- **NIX-002.AC02:** Placeholder acceptance text for NIX-002.AC02.
- **NIX-002.AC03:** Placeholder acceptance text for NIX-002.AC03.
- **NIX-002.AC04:** Placeholder acceptance text for NIX-002.AC04.

### NIX-003 — Fixture requirement NIX-003

Weight: 5 | Dependencies: NIX-001, NIX-002 | Verification suite: `nix-script-taint`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-003.AC01:** Placeholder acceptance text for NIX-003.AC01.
- **NIX-003.AC02:** Placeholder acceptance text for NIX-003.AC02.
- **NIX-003.AC03:** Placeholder acceptance text for NIX-003.AC03.
- **NIX-003.AC04:** Placeholder acceptance text for NIX-003.AC04.

### NIX-004 — Fixture requirement NIX-004

Weight: 5 | Dependencies: NIX-002 | Verification suite: `nixos-hardening`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-004.AC01:** Placeholder acceptance text for NIX-004.AC01.
- **NIX-004.AC02:** Placeholder acceptance text for NIX-004.AC02.
- **NIX-004.AC03:** Placeholder acceptance text for NIX-004.AC03.
- **NIX-004.AC04:** Placeholder acceptance text for NIX-004.AC04.

### NIX-005 — Fixture requirement NIX-005

Weight: 5 | Dependencies: NIX-001, NIX-002 | Verification suite: `nix-build-trust`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-005.AC01:** Placeholder acceptance text for NIX-005.AC01.
- **NIX-005.AC02:** Placeholder acceptance text for NIX-005.AC02.
- **NIX-005.AC03:** Placeholder acceptance text for NIX-005.AC03.
- **NIX-005.AC04:** Placeholder acceptance text for NIX-005.AC04.

### NIX-006 — Fixture requirement NIX-006

Weight: 5 | Dependencies: NIX-001, NIX-002, NIX-003 | Verification suite: `nix-secrets-store`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-006.AC01:** Placeholder acceptance text for NIX-006.AC01.
- **NIX-006.AC02:** Placeholder acceptance text for NIX-006.AC02.
- **NIX-006.AC03:** Placeholder acceptance text for NIX-006.AC03.
- **NIX-006.AC04:** Placeholder acceptance text for NIX-006.AC04.

### NIX-007 — Fixture requirement NIX-007

Weight: 3 | Dependencies: NIX-001 | Verification suite: `nix-input-inventory`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-007.AC01:** Placeholder acceptance text for NIX-007.AC01.
- **NIX-007.AC02:** Placeholder acceptance text for NIX-007.AC02.
- **NIX-007.AC03:** Placeholder acceptance text for NIX-007.AC03.

### NIX-008 — Fixture requirement NIX-008

Weight: 5 | Dependencies: NIX-007 | Verification suite: `nix-resolved-closure`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-008.AC01:** Placeholder acceptance text for NIX-008.AC01.
- **NIX-008.AC02:** Placeholder acceptance text for NIX-008.AC02.
- **NIX-008.AC03:** Placeholder acceptance text for NIX-008.AC03.

### NIX-009 — Fixture requirement NIX-009

Weight: 5 | Dependencies: NIX-005, NIX-008, HS-009 | Verification suite: `nix-sca-patches`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-009.AC01:** Placeholder acceptance text for NIX-009.AC01.
- **NIX-009.AC02:** Placeholder acceptance text for NIX-009.AC02.
- **NIX-009.AC03:** Placeholder acceptance text for NIX-009.AC03.
- **NIX-009.AC04:** Placeholder acceptance text for NIX-009.AC04.

### NIX-010 — Fixture requirement NIX-010

Weight: 5 | Dependencies: NIX-003, NIX-004, NIX-005, NIX-006, NIX-009 | Verification suite: `nix-remediation`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-010.AC01:** Placeholder acceptance text for NIX-010.AC01.
- **NIX-010.AC02:** Placeholder acceptance text for NIX-010.AC02.
- **NIX-010.AC03:** Placeholder acceptance text for NIX-010.AC03.
- **NIX-010.AC04:** Placeholder acceptance text for NIX-010.AC04.

### NIX-011 — Fixture requirement NIX-011

Weight: 5 | Dependencies: NIX-008, LOOP-002 | Verification suite: `nix-eval-isolation`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-011.AC01:** Placeholder acceptance text for NIX-011.AC01.
- **NIX-011.AC02:** Placeholder acceptance text for NIX-011.AC02.
- **NIX-011.AC03:** Placeholder acceptance text for NIX-011.AC03.
- **NIX-011.AC04:** Placeholder acceptance text for NIX-011.AC04.

### NIX-012 — Fixture requirement NIX-012

Weight: 5 | Dependencies: CORE-003, HS-001, NIX-001 | Verification suite: `nixos-host-runtime`

Structural stand-in for the real requirement text.

Acceptance:

- **NIX-012.AC01:** Placeholder acceptance text for NIX-012.AC01.
- **NIX-012.AC02:** Placeholder acceptance text for NIX-012.AC02.
- **NIX-012.AC03:** Placeholder acceptance text for NIX-012.AC03.
- **NIX-012.AC04:** Placeholder acceptance text for NIX-012.AC04.

### X-001 — Fixture requirement X-001

Weight: 3 | Dependencies: HS-001, NIX-006 | Verification suite: `language-secrets`

Structural stand-in for the real requirement text.

Acceptance:

- **X-001.AC01:** Placeholder acceptance text for X-001.AC01.
- **X-001.AC02:** Placeholder acceptance text for X-001.AC02.
- **X-001.AC03:** Placeholder acceptance text for X-001.AC03.

### X-002 — Fixture requirement X-002

Weight: 5 | Dependencies: HS-002, HS-007, NIX-002, NIX-007 | Verification suite: `language-aibom`

Structural stand-in for the real requirement text.

Acceptance:

- **X-002.AC01:** Placeholder acceptance text for X-002.AC01.
- **X-002.AC02:** Placeholder acceptance text for X-002.AC02.
- **X-002.AC03:** Placeholder acceptance text for X-002.AC03.
- **X-002.AC04:** Placeholder acceptance text for X-002.AC04.

### X-003 — Fixture requirement X-003

Weight: 3 | Dependencies: HS-005, NIX-003, X-002 | Verification suite: `language-llm-agent`

Structural stand-in for the real requirement text.

Acceptance:

- **X-003.AC01:** Placeholder acceptance text for X-003.AC01.
- **X-003.AC02:** Placeholder acceptance text for X-003.AC02.
- **X-003.AC03:** Placeholder acceptance text for X-003.AC03.

### X-004 — Fixture requirement X-004

Weight: 5 | Dependencies: HS-005, NIX-003, NIX-006, X-002 | Verification suite: `language-privacy-lineage`

Structural stand-in for the real requirement text.

Acceptance:

- **X-004.AC01:** Placeholder acceptance text for X-004.AC01.
- **X-004.AC02:** Placeholder acceptance text for X-004.AC02.
- **X-004.AC03:** Placeholder acceptance text for X-004.AC03.
- **X-004.AC04:** Placeholder acceptance text for X-004.AC04.

### X-005 — Fixture requirement X-005

Weight: 3 | Dependencies: X-004, CORE-003 | Verification suite: `language-explorer`

Structural stand-in for the real requirement text.

Acceptance:

- **X-005.AC01:** Placeholder acceptance text for X-005.AC01.
- **X-005.AC02:** Placeholder acceptance text for X-005.AC02.
- **X-005.AC03:** Placeholder acceptance text for X-005.AC03.

### X-006 — Fixture requirement X-006

Weight: 3 | Dependencies: HS-005, NIX-003, X-004 | Verification suite: `language-polyglot-bridges`

Structural stand-in for the real requirement text.

Acceptance:

- **X-006.AC01:** Placeholder acceptance text for X-006.AC01.
- **X-006.AC02:** Placeholder acceptance text for X-006.AC02.
- **X-006.AC03:** Placeholder acceptance text for X-006.AC03.

### X-007 — Fixture requirement X-007

Weight: 3 | Dependencies: CORE-003, HS-005, NIX-004, NIX-009 | Verification suite: `language-assurance`

Structural stand-in for the real requirement text.

Acceptance:

- **X-007.AC01:** Placeholder acceptance text for X-007.AC01.
- **X-007.AC02:** Placeholder acceptance text for X-007.AC02.
- **X-007.AC03:** Placeholder acceptance text for X-007.AC03.

### X-008 — Fixture requirement X-008

Weight: 3 | Dependencies: HS-005, HS-009, NIX-004, NIX-009 | Verification suite: `language-evidence-posture`

Structural stand-in for the real requirement text.

Acceptance:

- **X-008.AC01:** Placeholder acceptance text for X-008.AC01.
- **X-008.AC02:** Placeholder acceptance text for X-008.AC02.
- **X-008.AC03:** Placeholder acceptance text for X-008.AC03.

### X-009 — Fixture requirement X-009

Weight: 3 | Dependencies: HS-010, NIX-010, X-008 | Verification suite: `language-proof-remediation`

Structural stand-in for the real requirement text.

Acceptance:

- **X-009.AC01:** Placeholder acceptance text for X-009.AC01.
- **X-009.AC02:** Placeholder acceptance text for X-009.AC02.
- **X-009.AC03:** Placeholder acceptance text for X-009.AC03.

### X-010 — Fixture requirement X-010

Weight: 3 | Dependencies: HS-008, HS-009, NIX-008, NIX-009 | Verification suite: `language-bom`

Structural stand-in for the real requirement text.

Acceptance:

- **X-010.AC01:** Placeholder acceptance text for X-010.AC01.
- **X-010.AC02:** Placeholder acceptance text for X-010.AC02.
- **X-010.AC03:** Placeholder acceptance text for X-010.AC03.

### X-011 — Fixture requirement X-011

Weight: 3 | Dependencies: X-004, X-007, X-008, X-010 | Verification suite: `language-compliance`

Structural stand-in for the real requirement text.

Acceptance:

- **X-011.AC01:** Placeholder acceptance text for X-011.AC01.
- **X-011.AC02:** Placeholder acceptance text for X-011.AC02.
- **X-011.AC03:** Placeholder acceptance text for X-011.AC03.

### X-012 — Fixture requirement X-012

Weight: 3 | Dependencies: CORE-003, X-004, X-008, X-010, X-011 | Verification suite: `language-report-formats`

Structural stand-in for the real requirement text.

Acceptance:

- **X-012.AC01:** Placeholder acceptance text for X-012.AC01.
- **X-012.AC02:** Placeholder acceptance text for X-012.AC02.
- **X-012.AC03:** Placeholder acceptance text for X-012.AC03.

### X-013 — Fixture requirement X-013

Weight: 3 | Dependencies: CORE-002, HS-005, NIX-003, X-007 | Verification suite: `language-scan-modes`

Structural stand-in for the real requirement text.

Acceptance:

- **X-013.AC01:** Placeholder acceptance text for X-013.AC01.
- **X-013.AC02:** Placeholder acceptance text for X-013.AC02.
- **X-013.AC03:** Placeholder acceptance text for X-013.AC03.
- **X-013.AC04:** Placeholder acceptance text for X-013.AC04.

### X-014 — Fixture requirement X-014

Weight: 3 | Dependencies: HS-005, NIX-004, X-007, X-013 | Verification suite: `language-integrations`

Structural stand-in for the real requirement text.

Acceptance:

- **X-014.AC01:** Placeholder acceptance text for X-014.AC01.
- **X-014.AC02:** Placeholder acceptance text for X-014.AC02.
- **X-014.AC03:** Placeholder acceptance text for X-014.AC03.
- **X-014.AC04:** Placeholder acceptance text for X-014.AC04.

### X-015 — Fixture requirement X-015

Weight: 3 | Dependencies: HS-002, NIX-001, X-002, X-003, X-007 | Verification suite: `language-local-ai`

Structural stand-in for the real requirement text.

Acceptance:

- **X-015.AC01:** Placeholder acceptance text for X-015.AC01.
- **X-015.AC02:** Placeholder acceptance text for X-015.AC02.
- **X-015.AC03:** Placeholder acceptance text for X-015.AC03.

### X-016 — Fixture requirement X-016

Weight: 3 | Dependencies: X-005, X-008, X-009, X-010 | Verification suite: `language-governance`

Structural stand-in for the real requirement text.

Acceptance:

- **X-016.AC01:** Placeholder acceptance text for X-016.AC01.
- **X-016.AC02:** Placeholder acceptance text for X-016.AC02.
- **X-016.AC03:** Placeholder acceptance text for X-016.AC03.

### QA-001 — Fixture requirement QA-001

Weight: 5 | Dependencies: CORE-001 | Verification suite: `language-corpora-integrity`

Structural stand-in for the real requirement text.

Acceptance:

- **QA-001.AC01:** Placeholder acceptance text for QA-001.AC01.
- **QA-001.AC02:** Placeholder acceptance text for QA-001.AC02.
- **QA-001.AC03:** Placeholder acceptance text for QA-001.AC03.
- **QA-001.AC04:** Placeholder acceptance text for QA-001.AC04.

### QA-002 — Fixture requirement QA-002

Weight: 5 | Dependencies: HS-011, NIX-009, X-004, X-010, QA-001 | Verification suite: `language-accuracy-regression`

Structural stand-in for the real requirement text.

Acceptance:

- **QA-002.AC01:** Placeholder acceptance text for QA-002.AC01.
- **QA-002.AC02:** Placeholder acceptance text for QA-002.AC02.
- **QA-002.AC03:** Placeholder acceptance text for QA-002.AC03.
- **QA-002.AC04:** Placeholder acceptance text for QA-002.AC04.

### QA-003 — Fixture requirement QA-003

Weight: 3 | Dependencies: LOOP-002, HS-001, HS-005, NIX-001, NIX-011, X-007 | Verification suite: `language-stress-offline`

Structural stand-in for the real requirement text.

Acceptance:

- **QA-003.AC01:** Placeholder acceptance text for QA-003.AC01.
- **QA-003.AC02:** Placeholder acceptance text for QA-003.AC02.
- **QA-003.AC03:** Placeholder acceptance text for QA-003.AC03.
- **QA-003.AC04:** Placeholder acceptance text for QA-003.AC04.

### QA-004 — Fixture requirement QA-004

Weight: 3 | Dependencies: NIX-012, X-012, X-014, QA-002 | Verification suite: `language-package-ci`

Structural stand-in for the real requirement text.

Acceptance:

- **QA-004.AC01:** Placeholder acceptance text for QA-004.AC01.
- **QA-004.AC02:** Placeholder acceptance text for QA-004.AC02.
- **QA-004.AC03:** Placeholder acceptance text for QA-004.AC03.

### QA-005 — Fixture requirement QA-005

Weight: 5 | Dependencies: X-001, X-002, X-003, X-005, X-006, X-007, X-008, X-009, X-010, X-011, X-012, X-013, X-014, X-015, X-016, QA-004 | Verification suite: `language-end-to-end`

Structural stand-in for the real requirement text.

Acceptance:

- **QA-005.AC01:** Placeholder acceptance text for QA-005.AC01.
- **QA-005.AC02:** Placeholder acceptance text for QA-005.AC02.
- **QA-005.AC03:** Placeholder acceptance text for QA-005.AC03.
- **QA-005.AC04:** Placeholder acceptance text for QA-005.AC04.

### DOC-001 — Fixture requirement DOC-001

Weight: 3 | Dependencies: CORE-001, HS-011, NIX-011, NIX-012, X-011, X-014, X-016 | Verification suite: `language-doc-coverage`

Structural stand-in for the real requirement text.

Acceptance:

- **DOC-001.AC01:** Placeholder acceptance text for DOC-001.AC01.
- **DOC-001.AC02:** Placeholder acceptance text for DOC-001.AC02.
- **DOC-001.AC03:** Placeholder acceptance text for DOC-001.AC03.

### DOC-002 — Fixture requirement DOC-002

Weight: 3 | Dependencies: QA-002, QA-005, DOC-001 | Verification suite: `language-doc-examples-metrics`

Structural stand-in for the real requirement text.

Acceptance:

- **DOC-002.AC01:** Placeholder acceptance text for DOC-002.AC01.
- **DOC-002.AC02:** Placeholder acceptance text for DOC-002.AC02.
- **DOC-002.AC03:** Placeholder acceptance text for DOC-002.AC03.

### DOC-003 — Fixture requirement DOC-003

Weight: 2 | Dependencies: LOOP-006, QA-003, DOC-001 | Verification suite: `loop-runbook`

Structural stand-in for the real requirement text.

Acceptance:

- **DOC-003.AC01:** Placeholder acceptance text for DOC-003.AC01.
- **DOC-003.AC02:** Placeholder acceptance text for DOC-003.AC02.
- **DOC-003.AC03:** Placeholder acceptance text for DOC-003.AC03.

### REL-001 — Fixture requirement REL-001

Weight: 2 | Dependencies: QA-005, DOC-002, DOC-003 | Verification suite: `language-release-final`

Structural stand-in for the real requirement text.

Acceptance:

- **REL-001.AC01:** Placeholder acceptance text for REL-001.AC01.
- **REL-001.AC02:** Placeholder acceptance text for REL-001.AC02.
- **REL-001.AC03:** Placeholder acceptance text for REL-001.AC03.
- **REL-001.AC04:** Placeholder acceptance text for REL-001.AC04.

## 9. Release gates and definition of done

Fixture end marker.
