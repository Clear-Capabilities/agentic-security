// PRD Product Acceptance Scenario G — uncommitted change.
//
// "The issue exists only in the working tree. Output says uncommitted, author
// unknown, and no email." Like the shallow-clone fixture, there is no correct
// SHA here — the finding was never committed, so there is nothing for a
// commit-based origin to name. Accuracy for this class means the engine
// correctly reported `status:'uncommitted'`.
//
// FAMILY CHOICE IS LOAD-BEARING. coordinator.js's uncommitted short-circuit
// (`annotateGitProvenance`'s "Cheap, correct short-circuit (PRD Scenario G)")
// keys on `finding.line` specifically — NOT `finding.sink.line`. Verified
// directly: the REGEX-parser injection families used elsewhere in this
// corpus (SQL Injection, Command Injection, Code Injection, Path Traversal)
// only ever populate `finding.sink.line`, never bare `finding.line`, so the
// short-circuit's `finding.file && finding.line` guard is false for all of
// them and they fall through to the ordinary history walk instead — which,
// for a genuinely uncommitted line, correctly still lands on `status:
// 'partial'` (reason `predicate-never-confirmed-in-candidates`), never a
// false `complete`, but is NOT the `uncommitted` status this scenario is
// actually about. The OWNERSHIP-AUTHZ family (`broken-access-control`,
// sast/logic-style detector) is one of the few that stamps `finding.line`
// directly, so it is what this fixture uses to exercise the intended
// short-circuit path rather than the generic partial-history fallback.
import * as fs from 'node:fs';
import * as path from 'node:path';

export const manifest = {
  id: 'uncommitted-change',
  scenario: 'PRD Scenario G — uncommitted change',
  description: 'A vulnerable edit exists only in the working tree, never committed.',
  expect: 'uncommitted',
  build(fx) {
    fx.writeFile('server.js', 'function h(req) {\n  return 1;\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    // Dirty the working tree WITHOUT committing.
    fs.writeFileSync(
      path.join(fx.root, 'server.js'),
      'function h(req) {\n  const input = req.query.id;\n  return db.find(input);\n}\n',
    );
    return null; // no commit is the correct answer for this class
  },
  finding: { file: 'server.js', line: 3, cwe: 'CWE-639' },
};
