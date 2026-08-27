import { blameLine } from './git-evidence.js';
import { EVIDENCE_ROLE } from './schema.js';

export function attributeEvidence(scanRoot, finding) {
  const nodes = [];
  const push = (role, file, line) => {
    if (!file || !line) return;
    const blame = blameLine(scanRoot, file, line);
    nodes.push({ role, path: file, line, commit: blame && !blame.uncommitted ? blame.commit : null });
  };

  if (finding.source || finding.sink) {
    if (finding.source) push(EVIDENCE_ROLE.SOURCE, finding.source.file || finding.file, finding.source.line);
    if (finding.sink) push(EVIDENCE_ROLE.SINK, finding.sink.file || finding.file, finding.sink.line);
  } else {
    push(EVIDENCE_ROLE.SINK, finding.file, finding.line);
  }

  if (Array.isArray(finding.pathSteps)) {
    for (const step of finding.pathSteps) {
      const role = step.removedGuard ? EVIDENCE_ROLE.REMOVED_GUARD : EVIDENCE_ROLE.TRANSFORMATION;
      push(role, step.file || finding.file, step.line);
    }
  }

  return nodes;
}
