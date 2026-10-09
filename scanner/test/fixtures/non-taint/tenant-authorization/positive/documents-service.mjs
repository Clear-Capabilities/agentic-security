// Document service used by the /documents/:id route. No user input reaches a dangerous call here:
// the flaw is a missing ownership check, which a source-to-sink analysis cannot see.
const DOCUMENTS = new Map([
  ['doc-1001', { id: 'doc-1001', tenantId: 'acme', title: 'Q3 pricing plan' }],
  ['doc-2002', { id: 'doc-2002', tenantId: 'globex', title: 'Roadmap' }],
]);

export function findDocument(documentId) {
  return DOCUMENTS.get(documentId) || null;
}

// Vulnerable: any signed-in actor may read any document, whichever tenant owns it.
export function canReadDocument(actor, documentId) {
  const doc = findDocument(documentId);
  return Boolean(actor && actor.userId && doc);
}
