// Same service with the tenant check in place.
const DOCUMENTS = new Map([
  ['doc-1001', { id: 'doc-1001', tenantId: 'acme', title: 'Q3 pricing plan' }],
  ['doc-2002', { id: 'doc-2002', tenantId: 'globex', title: 'Roadmap' }],
]);

export function findDocument(documentId) {
  return DOCUMENTS.get(documentId) || null;
}

export function canReadDocument(actor, documentId) {
  const doc = findDocument(documentId);
  return Boolean(actor && actor.userId && doc && doc.tenantId === actor.tenantId);
}
