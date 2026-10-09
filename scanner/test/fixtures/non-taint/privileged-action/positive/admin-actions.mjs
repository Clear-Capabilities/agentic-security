// Guard for the admin actions menu. The flaw is authorisation by authentication alone.
const ADMIN_ACTIONS = new Set(['delete-workspace', 'rotate-api-keys', 'export-audit-log']);

export function isAdminAction(action) {
  return ADMIN_ACTIONS.has(action);
}

// Vulnerable: any authenticated actor passes, the role is never consulted.
export function canRunAdminAction(actor, action) {
  if (!actor || !actor.userId) return false;
  return isAdminAction(action);
}
