// Same guard, with the role required.
const ADMIN_ACTIONS = new Set(['delete-workspace', 'rotate-api-keys', 'export-audit-log']);

export function isAdminAction(action) {
  return ADMIN_ACTIONS.has(action);
}

export function canRunAdminAction(actor, action) {
  if (!actor || !actor.userId) return false;
  if (!isAdminAction(action)) return false;
  return Array.isArray(actor.roles) && actor.roles.includes('admin');
}
