// Vulnerable: any signed-in actor is allowed, whatever tenant owns the resource.
export function authorize(actor, resource) {
  return Boolean(actor && actor.id);
}
