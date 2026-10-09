// Fixed: the actor must belong to the resource's tenant.
export function authorize(actor, resource) {
  return Boolean(actor && resource && actor.tenant === resource.tenant);
}
