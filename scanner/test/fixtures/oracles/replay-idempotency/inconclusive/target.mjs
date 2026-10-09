// Inconclusive: the handler never reaches its effect, so it was not shown to be working.
export function createHandler(deps) {
  return async function handle() { throw new Error('service unavailable'); };
}
