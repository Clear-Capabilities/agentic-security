import { verifyCaller } from "./identity.js";

export async function authenticateHttpRequest(req: { headers: Record<string, string> }) {
  const result = await verifyCaller(req.headers["authorization"]);
  return result;
}

export function requireScopeForAction(action: string, scopes: string[]) {
  return { allowed: scopes.includes(action) };
}
