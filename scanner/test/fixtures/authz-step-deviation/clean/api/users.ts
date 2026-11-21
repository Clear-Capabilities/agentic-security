import { authenticateHttpRequest, requireScopeForAction } from "./auth.js";

export async function handleUsersRequest(req: any, res: any) {
  const auth = await authenticateHttpRequest(req);
  if (!auth.ok) {
    res.statusCode = 401;
    return res.end();
  }
  const scope = requireScopeForAction("users.read", auth.scopes);
  if (!scope.allowed) {
    res.statusCode = 403;
    return res.end();
  }
  res.end(JSON.stringify({ users: [] }));
}
