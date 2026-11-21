import { authenticateHttpRequest, requireScopeForAction } from "./auth.js";

export async function handleReportsRequest(req: any, res: any) {
  const auth = await authenticateHttpRequest(req);
  if (!auth.ok) {
    res.statusCode = 401;
    return res.end();
  }
  const scope = requireScopeForAction("reports.read", auth.scopes);
  if (!scope.allowed) {
    res.statusCode = 403;
    return res.end();
  }
  res.end(JSON.stringify({ reports: [] }));
}
