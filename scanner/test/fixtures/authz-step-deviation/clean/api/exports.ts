import { verifyCaller } from "./identity.js";
import { requireScopeForAction } from "./auth.js";

export async function handleExportRequest(req: any, res: any) {
  const auth = await verifyCaller(req.headers["authorization"]);
  if (!auth.ok) {
    res.statusCode = 401;
    return res.end();
  }
  const scope = requireScopeForAction("export.read", auth.scopes);
  if (!scope.allowed) {
    res.statusCode = 403;
    return res.end();
  }
  res.end(JSON.stringify({ export: "all records" }));
}
