// Infrastructure repair (verified-remediation PRD FR-15, M4-05): judge the EFFECTIVE configuration, not the edited text.
//
// Every declared configuration file of a revision is ingested together by the deployment boundary adapters (`src/lineage/deployment/`:
// container composition, Kubernetes manifests, a Terraform plan in JSON), so files merge the way the adapters model them: a
// composition override that re-publishes a port is part of the graph whatever the main file says. Nothing is executed, deployed or
// fetched; no cloud API is called.
//
//   checkInfrastructure  the `infrastructure-effective` obligation. A service is EXPOSED when a public route reaches it over routing
//                        edges (`routes-to`) alone: its own published port, load balancer or ingress. Every service the profile says
//                        must not be exposed must have no such route (the exposure is closed); every service it says must stay
//                        exposed must still have one (an approved workflow still works, AC-15.4). A route, hop or service the adapters
//                        could not resolve, and a file they could not parse, is a gap: the obligation fails rather than assume the
//                        exposure closed.
//
// Limits, stated: only the formats the adapters read; reachability through a service's dependencies (another service that is itself
// exposed) is not exposure here and is not judged; host firewalls, service meshes and cloud policies outside the files are not read;
// nothing is applied (the shared apply service never writes composition or Terraform files) and nothing is deployed.
import { ingestDeploymentConfig } from '../lineage/deployment/ingest.js';

/** Which services a public route reaches over routing edges only. Returns {exposed: Map(name -> route names), gaps: string[]}. */
export function directExposure(graph) {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const routesTo = new Map();
  for (const e of graph.edges) if (e.relation === 'routes-to') { if (!routesTo.has(e.from)) routesTo.set(e.from, []); routesTo.get(e.from).push(e); }
  const exposed = new Map(); const gaps = [];
  for (const start of graph.nodes.filter((n) => n.kind === 'route' && n.trustZone === 'public')) {
    const seen = new Set([start.id]); const queue = [start.id];
    while (queue.length) {
      const id = queue.shift();
      for (const e of routesTo.get(id) || []) {
        if (e.effect === 'deny' || seen.has(e.to)) continue;
        seen.add(e.to);
        const to = nodes.get(e.to);
        if (!to) { gaps.push(`${start.name}: routes to an unknown node`); continue; }
        if (to.resolved === false) gaps.push(`${start.name}: routes to an unresolved ${to.kind} ${to.name}`);
        if (to.kind === 'service') { if (!exposed.has(to.name)) exposed.set(to.name, []); exposed.get(to.name).push(start.name); }
        queue.push(e.to);
      }
    }
  }
  return { exposed, gaps };
}

/** The `infrastructure-effective` check over one revision's files. */
export function checkInfrastructure(decl, files) {
  const input = decl.files.filter((f) => typeof files[f] === 'string').map((f) => ({ path: f, text: files[f] }));
  const problems = [];
  for (const f of decl.files) if (typeof files[f] !== 'string') problems.push(`${f} is missing from the revision`);
  const g = ingestDeploymentConfig({ files: input, environment: decl.environment });
  if (!g || g.status !== 'ok' || !g.graph) return { ok: false, problems: [...problems, `the configuration could not be ingested: ${(g?.errors || []).map((e) => e.message).join('; ').slice(0, 200) || g?.status}`], exposed: {} };
  // every declared file must be read by an adapter: a file nobody parsed could re-open what the others close
  for (const f of g.files || []) if (f.status !== 'ingested') problems.push(`${f.file}: ${f.status}, so its effect on exposure is unknown`);
  const { exposed, gaps } = directExposure(g.graph);
  problems.push(...gaps);
  for (const s of decl.mustNotExpose) if (exposed.has(s)) problems.push(`${s} is still exposed by ${exposed.get(s).join(', ')}`);
  const services = new Set(g.graph.nodes.filter((n) => n.kind === 'service').map((n) => n.name));
  for (const s of decl.mustStayExposed) if (!exposed.has(s)) problems.push(`${s} is no longer exposed${services.has(s) ? '' : ' (the service is gone)'}: an approved workflow is broken`);
  return { ok: problems.length === 0, problems, exposed: Object.fromEntries([...exposed].map(([k, v]) => [k, v])) };
}
