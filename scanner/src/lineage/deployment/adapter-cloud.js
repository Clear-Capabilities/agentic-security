// adapter-cloud.js: Terraform plan JSON and IAM policy documents into
// deployment boundary nodes and edges (X-302).
//
// Input is a plan that someone already produced (`terraform show -json`); this
// adapter never runs terraform, never evaluates HCL and never contacts a
// provider. Values the plan itself marks as unknown after apply are not
// guessed: the relation becomes an unresolved node plus a gap. Policy
// documents are read with JSON.parse; `NotAction` / `NotResource` statements
// and conditions it cannot interpret are reported, not approximated.

import { adapterContext, isObject, asArray, str } from './adapter-kit.js';

export const TERRAFORM_PARSER = 'terraform-plan-json';
export const TERRAFORM_PARSER_VERSION = '1';
export const IAM_PARSER = 'iam-policy-json';
export const IAM_PARSER_VERSION = '1';

const MAX_STATEMENTS = 200;
const MAX_RESOURCES_PER_STATEMENT = 50;

function toList(v) { return typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter(x => typeof x === 'string') : []; }

/** Emit grants edges for every statement of a policy document. Returns the number of statements read. */
function applyPolicy(kit, identity, policy, subject) {
  const statements = Array.isArray(policy?.Statement) ? policy.Statement : isObject(policy?.Statement) ? [policy.Statement] : null;
  if (!statements) { kit.gap('malformed-input', subject, 'policy document has no Statement'); return 0; }
  let read = 0;
  for (const st of statements.slice(0, MAX_STATEMENTS)) {
    if (!isObject(st)) { kit.gap('malformed-input', subject, 'a policy statement that is not an object is skipped'); continue; }
    if (st.NotAction !== undefined || st.NotResource !== undefined || st.NotPrincipal !== undefined) {
      kit.gap('unsupported-syntax', subject, 'NotAction, NotResource and NotPrincipal statements are not interpreted; the statement is skipped');
      continue;
    }
    const effect = st.Effect === 'Allow' ? 'allow' : st.Effect === 'Deny' ? 'deny' : null;
    if (!effect) { kit.gap('malformed-input', subject, `statement Effect must be Allow or Deny, got ${JSON.stringify(st.Effect)}`); continue; }
    const actions = toList(st.Action).sort();
    const resources = toList(st.Resource);
    if (actions.length === 0 || resources.length === 0) { kit.gap('malformed-input', subject, 'a statement without Action and Resource is skipped'); continue; }
    const conditioned = isObject(st.Condition) && Object.keys(st.Condition).length > 0;
    read += 1;
    if (resources.length > MAX_RESOURCES_PER_STATEMENT) kit.gap('limit-exceeded', subject, `a statement lists ${resources.length} resources; only the first ${MAX_RESOURCES_PER_STATEMENT} are read`);
    for (const r of resources.slice(0, MAX_RESOURCES_PER_STATEMENT)) {
      const target = kit.node('resource', `aws/${r}`, { trustZone: 'internal', attrs: r === '*' ? { wildcard: true } : {} });
      const attrs = { actions: actions.join(',').slice(0, 250) };
      if (conditioned) attrs.conditioned = true;
      kit.edge('grants', identity, target, {
        effect, confidence: conditioned ? 'low' : 'high', discriminator: `${actions.join(',')}${conditioned ? ';cond' : ''}`.slice(0, 250), attrs,
      });
    }
  }
  if (statements.length > MAX_STATEMENTS) kit.gap('limit-exceeded', subject, `policy has ${statements.length} statements; only the first ${MAX_STATEMENTS} are read`);
  return read;
}

export function parseIamPolicy(text, fileCtx) {
  const kit = adapterContext({ ...fileCtx, parser: IAM_PARSER, parserVersion: IAM_PARSER_VERSION });
  let doc;
  try { doc = JSON.parse(text); } catch (e) {
    kit.gap('malformed-input', fileCtx.file, `not valid JSON (${String(e.message).split('\n')[0]})`);
    return kit.result();
  }
  const identityName = str(fileCtx.identity);
  let identity;
  if (identityName) identity = kit.node('identity', `iam/${identityName}`, { trustZone: 'internal' });
  else {
    identity = kit.unresolved('identity', `iam/policy:${fileCtx.file}`, 'the policy document is not attached to a named identity', { trustZone: 'unknown' });
    kit.gap('unresolved-identity', fileCtx.file, 'the policy document is not attached to a named identity; supply the identity it belongs to');
  }
  applyPolicy(kit, identity, doc, fileCtx.file);
  return kit.result();
}

function roleNameFromArn(arn) {
  const m = /^arn:[^:]*:iam::[^:]*:role\/(?:.*\/)?([^/]+)$/.exec(arn ?? '');
  return m ? m[1] : null;
}

export function parseTerraformPlan(text, fileCtx) {
  const kit = adapterContext({ ...fileCtx, parser: TERRAFORM_PARSER, parserVersion: TERRAFORM_PARSER_VERSION });
  let plan;
  try { plan = JSON.parse(text); } catch (e) {
    kit.gap('malformed-input', fileCtx.file, `not valid JSON (${String(e.message).split('\n')[0]})`);
    return kit.result();
  }
  if (!isObject(plan) || !str(plan.format_version) || !Array.isArray(plan.resource_changes)) {
    kit.gap('unsupported-format', fileCtx.file, 'not a terraform plan in JSON form (needs format_version and resource_changes)');
    return kit.result();
  }
  const resources = new Map();
  for (const rc of plan.resource_changes) {
    if (!isObject(rc) || !str(rc.address) || !isObject(rc.change)) continue;
    const actions = asArray(rc.change.actions);
    if (actions.includes('delete') && !actions.includes('create')) continue;
    resources.set(rc.address, { type: rc.type, name: rc.name, after: isObject(rc.change.after) ? rc.change.after : {}, unknown: isObject(rc.change.after_unknown) ? rc.change.after_unknown : {} });
  }
  const config = new Map();
  for (const r of asArray(plan.configuration?.root_module?.resources)) {
    if (isObject(r) && str(r.address)) config.set(r.address, isObject(r.expressions) ? r.expressions : {});
  }
  const refTarget = (address, field, wantType) => {
    const refs = asArray(config.get(address)?.[field]?.references);
    for (const ref of refs) {
      const m = /^([a-z0-9_]+\.[A-Za-z0-9_-]+)(?:\.|$)/.exec(ref);
      if (m && resources.get(m[1])?.type === wantType) return m[1];
    }
    return null;
  };

  const identityNodes = new Map();
  const roleNode = (address) => {
    if (identityNodes.has(address)) return identityNodes.get(address);
    const r = resources.get(address);
    const name = str(r?.after?.name);
    let node;
    if (name && r.unknown.name !== true) node = kit.node('identity', `iam-role/${name}`, { trustZone: 'internal' });
    else {
      node = kit.unresolved('identity', `iam-role/${address}`, 'the role name is only known after apply', { trustZone: 'unknown' });
      kit.gap('unresolved-identity', address, 'the role name is only known after apply');
    }
    identityNodes.set(address, node);
    return node;
  };
  const roleByArn = (arn, subject) => {
    const n = roleNameFromArn(arn);
    if (!n) { kit.gap('unresolved-identity', subject, 'the role reference is not a literal role ARN and has no resolvable reference'); return kit.unresolved('identity', `iam-role/${subject}`, 'unresolved role reference', { trustZone: 'unknown' }); }
    return kit.unresolved('identity', `iam-role/${n}`, 'the role is not defined in this plan', { trustZone: 'unknown' });
  };

  const handled = new Set(['aws_iam_role', 'aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_role_policy_attachment', 'aws_lambda_function', 'aws_s3_bucket', 'aws_security_group']);
  const unsupportedTypes = new Set();
  const policies = new Map();
  for (const [address, r] of resources) {
    if (r.type === 'aws_iam_policy' || r.type === 'aws_iam_role_policy') {
      let doc = null;
      if (typeof r.after.policy === 'string' && r.unknown.policy !== true) { try { doc = JSON.parse(r.after.policy); } catch { doc = null; } }
      policies.set(address, doc);
    }
    if (!handled.has(r.type)) unsupportedTypes.add(r.type);
  }

  for (const [address, r] of resources) {
    switch (r.type) {
      case 'aws_iam_role': roleNode(address); break;
      case 'aws_iam_role_policy': {
        const roleAddr = refTarget(address, 'role', 'aws_iam_role');
        const ident = roleAddr ? roleNode(roleAddr) : (str(r.after.role) && r.unknown.role !== true ? kit.node('identity', `iam-role/${r.after.role}`, { trustZone: 'internal' }) : kit.unresolved('identity', `iam-role/${address}`, 'the role is only known after apply', { trustZone: 'unknown' }));
        const doc = policies.get(address);
        if (!doc) kit.gap('unresolved-identity', address, 'the policy document is only known after apply or is not valid JSON; its grants are unknown');
        else applyPolicy(kit, ident, doc, address);
        break;
      }
      case 'aws_iam_role_policy_attachment': {
        const roleAddr = refTarget(address, 'role', 'aws_iam_role');
        const polAddr = refTarget(address, 'policy_arn', 'aws_iam_policy');
        const ident = roleAddr ? roleNode(roleAddr) : (str(r.after.role) && r.unknown.role !== true ? kit.node('identity', `iam-role/${r.after.role}`, { trustZone: 'internal' }) : kit.unresolved('identity', `iam-role/${address}`, 'the role is only known after apply', { trustZone: 'unknown' }));
        if (!polAddr) {
          kit.gap('unresolved-identity', address, `attached policy ${typeof r.after.policy_arn === 'string' ? r.after.policy_arn : '(known after apply)'} is not defined in this plan, so what it grants is unknown`);
          const target = kit.unresolved('resource', `aws/policy:${typeof r.after.policy_arn === 'string' ? r.after.policy_arn : address}`, 'the attached policy is not defined in this plan', { trustZone: 'unknown' });
          kit.edge('grants', ident, target, { effect: 'allow', confidence: 'low', discriminator: 'attached-policy' });
        } else if (!policies.get(polAddr)) {
          kit.gap('unresolved-identity', polAddr, 'the policy document is only known after apply or is not valid JSON; its grants are unknown');
        } else applyPolicy(kit, ident, policies.get(polAddr), address);
        break;
      }
      case 'aws_lambda_function': {
        const name = str(r.after.function_name);
        const node = name && r.unknown.function_name !== true
          ? kit.node('service', `lambda/${name}`, { trustZone: 'internal' })
          : kit.unresolved('service', `lambda/${address}`, 'the function name is only known after apply', { trustZone: 'unknown' });
        const roleAddr = refTarget(address, 'role', 'aws_iam_role');
        const ident = roleAddr ? roleNode(roleAddr) : (typeof r.after.role === 'string' ? roleByArn(r.after.role, address) : roleByArn(null, address));
        kit.edge('assumes', node, ident, { confidence: roleAddr ? 'high' : 'low' });
        break;
      }
      case 'aws_s3_bucket': {
        const b = str(r.after.bucket);
        if (b && r.unknown.bucket !== true) kit.node('resource', `s3/${b}`, { trustZone: r.after.acl === 'public-read' || r.after.acl === 'public-read-write' ? 'public' : 'internal', attrs: { acl: typeof r.after.acl === 'string' ? r.after.acl : 'unspecified' } });
        else kit.unresolved('resource', `s3/${address}`, 'the bucket name is only known after apply', { trustZone: 'unknown' });
        break;
      }
      case 'aws_security_group': {
        const name = str(r.after.name) ?? address;
        const sg = kit.node('resource', `sg/${name}`, { trustZone: 'internal' });
        for (const rule of asArray(r.after.ingress)) {
          const cidrs = asArray(rule?.cidr_blocks).filter(c => typeof c === 'string');
          const ports = `${rule?.protocol ?? '-1'}:${rule?.from_port ?? 0}-${rule?.to_port ?? 0}`;
          for (const cidr of cidrs) {
            const src = kit.node('route', `cidr/${cidr}`, { trustZone: cidr === '0.0.0.0/0' ? 'public' : 'edge', attrs: { cidr } });
            kit.edge('network-allows', src, sg, { confidence: 'high', discriminator: ports, attrs: { ports } });
          }
        }
        break;
      }
      default: break;
    }
  }
  if (unsupportedTypes.size) {
    const list = [...unsupportedTypes].sort();
    kit.gap('unsupported-format', fileCtx.file, `resource types not interpreted by this adapter: ${list.slice(0, 10).join(', ')}${list.length > 10 ? `, and ${list.length - 10} more` : ''}`);
  }
  return kit.result();
}
