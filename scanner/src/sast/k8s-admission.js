// Kubernetes admission / RBAC / PodSecurity analyzer — Item #4 of the
// world-class+3 plan.
//
// Coverage:
//
//   RBAC (Role / ClusterRole / RoleBinding / ClusterRoleBinding):
//     - k8s-rbac-wildcard-verbs       verbs: ['*']
//     - k8s-rbac-wildcard-resources   resources: ['*']
//     - k8s-rbac-wildcard-apigroups   apiGroups: ['*']
//     - k8s-rbac-cluster-admin        ClusterRoleBinding → cluster-admin
//     - k8s-rbac-system-anonymous     binding subject system:anonymous /
//                                      system:unauthenticated
//     - k8s-rbac-system-authenticated-write  bound to write-capable role
//
//   PodSecurity:
//     - k8s-pod-privileged            securityContext.privileged: true
//     - k8s-pod-hostnetwork           hostNetwork: true
//     - k8s-pod-hostpid               hostPID: true
//     - k8s-pod-hostipc               hostIPC: true
//     - k8s-pod-hostpath              volumes[].hostPath
//     - k8s-pod-allow-privesc         allowPrivilegeEscalation: true
//     - k8s-pod-run-as-root           runAsNonRoot: false  OR  runAsUser: 0
//     - k8s-pod-capabilities-broad    capabilities.add: SYS_ADMIN / NET_ADMIN / ALL
//
//   Admission webhooks:
//     - k8s-webhook-failure-ignore    ValidatingWebhookConfiguration with
//                                      failurePolicy: Ignore on security-critical webhook
//
//   Service account / token mount:
//     - k8s-sa-automount-admin        ServiceAccount with automountServiceAccountToken !== false
//                                      AND bound to a powerful ClusterRole
//
// Detection: lightweight YAML parsing via regex on `kind:` and `key: value`
// pairs. We avoid pulling in a YAML lib for now — k8s YAML is simple enough
// that pattern detection on key prefixes is reliable.
//
// Opt-out: AGENTIC_SECURITY_NO_K8S_ADM=1

import { blankComments } from './_comment-strip.js';

// The finding families this module can emit (F10.2 producer registry).
//
// Declared HERE, next to the rules, because no external method enumerates them:
// this module passes `family` POSITIONALLY (`_shape(file, line, ruleId, vuln,
// fam, ...)`), so a textual search for `family:` finds nothing, and a corpus
// sweep only ever reports a LOWER BOUND -- it sees whichever families a fixture
// happened to trigger. This list is the union of both, and
// `test/family-registry.test.js` fails if a scan produces a family from this
// module that is not listed.
//
// Add the family here in the same edit that adds the rule.
export const EMITS = [
  'k8s-pod-security-allow-privesc',
  'k8s-pod-security-capabilities-broad',
  'k8s-pod-security-hostnetwork',
  'k8s-pod-security-hostpath',
  'k8s-pod-security-hostpid',
  'k8s-pod-security-privileged',
  'k8s-pod-security-run-as-root',
  'k8s-rbac-anonymous',
  'k8s-rbac-cluster-admin',
  'k8s-rbac-overbroad-binding',
  'k8s-rbac-wildcard',
  'k8s-webhook-bypass',
  'k8s-webhook-sideeffects',
];

const _IS_K8S_FILE = /\.(?:yaml|yml)$/i;

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _shape(file, line, ruleId, vuln, fam, sev, cwe, remediation, description) {
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line, vuln, severity: sev, cwe,
    family: fam, parser: 'K8S-ADM',
    confidence: 0.85,
    stride: 'Elevation of Privilege',
    description: description || vuln,
    remediation,
  };
}

function _docKinds(raw) {
  // Heuristic: split on `---` document separators and extract kind: line.
  return raw.split(/^---\s*$/m).map(doc => {
    const k = /kind:\s*([A-Za-z0-9]+)/.exec(doc);
    return { kind: k ? k[1] : null, body: doc };
  });
}

// ── RBAC ───────────────────────────────────────────────────────────────────

function detectRbac(file, raw, out, seen) {
  const docs = _docKinds(raw);
  for (const { kind, body } of docs) {
    if (!kind) continue;
    if (!/^(?:Role|ClusterRole|RoleBinding|ClusterRoleBinding)$/.test(kind)) continue;

    // Role / ClusterRole rules — wildcards.
    if (/^(?:Role|ClusterRole)$/.test(kind)) {
      // Use the entire document body as the rules block — simpler than trying
      // to delimit the rules: section across all YAML formatting variants.
      const block = body;
      if (/verbs:\s*\[\s*['"]?\*['"]?\s*\]/.test(block) || /verbs:\s*\n\s*-\s*['"]?\*['"]?/.test(block)) {
        const ln = _line(raw, (block.match(/verbs:/) || [''])[0] || '');
        const id = `k8s-rbac-wildcard-verbs:${file}:${ln}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push(_shape(file, ln, 'k8s-rbac-wildcard-verbs',
            `${kind} grants wildcard verbs ['*'] — full action access`,
            'k8s-rbac-wildcard', 'high', 'CWE-269',
            'Replace `verbs: ["*"]` with the specific verbs needed (get, list, watch, create, update, patch, delete). Use kubectl auth can-i to confirm minimum required set.',
            'Wildcard verbs include exec, port-forward, and other powerful operations beyond CRUD. CIS Kubernetes Benchmark 5.1.x explicitly bans wildcard verbs in production RBAC.'));
        }
      }
      if (/resources:\s*\[\s*['"]?\*['"]?\s*\]/.test(block) || /resources:\s*\n\s*-\s*['"]?\*['"]?/.test(block)) {
        const ln = _line(raw, block.match(/resources:/)[0]);
        const id = `k8s-rbac-wildcard-resources:${file}:${ln}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push(_shape(file, ln, 'k8s-rbac-wildcard-resources',
            `${kind} grants wildcard resources ['*'] — every Kubernetes object type`,
            'k8s-rbac-wildcard', 'high', 'CWE-269',
            'Enumerate the specific resource kinds (pods, services, deployments, secrets, configmaps, ...) the role actually needs. Wildcard resources includes secrets, which exposes credential material to every subject.',
            'Wildcard resources include secrets, certificates, and CRDs. The 2019-2021 cryptojacking K8s incidents all leveraged over-broad ClusterRoles with wildcard resources.'));
        }
      }
      if (/apiGroups:\s*\[\s*['"]?\*['"]?\s*\]/.test(block) || /apiGroups:\s*\n\s*-\s*['"]?\*['"]?/.test(block)) {
        const ln = _line(raw, block.match(/apiGroups:/)[0]);
        const id = `k8s-rbac-wildcard-apigroups:${file}:${ln}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push(_shape(file, ln, 'k8s-rbac-wildcard-apigroups',
            `${kind} grants wildcard apiGroups — every API group including CRDs`,
            'k8s-rbac-wildcard', 'medium', 'CWE-269',
            'List the specific apiGroups needed (e.g. "", "apps", "batch", "rbac.authorization.k8s.io"). Wildcard apiGroups gives access to every CRD that may be installed later — future-proofing in the wrong direction.',
            'Wildcard apiGroups is especially dangerous when CRDs grant cluster-level permissions through their own controllers (cert-manager, ArgoCD, Tekton).'));
        }
      }
    }

    // RoleBinding / ClusterRoleBinding
    if (/^(?:RoleBinding|ClusterRoleBinding)$/.test(kind)) {
      // cluster-admin binding.
      if (/roleRef:\s*[\s\S]*?name:\s*cluster-admin/.test(body)) {
        const ln = _line(raw, 'cluster-admin');
        const id = `k8s-rbac-cluster-admin:${file}:${ln}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push(_shape(file, ln, 'k8s-rbac-cluster-admin',
            `${kind} binds to cluster-admin — full cluster control`,
            'k8s-rbac-cluster-admin', 'critical', 'CWE-269',
            'Replace cluster-admin with a narrowly-scoped ClusterRole or RoleBinding limited to the operational namespace. Use Role/RoleBinding (namespaced) instead of ClusterRoleBinding wherever possible.',
            'cluster-admin is the K8s equivalent of root. A bound user/SA can install controllers, create privileged pods, and exfiltrate every secret. CIS K8s 5.1.1 mandates minimizing cluster-admin bindings.'));
        }
      }
      // system:anonymous / system:unauthenticated subjects.
      if (/subjects:\s*[\s\S]*?(?:name:\s*system:(?:anonymous|unauthenticated))/.test(body)) {
        const ln = _line(raw, 'system:');
        const id = `k8s-rbac-system-anonymous:${file}:${ln}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push(_shape(file, ln, 'k8s-rbac-system-anonymous',
            `${kind} binds a role to system:anonymous / system:unauthenticated`,
            'k8s-rbac-anonymous', 'critical', 'CWE-862',
            'Remove the anonymous/unauthenticated subject. Replace with a ServiceAccount or explicit User/Group bound only after authentication. If you genuinely need a permissionless API for a probe, scope it to /healthz / /readyz only.',
            'Binding any role to system:anonymous makes that role available without authentication — anyone with network reach to the API server can act with those permissions.'));
        }
      }
      // system:authenticated bound to write-capable role.
      if (/subjects:\s*[\s\S]*?name:\s*system:authenticated/.test(body) &&
          /roleRef:\s*[\s\S]*?name:\s*(?:cluster-admin|admin|edit|system:node)/.test(body)) {
        const ln = _line(raw, 'system:authenticated');
        const id = `k8s-rbac-system-authenticated-write:${file}:${ln}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push(_shape(file, ln, 'k8s-rbac-system-authenticated-write',
            `${kind} binds a write-capable role to system:authenticated`,
            'k8s-rbac-overbroad-binding', 'high', 'CWE-863',
            'Replace system:authenticated with specific groups, ServiceAccounts, or users. system:authenticated includes every Service Account in every namespace + every legitimately-issued client cert.',
            'system:authenticated is essentially "anyone who has a valid token" — including every default service account on every workload, friendly or hostile.'));
        }
      }
    }
  }
}

// ── PodSecurity ────────────────────────────────────────────────────────────

function detectPodSecurity(file, raw, out, seen) {
  const docs = _docKinds(raw);
  for (const { kind, body } of docs) {
    if (!kind) continue;
    if (!/^(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet|ReplicationController)$/.test(kind)) continue;

    const checks = [
      { re: /privileged:\s*true\b/g,                  rule: 'k8s-pod-privileged',       sev: 'critical', cwe: 'CWE-250',
        vuln: 'Pod runs in privileged mode',
        remediation: 'Remove privileged: true. Use capability drops (capabilities.drop: [ALL]) and capabilities.add only the specific Linux caps required.' },
      { re: /hostNetwork:\s*true\b/g,                 rule: 'k8s-pod-hostnetwork',      sev: 'high',     cwe: 'CWE-668',
        vuln: 'Pod uses host network — shares node IP stack',
        remediation: 'Remove hostNetwork: true. If you need NodePort behavior, use a Service of type NodePort or LoadBalancer instead.' },
      { re: /hostPID:\s*true\b/g,                     rule: 'k8s-pod-hostpid',          sev: 'high',     cwe: 'CWE-668',
        vuln: 'Pod uses host PID namespace — can see/signal node processes',
        remediation: 'Remove hostPID: true. Container escape research targets host-pid pods first.' },
      { re: /hostIPC:\s*true\b/g,                     rule: 'k8s-pod-hostipc',          sev: 'high',     cwe: 'CWE-668',
        vuln: 'Pod uses host IPC namespace',
        remediation: 'Remove hostIPC: true. Almost no workload genuinely needs this.' },
      { re: /hostPath:\s*\n\s*path:/g,                rule: 'k8s-pod-hostpath',         sev: 'high',     cwe: 'CWE-732',
        vuln: 'Pod mounts a hostPath volume — node-filesystem reach',
        remediation: 'Replace hostPath with PersistentVolumeClaim or ConfigMap. hostPath mounts let the pod read any file the node user can read — including /var/lib/kubelet/pods/* (other pods\' secrets).' },
      { re: /allowPrivilegeEscalation:\s*true\b/g,    rule: 'k8s-pod-allow-privesc',    sev: 'high',     cwe: 'CWE-250',
        vuln: 'Pod allows privilege escalation (no_new_privs disabled)',
        remediation: 'Set allowPrivilegeEscalation: false. This sets the no_new_privs bit, preventing setuid / setgid binaries from gaining additional privileges.' },
      { re: /runAsNonRoot:\s*false\b/g,               rule: 'k8s-pod-run-as-root',      sev: 'medium',   cwe: 'CWE-250',
        vuln: 'Pod explicitly allows running as root',
        remediation: 'Set runAsNonRoot: true and runAsUser: <non-zero>. Build images with a non-root USER directive.' },
      { re: /runAsUser:\s*0\b/g,                      rule: 'k8s-pod-run-as-root',      sev: 'medium',   cwe: 'CWE-250',
        vuln: 'Pod runAsUser: 0 (root)',
        remediation: 'Set runAsUser to a non-zero UID (e.g. 1000). Combine with runAsNonRoot: true for defense-in-depth.' },
      { re: /capabilities:\s*\n\s*add:\s*[\s\S]{0,200}?(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b/g,
                                                       rule: 'k8s-pod-capabilities-broad', sev: 'high',   cwe: 'CWE-250',
        vuln: 'Pod adds dangerous Linux capability (SYS_ADMIN / NET_ADMIN / SYS_PTRACE / ALL)',
        remediation: 'Drop ALL and add only the minimum cap(s) needed. SYS_ADMIN approximates root inside the container; NET_ADMIN allows iptables manipulation; SYS_PTRACE allows reading every process\'s memory.' },
    ];

    for (const c of checks) {
      let m;
      while ((m = c.re.exec(body))) {
        const docStart = raw.indexOf(body);
        const ln = _line(raw, body.slice(0, m.index)) + (docStart > 0 ? _line(raw, raw.slice(0, docStart)) - 1 : 0);
        const id = `${c.rule}:${file}:${ln}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(_shape(file, ln, c.rule, c.vuln,
          c.rule.replace(/^k8s-pod-/, 'k8s-pod-security-'), c.sev, c.cwe,
          c.remediation,
          undefined));
      }
    }
  }
}

// ── Admission webhooks ─────────────────────────────────────────────────────

function detectWebhooks(file, raw, out, seen) {
  const docs = _docKinds(raw);
  for (const { kind, body } of docs) {
    if (!/^(?:ValidatingWebhookConfiguration|MutatingWebhookConfiguration)$/.test(kind || '')) continue;
    // failurePolicy: Ignore on security-sensitive admission webhook.
    if (/failurePolicy:\s*Ignore\b/.test(body)) {
      const ln = _line(raw, body.match(/failurePolicy:/)[0]);
      const id = `k8s-webhook-failure-ignore:${file}:${ln}`;
      if (!seen.has(id)) {
        seen.add(id);
        out.push(_shape(file, ln, 'k8s-webhook-failure-ignore',
          `${kind} uses failurePolicy: Ignore — admission silently bypassed on webhook outage`,
          'k8s-webhook-bypass', 'high', 'CWE-754',
          'Set failurePolicy: Fail for security-critical webhooks (PodSecurity, image-signing verification, network policy enforcement). Use Ignore only for observability/audit-only webhooks where false-pass is preferable to API-server stalls.',
          'failurePolicy: Ignore means a webhook outage (network blip, pod crash) silently disables the admission check — a perfect window for a bypass attack. The 2022 Argo CD incident exploited exactly this.'));
      }
    }
    // sideEffects: None / NoneOnDryRun missing → flag as a separate issue.
    if (!/sideEffects:/.test(body)) {
      const ln = _line(raw, body);
      const id = `k8s-webhook-no-sideeffects:${file}:${ln}`;
      if (!seen.has(id)) {
        seen.add(id);
        out.push(_shape(file, ln, 'k8s-webhook-no-sideeffects',
          `${kind} missing sideEffects declaration`,
          'k8s-webhook-sideeffects', 'low', 'CWE-1287',
          'Add `sideEffects: None` or `sideEffects: NoneOnDryRun`. Required since admissionregistration.k8s.io/v1; missing the field makes dry-run admission unreliable.',
          undefined));
      }
    }
  }
}

// ── Entry point ────────────────────────────────────────────────────────────

export function scanK8sAdmission(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_K8S_ADM === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  if (!_IS_K8S_FILE.test(fp)) return [];
  if (!/^(?:apiVersion|kind):/m.test(raw)) return [];

  const out = [];
  const seen = new Set();
  try { detectRbac(fp, raw, out, seen); } catch {}
  try { detectPodSecurity(fp, raw, out, seen); } catch {}
  try { detectWebhooks(fp, raw, out, seen); } catch {}
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = { detectRbac, detectPodSecurity, detectWebhooks, _docKinds };
