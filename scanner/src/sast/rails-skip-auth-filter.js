// Rails controller skips its authentication filter for every action while declaring per-action auth levels: CWE-287.
//
// THE SHAPE.
//
//     class AccountsController < ApplicationController
//       skip_before_action :authenticate_for_action        # no only:/except:: every action
//       auth_level_for :index, :member                     # per-action declarations the skipped filter would enforce
//       auth_level_for :destroy, :admin
//
// A controller that declares an authentication or authorization level per action relies on a filter to enforce those declarations.
// Skipping a filter of that kind unconditionally turns every declaration in the file into a comment, and any action without one is open
// as well. The fix limits the skip to the actions meant to be public (`except:`/`only:`).
//
// WHAT MUST BE TRUE TO REPORT. A `skip_before_action` (or `skip_before_filter`) of a filter whose name is about authentication or
// authorization, with no `only:`, `except:`, `if:` or `unless:` option; and at least two class-level per-action macro calls in the same
// file whose name is about auth, access, permission or role (`action_auth_level :index, :student`). The second condition is what makes
// the skip a contradiction rather than a deliberately public controller. CWE-287 when the skipped filter authenticates, CWE-285 when it
// only authorizes.

const FILE_RE = /_controller\.rb$/i;
const SKIP = /^\s*skip_before_(?:action|filter)\s+:(\w+)\s*(.*)$/;
const AUTH_FILTER = /auth|login|sign_?in|permission|access|require_user|require_admin/i;
const AUTHN_FILTER = /authent|login|sign_?in|require_user/i;
const MACRO = /^\s*(\w*(?:auth|access|permission|role|privilege)\w*)\s+:\w+/i;
const NOT_MACRO = /^(?:before_action|after_action|around_action|skip_\w+|before_filter|prepend_before_action|append_before_action|protect_from_forgery|attr_\w+|alias_method|helper_method)$/;

export function scanRailsSkipAuthFilter(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || !/skip_before_(?:action|filter)/.test(code)) return [];
  if (/(?:^|\/)(?:spec|test)\//.test(file)) return [];
  const lines = code.split('\n');
  const macros = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(MACRO);
    if (m && !NOT_MACRO.test(m[1])) macros.push({ line: i + 1, name: m[1] });
  }
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const s = lines[i].match(SKIP);
    if (!s || !AUTH_FILTER.test(s[1])) continue;
    // The options may continue on the next lines after a trailing comma.
    let opts = s[2];
    for (let k = i + 1; /,\s*$/.test(opts) && k < lines.length && k - i < 6; k++) opts += ' ' + lines[k];
    if (/\b(?:only|except|if|unless)\s*:/.test(opts) || /:(?:only|except|if|unless)\s*=>/.test(opts)) continue;
    // The declarations must belong to the skipped filter: the two names share a word (`authenticate_for_action` and
    // `action_auth_level` share `action`). A course-scoping filter says nothing about an unrelated level macro.
    const words = (n) => n.toLowerCase().split('_').filter((w) => w.length >= 4 && !/^(?:auth\w*|user|users|with|from)$/.test(w));
    const fw = new Set(words(s[1]));
    const related = macros.filter((m) => m.name !== s[1] && words(m.name).some((w) => fw.has(w)));
    if (related.length < 2) continue;
    const authn = AUTHN_FILTER.test(s[1]);
    out.push({
      id: `rails-skip-auth-filter:${file}:${i + 1}`,
      file, line: i + 1,
      vuln: `skip_before_action :${s[1]} applies to every action while the controller declares per-action auth levels`,
      severity: 'high',
      cwe: authn ? 'CWE-287' : 'CWE-285',
      family: authn ? 'auth' : 'broken-access-control',
      stride: 'Spoofing',
      description: `This controller skips \`${s[1]}\` for all of its actions, yet declares \`${related[0].name}\` for individual actions (${related.length} declarations, first at line ${related[0].line}). Those declarations only matter when the skipped filter runs, so every action in the controller, including any with no declaration, is reachable without the check.`,
      remediation: `Limit the skip to the actions that are meant to be public: \`skip_before_action :${s[1]}, only: [...]\` (or \`except: [...]\` for the protected ones), and give every remaining action its auth level.`,
      snippet: lines[i].trim().slice(0, 200),
      parser: 'RAILS-SKIP-AUTH',
      confidence: 0.6,
    });
  }
  return out;
}
