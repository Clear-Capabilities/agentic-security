// Vendored / copied library detection via version-string fingerprinting.
//
// Detects library code copied into src/ that bypasses SCA. Uses version
// string patterns (_.VERSION, jQuery.fn.jquery, etc.) and characteristic
// function signatures to identify vendored libraries.

const VERSION_FINGERPRINTS = [
  { pkg: 'lodash', ecosystem: 'npm', patterns: [
    { re: /\b(?:lodash|_)\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
    { re: /\b__lodash_hash_undefined__\b/, version: null },
  ]},
  { pkg: 'jquery', ecosystem: 'npm', patterns: [
    { re: /jQuery\.fn\.jquery\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
    { re: /\bjQuery\.fn\.init\b/, version: null },
  ]},
  { pkg: 'underscore', ecosystem: 'npm', patterns: [
    { re: /\b_\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'moment', ecosystem: 'npm', patterns: [
    { re: /\bmoment\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
    { re: /\bmoment\.(?:utc|parseZone|duration|locale)\b/, version: null },
  ]},
  { pkg: 'handlebars', ecosystem: 'npm', patterns: [
    { re: /\bHandlebars\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'backbone', ecosystem: 'npm', patterns: [
    { re: /\bBackbone\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'angular', ecosystem: 'npm', patterns: [
    { re: /\bangular\.version\s*=\s*\{[^}]*full\s*:\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'vue', ecosystem: 'npm', patterns: [
    { re: /\bVue\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'react', ecosystem: 'npm', patterns: [
    { re: /\bReactVersion\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'dompurify', ecosystem: 'npm', patterns: [
    { re: /\bDOMPurify\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'marked', ecosystem: 'npm', patterns: [
    { re: /\bmarked\.(?:defaults|setOptions|use|parse)\b[\s\S]{0,200}version\s*[:=]\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'axios', ecosystem: 'npm', patterns: [
    { re: /\baxios\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'socket.io-client', ecosystem: 'npm', patterns: [
    { re: /\bio\.protocol\s*=\s*(\d+)/, version: null },
  ]},
  { pkg: 'highlight.js', ecosystem: 'npm', patterns: [
    { re: /\bhljs\.versionString\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'chart.js', ecosystem: 'npm', patterns: [
    { re: /\bChart\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
];

const SKIP_DIRS = /(?:^|[/\\])(?:node_modules|vendor|dist|build|\.next|__pycache__|\.git)[/\\]/;

export function detectVendoredLibraries(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const detected = [];
  const seen = new Set();

  for (const [fp, content] of Object.entries(fileContents)) {
    if (!content || typeof content !== 'string') continue;
    if (SKIP_DIRS.test(fp)) continue;
    if (content.length < 500) continue;

    for (const lib of VERSION_FINGERPRINTS) {
      for (const pat of lib.patterns) {
        const m = content.match(pat.re);
        if (!m) continue;
        const version = pat.versionGroup ? m[pat.versionGroup] : null;
        const key = `${lib.pkg}:${fp}`;
        if (seen.has(key)) continue;
        seen.add(key);
        detected.push({
          name: lib.pkg,
          version: version || 'unknown',
          ecosystem: lib.ecosystem,
          file: fp,
          scope: 'vendored',
          isVendored: true,
        });
        break;
      }
    }
  }
  // Pass 2: Function-body structural matching for minified/forked copies
  const FUNCTION_BODY_SIGS = [
    { pkg: 'lodash', ecosystem: 'npm', fn: 'merge', paramMin: 1,
      bodyContains: ['assignValue', 'baseFor', 'isObject', 'baseMerge'] },
    { pkg: 'lodash', ecosystem: 'npm', fn: 'template', paramMin: 1,
      bodyContains: ['sourceURL', 'interpolate', 'evaluate', 'escape'] },
    { pkg: 'lodash', ecosystem: 'npm', fn: 'defaultsDeep', paramMin: 1,
      bodyContains: ['baseMerge', 'isMergeableObject', 'customDefaultsMerge'] },
    { pkg: 'jquery', ecosystem: 'npm', fn: 'ajax', paramMin: 1,
      bodyContains: ['XMLHttpRequest', 'ajaxSettings', 'crossDomain', 'responseFields'] },
    { pkg: 'handlebars', ecosystem: 'npm', fn: 'compile', paramMin: 1,
      bodyContains: ['templateSpec', 'container', 'invokePartial', 'blockParams'] },
    { pkg: 'marked', ecosystem: 'npm', fn: 'parse', paramMin: 1,
      bodyContains: ['Lexer', 'Parser', 'blockTokens', 'walkTokens'] },
    { pkg: 'ejs', ecosystem: 'npm', fn: 'render', paramMin: 1,
      bodyContains: ['includeFile', 'resolveInclude', 'rethrow', 'escapeFn'] },
    { pkg: 'moment', ecosystem: 'npm', fn: 'format', paramMin: 0,
      bodyContains: ['formatMoment', 'expandFormat', 'makeFormatFunction', 'localFormattingTokens'] },
    { pkg: 'underscore', ecosystem: 'npm', fn: 'template', paramMin: 1,
      bodyContains: ['interpolate', 'evaluate', 'escape', 'templateSettings'] },
    { pkg: 'minimist', ecosystem: 'npm', fn: 'parse', paramMin: 1,
      bodyContains: ['boolean', 'alias', 'default', 'stopEarly', 'unknown'] },
  ];

  for (const [fp, content] of Object.entries(fileContents)) {
    if (!content || typeof content !== 'string') continue;
    if (SKIP_DIRS.test(fp)) continue;
    if (!/\.(?:js|mjs|cjs)$/i.test(fp)) continue;
    if (content.length < 200 || content.length > 500_000) continue;

    for (const sig of FUNCTION_BODY_SIGS) {
      const key = `${sig.pkg}:${fp}`;
      if (seen.has(key)) continue;
      const fnRe = new RegExp(`(?:function\\s+${sig.fn}|(?:const|let|var)\\s+${sig.fn}\\s*=|${sig.fn}\\s*[:=]\\s*function)\\s*\\(`, 'g');
      const m = fnRe.exec(content);
      if (!m) continue;
      const bodyWindow = content.slice(m.index, m.index + 2000);
      const matchCount = sig.bodyContains.filter(kw => bodyWindow.includes(kw)).length;
      if (matchCount < Math.ceil(sig.bodyContains.length * 0.6)) continue;
      seen.add(key);
      detected.push({
        name: sig.pkg,
        version: 'unknown',
        ecosystem: sig.ecosystem,
        file: fp,
        scope: 'vendored',
        isVendored: true,
        _detectionMethod: 'function-body-signature',
        _matchedKeywords: matchCount,
      });
    }
  }

  return detected;
}
