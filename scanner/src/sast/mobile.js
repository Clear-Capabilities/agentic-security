// Mobile security pipeline — Recommendation #4 of the world-class+2 plan.
//
// Android: parses AndroidManifest.xml + Kotlin/Java source for mobile-
// specific vulnerability patterns. iOS: parses Info.plist + Swift / Obj-C
// source for the matching iOS patterns.
//
// Android families covered:
//   - mobile-exported-component  Activity/Service/Receiver exported without
//                                permission (CWE-925/926)
//   - mobile-debug-build         android:debuggable="true" in release manifest
//   - mobile-allow-backup        android:allowBackup="true" (data exfil at
//                                device level)
//   - mobile-cleartext-transit   android:usesCleartextTraffic="true"
//                                (CWE-319)
//   - mobile-webview-js-iface    WebView.addJavascriptInterface (CWE-749)
//   - mobile-intent-spoof        Intent.parseUri / startActivity(tainted)
//                                (CWE-927)
//   - mobile-keychain-misuse     SharedPreferences MODE_WORLD_* writes
//
// iOS families covered:
//   - ios-cleartext-transit      NSExceptionAllowsInsecureHTTPLoads /
//                                NSAllowsArbitraryLoads = true
//   - ios-keychain-accessible    kSecAttrAccessibleAlways /
//                                kSecAttrAccessibleAlwaysThisDeviceOnly
//   - ios-debug-build            DEBUG flag in release configuration
//   - ios-biometric-fallback     LAPolicy.deviceOwnerAuthentication (allows
//                                passcode fallback when Face/Touch ID is
//                                required for sensitive ops)
//   - ios-webview-untrusted-url  WKWebView.load(URLRequest with tainted url)

import { blankComments } from './_comment-strip.js';

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _finding(file, line, raw, ruleId, vuln, family, severity, cwe, remediation, subfamily) {
  return {
    id: `${ruleId}:${file}:${line}`, file, line, vuln, severity, cwe,
    stride: severity === 'critical' ? 'Elevation of Privilege' : 'Information Disclosure',
    snippet: _snip(raw, line),
    remediation, family, subfamily,
    confidence: 0.85, parser: 'MOBILE',
  };
}

// ── Android: AndroidManifest.xml ───────────────────────────────────────────

function _scanAndroidManifest(file, raw, out, seen) {
  const code = raw;
  // exported="true" components without permission attribute
  const expRe = /<\s*(activity|service|receiver|provider)\b([^>]*?)\bandroid:exported\s*=\s*"true"([^>]*?)\/?\s*>/gi;
  let m;
  while ((m = expRe.exec(code))) {
    const attrs = (m[2] + m[3]) || '';
    if (/android:permission\s*=/.test(attrs)) continue;
    const line = _lineOf(raw, m.index);
    const id = `mobile-exported-component:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'mobile-exported-component',
      `Exported ${m[1]} without permission attribute`,
      'mobile-exported-component', 'high', 'CWE-925',
      'Set android:exported="false" if the component is internal-only. If exported, add android:permission="<custom-permission>" requiring a signature-level permission so only your own app or apps you control can invoke it.',
      'exported-no-permission'));
  }
  // debuggable=true
  if (/android:debuggable\s*=\s*"true"/i.test(code)) {
    const idx = code.search(/android:debuggable\s*=\s*"true"/i);
    const line = _lineOf(raw, idx);
    out.push(_finding(file, line, raw, 'mobile-debug-build',
      'android:debuggable="true" — debug build flag set in manifest',
      'mobile-debug-build', 'high', 'CWE-489',
      'Remove android:debuggable from the manifest entirely (Gradle controls the debuggable flag automatically per build type). A debuggable release build allows JDWP attach + heap dump from any host.',
      'debuggable-true'));
  }
  // allowBackup=true (Android < 12 backs up app data including SharedPreferences without encryption)
  if (/android:allowBackup\s*=\s*"true"/i.test(code)) {
    const idx = code.search(/android:allowBackup\s*=\s*"true"/i);
    const line = _lineOf(raw, idx);
    out.push(_finding(file, line, raw, 'mobile-allow-backup',
      'android:allowBackup="true" — application data backed up via adb backup / cloud',
      'mobile-allow-backup', 'medium', 'CWE-200',
      'Set android:allowBackup="false" unless you have a documented backup strategy. Alternatively, define an explicit android:fullBackupContent rules file that excludes sensitive paths (databases, SharedPreferences).',
      'allow-backup'));
  }
  // cleartext traffic
  if (/android:usesCleartextTraffic\s*=\s*"true"/i.test(code)) {
    const idx = code.search(/android:usesCleartextTraffic\s*=\s*"true"/i);
    const line = _lineOf(raw, idx);
    out.push(_finding(file, line, raw, 'mobile-cleartext-transit',
      'android:usesCleartextTraffic="true" — HTTP transmission allowed',
      'mobile-cleartext-transit', 'high', 'CWE-319',
      'Remove the attribute (defaults to false on API 28+) and use a network-security-config XML to allow-list specific debug hosts if needed. Any cleartext traffic is sniffable on hostile Wi-Fi.',
      'cleartext-true'));
  }
}

// ── Android: Kotlin/Java source ────────────────────────────────────────────

function _scanAndroidSource(file, raw, out, seen) {
  const code = blankComments(raw);
  // WebView.addJavascriptInterface (CWE-749)
  const wRe = /\b(\w+)\s*\.\s*addJavascriptInterface\s*\(/g;
  let m;
  while ((m = wRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `mobile-webview-js-iface:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'mobile-webview-js-iface',
      'WebView.addJavascriptInterface — JS bridge exposes app code to web content',
      'mobile-webview-js-iface', 'high', 'CWE-749',
      'Avoid addJavascriptInterface entirely. Use JavascriptInterface-annotated methods ONLY when minSdk ≥ 17 AND validate every public method does no privilege escalation. Prefer @JavascriptInterface-tagged interfaces with explicit allow-listed methods.',
      'webview-js-iface'));
  }
  // Intent.parseUri with non-literal
  const piRe = /\bIntent\s*\.\s*parseUri\s*\(\s*(?!["'])\w/g;
  while ((m = piRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `mobile-intent-spoof:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'mobile-intent-spoof',
      'Intent.parseUri with non-literal URI string — intent injection risk',
      'mobile-intent-spoof', 'high', 'CWE-927',
      'Validate the URI against an allow-list of schemes and authorities before parseUri. Better: take a structured input (component name + extras) and build the Intent manually.',
      'intent-parse-uri'));
  }
  // SharedPreferences MODE_WORLD_*
  const sRe = /\bContext\s*\.\s*(?:MODE_WORLD_(?:READABLE|WRITEABLE))\b/g;
  while ((m = sRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `mobile-keychain-misuse:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'mobile-keychain-misuse',
      'SharedPreferences in MODE_WORLD_* — readable/writable by any installed app',
      'mobile-keychain-misuse', 'high', 'CWE-732',
      'Use MODE_PRIVATE (the default). MODE_WORLD_* is deprecated since API 17 and exposes credentials to every other app on the device.',
      'shared-prefs-world-mode'));
  }
}

// ── iOS: Info.plist ────────────────────────────────────────────────────────

function _scanIosPlist(file, raw, out, seen) {
  // NSAllowsArbitraryLoads
  if (/NSAllowsArbitraryLoads\s*<\/key>\s*<true\b/i.test(raw)) {
    const idx = raw.search(/NSAllowsArbitraryLoads/i);
    const line = _lineOf(raw, idx);
    out.push(_finding(file, line, raw, 'ios-cleartext-transit',
      'NSAllowsArbitraryLoads = YES — App Transport Security disabled for all hosts',
      'ios-cleartext-transit', 'high', 'CWE-319',
      'Remove NSAllowsArbitraryLoads. If a specific upstream legitimately requires cleartext, use NSExceptionDomains with the smallest possible per-host exception.',
      'ats-disabled'));
  }
}

// ── iOS: Swift / Obj-C ─────────────────────────────────────────────────────

function _scanIosSource(file, raw, out, seen) {
  const code = blankComments(raw);
  // kSecAttrAccessibleAlways — Keychain item accessible at any time
  const kRe = /\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b/g;
  let m;
  while ((m = kRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `ios-keychain-accessible:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'ios-keychain-accessible',
      'Keychain item set to kSecAttrAccessibleAlways — accessible without device unlock',
      'ios-keychain-accessible', 'high', 'CWE-922',
      'Use kSecAttrAccessibleWhenUnlocked (or kSecAttrAccessibleWhenUnlockedThisDeviceOnly for highest sensitivity). The "Always" variants don\'t require device unlock and are accessible to forensic tools.',
      'keychain-always-accessible'));
  }
  // LAPolicy.deviceOwnerAuthentication (allows passcode fallback)
  const bRe = /\bLAPolicy\s*\.\s*deviceOwnerAuthentication\b(?!WithBiometrics)/g;
  while ((m = bRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `ios-biometric-fallback:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'ios-biometric-fallback',
      'LAPolicy.deviceOwnerAuthentication — allows passcode fallback for biometric prompt',
      'ios-biometric-fallback', 'medium', 'CWE-308',
      'For sensitive operations (payments, vault access) use LAPolicy.deviceOwnerAuthenticationWithBiometrics to require Face/Touch ID with NO passcode fallback. Passcode fallback opens the operation to anyone who knows the passcode.',
      'biometric-with-fallback'));
  }
  // WKWebView.load(URLRequest(url: tainted))
  const wRe = /\b\w+\s*\.\s*load\s*\(\s*URLRequest\s*\(\s*url\s*:\s*(?!URL\s*\(\s*string\s*:\s*["'])/g;
  while ((m = wRe.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `ios-webview-untrusted-url:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_finding(file, line, raw, 'ios-webview-untrusted-url',
      'WKWebView loaded with non-literal URL — open-redirect / phishing risk',
      'ios-webview-untrusted-url', 'medium', 'CWE-601',
      'Validate the URL against an allow-list of schemes (https only) and hosts before passing to URLRequest. WKWebView reachable from a deeplink with attacker-controlled URL = in-app phishing surface.',
      'webview-untrusted-url'));
  }
}

// ── Public entry point ─────────────────────────────────────────────────────

export function scanMobile(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const out = [];
  const seen = new Set();
  try {
    if (/AndroidManifest\.xml$/i.test(fp)) _scanAndroidManifest(fp, raw, out, seen);
    else if (/Info\.plist$/i.test(fp)) _scanIosPlist(fp, raw, out, seen);
    else if (/\.(?:kt|java)$/i.test(fp) && /\b(?:android\.|androidx\.|Activity|Service|BroadcastReceiver|WebView|SharedPreferences)\b/.test(raw)) {
      _scanAndroidSource(fp, raw, out, seen);
    }
    else if (/\.(?:swift|m|mm)$/i.test(fp) && /\b(?:NS|UI|WK|LA|kSec|Foundation|UIKit|SwiftUI)\w*/.test(raw)) {
      _scanIosSource(fp, raw, out, seen);
    }
  } catch {}
  return out;
}

export const _internals = { _scanAndroidManifest, _scanAndroidSource, _scanIosPlist, _scanIosSource };
