// Revision-pinned NixOS / Home Manager option catalog (NIX-002).
//
// This is NOT a copy of the option set. It lists the options the scanner reasons
// about, with a type, a default PER RELEASE, and the renames that must be followed
// so an old spelling cannot bypass a hardening rule that is written against the new
// one. Anything absent from here is "uncataloged" and its default is unknown, never
// guessed. A default is only "proven" when it is recorded for the release in force
// (or recorded identically for every release in the catalog).
//
// The catalog is pinned by NixOS release (the CI-tested set in CATALOG_RELEASES) and
// by a content hash (`catalogRevision`), so a report can say exactly which table it
// was judged against. Refresh it, and bump CATALOG_SCHEMA when the shape changes, by
// editing the tables below: the revision hash changes with them.

import { createHash } from 'node:crypto';

export const CATALOG_SCHEMA = 1;
export const CATALOG_RELEASES = Object.freeze(['24.11', '25.05', '25.11']);

const same = (v) => Object.freeze(Object.fromEntries(CATALOG_RELEASES.map((r) => [r, v])));

/** option path -> { type, default?: {release: value} }. A missing `default` means "no static default" (unknown). */
const NIXOS_OPTIONS = {
  'services.openssh.enable': { type: 'bool', default: same(false) },
  'services.openssh.openFirewall': { type: 'bool', default: same(true) },
  'services.openssh.ports': { type: 'listOf', default: same([22]) },
  'services.openssh.settings.PermitRootLogin': { type: 'enum', default: same('prohibit-password') },
  'services.openssh.settings.PasswordAuthentication': { type: 'bool', default: same(true) },
  'services.openssh.settings.KbdInteractiveAuthentication': { type: 'bool', default: same(true) },
  'services.openssh.settings.X11Forwarding': { type: 'bool', default: same(false) },
  'networking.firewall.enable': { type: 'bool', default: same(true) },
  'networking.firewall.allowedTCPPorts': { type: 'listOf', default: same([]) },
  'networking.firewall.allowedUDPPorts': { type: 'listOf', default: same([]) },
  'networking.hostName': { type: 'str', default: same('nixos') },
  'security.sudo.enable': { type: 'bool', default: same(true) },
  'security.sudo.wheelNeedsPassword': { type: 'bool', default: same(true) },
  'security.sudo.extraConfig': { type: 'lines', default: same('') },
  'security.sudo.execWheelOnly': { type: 'bool', default: same(false) },
  'networking.firewall.allowedTCPPortRanges': { type: 'listOf', default: same([]) },
  'users.mutableUsers': { type: 'bool', default: same(true) },
  'nix.settings.sandbox': { type: 'bool', default: same(true) },
  'nix.settings.trusted-users': { type: 'listOf', default: same(['root']) },
  'services.nginx.enable': { type: 'bool', default: same(false) },
  'services.postgresql.enable': { type: 'bool', default: same(false) },
  'services.postgresql.enableTCPIP': { type: 'bool', default: same(false) },
  'services.xserver.enable': { type: 'bool', default: same(false) },
  'system.stateVersion': { type: 'str' },
};

const HM_OPTIONS = {
  'programs.git.enable': { type: 'bool', default: same(false) },
  'programs.bash.enable': { type: 'bool', default: same(false) },
  'services.gpg-agent.enable': { type: 'bool', default: same(false) },
  'home.stateVersion': { type: 'str' },
};

/** old spelling -> current spelling. A definition at the old path is evaluated as the new path. */
const NIXOS_RENAMES = {
  'services.openssh.permitRootLogin': 'services.openssh.settings.PermitRootLogin',
  'services.openssh.passwordAuthentication': 'services.openssh.settings.PasswordAuthentication',
  'services.openssh.kbdInteractiveAuthentication': 'services.openssh.settings.KbdInteractiveAuthentication',
  'services.openssh.challengeResponseAuthentication': 'services.openssh.settings.KbdInteractiveAuthentication',
  'services.openssh.forwardX11': 'services.openssh.settings.X11Forwarding',
  'nix.useSandbox': 'nix.settings.sandbox',
  'nix.trustedUsers': 'nix.settings.trusted-users',
};

/** Prefixes the catalog is authoritative for: an option under one that is neither listed nor renamed is "unknown", not "fine". */
const AUTHORITATIVE = ['services.openssh', 'networking.firewall', 'security.sudo'];
/** Freeform attribute sets: any key is valid, but only the listed ones have a known default. */
const FREEFORM = ['services.openssh.settings', 'nix.settings', 'networking.firewall.interfaces'];

const CATALOG = {
  schema: CATALOG_SCHEMA,
  releases: [...CATALOG_RELEASES],
  nixos: { options: NIXOS_OPTIONS, renames: NIXOS_RENAMES, authoritative: AUTHORITATIVE, freeform: FREEFORM },
  homeManager: { options: HM_OPTIONS, renames: {}, authoritative: [], freeform: [] },
};

export function computeCatalogRevision(catalog) {
  const { revision, ...content } = catalog;
  void revision;
  return `nixos-option-catalog/${catalog.schema}+${createHash('sha256').update(JSON.stringify(content)).digest('hex').slice(0, 12)}`;
}

export const CATALOG_REVISION = computeCatalogRevision(CATALOG);

export function defaultCatalog() {
  return { ...CATALOG, revision: CATALOG_REVISION };
}

/** `nixos-24.11`, `release-25.05`, `24.11` -> '24.11'; anything else null. */
export function normalizeRelease(text) {
  const m = /(?:^|[^0-9])(\d{2}\.(?:05|11))(?![0-9])/.exec(String(text || ''));
  return m ? m[1] : null;
}
