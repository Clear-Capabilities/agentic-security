final: prev: {
  # a verified backport: the fetched patch is pinned by content hash
  curl-backport = prev.curl-backport.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [
      (prev.fetchpatch {
        url = "https://example.invalid/patches/curl-fix.patch";
        sha256 = "sha256-FIXPATCHHASHFIXPATCHHASHFIXPATCHHASHFIXPATCHH=";
      })
    ];
  });
  # a CVE-named patch with no content hash: a claim, not evidence
  curl-claim = prev.curl-claim.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [ ./CVE-2099-0001.patch ];
  });
  # version bump to a fixed release
  curl-bump = prev.curl-bump.overrideAttrs (old: {
    version = "8.8.0";
  });
}
