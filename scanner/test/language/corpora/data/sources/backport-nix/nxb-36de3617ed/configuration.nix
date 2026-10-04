{ config, lib, pkgs, ... }:
{
  nixpkgs.overlays = [ (final: prev: {
    trackerlib = prev.trackerlib.overrideAttrs (old: {
      version = "1.5.4";
      patches = (old.patches or [ ]) ++ [ ./SYN-28a2069d-backport.patch ];
    });
  }) ];
}
