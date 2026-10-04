{ config, lib, pkgs, ... }:
{
  nixpkgs.overlays = [ (final: prev: {
    crmlib = prev.crmlib.overrideAttrs (old: {
      version = "1.5.0";
      patches = (old.patches or [ ]) ++ [ ./SYN-a8d81273-backport.patch ];
    });
  }) ];
}
