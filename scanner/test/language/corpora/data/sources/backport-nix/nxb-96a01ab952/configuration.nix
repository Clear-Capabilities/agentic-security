{ config, lib, pkgs, ... }:
{
  nixpkgs.overlays = [ (final: prev: {
    crmlib = prev.crmlib.overrideAttrs (old: {
      version = "1.5.5";
    });
  }) ];
}
