{ config, lib, pkgs, ... }:
{
  nixpkgs.overlays = [ (final: prev: {
    billinglib = prev.billinglib.overrideAttrs (old: {
      version = "1.5.1";
    });
  }) ];
}
