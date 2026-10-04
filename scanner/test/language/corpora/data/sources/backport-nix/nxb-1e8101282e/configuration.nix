{ config, lib, pkgs, ... }:
{
  nixpkgs.overlays = [ (final: prev: {
    mailerlib = prev.mailerlib.overrideAttrs (old: {
      version = "1.5.3";
    });
  }) ];
}
