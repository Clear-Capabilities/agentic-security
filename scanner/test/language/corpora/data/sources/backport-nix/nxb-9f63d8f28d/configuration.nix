{ config, lib, pkgs, ... }:
{
  nixpkgs.overlays = [ (final: prev: {
    wikilib = prev.wikilib.overrideAttrs (old: {
      version = "1.5.2";
      patches = (old.patches or [ ]) ++ [ ./SYN-87779be4-backport.patch ];
    });
  }) ];
}
