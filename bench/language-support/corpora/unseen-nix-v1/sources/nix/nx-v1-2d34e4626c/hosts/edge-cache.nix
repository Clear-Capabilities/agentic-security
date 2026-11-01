{ config, lib, pkgs, ... }:
let
  unstable = import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/3f0c6d1a9b2e8f7c4d5a6b7c8d9e0f1a2b3c4d5e.tar.gz";
    sha256 = "1q2w3x4r5v6b7n8m9k0j1h2g3f4d5s6a7p8l9z0y1x2c3v4b5n6m";
  }) { };
in
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "edge-cache";

  services.caddy = {
    enable = true;
    package = unstable.caddy;
    virtualHosts."assets.example.org".extraConfig = ''
      reverse_proxy 10.20.0.15:8080
    '';
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
