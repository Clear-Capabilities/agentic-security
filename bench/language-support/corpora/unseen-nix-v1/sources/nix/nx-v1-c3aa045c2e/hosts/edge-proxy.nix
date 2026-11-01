{ config, lib, pkgs, ... }:
let
  unstable = import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { };
in
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "edge-proxy";

  services.caddy = {
    enable = true;
    package = unstable.caddy;
    virtualHosts."app.example.org".extraConfig = ''
      reverse_proxy 10.20.0.14:8080
    '';
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
