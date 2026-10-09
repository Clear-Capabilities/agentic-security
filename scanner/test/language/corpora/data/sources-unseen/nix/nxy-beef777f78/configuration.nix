{ config, lib, pkgs, ... }:
with lib;
{
  virtualisation.docker.enable = true;
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = mkForce [ 22 2375 ];
}
