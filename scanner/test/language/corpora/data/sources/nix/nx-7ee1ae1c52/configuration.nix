{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  nix.settings.trusted-users = [ "root" "@wheel" "billing" ];
  networking.domain = lib.mkDefault "billing.example.org";
}
