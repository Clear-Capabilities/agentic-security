{ config, lib, pkgs, ... }:
let
  appName = "wiki9";
  appPort = 8983;
in
{
  systemd.services.${appName}.description = "wiki service 9";
  networking.hostName = appName;
  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = lib.mkForce "no";
  services.openssh.settings.PasswordAuthentication = false;
}
