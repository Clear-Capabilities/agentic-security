{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;
  services.openssh.settings.PermitRootLogin = "yes";
}
