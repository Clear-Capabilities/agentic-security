{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;
  services.openssh.settings.PermitRootLogin = "yes";
}
