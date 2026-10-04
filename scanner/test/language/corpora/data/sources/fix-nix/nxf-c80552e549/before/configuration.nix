{ config, lib, pkgs, ... }:
let
  appName = "crm7";
  appPort = 8781;
in
{
  systemd.services.${appName}.description = "crm service 7";
  networking.hostName = appName;
  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;
  services.openssh.settings.PermitRootLogin = "yes";
}
