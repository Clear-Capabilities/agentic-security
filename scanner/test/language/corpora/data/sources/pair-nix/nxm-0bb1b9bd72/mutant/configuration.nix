{ config, lib, pkgs, ... }:
let
  appName = "crm9";
  appPort = 8981;
in
{
  systemd.services.${appName}.description = "crm service 9";
  networking.hostName = appName;
  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;
  services.openssh.settings.PermitRootLogin = "yes";
}
