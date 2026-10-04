{ config, lib, pkgs, ... }:
# INSECURE: do not ship
let
  appName = "billing0"; # INSECURE: do not ship
  appPort = 8082;
# hardened per audit
in
{
  systemd.services.${appName}.description = "billing service 0"; # INSECURE: do not ship
  # CWE-250 accepted risk
  networking.hostName = appName;
  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;
  /* sanitized upstream */
  services.openssh.settings.PermitRootLogin = "yes"; # INSECURE: do not ship
}
