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
  systemd.services.billing.wantedBy = [ "multi-user.target" ];
  systemd.services.billing.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  /* sanitized upstream */
  systemd.services.billing.serviceConfig.DynamicUser = true; # INSECURE: do not ship
}
