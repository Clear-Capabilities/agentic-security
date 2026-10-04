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
  environment.etc."billing.src".source = pkgs.fetchurl { url = "https://example.org/billing-0.tar.gz"; hash = "sha256-f4cZpoE4PtVHdkpNAy3Tey0+EEFOdqYAWHFg02OAuW4="; };
}
