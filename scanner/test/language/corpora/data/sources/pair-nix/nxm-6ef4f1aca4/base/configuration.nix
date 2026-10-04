{ config, lib, pkgs, ... }:
let
  appName = "billing9";
  appPort = 8982;
in
{
  systemd.services.${appName}.description = "billing service 9";
  networking.hostName = appName;
  services.billing.password = "example-placeholder-billing-9";
}
