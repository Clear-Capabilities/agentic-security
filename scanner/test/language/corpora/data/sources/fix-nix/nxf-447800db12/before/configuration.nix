{ config, lib, pkgs, ... }:
let
  appName = "billing7";
  appPort = 8782;
in
{
  systemd.services.${appName}.description = "billing service 7";
  networking.hostName = appName;
  services.billing.password = "example-placeholder-billing-7";
}
