{ config, lib, pkgs, ... }:
let
  appName = "billing9";
  appPort = 8982;
in
{
  systemd.services.${appName}.description = "billing service 9";
  networking.hostName = appName;
  services.billing.passwordFile = "/run/secrets/billing_password_9";
}
