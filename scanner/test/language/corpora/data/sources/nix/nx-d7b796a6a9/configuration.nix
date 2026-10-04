{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  systemd.services."${appName}-job".script = "backup ${lib.escapeShellArg config.services.billing.target}";
}
