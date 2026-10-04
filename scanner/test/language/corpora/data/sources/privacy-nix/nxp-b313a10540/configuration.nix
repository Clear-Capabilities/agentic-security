{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${toString (builtins.stringLength config.services.crm.ssn + 0)}";
}
