{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${builtins.hashString "sha256" config.services.crm.dob}";
}
