{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${builtins.hashString "sha256" config.services.crm.diagnosis}";
}
