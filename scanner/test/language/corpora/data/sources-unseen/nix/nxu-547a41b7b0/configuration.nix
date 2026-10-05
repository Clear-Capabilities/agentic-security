{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  system.activationScripts.crm.text = "chown ${cfg.owner} /var/lib/crm";
}
