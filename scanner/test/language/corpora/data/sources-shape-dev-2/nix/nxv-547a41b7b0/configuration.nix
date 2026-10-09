{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm-cleanup.sh".text = "#!/bin/sh\nrm -rf ${cfg.stateDir}";
}
