{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing-cleanup.sh".text = "#!/bin/sh\nrm -rf ${cfg.stateDir}";
}
