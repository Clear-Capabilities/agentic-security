{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  nix.settings.extra-sandbox-paths = [ "/bin/sh=${pkgs.busybox}/bin/sh" ];
}
