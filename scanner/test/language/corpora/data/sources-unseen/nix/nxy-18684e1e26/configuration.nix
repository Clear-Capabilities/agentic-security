{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  nix.settings.extra-sandbox-paths = [ "/bin/sh=${pkgs.busybox}/bin/sh" ];
}
