{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  services.openssh.enable = false;
  services.openssh.settings.PermitRootLogin = "yes";
}
