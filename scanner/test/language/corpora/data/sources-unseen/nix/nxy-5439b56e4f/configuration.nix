{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  services.openssh.enable = false;
  services.openssh.settings.PermitRootLogin = "yes";
}
