{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "no";
  services.openssh.settings.PasswordAuthentication = lib.mkForce true;
}
