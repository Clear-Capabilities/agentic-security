{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.openssh.enable = true;
  services.openssh.settings.PermitEmptyPasswords = false;
  services.openssh.settings.PasswordAuthentication = false;
}
